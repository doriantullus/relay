//! mock_vfs — scriptable Vfs test double for the transfer queue: a virtual
//! file tree, per-path fault injection, byte-rate shaping, and an op log
//! for assertions. Entirely in-memory and offline.
//!
//! Thread-safety: one spin lock guards tree + faults + op log, so eight
//! queue workers can hammer one mock. Sink callbacks and shaping sleeps
//! happen OUTSIDE the lock (a sink may re-enter the engine).
//!
//! Mid-stream read/write faults surface as bare error.ReadFailed /
//! error.WriteFailed (std.Io streams carry no payload); the scheduler
//! classifies those as transient by design, so scripted stream faults model
//! connection drops. Faults that need a specific ErrorClass (permanent,
//! auth, ...) are injected on the *operations* (open/stat/list/...), which
//! do carry Diagnostics.

const std = @import("std");
const vfs_mod = @import("../vfs/vfs.zig");
const diag_mod = @import("../diag.zig");
const cancel_mod = @import("../cancel.zig");

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub const Op = enum { stat, list, open_read, open_write, read, write, mkdir, remove, rename, chmod };

pub const FaultSpec = struct {
    /// Exact path, or "*" to match any path.
    path: []const u8,
    op: Op,
    /// Let this many matching calls through before failing.
    skip: u32 = 0,
    /// Fail this many matching calls, then disarm. maxInt(u32) ≈ forever.
    times: u32 = 1,
    err: vfs_mod.Error = error.ConnectionLost,
    class: diag_mod.ErrorClass = .transient,
    code: u32 = 0,
    message: []const u8 = "injected fault",
    /// For .read/.write only: absolute stream offset at which the fault
    /// fires. Reads/writes short of the boundary are served up to it, so
    /// the failure lands at exactly this byte.
    at_bytes: u64 = 0,
};

const Fault = struct {
    path: []u8,
    message: []u8,
    op: Op,
    skip: u32,
    times: u32,
    err: vfs_mod.Error,
    class: diag_mod.ErrorClass,
    code: u32,
    at_bytes: u64,
};

const Node = union(enum) {
    dir,
    file: std.ArrayList(u8),
};

pub const MockVfs = struct {
    gpa: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    tree: std.StringHashMapUnmanaged(Node) = .empty,
    faults: std.ArrayList(Fault) = .empty,
    op_log: std.ArrayList([]u8) = .empty,
    caps_value: vfs_mod.Caps = .{
        .resume_read = true,
        .resume_write = true,
        .atomic_rename = true,
        .case_sensitive = true,
    },

    // Shaping knobs (set before transfers start).
    /// Max bytes served per stream read call.
    read_chunk: usize = std.math.maxInt(usize),
    /// Sleep after each stream read call (sliced, cancel-checked).
    read_stall_ns: u64 = 0,
    /// Sleep after each write drain call.
    write_stall_ns: u64 = 0,
    /// Listing entries per sink batch.
    list_batch: usize = 64,
    /// Sleep between sink batches — makes incremental folder expansion
    /// observable in tests.
    list_stall_ns: u64 = 0,

    // Lock-free counters for coalescing assertions.
    read_calls: std.atomic.Value(u64) = .init(0),
    write_calls: std.atomic.Value(u64) = .init(0),

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator) MockVfs {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Self) void {
        var it = self.tree.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.*) {
                .file => |*content| content.deinit(self.gpa),
                .dir => {},
            }
            self.gpa.free(entry.key_ptr.*);
        }
        self.tree.deinit(self.gpa);
        for (self.faults.items) |f| self.freeFault(f);
        self.faults.deinit(self.gpa);
        for (self.op_log.items) |line| self.gpa.free(line);
        self.op_log.deinit(self.gpa);
        self.* = undefined;
    }

    /// The mock must be pinned (the returned Vfs captures `self`).
    pub fn vfs(self: *Self) vfs_mod.Vfs {
        return .{ .vtable = &vtable, .ctx = self };
    }

    // ------------------------------------------------------------------
    // Scripting API
    // ------------------------------------------------------------------

    pub fn addDir(self: *Self, path: []const u8) error{OutOfMemory}!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureParentsLocked(path);
        try self.putNodeLocked(path, .dir);
    }

    pub fn addFile(self: *Self, path: []const u8, contents: []const u8) error{OutOfMemory}!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureParentsLocked(path);
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(self.gpa);
        try list.appendSlice(self.gpa, contents);
        try self.putNodeLocked(path, .{ .file = list });
    }

    /// Copy of a file's contents for assertions; null when absent.
    pub fn contentsAlloc(self: *Self, gpa: std.mem.Allocator, path: []const u8) error{OutOfMemory}!?[]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const node = self.tree.getPtr(path) orelse return null;
        return switch (node.*) {
            .file => |content| try gpa.dupe(u8, content.items),
            .dir => null,
        };
    }

    pub fn fileSize(self: *Self, path: []const u8) ?u64 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const node = self.tree.getPtr(path) orelse return null;
        return switch (node.*) {
            .file => |content| content.items.len,
            .dir => null,
        };
    }

    pub fn injectFault(self: *Self, spec: FaultSpec) error{OutOfMemory}!void {
        const path = try self.gpa.dupe(u8, spec.path);
        errdefer self.gpa.free(path);
        const message = try self.gpa.dupe(u8, spec.message);
        errdefer self.gpa.free(message);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.faults.append(self.gpa, .{
            .path = path,
            .message = message,
            .op = spec.op,
            .skip = spec.skip,
            .times = spec.times,
            .err = spec.err,
            .class = spec.class,
            .code = spec.code,
            .at_bytes = spec.at_bytes,
        });
    }

    pub fn clearFaults(self: *Self) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.faults.items) |f| self.freeFault(f);
        self.faults.clearRetainingCapacity();
    }

    /// Number of logged operations whose formatted line contains `needle`.
    pub fn opCountContaining(self: *Self, needle: []const u8) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var count: usize = 0;
        for (self.op_log.items) |line| {
            if (std.mem.indexOf(u8, line, needle) != null) count += 1;
        }
        return count;
    }

    pub fn hasOp(self: *Self, needle: []const u8) bool {
        return self.opCountContaining(needle) > 0;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn freeFault(self: *Self, f: Fault) void {
        self.gpa.free(f.path);
        self.gpa.free(f.message);
    }

    fn ensureParentsLocked(self: *Self, path: []const u8) error{OutOfMemory}!void {
        var i: usize = 1;
        while (std.mem.indexOfScalarPos(u8, path, i, '/')) |slash| {
            try self.putNodeLocked(path[0..slash], .dir);
            i = slash + 1;
        }
    }

    fn putNodeLocked(self: *Self, path: []const u8, node: Node) error{OutOfMemory}!void {
        if (self.tree.getPtr(path)) |existing| {
            switch (existing.*) {
                .file => |*content| content.deinit(self.gpa),
                .dir => {},
            }
            existing.* = node;
            return;
        }
        const key = try self.gpa.dupe(u8, path);
        errdefer self.gpa.free(key);
        try self.tree.put(self.gpa, key, node);
    }

    /// Best-effort (OOM drops the line — assertions, not bookkeeping).
    fn logLocked(self: *Self, comptime fmt: []const u8, args: anytype) void {
        const line = std.fmt.allocPrint(self.gpa, fmt, args) catch return;
        self.op_log.append(self.gpa, line) catch self.gpa.free(line);
    }

    /// Scan op-level faults; first match wins. Decrements skip/times and
    /// disarms exhausted entries.
    fn checkFaultLocked(self: *Self, op: Op, path: []const u8, diag: *diag_mod.Diagnostics) vfs_mod.Error!void {
        for (self.faults.items, 0..) |*f, i| {
            if (f.op != op) continue;
            if (!std.mem.eql(u8, f.path, "*") and !std.mem.eql(u8, f.path, path)) continue;
            if (f.skip > 0) {
                f.skip -= 1;
                continue;
            }
            const err = f.err;
            diag.set(f.class, f.code, "{s}", .{f.message});
            if (f.times != std.math.maxInt(u32)) {
                f.times -= 1;
                if (f.times == 0) {
                    self.freeFault(self.faults.orderedRemove(i));
                }
            }
            return err;
        }
    }

    /// Stream fault check at absolute position `pos` wanting `want` bytes.
    /// Returns the allowed byte count, or null when the fault fires now.
    fn streamFaultLocked(self: *Self, op: Op, path: []const u8, pos: u64, want: usize) ?usize {
        for (self.faults.items, 0..) |*f, i| {
            if (f.op != op) continue;
            if (!std.mem.eql(u8, f.path, "*") and !std.mem.eql(u8, f.path, path)) continue;
            if (pos >= f.at_bytes) {
                if (f.times != std.math.maxInt(u32)) {
                    f.times -= 1;
                    if (f.times == 0) self.freeFault(self.faults.orderedRemove(i));
                }
                return null;
            }
            return @intCast(@min(@as(u64, want), f.at_bytes - pos));
        }
        return want;
    }

    /// Sliced shaping sleep; true when the transfer's token canceled.
    fn stall(io: std.Io, token: *const cancel_mod.CancelToken, total_ns: u64) bool {
        const slice_ns: u64 = 2 * std.time.ns_per_ms;
        var left = total_ns;
        while (left > 0) {
            if (token.isCanceled()) return true;
            const ns = @min(left, slice_ns);
            io.sleep(.fromNanoseconds(ns), .awake) catch {};
            left -= ns;
        }
        return token.isCanceled();
    }

    // ------------------------------------------------------------------
    // Vfs vtable
    // ------------------------------------------------------------------

    const vtable: vfs_mod.VTable = .{
        .caps = capsFn,
        .stat = statFn,
        .list = listFn,
        .openRead = openReadFn,
        .openWrite = openWriteFn,
        .mkdir = mkdirFn,
        .remove = removeFn,
        .rename = renameFn,
        .chmod = chmodFn,
    };

    fn fromCtx(ctx: *anyopaque) *Self {
        return @ptrCast(@alignCast(ctx));
    }

    fn capsFn(ctx: *anyopaque) vfs_mod.Caps {
        return fromCtx(ctx).caps_value;
    }

    fn statFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) vfs_mod.Error!vfs_mod.Entry {
        _ = io;
        const self = fromCtx(ctx);
        try cancel.check();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.logLocked("stat {s}", .{path});
        try self.checkFaultLocked(.stat, path, diag);
        if (std.mem.eql(u8, path, "/")) return .{ .name = "", .kind = .dir };
        const node = self.tree.getPtr(path) orelse {
            diag.set(.permanent, 0, "mock: not found: {s}", .{path});
            return error.NotFound;
        };
        return switch (node.*) {
            .dir => .{ .name = "", .kind = .dir },
            .file => |content| .{ .name = "", .kind = .file, .size = content.items.len },
        };
    }

    fn listFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, arena: std.mem.Allocator, sink: vfs_mod.ListingSink) vfs_mod.Error!void {
        const self = fromCtx(ctx);
        try cancel.check();

        // Build the entry list under the lock, deliver outside it (the
        // sink re-enters the engine, which takes its own locks).
        var entries: std.ArrayList(vfs_mod.Entry) = .empty;
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            self.logLocked("list {s}", .{path});
            try self.checkFaultLocked(.list, path, diag);
            if (!std.mem.eql(u8, path, "/")) {
                const node = self.tree.getPtr(path) orelse {
                    diag.set(.permanent, 0, "mock: not found: {s}", .{path});
                    return error.NotFound;
                };
                if (node.* != .dir) {
                    diag.set(.permanent, 0, "mock: not a directory: {s}", .{path});
                    return error.NotADirectory;
                }
            }
            var it = self.tree.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const name = childName(path, key) orelse continue;
                try entries.append(arena, switch (entry.value_ptr.*) {
                    .dir => .{ .name = try arena.dupe(u8, name), .kind = .dir },
                    .file => |content| .{
                        .name = try arena.dupe(u8, name),
                        .kind = .file,
                        .size = content.items.len,
                    },
                });
            }
        }
        // Hash map order is arbitrary; sort for deterministic tests.
        std.mem.sort(vfs_mod.Entry, entries.items, {}, entryNameLessThan);

        var off: usize = 0;
        while (off < entries.items.len) {
            if (cancel.isCanceled()) {
                diag.set(.cancel, 0, "mock: list canceled", .{});
                return error.Canceled;
            }
            const n = @min(self.list_batch, entries.items.len - off);
            sink.batch(entries.items[off .. off + n]);
            off += n;
            if (off < entries.items.len and self.list_stall_ns > 0) {
                if (stall(io, cancel, self.list_stall_ns)) {
                    diag.set(.cancel, 0, "mock: list canceled", .{});
                    return error.Canceled;
                }
            }
        }
    }

    fn childName(parent: []const u8, key: []const u8) ?[]const u8 {
        if (key.len == 0 or std.mem.eql(u8, key, parent)) return null;
        const prefix_len = if (std.mem.eql(u8, parent, "/")) 1 else parent.len + 1;
        if (key.len <= prefix_len) return null;
        if (!std.mem.eql(u8, parent, "/")) {
            if (!std.mem.startsWith(u8, key, parent) or key[parent.len] != '/') return null;
        }
        const rest = key[prefix_len..];
        if (std.mem.indexOfScalar(u8, rest, '/') != null) return null;
        return rest;
    }

    fn entryNameLessThan(_: void, a: vfs_mod.Entry, b: vfs_mod.Entry) bool {
        return std.mem.lessThan(u8, a.name, b.name);
    }

    fn openReadFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64) vfs_mod.Error!vfs_mod.ReadStream {
        const self = fromCtx(ctx);
        try cancel.check();
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            self.logLocked("open_read {s} off={d}", .{ path, offset });
            try self.checkFaultLocked(.open_read, path, diag);
            const node = self.tree.getPtr(path) orelse {
                diag.set(.permanent, 0, "mock: not found: {s}", .{path});
                return error.NotFound;
            };
            switch (node.*) {
                .dir => {
                    diag.set(.permanent, 0, "mock: is a directory: {s}", .{path});
                    return error.IsADirectory;
                },
                .file => |content| if (offset > content.items.len) {
                    diag.set(.permanent, 0, "mock: offset {d} past EOF of {s}", .{ offset, path });
                    return error.Unexpected;
                },
            }
        }
        const rc = self.gpa.create(ReadCtx) catch return error.OutOfMemory;
        errdefer self.gpa.destroy(rc);
        const owned_path = self.gpa.dupe(u8, path) catch return error.OutOfMemory;
        rc.* = .{
            .mock = self,
            .io = io,
            .cancel = cancel,
            .path = owned_path,
            .pos = offset,
            .reader = .{ .vtable = &ReadCtx.reader_vtable, .buffer = &.{}, .seek = 0, .end = 0 },
        };
        return .{ .reader = &rc.reader, .context = rc, .closeFn = ReadCtx.close };
    }

    const ReadCtx = struct {
        mock: *Self,
        io: std.Io,
        cancel: *cancel_mod.CancelToken,
        path: []u8,
        pos: u64,
        reader: std.Io.Reader,

        const reader_vtable: std.Io.Reader.VTable = .{ .stream = streamFn };

        fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const rc: *ReadCtx = @alignCast(@fieldParentPtr("reader", r));
            const m = rc.mock;
            _ = m.read_calls.fetchAdd(1, .monotonic);
            if (rc.cancel.isCanceled()) return error.ReadFailed;
            var written: usize = 0;
            {
                lockSpin(&m.mutex);
                defer m.mutex.unlock();
                const node = m.tree.getPtr(rc.path) orelse return error.ReadFailed;
                const content = switch (node.*) {
                    .file => |c| c.items,
                    .dir => return error.ReadFailed,
                };
                if (rc.pos >= content.len) return error.EndOfStream;
                var want: usize = limit.minInt64(content.len - rc.pos);
                want = @min(want, m.read_chunk);
                if (want == 0) return 0;
                // A fault boundary inside `want` clamps this read so the
                // failure fires on the NEXT call at exactly `at_bytes`.
                want = m.streamFaultLocked(.read, rc.path, rc.pos, want) orelse {
                    m.logLocked("read_fault {s} at={d}", .{ rc.path, rc.pos });
                    return error.ReadFailed;
                };
                const pos: usize = @intCast(rc.pos);
                written = try w.write(content[pos .. pos + want]);
                rc.pos += written;
            }
            if (m.read_stall_ns > 0) {
                if (stall(rc.io, rc.cancel, m.read_stall_ns)) return error.ReadFailed;
            }
            return written;
        }

        fn close(context: *anyopaque, io: std.Io) void {
            _ = io;
            const rc: *ReadCtx = @ptrCast(@alignCast(context));
            const m = rc.mock;
            lockSpin(&m.mutex);
            m.logLocked("close_read {s}", .{rc.path});
            m.mutex.unlock();
            m.gpa.free(rc.path);
            m.gpa.destroy(rc);
        }
    };

    fn openWriteFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64, mode: vfs_mod.OpenMode) vfs_mod.Error!vfs_mod.WriteStream {
        const self = fromCtx(ctx);
        try cancel.check();
        var pos: u64 = 0;
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            self.logLocked("open_write {s} off={d} mode={t}", .{ path, offset, mode });
            try self.checkFaultLocked(.open_write, path, diag);
            if (self.tree.getPtr(path)) |node| {
                if (node.* == .dir) {
                    diag.set(.permanent, 0, "mock: is a directory: {s}", .{path});
                    return error.IsADirectory;
                }
            } else {
                // Lenient: parents materialize implicitly so transfer tests
                // need no mkdir choreography on the destination side.
                self.ensureParentsLocked(path) catch return error.OutOfMemory;
                self.putNodeLocked(path, .{ .file = .empty }) catch return error.OutOfMemory;
            }
            const content = &self.tree.getPtr(path).?.file;
            switch (mode) {
                .create_truncate => content.clearRetainingCapacity(),
                .create_resume => {
                    if (offset > content.items.len) {
                        diag.set(.permanent, 0, "mock: resume offset {d} past EOF of {s}", .{ offset, path });
                        return error.Unexpected;
                    }
                    // Anything past the offset is a partial tail from the
                    // failed attempt; the resumed stream rewrites from here.
                    content.shrinkRetainingCapacity(@intCast(offset));
                    pos = offset;
                },
                .append => pos = content.items.len,
            }
        }
        const wc = self.gpa.create(WriteCtx) catch return error.OutOfMemory;
        errdefer self.gpa.destroy(wc);
        const owned_path = self.gpa.dupe(u8, path) catch return error.OutOfMemory;
        wc.* = .{
            .mock = self,
            .io = io,
            .cancel = cancel,
            .path = owned_path,
            .pos = pos,
            .writer = .{ .vtable = &WriteCtx.writer_vtable, .buffer = &.{} },
        };
        return .{ .writer = &wc.writer, .context = wc, .closeFn = WriteCtx.close };
    }

    const WriteCtx = struct {
        mock: *Self,
        io: std.Io,
        cancel: *cancel_mod.CancelToken,
        path: []u8,
        pos: u64,
        writer: std.Io.Writer,

        const writer_vtable: std.Io.Writer.VTable = .{ .drain = drainFn };

        fn drainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const wc: *WriteCtx = @alignCast(@fieldParentPtr("writer", w));
            const m = wc.mock;
            _ = m.write_calls.fetchAdd(1, .monotonic);
            if (wc.cancel.isCanceled()) return error.WriteFailed;
            var consumed: usize = 0;
            {
                lockSpin(&m.mutex);
                defer m.mutex.unlock();
                outer: {
                    for (data[0 .. data.len - 1]) |slice| {
                        const wrote = try wc.writeSliceLocked(slice);
                        consumed += wrote;
                        if (wrote < slice.len) break :outer;
                    }
                    const last = data[data.len - 1];
                    var i: usize = 0;
                    while (i < splat) : (i += 1) {
                        const wrote = try wc.writeSliceLocked(last);
                        consumed += wrote;
                        if (wrote < last.len) break :outer;
                    }
                }
            }
            if (m.write_stall_ns > 0) {
                if (stall(wc.io, wc.cancel, m.write_stall_ns)) return error.WriteFailed;
            }
            return consumed;
        }

        /// Caller holds the mock lock. A fault boundary inside the slice
        /// commits the prefix and returns short (no error, fault stays
        /// armed); the caller's NEXT drain lands exactly on `at_bytes`,
        /// consumes the fault, and fails — matching a socket that dies with
        /// data in flight.
        fn writeSliceLocked(wc: *WriteCtx, slice: []const u8) std.Io.Writer.Error!usize {
            if (slice.len == 0) return 0;
            const m = wc.mock;
            const node = m.tree.getPtr(wc.path) orelse return error.WriteFailed;
            const content = switch (node.*) {
                .file => |*c| c,
                .dir => return error.WriteFailed,
            };
            const allowed = m.streamFaultLocked(.write, wc.path, wc.pos, slice.len) orelse {
                m.logLocked("write_fault {s} at={d}", .{ wc.path, wc.pos });
                return error.WriteFailed;
            };
            const part = slice[0..allowed];
            const pos: usize = @intCast(wc.pos);
            const overlap = @min(content.items.len -| pos, part.len);
            @memcpy(content.items[pos .. pos + overlap], part[0..overlap]);
            content.appendSlice(m.gpa, part[overlap..]) catch return error.WriteFailed;
            wc.pos += part.len;
            return part.len;
        }

        fn close(context: *anyopaque, io: std.Io) vfs_mod.Error!void {
            _ = io;
            const wc: *WriteCtx = @ptrCast(@alignCast(context));
            const m = wc.mock;
            lockSpin(&m.mutex);
            m.logLocked("close_write {s}", .{wc.path});
            m.mutex.unlock();
            m.gpa.free(wc.path);
            m.gpa.destroy(wc);
        }
    };

    fn mkdirFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) vfs_mod.Error!void {
        _ = io;
        const self = fromCtx(ctx);
        try cancel.check();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.logLocked("mkdir {s}", .{path});
        try self.checkFaultLocked(.mkdir, path, diag);
        if (self.tree.getPtr(path) != null) {
            diag.set(.permanent, 0, "mock: already exists: {s}", .{path});
            return error.AlreadyExists;
        }
        self.ensureParentsLocked(path) catch return error.OutOfMemory;
        self.putNodeLocked(path, .dir) catch return error.OutOfMemory;
    }

    fn removeFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, recursive: bool) vfs_mod.Error!void {
        _ = io;
        const self = fromCtx(ctx);
        try cancel.check();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.logLocked("remove {s} recursive={d}", .{ path, @intFromBool(recursive) });
        try self.checkFaultLocked(.remove, path, diag);
        const node = self.tree.getPtr(path) orelse {
            diag.set(.permanent, 0, "mock: not found: {s}", .{path});
            return error.NotFound;
        };
        if (node.* == .dir and !recursive) {
            var it = self.tree.iterator();
            while (it.next()) |entry| {
                if (childName(path, entry.key_ptr.*) != null) {
                    diag.set(.permanent, 0, "mock: directory not empty: {s}", .{path});
                    return error.Unexpected;
                }
            }
        }
        self.removeSubtreeLocked(path) catch return error.OutOfMemory;
    }

    fn removeSubtreeLocked(self: *Self, path: []const u8) error{OutOfMemory}!void {
        var doomed: std.ArrayList([]const u8) = .empty;
        defer doomed.deinit(self.gpa);
        var it = self.tree.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (std.mem.eql(u8, key, path) or isUnder(path, key)) {
                try doomed.append(self.gpa, key);
            }
        }
        for (doomed.items) |key| {
            const kv = self.tree.fetchRemove(key).?;
            switch (kv.value) {
                .file => |content| {
                    var c = content;
                    c.deinit(self.gpa);
                },
                .dir => {},
            }
            self.gpa.free(kv.key);
        }
    }

    fn isUnder(parent: []const u8, key: []const u8) bool {
        return key.len > parent.len + 1 and
            std.mem.startsWith(u8, key, parent) and key[parent.len] == '/';
    }

    fn renameFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, from: []const u8, to: []const u8) vfs_mod.Error!void {
        _ = io;
        const self = fromCtx(ctx);
        try cancel.check();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.logLocked("rename {s} -> {s}", .{ from, to });
        try self.checkFaultLocked(.rename, from, diag);
        if (self.tree.getPtr(from) == null) {
            diag.set(.permanent, 0, "mock: not found: {s}", .{from});
            return error.NotFound;
        }
        // Collect the subtree first: rehashing during iteration is UB.
        var moves: std.ArrayList(struct { old: []const u8, new: []u8 }) = .empty;
        defer {
            for (moves.items) |mv| self.gpa.free(mv.new);
            moves.deinit(self.gpa);
        }
        var it = self.tree.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (!std.mem.eql(u8, key, from) and !isUnder(from, key)) continue;
            const new_key = std.fmt.allocPrint(self.gpa, "{s}{s}", .{ to, key[from.len..] }) catch return error.OutOfMemory;
            moves.append(self.gpa, .{ .old = key, .new = new_key }) catch {
                self.gpa.free(new_key);
                return error.OutOfMemory;
            };
        }
        for (moves.items) |mv| {
            const kv = self.tree.fetchRemove(mv.old).?;
            self.gpa.free(kv.key);
            self.putNodeLocked(mv.new, kv.value) catch return error.OutOfMemory;
        }
    }

    fn chmodFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, mode: u16) vfs_mod.Error!void {
        _ = io;
        const self = fromCtx(ctx);
        try cancel.check();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.logLocked("chmod {s} {o}", .{ path, mode });
        try self.checkFaultLocked(.chmod, path, diag);
        if (self.tree.getPtr(path) == null) {
            diag.set(.permanent, 0, "mock: not found: {s}", .{path});
            return error.NotFound;
        }
        // Modes are not modeled; the op log is the observable effect.
    }
};

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const TestSink = struct {
    entries: std.ArrayList(vfs_mod.Entry) = .empty,
    batches: usize = 0,
    gpa: std.mem.Allocator,

    fn sink(self: *TestSink) vfs_mod.ListingSink {
        return .{ .context = self, .batchFn = batch };
    }

    fn batch(context: *anyopaque, entries: []const vfs_mod.Entry) void {
        const self: *TestSink = @ptrCast(@alignCast(context));
        self.batches += 1;
        self.entries.appendSlice(self.gpa, entries) catch unreachable;
    }
};

test "tree: stat, list batches, deterministic order" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    mock.list_batch = 2;

    try mock.addFile("/src/b.txt", "bee");
    try mock.addFile("/src/a.txt", "ay");
    try mock.addDir("/src/sub");
    try mock.addFile("/src/sub/deep.txt", "deep");

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    const st = try v.stat(io, &token, &diag, "/src/b.txt");
    try std.testing.expectEqual(vfs_mod.EntryKind.file, st.kind);
    try std.testing.expectEqual(@as(?u64, 3), st.size);
    try std.testing.expectEqual(vfs_mod.EntryKind.dir, (try v.stat(io, &token, &diag, "/src")).kind);
    try std.testing.expectError(error.NotFound, v.stat(io, &token, &diag, "/nope"));
    try std.testing.expectEqual(diag_mod.ErrorClass.permanent, diag.class);

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var ts: TestSink = .{ .gpa = std.testing.allocator };
    defer ts.entries.deinit(std.testing.allocator);
    try v.list(io, &token, &diag, "/src", arena.allocator(), ts.sink());

    try std.testing.expectEqual(@as(usize, 3), ts.entries.items.len);
    try std.testing.expectEqual(@as(usize, 2), ts.batches); // 3 entries, batch=2
    try std.testing.expectEqualStrings("a.txt", ts.entries.items[0].name);
    try std.testing.expectEqualStrings("b.txt", ts.entries.items[1].name);
    try std.testing.expectEqualStrings("sub", ts.entries.items[2].name);
    try std.testing.expectEqual(vfs_mod.EntryKind.dir, ts.entries.items[2].kind);
    try std.testing.expect(mock.hasOp("list /src"));
}

test "read stream: offset honored, EOF, close logs" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    try mock.addFile("/f", "0123456789");

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    const rs = try v.openRead(io, &token, &diag, "/f", 4);
    var buf: [16]u8 = undefined;
    const n = try rs.reader.readSliceShort(&buf);
    try std.testing.expectEqualStrings("456789", buf[0..n]);
    rs.close(io);
    try std.testing.expect(mock.hasOp("open_read /f off=4"));
    try std.testing.expect(mock.hasOp("close_read /f"));

    try std.testing.expectError(error.Unexpected, v.openRead(io, &token, &diag, "/f", 99));
}

test "write stream: truncate, resume drops the tail, append" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    try mock.addFile("/w", "OLD-CONTENT");

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    {
        const ws = try v.openWrite(io, &token, &diag, "/w", 0, .create_truncate);
        try ws.writer.writeAll("abcdef");
        try ws.close(io);
    }
    {
        const ws = try v.openWrite(io, &token, &diag, "/w", 3, .create_resume);
        try ws.writer.writeAll("XYZ");
        try ws.close(io);
    }
    {
        const ws = try v.openWrite(io, &token, &diag, "/w", 0, .append);
        try ws.writer.writeAll("!");
        try ws.close(io);
    }
    const got = (try mock.contentsAlloc(std.testing.allocator, "/w")).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("abcXYZ!", got);

    // Implicit parents on a fresh path.
    const ws = try v.openWrite(io, &token, &diag, "/deep/new/file", 0, .create_truncate);
    try ws.writer.writeAll("hi");
    try ws.close(io);
    try std.testing.expectEqual(@as(?u64, 2), mock.fileSize("/deep/new/file"));
    try std.testing.expectEqual(vfs_mod.EntryKind.dir, (try v.stat(io, &token, &diag, "/deep/new")).kind);
}

test "op faults: skip and times semantics, wildcard path" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    try mock.addFile("/f", "data");

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    try mock.injectFault(.{
        .path = "*",
        .op = .stat,
        .skip = 1,
        .times = 2,
        .err = error.Timeout,
        .class = .transient,
        .code = 421,
        .message = "421 busy",
    });
    _ = try v.stat(io, &token, &diag, "/f"); // skipped
    try std.testing.expectError(error.Timeout, v.stat(io, &token, &diag, "/f"));
    try std.testing.expectEqual(diag_mod.ErrorClass.transient, diag.class);
    try std.testing.expectEqual(@as(u32, 421), diag.protocol_code);
    try std.testing.expect(std.mem.indexOf(u8, diag.message, "421 busy") != null);
    try std.testing.expectError(error.Timeout, v.stat(io, &token, &diag, "/f"));
    _ = try v.stat(io, &token, &diag, "/f"); // disarmed
}

test "read fault fires at the exact byte boundary, once" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    const payload = "A" ** 100 ++ "B" ** 100;
    try mock.addFile("/f", payload);
    try mock.injectFault(.{ .path = "/f", .op = .read, .at_bytes = 100 });

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    var buf: [256]u8 = undefined;
    {
        const rs = try v.openRead(io, &token, &diag, "/f", 0);
        defer rs.close(io);
        // Reads are clamped at the boundary, so a read of exactly 100
        // bytes succeeds and the next one fails.
        try rs.reader.readSliceAll(buf[0..100]);
        try std.testing.expectEqualStrings("A" ** 100, buf[0..100]);
        try std.testing.expectError(error.ReadFailed, rs.reader.readSliceShort(buf[0..50]));
    }
    // Fault consumed: a resumed stream reads the rest.
    {
        const rs = try v.openRead(io, &token, &diag, "/f", 100);
        defer rs.close(io);
        const n = try rs.reader.readSliceShort(&buf);
        try std.testing.expectEqualStrings("B" ** 100, buf[0..n]);
    }
    try std.testing.expect(mock.hasOp("read_fault /f at=100"));
}

test "write fault commits the prefix then fails" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    try mock.injectFault(.{ .path = "/up", .op = .write, .at_bytes = 5 });

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    const ws = try v.openWrite(io, &token, &diag, "/up", 0, .create_truncate);
    try std.testing.expectError(error.WriteFailed, ws.writer.writeAll("0123456789"));
    try ws.close(io);
    try std.testing.expectEqual(@as(?u64, 5), mock.fileSize("/up"));
}

test "mkdir, remove, rename move subtrees" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    try mock.addFile("/a/x", "1");
    try mock.addFile("/a/sub/y", "2");

    const v = mock.vfs();
    var token: cancel_mod.CancelToken = .{};
    var diag: diag_mod.Diagnostics = .{};

    try std.testing.expectError(error.AlreadyExists, v.mkdir(io, &token, &diag, "/a"));
    try v.mkdir(io, &token, &diag, "/b");

    try v.rename(io, &token, &diag, "/a", "/c");
    try std.testing.expectEqual(@as(?u64, 1), mock.fileSize("/c/sub/y"));
    try std.testing.expectError(error.NotFound, v.stat(io, &token, &diag, "/a/x"));

    try std.testing.expectError(error.Unexpected, v.remove(io, &token, &diag, "/c", false));
    try v.remove(io, &token, &diag, "/c", true);
    try std.testing.expectError(error.NotFound, v.stat(io, &token, &diag, "/c/sub/y"));
    try v.chmod(io, &token, &diag, "/b", 0o755);
    try std.testing.expect(mock.hasOp("chmod /b 755"));
}

test "list cancellation between batches" {
    const io = std.testing.io;
    var mock: MockVfs = .init(std.testing.allocator);
    defer mock.deinit();
    mock.list_batch = 1;
    try mock.addFile("/d/one", "1");
    try mock.addFile("/d/two", "2");

    const Canceling = struct {
        token: cancel_mod.CancelToken = .{},
        batches: usize = 0,
        fn batch(context: *anyopaque, entries: []const vfs_mod.Entry) void {
            _ = entries;
            const self: *@This() = @ptrCast(@alignCast(context));
            self.batches += 1;
            self.token.cancel(); // cancel after the first batch lands
        }
    };
    var cs: Canceling = .{};
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diag: diag_mod.Diagnostics = .{};
    try std.testing.expectError(error.Canceled, mock.vfs().list(
        io,
        &cs.token,
        &diag,
        "/d",
        arena.allocator(),
        .{ .context = &cs, .batchFn = Canceling.batch },
    ));
    try std.testing.expectEqual(@as(usize, 1), cs.batches);
    try std.testing.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
}

test {
    std.testing.refAllDecls(@This());
}

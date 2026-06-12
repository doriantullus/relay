//! sftp — the SFTP Vfs backend: a thin adapter from the pinned Vfs vtable
//! onto the SftpClient engine (../proto/sftp/sftp.zig). Same pool
//! discipline as the FTP backend: browse ops on the dedicated browse
//! connection, transfer streams holding a transfer lease for the stream's
//! lifetime, broken leases torn down instead of reused.
//!
//! The engine already speaks vfs currency (readdir streams vfs.Entry
//! batches, openRead/openWrite return vfs streams) and classifies SSH_FX_*
//! statuses into Diagnostics, so this layer is mostly lease plumbing.
//! Engine calls take no `io` (libssh2 pumps its own fd via poll.zig).

const std = @import("std");
const vfs = @import("vfs.zig");
const path_mod = @import("path.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const diag_mod = @import("../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const site_pool = @import("../pool/site_pool.zig");
const lease_mod = @import("../pool/lease.zig");
const sftp_mod = @import("../proto/sftp/sftp.zig");

const Allocator = std.mem.Allocator;
const Lease = lease_mod.Lease;
const SftpClient = sftp_mod.SftpClient;

pub const SftpVfs = struct {
    gpa: Allocator,
    pool: *site_pool.SitePool,

    pub fn init(gpa: Allocator, pool: *site_pool.SitePool) SftpVfs {
        return .{ .gpa = gpa, .pool = pool };
    }

    pub fn vfsInterface(self: *SftpVfs) vfs.Vfs {
        return .{ .vtable = &vtable, .ctx = self };
    }

    const vtable: vfs.VTable = .{
        .caps = vtCaps,
        .defaultPath = vtDefaultPath,
        .stat = vtStat,
        .list = vtList,
        .openRead = vtOpenRead,
        .openWrite = vtOpenWrite,
        .mkdir = vtMkdir,
        .remove = vtRemove,
        .rename = vtRename,
        .chmod = vtChmod,
    };

    fn fromCtx(ctx: *anyopaque) *SftpVfs {
        return @ptrCast(@alignCast(ctx));
    }

    fn vtCaps(ctx: *anyopaque) vfs.Caps {
        _ = ctx;
        // Capability set is fixed by the protocol version libssh2 speaks
        // (SFTPv3); see the engine's constant.
        return sftp_mod.Caps;
    }

    /// Errors after which the SSH session state is unknowable.
    fn isFatal(err: vfs.Error) bool {
        return switch (err) {
            error.ConnectionLost, error.Timeout, error.ProtocolViolation => true,
            else => false,
        };
    }

    fn engineOf(lease: *Lease, diag: *Diagnostics) vfs.Error!*SftpClient {
        switch (lease.engine()) {
            .sftp => |client| return client,
            else => {
                diag.set(.permanent, 0, "protocol mismatch: SFTP backend on a non-SFTP connection", .{});
                return error.Unexpected;
            },
        }
    }

    // ------------------------------------------------------------------ //
    // Browse operations

    /// realpath(".") — the SFTP server resolves it to the user's home
    /// (SFTP has no CWD; "." is stable for the session's lifetime).
    fn vtDefaultPath(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, buf: []u8) vfs.Error![]const u8 {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        return client.realpath(cancel, diag, ".", buf) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtStat(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!vfs.Entry {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        // lstat: report the link itself, like local.zig does.
        const attrs = client.lstat(cancel, diag, p) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
        // Entry.name aliases the caller's `p` (stat has no arena); owner/
        // group need allocation and are omitted here (listings carry them).
        return .{
            .name = if (p.len <= 1) "/" else path_mod.basename(p),
            .kind = attrs.kind,
            .size = attrs.size,
            .mode = attrs.mode,
            .mtime = attrs.mtime,
        };
    }

    fn vtList(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        p: []const u8,
        arena: Allocator,
        sink: vfs.ListingSink,
    ) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.readdir(cancel, diag, p, arena, sink) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtMkdir(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.mkdir(cancel, diag, p) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtRename(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, from: []const u8, to: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.rename(cancel, diag, from, to) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtChmod(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, mode: u16) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.chmod(cancel, diag, p, mode) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtRemove(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, recursive: bool) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        if (recursive) {
            return self.removeRecursive(io, cancel, diag, &lease, client, p, 0);
        }
        // unlink for files; directories answer FX_FAILURE/IsADirectory,
        // then rmdir decides.
        client.unlink(cancel, diag, p) catch |err| {
            if (isFatal(err)) {
                lease.markBroken();
                return err;
            }
            if (err == error.Canceled or err == error.AuthRequired or err == error.OutOfMemory or err == error.NotFound) return err;
            client.rmdir(cancel, diag, p) catch |rmdir_err| {
                if (isFatal(rmdir_err)) lease.markBroken();
                return rmdir_err;
            };
        };
    }

    const max_remove_depth = 64;

    fn removeRecursive(
        self: *SftpVfs,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        lease: *Lease,
        client: *SftpClient,
        p: []const u8,
        depth: usize,
    ) vfs.Error!void {
        if (depth > max_remove_depth) {
            diag.set(.permanent, 0, "remove: directory tree deeper than {d} levels", .{max_remove_depth});
            return error.Unexpected;
        }
        const attrs = client.lstat(cancel, diag, p) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
        if (attrs.kind != .dir) {
            client.unlink(cancel, diag, p) catch |err| {
                if (isFatal(err)) lease.markBroken();
                return err;
            };
            return;
        }

        var arena_inst: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_inst.deinit();
        var collector: ListCollector = .{ .arena = arena_inst.allocator() };
        client.readdir(cancel, diag, p, arena_inst.allocator(), collector.sink()) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
        if (collector.failed) return error.OutOfMemory;

        for (collector.entries.items) |entry| {
            // join() normalizes but resolves a leading ".." laterally
            // ("/p" + "../x" -> "/x"), so a hostile name could pull the
            // recursive delete outside the chosen subtree without this.
            if (!path_mod.isSafeChildName(entry.name)) continue;
            const child = path_mod.join(arena_inst.allocator(), p, entry.name) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidPath => continue, // hostile listing entry; skip
            };
            if (entry.kind == .dir) {
                try self.removeRecursive(io, cancel, diag, lease, client, child, depth + 1);
            } else {
                client.unlink(cancel, diag, child) catch |err| {
                    if (isFatal(err)) lease.markBroken();
                    return err;
                };
            }
        }
        client.rmdir(cancel, diag, p) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    const ListCollector = struct {
        arena: Allocator,
        entries: std.ArrayList(vfs.Entry) = .empty,
        failed: bool = false,

        fn sink(c: *ListCollector) vfs.ListingSink {
            return .{ .context = c, .batchFn = onBatch };
        }

        fn onBatch(ctx: *anyopaque, batch: []const vfs.Entry) void {
            const c: *ListCollector = @ptrCast(@alignCast(ctx));
            c.entries.appendSlice(c.arena, batch) catch {
                c.failed = true;
            };
        }
    };

    // ------------------------------------------------------------------ //
    // Transfer streams (transfer lease held for the stream's lifetime)

    fn vtOpenRead(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        p: []const u8,
        offset: u64,
    ) vfs.Error!vfs.ReadStream {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .transfer);
        errdefer lease.release(io);
        const client = try engineOf(&lease, diag);
        const inner = client.openRead(self.gpa, cancel, diag, p, offset) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
        const sc = self.gpa.create(ReadStreamCtx) catch {
            inner.close(io);
            return error.OutOfMemory;
        };
        sc.* = .{ .gpa = self.gpa, .lease = lease, .inner = inner, .diag = diag };
        return .{ .reader = inner.reader, .context = sc, .closeFn = ReadStreamCtx.close };
    }

    const ReadStreamCtx = struct {
        gpa: Allocator,
        lease: Lease,
        inner: vfs.ReadStream,
        /// The transfer's Diagnostics (outlives the stream per the Vfs
        /// contract); a .transient class at close means the connection
        /// dropped mid-transfer. Use a fresh Diagnostics per transfer.
        diag: *Diagnostics,

        fn close(context: *anyopaque, io: std.Io) void {
            const sc: *ReadStreamCtx = @ptrCast(@alignCast(context));
            sc.inner.close(io);
            if (sc.diag.class == .transient) sc.lease.markBroken();
            sc.lease.release(io);
            const gpa = sc.gpa;
            gpa.destroy(sc);
        }
    };

    fn vtOpenWrite(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        p: []const u8,
        offset: u64,
        mode: vfs.OpenMode,
    ) vfs.Error!vfs.WriteStream {
        const self = fromCtx(ctx);
        var lease = try self.pool.checkout(io, cancel, diag, .transfer);
        errdefer lease.release(io);
        const client = try engineOf(&lease, diag);
        const inner = client.openWrite(self.gpa, cancel, diag, p, offset, mode) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
        const sc = self.gpa.create(WriteStreamCtx) catch {
            _ = inner.close(io) catch {};
            return error.OutOfMemory;
        };
        sc.* = .{ .gpa = self.gpa, .lease = lease, .inner = inner };
        return .{ .writer = inner.writer, .context = sc, .closeFn = WriteStreamCtx.close };
    }

    const WriteStreamCtx = struct {
        gpa: Allocator,
        lease: Lease,
        inner: vfs.WriteStream,

        fn close(context: *anyopaque, io: std.Io) vfs.Error!void {
            const sc: *WriteStreamCtx = @ptrCast(@alignCast(context));
            const gpa = sc.gpa;
            var lease = sc.lease;
            const inner = sc.inner;
            gpa.destroy(sc);
            defer lease.release(io);
            inner.close(io) catch |err| {
                if (isFatal(err)) lease.markBroken();
                return err;
            };
        }
    };
};

// ---------------------------------------------------------------------------
// Tests. The engine needs a live SSH session (Docker integration covers
// it); offline tests exercise the adapter's pool plumbing and guards.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "caps pass the engine's protocol constant through" {
    var hub = site_pool.MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0,
    }, .{});
    defer pool.deinit(testing.io);

    var backend = SftpVfs.init(testing.allocator, &pool);
    const caps = backend.vfsInterface().caps();
    try testing.expect(caps.resume_read and caps.resume_write);
    try testing.expect(caps.atomic_rename and caps.chmod and caps.symlinks);
    try testing.expect(!caps.server_search);
}

test "protocol mismatch on a non-SFTP connection is a classified error" {
    const io = testing.io;
    var hub = site_pool.MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(), // hands out .mock engines
        .keepalive_interval_ms = 0,
    }, .{});
    defer pool.deinit(io);

    var backend = SftpVfs.init(testing.allocator, &pool);
    const v = backend.vfsInterface();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try testing.expectError(error.Unexpected, v.stat(io, &cancel, &diag, "/x"));
    try testing.expectEqual(diag_mod.ErrorClass.permanent, diag.class);
    try testing.expect(std.mem.indexOf(u8, diag.message, "protocol mismatch") != null);
    // The mismatched conn went back to the pool intact (not our breakage).
    try testing.expectEqual(@as(usize, 1), hub.openConns());
}

test {
    std.testing.refAllDecls(@This());
}

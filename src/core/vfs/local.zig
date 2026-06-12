//! local — the Vfs backend over std.Io.Dir/File. All paths are normalized
//! absolute RemotePaths (path.zig) resolved against a root `std.Io.Dir`
//! handle: the app opens "/" (or a scoped folder) as the root, tests use a
//! tmp dir. Resolving via an open handle instead of absolute OS paths keeps
//! the backend sandbox-friendly and makes tests hermetic.

const std = @import("std");
const vfs = @import("vfs.zig");
const path_mod = @import("path.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const diag_mod = @import("../diag.zig");
const Diagnostics = diag_mod.Diagnostics;

const Allocator = std.mem.Allocator;

/// Entries accumulated before each ListingSink batch.
pub const list_batch_len = 256;
/// Stream buffer for read/write handles (bulk transfer granularity).
pub const stream_buffer_len = 64 * 1024;
/// Longest symlink target captured into listings.
pub const max_link_len = 1024;

pub const LocalVfs = struct {
    gpa: Allocator,
    /// Borrowed; must outlive the LocalVfs. Must be opened with
    /// `.iterate = true` for `list` to work.
    root: std.Io.Dir,

    pub fn init(gpa: Allocator, root: std.Io.Dir) LocalVfs {
        return .{ .gpa = gpa, .root = root };
    }

    pub fn vfsInterface(self: *LocalVfs) vfs.Vfs {
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

    fn fromCtx(ctx: *anyopaque) *LocalVfs {
        return @ptrCast(@alignCast(ctx));
    }

    /// RemotePath -> sub-path relative to `root` ("." for the root itself).
    fn rel(p: []const u8) []const u8 {
        std.debug.assert(path_mod.isNormalized(p));
        return if (p.len == 1) "." else p[1..];
    }

    fn vtCaps(ctx: *anyopaque) vfs.Caps {
        _ = ctx;
        return .{
            .resume_read = true,
            .resume_write = true,
            .atomic_rename = true,
            .chmod = std.Io.File.Permissions.has_executable_bit,
            .symlinks = true,
            .mtime_set = false,
            .server_search = false,
            // APFS is case-insensitive by default but configurable; the
            // backend cannot know per-volume without statfs.
            .case_sensitive = null,
        };
    }

    /// $HOME when set and absolute, else "/". The caller normalizes (HOME
    /// may carry a trailing slash); a bogus HOME surfaces as the listing's
    /// own not-found error rather than being second-guessed here.
    fn vtDefaultPath(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, buf: []u8) vfs.Error![]const u8 {
        _ = ctx;
        _ = io;
        try checkCancel(cancel, diag);
        const home: []const u8 = blk: {
            const env = std.c.getenv("HOME") orelse break :blk "/";
            const span = std.mem.span(env);
            if (span.len == 0 or span[0] != '/') break :blk "/";
            break :blk span;
        };
        if (home.len > buf.len) {
            diag.set(.permanent, 0, "HOME is longer than the path buffer", .{});
            return error.Unexpected;
        }
        @memcpy(buf[0..home.len], home);
        return buf[0..home.len];
    }

    fn vtStat(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!vfs.Entry {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        const st = self.root.statFile(io, rel(p), .{ .follow_symlinks = false }) catch |err|
            return mapErr(diag, err, "stat", p);
        // Entry.name aliases the caller's `p` (stat has no arena).
        var entry = entryFromStat(if (p.len == 1) "/" else path_mod.basename(p), st);
        entry.link_target = null;
        return entry;
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
        try checkCancel(cancel, diag);
        var dir = self.root.openDir(io, rel(p), .{ .iterate = true }) catch |err|
            return mapErr(diag, err, "list", p);
        defer dir.close(io);

        var batch: [list_batch_len]vfs.Entry = undefined;
        var n: usize = 0;
        var it = dir.iterate();
        while (true) {
            try checkCancel(cancel, diag);
            const dirent = it.next(io) catch |err|
                return mapErr(diag, err, "list", p);
            const de = dirent orelse break;
            // The entry can vanish between readdir and stat; skip races.
            const st = dir.statFile(io, de.name, .{ .follow_symlinks = false }) catch continue;
            var entry = entryFromStat(arena.dupe(u8, de.name) catch return oom(diag), st);
            if (st.kind == .sym_link) {
                var link_buf: [max_link_len]u8 = undefined;
                if (dir.readLink(io, de.name, &link_buf)) |len| {
                    entry.link_target = arena.dupe(u8, link_buf[0..len]) catch return oom(diag);
                } else |_| {}
            }
            batch[n] = entry;
            n += 1;
            if (n == batch.len) {
                sink.batch(batch[0..n]);
                n = 0;
            }
        }
        if (n > 0) sink.batch(batch[0..n]);
    }

    fn vtOpenRead(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        p: []const u8,
        offset: u64,
    ) vfs.Error!vfs.ReadStream {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        const file = self.root.openFile(io, rel(p), .{ .mode = .read_only, .allow_directory = false }) catch |err|
            return mapErr(diag, err, "open", p);
        errdefer file.close(io);
        const rc = self.gpa.create(ReadCtx) catch return oom(diag);
        errdefer self.gpa.destroy(rc);
        rc.* = .{
            .gpa = self.gpa,
            .file = file,
            .file_reader = undefined,
            .buffer = undefined,
        };
        rc.file_reader = file.reader(io, &rc.buffer);
        if (offset != 0) rc.file_reader.seekTo(offset) catch |err|
            return mapErr(diag, err, "seek", p);
        return .{
            .reader = &rc.file_reader.interface,
            .context = rc,
            .closeFn = ReadCtx.close,
        };
    }

    const ReadCtx = struct {
        gpa: Allocator,
        file: std.Io.File,
        file_reader: std.Io.File.Reader,
        buffer: [stream_buffer_len]u8,

        fn close(context: *anyopaque, io: std.Io) void {
            const rc: *ReadCtx = @ptrCast(@alignCast(context));
            rc.file.close(io);
            const gpa = rc.gpa;
            gpa.destroy(rc);
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
        try checkCancel(cancel, diag);
        const file = self.root.createFile(io, rel(p), .{
            .truncate = mode == .create_truncate,
        }) catch |err| return mapErr(diag, err, "create", p);
        errdefer file.close(io);
        const wc = self.gpa.create(WriteCtx) catch return oom(diag);
        errdefer self.gpa.destroy(wc);
        wc.* = .{
            .gpa = self.gpa,
            .file = file,
            .diag = diag,
            .file_writer = undefined,
            .buffer = undefined,
        };
        wc.file_writer = file.writer(io, &wc.buffer);
        if (mode != .create_truncate and offset != 0) {
            wc.file_writer.seekTo(offset) catch |err|
                return mapErr(diag, err, "seek", p);
        }
        return .{
            .writer = &wc.file_writer.interface,
            .context = wc,
            .closeFn = WriteCtx.close,
        };
    }

    const WriteCtx = struct {
        gpa: Allocator,
        file: std.Io.File,
        /// Captured at open; per the Vfs contract it outlives the stream.
        diag: *Diagnostics,
        file_writer: std.Io.File.Writer,
        buffer: [stream_buffer_len]u8,

        fn close(context: *anyopaque, io: std.Io) vfs.Error!void {
            const wc: *WriteCtx = @ptrCast(@alignCast(context));
            const gpa = wc.gpa;
            defer gpa.destroy(wc);
            defer wc.file.close(io);
            wc.file_writer.interface.flush() catch {
                wc.diag.set(.permanent, 0, "final flush failed writing local file", .{});
                return error.Unexpected;
            };
        }
    };

    fn vtMkdir(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        self.root.createDir(io, rel(p), .default_dir) catch |err|
            return mapErr(diag, err, "mkdir", p);
    }

    fn vtRemove(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, recursive: bool) vfs.Error!void {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        if (recursive) {
            self.root.deleteTree(io, rel(p)) catch |err|
                return mapErr(diag, err, "remove", p);
            return;
        }
        self.root.deleteFile(io, rel(p)) catch |err| switch (err) {
            error.IsDir => self.root.deleteDir(io, rel(p)) catch |dir_err|
                return mapErr(diag, dir_err, "rmdir", p),
            else => return mapErr(diag, err, "remove", p),
        };
    }

    fn vtRename(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, from: []const u8, to: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        self.root.rename(rel(from), self.root, rel(to), io) catch |err|
            return mapErr(diag, err, "rename", from);
    }

    fn vtChmod(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, mode: u16) vfs.Error!void {
        const self = fromCtx(ctx);
        try checkCancel(cancel, diag);
        const file = self.root.openFile(io, rel(p), .{ .mode = .read_only }) catch |err|
            return mapErr(diag, err, "chmod", p);
        defer file.close(io);
        file.setPermissions(io, .fromMode(mode)) catch |err|
            return mapErr(diag, err, "chmod", p);
    }
};

fn entryFromStat(name: []const u8, st: std.Io.File.Stat) vfs.Entry {
    return .{
        .name = name,
        .kind = switch (st.kind) {
            .file => .file,
            .directory => .dir,
            .sym_link => .symlink,
            .unknown => .unknown,
            else => .special,
        },
        .size = st.size,
        .mode = @intCast(st.permissions.toMode() & 0o7777),
        .mtime = st.mtime.toSeconds(),
    };
}

fn checkCancel(cancel: *const CancelToken, diag: *Diagnostics) vfs.Error!void {
    cancel.check() catch {
        diag.set(.cancel, 0, "canceled", .{});
        return error.Canceled;
    };
}

fn oom(diag: *Diagnostics) vfs.Error {
    diag.set(.transient, 0, "out of memory", .{});
    return error.OutOfMemory;
}

/// Classifies a filesystem error. Local failures are permanent (retry will
/// not fix a missing file); only cancellation is classed differently.
fn mapErr(diag: *Diagnostics, err: anyerror, what: []const u8, p: []const u8) vfs.Error {
    const mapped: vfs.Error = switch (err) {
        error.FileNotFound => error.NotFound,
        error.NotDir => error.NotADirectory,
        error.IsDir => error.IsADirectory,
        error.AccessDenied, error.PermissionDenied, error.ReadOnlyFileSystem => error.PermissionDenied,
        error.PathAlreadyExists => error.AlreadyExists,
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Unseekable => error.NotSupported,
        else => error.Unexpected,
    };
    diag.set(
        if (mapped == error.Canceled) .cancel else .permanent,
        0,
        "{s} {s}: {t}",
        .{ what, p, err },
    );
    return mapped;
}

// ---------------------------------------------------------------------------
// Tests (tmp dir; no network)
// ---------------------------------------------------------------------------

const testing = std.testing;
const snapshot = @import("snapshot.zig");

const TestFs = struct {
    tmp: std.testing.TmpDir,
    local: LocalVfs,
    cancel: CancelToken,
    diag: Diagnostics,

    fn init(fs: *TestFs) void {
        fs.tmp = std.testing.tmpDir(.{ .iterate = true });
        fs.local = .init(testing.allocator, fs.tmp.dir);
        fs.cancel = .{};
        fs.diag = .{};
    }

    fn deinit(fs: *TestFs) void {
        fs.tmp.cleanup();
    }

    fn iface(fs: *TestFs) vfs.Vfs {
        return fs.local.vfsInterface();
    }
};

test "local: list streams into a DirSnapshot builder with stat metadata" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();

    try fs.tmp.dir.writeFile(io, .{ .sub_path = "hello.txt", .data = "hello, relay" });
    try fs.tmp.dir.createDir(io, "subdir", .default_dir);
    try fs.tmp.dir.writeFile(io, .{ .sub_path = "subdir/inner.bin", .data = "x" });

    var builder = try snapshot.Builder.init(testing.allocator, "/", 1);
    var finishing = false;
    errdefer if (!finishing) builder.abandon();
    const v = fs.iface();
    try v.list(io, &fs.cancel, &fs.diag, "/", builder.arena(), builder.sink());
    finishing = true;
    const snap = try builder.finish();
    defer snap.unref();

    try testing.expectEqual(@as(usize, 2), snap.entries.len);
    const index = try snap.sortIndex(testing.allocator, .{});
    defer testing.allocator.free(index);
    // dirs first: subdir, then hello.txt
    try testing.expectEqualStrings("subdir", snap.entries[index[0]].name);
    try testing.expectEqual(vfs.EntryKind.dir, snap.entries[index[0]].kind);
    const hello = &snap.entries[index[1]];
    try testing.expectEqualStrings("hello.txt", hello.name);
    try testing.expectEqual(vfs.EntryKind.file, hello.kind);
    try testing.expectEqual(@as(?u64, 12), hello.size);
    try testing.expect(hello.mode != null);
    try testing.expect(hello.mtime != null and hello.mtime.? > 0);
}

test "local: stat file, dir, root, and NotFound classification" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();

    try fs.tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "abc" });
    try fs.tmp.dir.createDir(io, "d", .default_dir);
    const v = fs.iface();

    const fe = try v.stat(io, &fs.cancel, &fs.diag, "/a.txt");
    try testing.expectEqual(vfs.EntryKind.file, fe.kind);
    try testing.expectEqual(@as(?u64, 3), fe.size);
    try testing.expectEqualStrings("a.txt", fe.name);

    const de = try v.stat(io, &fs.cancel, &fs.diag, "/d");
    try testing.expectEqual(vfs.EntryKind.dir, de.kind);

    const re = try v.stat(io, &fs.cancel, &fs.diag, "/");
    try testing.expectEqual(vfs.EntryKind.dir, re.kind);
    try testing.expectEqualStrings("/", re.name);

    try testing.expectError(error.NotFound, v.stat(io, &fs.cancel, &fs.diag, "/missing"));
    try testing.expectEqual(diag_mod.ErrorClass.permanent, fs.diag.class);
    try testing.expect(std.mem.indexOf(u8, fs.diag.message, "/missing") != null);
}

test "local: openRead honors offset; openWrite truncate/resume/append" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();
    const v = fs.iface();

    // Write a fresh file through the interface.
    {
        const ws = try v.openWrite(io, &fs.cancel, &fs.diag, "/data.bin", 0, .create_truncate);
        try ws.writer.writeAll("0123456789");
        try ws.close(io);
    }
    // Read from offset 4.
    {
        const rs = try v.openRead(io, &fs.cancel, &fs.diag, "/data.bin", 4);
        defer rs.close(io);
        const got = try rs.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("456789", got);
    }
    // Resume at offset 5: overwrite the tail without truncating the head.
    {
        const ws = try v.openWrite(io, &fs.cancel, &fs.diag, "/data.bin", 5, .create_resume);
        try ws.writer.writeAll("XYZWV");
        try ws.close(io);
        const rs = try v.openRead(io, &fs.cancel, &fs.diag, "/data.bin", 0);
        defer rs.close(io);
        const got = try rs.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("01234XYZWV", got);
    }
    // Truncate replaces everything.
    {
        const ws = try v.openWrite(io, &fs.cancel, &fs.diag, "/data.bin", 0, .create_truncate);
        try ws.writer.writeAll("new");
        try ws.close(io);
        const st = try v.stat(io, &fs.cancel, &fs.diag, "/data.bin");
        try testing.expectEqual(@as(?u64, 3), st.size);
    }

    try testing.expectError(
        error.NotFound,
        v.openRead(io, &fs.cancel, &fs.diag, "/nope.bin", 0),
    );
}

test "local: mkdir, rename, chmod, remove (recursive walk)" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();
    const v = fs.iface();

    try v.mkdir(io, &fs.cancel, &fs.diag, "/nest");
    try v.mkdir(io, &fs.cancel, &fs.diag, "/nest/deep");
    try testing.expectError(error.AlreadyExists, v.mkdir(io, &fs.cancel, &fs.diag, "/nest"));
    try fs.tmp.dir.writeFile(io, .{ .sub_path = "nest/deep/f.txt", .data = "f" });

    try v.rename(io, &fs.cancel, &fs.diag, "/nest/deep/f.txt", "/nest/g.txt");
    try testing.expectError(error.NotFound, v.stat(io, &fs.cancel, &fs.diag, "/nest/deep/f.txt"));

    if (std.Io.File.Permissions.has_executable_bit) {
        try v.chmod(io, &fs.cancel, &fs.diag, "/nest/g.txt", 0o600);
        const st = try v.stat(io, &fs.cancel, &fs.diag, "/nest/g.txt");
        try testing.expectEqual(@as(?u16, 0o600), st.mode);
    }

    // Non-recursive remove refuses nothing for files, handles dirs.
    try v.remove(io, &fs.cancel, &fs.diag, "/nest/g.txt", false);
    try v.remove(io, &fs.cancel, &fs.diag, "/nest/deep", false);
    // Recursive remove walks a populated tree.
    try v.mkdir(io, &fs.cancel, &fs.diag, "/nest/again");
    try fs.tmp.dir.writeFile(io, .{ .sub_path = "nest/again/x", .data = "x" });
    try v.remove(io, &fs.cancel, &fs.diag, "/nest", true);
    try testing.expectError(error.NotFound, v.stat(io, &fs.cancel, &fs.diag, "/nest"));
}

test "local: symlink entries carry kind and target in listings" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();

    try fs.tmp.dir.writeFile(io, .{ .sub_path = "target.txt", .data = "t" });
    fs.tmp.dir.symLink(io, "target.txt", "link.txt", .{}) catch |err| switch (err) {
        // Filesystems without symlink support skip the test body.
        error.AccessDenied => return,
        else => return err,
    };

    var builder = try snapshot.Builder.init(testing.allocator, "/", 1);
    var finishing = false;
    errdefer if (!finishing) builder.abandon();
    const v = fs.iface();
    try v.list(io, &fs.cancel, &fs.diag, "/", builder.arena(), builder.sink());
    finishing = true;
    const snap = try builder.finish();
    defer snap.unref();

    var saw_link = false;
    for (snap.entries) |entry| {
        if (std.mem.eql(u8, entry.name, "link.txt")) {
            saw_link = true;
            try testing.expectEqual(vfs.EntryKind.symlink, entry.kind);
            try testing.expectEqualStrings("target.txt", entry.link_target.?);
        }
    }
    try testing.expect(saw_link);
}

test "local: cancellation short-circuits with .cancel class" {
    const io = testing.io;
    var fs: TestFs = undefined;
    fs.init();
    defer fs.deinit();
    const v = fs.iface();

    fs.cancel.cancel();
    try testing.expectError(error.Canceled, v.stat(io, &fs.cancel, &fs.diag, "/x"));
    try testing.expectEqual(diag_mod.ErrorClass.cancel, fs.diag.class);
    try testing.expectError(error.Canceled, v.list(io, &fs.cancel, &fs.diag, "/", testing.allocator, undefined));
}

test {
    std.testing.refAllDecls(@This());
}

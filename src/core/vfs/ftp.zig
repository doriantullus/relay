//! ftp — the FTP/FTPS Vfs backend: a thin adapter from the pinned Vfs
//! vtable onto the FtpClient engine (../proto/ftp/client.zig). Connections
//! come from the per-site pool: browse operations (stat/list/mkdir/...)
//! run on the dedicated browse connection, transfer streams check out a
//! transfer lease that lives exactly as long as the stream.
//!
//! Caps are mapped from the engine's FEAT bitset, refreshed on every
//! browse checkout. Engine diagnostics pass through untouched (the engine
//! already classifies per diag.zig); this layer only adds lease hygiene —
//! a connection that died mid-protocol is released broken so the pool
//! tears it down instead of reusing it.

const std = @import("std");
const vfs = @import("vfs.zig");
const path_mod = @import("path.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const diag_mod = @import("../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const site_pool = @import("../pool/site_pool.zig");
const lease_mod = @import("../pool/lease.zig");
const ftp_client = @import("../proto/ftp/client.zig");

const Allocator = std.mem.Allocator;
const Lease = lease_mod.Lease;

pub const FtpVfs = struct {
    gpa: Allocator,
    pool: *site_pool.SitePool,
    /// Engine FEAT bitset (packed ftp_client.Caps) from the most recent
    /// browse checkout; atomic because caps() may race a checkout.
    feat_bits: std.atomic.Value(u16) = .init(0),

    pub fn init(gpa: Allocator, pool: *site_pool.SitePool) FtpVfs {
        return .{ .gpa = gpa, .pool = pool };
    }

    pub fn vfsInterface(self: *FtpVfs) vfs.Vfs {
        return .{ .vtable = &vtable, .ctx = self };
    }

    const vtable: vfs.VTable = .{
        .caps = vtCaps,
        .stat = vtStat,
        .list = vtList,
        .openRead = vtOpenRead,
        .openWrite = vtOpenWrite,
        .mkdir = vtMkdir,
        .remove = vtRemove,
        .rename = vtRename,
        .chmod = vtChmod,
    };

    fn fromCtx(ctx: *anyopaque) *FtpVfs {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn capsFromFeat(c: ftp_client.Caps) vfs.Caps {
        return .{
            .resume_read = c.rest,
            .resume_write = c.rest,
            // RNFR/RNTO is core RFC 959; servers overwrite atomically.
            .atomic_rename = true,
            // SITE CHMOD is not FEAT-advertised; offer it and surface the
            // server's refusal.
            .chmod = true,
            .symlinks = false,
            .mtime_set = false,
            .server_search = false,
            .case_sensitive = null,
        };
    }

    fn vtCaps(ctx: *anyopaque) vfs.Caps {
        const self = fromCtx(ctx);
        const bits: u9 = @truncate(self.feat_bits.load(.monotonic));
        return capsFromFeat(@bitCast(bits));
    }

    /// Errors that leave the control connection in an unknowable state;
    /// the lease must die rather than return to the pool.
    fn isFatal(err: vfs.Error) bool {
        return switch (err) {
            error.ConnectionLost, error.Timeout, error.ProtocolViolation => true,
            else => false,
        };
    }

    fn checkoutBrowse(self: *FtpVfs, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!Lease {
        var lease = try self.pool.checkout(io, cancel, diag, .browse);
        const client = engineOf(&lease, diag) catch |err| {
            lease.markBroken();
            lease.release(io);
            return err;
        };
        self.feat_bits.store(@as(u9, @bitCast(client.caps)), .monotonic);
        return lease;
    }

    fn engineOf(lease: *Lease, diag: *Diagnostics) vfs.Error!*ftp_client.FtpClient {
        switch (lease.engine()) {
            .ftp => |client| return client,
            else => {
                diag.set(.permanent, 0, "protocol mismatch: FTP backend on a non-FTP connection", .{});
                return error.Unexpected;
            },
        }
    }

    // ------------------------------------------------------------------ //
    // Browse operations

    fn vtStat(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!vfs.Entry {
        const self = fromCtx(ctx);
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);

        // FTP has no stat: probe SIZE (file) then CWD (dir). Entry.name
        // aliases the caller's `p` (stat has no arena).
        var entry: vfs.Entry = .{ .name = if (p.len <= 1) "/" else path_mod.basename(p) };
        var found = false;
        if (client.caps.size) {
            if (client.size(io, cancel, diag, p)) |file_size| {
                entry.size = file_size;
                entry.kind = .file;
                found = true;
            } else |err| {
                if (isFatal(err)) {
                    lease.markBroken();
                    return err;
                }
                if (err == error.Canceled or err == error.AuthRequired or err == error.OutOfMemory) return err;
                // 550 etc.: not a plain file; fall through to the dir probe.
            }
        }
        if (!found) {
            if (client.cwd(io, cancel, diag, p)) {
                entry.kind = .dir;
                found = true;
            } else |err| {
                if (isFatal(err)) {
                    lease.markBroken();
                    return err;
                }
                if (err == error.Canceled or err == error.AuthRequired or err == error.OutOfMemory) return err;
            }
        }
        if (!found) return error.NotFound; // diag still has the server's last reply
        if (entry.kind == .file and client.caps.mdtm) {
            if (client.mdtm(io, cancel, diag, p)) |mtime| {
                entry.mtime = mtime;
            } else |err| {
                if (isFatal(err)) {
                    lease.markBroken();
                    return err;
                }
                // MDTM refusal is cosmetic; keep the entry.
            }
        }
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
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.list(io, cancel, diag, p, arena, sink) catch |err| {
            // A mid-listing failure (including cancel) leaves an unread
            // completion reply on the control connection: retire it.
            if (isFatal(err) or err == error.Canceled) lease.markBroken();
            return err;
        };
    }

    fn vtMkdir(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.mkd(io, cancel, diag, p) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtRename(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, from: []const u8, to: []const u8) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.rename(io, cancel, diag, from, to) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtChmod(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, mode: u16) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        client.chmod(io, cancel, diag, p, mode) catch |err| {
            if (isFatal(err)) lease.markBroken();
            return err;
        };
    }

    fn vtRemove(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, p: []const u8, recursive: bool) vfs.Error!void {
        const self = fromCtx(ctx);
        var lease = try self.checkoutBrowse(io, cancel, diag);
        defer lease.release(io);
        const client = try engineOf(&lease, diag);
        if (recursive) {
            return self.removeRecursive(io, cancel, diag, &lease, client, p, 0);
        }
        // DELE for files; a directory answers 550, then RMD decides.
        client.dele(io, cancel, diag, p) catch |err| {
            if (isFatal(err)) {
                lease.markBroken();
                return err;
            }
            if (err == error.Canceled or err == error.AuthRequired or err == error.OutOfMemory) return err;
            client.rmd(io, cancel, diag, p) catch |rmd_err| {
                if (isFatal(rmd_err)) lease.markBroken();
                return rmd_err;
            };
        };
    }

    const max_remove_depth = 64;

    /// Depth-first delete: DELE wins fast for plain files; directories are
    /// listed into a temporary arena, children removed, then RMD.
    fn removeRecursive(
        self: *FtpVfs,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        lease: *Lease,
        client: *ftp_client.FtpClient,
        p: []const u8,
        depth: usize,
    ) vfs.Error!void {
        if (depth > max_remove_depth) {
            diag.set(.permanent, 0, "remove: directory tree deeper than {d} levels", .{max_remove_depth});
            return error.Unexpected;
        }
        if (client.dele(io, cancel, diag, p)) {
            return;
        } else |err| {
            if (isFatal(err)) {
                lease.markBroken();
                return err;
            }
            if (err == error.Canceled or err == error.AuthRequired or err == error.OutOfMemory) return err;
        }

        var arena_inst: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_inst.deinit();
        var collector: ListCollector = .{ .arena = arena_inst.allocator() };
        client.list(io, cancel, diag, p, arena_inst.allocator(), collector.sink()) catch |err| {
            if (isFatal(err) or err == error.Canceled) lease.markBroken();
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
                client.dele(io, cancel, diag, child) catch |err| {
                    if (isFatal(err)) lease.markBroken();
                    return err;
                };
            }
        }
        client.rmd(io, cancel, diag, p) catch |err| {
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
        const inner = client.retr(io, cancel, diag, p, offset) catch |err| {
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
        /// contract); its class after close tells lease hygiene whether
        /// the connection dropped. Use a fresh Diagnostics per transfer.
        diag: *Diagnostics,

        fn close(context: *anyopaque, io: std.Io) void {
            const sc: *ReadStreamCtx = @ptrCast(@alignCast(context));
            sc.inner.close(io); // engine ABORs + resyncs if incomplete
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
        const stor_mode: ftp_client.FtpClient.StorMode = switch (mode) {
            .create_truncate, .create_resume => .store,
            .append => .append,
        };
        const stor_offset: u64 = if (mode == .create_resume) offset else 0;
        const inner = client.stor(io, cancel, diag, p, stor_offset, stor_mode) catch |err| {
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
// Tests: caps mapping (pure) + ScriptedServer end-to-end through Vfs
// ---------------------------------------------------------------------------

const testing = std.testing;
const snapshot = @import("snapshot.zig");
const ftp_script = @import("../testutil/ftp_script.zig");
const transcript_mod = @import("../log/transcript.zig");
const ScriptedServer = ftp_script.ScriptedServer;
const Step = ftp_script.Step;

test "capsFromFeat maps the FEAT bitset" {
    const none = FtpVfs.capsFromFeat(.{});
    try testing.expect(!none.resume_read and !none.resume_write);
    try testing.expect(none.atomic_rename and none.chmod);
    try testing.expect(!none.symlinks and none.case_sensitive == null);

    const with_rest = FtpVfs.capsFromFeat(.{ .rest = true, .mlsd = true });
    try testing.expect(with_rest.resume_read and with_rest.resume_write);
}

/// Pool ConnFactory whose every connect spins up one ScriptedServer and a
/// fully logged-in FtpClient over it. Scripts are consumed in order:
/// script 0 backs the first connect (browse), script 1 the second, ...
const ScriptedFtpFactory = struct {
    gpa: Allocator,
    scripts: []const []const Step,
    transcript: *transcript_mod.Transcript,
    next: usize = 0,
    script_failures: usize = 0,

    const ConnCtx = struct {
        factory: *ScriptedFtpFactory,
        server: *ScriptedServer,
        client: *ftp_client.FtpClient,
    };

    fn factory(f: *ScriptedFtpFactory) site_pool.ConnFactory {
        return .{ .ctx = f, .connectFn = connect };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        site: *const site_pool.SiteConfig,
        role: site_pool.Role,
    ) vfs.Error!site_pool.Conn {
        _ = role;
        const f: *ScriptedFtpFactory = @ptrCast(@alignCast(ctx));
        if (f.next >= f.scripts.len) {
            diag.set(.permanent, 0, "scripted factory: no script left for this connect", .{});
            return error.Unexpected;
        }
        const script = f.scripts[f.next];
        f.next += 1;

        const server = f.gpa.create(ScriptedServer) catch return error.OutOfMemory;
        errdefer f.gpa.destroy(server);
        server.init(f.gpa, io, script) catch {
            diag.set(.permanent, 0, "scripted factory: server init failed", .{});
            return error.Unexpected;
        };
        errdefer server.deinit();

        const client = f.gpa.create(ftp_client.FtpClient) catch return error.OutOfMemory;
        errdefer f.gpa.destroy(client);
        client.* = ftp_client.FtpClient.init(
            f.gpa,
            server.clientReader(),
            server.clientWriter(),
            server.factory(),
            f.transcript,
            .{ .host = site.host },
        );
        errdefer client.deinit();

        // Full connect sequence with credentials fetched via the callback.
        const provider = site.creds orelse {
            diag.set(.auth, 0, "no credential provider configured", .{});
            return error.AuthRequired;
        };
        const creds = try provider.fetch(diag);
        try client.connect(io, cancel, diag, .{ .user = creds.user, .pass = creds.secret });

        const cc = f.gpa.create(ConnCtx) catch return error.OutOfMemory;
        cc.* = .{ .factory = f, .server = server, .client = client };
        return .{ .engine = .{ .ftp = client }, .ctx = cc, .vtable = &conn_vtable };
    }

    const conn_vtable: site_pool.Conn.VTable = .{
        .noop = connNoop,
        .alive = connAlive,
        .close = connClose,
    };

    fn connNoop(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!void {
        const cc: *ConnCtx = @ptrCast(@alignCast(ctx));
        return cc.client.noop(io, cancel, diag);
    }

    fn connAlive(ctx: *anyopaque) bool {
        _ = ctx;
        return true;
    }

    fn connClose(ctx: *anyopaque, io: std.Io) void {
        _ = io;
        const cc: *ConnCtx = @ptrCast(@alignCast(ctx));
        const f = cc.factory;
        const msg = cc.server.joinQuiet();
        if (msg.len != 0) {
            f.script_failures += 1;
            std.debug.print("--- scripted ftp factory failure ---\n{s}\n", .{msg});
        }
        cc.client.deinit();
        cc.server.deinit();
        f.gpa.destroy(cc.client);
        f.gpa.destroy(cc.server);
        f.gpa.destroy(cc);
    }
};

const TestCreds = struct {
    fetches: usize = 0,

    fn provider(tc: *TestCreds) site_pool.CredProvider {
        return .{ .ctx = tc, .fetchFn = fetch };
    }

    fn fetch(ctx: *anyopaque, diag: *Diagnostics) vfs.Error!site_pool.Credentials {
        _ = diag;
        const tc: *TestCreds = @ptrCast(@alignCast(ctx));
        tc.fetches += 1;
        return .{ .user = "alice", .secret = "hunter2" };
    }
};

const login_steps = [_]Step{
    .{ .reply = "220 relay-test FTP ready" },
    .{ .expect = "USER alice" },
    .{ .reply = "331 Password required" },
    .{ .expect = "PASS hunter2" },
    .{ .reply = "230 Logged in" },
    .{ .expect = "FEAT" },
    .{ .reply_multiline = &.{
        "211-Features:",
        " MLSD",
        " UTF8",
        " EPSV",
        " REST STREAM",
        " SIZE",
        " MDTM",
        "211 End",
    } },
    .{ .expect = "OPTS UTF8 ON" },
    .{ .reply = "200 ok" },
    .{ .expect = "TYPE I" },
    .{ .reply = "200 ok" },
};

test "ftp backend end-to-end: list streams into a DirSnapshot, stat, read stream over a transfer lease" {
    const io = testing.io;

    // Script 0: the browse connection (login + MLSD listing + SIZE/MDTM).
    const browse_script = login_steps ++ [_]Step{
        .{ .expect = "EPSV" },
        .{ .open_data = 3010 },
        .{ .reply = "229 Entering Extended Passive Mode (|||3010|)" },
        .{ .expect = "MLSD /pub" },
        .{ .reply = "150 Opening data connection for MLSD" },
        .{ .data_send = "type=file;size=12;modify=20240910084528; hello.txt\r\n" ++
            "type=dir;modify=20240101000000; sub\r\n" ++
            "type=file;size=3; b.bin\r\n" },
        .close_data,
        .{ .reply = "226 Transfer complete" },
        .{ .expect = "SIZE /pub/hello.txt" },
        .{ .reply = "213 12" },
        .{ .expect = "MDTM /pub/hello.txt" },
        .{ .reply = "213 20240910084528" },
    };
    // Script 1: the transfer connection (login + RETR).
    const transfer_script = login_steps ++ [_]Step{
        .{ .expect = "EPSV" },
        .{ .open_data = 3011 },
        .{ .reply = "229 ok (|||3011|)" },
        .{ .expect = "RETR /pub/hello.txt" },
        .{ .reply = "150 sending" },
        .{ .data_send = "hello, relay" },
        .close_data,
        .{ .reply = "226 Transfer complete" },
    };

    var transcript = try transcript_mod.Transcript.init(testing.allocator, .{ .capacity = 256, .max_line_bytes = 128 });
    defer transcript.deinit();
    var factory: ScriptedFtpFactory = .{
        .gpa = testing.allocator,
        .scripts = &.{ &browse_script, &transfer_script },
        .transcript = &transcript,
    };
    var creds: TestCreds = .{};
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .site_id = 7,
        .protocol = .ftp,
        .host = "test.example",
        .creds = creds.provider(),
        .factory = factory.factory(),
        .max_transfer_conns = 1,
        .keepalive_interval_ms = 0,
    }, .{});

    var backend = FtpVfs.init(testing.allocator, &pool);
    const v = backend.vfsInterface();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    // Caps are unknown before the first connect, mapped from FEAT after.
    try testing.expect(!v.caps().resume_read);

    // list -> DirSnapshot via the builder, end to end.
    var builder = try snapshot.Builder.init(testing.allocator, "/pub", 1);
    var finishing = false;
    errdefer if (!finishing) builder.abandon();
    try v.list(io, &cancel, &diag, "/pub", builder.arena(), builder.sink());
    finishing = true;
    const snap = try builder.finish();
    defer snap.unref();

    try testing.expectEqual(@as(usize, 3), snap.entries.len);
    const index = try snap.sortIndex(testing.allocator, .{});
    defer testing.allocator.free(index);
    try testing.expectEqualStrings("sub", snap.entries[index[0]].name); // dirs first
    try testing.expectEqualStrings("b.bin", snap.entries[index[1]].name);
    try testing.expectEqualStrings("hello.txt", snap.entries[index[2]].name);
    try testing.expectEqual(@as(?u64, 12), snap.entries[index[2]].size);

    // FEAT flowed through into Vfs caps.
    try testing.expect(v.caps().resume_read);
    try testing.expect(v.caps().resume_write);
    try testing.expectEqual(@as(usize, 1), creds.fetches);

    // stat over the same browse connection (no reconnect).
    const entry = try v.stat(io, &cancel, &diag, "/pub/hello.txt");
    try testing.expectEqual(vfs.EntryKind.file, entry.kind);
    try testing.expectEqual(@as(?u64, 12), entry.size);
    try testing.expectEqual(@as(?i64, 1725957928), entry.mtime);

    // Download through a transfer lease held for the stream's lifetime.
    var read_diag: Diagnostics = .{};
    const rs = try v.openRead(io, &cancel, &read_diag, "/pub/hello.txt", 0);
    const got = try rs.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("hello, relay", got);
    rs.close(io);

    // Two connects total: one browse, one transfer; creds fetched per conn.
    try testing.expectEqual(@as(usize, 2), factory.next);
    try testing.expectEqual(@as(usize, 2), creds.fetches);

    pool.disconnect(io);
    pool.deinit(io);
    try testing.expectEqual(@as(usize, 0), factory.script_failures);
}

test "ftp backend: mkdir, rename, chmod, remove run on the browse connection" {
    const io = testing.io;
    const browse_script = login_steps ++ [_]Step{
        .{ .expect = "MKD /photos" },
        .{ .reply = "257 \"/photos\" created" },
        .{ .expect = "RNFR /a.txt" },
        .{ .reply = "350 Ready" },
        .{ .expect = "RNTO /b.txt" },
        .{ .reply = "250 Rename successful" },
        .{ .expect = "SITE CHMOD 644 /b.txt" },
        .{ .reply = "200 ok" },
        .{ .expect = "DELE /b.txt" },
        .{ .reply = "250 Deleted" },
        .{ .expect = "DELE /photos" },
        .{ .reply = "550 /photos: Is a directory" },
        .{ .expect = "RMD /photos" },
        .{ .reply = "250 Removed" },
        .{ .expect = "DELE /missing" },
        .{ .reply = "550 not found" },
        .{ .expect = "RMD /missing" },
        .{ .reply = "550 not found" },
    };

    var transcript = try transcript_mod.Transcript.init(testing.allocator, .{ .capacity = 256, .max_line_bytes = 128 });
    defer transcript.deinit();
    var factory: ScriptedFtpFactory = .{
        .gpa = testing.allocator,
        .scripts = &.{&browse_script},
        .transcript = &transcript,
    };
    var creds: TestCreds = .{};
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .host = "test.example",
        .creds = creds.provider(),
        .factory = factory.factory(),
        .keepalive_interval_ms = 0,
    }, .{});

    var backend = FtpVfs.init(testing.allocator, &pool);
    const v = backend.vfsInterface();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try v.mkdir(io, &cancel, &diag, "/photos");
    try v.rename(io, &cancel, &diag, "/a.txt", "/b.txt");
    try v.chmod(io, &cancel, &diag, "/b.txt", 0o644);
    try v.remove(io, &cancel, &diag, "/b.txt", false);
    try v.remove(io, &cancel, &diag, "/photos", false); // DELE 550 -> RMD
    try testing.expectError(error.NotFound, v.remove(io, &cancel, &diag, "/missing", false));
    try testing.expectEqual(@as(u32, 550), diag.protocol_code);

    pool.disconnect(io);
    pool.deinit(io);
    try testing.expectEqual(@as(usize, 0), factory.script_failures);
    try testing.expectEqual(@as(usize, 1), factory.next); // one browse conn did it all
}

test {
    std.testing.refAllDecls(@This());
}

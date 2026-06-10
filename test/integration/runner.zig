//! runner — Relay's live integration suite (`zig build integration`).
//!
//! Drives the real protocol engines (proto/ftp/client.zig over real TCP +
//! LibreSSL TLS, proto/sftp over libssh2) against the Docker servers
//! declared in docker-compose.yml: vsftpd (FTPS, require_ssl_reuse=YES),
//! pure-ftpd (plain FTP + AUTH TLS), ProFTPD (mod_tls, default session-
//! reuse enforcement) and OpenSSH (atmoz/sftp).
//!
//! The runner owns the compose lifecycle (down → up --build --wait →
//! matrix → down). When no usable docker daemon is reachable it prints a
//! skip notice and exits 0, so docker-less environments never fail.
//!
//! Flags:
//!   --compose-file <path>   compose file (passed by build.zig)
//!   --only <substring>      run only matching servers (e.g. "vsftpd")
//!   --keep                  leave the containers running afterwards
//!   --no-compose            assume the servers are already up (no
//!                           down/up/down; provisioning still runs)

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const core = @import("relay_core");
const CancelToken = core.cancel.CancelToken;
const diag_mod = core.diag;
const Diagnostics = diag_mod.Diagnostics;
const vfs = core.vfs.iface;
const ftp = core.ftp.client;
const data_conn = core.ftp.data_conn;
const tls_libressl = core.tls.libressl;
const transcript_mod = core.transcript;
const session_mod = core.sftp.session;
const sftp_mod = core.sftp.client;
const SshSession = session_mod.SshSession;
const SftpClient = sftp_mod.SftpClient;

const project = "relay-integration";
const username = "relay";
const password = "relaypw";

const big_len: usize = 10 * 1024 * 1024;
const half_len: usize = big_len / 2;
const sftp_resume_at: usize = 6 * 1024 * 1024;
const tree_dirs: usize = 5;
const tree_files_per_dir: usize = 1000;

// ---------------------------------------------------------------------------
// servers under test
// ---------------------------------------------------------------------------

const FtpSpec = struct {
    /// Row label; also the remote file-name prefix (specs may share a
    /// server, so their files must not collide).
    name: []const u8,
    /// compose service name (docker exec target).
    service: []const u8,
    port: u16,
    tls: bool,
    /// Server advertises MLSD (vsftpd never does).
    mlsd: bool,
    /// vsftpd require_ssl_reuse=YES: also probe that turning reuse OFF
    /// fails loudly, proving the suite exercises the resumption path.
    reuse_probe: bool,
};

const ftp_specs = [_]FtpSpec{
    .{ .name = "pureftpd-ftp", .service = "pureftpd", .port = 42221, .tls = false, .mlsd = true, .reuse_probe = false },
    .{ .name = "pureftpd-ftps", .service = "pureftpd", .port = 42221, .tls = true, .mlsd = true, .reuse_probe = false },
    .{ .name = "vsftpd-ftps", .service = "vsftpd", .port = 42121, .tls = true, .mlsd = false, .reuse_probe = true },
    .{ .name = "proftpd-ftps", .service = "proftpd", .port = 42321, .tls = true, .mlsd = true, .reuse_probe = false },
};

const sftp_port: u16 = 42422;

// ---------------------------------------------------------------------------
// result table
// ---------------------------------------------------------------------------

const Status = enum { pass, fail, skip };

const Row = struct {
    server: []const u8,
    test_name: []const u8,
    status: Status,
    ms: u64,
    msg_buf: [192]u8 = undefined,
    msg_len: usize = 0,

    fn msg(r: *const Row) []const u8 {
        return r.msg_buf[0..r.msg_len];
    }
};

const Runtime = struct {
    gpa: Allocator,
    io: Io,
    compose_file: []const u8,
    only: ?[]const u8,
    keep: bool,
    no_compose: bool,
    rows: std.ArrayList(Row),

    fn addRow(rt: *Runtime, server: []const u8, test_name: []const u8, status: Status, ms: u64, detail: []const u8) void {
        var row: Row = .{ .server = server, .test_name = test_name, .status = status, .ms = ms };
        const n = @min(detail.len, row.msg_buf.len);
        @memcpy(row.msg_buf[0..n], detail[0..n]);
        row.msg_len = n;
        rt.rows.append(rt.gpa, row) catch {};
        const label = switch (status) {
            .pass => "PASS",
            .fail => "FAIL",
            .skip => "SKIP",
        };
        std.debug.print("  {s:<16} {s:<28} {s} ({d} ms) {s}\n", .{ server, test_name, label, ms, row.msg() });
    }

    fn anyFailure(rt: *const Runtime) bool {
        for (rt.rows.items) |row| if (row.status == .fail) return true;
        return false;
    }
};

/// Per-test scratch shared with the helpers: the diagnostics every engine
/// call fills (reported next to the error on failure) and a free-form note
/// (timings) shown next to PASS.
const TestCtx = struct {
    rt: *Runtime,
    diag: Diagnostics = .{},
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,

    fn gpa(tc: *TestCtx) Allocator {
        return tc.rt.gpa;
    }
    fn io(tc: *TestCtx) Io {
        return tc.rt.io;
    }

    fn notef(tc: *TestCtx, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&tc.note_buf, fmt, args) catch return;
        tc.note_len = s.len;
    }
    fn note(tc: *const TestCtx) []const u8 {
        return tc.note_buf[0..tc.note_len];
    }
};

fn nowTs(io: Io) Io.Clock.Timestamp {
    return .now(io, .awake);
}

fn elapsedMs(io: Io, t0: Io.Clock.Timestamp) u64 {
    const ns = t0.durationTo(nowTs(io)).raw.nanoseconds;
    if (ns <= 0) return 0;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

// ---------------------------------------------------------------------------
// docker / compose plumbing
// ---------------------------------------------------------------------------

fn runCmd(rt: *Runtime, argv: []const []const u8) error{ CmdFailed, OutOfMemory }![]u8 {
    const res = std.process.run(rt.gpa, rt.io, .{ .argv = argv }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CmdFailed,
    };
    defer rt.gpa.free(res.stderr);
    switch (res.term) {
        .exited => |code| if (code == 0) return res.stdout,
        else => {},
    }
    std.debug.print("command failed: {s} ...\n--- stderr ---\n{s}\n", .{ argv[0], res.stderr });
    rt.gpa.free(res.stdout);
    return error.CmdFailed;
}

fn cmdOk(rt: *Runtime, argv: []const []const u8) bool {
    const out = runCmd(rt, argv) catch return false;
    rt.gpa.free(out);
    return true;
}

fn compose(rt: *Runtime, extra: []const []const u8) error{ CmdFailed, OutOfMemory }![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(rt.gpa);
    try argv.appendSlice(rt.gpa, &.{ "docker", "compose", "-f", rt.compose_file, "-p", project });
    try argv.appendSlice(rt.gpa, extra);
    return runCmd(rt, argv.items);
}

fn composeOk(rt: *Runtime, extra: []const []const u8) bool {
    const out = compose(rt, extra) catch return false;
    rt.gpa.free(out);
    return true;
}

/// `docker compose exec` — provisioning shell snippets inside a service.
fn execInService(rt: *Runtime, service: []const u8, script: []const u8) !void {
    const out = try compose(rt, &.{ "exec", "-T", service, "sh", "-ec", script });
    rt.gpa.free(out);
}

/// One idempotent 5k-file tree: many/d0..d4 with 1000 files each.
const tree_script_body =
    \\cd "$ROOT"
    \\mkdir -p many
    \\cd many
    \\for d in d0 d1 d2 d3 d4; do
    \\  mkdir -p $d
    \\  seq 0 999 | sed "s|^|$d/f|" | xargs touch
    \\done
;

fn provisionFtp(rt: *Runtime, service: []const u8) !void {
    const script = "ROOT=/home/relay\n" ++ tree_script_body ++ "\nchown -R relay:relay /home/relay\n";
    try execInService(rt, service, script);
}

fn provisionSftp(rt: *Runtime, authorized_line: []const u8) !void {
    var buf: [1536]u8 = undefined;
    const script = try std.fmt.bufPrint(&buf, "ROOT=/home/relay/upload\nmkdir -p \"$ROOT\"\n" ++ tree_script_body ++
        \\
        \\mkdir -p /home/relay/.ssh
        \\echo '{s}' > /home/relay/.ssh/authorized_keys
        \\chown -R 1001:100 /home/relay/upload /home/relay/.ssh
        \\chmod 700 /home/relay/.ssh
        \\chmod 600 /home/relay/.ssh/authorized_keys
        \\
    , .{authorized_line});
    try execInService(rt, "sftp", script);
}

// ---------------------------------------------------------------------------
// transfer payload pattern (verifiable at any offset, never held in memory)
// ---------------------------------------------------------------------------

fn patternByte(i: usize) u8 {
    return @truncate(i *% 131 +% (i >> 13));
}

// ---------------------------------------------------------------------------
// FTP rig: real TCP control connection + TCP data-connection factory
// ---------------------------------------------------------------------------

/// Production-shaped passive-mode dialer: real TCP connect, fd exposed for
/// the FTPS data-connection TLS handshake.
const TcpFactory = struct {
    gpa: Allocator,

    fn factory(f: *TcpFactory) data_conn.DataConnFactory {
        return .{ .context = f, .dialFn = dial };
    }

    fn dial(
        ctx: *anyopaque,
        io: Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) data_conn.DialError!data_conn.DataConn {
        const f: *TcpFactory = @ptrCast(@alignCast(ctx));
        cancel.check() catch {
            diag.set(.cancel, 0, "canceled before data dial", .{});
            return error.Canceled;
        };
        const addr = Io.net.IpAddress.resolve(io, host, port) catch {
            diag.set(.transient, 0, "unparseable data address {s}:{d}", .{ host, port });
            return error.Unexpected;
        };
        const stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
            diag.set(.transient, 0, "data dial {s}:{d} failed: {t}", .{ host, port, err });
            if (err == error.ConnectionRefused) return error.ConnectionRefused;
            return error.ConnectionLost;
        };
        const conn = f.gpa.create(TcpDataConn) catch {
            stream.close(io);
            diag.set(.transient, 0, "out of memory dialing data connection", .{});
            return error.Unexpected;
        };
        conn.attach(f.gpa, io, stream);
        return .{
            .reader = &conn.rd.interface,
            .writer = &conn.wr.interface,
            .context = conn,
            .vtable = &tcp_conn_vtable,
            .fd = stream.socket.handle,
        };
    }
};

const TcpDataConn = struct {
    gpa: Allocator,
    io: Io,
    stream: Io.net.Stream,
    rd: Io.net.Stream.Reader,
    wr: Io.net.Stream.Writer,
    write_closed: bool,
    rbuf: [64 * 1024]u8,
    wbuf: [64 * 1024]u8,

    /// In-place init: the stream interfaces point at interior buffers, so
    /// a TcpDataConn is pinned once attached (hence the heap allocation).
    fn attach(conn: *TcpDataConn, gpa: Allocator, io: Io, stream: Io.net.Stream) void {
        conn.gpa = gpa;
        conn.io = io;
        conn.stream = stream;
        conn.write_closed = false;
        conn.rd = stream.reader(io, &conn.rbuf);
        conn.wr = stream.writer(io, &conn.wbuf);
    }
};

const tcp_conn_vtable: data_conn.DataConn.VTable = .{
    .closeWrite = tcpCloseWrite,
    .close = tcpClose,
};

fn tcpCloseWrite(ctx: *anyopaque) Io.Writer.Error!void {
    const conn: *TcpDataConn = @ptrCast(@alignCast(ctx));
    if (conn.write_closed) return;
    try conn.wr.interface.flush();
    conn.write_closed = true;
    conn.stream.shutdown(conn.io, .send) catch return error.WriteFailed;
}

fn tcpClose(ctx: *anyopaque) void {
    const conn: *TcpDataConn = @ptrCast(@alignCast(ctx));
    conn.wr.interface.flush() catch {};
    conn.stream.close(conn.io);
    const gpa = conn.gpa;
    conn.* = undefined;
    gpa.destroy(conn);
}

const FtpOpenOpts = struct {
    disable_session_reuse: bool = false,
};

/// One live FTP/FTPS control connection wrapped around FtpClient. Heap-
/// allocated and pinned: the client points at the interior stream buffers.
const FtpRig = struct {
    gpa: Allocator,
    io: Io,
    stream: Io.net.Stream,
    rd: Io.net.Stream.Reader,
    wr: Io.net.Stream.Writer,
    transcript: transcript_mod.Transcript,
    factory_ctx: TcpFactory,
    provider: ?*tls_libressl.LibresslProvider,
    client: ftp.FtpClient,
    cancel: CancelToken,
    diag: *Diagnostics,
    rbuf: [4096]u8,
    wbuf: [4096]u8,

    /// Opens with retries: vsftpd's standalone listener segfaults on TLS
    /// session teardown on linux/arm64 (every build tested) and runs under
    /// a restart loop in its container — ride over the restart gap.
    fn open(tc: *TestCtx, spec: *const FtpSpec, opts: FtpOpenOpts) !*FtpRig {
        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            return openOnce(tc, spec, opts) catch |err| switch (err) {
                error.ConnectionLost, error.ConnectionRefused, error.ConnectionResetByPeer => {
                    if (attempt >= 20) return err;
                    tc.diag.clear();
                    Io.sleep(tc.io(), .{ .nanoseconds = 250 * std.time.ns_per_ms }, .awake) catch {};
                    continue;
                },
                else => return err,
            };
        }
    }

    fn openOnce(tc: *TestCtx, spec: *const FtpSpec, opts: FtpOpenOpts) !*FtpRig {
        const gpa = tc.gpa();
        const io = tc.io();
        const rig = try gpa.create(FtpRig);
        errdefer gpa.destroy(rig);
        rig.gpa = gpa;
        rig.io = io;
        rig.cancel = .{};
        rig.diag = &tc.diag;
        rig.provider = null;
        rig.factory_ctx = .{ .gpa = gpa };

        const addr = try Io.net.IpAddress.resolve(io, "127.0.0.1", spec.port);
        rig.stream = try addr.connect(io, .{ .mode = .stream });
        errdefer rig.stream.close(io);
        rig.rd = rig.stream.reader(io, &rig.rbuf);
        rig.wr = rig.stream.writer(io, &rig.wbuf);

        rig.transcript = try transcript_mod.Transcript.init(gpa, .{ .capacity = 256, .max_line_bytes = 256 });
        errdefer rig.transcript.deinit();

        var client_opts: ftp.Options = .{
            .host = "127.0.0.1",
            .control_peer_ip = .{ 127, 0, 0, 1 },
            .control_fd = rig.stream.socket.handle,
            .data_mode = .passive,
        };
        if (spec.tls) {
            const p = try tls_libressl.LibresslProvider.init(gpa, .{});
            rig.provider = p;
            client_opts.tls = p.provider();
            client_opts.tls_mode = .explicit;
            // Throwaway self-signed server certs; verification is unit- and
            // spike-tested, session reuse is what this suite is for.
            client_opts.insecure_skip_verify = true;
            client_opts.disable_session_reuse = opts.disable_session_reuse;
        }
        errdefer if (rig.provider) |p| p.deinit();

        rig.client = ftp.FtpClient.init(
            gpa,
            &rig.rd.interface,
            &rig.wr.interface,
            rig.factory_ctx.factory(),
            &rig.transcript,
            client_opts,
        );
        errdefer rig.client.deinit();

        try rig.client.connect(io, &rig.cancel, rig.diag, .{ .user = username, .pass = password });
        return rig;
    }

    /// Graceful teardown (QUIT best-effort).
    fn close(rig: *FtpRig) void {
        rig.client.quit(rig.io, &rig.cancel, rig.diag) catch {};
        rig.kill();
    }

    /// Abrupt teardown: no QUIT, any open transfer hard-closed — the
    /// "kill at 50%" path of the resume tests.
    fn kill(rig: *FtpRig) void {
        const gpa = rig.gpa;
        rig.client.deinit();
        if (rig.provider) |p| p.deinit();
        rig.stream.close(rig.io);
        rig.transcript.deinit();
        gpa.destroy(rig);
    }
};

// -- FTP transfer helpers ---------------------------------------------------

fn ftpUploadPattern(rig: *FtpRig, path: []const u8, from: usize, to: usize) !void {
    const ws = try rig.client.stor(rig.io, &rig.cancel, rig.diag, path, from, .store);
    var closed = false;
    errdefer if (!closed) {
        ws.close(rig.io) catch {};
    };
    var chunk: [64 * 1024]u8 = undefined;
    var off = from;
    while (off < to) {
        const n = @min(chunk.len, to - off);
        for (chunk[0..n], 0..) |*b, i| b.* = patternByte(off + i);
        try ws.writer.writeAll(chunk[0..n]);
        off += n;
    }
    closed = true;
    try ws.close(rig.io);
}

/// Downloads `path` from `offset`, byte-compares against the pattern, and
/// requires exactly `total` bytes of file.
fn ftpVerifyDownload(rig: *FtpRig, path: []const u8, offset: usize, total: usize) !void {
    const rs = try rig.client.retr(rig.io, &rig.cancel, rig.diag, path, offset);
    defer rs.close(rig.io);
    var chunk: [64 * 1024]u8 = undefined;
    var off = offset;
    while (true) {
        const n = try rs.reader.readSliceShort(&chunk);
        for (chunk[0..n], 0..) |b, i| {
            if (b != patternByte(off + i)) return error.PayloadMismatch;
        }
        off += n;
        if (n < chunk.len) break;
    }
    if (off != total) return error.ShortDownload;
}

const ListSink = struct {
    entries: usize = 0,
    files: usize = 0,
    dirs: usize = 0,
    needle: []const u8 = "",
    found: bool = false,

    fn batchCb(ctx: *anyopaque, batch: []const vfs.Entry) void {
        const s: *ListSink = @ptrCast(@alignCast(ctx));
        for (batch) |e| {
            s.entries += 1;
            switch (e.kind) {
                .file => s.files += 1,
                .dir => s.dirs += 1,
                else => {},
            }
            if (s.needle.len != 0 and std.mem.eql(u8, e.name, s.needle)) s.found = true;
        }
    }

    fn sink(s: *ListSink) vfs.ListingSink {
        return .{ .context = s, .batchFn = batchCb };
    }
};

fn ftpList(rig: *FtpRig, path: []const u8, s: *ListSink) !void {
    var arena: std.heap.ArenaAllocator = .init(rig.gpa);
    defer arena.deinit();
    try rig.client.list(rig.io, &rig.cancel, rig.diag, path, arena.allocator(), s.sink());
}

/// Counts the provisioned 5k tree through whichever listing path the
/// client currently has enabled (MLSD or LIST).
fn countTree(rig: *FtpRig) !usize {
    var root: ListSink = .{};
    try ftpList(rig, "/many", &root);
    if (root.dirs != tree_dirs) return error.TreeRootMismatch;
    var total: usize = 0;
    for (0..tree_dirs) |d| {
        var buf: [16]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "/many/d{d}", .{d}) catch unreachable;
        var s: ListSink = .{};
        try ftpList(rig, path, &s);
        if (s.entries != tree_files_per_dir) return error.TreeDirMismatch;
        if (s.files != tree_files_per_dir) return error.TreeKindMismatch;
        total += s.entries;
    }
    return total;
}

/// Spec-scoped remote path (specs can share a server).
fn specPath(spec: *const FtpSpec, buf: []u8, comptime suffix: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "/{s}{s}", .{ spec.name, suffix }) catch unreachable;
}

// ---------------------------------------------------------------------------
// FTP matrix
// ---------------------------------------------------------------------------

fn ftpConnectAuth(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf: [256]u8 = undefined;
    const cwd = try rig.client.pwd(rig.io, &rig.cancel, rig.diag, &buf);
    if (!std.mem.eql(u8, cwd, "/")) return error.UnexpectedPwd;
    // ProFTPD advertises MLST only (per RFC 3659, MLSD is implied).
    if (spec.mlsd and !rig.client.caps.mlsd and !rig.client.caps.mlst) return error.MlsdNotAdvertised;
    if (!rig.client.caps.rest) return error.RestNotAdvertised;
}

fn ftpMlsdTree(tc: *TestCtx, spec: *const FtpSpec) !void {
    if (!spec.mlsd) return error.SkipIntegration;
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    if (!rig.client.caps.mlsd) {
        // MLST advertised without MLSD implies MLSD on every known server
        // (ProFTPD does exactly this); the engine stays literal, the suite
        // overrides to exercise the MLSD path.
        if (!rig.client.caps.mlst) return error.MlsdNotAdvertised;
        rig.client.caps.mlsd = true;
    }
    const t0 = nowTs(rig.io);
    const total = try countTree(rig);
    tc.notef("{d} entries via MLSD in {d} ms", .{ total, elapsedMs(rig.io, t0) });
}

fn ftpListTree(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    rig.client.caps.mlsd = false; // force the LIST parser path
    const t0 = nowTs(rig.io);
    const total = try countTree(rig);
    tc.notef("{d} entries via LIST in {d} ms", .{ total, elapsedMs(rig.io, t0) });
}

fn ftpUploadBig(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf: [64]u8 = undefined;
    const path = specPath(spec, &buf, "-big.bin");
    const t0 = nowTs(rig.io);
    try ftpUploadPattern(rig, path, 0, big_len);
    const sz = try rig.client.size(rig.io, &rig.cancel, rig.diag, path);
    if (sz != big_len) return error.SizeMismatch;
    tc.notef("10 MiB up in {d} ms", .{elapsedMs(rig.io, t0)});
}

fn ftpDownloadBig(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf: [64]u8 = undefined;
    const path = specPath(spec, &buf, "-big.bin");
    const t0 = nowTs(rig.io);
    try ftpVerifyDownload(rig, path, 0, big_len);
    tc.notef("10 MiB down+compare in {d} ms", .{elapsedMs(rig.io, t0)});
}

fn ftpResumeDownload(tc: *TestCtx, spec: *const FtpSpec) !void {
    var buf: [64]u8 = undefined;
    const path = specPath(spec, &buf, "-big.bin");

    // Phase 1: read exactly 50%, then kill the whole connection abruptly.
    {
        const rig = try FtpRig.open(tc, spec, .{});
        var killed = false;
        defer if (!killed) rig.kill();
        const rs = try rig.client.retr(rig.io, &rig.cancel, rig.diag, path, 0);
        var chunk: [64 * 1024]u8 = undefined;
        var off: usize = 0;
        while (off < half_len) {
            const n = try rs.reader.readSliceShort(chunk[0..@min(chunk.len, half_len - off)]);
            if (n == 0) return error.ShortDownload;
            for (chunk[0..n], 0..) |b, i| {
                if (b != patternByte(off + i)) return error.PayloadMismatch;
            }
            off += n;
        }
        killed = true;
        rig.kill();
    }

    // Phase 2: fresh connection, REST to 50%, verify the remainder.
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    try ftpVerifyDownload(rig, path, half_len, big_len);
    tc.notef("REST {d} verified", .{half_len});
}

fn ftpResumeUpload(tc: *TestCtx, spec: *const FtpSpec) !void {
    var buf: [64]u8 = undefined;
    const path = specPath(spec, &buf, "-resume.bin");

    // Phase 1: upload ~50% and kill without completing the STOR.
    {
        const rig = try FtpRig.open(tc, spec, .{});
        var killed = false;
        defer if (!killed) rig.kill();
        const ws = try rig.client.stor(rig.io, &rig.cancel, rig.diag, path, 0, .store);
        var chunk: [64 * 1024]u8 = undefined;
        var off: usize = 0;
        while (off < half_len) {
            const n = @min(chunk.len, half_len - off);
            for (chunk[0..n], 0..) |*b, i| b.* = patternByte(off + i);
            try ws.writer.writeAll(chunk[0..n]);
            off += n;
        }
        killed = true;
        rig.kill(); // no WriteStream.close: the transfer dies mid-flight
    }

    // Phase 2: resume from whatever the server actually kept.
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    const kept = try rig.client.size(rig.io, &rig.cancel, rig.diag, path);
    if (kept > half_len) return error.ServerKeptTooMuch;
    try ftpUploadPattern(rig, path, @intCast(kept), big_len);
    const final = try rig.client.size(rig.io, &rig.cancel, rig.diag, path);
    if (final != big_len) return error.SizeMismatch;
    try ftpVerifyDownload(rig, path, 0, big_len);
    tc.notef("kept {d}, resumed to {d}", .{ kept, big_len });
}

fn ftpUtf8Names(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf_a: [128]u8 = undefined;
    var buf_b: [128]u8 = undefined;
    const name_a = specPath(spec, &buf_a, "-påron-树莓-ファイル.txt");
    const name_b = specPath(spec, &buf_b, "-päron-renamed-ファイル.txt");
    const payload_len: usize = 4096;

    try ftpUploadPattern(rig, name_a, 0, payload_len);
    var s: ListSink = .{ .needle = name_a[1..] };
    try ftpList(rig, "/", &s);
    if (!s.found) return error.Utf8NameNotListed;

    try rig.client.rename(rig.io, &rig.cancel, rig.diag, name_a, name_b);
    const sz = try rig.client.size(rig.io, &rig.cancel, rig.diag, name_b);
    if (sz != payload_len) return error.SizeMismatch;
    try rig.client.dele(rig.io, &rig.cancel, rig.diag, name_b);
}

fn ftpFileOps(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    var buf_f: [80]u8 = undefined;
    const dir_a = specPath(spec, &buf_a, "-ops");
    const dir_b = specPath(spec, &buf_b, "-ops2");
    const file = std.fmt.bufPrint(&buf_f, "{s}/file.bin", .{dir_b}) catch unreachable;

    try rig.client.mkd(rig.io, &rig.cancel, rig.diag, dir_a);
    try rig.client.rename(rig.io, &rig.cancel, rig.diag, dir_a, dir_b);
    try ftpUploadPattern(rig, file, 0, 1024);
    try rig.client.chmod(rig.io, &rig.cancel, rig.diag, file, 0o644);
    try rig.client.dele(rig.io, &rig.cancel, rig.diag, file);
    try rig.client.rmd(rig.io, &rig.cancel, rig.diag, dir_b);
}

fn ftpCancelMidDownload(tc: *TestCtx, spec: *const FtpSpec) !void {
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    var buf: [64]u8 = undefined;
    const path = specPath(spec, &buf, "-big.bin");

    var xfer_cancel: CancelToken = .{};
    var xfer_diag: Diagnostics = .{};
    const rs = try rig.client.retr(rig.io, &xfer_cancel, &xfer_diag, path, 0);
    var rs_open = true;
    defer if (rs_open) rs.close(rig.io);

    var chunk: [64 * 1024]u8 = undefined;
    var got: usize = 0;
    while (got < 256 * 1024) {
        const n = try rs.reader.readSliceShort(&chunk);
        if (n == 0) return error.ShortDownload;
        got += n;
    }
    xfer_cancel.cancel();
    const t0 = nowTs(rig.io);
    var failed = false;
    // One buffered chunk may still be served; the next refill must fail.
    for (0..8) |_| {
        _ = rs.reader.readSliceShort(&chunk) catch {
            failed = true;
            break;
        };
    }
    if (!failed) return error.CancelIgnored;
    if (xfer_diag.class != .cancel) return error.WrongErrorClass;
    const latency = elapsedMs(rig.io, t0);
    rs_open = false;
    rs.close(rig.io); // ABOR + drain keeps the control connection usable
    rig.client.noop(rig.io, &rig.cancel, rig.diag) catch {
        // ProFTPD can emit its 426 transfer-abort reply after the ABOR
        // drain already finished; one stray reply is tolerated.
        tc.diag.clear();
        try rig.client.noop(rig.io, &rig.cancel, rig.diag);
    };
    tc.notef("cancel latency {d} ms, control usable after ABOR", .{latency});
}

/// FTPS-only: a listing forces a data-connection TLS handshake resuming
/// the control session. Against vsftpd (require_ssl_reuse=YES) success is
/// positive proof the resumption path works.
fn ftpTlsReuseWorks(tc: *TestCtx, spec: *const FtpSpec) !void {
    if (!spec.tls) return error.SkipIntegration;
    const rig = try FtpRig.open(tc, spec, .{});
    defer rig.close();
    rig.client.caps.mlsd = false;
    var s: ListSink = .{};
    try ftpList(rig, "/many/d0", &s);
    if (s.entries != tree_files_per_dir) return error.TreeDirMismatch;
}

/// vsftpd-only: with the per-site disable_session_reuse escape hatch ON,
/// the same listing MUST fail loudly — proving the suite genuinely
/// exercises session resumption (and not a server that doesn't care).
fn ftpReuseOffFailsLoudly(tc: *TestCtx, spec: *const FtpSpec) !void {
    if (!spec.reuse_probe) return error.SkipIntegration;
    const rig = try FtpRig.open(tc, spec, .{ .disable_session_reuse = true });
    defer rig.close();
    rig.client.caps.mlsd = false;
    var s: ListSink = .{};
    const result = ftpList(rig, "/many/d0", &s);
    if (result) |_| {
        return error.ServerToleratedNoReuse;
    } else |err| {
        tc.notef("refused as expected: {t} ({s})", .{ err, tc.diag.message });
        tc.diag.clear();
    }
}

const FtpTest = struct {
    name: []const u8,
    run: *const fn (tc: *TestCtx, spec: *const FtpSpec) anyerror!void,
};

const ftp_tests = [_]FtpTest{
    .{ .name = "connect+auth", .run = ftpConnectAuth },
    .{ .name = "mlsd 5k tree", .run = ftpMlsdTree },
    .{ .name = "list 5k tree", .run = ftpListTree },
    .{ .name = "upload 10MiB", .run = ftpUploadBig },
    .{ .name = "download 10MiB compare", .run = ftpDownloadBig },
    .{ .name = "resume download @50%", .run = ftpResumeDownload },
    .{ .name = "resume upload @50%", .run = ftpResumeUpload },
    .{ .name = "utf-8 filenames", .run = ftpUtf8Names },
    .{ .name = "mkdir/rename/chmod/delete", .run = ftpFileOps },
    .{ .name = "cancel mid-download", .run = ftpCancelMidDownload },
    .{ .name = "tls data session reuse", .run = ftpTlsReuseWorks },
    .{ .name = "reuse-off fails loudly", .run = ftpReuseOffFailsLoudly },
};

// ---------------------------------------------------------------------------
// SFTP rig + matrix
// ---------------------------------------------------------------------------

const accept_all_callbacks: session_mod.Callbacks = .{
    .context = @ptrCast(@constCast(&accept_all_token)),
    .verifyHostKey = acceptAllHostKeys,
};
const accept_all_token: u8 = 0;

fn acceptAllHostKeys(ctx: *anyopaque, info: *const session_mod.HostKeyInfo) session_mod.HostKeyDecision {
    _ = ctx;
    _ = info;
    // Host-key pinning/known_hosts verification is covered by the SFTP
    // live unit test (proto/sftp/live_test.zig); this suite is transfers.
    return .accept;
}

const SftpAuth = union(enum) {
    pw,
    key: []const u8, // openssh-key-v1 PEM bytes
};

const SftpRig = struct {
    gpa: Allocator,
    io: Io,
    stream: Io.net.Stream,
    session: SshSession,
    client: SftpClient,
    cancel: CancelToken,
    diag: *Diagnostics,

    fn open(tc: *TestCtx, auth: SftpAuth) !*SftpRig {
        const gpa = tc.gpa();
        const io = tc.io();
        const rig = try gpa.create(SftpRig);
        errdefer gpa.destroy(rig);
        rig.gpa = gpa;
        rig.io = io;
        rig.cancel = .{};
        rig.diag = &tc.diag;

        const addr = try Io.net.IpAddress.resolve(io, "127.0.0.1", sftp_port);
        rig.stream = try addr.connect(io, .{ .mode = .stream });
        errdefer rig.stream.close(io);

        rig.session = try SshSession.init(
            gpa,
            io,
            rig.stream.socket.handle,
            "127.0.0.1",
            sftp_port,
            &rig.cancel,
            rig.diag,
            accept_all_callbacks,
        );
        errdefer rig.session.deinit();

        const auth_opts: session_mod.AuthOptions = switch (auth) {
            .pw => .{ .username = username, .try_agent = false, .password = password },
            .key => |pem| .{
                .username = username,
                .try_agent = false,
                .key = .{ .file_bytes = pem, .label = "integration ed25519" },
            },
        };
        try rig.session.authenticate(&rig.cancel, rig.diag, auth_opts);
        rig.client = try SftpClient.init(&rig.session, &rig.cancel, rig.diag);
        return rig;
    }

    fn close(rig: *SftpRig) void {
        const gpa = rig.gpa;
        rig.client.deinit();
        rig.session.deinit();
        rig.stream.close(rig.io);
        gpa.destroy(rig);
    }
};

fn sftpUploadPattern(rig: *SftpRig, path: []const u8, from: usize, to: usize, mode: vfs.OpenMode) !void {
    const ws = try rig.client.openWrite(rig.gpa, &rig.cancel, rig.diag, path, from, mode);
    var closed = false;
    errdefer if (!closed) {
        ws.close(rig.io) catch {};
    };
    var chunk: [64 * 1024]u8 = undefined;
    var off = from;
    while (off < to) {
        const n = @min(chunk.len, to - off);
        for (chunk[0..n], 0..) |*b, i| b.* = patternByte(off + i);
        try ws.writer.writeAll(chunk[0..n]);
        off += n;
    }
    closed = true;
    try ws.close(rig.io);
}

fn sftpVerifyDownload(rig: *SftpRig, path: []const u8, offset: usize, total: usize) !void {
    const rs = try rig.client.openRead(rig.gpa, &rig.cancel, rig.diag, path, offset);
    defer rs.close(rig.io);
    var chunk: [64 * 1024]u8 = undefined;
    var off = offset;
    while (true) {
        const n = try rs.reader.readSliceShort(&chunk);
        for (chunk[0..n], 0..) |b, i| {
            if (b != patternByte(off + i)) return error.PayloadMismatch;
        }
        off += n;
        if (n < chunk.len) break;
    }
    if (off != total) return error.ShortDownload;
}

fn sftpPasswordAuth(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    var buf: [1024]u8 = undefined;
    const rp = try rig.client.realpath(&rig.cancel, rig.diag, ".", &buf);
    if (!std.mem.eql(u8, rp, "/")) return error.UnexpectedRealpath;
}

fn sftpKeyAuth(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .{ .key = client_key.pem() });
    defer rig.close();
    var buf: [1024]u8 = undefined;
    _ = try rig.client.realpath(&rig.cancel, rig.diag, ".", &buf);
}

fn sftpReaddirTree(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    const t0 = nowTs(rig.io);
    var arena: std.heap.ArenaAllocator = .init(rig.gpa);
    defer arena.deinit();
    var root: ListSink = .{};
    try rig.client.readdir(&rig.cancel, rig.diag, "/upload/many", arena.allocator(), root.sink());
    if (root.dirs != tree_dirs) return error.TreeRootMismatch;
    var total: usize = 0;
    for (0..tree_dirs) |d| {
        var buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "/upload/many/d{d}", .{d}) catch unreachable;
        _ = arena.reset(.retain_capacity);
        var s: ListSink = .{};
        try rig.client.readdir(&rig.cancel, rig.diag, path, arena.allocator(), s.sink());
        if (s.entries != tree_files_per_dir) return error.TreeDirMismatch;
        total += s.entries;
    }
    tc.notef("{d} entries in {d} ms", .{ total, elapsedMs(rig.io, t0) });
}

fn sftpUploadBig(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    const t0 = nowTs(rig.io);
    try sftpUploadPattern(rig, "/upload/big.bin", 0, sftp_resume_at, .create_truncate);
    try sftpUploadPattern(rig, "/upload/big.bin", sftp_resume_at, big_len, .create_resume);
    const st = try rig.client.stat(&rig.cancel, rig.diag, "/upload/big.bin");
    if (st.size != big_len) return error.SizeMismatch;
    tc.notef("10 MiB up (resume @{d} MiB) in {d} ms", .{ sftp_resume_at / (1024 * 1024), elapsedMs(rig.io, t0) });
}

fn sftpDownloadBig(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    const t0 = nowTs(rig.io);
    try sftpVerifyDownload(rig, "/upload/big.bin", 0, big_len);
    const ms = @max(elapsedMs(rig.io, t0), 1);
    // libssh2 keeps 4x the 32 KiB stream buffer of READs in flight; the
    // throughput line makes pipelining regressions visible at a glance.
    const mib_s = (big_len * 1000) / (1024 * 1024) / ms;
    tc.notef("pipelined download: 10 MiB in {d} ms ({d} MiB/s)", .{ ms, mib_s });
}

fn sftpFileOps(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    try rig.client.rename(&rig.cancel, rig.diag, "/upload/big.bin", "/upload/big2.bin");
    try rig.client.chmod(&rig.cancel, rig.diag, "/upload/big2.bin", 0o600);
    const st = try rig.client.stat(&rig.cancel, rig.diag, "/upload/big2.bin");
    if (st.mode != 0o600) return error.ChmodMismatch;
    try rig.client.rename(&rig.cancel, rig.diag, "/upload/big2.bin", "/upload/big.bin");
    try rig.client.mkdir(&rig.cancel, rig.diag, "/upload/newdir");
    const dst = try rig.client.stat(&rig.cancel, rig.diag, "/upload/newdir");
    if (dst.kind != .dir) return error.MkdirMismatch;
    try rig.client.rmdir(&rig.cancel, rig.diag, "/upload/newdir");
    try sftpUploadPattern(rig, "/upload/todelete.bin", 0, 1024, .create_truncate);
    try rig.client.unlink(&rig.cancel, rig.diag, "/upload/todelete.bin");
    var nf: Diagnostics = .{};
    if (rig.client.stat(&rig.cancel, &nf, "/upload/todelete.bin")) |_| {
        return error.DeleteIneffective;
    } else |err| if (err != error.NotFound) return error.WrongError;
}

fn sftpCancelMidDownload(tc: *TestCtx) !void {
    const rig = try SftpRig.open(tc, .pw);
    defer rig.close();
    var xfer_cancel: CancelToken = .{};
    var xfer_diag: Diagnostics = .{};
    const rs = try rig.client.openRead(rig.gpa, &xfer_cancel, &xfer_diag, "/upload/big.bin", 0);
    defer rs.close(rig.io);
    var chunk: [4096]u8 = undefined;
    if (try rs.reader.readSliceShort(&chunk) != chunk.len) return error.ShortDownload;
    xfer_cancel.cancel();
    const t0 = nowTs(rig.io);
    var failed = false;
    var served: usize = 0;
    while (served <= sftp_mod.read_buffer_len) {
        served += rs.reader.readSliceShort(&chunk) catch {
            failed = true;
            break;
        };
    }
    if (!failed) return error.CancelIgnored;
    if (xfer_diag.class != .cancel) return error.WrongErrorClass;
    const latency = elapsedMs(rig.io, t0);
    if (latency > 500) return error.CancelTooSlow;
    tc.notef("cancel latency {d} ms", .{latency});
}

const SftpTest = struct {
    name: []const u8,
    run: *const fn (tc: *TestCtx) anyerror!void,
};

const sftp_tests = [_]SftpTest{
    .{ .name = "connect+password auth", .run = sftpPasswordAuth },
    .{ .name = "connect+ed25519 key auth", .run = sftpKeyAuth },
    .{ .name = "readdir 5k tree", .run = sftpReaddirTree },
    .{ .name = "upload 10MiB (resume)", .run = sftpUploadBig },
    .{ .name = "pipelined download 10MiB", .run = sftpDownloadBig },
    .{ .name = "rename/chmod/mkdir/delete", .run = sftpFileOps },
    .{ .name = "cancel mid-download", .run = sftpCancelMidDownload },
};

// ---------------------------------------------------------------------------
// generated SSH client key (same construction as proto/sftp/live_test.zig)
// ---------------------------------------------------------------------------

var client_key: ClientKey = .{};

const ClientKey = struct {
    pem_buf: [1024]u8 = undefined,
    pem_len: usize = 0,
    line_buf: [128]u8 = undefined,
    line_len: usize = 0,

    fn pem(k: *const ClientKey) []const u8 {
        return k.pem_buf[0..k.pem_len];
    }
    fn authorizedLine(k: *const ClientKey) []const u8 {
        return k.line_buf[0..k.line_len];
    }
};

fn wireString(w: *Io.Writer, bytes: []const u8) void {
    w.writeInt(u32, @intCast(bytes.len), .big) catch unreachable;
    w.writeAll(bytes) catch unreachable;
}

/// Deterministic ed25519 keypair as an unencrypted openssh-key-v1 file plus
/// the matching authorized_keys line (installed via docker exec).
fn makeClientKey() ClientKey {
    var out: ClientKey = .{};
    const seed = [_]u8{0xa7} ** 32;
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const pub_bytes = kp.public_key.toBytes();
    const secret = kp.secret_key.toBytes(); // 64 bytes: seed ++ public

    var blob_buf: [64]u8 = undefined;
    var bw: Io.Writer = .fixed(&blob_buf);
    wireString(&bw, "ssh-ed25519");
    wireString(&bw, &pub_bytes);
    const blob = bw.buffered();

    var lw: Io.Writer = .fixed(&out.line_buf);
    lw.writeAll("ssh-ed25519 ") catch unreachable;
    var b64_buf: [96]u8 = undefined;
    lw.writeAll(std.base64.standard.Encoder.encode(&b64_buf, blob)) catch unreachable;
    lw.writeAll(" relay-integration") catch unreachable;
    out.line_len = lw.buffered().len;

    var bin_buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&bin_buf);
    w.writeAll("openssh-key-v1\x00") catch unreachable;
    wireString(&w, "none"); // cipher
    wireString(&w, "none"); // kdf
    wireString(&w, ""); // kdf options
    w.writeInt(u32, 1, .big) catch unreachable;
    wireString(&w, blob);

    var sec_buf: [256]u8 = undefined;
    var sw: Io.Writer = .fixed(&sec_buf);
    sw.writeInt(u32, 0x52454c41, .big) catch unreachable; // checkint x2
    sw.writeInt(u32, 0x52454c41, .big) catch unreachable;
    wireString(&sw, "ssh-ed25519");
    wireString(&sw, &pub_bytes);
    wireString(&sw, &secret);
    wireString(&sw, "relay-integration");
    var pad: u8 = 1;
    while (sw.buffered().len % 8 != 0) : (pad += 1) {
        sw.writeByte(pad) catch unreachable;
    }
    wireString(&w, sw.buffered());

    var pem_b64_buf: [768]u8 = undefined;
    const pem_b64 = std.base64.standard.Encoder.encode(&pem_b64_buf, w.buffered());
    var pw: Io.Writer = .fixed(&out.pem_buf);
    pw.writeAll("-----BEGIN OPENSSH PRIVATE KEY-----\n") catch unreachable;
    var rest = pem_b64;
    while (rest.len > 70) {
        pw.writeAll(rest[0..70]) catch unreachable;
        pw.writeByte('\n') catch unreachable;
        rest = rest[70..];
    }
    pw.writeAll(rest) catch unreachable;
    pw.writeAll("\n-----END OPENSSH PRIVATE KEY-----\n") catch unreachable;
    out.pem_len = pw.buffered().len;
    return out;
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

fn wantServer(rt: *const Runtime, name: []const u8) bool {
    const filter = rt.only orelse return true;
    return std.mem.indexOf(u8, name, filter) != null;
}

fn runFtpMatrix(rt: *Runtime) void {
    for (&ftp_specs) |*spec| {
        if (!wantServer(rt, spec.name)) continue;
        std.debug.print("\n[{s}] 127.0.0.1:{d} (tls={})\n", .{ spec.name, spec.port, spec.tls });
        for (ftp_tests) |t| {
            var tc: TestCtx = .{ .rt = rt };
            const t0 = nowTs(rt.io);
            if (t.run(&tc, spec)) {
                rt.addRow(spec.name, t.name, .pass, elapsedMs(rt.io, t0), tc.note());
            } else |err| {
                if (err == error.SkipIntegration) {
                    rt.addRow(spec.name, t.name, .skip, 0, "not applicable");
                } else {
                    var buf: [192]u8 = undefined;
                    const detail = std.fmt.bufPrint(&buf, "{t}: {s}", .{ err, tc.diag.message }) catch "";
                    rt.addRow(spec.name, t.name, .fail, elapsedMs(rt.io, t0), detail);
                }
            }
        }
    }
}

fn runSftpMatrix(rt: *Runtime) void {
    if (!wantServer(rt, "sftp")) return;
    std.debug.print("\n[sftp] 127.0.0.1:{d} (openssh)\n", .{sftp_port});
    for (sftp_tests) |t| {
        var tc: TestCtx = .{ .rt = rt };
        const t0 = nowTs(rt.io);
        if (t.run(&tc)) {
            rt.addRow("sftp", t.name, .pass, elapsedMs(rt.io, t0), tc.note());
        } else |err| {
            var buf: [192]u8 = undefined;
            const detail = std.fmt.bufPrint(&buf, "{t}: {s}", .{ err, tc.diag.message }) catch "";
            rt.addRow("sftp", t.name, .fail, elapsedMs(rt.io, t0), detail);
        }
    }
}

fn printTable(rt: *Runtime) void {
    var pass: usize = 0;
    var fail: usize = 0;
    var skip: usize = 0;
    std.debug.print("\n================================ results ================================\n", .{});
    for (rt.rows.items) |*row| {
        const label = switch (row.status) {
            .pass => "PASS",
            .fail => "FAIL",
            .skip => "SKIP",
        };
        switch (row.status) {
            .pass => pass += 1,
            .fail => fail += 1,
            .skip => skip += 1,
        }
        std.debug.print("{s:<16} {s:<28} {s:<5} {d:>6} ms  {s}\n", .{
            row.server, row.test_name, label, row.ms, row.msg(),
        });
    }
    std.debug.print("==========================================================================\n", .{});
    std.debug.print("{d} passed, {d} failed, {d} skipped\n", .{ pass, fail, skip });
}

fn runAll(rt: *Runtime) !u8 {
    if (!cmdOk(rt, &.{ "docker", "version", "--format", "{{.Server.Version}}" }) or
        !cmdOk(rt, &.{ "docker", "compose", "version" }))
    {
        std.debug.print("integration: no usable docker daemon — skipping the live suite.\n", .{});
        return 0;
    }

    client_key = makeClientKey();

    if (!rt.no_compose) {
        // Clean slate: leftover tmpfs state from an interrupted run would
        // make file-name assertions order-dependent.
        _ = composeOk(rt, &.{ "down", "-v", "--remove-orphans" });
        std.debug.print("integration: docker compose up --build --wait (first build takes minutes)...\n", .{});
        if (!composeOk(rt, &.{ "up", "-d", "--build", "--wait", "--wait-timeout", "300" })) {
            const logs = compose(rt, &.{ "logs", "--tail", "50" }) catch null;
            if (logs) |l| {
                defer rt.gpa.free(l);
                std.debug.print("--- compose logs ---\n{s}\n", .{l});
            }
            _ = composeOk(rt, &.{ "down", "-v", "--remove-orphans" });
            std.debug.print("integration: docker compose up failed\n", .{});
            return 1;
        }
    }
    defer if (!rt.keep and !rt.no_compose) {
        _ = composeOk(rt, &.{ "down", "-v", "--remove-orphans" });
    };

    // Provision the 5k trees + the SFTP authorized key.
    for ([_][]const u8{ "vsftpd", "pureftpd", "proftpd" }) |service| {
        provisionFtp(rt, service) catch {
            std.debug.print("integration: provisioning {s} failed\n", .{service});
            return 1;
        };
    }
    provisionSftp(rt, client_key.authorizedLine()) catch {
        std.debug.print("integration: provisioning sftp failed\n", .{});
        return 1;
    };

    runFtpMatrix(rt);
    runSftpMatrix(rt);
    printTable(rt);
    return if (rt.anyFailure()) 1 else 0;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // The environ matters: docker/compose children must inherit PATH
    // (credential helpers etc.); Threaded defaults to an empty environ.
    var threaded: Io.Threaded = .init(std.heap.c_allocator, .{ .environ = init.environ });
    defer threaded.deinit();

    var rt: Runtime = .{
        .gpa = std.heap.c_allocator,
        .io = threaded.io(),
        .compose_file = "",
        .only = null,
        .keep = false,
        .no_compose = false,
        .rows = .empty,
    };
    defer rt.rows.deinit(rt.gpa);

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--compose-file")) {
            rt.compose_file = args.next() orelse return error.MissingComposeFile;
        } else if (std.mem.eql(u8, arg, "--only")) {
            rt.only = args.next() orelse return error.MissingOnlyValue;
        } else if (std.mem.eql(u8, arg, "--keep")) {
            rt.keep = true;
        } else if (std.mem.eql(u8, arg, "--no-compose")) {
            rt.no_compose = true;
        } else {
            std.debug.print("usage: runner --compose-file <path> [--only <substr>] [--keep] [--no-compose]\n", .{});
            return error.UnknownArgument;
        }
    }
    if (rt.compose_file.len == 0) return error.MissingComposeFile;

    const code = try runAll(&rt);
    if (code != 0) std.process.exit(code);
}

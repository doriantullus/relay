//! live_test — the full SFTP integration matrix against a real OpenSSH
//! server in Docker (atmoz/sftp). Covers what the stubbed unit tests can't:
//! handshake, host-key fingerprint pinning, password + publickey auth on
//! the wire, readdir of 1000 entries, 10 MiB upload/download with offset
//! resume, rename/chmod/symlink, classified live errors, and cancel
//! mid-download latency.
//!
//! Gating: opt-in only. The single test skips (error.SkipZigTest) unless
//! RELAY_SFTP_LIVE=1 is set, so plain `zig build test` stays deterministic
//! and offline even on machines with a docker daemon (CI unit runners ship
//! one). With the gate set it still skips cleanly when no usable docker
//! daemon is reachable or the image can't be obtained. Run it manually:
//! `RELAY_SFTP_LIVE=1 zig build test`. The container is removed in
//! errdefer/defer paths. Referenced from sftp.zig's test block.

const std = @import("std");
const c = @import("c");
const session_mod = @import("session.zig");
const sftp_mod = @import("sftp.zig");
const keys = @import("../ssh/keys.zig");
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const CancelToken = @import("../../cancel.zig").CancelToken;
const vfs = @import("../../vfs/vfs.zig");
const SshSession = session_mod.SshSession;
const SftpClient = sftp_mod.SftpClient;

const t = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const image = "atmoz/sftp:alpine";
const username = "relay";
const password = "relaypw";
/// atmoz user spec: name:pass:uid:gid:writable-dir (chroot home stays
/// root-owned; only /upload is writable by the user).
const user_spec = username ++ ":" ++ password ++ ":1001:100:upload";

const big_len: usize = 10 * 1024 * 1024;
const resume_at: usize = 6 * 1024 * 1024;
const read_offset: usize = 7 * 1024 * 1024;
const many_count: usize = 1000;

// ---------------------------------------------------------------------------
// docker plumbing
// ---------------------------------------------------------------------------

/// Runs one docker CLI command; returns stdout (caller frees). Spawn
/// failures and non-zero exits collapse to DockerFailed — the caller
/// decides whether that means "skip" or "test bug".
fn docker(gpa: Allocator, io: Io, argv: []const []const u8) error{ DockerFailed, OutOfMemory }![]u8 {
    const res = std.process.run(gpa, io, .{ .argv = argv }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DockerFailed,
    };
    defer gpa.free(res.stderr);
    switch (res.term) {
        .exited => |code| if (code == 0) return res.stdout,
        else => {},
    }
    gpa.free(res.stdout);
    return error.DockerFailed;
}

fn dockerOk(gpa: Allocator, io: Io, argv: []const []const u8) bool {
    const out = docker(gpa, io, argv) catch return false;
    gpa.free(out);
    return true;
}

const Container = struct {
    gpa: Allocator,
    io: Io,
    port: u16,
    name_buf: [48]u8,
    name_len: usize,

    fn name(ct: *const Container) []const u8 {
        return ct.name_buf[0..ct.name_len];
    }

    /// null = the environment can't host the live matrix (no docker, no
    /// image and no network, sshd never came up): skip, never fail.
    fn start(gpa: Allocator, io: Io) ?Container {
        if (!dockerOk(gpa, io, &.{ "docker", "version", "--format", "{{.Server.Version}}" }))
            return null;
        if (!dockerOk(gpa, io, &.{ "docker", "image", "inspect", image })) {
            if (!dockerOk(gpa, io, &.{ "docker", "pull", image })) return null;
        }
        // Pseudo-random high ports; one retry in case the first is taken.
        var attempt: u64 = 0;
        while (attempt < 2) : (attempt += 1) {
            const port = pickPort(io, attempt);
            var ct: Container = .{
                .gpa = gpa,
                .io = io,
                .port = port,
                .name_buf = undefined,
                .name_len = 0,
            };
            var w: Io.Writer = .fixed(&ct.name_buf);
            w.print("relay-sftp-live-{d}", .{port}) catch unreachable;
            ct.name_len = w.buffered().len;

            var port_buf: [32]u8 = undefined;
            const port_map = std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}:22", .{port}) catch unreachable;
            if (!dockerOk(gpa, io, &.{
                "docker", "run", "-d", "--rm", "--name", ct.name(), "-p", port_map, image, user_spec,
            })) continue;
            // TTL self-destruct: a crashed test process (panic skips defers)
            // must not leak the container; --rm then auto-removes it.
            _ = dockerOk(gpa, io, &.{
                "docker", "exec", "-d", ct.name(), "sh", "-c", "sleep 600; kill 1",
            });
            if (waitReady(io, port)) return ct;
            ct.stop();
            return null;
        }
        return null;
    }

    fn exec(ct: *const Container, script: []const u8) !void {
        const out = try docker(ct.gpa, ct.io, &.{ "docker", "exec", ct.name(), "sh", "-ec", script });
        ct.gpa.free(out);
    }

    fn stop(ct: *const Container) void {
        const out = docker(ct.gpa, ct.io, &.{ "docker", "rm", "-f", ct.name() }) catch return;
        ct.gpa.free(out);
    }
};

/// Clock-seeded port in [20000, 40000) — collision avoidance for parallel
/// test runs in the same checkout, not security.
fn pickPort(io: Io, attempt: u64) u16 {
    const now: Io.Clock.Timestamp = .now(io, .awake);
    const ns: u96 = @bitCast(now.raw.nanoseconds);
    const mix = (@as(u64, @truncate(ns)) +% attempt) *% 0x9e3779b97f4a7c15;
    return 20000 + @as(u16, @intCast((mix >> 32) % 20000));
}

/// Waits (≤ ~30 s) until sshd answers with an SSH banner on the forwarded
/// port. Docker's proxy accepts TCP before the container listens, so a
/// successful connect alone is not readiness.
fn waitReady(io: Io, port: u16) bool {
    for (0..150) |_| {
        if (bannerVisible(io, port)) return true;
        Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch return false;
    }
    return false;
}

fn bannerVisible(io: Io, port: u16) bool {
    const addr = Io.net.IpAddress.resolve(io, "127.0.0.1", port) catch return false;
    const stream = addr.connect(io, .{ .mode = .stream }) catch return false;
    defer stream.close(io);
    var fds = [1]std.posix.pollfd{.{
        .fd = stream.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, 2000) catch return false;
    if (n == 0) return false;
    var buf: [8]u8 = undefined;
    const got = std.posix.read(stream.socket.handle, &buf) catch return false;
    return got >= 4 and std.mem.eql(u8, buf[0..4], "SSH-");
}

// ---------------------------------------------------------------------------
// host-key pinning: ground truth read out of the container
// ---------------------------------------------------------------------------

const PinnedKeys = struct {
    list: [4]keys.PublicKey,
    len: usize,

    fn slice(p: *const PinnedKeys) []const keys.PublicKey {
        return p.list[0..p.len];
    }

    fn deinit(p: *PinnedKeys) void {
        for (p.list[0..p.len]) |*k| k.deinit();
        p.* = undefined;
    }
};

fn fetchHostKeys(ct: *const Container, gpa: Allocator) !PinnedKeys {
    const out = try docker(gpa, ct.io, &.{
        "docker", "exec", ct.name(), "sh", "-ec", "cat /etc/ssh/ssh_host_*_key.pub",
    });
    defer gpa.free(out);
    var pinned: PinnedKeys = .{ .list = undefined, .len = 0 };
    errdefer pinned.deinit();
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        if (pinned.len == pinned.list.len) break;
        // Key types keys.zig doesn't model (none expected from atmoz) are
        // simply not pinnable; skip them.
        pinned.list[pinned.len] = keys.parsePublicLine(gpa, line) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        pinned.len += 1;
    }
    if (pinned.len == 0) return error.NoHostKeys;
    return pinned;
}

const PinnedHostKeyCb = struct {
    pinned: []const keys.PublicKey,
    matched: bool = false,
    fp_consistent: bool = false,

    fn verify(ctx: *anyopaque, info: *const session_mod.HostKeyInfo) session_mod.HostKeyDecision {
        const cb: *PinnedHostKeyCb = @ptrCast(@alignCast(ctx));
        for (cb.pinned) |*pk| {
            if (std.mem.eql(u8, pk.blob, info.key_blob)) {
                cb.matched = true;
                cb.fp_consistent = std.mem.eql(
                    u8,
                    &keys.fingerprintSha256(pk.blob),
                    &info.sha256_fp,
                );
                return .accept;
            }
        }
        return .reject;
    }

    fn callbacks(cb: *PinnedHostKeyCb) session_mod.Callbacks {
        return .{ .context = cb, .verifyHostKey = verify };
    }
};

// ---------------------------------------------------------------------------
// generated client key (no fixture/mount dependency)
// ---------------------------------------------------------------------------

fn wireString(w: *Io.Writer, bytes: []const u8) void {
    w.writeInt(u32, @intCast(bytes.len), .big) catch unreachable;
    w.writeAll(bytes) catch unreachable;
}

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

/// Deterministic ed25519 keypair as an unencrypted openssh-key-v1 file
/// (auth path: keys.zig validation + userauth_publickey_frommemory) plus
/// the matching authorized_keys line injected into the server.
fn makeClientKey() ClientKey {
    var out: ClientKey = .{};
    const seed = [_]u8{0x5a} ** 32;
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
    lw.writeAll(" relay-live") catch unreachable;
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
    wireString(&sw, "relay-live");
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
// matrix helpers
// ---------------------------------------------------------------------------

const Conn = struct {
    stream: Io.net.Stream,
    session: SshSession,

    fn close(conn: *Conn, io: Io) void {
        conn.session.deinit();
        conn.stream.close(io);
    }
};

fn dial(
    gpa: Allocator,
    io: Io,
    port: u16,
    cancel: *CancelToken,
    diag: *Diagnostics,
    callbacks: session_mod.Callbacks,
) !Conn {
    const addr = try Io.net.IpAddress.resolve(io, "127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);
    const session = try SshSession.init(
        gpa,
        io,
        stream.socket.handle,
        "127.0.0.1",
        port,
        cancel,
        diag,
        callbacks,
    );
    return .{ .stream = stream, .session = session };
}

/// Transfer payload byte at absolute file offset `i` — verifiable at any
/// resume offset without holding 10 MiB in memory.
fn patternByte(i: usize) u8 {
    return @truncate(i *% 131 +% (i >> 13));
}

fn upload(
    client: *SftpClient,
    gpa: Allocator,
    io: Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    path: []const u8,
    from: usize,
    to: usize,
    mode: vfs.OpenMode,
) !void {
    const ws = try client.openWrite(gpa, cancel, diag, path, from, mode);
    var closed = false;
    errdefer if (!closed) {
        ws.close(io) catch {};
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
    try ws.close(io);
}

fn verifyDownload(
    client: *SftpClient,
    gpa: Allocator,
    io: Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    path: []const u8,
    offset: usize,
) !void {
    const rs = try client.openRead(gpa, cancel, diag, path, offset);
    defer rs.close(io);
    var chunk: [64 * 1024]u8 = undefined;
    var off = offset;
    while (true) {
        const n = try rs.reader.readSliceShort(&chunk);
        for (chunk[0..n], 0..) |b, i| {
            if (b != patternByte(off + i)) return error.PatternMismatch;
        }
        off += n;
        if (n < chunk.len) break; // short read = end of stream
    }
    try t.expectEqual(big_len, off);
}

const CountingSink = struct {
    count: usize = 0,
    bad: usize = 0,
    batches: usize = 0,

    fn batch(ctx: *anyopaque, entries: []const vfs.Entry) void {
        const s: *CountingSink = @ptrCast(@alignCast(ctx));
        s.batches += 1;
        for (entries) |e| {
            s.count += 1;
            if (e.name.len < 2 or e.name[0] != 'f' or e.kind != .file) s.bad += 1;
        }
    }

    fn sink(s: *CountingSink) vfs.ListingSink {
        return .{ .context = s, .batchFn = batch };
    }
};

// ---------------------------------------------------------------------------
// the matrix
// ---------------------------------------------------------------------------

test "live: SFTP matrix against dockerized OpenSSH (set RELAY_SFTP_LIVE=1 to run)" {
    // Mirrors keychain.zig's RELAY_KEYCHAIN_SMOKE gate: unit runs must
    // never touch docker or the network, even when both are available.
    const gate = std.c.getenv("RELAY_SFTP_LIVE") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(gate), "1")) return error.SkipZigTest;

    const gpa = t.allocator;
    const io = t.io;

    var ct = Container.start(gpa, io) orelse return error.SkipZigTest;
    defer ct.stop();

    const key = makeClientKey();

    // Provision: authorized_keys for the publickey leg (atmoz only scans
    // mounted keys at startup, so install it directly) + 1000 listing files.
    var script_buf: [768]u8 = undefined;
    const home = "/home/" ++ username;
    try ct.exec(try std.fmt.bufPrint(&script_buf,
        \\mkdir -p {s}/.ssh {s}/upload/many
        \\echo '{s}' > {s}/.ssh/authorized_keys
        \\chown -R 1001 {s}/.ssh
        \\chmod 700 {s}/.ssh
        \\chmod 600 {s}/.ssh/authorized_keys
        \\cd {s}/upload/many
        \\i=1; while [ $i -le {d} ]; do : > f$i; i=$((i+1)); done
    , .{ home, home, key.authorizedLine(), home, home, home, home, home, many_count }));

    var pinned = try fetchHostKeys(&ct, gpa);
    defer pinned.deinit();

    // ---- connection 1: handshake + pinned host key + password auth ------
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var cb: PinnedHostKeyCb = .{ .pinned = pinned.slice() };
    var conn = try dial(gpa, io, ct.port, &cancel, &diag, cb.callbacks());
    defer conn.close(io);
    try t.expect(cb.matched);
    try t.expect(cb.fp_consistent);

    try conn.session.authenticate(&cancel, &diag, .{
        .username = username,
        .try_agent = false,
        .password = password,
    });

    conn.session.keepalive(5);
    _ = try conn.session.keepaliveSend(&cancel, &diag);

    var client = try SftpClient.init(&conn.session, &cancel, &diag);
    defer client.deinit();

    // realpath: chroot root
    var rp_buf: [1024]u8 = undefined;
    try t.expectEqualStrings("/", try client.realpath(&cancel, &diag, ".", &rp_buf));

    // readdir: 1000 files stream through the sink in batches
    {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        var sink: CountingSink = .{};
        try client.readdir(&cancel, &diag, "/upload/many", arena.allocator(), sink.sink());
        try t.expectEqual(many_count, sink.count);
        try t.expectEqual(@as(usize, 0), sink.bad);
        try t.expect(sink.batches >= many_count / sftp_mod.listing_batch_len);
    }

    // upload 10 MiB: truncate to 6 MiB, then resume the rest at offset
    try upload(&client, gpa, io, &cancel, &diag, "/upload/big.bin", 0, resume_at, .create_truncate);
    try upload(&client, gpa, io, &cancel, &diag, "/upload/big.bin", resume_at, big_len, .create_resume);
    {
        const st = try client.stat(&cancel, &diag, "/upload/big.bin");
        try t.expectEqual(@as(?u64, big_len), st.size);
        try t.expectEqual(vfs.EntryKind.file, st.kind);
    }

    // download in full and resumed from 7 MiB; byte-exact both ways
    try verifyDownload(&client, gpa, io, &cancel, &diag, "/upload/big.bin", 0);
    try verifyDownload(&client, gpa, io, &cancel, &diag, "/upload/big.bin", read_offset);

    // rename + classified NotFound on the old path
    try client.rename(&cancel, &diag, "/upload/big.bin", "/upload/big2.bin");
    {
        var nf: Diagnostics = .{};
        try t.expectError(error.NotFound, client.stat(&cancel, &nf, "/upload/big.bin"));
        try t.expectEqual(diag_mod.ErrorClass.permanent, nf.class);
        try t.expectEqual(@as(u32, c.LIBSSH2_FX_NO_SUCH_FILE), nf.protocol_code);
    }

    // chmod
    try client.chmod(&cancel, &diag, "/upload/big2.bin", 0o600);
    try t.expectEqual(@as(?u16, 0o600), (try client.stat(&cancel, &diag, "/upload/big2.bin")).mode);

    // symlink / readlink / lstat-vs-stat
    try client.symlink(&cancel, &diag, "big2.bin", "/upload/link.bin");
    var link_buf: [1024]u8 = undefined;
    try t.expectEqualStrings("big2.bin", try client.readlink(&cancel, &diag, "/upload/link.bin", &link_buf));
    try t.expectEqual(vfs.EntryKind.symlink, (try client.lstat(&cancel, &diag, "/upload/link.bin")).kind);
    try t.expectEqual(@as(?u64, big_len), (try client.stat(&cancel, &diag, "/upload/link.bin")).size);

    // mkdir / rmdir / unlink
    try client.mkdir(&cancel, &diag, "/upload/newdir");
    try t.expectEqual(vfs.EntryKind.dir, (try client.stat(&cancel, &diag, "/upload/newdir")).kind);
    try client.rmdir(&cancel, &diag, "/upload/newdir");
    try client.unlink(&cancel, &diag, "/upload/link.bin");

    // permission denied outside the writable subtree (chroot / is root's)
    {
        var pd: Diagnostics = .{};
        try t.expectError(
            error.PermissionDenied,
            client.openWrite(gpa, &cancel, &pd, "/forbidden.bin", 0, .create_truncate),
        );
        try t.expectEqual(diag_mod.ErrorClass.permanent, pd.class);
    }

    // cancel mid-download: poll loop must exit in < 150 ms with .cancel
    {
        var dl_cancel: CancelToken = .{};
        var dl_diag: Diagnostics = .{};
        const rs = try client.openRead(gpa, &dl_cancel, &dl_diag, "/upload/big2.bin", 0);
        defer rs.close(io);
        var chunk: [4096]u8 = undefined;
        try t.expectEqual(chunk.len, try rs.reader.readSliceShort(&chunk));
        dl_cancel.cancel();
        const t0: Io.Clock.Timestamp = .now(io, .awake);
        // The reader may first serve what it already buffered (≤ 32 KiB);
        // the next refill must fail instead of fetching more of the 10 MiB.
        var failed = false;
        var served: usize = 0;
        while (served <= sftp_mod.read_buffer_len) {
            served += rs.reader.readSliceShort(&chunk) catch {
                failed = true;
                break;
            };
        }
        const elapsed_ms = @divTrunc(
            t0.durationTo(.now(io, .awake)).raw.nanoseconds,
            std.time.ns_per_ms,
        );
        try t.expect(failed);
        try t.expect(elapsed_ms < 150);
        try t.expectEqual(diag_mod.ErrorClass.cancel, dl_diag.class);
    }

    // ---- connection 2: publickey auth over the wire ----------------------
    {
        var cb2: PinnedHostKeyCb = .{ .pinned = pinned.slice() };
        var cancel2: CancelToken = .{};
        var diag2: Diagnostics = .{};
        var conn2 = try dial(gpa, io, ct.port, &cancel2, &diag2, cb2.callbacks());
        defer conn2.close(io);
        try conn2.session.authenticate(&cancel2, &diag2, .{
            .username = username,
            .try_agent = false,
            .key = .{ .file_bytes = key.pem(), .label = "live ed25519" },
        });
    }

    // ---- connection 3: wrong password -> AuthFailed, .auth trail ---------
    {
        var cb3: PinnedHostKeyCb = .{ .pinned = pinned.slice() };
        var cancel3: CancelToken = .{};
        var diag3: Diagnostics = .{};
        var conn3 = try dial(gpa, io, ct.port, &cancel3, &diag3, cb3.callbacks());
        defer conn3.close(io);
        try t.expectError(error.AuthFailed, conn3.session.authenticate(&cancel3, &diag3, .{
            .username = username,
            .try_agent = false,
            .password = "wrong-password",
        }));
        try t.expectEqual(diag_mod.ErrorClass.auth, diag3.class);
        try t.expectEqual(@as(usize, 1), conn3.session.trail.len);
        try t.expectEqual(session_mod.AuthMethod.password, conn3.session.trail.slice()[0].method);
    }
}

//! libressl — the production `TlsProvider` (see provider.zig for the
//! contract) backed by the vendored static LibreSSL.
//!
//! Shape: one `LibresslProvider` (one SSL_CTX) per site; `handshake` wraps
//! an already-connected fd, drives `SSL_connect` non-blocking with a 100 ms
//! poll/cancel loop, and returns a `Stream` whose concrete
//! `std.Io.Reader`/`std.Io.Writer` vtables pump SSL_read/SSL_write with the
//! same WANT_READ/WANT_WRITE loop. Certificate verification is delegated to
//! verify_sectrust.zig (SecTrust on macOS, default CA paths on Linux).
//!
//! Session reuse — the whole reason this module exists (FTPS data
//! connections MUST resume the control connection's TLS session):
//! `exportSession` = SSL_get1_session (takes a refcount), `handshake` with
//! `opts.session` = SSL_set_session, `releaseSession` = SSL_SESSION_free.

const std = @import("std");
const c = @import("c");
const iface = @import("provider.zig");
const verify = @import("verify_sectrust.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const Diagnostics = @import("../diag.zig").Diagnostics;

const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Error = iface.Error;

/// Cancellation latency bound (contract: cancel resolves in ~100 ms).
const poll_interval_ms = 100;

/// One TLS record of plaintext per refill.
pub const read_buffer_len = 16 * 1024;
/// Control-connection writes are small and flushed per command; bulk
/// uploads drain through unbuffered.
pub const write_buffer_len = 4 * 1024;

/// RFC 1035 limit; longer hosts are rejected before any C call.
pub const max_host_len = 253;

pub const Options = struct {
    min_version: iface.Version = .tls12,
    /// Mirrors HandshakeOptions: FTPS stays on 1.2 (LibreSSL has no TLS 1.3
    /// resumption); a future SFTP-over-TLS or explicit opt-in can raise it.
    max_version: iface.Version = .tls12,
};

/// Version enum → TLS wire code (what SSL_CTX_set_{min,max}_proto_version
/// expect).
pub fn versionCode(v: iface.Version) u16 {
    return switch (v) {
        .tls12 => c.TLS1_2_VERSION,
        .tls13 => c.TLS1_3_VERSION,
    };
}

/// Verify-result code → contract error. Pure; unit-tested.
pub fn verifyResultError(vr: c_long) Error {
    return if (vr == c.X509_V_ERR_HOSTNAME_MISMATCH)
        error.HostnameMismatch
    else
        error.CertificateUntrusted;
}

pub const LibresslProvider = struct {
    gpa: Allocator,
    ssl_ctx: *c.SSL_CTX,

    pub fn init(gpa: Allocator, opts: Options) Error!*LibresslProvider {
        const self = try gpa.create(LibresslProvider);
        errdefer gpa.destroy(self);

        // SSL_CTX_new failure with the static method is allocation failure.
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OutOfMemory;
        errdefer c.SSL_CTX_free(ctx);

        if (c.SSL_CTX_set_min_proto_version(ctx, versionCode(opts.min_version)) != 1)
            return error.Unexpected;
        if (c.SSL_CTX_set_max_proto_version(ctx, versionCode(opts.max_version)) != 1)
            return error.Unexpected;
        // LibreSSL never ships compression, but pin the intent (CRIME).
        // SSL_CTX_set_options is a macro over SSL_CTX_ctrl.
        _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_OPTIONS, c.SSL_OP_NO_COMPRESSION, null);
        // We drive WANT_READ/WANT_WRITE retries ourselves; AUTO_RETRY would
        // block inside the library, unkillable by CancelToken.
        _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_CLEAR_MODE, c.SSL_MODE_AUTO_RETRY, null);
        // Verify failures must abort the handshake (per-connection
        // insecure_skip_verify downgrades to SSL_VERIFY_NONE on the SSL).
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        verify.install(ctx);

        self.* = .{ .gpa = gpa, .ssl_ctx = ctx };
        return self;
    }

    pub fn deinit(self: *LibresslProvider) void {
        const gpa = self.gpa;
        c.SSL_CTX_free(self.ssl_ctx);
        gpa.destroy(self);
    }

    pub fn provider(self: *LibresslProvider) iface.TlsProvider {
        return .{ .ctx = self, .vtable = &provider_vtable };
    }

    const provider_vtable: iface.VTable = .{
        .handshake = vtHandshake,
        .releaseSession = vtReleaseSession,
        .deinit = vtDeinit,
    };

    fn vtHandshake(
        ctx: *anyopaque,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        fd: posix.fd_t,
        opts: iface.HandshakeOptions,
    ) Error!*iface.Stream {
        const self: *LibresslProvider = @ptrCast(@alignCast(ctx));
        return self.handshake(gpa, cancel, diag, fd, opts);
    }

    fn vtReleaseSession(ctx: *anyopaque, session: *iface.Session) void {
        _ = ctx;
        c.SSL_SESSION_free(@ptrCast(@alignCast(session)));
    }

    fn vtDeinit(ctx: *anyopaque) void {
        const self: *LibresslProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }

    pub fn handshake(
        self: *LibresslProvider,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        fd: posix.fd_t,
        opts: iface.HandshakeOptions,
    ) Error!*iface.Stream {
        if (opts.host.len == 0 or opts.host.len > max_host_len) {
            // Empty would also silently disable SSL_set1_host checking.
            diag.set(.permanent, 0, "invalid hostname length {d} (max {d})", .{ opts.host.len, max_host_len });
            return error.ProtocolViolation;
        }
        try setNonblocking(fd, diag);

        const stream = try gpa.create(SslStream);
        errdefer gpa.destroy(stream);

        const ssl = c.SSL_new(self.ssl_ctx) orelse return error.OutOfMemory;
        errdefer c.SSL_free(ssl);

        stream.gpa = gpa;
        stream.ssl = ssl;
        stream.fd = fd;
        stream.cancel = cancel;
        stream.last_error = .{};
        @memcpy(stream.host_buf[0..opts.host.len], opts.host);
        stream.host_buf[opts.host.len] = 0;
        const host_z: [:0]const u8 = stream.host_buf[0..opts.host.len :0];

        if (c.SSL_set_fd(ssl, fd) != 1)
            return sslSetupFailure(diag, "SSL_set_fd");

        // Per-connection version bounds may narrow the provider's.
        if (c.SSL_set_min_proto_version(ssl, versionCode(opts.min_version)) != 1)
            return sslSetupFailure(diag, "SSL_set_min_proto_version");
        if (c.SSL_set_max_proto_version(ssl, versionCode(opts.max_version)) != 1)
            return sslSetupFailure(diag, "SSL_set_max_proto_version");

        // SNI carries DNS names only (RFC 6066 §3 forbids IP literals).
        const host_is_ip = isIpLiteral(opts.host);
        if (!host_is_ip) {
            if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(@constCast(host_z.ptr))) != 1)
                return sslSetupFailure(diag, "SNI hostname");
        }

        if (opts.insecure_skip_verify) {
            c.SSL_set_verify(ssl, c.SSL_VERIFY_NONE, null);
        } else if (host_is_ip) {
            // Built-in hostname check path (Linux); SecTrust gets the name
            // via VerifyState on macOS either way.
            if (c.X509_VERIFY_PARAM_set1_ip_asc(c.SSL_get0_param(ssl), host_z.ptr) != 1)
                return sslSetupFailure(diag, "verify IP");
        } else {
            if (c.SSL_set1_host(ssl, host_z.ptr) != 1)
                return sslSetupFailure(diag, "verify hostname");
        }

        stream.verify_state = .{ .host = host_z, .skip_verify = opts.insecure_skip_verify };
        verify.attach(ssl, &stream.verify_state);

        if (opts.session) |sess| {
            if (c.SSL_set_session(ssl, @ptrCast(@alignCast(sess))) != 1)
                return sslSetupFailure(diag, "SSL_set_session");
        }

        while (true) {
            c.ERR_clear_error();
            const rc = c.SSL_connect(ssl);
            if (rc == 1) break;
            switch (c.SSL_get_error(ssl, rc)) {
                c.SSL_ERROR_WANT_READ => try waitFd(fd, .in, cancel, diag),
                c.SSL_ERROR_WANT_WRITE => try waitFd(fd, .out, cancel, diag),
                else => |code| return mapHandshakeFailure(ssl, code, rc, opts, &stream.verify_state, diag),
            }
        }

        stream.reader = .{
            .vtable = &SslStream.reader_vtable,
            .buffer = &stream.read_buf,
            .seek = 0,
            .end = 0,
        };
        stream.writer = .{
            .vtable = &SslStream.writer_vtable,
            .buffer = &stream.write_buf,
            .end = 0,
        };
        stream.interface = .{
            .reader = &stream.reader,
            .writer = &stream.writer,
            .context = stream,
            .vtable = &SslStream.stream_vtable,
        };
        return &stream.interface;
    }
};

/// The concrete Stream. Heap-allocated as one block (interfaces point at
/// interior fields, so it must never move); freed by `close`.
const SslStream = struct {
    gpa: Allocator,
    ssl: *c.SSL,
    fd: posix.fd_t,
    cancel: *CancelToken,
    /// Detail behind the last ReadFailed/WriteFailed (Reader/Writer errors
    /// carry no payload).
    last_error: Diagnostics,
    verify_state: verify.VerifyState,
    interface: iface.Stream,
    reader: std.Io.Reader,
    writer: std.Io.Writer,
    host_buf: [max_host_len + 1]u8,
    read_buf: [read_buffer_len]u8,
    write_buf: [write_buffer_len]u8,

    const stream_vtable: iface.StreamVTable = .{
        .exportSession = vtExportSession,
        .close = vtClose,
    };
    const reader_vtable: std.Io.Reader.VTable = .{
        .stream = readerStream,
    };
    const writer_vtable: std.Io.Writer.VTable = .{
        .drain = writerDrain,
    };

    fn vtExportSession(ctx: *anyopaque) ?*iface.Session {
        const s: *SslStream = @ptrCast(@alignCast(ctx));
        return @ptrCast(c.SSL_get1_session(s.ssl));
    }

    fn vtClose(ctx: *anyopaque) void {
        const s: *SslStream = @ptrCast(@alignCast(ctx));
        // Best-effort close_notify: one SSL_shutdown round; never block or
        // poll here (the fd may already be dead). Does not close the fd —
        // the connection owns it.
        _ = c.SSL_shutdown(s.ssl);
        c.SSL_free(s.ssl);
        const gpa = s.gpa;
        gpa.destroy(s);
    }

    fn wasResumed(s: *const SslStream) bool {
        // SSL_session_reused is a macro over SSL_ctrl.
        return c.SSL_ctrl(@constCast(s.ssl), c.SSL_CTRL_GET_SESSION_REUSED, 0, null) == 1;
    }

    fn readerStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const s: *SslStream = @alignCast(@fieldParentPtr("reader", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = try s.sslRead(dest);
        w.advance(n);
        return n;
    }

    fn sslRead(s: *SslStream, dest: []u8) error{ ReadFailed, EndOfStream }!usize {
        std.debug.assert(dest.len != 0);
        while (true) {
            c.ERR_clear_error();
            const cap: c_int = @intCast(@min(dest.len, std.math.maxInt(c_int)));
            const rc = c.SSL_read(s.ssl, dest.ptr, cap);
            if (rc > 0) return @intCast(rc);
            switch (c.SSL_get_error(s.ssl, rc)) {
                c.SSL_ERROR_ZERO_RETURN => return error.EndOfStream,
                c.SSL_ERROR_WANT_READ => waitFd(s.fd, .in, s.cancel, &s.last_error) catch return error.ReadFailed,
                c.SSL_ERROR_WANT_WRITE => waitFd(s.fd, .out, s.cancel, &s.last_error) catch return error.ReadFailed,
                c.SSL_ERROR_SYSCALL => {
                    // EOF without close_notify: ubiquitous on FTPS data
                    // connections; treat as end of stream, not an error.
                    if (rc == 0) return error.EndOfStream;
                    s.last_error.set(.transient, 0, "TLS read failed: {t}", .{errnoNow()});
                    return error.ReadFailed;
                },
                else => {
                    var buf: [256]u8 = undefined;
                    s.last_error.set(.transient, 0, "TLS read failed: {s}", .{drainErrChain(&buf)});
                    return error.ReadFailed;
                },
            }
        }
    }

    fn writerDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const s: *SslStream = @alignCast(@fieldParentPtr("writer", w));
        const buffered = w.buffered();
        if (buffered.len != 0) {
            try s.sslWriteAll(buffered);
            w.end = 0;
        }
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            try s.sslWriteAll(slice);
            consumed += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try s.sslWriteAll(last);
            consumed += last.len;
        }
        return consumed;
    }

    fn sslWriteAll(s: *SslStream, bytes: []const u8) std.Io.Writer.Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            c.ERR_clear_error();
            const cap: c_int = @intCast(@min(bytes.len - off, std.math.maxInt(c_int)));
            // Same buffer/length on retry after WANT_*, as LibreSSL requires
            // (no ACCEPT_MOVING_WRITE_BUFFER needed: off only moves on
            // success).
            const rc = c.SSL_write(s.ssl, bytes.ptr + off, cap);
            if (rc > 0) {
                off += @intCast(rc);
                continue;
            }
            switch (c.SSL_get_error(s.ssl, rc)) {
                c.SSL_ERROR_WANT_READ => waitFd(s.fd, .in, s.cancel, &s.last_error) catch return error.WriteFailed,
                c.SSL_ERROR_WANT_WRITE => waitFd(s.fd, .out, s.cancel, &s.last_error) catch return error.WriteFailed,
                c.SSL_ERROR_SYSCALL, c.SSL_ERROR_ZERO_RETURN => {
                    s.last_error.set(.transient, 0, "TLS write failed: {t}", .{errnoNow()});
                    return error.WriteFailed;
                },
                else => {
                    var buf: [256]u8 = undefined;
                    s.last_error.set(.transient, 0, "TLS write failed: {s}", .{drainErrChain(&buf)});
                    return error.WriteFailed;
                },
            }
        }
    }
};

const Want = enum { in, out };

/// One ≤100 ms poll wakeup, checking `cancel` first — the contract that
/// makes C-library calls cancellable. Returns when the fd is ready (or has
/// an error condition: the next SSL_* call reports it properly).
fn waitFd(fd: posix.fd_t, want: Want, cancel: *CancelToken, diag: *Diagnostics) Error!void {
    var fds = [_]posix.pollfd{.{
        .fd = fd,
        .events = switch (want) {
            .in => posix.POLL.IN,
            .out => posix.POLL.OUT,
        },
        .revents = 0,
    }};
    while (true) {
        if (cancel.isCanceled()) {
            diag.set(.cancel, 0, "TLS operation canceled", .{});
            return error.Canceled;
        }
        const n = posix.poll(&fds, poll_interval_ms) catch {
            diag.set(.permanent, 0, "poll on TLS socket failed", .{});
            return error.Unexpected;
        };
        if (n != 0) return;
    }
}

fn setNonblocking(fd: posix.fd_t, diag: *Diagnostics) Error!void {
    const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(rc) != .SUCCESS) {
        diag.set(.permanent, 0, "fcntl(F_GETFL) failed: {t}", .{posix.errno(rc)});
        return error.Unexpected;
    }
    const flags = @as(usize, @intCast(rc)) | (1 << @bitOffsetOf(posix.O, "NONBLOCK"));
    const rc2 = posix.system.fcntl(fd, posix.F.SETFL, flags);
    if (posix.errno(rc2) != .SUCCESS) {
        diag.set(.permanent, 0, "fcntl(F_SETFL) failed: {t}", .{posix.errno(rc2)});
        return error.Unexpected;
    }
}

/// True for IPv4/IPv6 literals (which get no SNI and IP-based verification).
fn isIpLiteral(host: []const u8) bool {
    if (std.Io.net.Ip4Address.parse(host, 0)) |_| return true else |_| {}
    if (std.Io.net.Ip6Address.parse(host, 0)) |_| return true else |_| {}
    return false;
}

/// Setup-step failure before/while configuring the SSL: not a peer problem.
fn sslSetupFailure(diag: *Diagnostics, what: []const u8) Error {
    var buf: [256]u8 = undefined;
    diag.set(.permanent, 0, "TLS setup failed at {s}: {s}", .{ what, drainErrChain(&buf) });
    return error.Unexpected;
}

/// Failed SSL_connect → contract error + diagnostics. `code` is the
/// SSL_get_error classification for `rc`.
fn mapHandshakeFailure(
    ssl: *c.SSL,
    code: c_int,
    rc: c_int,
    opts: iface.HandshakeOptions,
    vs: *const verify.VerifyState,
    diag: *Diagnostics,
) Error {
    var chain_buf: [256]u8 = undefined;
    switch (code) {
        c.SSL_ERROR_SSL => {
            // Verify result is only meaningful when verification was on:
            // with skip_verify the recorded result is non-fatal noise.
            const vr = c.SSL_get_verify_result(ssl);
            if (!opts.insecure_skip_verify and vr != c.X509_V_OK) {
                var subject_buf: [256]u8 = undefined;
                const reason = c.X509_verify_cert_error_string(vr);
                diag.set(.permanent, 0, "certificate verification failed for {s}: {s}{s}{s} (subject: {s})", .{
                    opts.host,
                    std.mem.span(reason),
                    if (vs.detail().len != 0) " — " else "",
                    vs.detail(),
                    peerSubject(ssl, &subject_buf),
                });
                return verifyResultError(vr);
            }
            // Protocol-level failure; the ERR chain carries the alert text
            // (e.g. "sslv3 alert handshake failure").
            diag.set(.permanent, 0, "TLS handshake with {s} failed: {s}", .{ opts.host, drainErrChain(&chain_buf) });
            return error.HandshakeFailed;
        },
        c.SSL_ERROR_SYSCALL => {
            if (rc == 0) {
                diag.set(.transient, 0, "connection closed during TLS handshake with {s}", .{opts.host});
            } else {
                diag.set(.transient, 0, "TLS handshake I/O error with {s}: {t}", .{ opts.host, errnoNow() });
            }
            return error.ConnectionLost;
        },
        c.SSL_ERROR_ZERO_RETURN => {
            diag.set(.transient, 0, "connection closed during TLS handshake with {s}", .{opts.host});
            return error.ConnectionLost;
        },
        else => {
            diag.set(.permanent, 0, "TLS handshake with {s} failed (SSL_get_error={d}): {s}", .{
                opts.host, code, drainErrChain(&chain_buf),
            });
            return error.Unexpected;
        },
    }
}

/// Subject DN of the peer certificate, for cert-failure diagnostics.
fn peerSubject(ssl: *c.SSL, buf: []u8) []const u8 {
    const cert = c.SSL_get_peer_certificate(ssl) orelse return "unknown";
    defer c.X509_free(cert);
    const line = c.X509_NAME_oneline(c.X509_get_subject_name(cert), buf.ptr, @intCast(buf.len));
    if (line == null) return "unknown";
    return std.mem.sliceTo(buf, 0);
}

/// Formats and clears the thread's ERR queue ("lib:func:reason; ..." text).
fn drainErrChain(buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    var first = true;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        var line: [128]u8 = undefined;
        c.ERR_error_string_n(e, &line, line.len);
        const text = std.mem.sliceTo(&line, 0);
        if (!first) w.writeAll("; ") catch break;
        w.writeAll(text) catch break;
        first = false;
    }
    if (first) return "no error details";
    return w.buffered();
}

fn errnoNow() posix.E {
    return @enumFromInt(std.c._errno().*);
}

// ---------------------------------------------------------------------------
// Tests — pure unit (offline)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "version mapping matches TLS wire codes" {
    try testing.expectEqual(@as(u16, 0x0303), versionCode(.tls12));
    try testing.expectEqual(@as(u16, 0x0304), versionCode(.tls13));
    try testing.expectEqual(@as(u16, c.TLS1_2_VERSION), versionCode(.tls12));
    try testing.expectEqual(@as(u16, c.TLS1_3_VERSION), versionCode(.tls13));
}

test "verify-result error mapping" {
    try testing.expectEqual(Error.HostnameMismatch, verifyResultError(c.X509_V_ERR_HOSTNAME_MISMATCH));
    try testing.expectEqual(Error.CertificateUntrusted, verifyResultError(c.X509_V_ERR_CERT_UNTRUSTED));
    try testing.expectEqual(Error.CertificateUntrusted, verifyResultError(c.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN));
}

test "ip literal detection" {
    try testing.expect(isIpLiteral("127.0.0.1"));
    try testing.expect(isIpLiteral("::1"));
    try testing.expect(!isIpLiteral("example.com"));
    try testing.expect(!isIpLiteral("localhost"));
}

test "provider init/deinit through both call paths" {
    // Direct.
    const p1 = try LibresslProvider.init(testing.allocator, .{});
    p1.deinit();
    // Via the contract vtable, with TLS 1.3 bounds.
    const p2 = try LibresslProvider.init(testing.allocator, .{ .min_version = .tls12, .max_version = .tls13 });
    p2.provider().deinit();
}

test "provider init under allocation failure" {
    const Check = struct {
        fn run(gpa: Allocator) !void {
            const p = try LibresslProvider.init(gpa, .{});
            p.deinit();
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Check.run, .{});
}

test "session handle refcount discipline (no network)" {
    const p = try LibresslProvider.init(testing.allocator, .{});
    defer p.deinit();
    const prov = p.provider();

    // SSL_SESSION_new gives refcount 1; up_ref simulates the second handle
    // exportSession would hand out. Each releaseSession must drop exactly
    // one reference: the second release frees (GPA leak detection + libc
    // malloc guards would trip on imbalance).
    const raw = c.SSL_SESSION_new() orelse return error.OutOfMemory;
    try testing.expectEqual(@as(c_int, 1), c.SSL_SESSION_up_ref(raw));
    const session: *iface.Session = @ptrCast(raw);
    prov.releaseSession(session);
    prov.releaseSession(session);
}

test "error chain formatting" {
    c.ERR_clear_error();
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("no error details", drainErrChain(&buf));

    c.ERR_put_error(c.ERR_LIB_SSL, 0, c.SSL_R_UNKNOWN_PROTOCOL, "test.c", 1);
    const text = drainErrChain(&buf);
    try testing.expect(std.mem.indexOf(u8, text, "SSL") != null);
    // The queue was drained.
    try testing.expectEqualStrings("no error details", drainErrChain(&buf));
}

/// AF_UNIX socketpair via libc (macOS lacks socketpair(AF_INET), which is
/// all std.Io.net.Socket.createPair offers). SSL only needs an fd.
fn testSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds) != 0)
        return error.TestUnexpectedResult;
    return fds;
}

test "handshake cancel resolves without network" {
    const fds = try testSocketPair();
    defer for (fds) |fd| {
        _ = std.c.close(fd);
    };

    const p = try LibresslProvider.init(testing.allocator, .{});
    defer p.deinit();

    var cancel: CancelToken = .{};
    cancel.cancel();
    var diag: Diagnostics = .{};
    // ClientHello is written into the socketpair buffer, then the peer
    // never answers: the WANT_READ poll loop must notice the cancel flag.
    const result = p.provider().handshake(
        testing.allocator,
        &cancel,
        &diag,
        fds[0],
        .{ .host = "relay-test.invalid", .insecure_skip_verify = true },
    );
    try testing.expectError(error.Canceled, result);
    try testing.expectEqual(.cancel, diag.class);
}

test "handshake against a non-TLS peer is a classified failure" {
    const fds = try testSocketPair();
    defer for (fds) |fd| {
        _ = std.c.close(fd);
    };

    // The "server" already answered with plain FTP; the client's first
    // record read hits a non-TLS header.
    const banner = "220 plaintext FTP service ready\r\n";
    try testing.expectEqual(@as(isize, banner.len), std.c.write(fds[1], banner.ptr, banner.len));

    const p = try LibresslProvider.init(testing.allocator, .{});
    defer p.deinit();

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    const result = p.provider().handshake(
        testing.allocator,
        &cancel,
        &diag,
        fds[0],
        .{ .host = "relay-test.invalid", .insecure_skip_verify = true },
    );
    try testing.expectError(error.HandshakeFailed, result);
    try testing.expectEqual(.permanent, diag.class);
    try testing.expect(diag.message.len != 0);
}

test "empty and over-long hostnames are rejected" {
    const p = try LibresslProvider.init(testing.allocator, .{});
    defer p.deinit();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    const long_host = "x" ** (max_host_len + 1);
    try testing.expectError(error.ProtocolViolation, p.provider().handshake(
        testing.allocator,
        &cancel,
        &diag,
        -1,
        .{ .host = long_host },
    ));
    try testing.expectError(error.ProtocolViolation, p.provider().handshake(
        testing.allocator,
        &cancel,
        &diag,
        -1,
        .{ .host = "" },
    ));
}

// ---------------------------------------------------------------------------
// Tests — live-local (child `openssl s_server` on 127.0.0.1; no external
// network). Skipped when /usr/bin/openssl is missing.
// ---------------------------------------------------------------------------

const live = struct {
    const openssl_bin = "/usr/bin/openssl";

    const Server = struct {
        child: std.process.Child,
        port: u16,

        fn stop(s: *Server, io: std.Io) void {
            s.child.kill(io);
        }
    };

    /// Generates a throwaway self-signed cert in `tmp` and starts
    /// `openssl s_server -www`. Returns null (= skip) if the binary is
    /// missing or unusable.
    fn start(io: std.Io, tmp: *testing.TmpDir) !?Server {
        var genkey = std.process.spawn(io, .{
            .argv = &.{
                openssl_bin, "req",           "-x509",
                "-newkey",   "rsa:2048",      "-keyout",
                "key.pem",   "-out",          "cert.pem",
                "-days",     "2",             "-nodes",
                "-subj",     "/CN=localhost",
            },
            .cwd = .{ .dir = tmp.dir },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return null;
        const term = try genkey.wait(io);
        if (term != .exited or term.exited != 0) return null;

        // Crude but effective: a port derived from the PID, then probe.
        var prng = std.Random.DefaultPrng.init(@intCast(std.c.getpid()));
        var attempt: usize = 0;
        while (attempt < 3) : (attempt += 1) {
            const port: u16 = 20000 + prng.random().uintLessThan(u16, 40000);
            var port_buf: [8]u8 = undefined;
            const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
            var child = std.process.spawn(io, .{
                .argv = &.{
                    openssl_bin, "s_server", "-accept", port_str,
                    "-cert",     "cert.pem", "-key",    "key.pem",
                    "-www",
                },
                .cwd = .{ .dir = tmp.dir },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            }) catch return null;
            // Wait for it to listen (up to ~5 s).
            var probes: usize = 0;
            while (probes < 50) : (probes += 1) {
                if (connect(io, port)) |probe| {
                    var stream = probe;
                    stream.close(io);
                    return .{ .child = child, .port = port };
                } else |_| {}
                try io.sleep(.fromMilliseconds(100), .awake);
            }
            child.kill(io);
        }
        return error.ServerNeverListened;
    }

    fn connect(io: std.Io, port: u16) !std.Io.net.Stream {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        return addr.connect(io, .{ .mode = .stream });
    }
};

test "live-local: FTPS-critical handshake, echo exchange, session resumption (set RELAY_TLS_LIVE=1 to run)" {
    // Spawns a child `openssl s_server` and uses real loopback TCP — opt-in
    // only (mirrors RELAY_SFTP_LIVE) so plain `zig build test` stays
    // process- and network-free. The same resumption property is proven by
    // the integration suite against vsftpd require_ssl_reuse=YES.
    _ = std.c.getenv("RELAY_TLS_LIVE") orelse return error.SkipZigTest;

    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var server = (try live.start(io, &tmp)) orelse return error.SkipZigTest;
    defer server.stop(io);

    const p = try LibresslProvider.init(gpa, .{});
    defer p.deinit();
    const prov = p.provider();

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    // --- Connection 1: full handshake, request/response, session export.
    var conn1 = try live.connect(io, server.port);
    defer conn1.close(io);
    const stream1 = try prov.handshake(gpa, &cancel, &diag, conn1.socket.handle, .{
        .host = "localhost",
        .insecure_skip_verify = true, // self-signed; SecTrust path is exercised in integration, not unit
    });
    try stream1.writer.writeAll("GET / HTTP/1.0\r\n\r\n");
    try stream1.writer.flush();
    const body1 = try stream1.reader.allocRemaining(gpa, .unlimited);
    defer gpa.free(body1);
    try testing.expect(std.mem.indexOf(u8, body1, "HTTP/1.0 200 ok") != null);

    const session = stream1.exportSession() orelse return error.TestUnexpectedResult;
    defer prov.releaseSession(session);
    {
        const s1: *SslStream = @ptrCast(@alignCast(stream1.context));
        try testing.expect(!s1.wasResumed());
    }
    stream1.close();

    // --- Connection 2: must resume the exported session (the FTPS
    // data-connection requirement this provider exists for).
    var conn2 = try live.connect(io, server.port);
    defer conn2.close(io);
    const stream2 = try prov.handshake(gpa, &cancel, &diag, conn2.socket.handle, .{
        .host = "localhost",
        .session = session,
        .insecure_skip_verify = true,
    });
    var closed2 = false;
    defer if (!closed2) stream2.close();
    {
        const s2: *SslStream = @ptrCast(@alignCast(stream2.context));
        try testing.expect(s2.wasResumed());
    }
    try stream2.writer.writeAll("GET / HTTP/1.0\r\n\r\n");
    try stream2.writer.flush();
    const body2 = try stream2.reader.allocRemaining(gpa, .unlimited);
    defer gpa.free(body2);
    try testing.expect(std.mem.indexOf(u8, body2, "HTTP/1.0 200 ok") != null);
    // s_server's status page reports session reuse server-side too.
    try testing.expect(std.mem.indexOf(u8, body2, "Reused") != null);
    stream2.close();
    closed2 = true;
}

test {
    std.testing.refAllDecls(@This());
}

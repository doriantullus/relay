//! M0 spike 1: prove libssh2 + static LibreSSL link and function on
//! aarch64-macos. Success criteria:
//!   1. binary links with no system ssl/crypto dylib references,
//!   2. libssh2_version() and OpenSSL_version() report the vendored versions,
//!   3. a real SSH-2 handshake (no auth) against a live server, with the TCP
//!      connection established through std.Io.Threaded networking and the
//!      socket fd handed to libssh2 — the exact M1 architecture seam.
//!
//! Usage: zig build spike-ssh [-- --host <h>] [-- --port <p>]
//! With no --host it tries 127.0.0.1:<port> first and falls back to
//! github.com when nothing is listening locally.

const std = @import("std");
const Io = std.Io;
const c = @import("c");

pub fn main(init: std.process.Init.Minimal) !void {
    const ssh2_ver = c.libssh2_version(0) orelse return error.Libssh2VersionMismatch;
    std.debug.print("libssh2:  {s}\n", .{std.mem.span(ssh2_ver)});
    std.debug.print("crypto:   {s}\n", .{std.mem.span(c.OpenSSL_version(c.OPENSSL_VERSION))});

    if (c.libssh2_init(0) != 0) return error.Libssh2InitFailed;
    defer c.libssh2_exit();
    std.debug.print("libssh2_init: ok\n", .{});

    // ---- args ----------------------------------------------------------
    var host_arg: ?[]const u8 = null;
    var port: u16 = 22;
    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            host_arg = args.next() orelse return error.MissingHostValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const text = args.next() orelse return error.MissingPortValue;
            port = try std.fmt.parseInt(u16, text, 10);
        } else {
            std.debug.print("usage: spike-ssh [--host <host>] [--port <port>]\n", .{});
            return error.UnknownArgument;
        }
    }

    // ---- Io: std.Io.Threaded, same implementation Relay uses in M1 ------
    // The allocator only backs Io.async (used by HostName.connect's
    // happy-eyeballs); we link libc anyway, so c_allocator is fine here.
    var threaded: Io.Threaded = .init(std.heap.c_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const stream: Io.net.Stream = if (host_arg) |host|
        try dial(io, host, port)
    else
        dial(io, "127.0.0.1", port) catch |err| switch (err) {
            error.ConnectionRefused,
            error.ConnectionResetByPeer,
            error.Timeout,
            error.NetworkUnreachable,
            error.HostUnreachable,
            => fallback: {
                std.debug.print("127.0.0.1:{d} not listening ({t}); falling back to github.com\n", .{ port, err });
                break :fallback try dial(io, "github.com", port);
            },
            else => return err,
        };
    defer stream.close(io);

    // The handoff that matters for M1: std.Io.net.Stream wraps a Socket whose
    // `handle` field is the plain OS fd (std.posix.fd_t == c_int == the
    // libssh2_socket_t libssh2 wants on POSIX). No private API involved.
    const fd: c.libssh2_socket_t = stream.socket.handle;
    std.debug.print("connected, stream fd: {d}\n", .{fd});

    // ---- libssh2 handshake (no auth) -------------------------------------
    const session = c.libssh2_session_init_ex(null, null, null, null) orelse
        return error.SessionInitFailed;
    defer _ = c.libssh2_session_free(session);
    c.libssh2_session_set_blocking(session, 1);

    const t0: Io.Clock.Timestamp = .now(io, .awake);
    const rc = c.libssh2_session_handshake(session, fd);
    if (rc != 0) {
        var msg: [*c]u8 = null;
        var msg_len: c_int = 0;
        _ = c.libssh2_session_last_error(session, &msg, &msg_len, 0);
        if (msg != null and msg_len > 0) {
            std.debug.print("handshake failed: rc={d}: {s}\n", .{ rc, msg[0..@intCast(msg_len)] });
        } else {
            std.debug.print("handshake failed: rc={d}\n", .{rc});
        }
        return error.HandshakeFailed;
    }
    const t1: Io.Clock.Timestamp = .now(io, .awake);
    const handshake_ms = @divTrunc(t0.durationTo(t1).raw.nanoseconds, std.time.ns_per_ms);
    std.debug.print("handshake: ok ({d} ms)\n", .{handshake_ms});

    printMethod(session, "kex     ", c.LIBSSH2_METHOD_KEX);
    printMethod(session, "hostkey ", c.LIBSSH2_METHOD_HOSTKEY);
    printMethod(session, "crypt_cs", c.LIBSSH2_METHOD_CRYPT_CS);
    printMethod(session, "mac_cs  ", c.LIBSSH2_METHOD_MAC_CS);

    // SHA256 host key fingerprint, formatted the way OpenSSH prints it:
    // "SHA256:" ++ unpadded standard base64 of the raw 32-byte digest.
    const hash = c.libssh2_hostkey_hash(session, c.LIBSSH2_HOSTKEY_HASH_SHA256) orelse
        return error.NoHostKeyHash;
    var b64_buf: [44]u8 = undefined;
    const fp = std.base64.standard_no_pad.Encoder.encode(&b64_buf, hash[0..32]);
    std.debug.print("fingerprint: SHA256:{s}\n", .{fp});

    // libssh2_session_disconnect is a C macro; call the _ex form directly.
    _ = c.libssh2_session_disconnect_ex(
        session,
        c.SSH_DISCONNECT_BY_APPLICATION,
        "relay m0 spike: handshake only",
        "",
    );
    std.debug.print("disconnect: ok\n", .{});
}

/// IP literal -> IpAddress.resolve + connect; anything else -> HostName
/// lookup + connect (happy-eyeballs over every resolved address).
fn dial(io: Io, host: []const u8, port: u16) !Io.net.Stream {
    if (Io.net.IpAddress.resolve(io, host, port)) |addr| {
        std.debug.print("dial {f} ...\n", .{addr});
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {
        // Not an IP literal; treat as a DNS name.
        const name = try Io.net.HostName.init(host);
        std.debug.print("dial {s}:{d} (dns) ...\n", .{ host, port });
        return name.connect(io, port, .{ .mode = .stream });
    }
}

fn printMethod(session: *c.LIBSSH2_SESSION, label: []const u8, method: c_int) void {
    const m = c.libssh2_session_methods(session, method);
    if (m != null) {
        std.debug.print("{s}: {s}\n", .{ label, std.mem.span(m) });
    } else {
        std.debug.print("{s}: (not negotiated)\n", .{label});
    }
}

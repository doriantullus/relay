//! M0 spike 1: prove libssh2 + static LibreSSL link and function on
//! aarch64-macos. Success criteria:
//!   1. binary links with no system ssl/crypto dylib references,
//!   2. libssh2_version() and OpenSSL_version() report the vendored versions,
//!   3. (extended) SSH handshake against a local sshd lists a directory.

const std = @import("std");
const c = @import("c");

pub fn main() !void {
    const ssh2_ver = c.libssh2_version(0) orelse return error.Libssh2VersionMismatch;
    std.debug.print("libssh2:  {s}\n", .{std.mem.span(ssh2_ver)});
    std.debug.print("crypto:   {s}\n", .{std.mem.span(c.OpenSSL_version(c.OPENSSL_VERSION))});

    if (c.libssh2_init(0) != 0) return error.Libssh2InitFailed;
    defer c.libssh2_exit();
    std.debug.print("libssh2_init: ok\n", .{});
}

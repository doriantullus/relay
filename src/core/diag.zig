//! diag — rich error context carried as an out-param next to Zig error
//! returns (Zig errors carry no payload). Every fallible VFS/protocol call
//! takes `diag: *Diagnostics`; on error the callee fills it with whatever
//! the server actually said. The UI never shows bare Zig error names.

const std = @import("std");

/// Drives all retry and UI behavior (see the plan's retry matrix):
/// - transient: auto-retry with backoff (FTP 4xx, drops, timeouts)
/// - permanent: never auto-retried (FTP 5xx, NotFound, PermissionDenied)
/// - auth: pauses the whole site, raises one interactive prompt
/// - cancel: terminal, silent
pub const ErrorClass = enum { transient, permanent, auth, cancel };

pub const Diagnostics = struct {
    class: ErrorClass = .permanent,
    /// FTP reply code (e.g. 550), SFTP status (SSH_FX_*), or 0.
    protocol_code: u32 = 0,
    /// Human-readable context, formatted into `buf` (servers' verbatim
    /// reply text, SSH disconnect reason, TLS alert, errno text, ...).
    message: []const u8 = "",
    buf: [512]u8 = undefined,

    pub fn set(self: *Diagnostics, class: ErrorClass, code: u32, comptime fmt: []const u8, args: anytype) void {
        self.class = class;
        self.protocol_code = code;
        self.message = std.fmt.bufPrint(&self.buf, fmt, args) catch &self.buf;
    }

    pub fn clear(self: *Diagnostics) void {
        self.* = .{};
    }
};

test "diagnostics set formats into internal buffer" {
    var d: Diagnostics = .{};
    d.set(.transient, 421, "server said: {s}", .{"421 Too many connections"});
    try std.testing.expectEqual(.transient, d.class);
    try std.testing.expectEqual(@as(u32, 421), d.protocol_code);
    try std.testing.expect(std.mem.indexOf(u8, d.message, "Too many connections") != null);
}

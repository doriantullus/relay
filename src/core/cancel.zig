//! Cooperative cancellation token, the second of three cancellation layers
//! (std.Io Future.cancel above it, protocol courtesy like FTP ABOR below).
//!
//! Carried through every VFS/protocol call. C-library wrappers (LibreSSL,
//! libssh2) MUST check it on every poll-loop wakeup (≤100 ms) because their
//! C calls are not std.Io cancellation points. UI semantics: cancel of an
//! active transfer resolves within ~100 ms worst case.

const std = @import("std");

pub const CancelToken = struct {
    flag: std.atomic.Value(bool) = .init(false),

    pub fn cancel(self: *CancelToken) void {
        self.flag.store(true, .release);
    }

    pub fn isCanceled(self: *const CancelToken) bool {
        return self.flag.load(.acquire);
    }

    /// Error-union form for use between protocol steps:
    /// `try token.check();`
    pub fn check(self: *const CancelToken) error{Canceled}!void {
        if (self.isCanceled()) return error.Canceled;
    }

    pub fn reset(self: *CancelToken) void {
        self.flag.store(false, .release);
    }
};

test "cancel token lifecycle" {
    var token: CancelToken = .{};
    try std.testing.expect(!token.isCanceled());
    try token.check();
    token.cancel();
    try std.testing.expect(token.isCanceled());
    try std.testing.expectError(error.Canceled, token.check());
    token.reset();
    try token.check();
}

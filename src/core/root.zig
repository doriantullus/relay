//! relay_core — protocol engines (FTP/FTPS/SFTP), transfer queue, VFS,
//! credentials, settings. Architectural law: this module never imports
//! ObjC and stays portable (it builds and unit-tests on Linux CI).
//!
//! All I/O is coded against `*std.Io.Reader` / `*std.Io.Writer`, never raw
//! sockets, so every protocol layer unit-tests against in-memory streams.

const std = @import("std");

pub const version: std.SemanticVersion = .{ .major = 0, .minor = 1, .patch = 0 };

test "module sanity" {
    try std.testing.expectEqual(@as(usize, 0), version.major);
    try std.testing.expectEqual(@as(usize, 1), version.minor);
}

test {
    std.testing.refAllDecls(@This());
}

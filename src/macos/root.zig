//! relay_mac — zig-objc AppKit wrappers, libdispatch/CoreFoundation/Security
//! helpers, FSEvents, QuickLook, and drag & drop glue. macOS only.

const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("relay_mac is macOS-only");
}

pub const objc = @import("objc");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

//! relay_ui — platform-neutral application logic shared by the macOS and
//! Linux frontends. Architectural law: this module imports `relay_core` only;
//! it never imports a UI toolkit.

const std = @import("std");

pub const core = @import("relay_core");

pub const platform = struct {
    pub const Paths = @import("platform/paths.zig").Paths;
    pub const MainLoop = @import("platform/main_loop.zig").MainLoop;
    pub const ManualMainLoop = @import("platform/main_loop.zig").Manual;
};

pub const fuzzy = @import("fuzzy.zig");
pub const format = @import("format.zig");
pub const temp_cache = @import("temp_cache.zig");
pub const vim = @import("vim.zig");
pub const bridge = @import("bridge.zig");
pub const factories = @import("factories.zig");
pub const inspector = @import("inspector.zig");
pub const transcript = @import("transcript.zig");
pub const palette = @import("palette.zig");
pub const edit_sessions = @import("edit_sessions.zig");
pub const terminal = @import("terminal.zig");
pub const sites = @import("sites.zig");

test "module sanity" {
    try std.testing.expectEqual(@as(usize, 0), core.version.major);
}

test {
    _ = platform.Paths;
    _ = platform.MainLoop;
    _ = platform.ManualMainLoop;
    _ = fuzzy;
    _ = format;
    _ = temp_cache;
    _ = vim;
    _ = bridge;
    _ = factories;
    _ = inspector;
    _ = transcript;
    _ = palette;
    _ = edit_sessions;
    _ = terminal;
    _ = sites;
}

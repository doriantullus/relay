//! relay_mac — zig-objc AppKit wrappers, libdispatch/CoreFoundation/Security
//! helpers, FSEvents, QuickLook, and drag & drop glue. macOS only.
//!
//! Law (docs/UX.md, docs/spikes/ui.md): ALL selector strings live in this
//! module. Feature code (src/app/) never calls msgSend with raw strings.

const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("relay_mac is macOS-only");
}

pub const objc = @import("objc");

pub const foundation = @import("foundation.zig");
pub const dispatch = @import("dispatch.zig");
pub const runtime = @import("runtime.zig");

pub const appkit = struct {
    pub const window = @import("appkit/window.zig");
    pub const table_source = @import("appkit/table_source.zig");
    pub const outline_view = @import("appkit/outline_view.zig");
    pub const menu = @import("appkit/menu.zig");
    pub const toolbar = @import("appkit/toolbar.zig");
    pub const split_view = @import("appkit/split_view.zig");
    pub const panels = @import("appkit/panels.zig");
    pub const drag = @import("appkit/drag.zig");
};

const std = @import("std");

test {
    _ = foundation;
    _ = dispatch;
    _ = runtime;
    _ = appkit.window;
    _ = appkit.table_source;
    _ = appkit.outline_view;
    _ = appkit.menu;
    _ = appkit.toolbar;
    _ = appkit.split_view;
    _ = appkit.panels;
    _ = appkit.drag;
}

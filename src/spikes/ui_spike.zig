//! M0 spike 2 + 3 (THE GATE): drive AppKit from pure Zig via zig-objc.
//! Success criteria:
//!   1. NSApplication + NSWindow created and run from Zig main(),
//!   2. view-based NSTableView whose dataSource/delegate is an ObjC class
//!      defined from Zig (allocateClassPair/addMethod) backed by 100k rows,
//!   3. fixed row height, custom-drawn cells, sorting, type-select,
//!   4. a background std.Io.Threaded worker marshals row updates to the
//!      main thread via dispatch_async (zig-objc block) without blocking UI.
//!
//! Run with: zig build spike-ui -- --auto-exit-seconds 5

const std = @import("std");
const objc = @import("objc");

pub fn main() !void {
    std.debug.print("ui spike: not yet implemented (see M0 gate criteria above)\n", .{});
    _ = objc.getClass("NSObject") orelse return error.ObjcRuntimeUnavailable;
    std.debug.print("objc runtime reachable: NSObject class found\n", .{});
}

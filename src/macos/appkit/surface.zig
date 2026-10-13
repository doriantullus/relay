//! surface — a flat chrome backdrop drawn in semantic colors. Hosts put one
//! BEHIND a pane's path bar, status bar or a panel header so that chrome
//! reads as a distinct tier from the list it frames (windowBackgroundColor
//! vs. the list's controlBackgroundColor), with optional hairline
//! separators on the top/bottom edge and an optional accent tint that marks
//! the ACTIVE pane (controlAccentColor at low alpha, so it follows the
//! system accent and both appearances).
//!
//! Same mechanics as banner.zig: a runtime-defined NSView subclass drawing
//! in drawRect:, state recovered from the cached ivar, semantic NSColors
//! only. Main thread only.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");

const c = objc.c;
const NSRect = foundation.NSRect;
const rect = foundation.rect;
const getClass = foundation.class;

/// Hairline thickness in points (1 device pixel on 1x, 2 on 2x — the
/// standard AppKit separator weight).
const separator_h: f64 = 1;
/// Alpha of the controlAccentColor wash over the fill while `accent` is set.
const accent_alpha: f64 = 0.12;
/// Alpha of the labelColor wash that shades a chrome tier. windowBackground
/// resolves to plain white in light mode on current macOS, so the tier
/// needs a nudge away from the list: a little darker in light mode, a
/// little lighter in dark mode (labelColor flips with the appearance).
const shade_alpha: f64 = 0.06;

pub const Style = struct {
    fill: foundation.Color = .window_background,
    /// Shade the fill with labelColor at low alpha so the tier reads apart
    /// from the list it frames in both appearances.
    shade: bool = true,
    separator_top: bool = false,
    separator_bottom: bool = false,
    /// Active-pane treatment: wash the fill with the system accent.
    accent: bool = false,
};

var g_view_class: ?runtime.DefinedClass = null;

fn viewClass() runtime.DefinedClass {
    if (g_view_class) |dc| return dc;
    const dc = runtime.defineClass("RelaySurface", "NSView", &.{}, .{
        .{ "drawRect:", surfaceDrawRect },
        .{ "isOpaque", surfaceIsOpaque },
    }) catch @panic("relay_mac/surface: failed to define RelaySurface");
    g_view_class = dc;
    return dc;
}

pub const Surface = struct {
    alloc: std.mem.Allocator,
    /// RelaySurface NSView (rc 1, owned here).
    obj: objc.Object,
    style: Style,

    /// Build a surface. Heap-owned; embed `view()` and call deinit() at
    /// teardown (it removes itself from its superview).
    pub fn create(gpa: std.mem.Allocator, frame: NSRect, style: Style) !*Surface {
        const dc = viewClass();
        const self = try gpa.create(Surface);
        errdefer gpa.destroy(self);
        const obj = dc.newWithFrame(frame); // rc 1
        dc.attach(obj.value, self);
        self.* = .{ .alloc = gpa, .obj = obj, .style = style };
        return self;
    }

    pub fn deinit(self: *Surface) void {
        self.obj.msgSend(void, "removeFromSuperview", .{});
        self.obj.msgSend(void, "release", .{});
        self.alloc.destroy(self);
    }

    pub fn view(self: *Surface) c.id {
        return self.obj.value;
    }

    /// Toggle the active-pane accent wash; redraws only on change.
    pub fn setAccent(self: *Surface, on: bool) void {
        if (self.style.accent == on) return;
        self.style.accent = on;
        self.obj.msgSend(void, "setNeedsDisplay:", .{true});
    }

    pub fn setStyle(self: *Surface, style: Style) void {
        self.style = style;
        self.obj.msgSend(void, "setNeedsDisplay:", .{true});
    }
};

fn fill(color: objc.Object, r: NSRect) void {
    color.msgSend(void, "setFill", .{});
    getClass("NSBezierPath")
        .msgSend(objc.Object, "bezierPathWithRect:", .{r})
        .msgSend(void, "fill", .{});
}

fn surfaceDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const self = viewClass().state(Surface, target);
    const bounds = objc.Object.fromId(target).msgSend(NSRect, "bounds", .{});
    const w = bounds.size.width;
    const h = bounds.size.height;

    fill(self.style.fill.object(), bounds);
    if (self.style.shade) {
        const shade = foundation.Color.label.object()
            .msgSend(objc.Object, "colorWithAlphaComponent:", .{shade_alpha});
        fill(shade, bounds);
    }
    if (self.style.accent) {
        const wash = foundation.Color.control_accent.object()
            .msgSend(objc.Object, "colorWithAlphaComponent:", .{accent_alpha});
        fill(wash, bounds);
    }
    // Non-flipped: y grows upward, so the top edge is at h - separator_h.
    if (self.style.separator_top) fill(foundation.Color.separator.object(), rect(0, h - separator_h, w, separator_h));
    if (self.style.separator_bottom) fill(foundation.Color.separator.object(), rect(0, 0, w, separator_h));
}

fn surfaceIsOpaque(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1; // the fill covers the bounds; lets AppKit skip what is behind
}

// ---------------------------------------------------------------------------
// Tests (headless: no window, nothing drawn).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "create / accent toggle / deinit" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const s = try Surface.create(testing.allocator, rect(0, 0, 200, 26), .{ .separator_bottom = true });
    defer s.deinit();

    try testing.expect(!s.style.accent);
    try testing.expect(s.style.separator_bottom);
    try testing.expect(s.style.shade);
    try testing.expectEqual(foundation.Color.window_background, s.style.fill);

    s.setAccent(true);
    try testing.expect(s.style.accent);
    s.setAccent(true); // idempotent
    try testing.expect(s.style.accent);
    s.setAccent(false);
    try testing.expect(!s.style.accent);

    // The ivar round-trips back to this Surface, and the view is opaque.
    try testing.expectEqual(s, viewClass().state(Surface, s.view()));
    try testing.expect(foundation.toBool(s.obj.msgSend(foundation.BOOL, "isOpaque", .{})));
}

test "setStyle replaces every field" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const s = try Surface.create(testing.allocator, rect(0, 0, 10, 10), .{});
    defer s.deinit();
    s.setStyle(.{ .fill = .control_background, .shade = false, .separator_top = true, .accent = true });
    try testing.expectEqual(foundation.Color.control_background, s.style.fill);
    try testing.expect(s.style.separator_top);
    try testing.expect(!s.style.separator_bottom);
    try testing.expect(s.style.accent);
    try testing.expect(!s.style.shade);
}

//! tab_bar — the custom-drawn tab strip pinned above a pane: Safari-style
//! tabs left-to-right, a close "×" at the leading edge of every tab, and a
//! "+" new-tab button right after the last tab (clamped to the bar width).
//!
//! Built on the same mechanics as banner.zig/table_source.zig: a runtime-
//! defined NSView subclass that custom-draws EVERYTHING in drawRect: (no
//! subviews per tab), state recovered from the cached relayState ivar, and
//! semantic NSColors only so dark-mode flips redraw correctly. mouseDown:
//! converts the click point and routes through the same pure hit-test the
//! unit tests exercise headless.
//!
//! Threading: every public method and both callbacks run on the main thread
//! only; callbacks are pool-wrapped.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");

const c = objc.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const NSRect = foundation.NSRect;
const NSSize = foundation.NSSize;
const NSPoint = foundation.NSPoint;
const rect = foundation.rect;
const getClass = foundation.class;

// ---------------------------------------------------------------------------
// Geometry (fixed-height strip; all layout is pure Zig so the hit-test and
// frame math are unit-testable without ObjC).
// ---------------------------------------------------------------------------
/// Canonical bar height. Hosts give the strip exactly this many points
/// (13pt labels sit comfortably inside the 24pt tab body).
pub const bar_height: f64 = 30;

const h_pad: f64 = 8;
const tab_gap: f64 = 4;
const max_tab_width: f64 = 220;
const min_tab_width: f64 = 100;
const tab_v_inset: f64 = 3;
const corner_radius: f64 = 5;
const close_edge: f64 = 14;
const close_leading_pad: f64 = 4;
const title_trailing_pad: f64 = 8;
const new_button_edge: f64 = 24;
const font_size: f64 = 13;
const glyph_font_size: f64 = 13;
const line_break_truncating_middle: NSInteger = 5; // NSLineBreakByTruncatingMiddle
const text_alignment_center: NSInteger = 2; // NSTextAlignmentCenter

/// Per-tab width: the space left of the "+" button split evenly, clamped to
/// [min_tab_width, max_tab_width]. Below the minimum, tabs overflow the bar
/// (the "+" button clamps to the right edge and wins the hit-test).
pub fn tabWidth(bounds_w: f64, count: usize) f64 {
    if (count == 0) return 0;
    const n: f64 = @floatFromInt(count);
    const avail = bounds_w - h_pad - h_pad - new_button_edge - tab_gap;
    const per = (avail - tab_gap * (n - 1)) / n;
    return std.math.clamp(per, min_tab_width, max_tab_width);
}

/// Frame of tab `index` (flipped coordinates, y down from the top edge).
pub fn tabFrame(bounds_w: f64, count: usize, index: usize) NSRect {
    const w = tabWidth(bounds_w, count);
    const x = h_pad + @as(f64, @floatFromInt(index)) * (w + tab_gap);
    return rect(x, tab_v_inset, w, bar_height - 2 * tab_v_inset);
}

/// Close "×" hit region: a square at the LEFT inside edge of the tab,
/// vertically centered (always shown; no hover tracking in v1).
pub fn closeFrame(tab: NSRect) NSRect {
    const y = tab.origin.y + (tab.size.height - close_edge) / 2;
    return rect(tab.origin.x + close_leading_pad, y, close_edge, close_edge);
}

/// "+" new-tab button: right after the last tab, clamped so it never leaves
/// the bar (Safari placement). With zero tabs it sits at the leading edge.
pub fn newButtonFrame(bounds_w: f64, count: usize) NSRect {
    var x: f64 = h_pad;
    if (count > 0) {
        const w = tabWidth(bounds_w, count);
        x = h_pad + @as(f64, @floatFromInt(count)) * (w + tab_gap);
    }
    const max_x = @max(0, bounds_w - h_pad - new_button_edge);
    x = @min(x, max_x);
    return rect(x, (bar_height - new_button_edge) / 2, new_button_edge, new_button_edge);
}

fn frameContains(f: NSRect, x: f64, y: f64) bool {
    return x >= f.origin.x and x < f.origin.x + f.size.width and
        y >= f.origin.y and y < f.origin.y + f.size.height;
}

pub const Hit = union(enum) {
    none,
    /// Tab body (select).
    tab: usize,
    /// The "×" region of a tab (close).
    close: usize,
    new_tab,
};

/// Classify a click at (x, y) in flipped view coordinates. The "+" button is
/// tested first: when tabs overflow a narrow bar it is clamped on top of
/// them and must win.
pub fn hitTest(x: f64, y: f64, count: usize, bounds_w: f64) Hit {
    if (y < 0 or y >= bar_height) return .none;
    if (frameContains(newButtonFrame(bounds_w, count), x, y)) return .new_tab;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const tab = tabFrame(bounds_w, count, i);
        if (!frameContains(tab, x, y)) continue;
        if (frameContains(closeFrame(tab), x, y)) return .{ .close = i };
        return .{ .tab = i };
    }
    return .none;
}

const NSFontAttributeName = foundation.NSFontAttributeName;
const NSForegroundColorAttributeName = foundation.NSForegroundColorAttributeName;
const NSParagraphStyleAttributeName = foundation.NSParagraphStyleAttributeName;

// ---------------------------------------------------------------------------
// Runtime class (defined once, shared across every TabBar instance).
// ---------------------------------------------------------------------------
var g_view_class: ?runtime.DefinedClass = null;

fn viewClass() runtime.DefinedClass {
    if (g_view_class) |dc| return dc;
    const dc = runtime.defineClass("RelayTabBar", "NSView", &.{}, .{
        .{ "drawRect:", tabBarDrawRect },
        .{ "isFlipped", tabBarIsFlipped },
        .{ "mouseDown:", tabBarMouseDown },
    }) catch @panic("relay_mac/tab_bar: failed to define RelayTabBar");
    g_view_class = dc;
    return dc;
}

// ---------------------------------------------------------------------------
// TabBar
// ---------------------------------------------------------------------------
/// All callbacks fire on the main thread, from inside mouseDown:.
pub const Delegate = struct {
    ctx: *anyopaque,
    onSelect: *const fn (ctx: *anyopaque, index: usize) void,
    onClose: *const fn (ctx: *anyopaque, index: usize) void,
    onNew: *const fn (ctx: *anyopaque) void,
};

pub const TabBar = struct {
    alloc: std.mem.Allocator,
    /// RelayTabBar NSView (the strip; draws tabs, no subviews).
    obj: objc.Object,
    delegate: Delegate,
    /// Owned title copies; freed on the next setTabs()/deinit().
    titles: [][]u8 = &.{},
    active: usize = 0,

    /// Build a tab bar. The returned struct is heap-owned; embed `view()`
    /// into a layout and call deinit() at teardown. Main thread only.
    pub fn init(gpa: std.mem.Allocator, frame: NSRect, delegate: Delegate) !*TabBar {
        const dc = viewClass();

        const self = try gpa.create(TabBar);
        errdefer gpa.destroy(self);

        const obj = dc.newWithFrame(frame); // rc 1
        dc.attach(obj.value, self);
        // Track the host's width; height is fixed at bar_height.
        obj.msgSend(void, "setAutoresizingMask:", .{ns_view_width_sizable | ns_view_min_y_margin});

        self.* = .{
            .alloc = gpa,
            .obj = obj,
            .delegate = delegate,
        };
        return self;
    }

    pub fn deinit(self: *TabBar) void {
        self.freeTitles();
        self.obj.msgSend(void, "removeFromSuperview", .{});
        self.obj.msgSend(void, "release", .{});
        self.alloc.destroy(self);
    }

    /// The NSView to insert into a host layout (the strip itself).
    pub fn view(self: *TabBar) c.id {
        return self.obj.value;
    }

    /// Replace the tab set: titles are copied into TabBar-owned memory and
    /// the previous set is freed; `active` is clamped to the new count.
    pub fn setTabs(self: *TabBar, titles: []const []const u8, active: usize) !void {
        const copies = try self.alloc.alloc([]u8, titles.len);
        var done: usize = 0;
        errdefer {
            for (copies[0..done]) |t| self.alloc.free(t);
            self.alloc.free(copies);
        }
        for (titles, 0..) |title, i| {
            copies[i] = try self.alloc.dupe(u8, title);
            done = i + 1;
        }
        self.freeTitles();
        self.titles = copies;
        self.active = if (titles.len == 0) 0 else @min(active, titles.len - 1);
        self.obj.msgSend(void, "setNeedsDisplay:", .{true});
    }

    pub fn setHidden(self: *TabBar, hidden: bool) void {
        self.obj.msgSend(void, "setHidden:", .{hidden});
    }

    pub fn count(self: *TabBar) usize {
        return self.titles.len;
    }

    pub fn activeIndex(self: *TabBar) usize {
        return self.active;
    }

    fn freeTitles(self: *TabBar) void {
        for (self.titles) |t| self.alloc.free(t);
        if (self.titles.len > 0) self.alloc.free(self.titles);
        self.titles = &.{};
    }

    /// Route a classified click to the delegate (mouseDown: tail; split out
    /// so dispatch is testable without synthesizing NSEvents).
    fn dispatchHit(self: *TabBar, hit: Hit) void {
        switch (hit) {
            .none => {},
            .tab => |i| self.delegate.onSelect(self.delegate.ctx, i),
            .close => |i| self.delegate.onClose(self.delegate.ctx, i),
            .new_tab => self.delegate.onNew(self.delegate.ctx),
        }
    }
};

// NSView autoresizing-mask bits.
const ns_view_width_sizable: NSUInteger = 1 << 1;
const ns_view_min_y_margin: NSUInteger = 1 << 5;

// ---------------------------------------------------------------------------
// RelayTabBar IMPs (custom drawing + click routing)
// ---------------------------------------------------------------------------
fn tabBarIsFlipped(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1;
}

fn tabBarDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const self = viewClass().state(TabBar, target);
    const view_obj = objc.Object.fromId(target);
    const bounds = view_obj.msgSend(NSRect, "bounds", .{});
    const w = bounds.size.width;

    // Background + 1px separator along the bottom edge. Semantic only.
    foundation.Color.window_background.setFill();
    getClass("NSBezierPath")
        .msgSend(objc.Object, "bezierPathWithRect:", .{bounds})
        .msgSend(void, "fill", .{});
    foundation.Color.separator.setFill();
    getClass("NSBezierPath")
        .msgSend(objc.Object, "bezierPathWithRect:", .{
            rect(0, bounds.size.height - 1, w, 1),
        })
        .msgSend(void, "fill", .{});

    for (self.titles, 0..) |title, i| {
        const tab = tabFrame(w, self.titles.len, i);
        const is_active = i == self.active;

        // Active tab: subtle rounded fill that reads in both appearances.
        if (is_active) {
            foundation.Color.quaternary_label.setFill();
            getClass("NSBezierPath")
                .msgSend(objc.Object, "bezierPathWithRoundedRect:xRadius:yRadius:", .{
                    tab, corner_radius, corner_radius,
                })
                .msgSend(void, "fill", .{});
        }

        // Close "×" at the leading inside edge (always shown in v1).
        const close = closeFrame(tab);
        drawGlyph("\u{00D7}", close, foundation.secondaryLabelColor());

        // Title: middle-truncated + clipped between the "×" and the trailing
        // edge (NSView does not clip drawing to bounds by default).
        const text_x = close.origin.x + close.size.width + close_leading_pad;
        const avail_w = @max(0, tab.origin.x + tab.size.width - title_trailing_pad - text_x);
        const color = if (is_active) foundation.labelColor() else foundation.secondaryLabelColor();
        drawTitle(title, rect(text_x, tab.origin.y, avail_w, tab.size.height), color);
    }

    // "+" new-tab button right after the last tab (clamped to the bar).
    drawGlyph("+", newButtonFrame(w, self.titles.len), foundation.secondaryLabelColor());
}

/// Draw `text` centered in `frame` with the truncating/clipping paragraph
/// style (law: drawInRect, never drawAtPoint — it does not clip).
fn drawText(text: []const u8, frame: NSRect, font: objc.Object, color: objc.Object) void {
    const str = foundation.nsString(text);

    const para = getClass("NSMutableParagraphStyle").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    defer para.msgSend(void, "release", .{});
    para.msgSend(void, "setLineBreakMode:", .{line_break_truncating_middle});
    para.msgSend(void, "setAlignment:", .{text_alignment_center});

    const attrs = getClass("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
    attrs.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ color.value, NSForegroundColorAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ para.value, NSParagraphStyleAttributeName.* });

    const text_size = str.msgSend(NSSize, "sizeWithAttributes:", .{attrs});
    const y = frame.origin.y + (frame.size.height - text_size.height) / 2;
    str.msgSend(void, "drawInRect:withAttributes:", .{
        rect(frame.origin.x, y, frame.size.width, text_size.height),
        attrs,
    });
}

fn drawTitle(text: []const u8, frame: NSRect, color: objc.Object) void {
    drawText(text, frame, foundation.systemFont(font_size), color);
}

fn drawGlyph(glyph: []const u8, frame: NSRect, color: objc.Object) void {
    drawText(glyph, frame, foundation.systemFont(glyph_font_size), color);
}

fn tabBarMouseDown(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const self = viewClass().state(TabBar, target);
    const view_obj = objc.Object.fromId(target);
    const event = objc.Object.fromId(event_id);
    const loc = event.msgSend(NSPoint, "locationInWindow", .{});
    // Flipped view: the converted point is y-down, matching the pure math.
    const p = view_obj.msgSend(NSPoint, "convertPoint:fromView:", .{ loc, @as(c.id, null) });
    const bounds = view_obj.msgSend(NSRect, "bounds", .{});
    self.dispatchHit(hitTest(p.x, p.y, self.titles.len, bounds.size.width));
}

// ---------------------------------------------------------------------------
// Pure-geometry tests (no ObjC).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "tab width clamps between min and max" {
    // Zero tabs occupy no width.
    try testing.expectEqual(@as(f64, 0), tabWidth(800, 0));
    // One tab in a wide bar hits the 220 cap.
    try testing.expectEqual(max_tab_width, tabWidth(1200, 1));
    // Many tabs in a narrow bar hit the 100 floor.
    try testing.expectEqual(min_tab_width, tabWidth(400, 8));
    // In between: exact even split of the space left of the "+" button.
    // avail = 700 - 8 - 8 - 24 - 4 = 656; (656 - 4*3) / 4 = 161.
    try testing.expectEqual(@as(f64, 161), tabWidth(700, 4));
}

test "tab frames lay out left-to-right from the leading pad" {
    const w = tabWidth(1200, 3);
    const t0 = tabFrame(1200, 3, 0);
    const t1 = tabFrame(1200, 3, 1);
    try testing.expectEqual(h_pad, t0.origin.x);
    try testing.expectEqual(w, t0.size.width);
    try testing.expectEqual(tab_v_inset, t0.origin.y);
    try testing.expectEqual(bar_height - 2 * tab_v_inset, t0.size.height);
    // Adjacent tabs are exactly one gap apart.
    try testing.expectEqual(t0.origin.x + w + tab_gap, t1.origin.x);
}

test "close region sits at the leading inside edge of its tab" {
    const tab = tabFrame(1200, 2, 1);
    const close = closeFrame(tab);
    try testing.expectEqual(tab.origin.x + close_leading_pad, close.origin.x);
    try testing.expectEqual(close_edge, close.size.width);
    // Vertically centered inside the tab body.
    try testing.expect(close.origin.y > tab.origin.y);
    try testing.expect(close.origin.y + close.size.height < tab.origin.y + tab.size.height + 0.001);
}

test "new-tab button follows the last tab and clamps to the bar" {
    // Zero tabs: button at the leading edge.
    const empty = newButtonFrame(800, 0);
    try testing.expectEqual(h_pad, empty.origin.x);
    try testing.expectEqual(new_button_edge, empty.size.width);

    // Few tabs: right after the last tab (one gap past its trailing edge).
    const last = tabFrame(1200, 2, 1);
    const plus = newButtonFrame(1200, 2);
    try testing.expectEqual(last.origin.x + last.size.width + tab_gap, plus.origin.x);

    // Many tabs in a narrow bar: clamped to the right edge, not pushed out.
    const clamped = newButtonFrame(400, 8);
    try testing.expectEqual(400 - h_pad - new_button_edge, clamped.origin.x);
}

test "hit test: empty bar" {
    // Only the "+" button is live.
    const plus = newButtonFrame(800, 0);
    const hit = hitTest(plus.origin.x + 2, bar_height / 2, 0, 800);
    try testing.expectEqual(Hit.new_tab, hit);
    try testing.expectEqual(Hit.none, hitTest(200, bar_height / 2, 0, 800));
    // Outside the strip vertically.
    try testing.expectEqual(Hit.none, hitTest(plus.origin.x + 2, -1, 0, 800));
    try testing.expectEqual(Hit.none, hitTest(plus.origin.x + 2, bar_height + 1, 0, 800));
}

test "hit test: close region vs tab body" {
    const tab = tabFrame(1200, 3, 1);
    const close = closeFrame(tab);
    const cx = close.origin.x + close.size.width / 2;
    const cy = close.origin.y + close.size.height / 2;
    try testing.expectEqual(Hit{ .close = 1 }, hitTest(cx, cy, 3, 1200));
    // Same x but above the "×" square: the tab body wins.
    try testing.expectEqual(Hit{ .tab = 1 }, hitTest(cx, tab.origin.y + 0.5, 3, 1200));
    // Past the "×": tab body.
    const bx = close.origin.x + close.size.width + 10;
    try testing.expectEqual(Hit{ .tab = 1 }, hitTest(bx, cy, 3, 1200));
    // In the gap between tabs: nothing.
    const gap_x = tab.origin.x - tab_gap / 2;
    try testing.expectEqual(Hit.none, hitTest(gap_x, cy, 3, 1200));
    // Above/below the tab inset: nothing.
    try testing.expectEqual(Hit.none, hitTest(bx, 1, 3, 1200));
}

test "hit test: clamped plus button wins over overflowing tabs" {
    // 8 floor-width tabs overflow a 400pt bar; the "+" clamps to the right
    // edge on top of them and must take the click.
    const plus = newButtonFrame(400, 8);
    const hit = hitTest(plus.origin.x + 2, bar_height / 2, 8, 400);
    try testing.expectEqual(Hit.new_tab, hit);
}

// ---------------------------------------------------------------------------
// Headless ObjC tests (build + drive the real view; nothing on screen).
// ---------------------------------------------------------------------------
var g_test_selects: u32 = 0;
var g_test_closes: u32 = 0;
var g_test_news: u32 = 0;
var g_test_last_index: usize = 0;
var g_test_ctx: ?*anyopaque = null;

fn testOnSelect(ctx: *anyopaque, index: usize) void {
    g_test_selects += 1;
    g_test_last_index = index;
    g_test_ctx = ctx;
}

fn testOnClose(ctx: *anyopaque, index: usize) void {
    g_test_closes += 1;
    g_test_last_index = index;
    g_test_ctx = ctx;
}

fn testOnNew(ctx: *anyopaque) void {
    g_test_news += 1;
    g_test_ctx = ctx;
}

fn resetTestCounters() void {
    g_test_selects = 0;
    g_test_closes = 0;
    g_test_news = 0;
    g_test_last_index = 0;
    g_test_ctx = null;
}

fn testDelegate(ctx: *anyopaque) Delegate {
    return .{ .ctx = ctx, .onSelect = testOnSelect, .onClose = testOnClose, .onNew = testOnNew };
}

test "init / setTabs / setHidden state machine" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    var fake_ctx: u32 = 0;
    const bar = try TabBar.init(testing.allocator, rect(0, 0, 800, bar_height), testDelegate(&fake_ctx));
    defer bar.deinit();

    try testing.expectEqual(@as(usize, 0), bar.count());
    try testing.expectEqual(@as(usize, 0), bar.activeIndex());

    try bar.setTabs(&.{ "ftp.example.com", "Local" }, 1);
    try testing.expectEqual(@as(usize, 2), bar.count());
    try testing.expectEqual(@as(usize, 1), bar.activeIndex());
    try testing.expectEqualStrings("ftp.example.com", bar.titles[0]);
    try testing.expectEqualStrings("Local", bar.titles[1]);

    // Active index clamps to the new count; titles are replaced.
    try bar.setTabs(&.{"only"}, 5);
    try testing.expectEqual(@as(usize, 1), bar.count());
    try testing.expectEqual(@as(usize, 0), bar.activeIndex());

    // Back to empty frees everything (leak-checked by testing.allocator).
    try bar.setTabs(&.{}, 0);
    try testing.expectEqual(@as(usize, 0), bar.count());

    bar.setHidden(true);
    try testing.expect(foundation.toBool(bar.obj.msgSend(foundation.BOOL, "isHidden", .{})));
    bar.setHidden(false);
    try testing.expect(!foundation.toBool(bar.obj.msgSend(foundation.BOOL, "isHidden", .{})));
}

test "setTabs copies titles into owned memory" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    var fake_ctx: u32 = 0;
    const bar = try TabBar.init(testing.allocator, rect(0, 0, 800, bar_height), testDelegate(&fake_ctx));
    defer bar.deinit();

    var scratch = "mutable".*;
    try bar.setTabs(&.{&scratch}, 0);
    @memset(&scratch, '!');
    try testing.expectEqualStrings("mutable", bar.titles[0]);
}

test "hit dispatch routes to the delegate" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    var fake_ctx: u32 = 0xBEEF;
    const bar = try TabBar.init(testing.allocator, rect(0, 0, 800, bar_height), testDelegate(&fake_ctx));
    defer bar.deinit();
    try bar.setTabs(&.{ "a", "b", "c" }, 0);

    resetTestCounters();
    bar.dispatchHit(.{ .tab = 2 });
    try testing.expectEqual(@as(u32, 1), g_test_selects);
    try testing.expectEqual(@as(usize, 2), g_test_last_index);
    try testing.expectEqual(@as(?*anyopaque, &fake_ctx), g_test_ctx);

    bar.dispatchHit(.{ .close = 1 });
    try testing.expectEqual(@as(u32, 1), g_test_closes);
    try testing.expectEqual(@as(usize, 1), g_test_last_index);

    bar.dispatchHit(.new_tab);
    try testing.expectEqual(@as(u32, 1), g_test_news);

    bar.dispatchHit(.none);
    try testing.expectEqual(@as(u32, 1), g_test_selects);
    try testing.expectEqual(@as(u32, 1), g_test_closes);
    try testing.expectEqual(@as(u32, 1), g_test_news);
}

test "view is a RelayTabBar instance with the state attached" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    var fake_ctx: u32 = 0;
    const bar = try TabBar.init(testing.allocator, rect(0, 0, 800, bar_height), testDelegate(&fake_ctx));
    defer bar.deinit();

    try testing.expect(bar.view() != null);
    try testing.expectEqual(bar, viewClass().state(TabBar, bar.view()));
    // Flipped so the pure y-down geometry matches view coordinates.
    try testing.expect(foundation.toBool(bar.obj.msgSend(foundation.BOOL, "isFlipped", .{})));
}

test {
    testing.refAllDecls(@This());
}

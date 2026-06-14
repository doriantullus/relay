//! split_view — NSSplitView helpers: hSplit/vSplit with autosave names,
//! per-child min sizes (delegate class), holding priorities, and
//! programmatic collapse/uncollapse (sidebar Cmd+Opt+S, bottom panel Cmd+J).
//!
//! Collapse model: NSSplitView treats hidden subviews as collapsed, so
//! collapse(i) hides the child and calls adjustSubviews (the classic
//! non-NSSplitViewController approach; isSubviewCollapsed: agrees).
//!
//! Main thread only. All selector strings live in relay_mac (law).

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

// Shared ABI helpers: single definitions live in relay_mac foundation.zig,
// re-exported through table_source.zig (deduped in M2 phase 3).
const ts = @import("table_source.zig");
const NSInteger = ts.NSInteger;
const NSRect = ts.NSRect;
const rect = ts.rect;
const getClass = ts.getClass;
const nsStr = ts.nsStr;

pub const ChildSpec = struct {
    view: c.id,
    /// Minimum width (hSplit) or height (vSplit) in points.
    min_size: f64 = 0,
    /// May be collapsed by dragging the divider past the minimum or by
    /// collapse()/toggleCollapse().
    collapsible: bool = false,
    /// NSLayoutPriority-style holding priority; higher holds its size.
    holding_priority: ?f32 = null,
};

pub const Options = struct {
    autosave_name: ?[:0]const u8 = null,
};

/// Children laid out side by side (vertical dividers) — sidebar | content.
pub fn hSplit(
    alloc: std.mem.Allocator,
    children: []const ChildSpec,
    options: Options,
) !*SplitView {
    return SplitView.init(alloc, children, options, true);
}

/// Children stacked top to bottom (horizontal dividers) — panes / bottom panel.
pub fn vSplit(
    alloc: std.mem.Allocator,
    children: []const ChildSpec,
    options: Options,
) !*SplitView {
    return SplitView.init(alloc, children, options, false);
}

// Pure divider-constraint math (unit-tested headless).
pub fn minCoordinateForDivider(proposed: f64, subview_origin: f64, min_size: f64) f64 {
    return @max(proposed, subview_origin + min_size);
}

pub fn maxCoordinateForDivider(
    proposed: f64,
    next_subview_end: f64,
    next_min_size: f64,
    divider_thickness: f64,
) f64 {
    return @min(proposed, next_subview_end - next_min_size - divider_thickness);
}

// ---------------------------------------------------------------------------
// Runtime delegate class
// ---------------------------------------------------------------------------
var g_classes_ready = false;
var g_helper_class: objc.Class = undefined;
var g_helper_state_ivar: c.Ivar = null;

fn ensureClasses() void {
    if (g_classes_ready) return;
    g_classes_ready = true;

    const cls = objc.allocateClassPair(getClass("NSObject"), "RelaySplitDelegate") orelse
        @panic("allocateClassPair(RelaySplitDelegate)");
    if (!cls.addIvar("relayState")) @panic("addIvar(RelaySplitDelegate)");
    if (!cls.addMethod("splitView:constrainMinCoordinate:ofSubviewAt:", helperConstrainMin))
        @panic("addMethod(splitView:constrainMinCoordinate:ofSubviewAt:)");
    if (!cls.addMethod("splitView:constrainMaxCoordinate:ofSubviewAt:", helperConstrainMax))
        @panic("addMethod(splitView:constrainMaxCoordinate:ofSubviewAt:)");
    if (!cls.addMethod("splitView:canCollapseSubview:", helperCanCollapse))
        @panic("addMethod(splitView:canCollapseSubview:)");
    objc.registerClassPair(cls);
    g_helper_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
    if (g_helper_state_ivar == null) @panic("ivar lookup (RelaySplitDelegate)");
    g_helper_class = cls;
}

fn stateFromIvar(target: c.id) *SplitView {
    const raw = c.object_getIvar(target, g_helper_state_ivar) orelse
        @panic("relay split state ivar is null");
    return @ptrCast(@alignCast(raw));
}

// ---------------------------------------------------------------------------
// SplitView
// ---------------------------------------------------------------------------
pub const SplitView = struct {
    alloc: std.mem.Allocator,
    children: []ChildSpec,
    split: objc.Object,
    helper: objc.Object,
    /// true → children side by side (NSSplitView isVertical YES).
    horizontal: bool,
    /// Per-child remembered extent along the split axis, so uncollapse
    /// restores the size the user (or layout) last had it at.
    saved_extent: []f64,

    fn init(
        alloc: std.mem.Allocator,
        children: []const ChildSpec,
        options: Options,
        horizontal: bool,
    ) !*SplitView {
        ensureClasses();

        const self = try alloc.create(SplitView);
        errdefer alloc.destroy(self);
        const owned = try alloc.dupe(ChildSpec, children);
        errdefer alloc.free(owned);
        const saved = try alloc.alloc(f64, children.len);
        errdefer alloc.free(saved);
        @memset(saved, 0);

        const split = getClass("NSSplitView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 900, 600)});
        // "Vertical" in AppKit means vertical *dividers*, i.e. side-by-side.
        split.msgSend(void, "setVertical:", .{horizontal});
        split.msgSend(void, "setDividerStyle:", .{@as(NSInteger, 1)}); // thin

        const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});

        self.* = .{
            .alloc = alloc,
            .children = owned,
            .split = split,
            .helper = helper,
            .horizontal = horizontal,
            .saved_extent = saved,
        };
        c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(self));

        for (owned) |child| {
            split.msgSend(void, "addSubview:", .{objc.Object.fromId(child.view)});
        }
        for (owned, 0..) |child, i| {
            if (child.holding_priority) |priority| {
                split.msgSend(void, "setHoldingPriority:forSubviewAtIndex:", .{
                    priority, @as(NSInteger, @intCast(i)),
                });
            }
        }

        // Delegate before autosave so restoration consults the constraints.
        split.msgSend(void, "setDelegate:", .{helper});
        if (options.autosave_name) |name|
            split.msgSend(void, "setAutosaveName:", .{nsStr(name.ptr)});
        split.msgSend(void, "adjustSubviews", .{});

        return self;
    }

    pub fn deinit(self: *SplitView) void {
        self.split.msgSend(void, "setDelegate:", .{@as(c.id, null)});
        self.split.msgSend(void, "release", .{});
        self.helper.msgSend(void, "release", .{});
        self.alloc.free(self.children);
        self.alloc.free(self.saved_extent);
        self.alloc.destroy(self);
    }

    /// The NSSplitView to embed.
    pub fn view(self: *SplitView) c.id {
        return self.split.value;
    }

    /// Subview extent along the split axis (width for side-by-side, height
    /// for stacked). This is ground truth — `isSubviewCollapsed:`/`isHidden`
    /// track flags that NSSplitView does NOT honor under `adjustSubviews`,
    /// so collapse must move the divider and read the resulting frame back.
    fn axisExtent(self: *SplitView, index: usize) f64 {
        const f = self.subviewFrame(index);
        return if (self.horizontal) f.size.width else f.size.height;
    }

    fn splitAxisExtent(self: *SplitView) f64 {
        const f = self.split.msgSend(NSRect, "frame", .{});
        return if (self.horizontal) f.size.width else f.size.height;
    }

    fn dividerThickness(self: *SplitView) f64 {
        return self.split.msgSend(f64, "dividerThickness", .{});
    }

    pub fn isCollapsed(self: *SplitView, index: usize) bool {
        if (index >= self.children.len) return false;
        return self.axisExtent(index) < 1.0;
    }

    pub fn collapse(self: *SplitView, index: usize) void {
        if (index >= self.children.len) return;
        const cur = self.axisExtent(index);
        if (cur > 1.0) self.saved_extent[index] = cur; // remember for restore
        // Drive the bordering divider to the edge so the subview gets 0.
        // index 0 → divider 0 to the near edge; otherwise → divider before
        // it to the far edge (clamped by NSSplitView to the other minimums).
        if (index == 0) {
            self.setPosition(0, 0);
        } else {
            self.setPosition(index - 1, self.splitAxisExtent());
        }
    }

    pub fn uncollapse(self: *SplitView, index: usize) void {
        if (index >= self.children.len) return;
        var ext = self.saved_extent[index];
        const min = self.children[index].min_size;
        if (ext < min) ext = if (min > 1.0) min else 180;
        if (index == 0) {
            self.setPosition(0, ext);
        } else {
            const full = self.splitAxisExtent();
            self.setPosition(index - 1, full - ext - self.dividerThickness());
        }
    }

    /// Returns the new collapsed state.
    pub fn toggleCollapse(self: *SplitView, index: usize) bool {
        if (self.isCollapsed(index)) {
            self.uncollapse(index);
            return false;
        }
        self.collapse(index);
        return true;
    }

    /// Set the divider position (x for hSplit, y for vSplit).
    pub fn setPosition(self: *SplitView, divider_index: usize, position: f64) void {
        self.split.msgSend(void, "setPosition:ofDividerAtIndex:", .{
            position, @as(NSInteger, @intCast(divider_index)),
        });
    }

    fn subviewFrame(self: *SplitView, index: usize) NSRect {
        return objc.Object.fromId(self.children[index].view).msgSend(NSRect, "frame", .{});
    }

    fn origin(self: *SplitView, frame: NSRect) f64 {
        return if (self.horizontal) frame.origin.x else frame.origin.y;
    }

    fn extent(self: *SplitView, frame: NSRect) f64 {
        return if (self.horizontal) frame.size.width else frame.size.height;
    }
};

// ---------------------------------------------------------------------------
// Delegate IMPs
// ---------------------------------------------------------------------------
fn helperConstrainMin(
    target: c.id,
    _: c.SEL,
    _: c.id,
    proposed: f64,
    divider_index: NSInteger,
) callconv(.c) f64 {
    const sv = stateFromIvar(target);
    const i: usize = @intCast(divider_index);
    if (i >= sv.children.len) return proposed;
    // A collapsible subview may shrink all the way to 0 (that IS its
    // collapse); only non-collapsible children enforce a hard minimum.
    if (sv.children[i].collapsible) return proposed;
    const frame = sv.subviewFrame(i);
    return minCoordinateForDivider(proposed, sv.origin(frame), sv.children[i].min_size);
}

fn helperConstrainMax(
    target: c.id,
    _: c.SEL,
    _: c.id,
    proposed: f64,
    divider_index: NSInteger,
) callconv(.c) f64 {
    const sv = stateFromIvar(target);
    const next: usize = @intCast(divider_index + 1);
    if (next >= sv.children.len) return proposed;
    if (sv.children[next].collapsible) return proposed; // may collapse to 0
    const frame = sv.subviewFrame(next);
    const end = sv.origin(frame) + sv.extent(frame);
    const thickness = sv.dividerThickness();
    return maxCoordinateForDivider(proposed, end, sv.children[next].min_size, thickness);
}

fn helperCanCollapse(_: c.id, _: c.SEL, _: c.id, _: c.id) callconv(.c) c.BOOL {
    // Always NO: we collapse/uncollapse by driving the divider position
    // (relaxed constraints let collapsible children reach 0). If NSSplitView
    // owned the collapsed *flag*, it would refuse to restore size on
    // setPosition — leaving the panel stuck collapsed (the Cmd+J bug).
    return 0;
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
test "divider constraint math" {
    // Divider can't move left past subview-0 origin + min size.
    try std.testing.expectEqual(@as(f64, 180), minCoordinateForDivider(100, 0, 180));
    try std.testing.expectEqual(@as(f64, 300), minCoordinateForDivider(300, 0, 180));
    // Divider can't move right past (end of next subview - its min - divider).
    try std.testing.expectEqual(@as(f64, 699), maxCoordinateForDivider(800, 900, 200, 1));
    try std.testing.expectEqual(@as(f64, 500), maxCoordinateForDivider(500, 900, 200, 1));
}

test "delegate class registers and recovers state (headless)" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    ensureClasses();

    var sv: SplitView = undefined;
    sv.children = @constCast(&[_]ChildSpec{
        .{ .view = null, .collapsible = true },
        .{ .view = null },
    });
    sv.horizontal = true;

    const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    defer helper.msgSend(void, "release", .{});
    c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(&sv));

    // NSSplitView's own collapse is always disabled: we drive collapse by
    // divider position so setPosition can restore the size (NSSplitView
    // would otherwise latch the collapsed flag and refuse to expand).
    const can = helper.msgSend(c.BOOL, "splitView:canCollapseSubview:", .{
        @as(c.id, null), @as(c.id, null),
    });
    try std.testing.expectEqual(@as(c.BOOL, 0), can);
}

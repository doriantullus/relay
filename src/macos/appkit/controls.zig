//! controls — small AppKit control builders shared by the app's controllers
//! (prefs window, inspector panel, transcript/transfers bars). Lives in
//! relay_mac so every ObjC selector string stays in the wrapper layer (Law).
//!
//! Two label and two popup builders coexist on purpose: they differ in
//! ownership and styling, not just arguments. `makeLabel`/`makePopup` return
//! *autoreleased* controls (a superview must retain them) and carry the
//! prefs/inspector `LabelStyle`; `makeFieldLabel`/`makeEmptyPopup` return
//! *retained*, caller-owned controls wired to a target/action, as the
//! transcript/transfers status bars need. Merging them would change one
//! caller's memory contract, so they stay distinct.
//!
//! Main thread only.

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");

const Allocator = std.mem.Allocator;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const NSRect = foundation.NSRect;

// --- AppKit enum constants -------------------------------------------------
const ns_control_state_on: NSInteger = 1;
const button_type_switch: NSUInteger = 3; // NSButtonTypeSwitch
const button_type_radio: NSUInteger = 4; // NSButtonTypeRadio
const bezel_style_rounded: NSUInteger = 1; // NSBezelStyleRounded
const line_break_truncate_middle: NSUInteger = 5; // NSLineBreakByTruncatingMiddle
const text_alignment_right: NSInteger = 1; // NSTextAlignmentRight
const control_size_small: NSUInteger = 1; // NSControlSizeSmall

// NSAutoresizingMaskOptions.
pub const mask_min_x_margin: NSUInteger = 1 << 0;
pub const mask_width_sizable: NSUInteger = 1 << 1;
pub const mask_max_x_margin: NSUInteger = 1 << 2;
pub const mask_min_y_margin: NSUInteger = 1 << 3;
pub const mask_height_sizable: NSUInteger = 1 << 4;
pub const mask_max_y_margin: NSUInteger = 1 << 5;

// --- View plumbing ---------------------------------------------------------
pub fn addSubview(parent: objc.Object, child: objc.Object) void {
    parent.msgSend(void, "addSubview:", .{child});
}

pub fn release(obj: objc.Object) void {
    obj.msgSend(void, "release", .{});
}

pub fn setHidden(view: objc.Object, hidden: bool) void {
    view.msgSend(void, "setHidden:", .{hidden});
}

pub fn isHidden(view: objc.Object) bool {
    return foundation.toBool(view.msgSend(foundation.BOOL, "isHidden", .{}));
}

pub fn setFrame(view: objc.Object, frame: NSRect) void {
    view.msgSend(void, "setFrame:", .{frame});
}

/// Plain container NSView (retain count 1, caller-owned).
pub fn makeView(frame: NSRect) objc.Object {
    return foundation.class("NSView").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame});
}

pub fn setAutoresizing(view: objc.Object, mask: NSUInteger) void {
    view.msgSend(void, "setAutoresizingMask:", .{mask});
}

/// Retain an autoreleased id the caller wants to cache (e.g. an SF Symbol
/// NSImage). Null passes through.
pub fn retainId(maybe: ?c.id) ?c.id {
    const id_val = maybe orelse return null;
    _ = objc.Object.fromId(id_val).msgSend(c.id, "retain", .{});
    return id_val;
}

pub fn releaseId(maybe: ?c.id) void {
    const id_val = maybe orelse return;
    objc.Object.fromId(id_val).msgSend(void, "release", .{});
}

// --- Labels ----------------------------------------------------------------
pub const LabelStyle = struct {
    bold: bool = false,
    secondary: bool = false,
    small: bool = false,
    right: bool = false,
    selectable: bool = false,
    truncate_middle: bool = false,
};

/// Non-editable text label (autoreleased; a superview must retain it).
/// Used by the prefs window and inspector panel.
pub fn makeLabel(text: []const u8, frame: NSRect, style: LabelStyle) objc.Object {
    const label = foundation.class("NSTextField")
        .msgSend(objc.Object, "labelWithString:", .{foundation.nsString(text)});
    label.msgSend(void, "setFrame:", .{frame});
    if (style.right) label.msgSend(void, "setAlignment:", .{text_alignment_right});
    if (style.selectable) label.msgSend(void, "setSelectable:", .{true});
    if (style.truncate_middle) label.msgSend(void, "setLineBreakMode:", .{line_break_truncate_middle});
    const font_size: foundation.CGFloat = if (style.small)
        foundation.smallSystemFontSize()
    else
        foundation.systemFontSize();
    const font = if (style.bold)
        foundation.boldSystemFont(font_size)
    else
        foundation.systemFont(font_size);
    label.msgSend(void, "setFont:", .{font});
    if (style.secondary) label.msgSend(void, "setTextColor:", .{foundation.secondaryLabelColor()});
    return label;
}

/// Small secondary status label (retained, caller-owned). Used by the
/// transcript/transfers bars, which cache the label and release it on deinit.
pub fn makeFieldLabel(text: []const u8, frame: NSRect, right_aligned: bool) objc.Object {
    const label = foundation.class("NSTextField")
        .msgSend(objc.Object, "labelWithString:", .{foundation.nsString(text)});
    label.msgSend(void, "setFrame:", .{frame});
    label.msgSend(void, "setFont:", .{foundation.systemFont(11)});
    label.msgSend(void, "setTextColor:", .{foundation.secondaryLabelColor()});
    if (right_aligned) label.msgSend(void, "setAlignment:", .{text_alignment_right});
    _ = label.msgSend(c.id, "retain", .{});
    return label;
}

pub fn setLabelText(label: objc.Object, text: []const u8) void {
    label.msgSend(void, "setStringValue:", .{foundation.nsString(text)});
}

// --- Buttons ---------------------------------------------------------------
pub fn makeCheckbox(title: []const u8, frame: NSRect) objc.Object {
    const button = foundation.class("NSButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    button.msgSend(void, "setButtonType:", .{button_type_switch});
    button.msgSend(void, "setTitle:", .{foundation.nsString(title)});
    return button;
}

/// Radio button; AppKit groups radios sharing one target+action.
pub fn makeRadio(title: []const u8, frame: NSRect) objc.Object {
    const button = foundation.class("NSButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    button.msgSend(void, "setButtonType:", .{button_type_radio});
    button.msgSend(void, "setTitle:", .{foundation.nsString(title)});
    return button;
}

pub fn makePushButton(title: []const u8, frame: NSRect) objc.Object {
    const button = foundation.class("NSButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    button.msgSend(void, "setBezelStyle:", .{bezel_style_rounded});
    button.msgSend(void, "setTitle:", .{foundation.nsString(title)});
    return button;
}

/// Small rounded push button wired to `target`/`action` (caller-owned).
pub fn makeButton(title: []const u8, frame: NSRect, target: c.id, action: [:0]const u8) objc.Object {
    const button = foundation.class("NSButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame});
    button.msgSend(void, "setTitle:", .{foundation.nsString(title)});
    button.msgSend(void, "setBezelStyle:", .{bezel_style_rounded});
    button.msgSend(void, "setControlSize:", .{control_size_small});
    button.msgSend(void, "setFont:", .{foundation.systemFont(11)});
    button.msgSend(void, "setTarget:", .{target});
    button.msgSend(void, "setAction:", .{objc.sel(action)});
    return button;
}

// --- Segmented control -----------------------------------------------------
/// Select-one segmented control (caller-owned), segment 0 selected.
pub fn makeSegmented(labels: []const []const u8, frame: NSRect, target: c.id, action: [:0]const u8) objc.Object {
    const seg = foundation.class("NSSegmentedControl").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame});
    seg.msgSend(void, "setSegmentCount:", .{@as(NSInteger, @intCast(labels.len))});
    for (labels, 0..) |label, i| setSegmentLabel(seg, i, label);
    seg.msgSend(void, "setControlSize:", .{control_size_small});
    seg.msgSend(void, "setSelectedSegment:", .{@as(NSInteger, 0)});
    seg.msgSend(void, "setTarget:", .{target});
    seg.msgSend(void, "setAction:", .{objc.sel(action)});
    return seg;
}

pub fn setSegmentLabel(seg: objc.Object, index: usize, label: []const u8) void {
    seg.msgSend(void, "setLabel:forSegment:", .{
        foundation.nsString(label), @as(NSInteger, @intCast(index)),
    });
}

pub fn selectedSegment(seg: objc.Object) NSInteger {
    return seg.msgSend(NSInteger, "selectedSegment", .{});
}

// --- Slider / text field ---------------------------------------------------
pub fn makeSlider(frame: NSRect, min: f64, max: f64, value: f64) objc.Object {
    const slider = foundation.class("NSSlider").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    slider.msgSend(void, "setMinValue:", .{min});
    slider.msgSend(void, "setMaxValue:", .{max});
    slider.msgSend(void, "setDoubleValue:", .{value});
    slider.msgSend(void, "setContinuous:", .{true});
    return slider;
}

pub fn makeTextField(frame: NSRect, initial: []const u8) objc.Object {
    const field = foundation.class("NSTextField").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    if (initial.len > 0) field.msgSend(void, "setStringValue:", .{foundation.nsString(initial)});
    return field;
}

// --- Popups ----------------------------------------------------------------
/// Pull-down-less popup pre-filled from `options` (autoreleased). Used by the
/// prefs window.
pub fn makePopup(frame: NSRect, options: []const []const u8) objc.Object {
    const popup = foundation.class("NSPopUpButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:pullsDown:", .{ frame, false })
        .msgSend(objc.Object, "autorelease", .{});
    for (options) |option| {
        popup.msgSend(void, "addItemWithTitle:", .{foundation.nsString(option)});
    }
    return popup;
}

/// Empty pull-down-less popup wired to `target`/`action` (caller-owned);
/// items added later via `popupAddItem`. Used by the transcript filter bar.
pub fn makeEmptyPopup(frame: NSRect, target: c.id, action: [:0]const u8) objc.Object {
    const popup = foundation.class("NSPopUpButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:pullsDown:", .{ frame, false });
    popup.msgSend(void, "setControlSize:", .{control_size_small});
    popup.msgSend(void, "setFont:", .{foundation.systemFont(11)});
    popup.msgSend(void, "setTarget:", .{target});
    popup.msgSend(void, "setAction:", .{objc.sel(action)});
    return popup;
}

pub fn popupAddItem(popup: objc.Object, title: []const u8) void {
    popup.msgSend(void, "addItemWithTitle:", .{foundation.nsString(title)});
}

pub fn popupIndex(popup: objc.Object) NSInteger {
    return popup.msgSend(NSInteger, "indexOfSelectedItem", .{});
}
pub const popupSelectedIndex = popupIndex;

pub fn setPopupIndex(popup: objc.Object, index: NSInteger) void {
    popup.msgSend(void, "selectItemAtIndex:", .{index});
}

// --- Generic control getters/setters --------------------------------------
pub fn isChecked(control: objc.Object) bool {
    return control.msgSend(NSInteger, "state", .{}) == ns_control_state_on;
}

pub fn setChecked(control: objc.Object, on: bool) void {
    control.msgSend(void, "setState:", .{@as(NSInteger, if (on) 1 else 0)});
}

pub fn sliderValue(slider: objc.Object) f64 {
    return slider.msgSend(f64, "doubleValue", .{});
}

pub fn setSliderValue(slider: objc.Object, value: f64) void {
    slider.msgSend(void, "setDoubleValue:", .{value});
}

/// UTF-8 copy of an NSControl's stringValue, owned by `gpa`.
pub fn textValue(gpa: Allocator, control: objc.Object) Allocator.Error![]u8 {
    return foundation.utf8FromNSString(gpa, control.msgSend(objc.Object, "stringValue", .{}));
}

pub fn setTextValue(control: objc.Object, text: []const u8) void {
    control.msgSend(void, "setStringValue:", .{foundation.nsString(text)});
}

pub fn setEnabled(control: objc.Object, enabled: bool) void {
    control.msgSend(void, "setEnabled:", .{enabled});
}

pub fn isEnabled(control: objc.Object) bool {
    return foundation.toBool(control.msgSend(foundation.BOOL, "isEnabled", .{}));
}

// --- Runloop pump (visual smoke tests) -------------------------------------
const NSDefaultRunLoopMode = @extern(*const c.id, .{ .name = "NSDefaultRunLoopMode" });

/// Pump the current runloop for up to `seconds`.
pub fn runLoopSpin(seconds: f64) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const run_loop = foundation.class("NSRunLoop").msgSend(objc.Object, "currentRunLoop", .{});
    const date = foundation.class("NSDate")
        .msgSend(objc.Object, "dateWithTimeIntervalSinceNow:", .{seconds});
    _ = run_loop.msgSend(c.BOOL, "runMode:beforeDate:", .{
        objc.Object.fromId(NSDefaultRunLoopMode.*), date,
    });
}

// --- Shared target/action dispatcher (mirrors menu.Registry) ---------------
pub const ControlAction = struct {
    ctx: ?*anyopaque = null,
    f: *const fn (ctx: ?*anyopaque, sender: c.id) void,
};

var g_target_class: ?runtime.DefinedClass = null;

fn targetClass() runtime.DefinedClass {
    if (g_target_class) |dc| return dc;
    const dc = runtime.defineClass("RelayControlTarget", "NSObject", &.{}, .{
        .{ "relayControlChanged:", controlChangedImp },
    }) catch @panic("appkit/controls: failed to define RelayControlTarget");
    g_target_class = dc;
    return dc;
}

fn controlChangedImp(target: c.id, _: c.SEL, sender: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const self = targetClass().state(ControlTarget, target);
    const tag = objc.Object.fromId(sender).msgSend(NSInteger, "tag", .{});
    if (tag < 0 or tag >= @as(NSInteger, @intCast(self.entries.items.len))) return;
    const action = self.entries.items[@intCast(tag)];
    action.f(action.ctx, sender);
}

/// Owns the tag→action table + the shared target instance. One per
/// controller; must outlive every control wired against it.
pub const ControlTarget = struct {
    gpa: Allocator,
    entries: std.ArrayList(ControlAction) = .empty,
    target: objc.Object,

    pub fn create(gpa: Allocator) Allocator.Error!*ControlTarget {
        const self = try gpa.create(ControlTarget);
        self.* = .{ .gpa = gpa, .target = undefined };
        self.target = targetClass().newWithState(self);
        return self;
    }

    pub fn destroy(self: *ControlTarget) void {
        self.target.msgSend(void, "release", .{});
        self.entries.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Route `control`'s action to `f(ctx, sender)` (tag-dispatched).
    pub fn wire(
        self: *ControlTarget,
        control: objc.Object,
        ctx: ?*anyopaque,
        f: *const fn (?*anyopaque, c.id) void,
    ) Allocator.Error!void {
        const tag: NSInteger = @intCast(self.entries.items.len);
        try self.entries.append(self.gpa, .{ .ctx = ctx, .f = f });
        control.msgSend(void, "setTag:", .{tag});
        control.msgSend(void, "setTarget:", .{self.target});
        control.msgSend(void, "setAction:", .{objc.sel("relayControlChanged:")});
    }
};

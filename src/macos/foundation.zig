//! foundation — the ABI base of relay_mac. Every other wrapper imports this.
//!
//! Owns (per docs/spikes/ui.md, the law): the LP64 scalar/geometry types,
//! BOOL helpers, NSString/NSNumber/NSURL conversion, autorelease-pool scope
//! helpers (including the retain/pop/autorelease dance for value-returning
//! callbacks), NSNotificationCenter glue, semantic NSColor accessors, and
//! NSFont helpers. Selector strings live HERE, never in src/app/.

const std = @import("std");
const objc = @import("objc");

pub const c = objc.c;

// ---------------------------------------------------------------------------
// ABI scalar + geometry types (LP64: NSInteger == long == i64, CGFloat == f64).
// NSInteger is i64, NOT c_long: zig-objc's type encoder emits 'l' for c_long
// but Apple's LP64 encoding for long is 'q' (docs/spikes/ui.md).
// ---------------------------------------------------------------------------
pub const NSInteger = i64;
pub const NSUInteger = u64;
pub const CGFloat = f64;

pub const NSPoint = extern struct { x: CGFloat = 0, y: CGFloat = 0 };
pub const NSSize = extern struct { width: CGFloat = 0, height: CGFloat = 0 };
pub const NSRect = extern struct { origin: NSPoint = .{}, size: NSSize = .{} };
pub const NSRange = extern struct { location: NSUInteger = 0, length: NSUInteger = 0 };

pub fn point(x: CGFloat, y: CGFloat) NSPoint {
    return .{ .x = x, .y = y };
}

pub fn size(w: CGFloat, h: CGFloat) NSSize {
    return .{ .width = w, .height = h };
}

pub fn rect(x: CGFloat, y: CGFloat, w: CGFloat, h: CGFloat) NSRect {
    return .{ .origin = point(x, y), .size = size(w, h) };
}

// ---------------------------------------------------------------------------
// BOOL: macOS keeps old-style signed-char BOOL on both x86_64 and arm64.
// Compare `!= 0` to read; return 0/1 from BOOL-returning IMPs.
// ---------------------------------------------------------------------------
comptime {
    if (c.BOOL != i8) @compileError("relay_mac expects ObjC BOOL == i8 on macOS");
}

pub const BOOL = i8;
pub const YES: BOOL = 1;
pub const NO: BOOL = 0;

pub inline fn toBool(v: BOOL) bool {
    return v != 0;
}

pub inline fn fromBool(v: bool) BOOL {
    return @intFromBool(v);
}

// ---------------------------------------------------------------------------
// Class lookup. Classes are link-time facts; a miss is a programmer error.
// ---------------------------------------------------------------------------
pub fn class(name: [:0]const u8) objc.Class {
    return objc.getClass(name) orelse
        std.debug.panic("relay_mac: ObjC class not found: {s}", .{name});
}

/// `nil` as a typed constant for msgSend args (`.{foundation.nil}`).
pub const nil: c.id = null;

// ---------------------------------------------------------------------------
// NSString
// ---------------------------------------------------------------------------
const ns_utf8_string_encoding: NSUInteger = 4;

/// Autoreleased NSString from any UTF-8 slice (no sentinel required).
pub fn nsString(utf8: []const u8) objc.Object {
    if (utf8.len == 0) return class("NSString").msgSend(objc.Object, "string", .{});
    return class("NSString").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithBytes:length:encoding:", .{
            utf8.ptr, @as(NSUInteger, utf8.len), ns_utf8_string_encoding,
        })
        .msgSend(objc.Object, "autorelease", .{});
}

/// Autoreleased NSString from a sentinel-terminated string (hot path; no
/// length bookkeeping on our side).
pub fn nsStringZ(utf8: [:0]const u8) objc.Object {
    return class("NSString").msgSend(objc.Object, "stringWithUTF8String:", .{utf8.ptr});
}

/// Stack-buffer variant for hot paths: format into the caller's buffer
/// (no heap) and wrap the result. Errors if the buffer is too small.
pub fn nsStringFmt(buf: []u8, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!objc.Object {
    const z = try std.fmt.bufPrintZ(buf, fmt, args);
    return nsStringZ(z);
}

/// UTF-8 copy of an NSString, owned by `gpa`.
pub fn utf8FromNSString(gpa: std.mem.Allocator, str: objc.Object) std.mem.Allocator.Error![]u8 {
    const ptr = str.msgSend(?[*:0]const u8, "UTF8String", .{}) orelse return gpa.dupe(u8, "");
    return gpa.dupe(u8, std.mem.span(ptr));
}

// ---------------------------------------------------------------------------
// NSNumber
// ---------------------------------------------------------------------------
pub fn nsNumberFromI64(v: i64) objc.Object {
    return class("NSNumber").msgSend(objc.Object, "numberWithLongLong:", .{v});
}

pub fn nsNumberFromU64(v: u64) objc.Object {
    return class("NSNumber").msgSend(objc.Object, "numberWithUnsignedLongLong:", .{v});
}

pub fn nsNumberFromF64(v: f64) objc.Object {
    return class("NSNumber").msgSend(objc.Object, "numberWithDouble:", .{v});
}

pub fn nsNumberFromBool(v: bool) objc.Object {
    return class("NSNumber").msgSend(objc.Object, "numberWithBool:", .{fromBool(v)});
}

pub fn i64FromNSNumber(num: objc.Object) i64 {
    return num.msgSend(i64, "longLongValue", .{});
}

pub fn u64FromNSNumber(num: objc.Object) u64 {
    return num.msgSend(u64, "unsignedLongLongValue", .{});
}

pub fn f64FromNSNumber(num: objc.Object) f64 {
    return num.msgSend(f64, "doubleValue", .{});
}

pub fn boolFromNSNumber(num: objc.Object) bool {
    return toBool(num.msgSend(BOOL, "boolValue", .{}));
}

// ---------------------------------------------------------------------------
// NSURL
// ---------------------------------------------------------------------------
pub fn fileURL(path: []const u8) objc.Object {
    return class("NSURL").msgSend(objc.Object, "fileURLWithPath:", .{nsString(path)});
}

pub fn urlWithString(s: []const u8) objc.Object {
    return class("NSURL").msgSend(objc.Object, "URLWithString:", .{nsString(s)});
}

/// File-system path of a file URL, owned by `gpa`.
pub fn pathFromURL(gpa: std.mem.Allocator, url: objc.Object) std.mem.Allocator.Error![]u8 {
    const ptr = url.msgSend(?[*:0]const u8, "fileSystemRepresentation", .{}) orelse
        return gpa.dupe(u8, "");
    return gpa.dupe(u8, std.mem.span(ptr));
}

// ---------------------------------------------------------------------------
// Autorelease-pool scope helpers
// ---------------------------------------------------------------------------
pub const AutoreleasePool = objc.AutoreleasePool;

/// Run `func(args...)` inside its own autorelease pool and return its result.
pub fn withPool(func: anytype, args: anytype) @typeInfo(@TypeOf(func)).@"fn".return_type.? {
    const pool = AutoreleasePool.init();
    defer pool.deinit();
    return @call(.auto, func, args);
}

/// The retain/pop/autorelease dance for value-returning callbacks
/// (docs/spikes/ui.md): retain `result`, pop `pool`, then re-autorelease
/// into the caller's (AppKit event-loop) pool. CONSUMES the pool — do not
/// `deinit` it again.
pub fn keepAcrossPool(pool: *AutoreleasePool, result: c.id) c.id {
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

// ---------------------------------------------------------------------------
// NSPasteboard
// ---------------------------------------------------------------------------
const NSPasteboardTypeString = @extern(*const c.id, .{ .name = "NSPasteboardTypeString" });

/// Replace the general pasteboard's contents with `text` as a plain string.
/// Runs in its own autorelease pool. Main thread only.
pub fn writeStringToPasteboard(text: []const u8) void {
    const pool = AutoreleasePool.init();
    defer pool.deinit();
    const pb = class("NSPasteboard").msgSend(objc.Object, "generalPasteboard", .{});
    _ = pb.msgSend(NSInteger, "clearContents", .{});
    _ = pb.msgSend(BOOL, "setString:forType:", .{ nsString(text), NSPasteboardTypeString.* });
}

// ---------------------------------------------------------------------------
// AppKit text-attribute keys + drawing constants (shared by the custom
// drawRect: views: table_source, outline_view, banner, tab_bar).
// ---------------------------------------------------------------------------
pub const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
pub const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });
pub const NSParagraphStyleAttributeName = @extern(*const c.id, .{ .name = "NSParagraphStyleAttributeName" });

/// NSLineBreakByTruncatingTail.
pub const line_break_truncating_tail: NSInteger = 4;
/// NSCompositingOperationSourceOver.
pub const compositing_source_over: NSUInteger = 2;

// ---------------------------------------------------------------------------
// NSNotificationCenter (default center; object: is always nil — Relay uses
// names + Zig-side state, not ObjC notification objects).
// ---------------------------------------------------------------------------
pub fn notificationCenter() objc.Object {
    return class("NSNotificationCenter").msgSend(objc.Object, "defaultCenter", .{});
}

/// `target` must respond to `selector` (one `id` argument: the NSNotification).
pub fn observeNotification(name: [:0]const u8, target: objc.Object, selector: [:0]const u8) void {
    notificationCenter().msgSend(void, "addObserver:selector:name:object:", .{
        target, objc.sel(selector), nsStringZ(name), nil,
    });
}

pub fn removeObserver(target: objc.Object) void {
    notificationCenter().msgSend(void, "removeObserver:", .{target});
}

pub fn postNotification(name: [:0]const u8) void {
    notificationCenter().msgSend(void, "postNotificationName:object:", .{ nsStringZ(name), nil });
}

// ---------------------------------------------------------------------------
// Semantic NSColors ONLY (docs/UX.md law: zero hard-coded colors).
// ---------------------------------------------------------------------------
pub const Color = enum {
    label,
    secondary_label,
    tertiary_label,
    quaternary_label,
    control_accent,
    control_text,
    disabled_control_text,
    separator,
    grid,
    window_background,
    control_background,
    text_background,
    under_page_background,
    selected_content_background,
    unemphasized_selected_content_background,
    selected_text_background,
    system_red,
    system_orange,
    system_yellow,
    system_green,
    system_blue,
    system_purple,
    system_gray,

    pub fn object(self: Color) objc.Object {
        const sel_name: [:0]const u8 = switch (self) {
            .label => "labelColor",
            .secondary_label => "secondaryLabelColor",
            .tertiary_label => "tertiaryLabelColor",
            .quaternary_label => "quaternaryLabelColor",
            .control_accent => "controlAccentColor",
            .control_text => "controlTextColor",
            .disabled_control_text => "disabledControlTextColor",
            .separator => "separatorColor",
            .grid => "gridColor",
            .window_background => "windowBackgroundColor",
            .control_background => "controlBackgroundColor",
            .text_background => "textBackgroundColor",
            .under_page_background => "underPageBackgroundColor",
            .selected_content_background => "selectedContentBackgroundColor",
            .unemphasized_selected_content_background => "unemphasizedSelectedContentBackgroundColor",
            .selected_text_background => "selectedTextBackgroundColor",
            .system_red => "systemRedColor",
            .system_orange => "systemOrangeColor",
            .system_yellow => "systemYellowColor",
            .system_green => "systemGreenColor",
            .system_blue => "systemBlueColor",
            .system_purple => "systemPurpleColor",
            .system_gray => "systemGrayColor",
        };
        return class("NSColor").msgSend(objc.Object, sel_name, .{});
    }

    /// `setFill` for drawRect: bodies.
    pub fn setFill(self: Color) void {
        self.object().msgSend(void, "setFill", .{});
    }
};

// Common accessors, named for call-site readability.
pub fn labelColor() objc.Object {
    return Color.label.object();
}

pub fn secondaryLabelColor() objc.Object {
    return Color.secondary_label.object();
}

pub fn controlAccentColor() objc.Object {
    return Color.control_accent.object();
}

// ---------------------------------------------------------------------------
// NSFont helpers
// ---------------------------------------------------------------------------
const NSFontWeightRegular = @extern(*const CGFloat, .{ .name = "NSFontWeightRegular" });
const NSFontWeightMedium = @extern(*const CGFloat, .{ .name = "NSFontWeightMedium" });
const NSFontWeightSemibold = @extern(*const CGFloat, .{ .name = "NSFontWeightSemibold" });
const NSFontWeightBold = @extern(*const CGFloat, .{ .name = "NSFontWeightBold" });

pub const FontWeight = enum {
    regular,
    medium,
    semibold,
    bold,

    pub fn value(self: FontWeight) CGFloat {
        return switch (self) {
            .regular => NSFontWeightRegular.*,
            .medium => NSFontWeightMedium.*,
            .semibold => NSFontWeightSemibold.*,
            .bold => NSFontWeightBold.*,
        };
    }
};

pub fn systemFont(font_size: CGFloat) objc.Object {
    return class("NSFont").msgSend(objc.Object, "systemFontOfSize:", .{font_size});
}

pub fn systemFontWeighted(font_size: CGFloat, weight: FontWeight) objc.Object {
    return class("NSFont").msgSend(objc.Object, "systemFontOfSize:weight:", .{ font_size, weight.value() });
}

pub fn boldSystemFont(font_size: CGFloat) objc.Object {
    return class("NSFont").msgSend(objc.Object, "boldSystemFontOfSize:", .{font_size});
}

/// The file-list Size/Modified column font (docs/UX.md: monospaced digits).
pub fn monospacedDigitSystemFont(font_size: CGFloat, weight: FontWeight) objc.Object {
    return class("NSFont").msgSend(objc.Object, "monospacedDigitSystemFontOfSize:weight:", .{
        font_size, weight.value(),
    });
}

/// Full monospace (transcript surface).
pub fn monospacedSystemFont(font_size: CGFloat, weight: FontWeight) objc.Object {
    return class("NSFont").msgSend(objc.Object, "monospacedSystemFontOfSize:weight:", .{
        font_size, weight.value(),
    });
}

pub fn systemFontSize() CGFloat {
    return class("NSFont").msgSend(CGFloat, "systemFontSize", .{});
}

pub fn smallSystemFontSize() CGFloat {
    return class("NSFont").msgSend(CGFloat, "smallSystemFontSize", .{});
}

// ---------------------------------------------------------------------------
// Tests (headless: conversions + round-trips; no windows).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "BOOL and geometry helpers" {
    try testing.expect(toBool(YES));
    try testing.expect(!toBool(NO));
    try testing.expectEqual(YES, fromBool(true));
    try testing.expectEqual(NO, fromBool(false));

    const r = rect(1, 2, 3, 4);
    try testing.expectEqual(@as(CGFloat, 1), r.origin.x);
    try testing.expectEqual(@as(CGFloat, 2), r.origin.y);
    try testing.expectEqual(@as(CGFloat, 3), r.size.width);
    try testing.expectEqual(@as(CGFloat, 4), r.size.height);
    try testing.expectEqual(@as(usize, 32), @sizeOf(NSRect));
}

test "NSString round-trips" {
    const pool = AutoreleasePool.init();
    defer pool.deinit();

    const cases = [_][]const u8{ "hello", "héllo wörld — ☃", "" };
    for (cases) |case| {
        const str = nsString(case);
        const back = try utf8FromNSString(testing.allocator, str);
        defer testing.allocator.free(back);
        try testing.expectEqualStrings(case, back);
    }

    const z = nsStringZ("relay/z");
    const back_z = try utf8FromNSString(testing.allocator, z);
    defer testing.allocator.free(back_z);
    try testing.expectEqualStrings("relay/z", back_z);

    var buf: [64]u8 = undefined;
    const fmted = try nsStringFmt(&buf, "{d} items in {s}", .{ @as(u32, 42), "pane" });
    const back_f = try utf8FromNSString(testing.allocator, fmted);
    defer testing.allocator.free(back_f);
    try testing.expectEqualStrings("42 items in pane", back_f);

    var tiny: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, nsStringFmt(&tiny, "{s}", .{"too long for tiny"}));
}

test "NSNumber round-trips" {
    const pool = AutoreleasePool.init();
    defer pool.deinit();

    try testing.expectEqual(@as(i64, -123456789), i64FromNSNumber(nsNumberFromI64(-123456789)));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), u64FromNSNumber(nsNumberFromU64(std.math.maxInt(u64))));
    try testing.expectEqual(@as(f64, 2.5), f64FromNSNumber(nsNumberFromF64(2.5)));
    try testing.expect(boolFromNSNumber(nsNumberFromBool(true)));
    try testing.expect(!boolFromNSNumber(nsNumberFromBool(false)));
}

test "NSURL file round-trip" {
    const pool = AutoreleasePool.init();
    defer pool.deinit();

    const url = fileURL("/usr/bin/true");
    const back = try pathFromURL(testing.allocator, url);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("/usr/bin/true", back);
}

test "semantic colors all resolve" {
    const pool = AutoreleasePool.init();
    defer pool.deinit();

    inline for (comptime std.enums.values(Color)) |color| {
        try testing.expect(color.object().value != null);
    }
    try testing.expect(labelColor().value != null);
    try testing.expect(secondaryLabelColor().value != null);
    try testing.expect(controlAccentColor().value != null);
}

test "fonts resolve and weights are ordered" {
    const pool = AutoreleasePool.init();
    defer pool.deinit();

    try testing.expect(systemFont(13).value != null);
    try testing.expect(systemFontWeighted(13, .semibold).value != null);
    try testing.expect(boldSystemFont(13).value != null);
    try testing.expect(monospacedDigitSystemFont(11, .regular).value != null);
    try testing.expect(monospacedSystemFont(11, .medium).value != null);
    try testing.expect(systemFontSize() > 0);
    try testing.expect(smallSystemFontSize() > 0);
    try testing.expect(FontWeight.regular.value() < FontWeight.bold.value());
}

test "withPool returns values" {
    const Fns = struct {
        fn double(x: u32) u32 {
            return x * 2;
        }
    };
    try testing.expectEqual(@as(u32, 84), withPool(Fns.double, .{@as(u32, 42)}));
}

test {
    testing.refAllDecls(@This());
}

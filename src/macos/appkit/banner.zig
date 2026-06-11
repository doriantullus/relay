//! banner — the reusable inline error/warning/info bar drawn ABOVE a file
//! list. A thin, NON-MODAL strip: a leading tinted SF Symbol, a tail-
//! truncated message, and a trailing dismiss "×" button. This is the
//! always-visible surface for async failures (connect refused/timeout, the
//! FTPS data-channel listing timeout, dropped connections); the sheet popup
//! is reserved for a just-initiated user CONNECT.
//!
//! Built on the same mechanics as table_source.zig: a runtime-defined NSView
//! subclass that custom-draws in drawRect: (the paragraph-style/clip pattern
//! so a long reason never overflows), state recovered from a cached ivar, and
//! semantic NSColors only (systemRed/Yellow/Blue at low alpha + labelColor).
//!
//! Threading: every public method and the dismiss callback run on the main
//! thread only; callbacks are pool-wrapped.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");
const ts = @import("table_source.zig");

const c = objc.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const NSRect = foundation.NSRect;
const NSSize = foundation.NSSize;
const NSPoint = foundation.NSPoint;
const rect = foundation.rect;
const getClass = foundation.class;

// ---------------------------------------------------------------------------
// Geometry (fixed-frame; the banner is a thin strip pinned above the list).
// ---------------------------------------------------------------------------
/// Canonical banner height. Hosts give the strip exactly this many points.
pub const banner_height: f64 = 28;

const h_pad: f64 = 8;
const icon_text_gap: f64 = 6;
const icon_edge: f64 = 14;
const dismiss_edge: f64 = 20;
const dismiss_trailing_pad: f64 = 4;
const font_size: f64 = 12;
const tint_alpha: f64 = 0.15;
const compositing_source_over: NSUInteger = 2;
const line_break_truncating_tail: NSInteger = 4; // NSLineBreakByTruncatingTail

/// Max bytes of reason text retained for drawing. Diagnostic messages are
/// short; anything longer is truncated at the byte level (and again
/// visually by the tail-truncating paragraph style).
const message_cap: usize = 512;

// ---------------------------------------------------------------------------
// Kind → semantic color. Tints the background (at low alpha) and the symbol.
// ---------------------------------------------------------------------------
pub const Kind = enum {
    @"error",
    warning,
    info,

    fn color(self: Kind) foundation.Color {
        return switch (self) {
            .@"error" => .system_red,
            .warning => .system_yellow,
            .info => .system_blue,
        };
    }
};

const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });
const NSParagraphStyleAttributeName = @extern(*const c.id, .{ .name = "NSParagraphStyleAttributeName" });

const symbol_name: [*:0]const u8 = "exclamationmark.triangle.fill";

// ---------------------------------------------------------------------------
// Runtime classes (defined once, shared across every Banner instance).
// ---------------------------------------------------------------------------
var g_view_class: ?runtime.DefinedClass = null;
var g_target_class: ?runtime.DefinedClass = null;

fn viewClass() runtime.DefinedClass {
    if (g_view_class) |dc| return dc;
    const dc = runtime.defineClass("RelayBanner", "NSView", &.{}, .{
        .{ "drawRect:", bannerDrawRect },
        .{ "isFlipped", bannerIsFlipped },
    }) catch @panic("relay_mac/banner: failed to define RelayBanner");
    g_view_class = dc;
    return dc;
}

fn targetClass() runtime.DefinedClass {
    if (g_target_class) |dc| return dc;
    const dc = runtime.defineClass("RelayBannerTarget", "NSObject", &.{}, .{
        .{ "relayBannerDismiss:", dismissImp },
    }) catch @panic("relay_mac/banner: failed to define RelayBannerTarget");
    g_target_class = dc;
    return dc;
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------
pub const DismissFn = *const fn (ctx: *anyopaque) void;

pub const Banner = struct {
    alloc: std.mem.Allocator,
    /// RelayBanner NSView (the strip). Owns the dismiss button as a subview.
    obj: objc.Object,
    /// The "×" NSButton subview.
    dismiss_button: objc.Object,
    /// RelayBannerTarget routing the button click back into Zig.
    target: objc.Object,
    /// Retained, kind-tinted SF Symbol images, lazily built per kind.
    symbols: [3]?c.id = .{ null, null, null },
    /// Current message; `msg_buf[0..msg_len]` is the live slice.
    msg_buf: [message_cap]u8 = undefined,
    msg_len: usize = 0,
    kind: Kind = .@"error",
    visible: bool = false,
    /// Dismiss handler (the host clears its pane error + hides us).
    dismiss_ctx: ?*anyopaque = null,
    dismiss_fn: ?DismissFn = null,

    /// Build a banner. The returned struct is heap-owned; embed `view()` into
    /// a layout and call deinit() at teardown. Main thread only.
    pub fn create(gpa: std.mem.Allocator) !*Banner {
        const view_dc = viewClass();
        const target_dc = targetClass();

        const self = try gpa.create(Banner);
        errdefer gpa.destroy(self);

        const obj = view_dc.newWithFrame(rect(0, 0, 320, banner_height)); // rc 1
        view_dc.attach(obj.value, self);
        // Hidden until the host calls show(); it draws nothing while hidden.
        obj.msgSend(void, "setHidden:", .{true});
        // Pin to the host's leading/trailing/top edges; height is fixed.
        obj.msgSend(void, "setAutoresizingMask:", .{ns_view_width_sizable | ns_view_min_y_margin});

        const target = target_dc.newWithState(self); // rc 1, owned by self

        const button = getClass("NSButton").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{
            rect(0, 0, dismiss_edge, dismiss_edge),
        }); // rc 1, owned by obj once added as subview
        button.msgSend(void, "setTitle:", .{foundation.nsString("\u{00D7}")}); // "×" MULTIPLICATION SIGN
        button.msgSend(void, "setBezelStyle:", .{ns_bezel_style_inline});
        button.msgSend(void, "setBordered:", .{false});
        button.msgSend(void, "setTarget:", .{target});
        button.msgSend(void, "setAction:", .{objc.sel("relayBannerDismiss:")});
        button.msgSend(void, "setToolTip:", .{foundation.nsString("Dismiss")});
        // Trailing-anchored: only the left margin is flexible.
        button.msgSend(void, "setAutoresizingMask:", .{ns_view_min_x_margin});
        obj.msgSend(void, "addSubview:", .{button});

        self.* = .{
            .alloc = gpa,
            .obj = obj,
            .dismiss_button = button,
            .target = target,
        };
        self.layoutDismiss();
        return self;
    }

    pub fn deinit(self: *Banner) void {
        self.dismiss_button.msgSend(void, "setTarget:", .{@as(c.id, null)});
        self.dismiss_button.msgSend(void, "removeFromSuperview", .{});
        self.dismiss_button.msgSend(void, "release", .{});
        self.target.msgSend(void, "release", .{});
        for (self.symbols) |maybe| {
            if (maybe) |img| objc.Object.fromId(img).msgSend(void, "release", .{});
        }
        self.obj.msgSend(void, "removeFromSuperview", .{});
        self.obj.msgSend(void, "release", .{});
        self.alloc.destroy(self);
    }

    /// The NSView to insert into a host layout (the strip itself).
    pub fn view(self: *Banner) c.id {
        return self.obj.value;
    }

    /// Set text + tint, unhide, and request a redraw. The message is copied
    /// into the banner's own buffer (truncated at message_cap bytes).
    pub fn show(self: *Banner, kind: Kind, message: []const u8) void {
        const n = @min(message.len, message_cap);
        @memcpy(self.msg_buf[0..n], message[0..n]);
        self.msg_len = n;
        self.kind = kind;
        self.visible = true;
        self.obj.msgSend(void, "setHidden:", .{false});
        self.obj.msgSend(void, "setNeedsDisplay:", .{true});
    }

    /// Hide the banner (auto-clear on successful (re)list/connect, or dismiss).
    pub fn hide(self: *Banner) void {
        self.visible = false;
        self.msg_len = 0;
        self.obj.msgSend(void, "setHidden:", .{true});
    }

    pub fn isVisible(self: *Banner) bool {
        return self.visible;
    }

    /// `f(ctx)` fires on the main thread when the user clicks "×".
    pub fn setDismissHandler(self: *Banner, ctx: *anyopaque, comptime f: DismissFn) void {
        self.dismiss_ctx = ctx;
        self.dismiss_fn = f;
    }

    /// Live message slice (valid until the next show()/hide()).
    pub fn currentMessage(self: *Banner) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }

    /// Position the "×" at the trailing edge, vertically centered.
    fn layoutDismiss(self: *Banner) void {
        const bounds = self.obj.msgSend(NSRect, "bounds", .{});
        const x = bounds.size.width - dismiss_edge - dismiss_trailing_pad;
        const y = (bounds.size.height - dismiss_edge) / 2;
        self.dismiss_button.msgSend(void, "setFrame:", .{rect(x, y, dismiss_edge, dismiss_edge)});
    }

    /// Retained, kind-tinted SF Symbol (palette-recolored to the kind color).
    fn tintedSymbol(self: *Banner, kind: Kind) ?c.id {
        const slot = &self.symbols[@intFromEnum(kind)];
        if (slot.*) |cached| return cached;

        const base = ts.systemSymbolImage(symbol_name) orelse return null;
        const tint = kind.color().object();
        const colors = getClass("NSArray").msgSend(objc.Object, "arrayWithObject:", .{tint});
        const config = getClass("NSImageSymbolConfiguration").msgSend(
            objc.Object,
            "configurationWithPaletteColors:",
            .{colors},
        );
        var img = objc.Object.fromId(base).msgSend(objc.Object, "imageWithSymbolConfiguration:", .{config});
        if (img.value == null) img = objc.Object.fromId(base);
        _ = img.msgSend(c.id, "retain", .{});
        slot.* = img.value;
        return img.value;
    }
};

// NSView autoresizing-mask bits + NSButton bezel style.
const ns_view_min_x_margin: NSUInteger = 1 << 0;
const ns_view_width_sizable: NSUInteger = 1 << 1;
const ns_view_min_y_margin: NSUInteger = 1 << 5;
const ns_bezel_style_inline: NSUInteger = 15;

// ---------------------------------------------------------------------------
// RelayBanner IMPs (custom drawing)
// ---------------------------------------------------------------------------
fn bannerIsFlipped(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1;
}

fn bannerDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const self = viewClass().state(Banner, target);
    if (!self.visible) return;

    const view_obj = objc.Object.fromId(target);
    const bounds = view_obj.msgSend(NSRect, "bounds", .{});

    // Background: the kind color at low alpha. Semantic only.
    const bg = self.kind.color().object()
        .msgSend(objc.Object, "colorWithAlphaComponent:", .{tint_alpha});
    bg.msgSend(void, "setFill", .{});
    getClass("NSBezierPath")
        .msgSend(objc.Object, "bezierPathWithRect:", .{bounds})
        .msgSend(void, "fill", .{});

    var text_x: f64 = h_pad;

    // Leading tinted SF Symbol.
    if (self.tintedSymbol(self.kind)) |img| {
        const icon_rect = rect(text_x, (bounds.size.height - icon_edge) / 2, icon_edge, icon_edge);
        objc.Object.fromId(img).msgSend(
            void,
            "drawInRect:fromRect:operation:fraction:respectFlipped:hints:",
            .{
                icon_rect,
                rect(0, 0, 0, 0),
                compositing_source_over,
                @as(f64, 1.0),
                true,
                @as(c.id, null),
            },
        );
        text_x += icon_edge + icon_text_gap;
    }

    // Message: labelColor, tail-truncated + clipped to the area before the
    // dismiss button (NSView does not clip drawing to bounds by default).
    if (self.msg_len == 0) return;
    const str = foundation.nsString(self.msg_buf[0..self.msg_len]);
    const font = foundation.systemFont(font_size);
    const color = foundation.labelColor();

    const para = getClass("NSMutableParagraphStyle").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    defer para.msgSend(void, "release", .{});
    para.msgSend(void, "setLineBreakMode:", .{line_break_truncating_tail});

    const attrs = getClass("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
    attrs.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ color.value, NSForegroundColorAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ para.value, NSParagraphStyleAttributeName.* });

    const size = str.msgSend(NSSize, "sizeWithAttributes:", .{attrs});
    const trailing = dismiss_edge + dismiss_trailing_pad + icon_text_gap;
    const avail_w = @max(0, bounds.size.width - text_x - trailing);
    const y = (bounds.size.height - size.height) / 2;
    str.msgSend(void, "drawInRect:withAttributes:", .{
        rect(text_x, y, avail_w, size.height),
        attrs,
    });
}

// ---------------------------------------------------------------------------
// RelayBannerTarget IMP (dismiss button action)
// ---------------------------------------------------------------------------
fn dismissImp(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const self = targetClass().state(Banner, target);
    if (self.dismiss_fn) |f| {
        if (self.dismiss_ctx) |ctx| f(ctx);
    }
}

// ---------------------------------------------------------------------------
// Headless tests (build + drive the real ObjC objects; nothing on screen).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "create / show / hide / isVisible state machine" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const b = try Banner.create(testing.allocator);
    defer b.deinit();

    // Starts hidden.
    try testing.expect(!b.isVisible());
    try testing.expect(foundation.toBool(b.obj.msgSend(foundation.BOOL, "isHidden", .{})));
    try testing.expectEqual(@as(usize, 0), b.currentMessage().len);

    b.show(.@"error", "Connection refused");
    try testing.expect(b.isVisible());
    try testing.expect(!foundation.toBool(b.obj.msgSend(foundation.BOOL, "isHidden", .{})));
    try testing.expectEqual(Kind.@"error", b.kind);
    try testing.expectEqualStrings("Connection refused", b.currentMessage());

    // Re-show with a different kind swaps tint + text.
    b.show(.warning, "Listing timed out");
    try testing.expectEqual(Kind.warning, b.kind);
    try testing.expectEqualStrings("Listing timed out", b.currentMessage());

    b.hide();
    try testing.expect(!b.isVisible());
    try testing.expect(foundation.toBool(b.obj.msgSend(foundation.BOOL, "isHidden", .{})));
    try testing.expectEqual(@as(usize, 0), b.currentMessage().len);
}

test "message truncation byte math" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const b = try Banner.create(testing.allocator);
    defer b.deinit();

    // Shorter than cap: stored verbatim.
    b.show(.info, "short");
    try testing.expectEqual(@as(usize, 5), b.currentMessage().len);

    // Longer than cap: clamped to message_cap bytes, prefix preserved.
    var huge: [message_cap + 64]u8 = undefined;
    @memset(&huge, 'x');
    b.show(.@"error", &huge);
    try testing.expectEqual(message_cap, b.currentMessage().len);
    for (b.currentMessage()) |ch| try testing.expectEqual(@as(u8, 'x'), ch);

    // Exactly cap: kept whole.
    b.show(.@"error", huge[0..message_cap]);
    try testing.expectEqual(message_cap, b.currentMessage().len);
}

test "kind maps to a semantic color" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    try testing.expectEqual(foundation.Color.system_red, Kind.@"error".color());
    try testing.expectEqual(foundation.Color.system_yellow, Kind.warning.color());
    try testing.expectEqual(foundation.Color.system_blue, Kind.info.color());
    // Each resolves to a real NSColor.
    inline for (comptime std.enums.values(Kind)) |k| {
        try testing.expect(k.color().object().value != null);
    }
}

var g_test_dismiss_calls: u32 = 0;
var g_test_dismiss_ctx: ?*anyopaque = null;

fn testDismiss(ctx: *anyopaque) void {
    g_test_dismiss_calls += 1;
    g_test_dismiss_ctx = ctx;
}

test "dismiss handler dispatches through the button action" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const b = try Banner.create(testing.allocator);
    defer b.deinit();

    var fake_ctx: u32 = 0xBEEF;
    g_test_dismiss_calls = 0;
    g_test_dismiss_ctx = null;
    b.setDismissHandler(&fake_ctx, testDismiss);

    // The dismiss button targets `b.target` with relayBannerDismiss:; firing
    // that action (the exact path NSButton drives on click) reaches the IMP,
    // recovers the Banner via its state ivar, and forwards to the handler.
    // (Headless: dispatch the action selector directly — there is no window
    // to route performClick: through.)
    try testing.expectEqual(b.target.value, b.dismiss_button.msgSend(c.id, "target", .{}));
    b.target.msgSend(void, "relayBannerDismiss:", .{b.dismiss_button.value});
    try testing.expectEqual(@as(u32, 1), g_test_dismiss_calls);
    try testing.expectEqual(@as(?*anyopaque, &fake_ctx), g_test_dismiss_ctx);

    // No handler installed → action is a no-op (recover state, do nothing).
    const b2 = try Banner.create(testing.allocator);
    defer b2.deinit();
    b2.target.msgSend(void, "relayBannerDismiss:", .{@as(c.id, null)});
    try testing.expectEqual(@as(u32, 1), g_test_dismiss_calls);
}

test "tinted symbol is cached per kind" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const b = try Banner.create(testing.allocator);
    defer b.deinit();

    const first = b.tintedSymbol(.@"error");
    const second = b.tintedSymbol(.@"error");
    try testing.expectEqual(first, second); // same retained handle reused
    // Distinct kinds occupy distinct cache slots.
    _ = b.tintedSymbol(.warning);
    _ = b.tintedSymbol(.info);
}

test {
    testing.refAllDecls(@This());
}

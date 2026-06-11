//! window — NSApplication bootstrap + NSWindow wrapper.
//!
//! All UI mutation happens on the main thread; `App.run` never returns
//! (terminate: exits the process). Sheets complete through zig-objc Blocks
//! marshaled back into Zig callbacks, pool-wrapped.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");

const c = objc.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const NSRect = foundation.NSRect;

pub const StyleMask = struct {
    pub const borderless: NSUInteger = 0;
    pub const titled: NSUInteger = 1 << 0;
    pub const closable: NSUInteger = 1 << 1;
    pub const miniaturizable: NSUInteger = 1 << 2;
    pub const resizable: NSUInteger = 1 << 3;
    /// NSWindowStyleMaskNonactivatingPanel (NSPanel only): the panel takes
    /// key without activating the app — palette/HUD panels.
    pub const nonactivating_panel: NSUInteger = 1 << 7;
    pub const full_size_content_view: NSUInteger = 1 << 15;
    /// titled | closable | miniaturizable | resizable — the document default.
    pub const standard: NSUInteger = titled | closable | miniaturizable | resizable;
};

/// NSFloatingWindowLevel — palette/utility panels above document windows.
pub const level_floating: NSInteger = 3;

const backing_store_buffered: NSUInteger = 2;
const activation_policy_regular: NSInteger = 0;

/// Sheet completion codes (NSModalResponse).
pub const modal_response_ok: NSInteger = 1;
pub const modal_response_cancel: NSInteger = 0;

// ---------------------------------------------------------------------------
// NSApplication
// ---------------------------------------------------------------------------
pub const App = struct {
    obj: objc.Object,

    pub fn shared() App {
        return .{ .obj = foundation.class("NSApplication").msgSend(objc.Object, "sharedApplication", .{}) };
    }

    /// Regular activation policy: Dock icon + menu bar (call before `run`).
    pub fn setRegularActivationPolicy(self: App) void {
        _ = self.obj.msgSend(foundation.BOOL, "setActivationPolicy:", .{activation_policy_regular});
    }

    pub fn activate(self: App) void {
        self.obj.msgSend(void, "activateIgnoringOtherApps:", .{true});
    }

    /// True when Relay is the frontmost (active) app. Used to gate
    /// background-only surfaces (e.g. transfer-failure notifications):
    /// foreground UI already shows the result, so notify only when this is
    /// false. Main thread only.
    pub fn isActive(self: App) bool {
        return foundation.toBool(self.obj.msgSend(foundation.BOOL, "isActive", .{}));
    }

    /// Install the NSApplicationDelegate. NSApplication holds it weakly;
    /// the caller keeps the strong reference (see app_delegate.AppDelegate).
    pub fn setDelegate(self: App, delegate: objc.Object) void {
        self.obj.msgSend(void, "setDelegate:", .{delegate});
    }

    /// Enters the main event loop. Never returns; `terminate` exits the
    /// process (code 0) and `stop` ends the loop after the next event.
    pub fn run(self: App) void {
        self.obj.msgSend(void, "run", .{});
    }

    pub fn stop(self: App) void {
        self.obj.msgSend(void, "stop:", .{foundation.nil});
    }

    pub fn terminate(self: App) void {
        self.obj.msgSend(void, "terminate:", .{foundation.nil});
    }
};

// ---------------------------------------------------------------------------
// Window delegate: one runtime-defined class for all Relay windows; its
// state ivar holds a heap DelegateState with the registered Zig callbacks.
// ---------------------------------------------------------------------------
pub const ShouldCloseFn = *const fn (ctx: ?*anyopaque) bool;

const DelegateState = struct {
    ctx: ?*anyopaque = null,
    should_close: ?ShouldCloseFn = null,
};

var g_delegate_class: ?runtime.DefinedClass = null;

fn delegateClass() runtime.DefinedClass {
    if (g_delegate_class) |dc| return dc;
    const dc = runtime.defineClass("RelayWindowDelegate", "NSObject", &.{}, .{
        .{ "windowShouldClose:", delegateWindowShouldClose },
    }) catch @panic("relay_mac/window: failed to define RelayWindowDelegate");
    g_delegate_class = dc;
    return dc;
}

fn delegateWindowShouldClose(target: c.id, _: c.SEL, _: c.id) callconv(.c) foundation.BOOL {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const st = delegateClass().state(DelegateState, target);
    const f = st.should_close orelse return foundation.YES;
    return foundation.fromBool(f(st.ctx));
}

// ---------------------------------------------------------------------------
// NSWindow
// ---------------------------------------------------------------------------
pub const Window = struct {
    obj: objc.Object,

    /// Caller-owned NSWindow (releasedWhenClosed disabled, retain count 1).
    pub fn create(content_frame: NSRect, title_text: []const u8, style: NSUInteger) Window {
        const win = foundation.class("NSWindow").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithContentRect:styleMask:backing:defer:", .{
            content_frame, style, backing_store_buffered, false,
        });
        win.msgSend(void, "setReleasedWhenClosed:", .{false});
        const self: Window = .{ .obj = win };
        self.setTitle(title_text);
        return self;
    }

    /// Like `create`, but instantiating `cls` — an NSWindow/NSPanel
    /// subclass, typically runtime-defined (M3 palette: a panel overriding
    /// canBecomeKeyWindow so a borderless panel can take key). Same
    /// ownership: caller-owned, releasedWhenClosed disabled.
    pub fn createWithClass(cls: objc.Class, content_frame: NSRect, style: NSUInteger) Window {
        const win = cls.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithContentRect:styleMask:backing:defer:", .{
            content_frame, style, backing_store_buffered, false,
        });
        win.msgSend(void, "setReleasedWhenClosed:", .{false});
        return .{ .obj = win };
    }

    /// Wrap an NSWindow that arrived from AppKit (delegate args, sheets).
    pub fn fromObject(obj: objc.Object) Window {
        return .{ .obj = obj };
    }

    pub fn release(self: Window) void {
        self.obj.msgSend(void, "release", .{});
    }

    pub fn setTitle(self: Window, title_text: []const u8) void {
        self.obj.msgSend(void, "setTitle:", .{foundation.nsString(title_text)});
    }

    pub fn title(self: Window, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return foundation.utf8FromNSString(gpa, self.obj.msgSend(objc.Object, "title", .{}));
    }

    pub fn setContentView(self: Window, view: objc.Object) void {
        self.obj.msgSend(void, "setContentView:", .{view});
    }

    pub fn contentView(self: Window) objc.Object {
        return self.obj.msgSend(objc.Object, "contentView", .{});
    }

    pub fn makeKeyAndOrderFront(self: Window) void {
        self.obj.msgSend(void, "makeKeyAndOrderFront:", .{foundation.nil});
    }

    pub fn orderOut(self: Window) void {
        self.obj.msgSend(void, "orderOut:", .{foundation.nil});
    }

    pub fn center(self: Window) void {
        self.obj.msgSend(void, "center", .{});
    }

    pub fn close(self: Window) void {
        self.obj.msgSend(void, "close", .{});
    }

    /// Through-the-close-button path (runs windowShouldClose:).
    pub fn performClose(self: Window) void {
        self.obj.msgSend(void, "performClose:", .{foundation.nil});
    }

    pub fn isVisible(self: Window) bool {
        return foundation.toBool(self.obj.msgSend(foundation.BOOL, "isVisible", .{}));
    }

    /// Window frame in screen coordinates.
    pub fn frame(self: Window) NSRect {
        return self.obj.msgSend(NSRect, "frame", .{});
    }

    /// Move (bottom-left origin, screen coordinates) without resizing.
    pub fn setFrameOrigin(self: Window, origin: foundation.NSPoint) void {
        self.obj.msgSend(void, "setFrameOrigin:", .{origin});
    }

    /// NSWindowLevel (see `level_floating`).
    pub fn setLevel(self: Window, level: NSInteger) void {
        self.obj.msgSend(void, "setLevel:", .{level});
    }

    /// Frame persistence across launches (docs/UX.md: every split/window
    /// has an autosave name). Returns false if the name is already taken.
    pub fn setFrameAutosaveName(self: Window, name: []const u8) bool {
        return foundation.toBool(self.obj.msgSend(
            foundation.BOOL,
            "setFrameAutosaveName:",
            .{foundation.nsString(name)},
        ));
    }

    // --- first responder -------------------------------------------------
    pub fn makeFirstResponder(self: Window, responder: ?objc.Object) bool {
        const id_val: c.id = if (responder) |r| r.value else null;
        return foundation.toBool(self.obj.msgSend(foundation.BOOL, "makeFirstResponder:", .{id_val}));
    }

    pub fn firstResponder(self: Window) objc.Object {
        return self.obj.msgSend(objc.Object, "firstResponder", .{});
    }

    // --- delegate ---------------------------------------------------------
    /// Register a windowShouldClose: handler. Installs (and retains) the
    /// shared delegate class instance on first use; replaces the handler on
    /// subsequent calls. The delegate lives for the window's lifetime.
    pub fn setShouldCloseHandler(self: Window, ctx: ?*anyopaque, f: ShouldCloseFn) void {
        const st = self.delegateState();
        st.ctx = ctx;
        st.should_close = f;
    }

    fn delegateState(self: Window) *DelegateState {
        const dc = delegateClass();
        const current = self.obj.msgSend(c.id, "delegate", .{});
        if (current) |cur| {
            if (c.object_getClass(cur) == dc.class.value) {
                return dc.state(DelegateState, cur);
            }
        }
        const st = std.heap.c_allocator.create(DelegateState) catch
            @panic("relay_mac/window: OOM allocating DelegateState");
        st.* = .{};
        const delegate = dc.newWithState(st); // rc 1, intentionally never released
        self.obj.msgSend(void, "setDelegate:", .{delegate});
        return st;
    }

    // --- sheets -----------------------------------------------------------
    /// Present `sheet` window-modally; `f(ctx, response)` runs (pool-wrapped,
    /// main thread) after `endSheet`.
    pub fn beginSheet(
        self: Window,
        sheet: Window,
        ctx: anytype,
        comptime f: fn (@TypeOf(ctx), NSInteger) void,
    ) void {
        const Ptr = @TypeOf(ctx);
        comptime {
            if (@typeInfo(Ptr) != .pointer) @compileError("beginSheet ctx must be a pointer");
        }
        const B = objc.Block(struct { ctx: usize }, .{NSInteger}, void);
        const Fns = struct {
            fn invoke(block: *const B.Context, response: NSInteger) callconv(.c) void {
                const pool = objc.AutoreleasePool.init();
                defer pool.deinit();
                f(@ptrFromInt(block.ctx), response);
            }
        };
        var block = B.init(.{ .ctx = @intFromPtr(ctx) }, Fns.invoke);
        self.obj.msgSend(void, "beginSheet:completionHandler:", .{ sheet.obj, &block });
    }

    /// Present a sheet with no completion callback.
    pub fn beginSheetSimple(self: Window, sheet: Window) void {
        self.obj.msgSend(void, "beginSheet:completionHandler:", .{
            sheet.obj, @as(?*anyopaque, null),
        });
    }

    pub fn endSheet(self: Window, sheet: Window, response: NSInteger) void {
        self.obj.msgSend(void, "endSheet:returnCode:", .{ sheet.obj, response });
    }

    /// The currently attached sheet, if any. NOTE: `App.terminate` is a
    /// no-op while a sheet is attached — dismiss sheets before terminating.
    pub fn attachedSheet(self: Window) ?Window {
        const sheet = self.obj.msgSend(c.id, "attachedSheet", .{});
        return if (sheet) |s| Window.fromObject(objc.Object.fromId(s)) else null;
    }
};

// ---------------------------------------------------------------------------
// Tests (headless: windows are created but never ordered front).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "Window create + title round-trip + content view" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const win = Window.create(foundation.rect(0, 0, 400, 300), "Relay Test Wíndow", StyleMask.standard);
    defer win.release();

    const got = try win.title(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("Relay Test Wíndow", got);

    win.setTitle("renamed");
    const got2 = try win.title(testing.allocator);
    defer testing.allocator.free(got2);
    try testing.expectEqualStrings("renamed", got2);

    const view = foundation.class("NSView").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{foundation.rect(0, 0, 400, 300)})
        .msgSend(objc.Object, "autorelease", .{});
    win.setContentView(view);
    try testing.expectEqual(view.value, win.contentView().value);
    try testing.expect(!win.isVisible());
}

test "createWithClass + frame/level primitives (headless)" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const win = Window.createWithClass(
        foundation.class("NSPanel"),
        foundation.rect(10, 20, 300, 200),
        StyleMask.borderless | StyleMask.nonactivating_panel,
    );
    defer win.release();
    try testing.expectEqualStrings("NSPanel", win.obj.getClassName());

    win.setLevel(level_floating);
    try testing.expectEqual(level_floating, win.obj.msgSend(NSInteger, "level", .{}));

    win.setFrameOrigin(foundation.point(50, 60));
    const f = win.frame();
    try testing.expectEqual(@as(foundation.CGFloat, 50), f.origin.x);
    try testing.expectEqual(@as(foundation.CGFloat, 60), f.origin.y);
    try testing.expectEqual(@as(foundation.CGFloat, 300), f.size.width);
}

var g_close_calls: u32 = 0;

fn testShouldClose(ctx: ?*anyopaque) bool {
    g_close_calls += 1;
    const allow: *bool = @ptrCast(@alignCast(ctx.?));
    return allow.*;
}

test "windowShouldClose handler wiring" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const win = Window.create(foundation.rect(0, 0, 200, 100), "close-test", StyleMask.standard);
    defer win.release();

    var allow = false;
    win.setShouldCloseHandler(&allow, testShouldClose);

    // Drive the delegate method exactly as AppKit would.
    const delegate = objc.Object.fromId(win.obj.msgSend(c.id, "delegate", .{}).?);
    try testing.expectEqual(
        foundation.NO,
        delegate.msgSend(foundation.BOOL, "windowShouldClose:", .{win.obj}),
    );
    allow = true;
    try testing.expectEqual(
        foundation.YES,
        delegate.msgSend(foundation.BOOL, "windowShouldClose:", .{win.obj}),
    );
    try testing.expectEqual(@as(u32, 2), g_close_calls);

    // Re-registering reuses the same delegate instance.
    win.setShouldCloseHandler(&allow, testShouldClose);
    try testing.expectEqual(
        delegate.value,
        win.obj.msgSend(c.id, "delegate", .{}).?,
    );
}

test {
    testing.refAllDecls(@This());
}

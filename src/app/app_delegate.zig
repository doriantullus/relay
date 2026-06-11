//! app_delegate — RelayAppDelegate, the NSApplicationDelegate defined from
//! Zig via the relay_mac runtime kit (cached-Ivar state convention; class
//! registered once, lazily).
//!
//! Responsibilities:
//!  - applicationDidFinishLaunching: → `Hooks.on_launch` (phase 3 builds
//!    the window + controllers there),
//!  - applicationDidBecomeActive: → `Hooks.on_did_become_active` (cheap
//!    freshness checks: the SSH-config smart group's mtime-gated re-parse),
//!  - applicationShouldTerminate: → `Hooks.on_will_terminate` (dismisses
//!    attached sheets — AppKit swallows terminate: while one is attached —
//!    and saves UI state), then graceful `AppCore.shutdown()` (cancels all
//!    site groups + queue workers, joins, persists the queue), then
//!    replies terminate-now,
//!  - applicationShouldHandleReopen:hasVisibleWindows: → `Hooks.on_reopen`
//!    when the Dock icon is clicked with no visible windows,
//!  - applicationSupportsSecureRestorableState: → YES (silences the macOS
//!    13+ console warning).
//!
//! Wiring (phase 3's main.zig):
//!     var hooks: app_delegate.Hooks = .{ .core = core, .on_launch = ..., .ctx = ... };
//!     const delegate = try app_delegate.AppDelegate.init(&hooks);
//!     delegate.install(); // before App.run()
//! `hooks` must be pinned and outlive the NSApplication run loop.

const std = @import("std");
const mac = @import("relay_mac");
const bridge = @import("bridge.zig");

const objc = mac.objc;
const runtime = mac.runtime;
const foundation = mac.foundation;
const c = runtime.c;

/// NSApplicationTerminateReply.
pub const terminate_cancel: foundation.NSUInteger = 0;
pub const terminate_now: foundation.NSUInteger = 1;
pub const terminate_later: foundation.NSUInteger = 2;

/// Zig-side delegate state, stored in the instance's relayState ivar.
/// Pinned by the caller; must outlive the delegate object.
pub const Hooks = struct {
    ctx: ?*anyopaque = null,
    /// Build the UI here (window, controllers, first listings).
    on_launch: ?*const fn (ctx: ?*anyopaque) void = null,
    /// Dock-icon click with no visible windows: re-show the main window.
    on_reopen: ?*const fn (ctx: ?*anyopaque) void = null,
    /// App became active (applicationDidBecomeActive:) — cheap freshness
    /// checks live here (SSH-config mtime re-parse).
    on_did_become_active: ?*const fn (ctx: ?*anyopaque) void = null,
    /// Pre-shutdown notification (save UI state); runs before the core
    /// teardown on quit.
    on_will_terminate: ?*const fn (ctx: ?*anyopaque) void = null,
    /// Torn down gracefully on quit (nulled afterwards so a second
    /// terminate request cannot double-shutdown). null in tests that only
    /// exercise the callback plumbing.
    core: ?*bridge.AppCore = null,
};

var g_class: ?runtime.DefinedClass = null;

/// Define-once (lazy). Must run before the first `setDelegate:` — AppKit
/// probes respondsToSelector: at set time.
fn delegateClass() runtime.Error!runtime.DefinedClass {
    if (g_class) |dc| return dc;
    const dc = try runtime.defineClass("RelayAppDelegate", "NSObject", &.{}, .{
        .{ "applicationDidFinishLaunching:", impDidFinishLaunching },
        .{ "applicationDidBecomeActive:", impDidBecomeActive },
        .{ "applicationShouldTerminate:", impShouldTerminate },
        .{ "applicationShouldHandleReopen:hasVisibleWindows:", impShouldHandleReopen },
        .{ "applicationSupportsSecureRestorableState:", impSupportsSecureRestorableState },
    });
    g_class = dc;
    return dc;
}

fn hooksOf(target: c.id) *Hooks {
    return runtime.stateFromIvar(Hooks, target, g_class.?.state_ivar);
}

fn impDidFinishLaunching(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const hooks = hooksOf(target);
    if (hooks.on_launch) |callback| callback(hooks.ctx);
}

fn impDidBecomeActive(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const hooks = hooksOf(target);
    if (hooks.on_did_become_active) |callback| callback(hooks.ctx);
}

fn impShouldTerminate(target: c.id, _: c.SEL, _: c.id) callconv(.c) foundation.NSUInteger {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const hooks = hooksOf(target);
    if (hooks.on_will_terminate) |callback| callback(hooks.ctx);
    if (hooks.core) |core| {
        hooks.core = null; // a second terminate must not double-shutdown
        core.shutdown(); // bounded: cancels + joins all workers, persists
    }
    return terminate_now;
}

fn impShouldHandleReopen(
    target: c.id,
    _: c.SEL,
    _: c.id,
    has_visible_windows: foundation.BOOL,
) callconv(.c) foundation.BOOL {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const hooks = hooksOf(target);
    if (!foundation.toBool(has_visible_windows)) {
        if (hooks.on_reopen) |callback| callback(hooks.ctx);
    }
    return foundation.YES;
}

fn impSupportsSecureRestorableState(_: c.id, _: c.SEL, _: c.id) callconv(.c) foundation.BOOL {
    return foundation.YES;
}

pub const AppDelegate = struct {
    /// The retained delegate instance (caller-owned; release via deinit —
    /// in the real app it lives for the process).
    object: objc.Object,

    pub fn init(hooks: *Hooks) runtime.Error!AppDelegate {
        const dc = try delegateClass();
        return .{ .object = dc.newWithState(@ptrCast(hooks)) };
    }

    pub fn deinit(self: AppDelegate) void {
        self.object.msgSend(void, "release", .{});
    }

    /// [NSApp setDelegate:]; call before App.run().
    /// NSApplication's delegate property is weak: this wrapper keeps the
    /// strong reference.
    pub fn install(self: AppDelegate) void {
        mac.appkit.window.App.shared().setDelegate(self.object);
    }
};

// ---------------------------------------------------------------------------
// Tests — headless per docs/spikes/ui.md: class definition, IMP dispatch,
// hooks plumbing, and the terminate→AppCore.shutdown path (window-dependent
// behavior, i.e. install() under a running NSApplication, is phase 3's
// app-level smoke).
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestFlags = struct {
    launched: usize = 0,
    reopened: usize = 0,
    activated: usize = 0,
    will_terminate: usize = 0,

    fn onLaunch(ctx: ?*anyopaque) void {
        const self: *TestFlags = @ptrCast(@alignCast(ctx.?));
        self.launched += 1;
    }
    fn onReopen(ctx: ?*anyopaque) void {
        const self: *TestFlags = @ptrCast(@alignCast(ctx.?));
        self.reopened += 1;
    }
    fn onDidBecomeActive(ctx: ?*anyopaque) void {
        const self: *TestFlags = @ptrCast(@alignCast(ctx.?));
        self.activated += 1;
    }
    fn onWillTerminate(ctx: ?*anyopaque) void {
        const self: *TestFlags = @ptrCast(@alignCast(ctx.?));
        self.will_terminate += 1;
    }
};

test "delegate class: launch + reopen + secure-state callbacks dispatch" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    var flags: TestFlags = .{};
    var hooks: Hooks = .{
        .ctx = &flags,
        .on_launch = TestFlags.onLaunch,
        .on_reopen = TestFlags.onReopen,
        .on_did_become_active = TestFlags.onDidBecomeActive,
    };
    const delegate = try AppDelegate.init(&hooks);
    defer delegate.deinit();

    delegate.object.msgSend(void, "applicationDidFinishLaunching:", .{foundation.nil});
    try testing.expectEqual(@as(usize, 1), flags.launched);

    // Activation hook (SSH-config freshness checks ride this).
    delegate.object.msgSend(void, "applicationDidBecomeActive:", .{foundation.nil});
    delegate.object.msgSend(void, "applicationDidBecomeActive:", .{foundation.nil});
    try testing.expectEqual(@as(usize, 2), flags.activated);

    // No visible windows: reopen fires and the event is consumed (YES).
    const reply_hidden = delegate.object.msgSend(
        foundation.BOOL,
        "applicationShouldHandleReopen:hasVisibleWindows:",
        .{ foundation.nil, foundation.NO },
    );
    try testing.expectEqual(foundation.YES, reply_hidden);
    try testing.expectEqual(@as(usize, 1), flags.reopened);

    // Visible windows: no callback.
    _ = delegate.object.msgSend(
        foundation.BOOL,
        "applicationShouldHandleReopen:hasVisibleWindows:",
        .{ foundation.nil, foundation.YES },
    );
    try testing.expectEqual(@as(usize, 1), flags.reopened);

    try testing.expectEqual(foundation.YES, delegate.object.msgSend(
        foundation.BOOL,
        "applicationSupportsSecureRestorableState:",
        .{foundation.nil},
    ));
}

test "applicationShouldTerminate shuts the AppCore down and replies terminate-now" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = relay_fake.init(testing.allocator);
    defer fake.deinit();

    // Real core, manual pump: testing.allocator reports the leak if the
    // delegate's shutdown path misses anything.
    const core = try bridge.AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    var flags: TestFlags = .{};
    var hooks: Hooks = .{
        .ctx = &flags,
        .on_will_terminate = TestFlags.onWillTerminate,
        .core = core,
    };
    const delegate = try AppDelegate.init(&hooks);
    defer delegate.deinit();

    const reply = delegate.object.msgSend(
        foundation.NSUInteger,
        "applicationShouldTerminate:",
        .{foundation.nil},
    );
    try testing.expectEqual(terminate_now, reply);
    try testing.expectEqual(@as(usize, 1), flags.will_terminate);
    try testing.expectEqual(@as(?*bridge.AppCore, null), hooks.core);

    // A second terminate request must not double-shutdown (core is nulled).
    const reply2 = delegate.object.msgSend(
        foundation.NSUInteger,
        "applicationShouldTerminate:",
        .{foundation.nil},
    );
    try testing.expectEqual(terminate_now, reply2);
    try testing.expectEqual(@as(usize, 2), flags.will_terminate);
}

const relay_fake = @import("relay_core").cred.fake.FakeStore;

test {
    std.testing.refAllDecls(@This());
}

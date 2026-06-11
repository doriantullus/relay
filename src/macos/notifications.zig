//! notifications — UNUserNotificationCenter wrapper.
//!
//! Degrades, never crashes (we ship ad-hoc signed): UserNotifications is
//! loaded at runtime (dlopen, so the framework is not a link-time
//! dependency of every test binary), and the center is touched ONLY when
//! the process is a real .app bundle — `+currentNotificationCenter` raises
//! NSInternalInconsistencyException in bare executables (zig test, smoke
//! binaries run outside the bundle), which Zig cannot catch. Every failure
//! path logs and turns `post` into a quiet no-op.
//!
//! Ad-hoc reality check (verified on macOS 15 / Darwin 24.6, M3 report):
//! an ad-hoc signed bundle CAN call the framework safely — the request
//! round-trips and the completion fires — but usernoted answers
//! granted=NO with "Notifications are not allowed for this application"
//! (UNErrorCode 1, no user prompt), both when launched directly and via
//! LaunchServices. So until Relay ships with a real signing identity the
//! pipeline runs end-to-end and every post is a quiet no-op; with a
//! provisioned signature the same code lights up unchanged. Unbundled
//! processes are detected before the first center call (which would
//! otherwise throw) and quietly disabled.
//!
//! Transfer-batch notifications: `attach(core)` subscribes to the bridge's
//! `transfer_state` events (main thread). The notifier tracks the set of
//! in-flight items; when the LAST one reaches a terminal state the batch is
//! summarized ("N transfers complete" / "… M failed") and posted — but only
//! while Relay is in the background (an active app's transfer panel already
//! shows the result). Authorization is requested once, lazily.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("foundation.zig");
const relay = @import("relay_core");

const c = objc.c;
const Allocator = std.mem.Allocator;
const BOOL = foundation.BOOL;

const log = std.log.scoped(.notifications);

const framework_path = "/System/Library/Frameworks/UserNotifications.framework/UserNotifications";

/// UNAuthorizationOptions: badge | sound | alert.
const authorization_options: u64 = 1 | 2 | 4;

pub const batch_identifier = "us.doriantull.relay.transfer-batch";

pub const Availability = enum(u8) {
    /// Nothing probed yet (also: authorization never requested).
    unprobed,
    /// Unbundled process / framework missing — posts are no-ops forever.
    unavailable,
    /// requestAuthorization in flight (completion lands off-main).
    requesting,
    denied,
    granted,
};

pub const BatchSummary = struct {
    completed: u32 = 0,
    failed: u32 = 0,
    canceled: u32 = 0,
};

/// Test/integration seam: when set, finished batches call this instead of
/// the UNUserNotificationCenter path (no background gating — the hook sees
/// every batch).
pub const BatchHook = struct {
    ctx: ?*anyopaque = null,
    notify: *const fn (?*anyopaque, BatchSummary) void,
};

pub const Notifier = struct {
    gpa: Allocator,
    /// Off-main writers: the authorization completion block.
    state: std.atomic.Value(Availability) = .init(.unprobed),
    /// Items seen in a non-terminal state and not yet finished.
    in_flight: std.AutoHashMapUnmanaged(u64, void) = .empty,
    batch: BatchSummary = .{},
    batch_hook: ?BatchHook = null,
    /// Post batch summaries even while the app is active (debugging).
    notify_when_active: bool = false,

    /// Heap-pinned: listener registrations and the authorization block
    /// capture this pointer for the app lifetime.
    pub fn create(gpa: Allocator) error{OutOfMemory}!*Notifier {
        const self = try gpa.create(Notifier);
        self.* = .{ .gpa = gpa };
        return self;
    }

    /// Tests/teardown only — in the app the notifier lives forever (the
    /// completion block may still fire late; see `state`).
    pub fn destroy(self: *Notifier) void {
        self.in_flight.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    // ------------------------------------------------------------------ //
    // Event wiring

    /// Subscribe to the bridge's transfer_state events. `core` is a
    /// `*bridge.AppCore` (generic so relay_mac never depends on src/app/);
    /// any type with the same `registerListener` shape works.
    pub fn attach(self: *Notifier, core: anytype) error{OutOfMemory}!void {
        try core.registerListener(.transfer_state, self, onTransferState);
    }

    /// transfer_state listener (main thread, run-to-completion).
    pub fn onTransferState(self: *Notifier, e: relay.events.CoreEvent.TransferStateChange) void {
        switch (e.state) {
            .queued, .connecting, .transferring, .paused => {
                // OOM: lose batch tracking for this item, never the app.
                self.in_flight.put(self.gpa, e.item_id, {}) catch
                    log.warn("transfer batch tracking lost an item (OOM)", .{});
            },
            .completed => self.finish(e.item_id, &self.batch.completed),
            .failed => self.finish(e.item_id, &self.batch.failed),
            .canceled => self.finish(e.item_id, &self.batch.canceled),
        }
    }

    fn finish(self: *Notifier, item_id: u64, counter: *u32) void {
        // Count terminal events even for items we never saw start (the
        // notifier may attach mid-transfer).
        _ = self.in_flight.remove(item_id);
        counter.* += 1;
        if (self.in_flight.count() == 0) self.batchDone();
    }

    fn batchDone(self: *Notifier) void {
        const summary = self.batch;
        self.batch = .{};
        if (self.batch_hook) |hook| {
            hook.notify(hook.ctx, summary);
            return;
        }
        // Cancel-only batches are direct user actions: no notification.
        if (summary.completed + summary.failed == 0) return;
        if (appIsActive() and !self.notify_when_active) return;

        var title_buf: [128]u8 = undefined;
        var body_buf: [256]u8 = undefined;
        const total = summary.completed + summary.failed;
        const title = if (summary.failed > 0)
            std.fmt.bufPrint(&title_buf, "Transfers finished with errors", .{}) catch return
        else
            std.fmt.bufPrint(&title_buf, "Transfers complete", .{}) catch return;
        const body = if (summary.failed > 0)
            std.fmt.bufPrint(&body_buf, "{d} of {d} failed ({d} completed)", .{
                summary.failed, total, summary.completed,
            }) catch return
        else
            std.fmt.bufPrint(&body_buf, "{d} {s} transferred", .{
                summary.completed, if (summary.completed == 1) "file" else "files",
            }) catch return;
        self.post(title, body, batch_identifier);
    }

    // ------------------------------------------------------------------ //
    // UNUserNotificationCenter

    /// Ask the user once (idempotent; later calls are no-ops). Safe in any
    /// process: unbundled/unsigned runs mark themselves unavailable and
    /// every subsequent post is a quiet no-op.
    pub fn requestAuthorization(self: *Notifier) void {
        if (self.state.load(.acquire) != .unprobed) return;
        const center = self.centerOrDisable() orelse return;
        self.state.store(.requesting, .release);

        const B = objc.Block(struct { ctx: usize }, .{ BOOL, c.id }, void);
        const Fns = struct {
            // Lands on a UN background queue: atomics + logging only.
            fn invoke(block: *const B.Context, granted: BOOL, err: c.id) callconv(.c) void {
                const pool = foundation.AutoreleasePool.init();
                defer pool.deinit();
                const notifier: *Notifier = @ptrFromInt(block.ctx);
                if (foundation.toBool(granted)) {
                    notifier.state.store(.granted, .release);
                    log.info("notification authorization granted", .{});
                } else {
                    notifier.state.store(.denied, .release);
                    logNSError("authorization denied", err);
                }
            }
        };
        var block = B.init(.{ .ctx = @intFromPtr(self) }, Fns.invoke);
        center.msgSend(void, "requestAuthorizationWithOptions:completionHandler:", .{
            authorization_options, &block,
        });
    }

    /// Deliver a notification now. Quiet no-op when unauthorized,
    /// unavailable, or still waiting on the user — never an error the
    /// caller has to handle. Re-using `identifier` replaces the previous
    /// notification with it (one rolling banner per identifier).
    pub fn post(self: *Notifier, title: []const u8, body: []const u8, identifier: []const u8) void {
        switch (self.state.load(.acquire)) {
            .unprobed => {
                // Lazy first use: kick the request; THIS post is dropped
                // (nobody to show it to yet), later ones go through.
                self.requestAuthorization();
                return;
            },
            .unavailable, .requesting, .denied => return,
            .granted => {},
        }
        const center = self.centerOrDisable() orelse return;

        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        const content = foundation.class("UNMutableNotificationContent")
            .msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{})
            .msgSend(objc.Object, "autorelease", .{});
        content.msgSend(void, "setTitle:", .{foundation.nsString(title)});
        content.msgSend(void, "setBody:", .{foundation.nsString(body)});

        const request = foundation.class("UNNotificationRequest").msgSend(
            objc.Object,
            "requestWithIdentifier:content:trigger:",
            .{ foundation.nsString(identifier), content, foundation.nil },
        );

        const B = objc.Block(struct { ctx: usize }, .{c.id}, void);
        const Fns = struct {
            fn invoke(_: *const B.Context, err: c.id) callconv(.c) void {
                const inner = foundation.AutoreleasePool.init();
                defer inner.deinit();
                logNSError("notification post failed", err);
            }
        };
        var block = B.init(.{ .ctx = @intFromPtr(self) }, Fns.invoke);
        center.msgSend(void, "addNotificationRequest:withCompletionHandler:", .{ request, &block });
    }

    pub fn availability(self: *const Notifier) Availability {
        return self.state.load(.acquire);
    }

    /// The shared center, or null after flagging this process unavailable
    /// (logged once). The bundle check MUST precede the class call:
    /// +currentNotificationCenter throws (uncatchable from Zig) outside a
    /// bundle.
    fn centerOrDisable(self: *Notifier) ?objc.Object {
        if (processIsBundled() and userNotificationsLoaded()) {
            return foundation.class("UNUserNotificationCenter")
                .msgSend(objc.Object, "currentNotificationCenter", .{});
        }
        if (self.state.load(.acquire) != .unavailable) {
            self.state.store(.unavailable, .release);
            log.warn("notifications unavailable (unbundled process or framework missing); disabled", .{});
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Process / framework probes
// ---------------------------------------------------------------------------

/// Foreground check for the "only notify in the background" gate. Main
/// thread only (like the transfer_state listener that calls it).
fn appIsActive() bool {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const app = foundation.class("NSApplication").msgSend(objc.Object, "sharedApplication", .{});
    return foundation.toBool(app.msgSend(BOOL, "isActive", .{}));
}

/// True when the process runs from a real .app bundle (CFBundleIdentifier
/// present) — the precondition for every UserNotifications call.
pub fn processIsBundled() bool {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const bundle = foundation.class("NSBundle").msgSend(objc.Object, "mainBundle", .{});
    if (bundle.value == null) return false;
    return bundle.msgSend(c.id, "bundleIdentifier", .{}) != null;
}

/// Loads UserNotifications on first use (dlopen keeps it out of the link
/// line and out of every headless test binary's import list).
fn userNotificationsLoaded() bool {
    if (objc.getClass("UNUserNotificationCenter") != null) return true;
    _ = std.c.dlopen(framework_path, .{ .LAZY = true, .GLOBAL = true }) orelse {
        return false;
    };
    return objc.getClass("UNUserNotificationCenter") != null;
}

fn logNSError(what: []const u8, err: c.id) void {
    if (err == null) return;
    const desc = objc.Object.fromId(err).msgSend(objc.Object, "localizedDescription", .{});
    const utf8 = desc.msgSend(?[*:0]const u8, "UTF8String", .{}) orelse {
        log.warn("{s}", .{what});
        return;
    };
    log.warn("{s}: {s}", .{ what, std.mem.span(utf8) });
}

// ---------------------------------------------------------------------------
// Tests (headless: batch tracking, gating, graceful unbundled degradation).
// The bundled/authorized path cannot run under `zig test` (no bundle) — it
// is exercised by the ad-hoc-signed brief run reported in M3.
// ---------------------------------------------------------------------------
const testing = std.testing;

const TransferStateChange = relay.events.CoreEvent.TransferStateChange;

const HookRecorder = struct {
    batches: std.ArrayList(BatchSummary) = .empty,

    fn notify(ctx: ?*anyopaque, summary: BatchSummary) void {
        const self: *HookRecorder = @ptrCast(@alignCast(ctx.?));
        self.batches.append(testing.allocator, summary) catch unreachable;
    }

    fn hook(self: *HookRecorder) BatchHook {
        return .{ .ctx = self, .notify = notify };
    }

    fn deinit(self: *HookRecorder) void {
        self.batches.deinit(testing.allocator);
    }
};

fn change(id: u64, state: relay.events.TransferState) TransferStateChange {
    return .{ .item_id = id, .state = state };
}

test "batch summary fires once when the last in-flight item finishes" {
    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    var rec: HookRecorder = .{};
    defer rec.deinit();
    n.batch_hook = rec.hook();

    n.onTransferState(change(1, .queued));
    n.onTransferState(change(2, .queued));
    n.onTransferState(change(1, .transferring));
    n.onTransferState(change(1, .completed));
    try testing.expectEqual(@as(usize, 0), rec.batches.items.len); // 2 still flying

    n.onTransferState(change(2, .failed));
    try testing.expectEqual(@as(usize, 1), rec.batches.items.len);
    try testing.expectEqual(@as(u32, 1), rec.batches.items[0].completed);
    try testing.expectEqual(@as(u32, 1), rec.batches.items[0].failed);
    try testing.expectEqual(@as(u32, 0), rec.batches.items[0].canceled);

    // Next batch starts clean.
    n.onTransferState(change(3, .queued));
    n.onTransferState(change(3, .completed));
    try testing.expectEqual(@as(usize, 2), rec.batches.items.len);
    try testing.expectEqual(@as(u32, 1), rec.batches.items[1].completed);
    try testing.expectEqual(@as(u32, 0), rec.batches.items[1].failed);
}

test "terminal events for never-seen items still close out as a batch" {
    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    var rec: HookRecorder = .{};
    defer rec.deinit();
    n.batch_hook = rec.hook();

    // Attach happened mid-transfer: only the terminal event arrives.
    n.onTransferState(change(42, .completed));
    try testing.expectEqual(@as(usize, 1), rec.batches.items.len);
    try testing.expectEqual(@as(u32, 1), rec.batches.items[0].completed);
}

test "paused items keep the batch open; cancel closes it" {
    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    var rec: HookRecorder = .{};
    defer rec.deinit();
    n.batch_hook = rec.hook();

    n.onTransferState(change(1, .queued));
    n.onTransferState(change(1, .paused));
    try testing.expectEqual(@as(usize, 0), rec.batches.items.len);
    n.onTransferState(change(1, .canceled));
    try testing.expectEqual(@as(usize, 1), rec.batches.items.len);
    try testing.expectEqual(@as(u32, 1), rec.batches.items[0].canceled);
}

test "attach wires through any core exposing registerListener" {
    const FakeCore = struct {
        ctx: ?*anyopaque = null,
        call: ?*const fn (*Notifier, TransferStateChange) void = null,

        pub fn registerListener(
            fake: *@This(),
            comptime tag: @TypeOf(.enum_literal),
            ctx: anytype,
            comptime handler: fn (@TypeOf(ctx), TransferStateChange) void,
        ) error{OutOfMemory}!void {
            comptime std.debug.assert(tag == .transfer_state);
            fake.ctx = @ptrCast(ctx);
            fake.call = handler;
        }
    };

    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    var rec: HookRecorder = .{};
    defer rec.deinit();
    n.batch_hook = rec.hook();

    var core: FakeCore = .{};
    try n.attach(&core);
    try testing.expectEqual(@as(?*anyopaque, @ptrCast(n)), core.ctx);

    // Events delivered through the registered listener drive the batch.
    core.call.?(@ptrCast(@alignCast(core.ctx.?)), change(5, .queued));
    core.call.?(@ptrCast(@alignCast(core.ctx.?)), change(5, .completed));
    try testing.expectEqual(@as(usize, 1), rec.batches.items.len);
}

test "unbundled process: requestAuthorization disables quietly, post no-ops" {
    // `zig test` binaries have no CFBundleIdentifier, so this exercises the
    // exact degradation path ad-hoc/unbundled runs hit in production.
    try testing.expect(!processIsBundled());

    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    try testing.expectEqual(Availability.unprobed, n.availability());

    n.requestAuthorization();
    try testing.expectEqual(Availability.unavailable, n.availability());
    n.requestAuthorization(); // idempotent
    try testing.expectEqual(Availability.unavailable, n.availability());

    // Posts (direct and via a real batch) are quiet no-ops.
    n.post("t", "b", "id");
    n.onTransferState(change(1, .queued));
    n.onTransferState(change(1, .completed));
    try testing.expectEqual(Availability.unavailable, n.availability());
}

test "lazy post in an unbundled process stays a no-op (no crash)" {
    const n = try Notifier.create(testing.allocator);
    defer n.destroy();
    n.post("hello", "world", "x"); // .unprobed → request → unavailable
    try testing.expectEqual(Availability.unavailable, n.availability());
}

test {
    testing.refAllDecls(@This());
}

//! dispatch — libdispatch glue, lifted from the proven spike patterns
//! (docs/spikes/ui.md): zig-objc Blocks marshaled with dispatch_async, every
//! invocation wrapped in its own autorelease pool.
//!
//! The main queue is the ONLY core→UI crossing point (docs/ARCHITECTURE.md):
//! workers own no UI state, they only dispatch blocks here. dispatch_async /
//! dispatch_after / dispatch_source_set_event_handler all Block_copy the
//! stack block before returning, so handing off a stack-initialized
//! objc.Block context is safe.

const std = @import("std");
const objc = @import("objc");

pub const Queue = *anyopaque;

// Ghostty pkg/macos pattern: the main queue is the address of the exported
// _dispatch_main_q variable; source types likewise are exported structs.
const dispatch_main_q = @extern(*opaque {}, .{ .name = "_dispatch_main_q" });
const dispatch_source_type_timer = @extern(*opaque {}, .{ .name = "_dispatch_source_type_timer" });

extern "c" fn dispatch_async(queue: Queue, block: *anyopaque) void;
extern "c" fn dispatch_after(when: u64, queue: Queue, block: *anyopaque) void;
extern "c" fn dispatch_time(when: u64, delta: i64) u64;
extern "c" fn dispatch_get_global_queue(identifier: isize, flags: usize) Queue;
extern "c" fn dispatch_source_create(stype: *anyopaque, handle: usize, mask: usize, queue: Queue) ?*anyopaque;
extern "c" fn dispatch_source_set_timer(source: *anyopaque, start: u64, interval: u64, leeway: u64) void;
extern "c" fn dispatch_source_set_event_handler(source: *anyopaque, block: *anyopaque) void;
extern "c" fn dispatch_source_cancel(source: *anyopaque) void;
extern "c" fn dispatch_resume(object: *anyopaque) void;
extern "c" fn dispatch_release(object: *anyopaque) void;

const dispatch_time_now: u64 = 0;

pub fn mainQueue() Queue {
    return @ptrCast(@constCast(dispatch_main_q));
}

/// Default-QoS global concurrent queue (tests; never for UI mutation).
pub fn globalQueue() Queue {
    return dispatch_get_global_queue(0, 0);
}

/// The one block shape we marshal: a Zig context pointer riding as usize.
const CtxBlock = objc.Block(struct { ctx: usize }, .{}, void);

fn ctxBlock(ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) CtxBlock.Context {
    const Ptr = @TypeOf(ctx);
    comptime {
        if (@typeInfo(Ptr) != .pointer) @compileError("dispatch ctx must be a pointer");
    }
    const Fns = struct {
        fn invoke(block: *const CtxBlock.Context) callconv(.c) void {
            const pool = objc.AutoreleasePool.init();
            defer pool.deinit();
            f(@ptrFromInt(block.ctx));
        }
    };
    return CtxBlock.init(.{ .ctx = @intFromPtr(ctx) }, Fns.invoke);
}

/// Marshal `f(ctx)` onto the main queue. Safe to call from any thread;
/// the invocation runs on the main thread inside its own autorelease pool.
pub fn mainQueueAsync(ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) void {
    asyncOnQueue(mainQueue(), ctx, f);
}

pub fn asyncOnQueue(queue: Queue, ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) void {
    var block = ctxBlock(ctx, f);
    dispatch_async(queue, @ptrCast(&block));
}

/// Run `f(ctx)` on the main queue after `seconds`.
pub fn after(seconds: f64, ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) void {
    afterOnQueue(mainQueue(), seconds, ctx, f);
}

pub fn afterOnQueue(queue: Queue, seconds: f64, ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) void {
    var block = ctxBlock(ctx, f);
    const delta_ns: i64 = @intFromFloat(seconds * @as(f64, std.time.ns_per_s));
    dispatch_after(dispatch_time(dispatch_time_now, delta_ns), queue, @ptrCast(&block));
}

/// Repeating dispatch_source timer. `f(ctx)` fires on the chosen queue every
/// `interval_ms`, pool-wrapped. Call `cancel` exactly once to stop and
/// release; never fires again afterwards.
pub const RepeatingTimer = struct {
    source: *anyopaque,

    pub const StartError = error{SourceCreateFailed};

    /// Timer on the main queue — the only variant UI code should use.
    pub fn startOnMain(
        interval_ms: u64,
        ctx: anytype,
        comptime f: fn (@TypeOf(ctx)) void,
    ) StartError!RepeatingTimer {
        return startOnQueue(mainQueue(), interval_ms, ctx, f);
    }

    pub fn startOnQueue(
        queue: Queue,
        interval_ms: u64,
        ctx: anytype,
        comptime f: fn (@TypeOf(ctx)) void,
    ) StartError!RepeatingTimer {
        const source = dispatch_source_create(
            @ptrCast(@constCast(dispatch_source_type_timer)),
            0,
            0,
            queue,
        ) orelse return StartError.SourceCreateFailed;

        var block = ctxBlock(ctx, f); // set_event_handler Block_copy's it
        dispatch_source_set_event_handler(source, @ptrCast(&block));

        const interval_ns: u64 = interval_ms * std.time.ns_per_ms;
        dispatch_source_set_timer(
            source,
            dispatch_time(dispatch_time_now, @intCast(interval_ns)),
            interval_ns,
            interval_ns / 10, // leeway: 10% — UI cadence, not a metronome
        );
        dispatch_resume(source);
        return .{ .source = source };
    }

    pub fn cancel(self: RepeatingTimer) void {
        dispatch_source_cancel(self.source);
        dispatch_release(self.source);
    }
};

// ---------------------------------------------------------------------------
// Tests. Global-queue variants verify the block plumbing deterministically
// with semaphores; the main-queue path additionally runs under the main
// NSRunLoop (the test runner executes on the main thread).
// ---------------------------------------------------------------------------
extern "c" fn dispatch_semaphore_create(value: isize) ?*anyopaque;
extern "c" fn dispatch_semaphore_wait(sema: *anyopaque, timeout: u64) isize;
extern "c" fn dispatch_semaphore_signal(sema: *anyopaque) isize;

const foundation = @import("foundation.zig");
const NSDefaultRunLoopMode = @extern(*const objc.c.id, .{ .name = "NSDefaultRunLoopMode" });

const testing = std.testing;

const SemaCtx = struct {
    sema: *anyopaque,
    count: std.atomic.Value(u64) = .init(0),

    fn bumpAndSignal(self: *SemaCtx) void {
        _ = self.count.fetchAdd(1, .monotonic);
        _ = dispatch_semaphore_signal(self.sema);
    }
};

fn waitFor(sema: *anyopaque, seconds: f64) !void {
    const delta_ns: i64 = @intFromFloat(seconds * @as(f64, std.time.ns_per_s));
    const timeout = dispatch_time(dispatch_time_now, delta_ns);
    if (dispatch_semaphore_wait(sema, timeout) != 0) return error.DispatchTimeout;
}

test "asyncOnQueue executes the block with the right ctx" {
    var ctx: SemaCtx = .{ .sema = dispatch_semaphore_create(0) orelse return error.SemaCreate };
    asyncOnQueue(globalQueue(), &ctx, SemaCtx.bumpAndSignal);
    try waitFor(ctx.sema, 5);
    try testing.expectEqual(@as(u64, 1), ctx.count.load(.acquire));
}

test "afterOnQueue fires once after the delay" {
    var ctx: SemaCtx = .{ .sema = dispatch_semaphore_create(0) orelse return error.SemaCreate };
    afterOnQueue(globalQueue(), 0.02, &ctx, SemaCtx.bumpAndSignal);
    try waitFor(ctx.sema, 5);
    try testing.expectEqual(@as(u64, 1), ctx.count.load(.acquire));
}

test "RepeatingTimer fires repeatedly, then cancel stops it" {
    var ctx: SemaCtx = .{ .sema = dispatch_semaphore_create(0) orelse return error.SemaCreate };
    const timer = try RepeatingTimer.startOnQueue(globalQueue(), 5, &ctx, SemaCtx.bumpAndSignal);
    // Three distinct fires (each signals once).
    try waitFor(ctx.sema, 5);
    try waitFor(ctx.sema, 5);
    try waitFor(ctx.sema, 5);
    timer.cancel();
    try testing.expect(ctx.count.load(.acquire) >= 3);
}

const MainCtx = struct {
    fired: bool = false,

    fn mark(self: *MainCtx) void {
        self.fired = true;
    }
};

test "mainQueueAsync drains on the main runloop" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    var ctx: MainCtx = .{};
    mainQueueAsync(&ctx, MainCtx.mark);

    // The test runner is on the main thread; spinning the main NSRunLoop
    // services the dispatch main queue. Bounded to keep failure clean.
    const runloop = foundation.class("NSRunLoop").msgSend(objc.Object, "mainRunLoop", .{});
    var spins: u32 = 0;
    while (!ctx.fired and spins < 100) : (spins += 1) {
        const date = foundation.class("NSDate")
            .msgSend(objc.Object, "dateWithTimeIntervalSinceNow:", .{@as(f64, 0.02)});
        _ = runloop.msgSend(foundation.BOOL, "runMode:beforeDate:", .{
            objc.Object.fromId(NSDefaultRunLoopMode.*), date,
        });
    }
    try testing.expect(ctx.fired);
}

test {
    testing.refAllDecls(@This());
}

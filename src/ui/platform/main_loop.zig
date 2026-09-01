//! Toolkit-neutral UI-thread scheduling seam.

const std = @import("std");

pub const MainLoop = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const Timer = struct { handle: *anyopaque };
    pub const TimerError = error{TimerCreateFailed};

    pub const VTable = struct {
        /// Enqueue `f(arg)` on the UI thread. Must not block.
        post: *const fn (
            ctx: *anyopaque,
            arg: *anyopaque,
            f: *const fn (*anyopaque) void,
        ) void,
        startTimer: *const fn (
            ctx: *anyopaque,
            interval_ms: u64,
            arg: *anyopaque,
            f: *const fn (*anyopaque) void,
        ) TimerError!Timer,
        cancelTimer: *const fn (ctx: *anyopaque, timer: Timer) void,
    };

    pub fn post(self: MainLoop, arg: anytype, comptime f: fn (@TypeOf(arg)) void) void {
        const Arg = @TypeOf(arg);
        comptime requirePointer(Arg);
        const Shim = struct {
            fn call(raw: *anyopaque) void {
                f(@ptrCast(@alignCast(raw)));
            }
        };
        self.vtable.post(self.ctx, @ptrCast(arg), Shim.call);
    }

    pub fn startTimer(
        self: MainLoop,
        interval_ms: u64,
        arg: anytype,
        comptime f: fn (@TypeOf(arg)) void,
    ) TimerError!Timer {
        const Arg = @TypeOf(arg);
        comptime requirePointer(Arg);
        const Shim = struct {
            fn call(raw: *anyopaque) void {
                f(@ptrCast(@alignCast(raw)));
            }
        };
        return self.vtable.startTimer(self.ctx, interval_ms, @ptrCast(arg), Shim.call);
    }

    pub fn cancelTimer(self: MainLoop, timer: Timer) void {
        self.vtable.cancelTimer(self.ctx, timer);
    }

    fn requirePointer(comptime T: type) void {
        if (@typeInfo(T) != .pointer) @compileError("MainLoop callback arg must be a pointer");
    }
};

/// Deterministic, allocation-free fake. Pin it before taking `mainLoop()`;
/// timer handles point into its fixed slot array. `advance` moves virtual
/// time and invokes every timer occurrence due by the new instant.
pub const Manual = struct {
    now_ms: u64 = 0,
    posts: [post_capacity]Post = undefined,
    post_head: usize = 0,
    post_len: usize = 0,
    timers: [timer_capacity]TimerSlot = @splat(.{}),

    const post_capacity = 256;
    const timer_capacity = 32;

    const Post = struct {
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    };

    const TimerSlot = struct {
        active: bool = false,
        interval_ms: u64 = 0,
        next_ms: u64 = 0,
        arg: *anyopaque = undefined,
        f: *const fn (*anyopaque) void = undefined,
    };

    pub fn mainLoop(self: *Manual) MainLoop {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    pub fn drain(self: *Manual) void {
        while (self.post_len > 0) {
            const queued = self.posts[self.post_head];
            self.post_head = (self.post_head + 1) % post_capacity;
            self.post_len -= 1;
            queued.f(queued.arg);
        }
    }

    pub fn advance(self: *Manual, elapsed_ms: u64) void {
        self.now_ms +|= elapsed_ms;
        for (&self.timers) |*slot| {
            while (slot.active and slot.next_ms <= self.now_ms) {
                slot.next_ms +|= slot.interval_ms;
                const arg = slot.arg;
                const f = slot.f;
                f(arg);
            }
        }
        self.drain();
    }

    fn fromCtx(ctx: *anyopaque) *Manual {
        return @ptrCast(@alignCast(ctx));
    }

    fn post(
        ctx: *anyopaque,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) void {
        const self = fromCtx(ctx);
        std.debug.assert(self.post_len < post_capacity);
        const tail = (self.post_head + self.post_len) % post_capacity;
        self.posts[tail] = .{ .arg = arg, .f = f };
        self.post_len += 1;
    }

    fn startTimer(
        ctx: *anyopaque,
        interval_ms: u64,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) MainLoop.TimerError!MainLoop.Timer {
        if (interval_ms == 0) return error.TimerCreateFailed;
        const self = fromCtx(ctx);
        for (&self.timers) |*slot| {
            if (slot.active) continue;
            slot.* = .{
                .active = true,
                .interval_ms = interval_ms,
                .next_ms = self.now_ms +| interval_ms,
                .arg = arg,
                .f = f,
            };
            return .{ .handle = @ptrCast(slot) };
        }
        return error.TimerCreateFailed;
    }

    fn cancelTimer(_: *anyopaque, timer: MainLoop.Timer) void {
        const slot: *TimerSlot = @ptrCast(@alignCast(timer.handle));
        std.debug.assert(slot.active);
        slot.active = false;
    }

    const vtable: MainLoop.VTable = .{
        .post = post,
        .startTimer = startTimer,
        .cancelTimer = cancelTimer,
    };
};

test "manual loop queues posts and advances repeating timers virtually" {
    const Recorder = struct {
        posts: usize = 0,
        ticks: usize = 0,

        fn onPost(self: *@This()) void {
            self.posts += 1;
        }

        fn onTick(self: *@This()) void {
            self.ticks += 1;
        }
    };

    var manual: Manual = .{};
    const loop = manual.mainLoop();
    var recorder: Recorder = .{};

    loop.post(&recorder, Recorder.onPost);
    try std.testing.expectEqual(@as(usize, 0), recorder.posts);
    manual.drain();
    try std.testing.expectEqual(@as(usize, 1), recorder.posts);

    const timer = try loop.startTimer(25, &recorder, Recorder.onTick);
    manual.advance(74);
    try std.testing.expectEqual(@as(usize, 2), recorder.ticks);
    manual.advance(1);
    try std.testing.expectEqual(@as(usize, 3), recorder.ticks);
    loop.cancelTimer(timer);
    manual.advance(100);
    try std.testing.expectEqual(@as(usize, 3), recorder.ticks);
}

test {
    std.testing.refAllDecls(MainLoop);
    std.testing.refAllDecls(Manual);
}

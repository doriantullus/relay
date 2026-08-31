//! rate_limit — token-bucket transfer shaping. The engine keeps one bucket
//! pair (up/down) globally and one pair per site lane; stream pumps acquire
//! from both before each chunk and sleep on exhaustion.
//!
//! The bucket uses a borrowing model: a consumer with any positive balance
//! takes its whole chunk (balance may go deep negative) and the *next*
//! consumer waits until the debt is repaid. Long-run throughput is exact —
//! integer math scaled by ns_per_s, no float drift — while a chunk is never
//! split, which keeps the pump loop trivial.

const std = @import("std");
const cancel_mod = @import("../cancel.zig");

const ns_per_s: i128 = std.time.ns_per_s;

const lockSpin = @import("../sync.zig").lockSpin;

/// Time source for the bucket. `real` reads the host clock and sleeps on
/// it (production); `virtual` advances a counter instead, so pacing is
/// deterministic and instant.
///
/// Why the seam exists: the bucket's accuracy is a property of its token
/// math, but measuring it through real sleeps measures the HOST's scheduler
/// too. On oversubscribed CI runners `io.sleep` overshoots without bound, so
/// no wall-clock tolerance can hold — a ±20% window here was red on GitHub's
/// macOS runners while the arithmetic was exactly right. Under `virtual` the
/// pacing assertions below are exact, and the one remaining real-clock test
/// asserts only a lower bound, which any host must satisfy.
pub const Clock = union(enum) {
    real: std.Io,
    virtual: *Virtual,

    pub const Virtual = struct {
        now_ns: i96 = 0,
        /// Total virtual time slept — the pacing the bucket actually asked
        /// for, with no host noise mixed in.
        slept_ns: u64 = 0,
        /// Fired after each sleep, to model an event arriving mid-wait.
        on_sleep: ?*const fn (*Virtual) void = null,
        /// Opaque payload for `on_sleep`.
        context: ?*anyopaque = null,

        pub fn clock(self: *Virtual) Clock {
            return .{ .virtual = self };
        }
    };

    pub fn fromIo(io: std.Io) Clock {
        return .{ .real = io };
    }

    pub fn nowNs(self: Clock) i96 {
        return switch (self) {
            .real => |io| std.Io.Clock.awake.now(io).nanoseconds,
            .virtual => |v| v.now_ns,
        };
    }

    fn sleep(self: Clock, ns: u64) void {
        switch (self) {
            // io.sleep's own Canceled belongs to std.Io task cancellation,
            // which this engine does not use; our token is checked above.
            .real => |io| io.sleep(.fromNanoseconds(ns), .awake) catch {},
            .virtual => |v| {
                v.now_ns += @intCast(ns);
                v.slept_ns += ns;
                if (v.on_sleep) |f| f(v);
            },
        }
    }
};

pub const TokenBucket = struct {
    /// Spin lock (see events.zig for why not std.Io.Mutex): the critical
    /// section is a handful of integer ops, and acquirers come from worker
    /// threads plus settings changes from the UI thread.
    mutex: std.atomic.Mutex = .unlocked,
    /// Bytes per second; 0 = unlimited.
    rate: u64,
    /// Burst allowance in bytes (also the maximum positive balance).
    capacity: u64,
    /// Token balance scaled by ns_per_s (byte·ns); negative = borrowed.
    balance_scaled: i128 = 0,
    last_ns: i96 = 0,
    /// First acquire after init/rate-change starts with a full burst.
    primed: bool = false,

    /// Upper bound for one wait slice; bounds cancel latency while keeping
    /// the number of wakeups (and thus oversleep accumulation) low enough
    /// for the ±20% accuracy contract.
    pub const max_sleep_ns: u64 = 20 * std.time.ns_per_ms;

    pub fn init(rate: u64, capacity: u64) TokenBucket {
        return .{ .rate = rate, .capacity = @max(capacity, 1) };
    }

    /// Runtime adjustment. Forgives outstanding debt so lowering the limit
    /// mid-transfer never stalls a pump for the old debt at the new rate.
    pub fn setRate(self: *TokenBucket, clock: Clock, new_rate: u64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.refillLocked(clock.nowNs());
        self.rate = new_rate;
        if (self.balance_scaled < 0) self.balance_scaled = 0;
    }

    pub fn setCapacity(self: *TokenBucket, clock: Clock, new_capacity: u64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.refillLocked(clock.nowNs());
        self.capacity = @max(new_capacity, 1);
    }

    /// Consume `n` tokens, sleeping (in cancel-checked slices) until the
    /// bucket can cover them. Returns immediately when unlimited.
    pub fn acquire(
        self: *TokenBucket,
        clock: Clock,
        token: *const cancel_mod.CancelToken,
        n: u64,
    ) error{Canceled}!void {
        if (n == 0) return;
        while (true) {
            try token.check();
            const wait_ns: u64 = blk: {
                lockSpin(&self.mutex);
                defer self.mutex.unlock();
                if (self.rate == 0) break :blk 0;
                self.refillLocked(clock.nowNs());
                if (self.balance_scaled > 0) {
                    self.balance_scaled -= @as(i128, n) * ns_per_s;
                    break :blk 0;
                }
                const deficit = 1 - self.balance_scaled;
                const ns = @divTrunc(deficit, self.rate) + 1;
                break :blk @intCast(@min(ns, std.math.maxInt(u64)));
            };
            if (wait_ns == 0) return;
            clock.sleep(@min(wait_ns, max_sleep_ns));
        }
    }

    fn refillLocked(self: *TokenBucket, now: i96) void {
        const cap_scaled = @as(i128, self.capacity) * ns_per_s;
        if (!self.primed) {
            self.primed = true;
            self.last_ns = now;
            self.balance_scaled = cap_scaled;
            return;
        }
        const elapsed = @max(0, @as(i128, now) - self.last_ns);
        self.last_ns = now;
        self.balance_scaled = @min(cap_scaled, self.balance_scaled + elapsed * self.rate);
    }
};

test "unlimited bucket never sleeps" {
    var v: Clock.Virtual = .{};
    var bucket: TokenBucket = .init(0, 1);
    var token: cancel_mod.CancelToken = .{};
    var i: usize = 0;
    while (i < 1000) : (i += 1) try bucket.acquire(v.clock(), &token, 1 << 30);
    try std.testing.expectEqual(@as(u64, 0), v.slept_ns);
}

test "rate accuracy is exact under a virtual clock" {
    const rate: u64 = 1_000_000; // bytes/s
    const capacity: u64 = 10_000;
    const chunk: u64 = 10_000;
    const chunks: u64 = 10;

    var v: Clock.Virtual = .{};
    var bucket: TokenBucket = .init(rate, capacity);
    var token: cancel_mod.CancelToken = .{};

    var i: u64 = 0;
    while (i < chunks) : (i += 1) try bucket.acquire(v.clock(), &token, chunk);

    // Borrowing model: the initial burst covers the first chunk and the
    // second is taken on credit, so the paced portion is total − 2 chunks.
    const expected_ns: i128 = @as(i128, (chunks * chunk - capacity - chunk)) * ns_per_s / rate;
    // Exact, not a tolerance: the only slack is the +1 ns rounding in
    // acquire's deficit math, at most once per paced chunk.
    try std.testing.expect(v.now_ns >= expected_ns);
    try std.testing.expect(v.now_ns <= expected_ns + @as(i128, chunks));
}

test "real clock: pacing is wired through std.Io" {
    const io = std.testing.io;
    const rate: u64 = 1_000_000;
    const capacity: u64 = 10_000;
    const chunk: u64 = 10_000;
    const chunks: u64 = 4;

    var bucket: TokenBucket = .init(rate, capacity);
    var token: cancel_mod.CancelToken = .{};

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var i: u64 = 0;
    while (i < chunks) : (i += 1) try bucket.acquire(.fromIo(io), &token, chunk);
    const elapsed_ns: i128 = std.Io.Clock.awake.now(io).nanoseconds - start;

    // LOWER BOUND ONLY, and that is the whole point: the bucket cannot hand
    // out tokens before they accrue, so this holds on any host however
    // loaded. An upper bound here would measure the host's sleep overshoot
    // rather than the bucket — see Clock's doc comment. Exactness lives in
    // the virtual-clock test above.
    const expected_ns: i128 = @as(i128, (chunks * chunk - capacity - chunk)) * ns_per_s / rate;
    try std.testing.expect(elapsed_ns >= @divTrunc(expected_ns * 9, 10));
}

test "pre-canceled token aborts immediately" {
    var v: Clock.Virtual = .{};
    var bucket: TokenBucket = .init(10, 1); // 10 B/s: would wait ~forever
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(v.clock(), &token, 1_000_000); // burst+borrow: no wait
    token.cancel();
    try std.testing.expectError(error.Canceled, bucket.acquire(v.clock(), &token, 1));
    try std.testing.expectEqual(@as(u64, 0), v.slept_ns);
}

test "cancel during exhaustion wait is observed within one sleep slice" {
    var v: Clock.Virtual = .{};
    var bucket: TokenBucket = .init(100, 1);
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(v.clock(), &token, 1_000_000_000); // huge debt

    // Model the cancel arriving mid-wait: it fires from inside the sleep.
    const Hook = struct {
        fn cancelFromSleep(vc: *Clock.Virtual) void {
            const t: *cancel_mod.CancelToken = @ptrCast(@alignCast(vc.context.?));
            t.cancel();
        }
    };
    v.on_sleep = Hook.cancelFromSleep;
    v.context = &token;
    v.slept_ns = 0;

    try std.testing.expectError(error.Canceled, bucket.acquire(v.clock(), &token, 1));
    // Exactly one slice — the token is re-checked at the top of every loop.
    try std.testing.expectEqual(TokenBucket.max_sleep_ns, v.slept_ns);
}

test "setRate to unlimited releases waiters' future acquires" {
    var v: Clock.Virtual = .{};
    var bucket: TokenBucket = .init(100, 1);
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(v.clock(), &token, 1_000_000_000);
    bucket.setRate(v.clock(), 0); // also forgives the debt
    v.slept_ns = 0;
    try bucket.acquire(v.clock(), &token, 1_000_000_000);
    try std.testing.expectEqual(@as(u64, 0), v.slept_ns);
}

test {
    std.testing.refAllDecls(@This());
}

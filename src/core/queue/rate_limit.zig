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

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

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
    pub fn setRate(self: *TokenBucket, io: std.Io, new_rate: u64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.refillLocked(nowNs(io));
        self.rate = new_rate;
        if (self.balance_scaled < 0) self.balance_scaled = 0;
    }

    pub fn setCapacity(self: *TokenBucket, io: std.Io, new_capacity: u64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.refillLocked(nowNs(io));
        self.capacity = @max(new_capacity, 1);
    }

    /// Consume `n` tokens, sleeping (in cancel-checked slices) until the
    /// bucket can cover them. Returns immediately when unlimited.
    pub fn acquire(
        self: *TokenBucket,
        io: std.Io,
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
                self.refillLocked(nowNs(io));
                if (self.balance_scaled > 0) {
                    self.balance_scaled -= @as(i128, n) * ns_per_s;
                    break :blk 0;
                }
                const deficit = 1 - self.balance_scaled;
                const ns = @divTrunc(deficit, self.rate) + 1;
                break :blk @intCast(@min(ns, std.math.maxInt(u64)));
            };
            if (wait_ns == 0) return;
            // io.sleep's own Canceled belongs to std.Io task cancellation,
            // which this engine does not use; our token is checked above.
            io.sleep(.fromNanoseconds(@min(wait_ns, max_sleep_ns)), .awake) catch {};
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
    const io = std.testing.io;
    var bucket: TokenBucket = .init(0, 1);
    var token: cancel_mod.CancelToken = .{};
    const start = nowNs(io);
    var i: usize = 0;
    while (i < 1000) : (i += 1) try bucket.acquire(io, &token, 1 << 30);
    const elapsed_ms = @divTrunc(nowNs(io) - start, std.time.ns_per_ms);
    try std.testing.expect(elapsed_ms < 50);
}

test "rate accuracy within 20% over a short window" {
    const io = std.testing.io;
    const rate: u64 = 1_000_000; // bytes/s
    const capacity: u64 = 10_000;
    const chunk: u64 = 10_000;
    const chunks: u64 = 10;

    var bucket: TokenBucket = .init(rate, capacity);
    var token: cancel_mod.CancelToken = .{};

    const start = nowNs(io);
    var i: u64 = 0;
    while (i < chunks) : (i += 1) try bucket.acquire(io, &token, chunk);
    const elapsed_ns: i128 = nowNs(io) - start;

    // Borrowing model: the initial burst covers the first chunk and the
    // second is taken on credit, so the paced portion is total − 2 chunks.
    const expected_ns: i128 = @as(i128, (chunks * chunk - capacity - chunk)) * ns_per_s / rate;
    try std.testing.expect(elapsed_ns >= @divTrunc(expected_ns * 8, 10));
    try std.testing.expect(elapsed_ns <= @divTrunc(expected_ns * 12, 10));
}

test "pre-canceled token aborts immediately" {
    const io = std.testing.io;
    var bucket: TokenBucket = .init(10, 1); // 10 B/s: would wait ~forever
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(io, &token, 1_000_000); // burst+borrow: no wait
    token.cancel();
    try std.testing.expectError(error.Canceled, bucket.acquire(io, &token, 1));
}

test "cancel during exhaustion wait is bounded by the sleep slice" {
    const io = std.testing.io;
    var bucket: TokenBucket = .init(100, 1);
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(io, &token, 1_000_000_000); // huge debt

    const Canceler = struct {
        fn run(t: *cancel_mod.CancelToken) void {
            std.Io.sleep(std.testing.io, .fromMilliseconds(5), .awake) catch {};
            t.cancel();
        }
    };
    const thread = try std.Thread.spawn(.{}, Canceler.run, .{&token});
    defer thread.join();

    const start = nowNs(io);
    try std.testing.expectError(error.Canceled, bucket.acquire(io, &token, 1));
    const elapsed_ms = @divTrunc(nowNs(io) - start, std.time.ns_per_ms);
    // One full slice (20 ms) + scheduling slack.
    try std.testing.expect(elapsed_ms < 100);
}

test "setRate to unlimited releases waiters' future acquires" {
    const io = std.testing.io;
    var bucket: TokenBucket = .init(100, 1);
    var token: cancel_mod.CancelToken = .{};
    try bucket.acquire(io, &token, 1_000_000_000);
    bucket.setRate(io, 0); // also forgives the debt
    const start = nowNs(io);
    try bucket.acquire(io, &token, 1_000_000_000);
    const elapsed_ms = @divTrunc(nowNs(io) - start, std.time.ns_per_ms);
    try std.testing.expect(elapsed_ms < 50);
}

test {
    std.testing.refAllDecls(@This());
}

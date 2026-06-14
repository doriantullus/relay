//! keepalive — the per-site idle maintenance worker. Spawned into the
//! pool's Io.Group on the first successful connect; `SitePool.disconnect`
//! cancels the group, which interrupts the sleep and joins the loop.
//!
//! Each sweep:
//! - reaps idle TRANSFER connections older than `idle_timeout_ms`
//!   (the browse connection is dedicated and kept warm instead),
//! - sends a protocol NOOP on every connection idle for at least
//!   `keepalive_interval_ms`; a failed NOOP retires the connection
//!   silently (transcript line only) so the next checkout reconnects
//!   transparently.
//!
//! NOOPs run with the slot `pinned` and the pool unlocked — a slow server
//! must not block checkouts.

const std = @import("std");
const site_pool = @import("site_pool.zig");
const SitePool = site_pool.SitePool;
const CancelToken = @import("../cancel.zig").CancelToken;
const Diagnostics = @import("../diag.zig").Diagnostics;

/// Worker loop body (Io.Group task). Exits on group cancellation (the
/// sleep is the cancellation point) or pool shutdown.
pub fn run(pool: *SitePool, io: std.Io) error{Canceled}!void {
    const interval_ms = pool.config.keepalive_interval_ms;
    std.debug.assert(interval_ms > 0);
    while (true) {
        try io.sleep(.fromMilliseconds(@intCast(interval_ms)), .awake);
        if (pool.cancel_token.isCanceled()) return;
        sweep(pool, io);
    }
}

/// One maintenance pass; callable directly from tests (virtual cadence).
pub fn sweep(pool: *SitePool, io: std.Io) void {
    const interval_ns = msToNs(pool.config.keepalive_interval_ms);
    const timeout_ns = msToNs(pool.config.idle_timeout_ms);
    const now = site_pool.nowNs(io);

    var reaped: [1 + site_pool.max_transfer_cap]site_pool.Conn = undefined;
    var reaped_n: usize = 0;
    var pinned: [1 + site_pool.max_transfer_cap]*site_pool.Slot = undefined;
    var pinned_n: usize = 0;

    pool.mutex.lockUncancelable(io);
    if (pool.shutdown) {
        pool.mutex.unlock(io);
        return;
    }
    for (&pool.transfers) |*slot| {
        if (slot.state != .idle) continue;
        if (timeout_ns > 0 and now - slot.last_used_ns >= timeout_ns) {
            reaped[reaped_n] = slot.conn;
            reaped_n += 1;
            slot.state = .empty;
            pool.note("idle transfer connection reaped after timeout", .{});
        }
    }
    maybePin(&pool.browse, now, interval_ns, &pinned, &pinned_n);
    for (&pool.transfers) |*slot| {
        maybePin(slot, now, interval_ns, &pinned, &pinned_n);
    }
    if (reaped_n > 0) pool.cond.broadcast(io);
    pool.mutex.unlock(io);

    for (reaped[0..reaped_n]) |conn| conn.close(io);

    // NOOP the pinned conns with the pool unlocked; failures retire the
    // connection silently.
    for (pinned[0..pinned_n]) |slot| {
        var scratch: Diagnostics = .{};
        const ok = blk: {
            slot.conn.noop(io, &pool.cancel_token, &scratch) catch break :blk false;
            break :blk true;
        };
        var to_close: ?site_pool.Conn = null;
        pool.mutex.lockUncancelable(io);
        std.debug.assert(slot.state == .pinned);
        if (ok and !pool.shutdown) {
            slot.state = .idle;
            slot.last_used_ns = site_pool.nowNs(io);
        } else {
            to_close = slot.conn;
            slot.state = .empty;
            if (!pool.shutdown) {
                pool.note("idle connection dropped (keepalive failed); reconnecting silently", .{});
            }
        }
        pool.cond.broadcast(io);
        pool.mutex.unlock(io);
        if (to_close) |conn| conn.close(io);
    }
}

fn maybePin(
    slot: *site_pool.Slot,
    now: i96,
    interval_ns: i96,
    pinned: *[1 + site_pool.max_transfer_cap]*site_pool.Slot,
    pinned_n: *usize,
) void {
    if (slot.state != .idle) return;
    if (interval_ns > 0 and now - slot.last_used_ns < interval_ns) return;
    slot.state = .pinned;
    pinned[pinned_n.*] = slot;
    pinned_n.* += 1;
}

fn msToNs(ms: u64) i96 {
    return @as(i96, @intCast(ms)) * std.time.ns_per_ms;
}

// ---------------------------------------------------------------------------
// Tests (mock conns; short real timers where the worker loop is involved)
// ---------------------------------------------------------------------------

const testing = std.testing;
const MockHub = site_pool.MockHub;
const MockConn = site_pool.MockConn;
const transcript_mod = @import("../log/transcript.zig");

fn sleepMs(io: std.Io, ms: u16) void {
    io.sleep(.fromMilliseconds(ms), .awake) catch {};
}

/// Polls `counter` until it reaches `want` or ~2s elapse (CI headroom);
/// returns the final value.
fn waitForCount(io: std.Io, counter: *std.atomic.Value(usize), want: usize) usize {
    var waited_ms: usize = 0;
    while (waited_ms < 2_000) : (waited_ms += 5) {
        if (counter.load(.monotonic) >= want) break;
        sleepMs(io, 5);
    }
    return counter.load(.monotonic);
}

test "sweep NOOPs idle conns once due, refreshing last_used" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0, // worker off; sweeps manual
        .idle_timeout_ms = 0,
    }, .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var browse = try pool.checkout(io, &cancel, &diag, .browse);
    browse.release(io);
    var transfer = try pool.checkout(io, &cancel, &diag, .transfer);
    transfer.release(io);

    // interval 0 => every idle conn is due on every sweep.
    sweep(&pool, io);
    try testing.expectEqual(@as(usize, 2), hub.noops.load(.monotonic));
    sweep(&pool, io);
    try testing.expectEqual(@as(usize, 4), hub.noops.load(.monotonic));

    // Both conns are still pooled and reusable.
    var again = try pool.checkout(io, &cancel, &diag, .browse);
    defer again.release(io);
    try testing.expectEqual(@as(usize, 2), hub.connects.load(.monotonic));
}

test "sweep skips conns idle for less than the interval" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 60_000, // nothing becomes due in this test
        .idle_timeout_ms = 0,
    }, .{});
    // keepalive_interval_ms > 0 starts the worker on connect; that's fine —
    // its first sweep is a minute out.
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    lease.release(io);

    sweep(&pool, io);
    try testing.expectEqual(@as(usize, 0), hub.noops.load(.monotonic));
}

test "idle transfer conns are reaped after idle_timeout; browse is kept" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0,
        .idle_timeout_ms = 1,
    }, .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var browse = try pool.checkout(io, &cancel, &diag, .browse);
    browse.release(io);
    var transfer = try pool.checkout(io, &cancel, &diag, .transfer);
    transfer.release(io);

    sleepMs(io, 5); // both conns now older than idle_timeout
    sweep(&pool, io);

    // The transfer conn was reaped; the dedicated browse conn was NOOPed
    // instead (interval 0 = always due) and kept.
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), hub.openConns());

    var t2 = try pool.checkout(io, &cancel, &diag, .transfer);
    defer t2.release(io);
    try testing.expectEqual(@as(usize, 3), hub.connects.load(.monotonic));
}

test "failed keepalive NOOP retires the conn; next checkout reconnects silently" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var transcript = try transcript_mod.Transcript.init(testing.allocator, .{ .capacity = 64, .max_line_bytes = 128 });
    defer transcript.deinit();
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0,
        .idle_timeout_ms = 0,
    }, .{ .transcript = &transcript });
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    lease.release(io);

    hub.fail_next_noops.store(1, .monotonic);
    sweep(&pool, io);
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));

    var lease2 = try pool.checkout(io, &cancel, &diag, .browse);
    defer lease2.release(io);
    try testing.expectEqual(@as(usize, 2), hub.connects.load(.monotonic));

    var snap = try transcript.snapshot(testing.allocator);
    defer snap.deinit(testing.allocator);
    var saw_note = false;
    for (snap.lines) |line| {
        if (std.mem.indexOf(u8, line.text, "keepalive failed") != null) saw_note = true;
    }
    try testing.expect(saw_note);
}

test "worker loop: NOOP cadence on short timers, disconnect joins cleanly" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 5,
        .idle_timeout_ms = 0,
    }, .{});

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    lease.release(io);

    // The worker started on first connect; expect repeated NOOPs.
    const seen = waitForCount(io, &hub.noops, 2);
    try testing.expect(seen >= 2);

    // disconnect cancels the group; this must not hang and the conn count
    // must come back to zero.
    pool.disconnect(io);
    try testing.expectEqual(@as(usize, 0), hub.openConns());
    const after = hub.noops.load(.monotonic);
    sleepMs(io, 20);
    // The loop is really gone: no more NOOPs accrue.
    try testing.expectEqual(after, hub.noops.load(.monotonic));
    pool.deinit(io);
}

test {
    std.testing.refAllDecls(@This());
}

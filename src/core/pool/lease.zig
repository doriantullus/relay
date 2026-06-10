//! lease — the checkout handle for one pooled connection. Defer
//! discipline:
//!
//! ```
//! var lease = try pool.checkout(io, cancel, diag, .browse);
//! defer lease.release(io);
//! engineCall(...) catch |err| {
//!     if (err == error.ConnectionLost) lease.markBroken();
//!     return err;
//! };
//! ```
//!
//! A lease released as broken tears its connection down instead of
//! returning it to the pool — a connection that failed mid-protocol is
//! never reused (control-channel state is unknowable after a drop).

const std = @import("std");
const site_pool = @import("site_pool.zig");

pub const Lease = struct {
    pool: *site_pool.SitePool,
    slot: *site_pool.Slot,
    conn: site_pool.Conn,
    role: site_pool.Role,
    broken: bool = false,
    released: bool = false,

    /// The protocol engine behind this lease; backends downcast per the
    /// site's protocol.
    pub fn engine(l: *const Lease) site_pool.Engine {
        return l.conn.engine;
    }

    /// Marks the connection as unusable; release will tear it down.
    /// Call on any error that leaves protocol state unknown
    /// (ConnectionLost, mid-transfer cancellation, protocol violations).
    pub fn markBroken(l: *Lease) void {
        l.broken = true;
    }

    /// Returns the connection to the pool (or tears it down when broken
    /// or the site has shut down). Idempotent — safe in defer alongside
    /// explicit early release.
    pub fn release(l: *Lease, io: std.Io) void {
        if (l.released) return;
        l.released = true;
        l.pool.releaseLease(l.slot, l.broken, io);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const CancelToken = @import("../cancel.zig").CancelToken;
const Diagnostics = @import("../diag.zig").Diagnostics;

test "release is idempotent and returns the conn for reuse" {
    const io = testing.io;
    var hub = site_pool.MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0,
    }, .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    try testing.expect(lease.engine() == .mock);
    lease.release(io);
    lease.release(io); // second release is a no-op
    try testing.expectEqual(@as(usize, 0), hub.closes.load(.monotonic));

    // The defer pattern: early release + defer both fire safely.
    {
        var l2 = try pool.checkout(io, &cancel, &diag, .browse);
        defer l2.release(io);
        l2.release(io);
    }
    try testing.expectEqual(@as(usize, 1), hub.connects.load(.monotonic));
}

test "markBroken release tears down instead of reusing" {
    const io = testing.io;
    var hub = site_pool.MockHub.init(testing.allocator);
    var pool = site_pool.SitePool.init(testing.allocator, .{
        .factory = hub.factory(),
        .keepalive_interval_ms = 0,
    }, .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    {
        var lease = try pool.checkout(io, &cancel, &diag, .transfer);
        defer lease.release(io);
        lease.markBroken();
    }
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), hub.openConns());
}

test {
    std.testing.refAllDecls(@This());
}

//! site_pool — SitePool: per-site connection ownership. One dedicated
//! BROWSE connection (listings/metadata stay snappy during transfers) plus
//! up to `max_transfer_conns` transfer connections, all created lazily on
//! first checkout through a `ConnFactory` that runs the full connect
//! sequence (dial, TLS, auth) via the protocol engines. Credential
//! fetching stays behind `CredProvider` so cred-store wiring lives in the
//! app layer.
//!
//! Failure policy:
//! - A lease released as broken is torn down, never reused.
//! - A dropped idle connection is replaced silently (transcript line only).
//! - `breaker_threshold` consecutive connect failures open a circuit
//!   breaker (site_status event) with exponential backoff; the first
//!   attempt after the backoff elapses is the half-open probe.
//!
//! `disconnect` cancels the site-wide CancelToken and the keepalive
//! worker's Io.Group, joins it, and closes every connection.
//!
//! The pool must be pinned (its mutex/condvar/slots are referenced by
//! leases and the keepalive worker).

const std = @import("std");
const vfs = @import("../vfs/vfs.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const diag_mod = @import("../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const events_mod = @import("../events.zig");
const transcript_mod = @import("../log/transcript.zig");
const sites = @import("../settings/sites.zig");
const lease_mod = @import("lease.zig");
const keepalive = @import("keepalive.zig");
const ftp_client = @import("../proto/ftp/client.zig");
const sftp_mod = @import("../proto/sftp/sftp.zig");

const Allocator = std.mem.Allocator;

pub const Lease = lease_mod.Lease;

/// Hard cap on transfer connections per site (UI slider range).
pub const max_transfer_cap = 32;

pub const Role = enum { browse, transfer };

/// Protocol engine behind a pooled connection; Vfs backends downcast per
/// the site's protocol. `.mock` carries no engine (pool tests).
pub const Engine = union(enum) {
    mock,
    ftp: *ftp_client.FtpClient,
    sftp: *sftp_mod.SftpClient,
};

/// One pooled connection as the pool sees it. The factory owns everything
/// behind `ctx` (sockets, buffers, the engine) and frees it in `close`.
pub const Conn = struct {
    engine: Engine,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Protocol keepalive (FTP NOOP / SFTP channel ping).
        noop: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!void,
        /// Cheap liveness hint consulted at checkout; false forces silent
        /// replacement. Engines without a cheap probe return true and rely
        /// on keepalive to discover drops.
        alive: *const fn (ctx: *anyopaque) bool,
        /// Full teardown: best-effort protocol goodbye, close the socket,
        /// free the engine. Must be safe on dead connections.
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };

    pub fn noop(c: Conn, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!void {
        return c.vtable.noop(c.ctx, io, cancel, diag);
    }
    pub fn alive(c: Conn) bool {
        return c.vtable.alive(c.ctx);
    }
    pub fn close(c: Conn, io: std.Io) void {
        c.vtable.close(c.ctx, io);
    }
};

pub const Credentials = struct {
    user: []const u8 = "",
    /// Password or key passphrase; never stored in the pool or site list.
    secret: []const u8 = "",
};

/// Credential fetch seam: the app layer backs this with the CredStore
/// (Keychain); tests with a counter. Called from connection workers.
pub const CredProvider = struct {
    ctx: *anyopaque,
    fetchFn: *const fn (ctx: *anyopaque, diag: *Diagnostics) vfs.Error!Credentials,

    pub fn fetch(p: CredProvider, diag: *Diagnostics) vfs.Error!Credentials {
        return p.fetchFn(p.ctx, diag);
    }
};

/// Runs the full connect sequence for one connection and classifies
/// failures into `diag`. Production factories dial TCP, stack TLS, and
/// authenticate via the engines; tests script it.
pub const ConnFactory = struct {
    ctx: *anyopaque,
    connectFn: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        site: *const SiteConfig,
        role: Role,
    ) vfs.Error!Conn,

    pub fn connect(
        f: ConnFactory,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        site: *const SiteConfig,
        role: Role,
    ) vfs.Error!Conn {
        return f.connectFn(f.ctx, io, cancel, diag, site, role);
    }
};

pub const SiteConfig = struct {
    site_id: u64 = 0,
    protocol: sites.Protocol = .ftp,
    host: []const u8 = "",
    /// 0 = protocol default.
    port: u16 = 0,
    creds: ?CredProvider = null,
    factory: ConnFactory,
    /// Clamped to `max_transfer_cap`.
    max_transfer_conns: usize = 4,
    /// 0 disables the keepalive worker (tests drive sweeps manually).
    keepalive_interval_ms: u64 = 30_000,
    /// Idle transfer connections older than this are reaped; 0 disables.
    idle_timeout_ms: u64 = 120_000,
    breaker_threshold: u32 = 3,
    connect_backoff_initial_ms: u64 = 1_000,
    connect_backoff_max_ms: u64 = 60_000,
};

/// Optional integration points; both null in most unit tests.
pub const Hooks = struct {
    events: ?*events_mod.EventQueue = null,
    transcript: ?*transcript_mod.Transcript = null,
};

pub const Slot = struct {
    state: State = .empty,
    conn: Conn = undefined,
    /// Awake-clock nanoseconds of the last release/keepalive touch.
    last_used_ns: i96 = 0,

    pub const State = enum {
        empty,
        /// A checkout is running the connect sequence (lock dropped).
        connecting,
        idle,
        leased,
        /// Keepalive is NOOPing it (lock dropped); unavailable to checkout.
        pinned,
    };
};

pub const SitePool = struct {
    gpa: Allocator,
    config: SiteConfig,
    hooks: Hooks,

    mutex: std.Io.Mutex = .init,
    /// Signaled whenever a slot can change hands (release, connect
    /// failure, keepalive re-idle, shutdown).
    cond: std.Io.Condition = .init,
    /// Site-wide cancellation; `disconnect` fires it.
    cancel_token: CancelToken = .{},
    /// Owns the keepalive worker.
    group: std.Io.Group = .init,
    keepalive_started: bool = false,
    shutdown: bool = false,

    browse: Slot = .{},
    transfers: [max_transfer_cap]Slot = @splat(.{}),

    consecutive_failures: u32 = 0,
    breaker_open: bool = false,
    /// Awake-clock deadline before which connects fast-fail while open.
    retry_at_ns: i96 = 0,
    backoff_ms: u64 = 0,
    site_online: bool = false,

    pub fn init(gpa: Allocator, config: SiteConfig, hooks: Hooks) SitePool {
        return .{ .gpa = gpa, .config = config, .hooks = hooks };
    }

    /// Cancels and joins everything, then closes any leftover connections.
    /// Outstanding leases must have been released.
    pub fn deinit(pool: *SitePool, io: std.Io) void {
        if (!pool.shutdown) pool.disconnect(io);
        std.debug.assert(pool.browse.state != .leased);
        for (&pool.transfers) |*slot| std.debug.assert(slot.state != .leased);
        pool.* = undefined;
    }

    fn maxConns(pool: *const SitePool) usize {
        return @max(1, @min(pool.config.max_transfer_conns, max_transfer_cap));
    }

    // ------------------------------------------------------------------ //
    // Checkout / release

    /// Checks out a connection lease. Browse is dedicated and exclusive:
    /// concurrent browse checkouts queue. Transfer checkouts queue once
    /// all `max_transfer_conns` slots are leased. Always release via
    /// `Lease.release` (defer discipline; see lease.zig).
    pub fn checkout(
        pool: *SitePool,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        role: Role,
    ) vfs.Error!Lease {
        pool.mutex.lockUncancelable(io);
        var locked = true;
        defer if (locked) pool.mutex.unlock(io);

        while (true) {
            if (pool.shutdown) {
                diag.set(.permanent, 0, "site is disconnected", .{});
                return error.ConnectionLost;
            }
            cancel.check() catch {
                diag.set(.cancel, 0, "canceled waiting for a connection", .{});
                return error.Canceled;
            };

            if (pool.takeIdleLocked(io, role)) |slot| {
                return .{ .pool = pool, .slot = slot, .conn = slot.conn, .role = role };
            }
            if (pool.emptySlotLocked(role)) |slot| {
                return pool.connectSlot(io, cancel, diag, slot, role, &locked);
            }
            pool.cond.wait(io, &pool.mutex) catch {
                diag.set(.cancel, 0, "canceled waiting for a connection", .{});
                return error.Canceled;
            };
        }
    }

    /// First idle, live slot for `role`; dead idles are torn down here —
    /// the transparent-reconnect path (transcript line only).
    fn takeIdleLocked(pool: *SitePool, io: std.Io, role: Role) ?*Slot {
        switch (role) {
            .browse => {
                const slot = &pool.browse;
                if (slot.state != .idle) return null;
                if (!slot.conn.alive()) {
                    pool.retireDeadIdleLocked(io, slot);
                    return null;
                }
                slot.state = .leased;
                return slot;
            },
            .transfer => {
                for (pool.transfers[0..pool.maxConns()]) |*slot| {
                    if (slot.state != .idle) continue;
                    if (!slot.conn.alive()) {
                        pool.retireDeadIdleLocked(io, slot);
                        continue;
                    }
                    slot.state = .leased;
                    return slot;
                }
                return null;
            },
        }
    }

    fn retireDeadIdleLocked(pool: *SitePool, io: std.Io, slot: *Slot) void {
        const conn = slot.conn;
        slot.state = .empty;
        pool.note("idle connection dropped; reconnecting silently", .{});
        // Closing a dead connection fails fast; acceptable under the lock.
        conn.close(io);
    }

    fn emptySlotLocked(pool: *SitePool, role: Role) ?*Slot {
        switch (role) {
            .browse => return if (pool.browse.state == .empty) &pool.browse else null,
            .transfer => {
                for (pool.transfers[0..pool.maxConns()]) |*slot| {
                    if (slot.state == .empty) return slot;
                }
                return null;
            },
        }
    }

    /// Runs the (slow) connect sequence with the pool unlocked; the slot is
    /// parked in `.connecting` so nobody else claims it. `locked` tracks
    /// the mutex for the caller's defer.
    fn connectSlot(
        pool: *SitePool,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        slot: *Slot,
        role: Role,
        locked: *bool,
    ) vfs.Error!Lease {
        if (pool.breaker_open) {
            const now = nowNs(io);
            if (now < pool.retry_at_ns) {
                const wait_ms = @divTrunc(pool.retry_at_ns - now, std.time.ns_per_ms);
                diag.set(.transient, 0, "circuit breaker open after {d} consecutive connect failures; retry in {d} ms", .{
                    pool.consecutive_failures, wait_ms,
                });
                return error.ConnectionLost;
            }
            // Backoff elapsed: this attempt is the half-open probe.
        }
        slot.state = .connecting;
        pool.mutex.unlock(io);
        locked.* = false;

        const conn = pool.config.factory.connect(io, cancel, diag, &pool.config, role) catch |err| {
            pool.mutex.lockUncancelable(io);
            locked.* = true;
            slot.state = .empty;
            // Cancellation says nothing about server health.
            if (err != error.Canceled) pool.noteConnectFailureLocked(io, diag);
            pool.cond.broadcast(io);
            return err;
        };

        pool.mutex.lockUncancelable(io);
        locked.* = true;
        if (pool.shutdown) {
            slot.state = .empty;
            pool.cond.broadcast(io);
            pool.mutex.unlock(io);
            locked.* = false;
            conn.close(io);
            diag.set(.permanent, 0, "site is disconnected", .{});
            return error.ConnectionLost;
        }
        pool.noteConnectSuccessLocked();
        slot.state = .leased;
        slot.conn = conn;
        pool.maybeStartKeepaliveLocked(io);
        return .{ .pool = pool, .slot = slot, .conn = conn, .role = role };
    }

    /// Called by Lease.release. Healthy leases go back to idle; broken
    /// leases (or releases after shutdown) tear the connection down.
    pub fn releaseLease(pool: *SitePool, slot: *Slot, broken: bool, io: std.Io) void {
        pool.mutex.lockUncancelable(io);
        std.debug.assert(slot.state == .leased);
        var to_close: ?Conn = null;
        if (broken or pool.shutdown) {
            to_close = slot.conn;
            slot.state = .empty;
            if (broken) pool.note("connection retired after error (lease returned broken)", .{});
        } else {
            slot.state = .idle;
            slot.last_used_ns = nowNs(io);
        }
        pool.cond.broadcast(io);
        pool.mutex.unlock(io);
        if (to_close) |conn| conn.close(io);
    }

    // ------------------------------------------------------------------ //
    // Connect failure accounting / circuit breaker

    fn noteConnectFailureLocked(pool: *SitePool, io: std.Io, diag: *const Diagnostics) void {
        pool.consecutive_failures += 1;
        if (pool.consecutive_failures < pool.config.breaker_threshold) return;
        pool.backoff_ms = if (pool.backoff_ms == 0)
            pool.config.connect_backoff_initial_ms
        else
            @min(pool.backoff_ms * 2, pool.config.connect_backoff_max_ms);
        pool.retry_at_ns = nowNs(io) + @as(i96, @intCast(pool.backoff_ms)) * std.time.ns_per_ms;
        if (!pool.breaker_open) {
            pool.breaker_open = true;
            pool.site_online = false;
            pool.postStatus(.offline, diag.message, diag.class);
            pool.note("circuit breaker open after {d} consecutive connect failures", .{
                pool.consecutive_failures,
            });
        }
    }

    fn noteConnectSuccessLocked(pool: *SitePool) void {
        pool.consecutive_failures = 0;
        pool.backoff_ms = 0;
        if (pool.breaker_open) {
            pool.breaker_open = false;
            pool.note("circuit breaker closed (connect succeeded)", .{});
        }
        if (!pool.site_online) {
            pool.site_online = true;
            pool.postStatus(.connected, "", null);
        }
    }

    // ------------------------------------------------------------------ //
    // Lifecycle

    fn maybeStartKeepaliveLocked(pool: *SitePool, io: std.Io) void {
        if (pool.keepalive_started or pool.config.keepalive_interval_ms == 0) return;
        // concurrent (not async): an async fallback could run the loop
        // inline on resource exhaustion and never return.
        pool.group.concurrent(io, keepalive.run, .{ pool, io }) catch return;
        pool.keepalive_started = true;
    }

    /// Cancels the site token and the keepalive worker, joins it, closes
    /// every idle connection, and marks the pool shut down. Outstanding
    /// leases tear their connections down on release.
    pub fn disconnect(pool: *SitePool, io: std.Io) void {
        pool.cancel_token.cancel();
        pool.group.cancel(io);

        var to_close: [1 + max_transfer_cap]Conn = undefined;
        var n: usize = 0;
        pool.mutex.lockUncancelable(io);
        if (pool.shutdown) {
            pool.mutex.unlock(io);
            return;
        }
        pool.shutdown = true;
        pool.site_online = false;
        if (pool.browse.state == .idle) {
            to_close[n] = pool.browse.conn;
            n += 1;
            pool.browse.state = .empty;
        }
        for (&pool.transfers) |*slot| {
            if (slot.state == .idle) {
                to_close[n] = slot.conn;
                n += 1;
                slot.state = .empty;
            }
        }
        pool.cond.broadcast(io);
        pool.mutex.unlock(io);

        for (to_close[0..n]) |conn| conn.close(io);
        // Clean user-initiated disconnect: a reason for the transcript, but
        // null error_class so the UI does not surface it as an error.
        pool.postStatus(.offline, "disconnected", null);
    }

    // ------------------------------------------------------------------ //
    // Hook plumbing

    /// `error_class` is the unambiguous failure signal: non-null only when
    /// `status` reflects a real failure (breaker trip). A clean disconnect
    /// posts .offline with a reason but a null class.
    fn postStatus(
        pool: *SitePool,
        status: events_mod.SiteStatus,
        reason: []const u8,
        error_class: ?diag_mod.ErrorClass,
    ) void {
        const queue = pool.hooks.events orelse return;
        _ = queue.post(.{ .site_status = .{
            .site_id = pool.config.site_id,
            .status = status,
            .reason = reason,
            .error_class = error_class,
        } }) catch {};
    }

    /// Transcript-only note (the "silent" channel for reconnects/reaps).
    pub fn note(pool: *SitePool, comptime fmt: []const u8, args: anytype) void {
        const transcript = pool.hooks.transcript orelse return;
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, fmt, args) catch &buf;
        transcript.append(.info, false, line);
    }
};

pub fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.now(.awake, io).nanoseconds;
}

// ---------------------------------------------------------------------------
// MockConn seam (test factory; also used by lease.zig / keepalive.zig tests)
// ---------------------------------------------------------------------------

/// Scriptable in-memory connection factory: counts connects/noops/closes
/// and injects failures. Only referenced from tests.
pub const MockHub = struct {
    gpa: Allocator,
    connects: std.atomic.Value(usize) = .init(0),
    browse_connects: std.atomic.Value(usize) = .init(0),
    transfer_connects: std.atomic.Value(usize) = .init(0),
    noops: std.atomic.Value(usize) = .init(0),
    closes: std.atomic.Value(usize) = .init(0),
    cred_fetches: std.atomic.Value(usize) = .init(0),
    /// Each pending unit fails one connect / noop, then auto-clears.
    fail_next_connects: std.atomic.Value(usize) = .init(0),
    fail_next_noops: std.atomic.Value(usize) = .init(0),
    failed_connects: std.atomic.Value(usize) = .init(0),
    connect_delay_ms: u64 = 0,

    pub fn init(gpa: Allocator) MockHub {
        return .{ .gpa = gpa };
    }

    pub fn factory(h: *MockHub) ConnFactory {
        return .{ .ctx = h, .connectFn = connect };
    }

    pub fn credProvider(h: *MockHub) CredProvider {
        return .{ .ctx = h, .fetchFn = fetchCreds };
    }

    /// Successful connects minus closes; 0 when everything was torn down.
    pub fn openConns(h: *MockHub) usize {
        const ok = h.connects.load(.monotonic) - h.failed_connects.load(.monotonic);
        return ok - h.closes.load(.monotonic);
    }

    fn fetchCreds(ctx: *anyopaque, diag: *Diagnostics) vfs.Error!Credentials {
        _ = diag;
        const h: *MockHub = @ptrCast(@alignCast(ctx));
        _ = h.cred_fetches.fetchAdd(1, .monotonic);
        return .{ .user = "alice", .secret = "hunter2" };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        site: *const SiteConfig,
        role: Role,
    ) vfs.Error!Conn {
        const h: *MockHub = @ptrCast(@alignCast(ctx));
        _ = h.connects.fetchAdd(1, .monotonic);
        switch (role) {
            .browse => _ = h.browse_connects.fetchAdd(1, .monotonic),
            .transfer => _ = h.transfer_connects.fetchAdd(1, .monotonic),
        }
        if (site.creds) |provider| _ = try provider.fetch(diag);
        if (h.connect_delay_ms != 0) {
            io.sleep(.fromMilliseconds(@intCast(h.connect_delay_ms)), .awake) catch {};
        }
        cancel.check() catch {
            _ = h.failed_connects.fetchAdd(1, .monotonic);
            diag.set(.cancel, 0, "mock connect canceled", .{});
            return error.Canceled;
        };
        if (takeOne(&h.fail_next_connects)) {
            _ = h.failed_connects.fetchAdd(1, .monotonic);
            diag.set(.transient, 0, "mock connect failure (scripted)", .{});
            return error.ConnectionLost;
        }
        const mc = h.gpa.create(MockConn) catch {
            _ = h.failed_connects.fetchAdd(1, .monotonic);
            return error.OutOfMemory;
        };
        mc.* = .{ .hub = h };
        return .{ .engine = .mock, .ctx = mc, .vtable = &mock_vtable };
    }

    const mock_vtable: Conn.VTable = .{
        .noop = mockNoop,
        .alive = mockAlive,
        .close = mockClose,
    };

    fn mockNoop(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!void {
        _ = io;
        const mc: *MockConn = @ptrCast(@alignCast(ctx));
        _ = mc.hub.noops.fetchAdd(1, .monotonic);
        cancel.check() catch {
            diag.set(.cancel, 0, "mock noop canceled", .{});
            return error.Canceled;
        };
        if (takeOne(&mc.hub.fail_next_noops)) {
            diag.set(.transient, 0, "mock noop failure (scripted)", .{});
            return error.ConnectionLost;
        }
        _ = mc.noops.fetchAdd(1, .monotonic);
    }

    fn mockAlive(ctx: *anyopaque) bool {
        const mc: *MockConn = @ptrCast(@alignCast(ctx));
        return mc.alive_flag.load(.acquire);
    }

    fn mockClose(ctx: *anyopaque, io: std.Io) void {
        _ = io;
        const mc: *MockConn = @ptrCast(@alignCast(ctx));
        const h = mc.hub;
        std.debug.assert(!mc.closed.swap(true, .acq_rel)); // double close
        _ = h.closes.fetchAdd(1, .monotonic);
        h.gpa.destroy(mc);
    }

    fn takeOne(v: *std.atomic.Value(usize)) bool {
        var cur = v.load(.monotonic);
        while (cur != 0) {
            cur = v.cmpxchgWeak(cur, cur - 1, .monotonic, .monotonic) orelse return true;
        }
        return false;
    }
};

pub const MockConn = struct {
    hub: *MockHub,
    alive_flag: std.atomic.Value(bool) = .init(true),
    noops: std.atomic.Value(usize) = .init(0),
    closed: std.atomic.Value(bool) = .init(false),

    pub fn fromConn(conn: Conn) *MockConn {
        std.debug.assert(conn.engine == .mock);
        return @ptrCast(@alignCast(conn.ctx));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testConfig(hub: *MockHub) SiteConfig {
    return .{
        .site_id = 42,
        .protocol = .ftp,
        .host = "test.example",
        .creds = hub.credProvider(),
        .factory = hub.factory(),
        .max_transfer_conns = 2,
        .keepalive_interval_ms = 0, // tests drive keepalive manually
        .breaker_threshold = 3,
        .connect_backoff_initial_ms = 5,
        .connect_backoff_max_ms = 40,
    };
}

test "lazy connect on first checkout; idle conns are reused" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    try testing.expectEqual(@as(usize, 0), hub.connects.load(.monotonic));

    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    try testing.expectEqual(@as(usize, 1), hub.connects.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), hub.cred_fetches.load(.monotonic));
    try testing.expect(lease.conn.engine == .mock);
    lease.release(io);

    // Reuse: no second connect.
    var lease2 = try pool.checkout(io, &cancel, &diag, .browse);
    defer lease2.release(io);
    try testing.expectEqual(@as(usize, 1), hub.connects.load(.monotonic));
}

test "browse and transfer connections are isolated" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var browse = try pool.checkout(io, &cancel, &diag, .browse);
    defer browse.release(io);
    // With the browse lease held, transfers still flow.
    var t1 = try pool.checkout(io, &cancel, &diag, .transfer);
    defer t1.release(io);
    var t2 = try pool.checkout(io, &cancel, &diag, .transfer);
    defer t2.release(io);

    try testing.expectEqual(@as(usize, 1), hub.browse_connects.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), hub.transfer_connects.load(.monotonic));
    try testing.expect(MockConn.fromConn(browse.conn) != MockConn.fromConn(t1.conn));
    try testing.expect(MockConn.fromConn(t1.conn) != MockConn.fromConn(t2.conn));
}

test "checkout under contention respects max_transfer_conns" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    const Worker = struct {
        const iterations = 25;

        fn run(p: *SitePool, worker_io: std.Io, in_flight: *std.atomic.Value(usize), peak: *std.atomic.Value(usize)) void {
            var cancel: CancelToken = .{};
            var diag: Diagnostics = .{};
            for (0..iterations) |_| {
                var lease = p.checkout(worker_io, &cancel, &diag, .transfer) catch unreachable;
                const cur = in_flight.fetchAdd(1, .acq_rel) + 1;
                var seen = peak.load(.monotonic);
                while (cur > seen) {
                    seen = peak.cmpxchgWeak(seen, cur, .monotonic, .monotonic) orelse break;
                }
                std.Thread.yield() catch {};
                _ = in_flight.fetchSub(1, .acq_rel);
                lease.release(worker_io);
            }
        }
    };

    var in_flight: std.atomic.Value(usize) = .init(0);
    var peak: std.atomic.Value(usize) = .init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &pool, io, &in_flight, &peak });
    }
    for (&threads) |*t| t.join();

    // Never more conns than the cap, never more leases in flight either.
    try testing.expect(peak.load(.monotonic) <= 2);
    try testing.expect(hub.transfer_connects.load(.monotonic) <= 2);
    try testing.expectEqual(@as(usize, 0), in_flight.load(.monotonic));
}

test "dropped idle conn is replaced transparently with a transcript line" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var transcript = try transcript_mod.Transcript.init(testing.allocator, .{ .capacity = 64, .max_line_bytes = 128 });
    defer transcript.deinit();
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{ .transcript = &transcript });
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    const first = MockConn.fromConn(lease.conn);
    lease.release(io);

    // The idle conn dies behind our back.
    first.alive_flag.store(false, .release);

    var lease2 = try pool.checkout(io, &cancel, &diag, .browse);
    defer lease2.release(io);
    try testing.expectEqual(@as(usize, 2), hub.connects.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));

    var snap = try transcript.snapshot(testing.allocator);
    defer snap.deinit(testing.allocator);
    var saw_note = false;
    for (snap.lines) |line| {
        if (std.mem.indexOf(u8, line.text, "reconnecting silently") != null) saw_note = true;
    }
    try testing.expect(saw_note);
}

test "broken lease is torn down, not reused" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var lease = try pool.checkout(io, &cancel, &diag, .transfer);
    lease.markBroken();
    lease.release(io);
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));

    var lease2 = try pool.checkout(io, &cancel, &diag, .transfer);
    defer lease2.release(io);
    try testing.expectEqual(@as(usize, 2), hub.connects.load(.monotonic));
}

test "circuit breaker: trips after 3 failures, fast-fails, recovers after backoff" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var queue = events_mod.EventQueue.init(testing.allocator);
    defer queue.deinit();
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{ .events = &queue });
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    hub.fail_next_connects.store(3, .monotonic);
    for (0..3) |_| {
        try testing.expectError(error.ConnectionLost, pool.checkout(io, &cancel, &diag, .browse));
        try testing.expectEqual(diag_mod.ErrorClass.transient, diag.class);
    }
    try testing.expect(pool.breaker_open);
    try testing.expectEqual(@as(usize, 3), hub.connects.load(.monotonic));

    // Fast-fail without touching the factory while the breaker is open.
    try testing.expectError(error.ConnectionLost, pool.checkout(io, &cancel, &diag, .browse));
    try testing.expectEqual(@as(usize, 3), hub.connects.load(.monotonic));
    try testing.expect(std.mem.indexOf(u8, diag.message, "circuit breaker open") != null);

    const batch = queue.drain();
    try testing.expectEqual(@as(usize, 1), batch.len);
    try testing.expectEqual(events_mod.SiteStatus.offline, batch[0].site_status.status);
    try testing.expectEqual(@as(u64, 42), batch[0].site_status.site_id);
    // Breaker trip is a real failure: it must carry a classified cause.
    try testing.expect(batch[0].site_status.error_class != null);
    try testing.expectEqual(diag_mod.ErrorClass.transient, batch[0].site_status.error_class.?);

    // After the backoff elapses the half-open probe goes through and the
    // breaker closes.
    io.sleep(.fromMilliseconds(10), .awake) catch {};
    var lease = try pool.checkout(io, &cancel, &diag, .browse);
    defer lease.release(io);
    try testing.expect(!pool.breaker_open);
    try testing.expectEqual(@as(usize, 4), hub.connects.load(.monotonic));

    const batch2 = queue.drain();
    try testing.expectEqual(@as(usize, 1), batch2.len);
    try testing.expectEqual(events_mod.SiteStatus.connected, batch2[0].site_status.status);
}

test "circuit breaker: failed half-open probe doubles the backoff" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    hub.fail_next_connects.store(4, .monotonic);
    for (0..3) |_| {
        try testing.expectError(error.ConnectionLost, pool.checkout(io, &cancel, &diag, .browse));
    }
    try testing.expectEqual(@as(u64, 5), pool.backoff_ms);
    io.sleep(.fromMilliseconds(10), .awake) catch {};
    // Half-open probe fails (4th scripted failure): backoff doubles.
    try testing.expectError(error.ConnectionLost, pool.checkout(io, &cancel, &diag, .browse));
    try testing.expectEqual(@as(usize, 4), hub.connects.load(.monotonic));
    try testing.expectEqual(@as(u64, 10), pool.backoff_ms);
    try testing.expect(pool.breaker_open);
}

test "disconnect closes idle conns and fails subsequent checkouts" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var browse = try pool.checkout(io, &cancel, &diag, .browse);
    browse.release(io);
    var transfer = try pool.checkout(io, &cancel, &diag, .transfer);

    pool.disconnect(io);
    // Idle browse conn closed by disconnect; the leased transfer conn is
    // closed when its lease comes back.
    try testing.expectEqual(@as(usize, 1), hub.closes.load(.monotonic));
    try testing.expect(pool.cancel_token.isCanceled());
    transfer.release(io);
    try testing.expectEqual(@as(usize, 2), hub.closes.load(.monotonic));

    try testing.expectError(error.ConnectionLost, pool.checkout(io, &cancel, &diag, .browse));
    try testing.expectEqual(@as(usize, 0), hub.openConns());
    pool.deinit(io);
}

test "checkout honors an already-canceled token" {
    const io = testing.io;
    var hub = MockHub.init(testing.allocator);
    var pool = SitePool.init(testing.allocator, testConfig(&hub), .{});
    defer pool.deinit(io);

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    cancel.cancel();
    try testing.expectError(error.Canceled, pool.checkout(io, &cancel, &diag, .transfer));
    try testing.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
    try testing.expectEqual(@as(usize, 0), hub.connects.load(.monotonic));
}

test {
    std.testing.refAllDecls(@This());
}

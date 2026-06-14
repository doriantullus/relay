//! poll — the EAGAIN driver for non-blocking libssh2.
//!
//! Every libssh2 call in the SFTP engine runs through `pump`/`pumpHandle`:
//! when the call returns LIBSSH2_ERROR_EAGAIN, poll(2) the session socket
//! for the directions libssh2 reports it is blocked on, waking at least
//! every 100 ms to check the `CancelToken`, then retry the call. This is
//! what turns blocking C-library waits into the ≤100 ms cancellation
//! latency the UI promises.
//!
//! The pump is generic over an `op` value (see `pump`) rather than over
//! libssh2 types so the retry/cancel/poll logic unit-tests against stub
//! ops without a server.

const std = @import("std");
const CancelToken = @import("../../cancel.zig").CancelToken;

/// LIBSSH2_ERROR_EAGAIN. Mirrored as a plain constant (asserted against
/// the real header below) so stub ops and tests never need libssh2.
pub const eagain = -37;
/// LIBSSH2_SESSION_BLOCK_INBOUND / LIBSSH2_SESSION_BLOCK_OUTBOUND.
pub const block_inbound: c_int = 0x0001;
pub const block_outbound: c_int = 0x0002;

comptime {
    const c = @import("c");
    std.debug.assert(c.LIBSSH2_ERROR_EAGAIN == eagain);
    std.debug.assert(c.LIBSSH2_SESSION_BLOCK_INBOUND == block_inbound);
    std.debug.assert(c.LIBSSH2_SESSION_BLOCK_OUTBOUND == block_outbound);
}

/// Upper bound on one poll(2) wait. The cancellation contract (cancel.zig)
/// requires a wakeup at least this often.
pub const poll_interval_ms = 100;

pub const Error = error{
    Canceled,
    /// poll(2) itself failed on the session socket — the fd is dead.
    ConnectionLost,
};

/// Drives one libssh2 call to completion. `op` is any value with:
///
///   fn call(op) Rc          — performs the libssh2 call; Rc is a signed
///                             integer type (c_int rcs, isize byte counts)
///   fn directions(op) c_int — libssh2_session_block_directions() bitmask
///
/// Returns the first rc that is not LIBSSH2_ERROR_EAGAIN; the caller maps
/// it. Cancellation is checked before the first call and on every poll
/// wakeup (≤100 ms apart).
pub fn pump(
    fd: std.posix.fd_t,
    cancel: *const CancelToken,
    op: anytype,
) Error!@TypeOf(op.call()) {
    while (true) {
        try cancel.check();
        const rc = op.call();
        if (rc != eagain) return rc;
        try waitSocket(fd, op.directions(), cancel);
    }
}

/// `pump` for libssh2 calls that signal EAGAIN by returning a null handle
/// (`libssh2_sftp_init`, `libssh2_sftp_open_ex`, `libssh2_userauth_list`).
/// `op` additionally needs `fn lastErrno(op) c_int`. Returns null when the
/// call failed for a real (non-EAGAIN) reason; the caller maps last_errno.
pub fn pumpHandle(
    fd: std.posix.fd_t,
    cancel: *const CancelToken,
    op: anytype,
) Error!@TypeOf(op.call()) {
    while (true) {
        try cancel.check();
        if (op.call()) |handle| return handle;
        if (op.lastErrno() != eagain) return null;
        try waitSocket(fd, op.directions(), cancel);
    }
}

/// Best-effort variant for teardown paths (disconnect, session free):
/// gives up after `max_polls` poll wakeups (~`max_polls` × 100 ms) and
/// returns the EAGAIN rc as-is so the caller can abandon the operation
/// instead of blocking shutdown.
pub fn pumpBounded(
    fd: std.posix.fd_t,
    cancel: *const CancelToken,
    op: anytype,
    max_polls: usize,
) Error!@TypeOf(op.call()) {
    var polls: usize = 0;
    while (true) {
        try cancel.check();
        const rc = op.call();
        if (rc != eagain) return rc;
        if (polls == max_polls) return rc;
        polls += 1;
        try waitSocket(fd, op.directions(), cancel);
    }
}

/// Map libssh2 block directions to poll(2) events. Defensive: EAGAIN with no
/// reported direction (never observed) polls for readability so callers' loops
/// stay cancelable, not hot.
pub fn directionsToPollEvents(directions: c_int) i16 {
    var events: i16 = 0;
    if (directions & block_inbound != 0) events |= std.posix.POLL.IN;
    if (directions & block_outbound != 0) events |= std.posix.POLL.OUT;
    return if (events == 0) std.posix.POLL.IN else events;
}

/// One bounded poll(2) on the session socket. Timeouts are not errors —
/// the caller simply retries the libssh2 call (which re-yields EAGAIN);
/// error/hangup revents are also left for libssh2 to read and classify.
pub fn waitSocket(
    fd: std.posix.fd_t,
    directions: c_int,
    cancel: *const CancelToken,
) Error!void {
    const events = directionsToPollEvents(directions);
    var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    _ = std.posix.poll(&fds, poll_interval_ms) catch return error.ConnectionLost;
    try cancel.check();
}

// ---------------------------------------------------------------------------
// Tests (stub ops + real OS pipes; no libssh2 session involved)
// ---------------------------------------------------------------------------

const t = std.testing;

const StubOp = struct {
    /// rcs returned by successive call()s; the last one repeats.
    script: []const isize,
    calls: usize = 0,
    dirs: c_int = block_inbound,
    /// When set, cancels the token after this many calls.
    cancel_after: ?usize = null,
    token: ?*CancelToken = null,

    fn call(op: *StubOp) isize {
        const i = @min(op.calls, op.script.len - 1);
        op.calls += 1;
        if (op.cancel_after) |n| if (op.calls >= n) op.token.?.cancel();
        return op.script[i];
    }

    fn directions(op: *StubOp) c_int {
        return op.dirs;
    }
};

const TestPipe = struct {
    fds: [2]std.posix.fd_t,

    fn init() !TestPipe {
        return .{ .fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true }) };
    }

    fn deinit(p: *TestPipe) void {
        for (p.fds) |fd| {
            const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
            file.close(std.testing.io);
        }
    }
};

test "pump returns the first non-EAGAIN rc" {
    var p = try TestPipe.init();
    defer p.deinit();
    var token: CancelToken = .{};

    // Write side of a fresh pipe is always poll-ready, so the EAGAIN
    // retries spin through poll without waiting out the timeout.
    var op: StubOp = .{ .script = &.{ eagain, eagain, 7 }, .dirs = block_outbound };
    try t.expectEqual(@as(isize, 7), try pump(p.fds[1], &token, &op));
    try t.expectEqual(@as(usize, 3), op.calls);
}

test "pump returns success immediately without polling a dead fd" {
    var token: CancelToken = .{};
    var op: StubOp = .{ .script = &.{0} };
    // fd is never polled when the first call succeeds; -1 would fail.
    try t.expectEqual(@as(isize, 0), try pump(-1, &token, &op));
    try t.expectEqual(@as(usize, 1), op.calls);
}

test "pre-canceled token aborts before the eagainable call" {
    var token: CancelToken = .{};
    token.cancel();
    var op: StubOp = .{ .script = &.{0} };
    try t.expectError(error.Canceled, pump(-1, &token, &op));
    try t.expectEqual(@as(usize, 0), op.calls);
}

test "cancel mid-pump resolves within the 150ms budget" {
    const io = std.testing.io;
    var p = try TestPipe.init();
    defer p.deinit();
    var token: CancelToken = .{};

    // Read end with no data: every wakeup is a full 100 ms poll timeout.
    // The op cancels the token during its first call, so pump must return
    // Canceled on the wakeup that follows — one poll interval after the
    // cancellation, well inside the ~100 ms worst-case contract.
    var op: StubOp = .{
        .script = &.{eagain},
        .cancel_after = 1,
        .token = &token,
    };
    const t0: std.Io.Clock.Timestamp = .now(io, .awake);
    try t.expectError(error.Canceled, pump(p.fds[0], &token, &op));
    const elapsed_ms = @divTrunc(
        t0.durationTo(.now(io, .awake)).raw.nanoseconds,
        std.time.ns_per_ms,
    );
    try t.expectEqual(@as(usize, 1), op.calls);
    try t.expect(elapsed_ms < 150);
}

test "pumpBounded gives up with the EAGAIN rc after its poll budget" {
    var p = try TestPipe.init();
    defer p.deinit();
    var token: CancelToken = .{};

    var op: StubOp = .{ .script = &.{eagain}, .dirs = block_outbound };
    try t.expectEqual(@as(isize, eagain), try pumpBounded(p.fds[1], &token, &op, 3));
    // initial call + one retry per allowed poll
    try t.expectEqual(@as(usize, 4), op.calls);
}

const StubHandleOp = struct {
    /// null entries simulate EAGAIN (lastErrno() == eagain); the sentinel
    /// usize value renders as a real failure (lastErrno() != eagain).
    script: []const ?usize,
    calls: usize = 0,
    errno: c_int = eagain,
    value: usize = 0,

    fn call(op: *StubHandleOp) ?*const usize {
        const i = @min(op.calls, op.script.len - 1);
        op.calls += 1;
        if (op.script[i]) |v| {
            op.value = v;
            return &op.value;
        }
        return null;
    }

    fn directions(op: *StubHandleOp) c_int {
        _ = op;
        return block_outbound;
    }

    fn lastErrno(op: *StubHandleOp) c_int {
        return op.errno;
    }
};

test "pumpHandle retries EAGAIN nulls and returns the handle" {
    var p = try TestPipe.init();
    defer p.deinit();
    var token: CancelToken = .{};

    var op: StubHandleOp = .{ .script = &.{ null, null, 42 } };
    const handle = (try pumpHandle(p.fds[1], &token, &op)).?;
    try t.expectEqual(@as(usize, 42), handle.*);
    try t.expectEqual(@as(usize, 3), op.calls);
}

test "pumpHandle surfaces real failures as null without retrying" {
    var token: CancelToken = .{};
    var op: StubHandleOp = .{ .script = &.{null}, .errno = -7 };
    try t.expectEqual(@as(?*const usize, null), try pumpHandle(-1, &token, &op));
    try t.expectEqual(@as(usize, 1), op.calls);
}

test {
    std.testing.refAllDecls(@This());
}

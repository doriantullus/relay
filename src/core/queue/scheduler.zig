//! scheduler — per-site worker lanes for the transfer queue. Each site gets
//! a lane with as many worker threads as its transfer-connection budget;
//! workers pull the next runnable item in queue order and run it against
//! the Vfs pair, entirely outside the engine lock.
//!
//! Retry matrix (diag.ErrorClass drives everything):
//! - transient → requeue with full-jitter exponential backoff
//!   (base 2 s ×2, cap 60 s), resume from offset when both ends' Caps
//!   allow, fail after max_attempts;
//! - permanent → Failed bucket, never auto-retried (requeueFailed only);
//! - auth → block the whole lane, raise exactly ONE prompt_needed,
//!   resume everything on success;
//! - cancel → terminal, silent.
//!
//! Mid-stream pump failures carry no Diagnostics (std.Io streams have no
//! payload channel), so they classify as transient connection drops — the
//! realistic case — unless the item's CancelToken fired.

const std = @import("std");
const item_mod = @import("item.zig");
const rate_limit = @import("rate_limit.zig");
const engine_mod = @import("engine.zig");
const vfs_mod = @import("../vfs/vfs.zig");
const diag_mod = @import("../diag.zig");
const cancel_mod = @import("../cancel.zig");

const Engine = engine_mod.Engine;
const TransferItem = item_mod.TransferItem;

/// Connection budget source. An interface rather than the real pool so the
/// queue unit-tests against mock_vfs with a fixed budget; the app wires
/// this to pool/site_pool.zig.
pub const Budget = struct {
    context: *anyopaque,
    connsFn: *const fn (context: *anyopaque, site_id: u64) u8,

    pub fn conns(b: Budget, site_id: u64) u8 {
        return b.connsFn(b.context, site_id);
    }
};

/// Same budget for every site; the test/default implementation.
pub const FixedBudget = struct {
    n: u8 = 2,

    pub fn budget(self: *FixedBudget) Budget {
        return .{ .context = self, .connsFn = connsFn };
    }

    fn connsFn(context: *anyopaque, site_id: u64) u8 {
        _ = site_id;
        const self: *FixedBudget = @ptrCast(@alignCast(context));
        return self.n;
    }
};

/// Resolves an endpoint's site id to its Vfs (local backend for
/// item.local_site_id, a pooled protocol backend otherwise).
pub const VfsProvider = struct {
    context: *anyopaque,
    getFn: *const fn (context: *anyopaque, site_id: u64) ?vfs_mod.Vfs,

    pub fn get(p: VfsProvider, site_id: u64) ?vfs_mod.Vfs {
        return p.getFn(p.context, site_id);
    }
};

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    base_ms: u64 = 2_000,
    cap_ms: u64 = 60_000,
};

/// Ceiling of the jitter window: min(cap, base · 2^(attempt−1)).
pub fn backoffCeilingMs(policy: RetryPolicy, attempt: u32) u64 {
    if (policy.base_ms == 0) return 0;
    const exp: u7 = @intCast(@min(attempt -| 1, 30));
    return @intCast(@min(@as(u128, policy.base_ms) << exp, policy.cap_ms));
}

/// Full jitter: uniform in [0, ceiling]. Full (not equal/decorrelated)
/// jitter maximally de-synchronizes the retry stampede after a server blip.
pub fn backoffNs(policy: RetryPolicy, attempt: u32, random: std.Random) u64 {
    const ceil_ms = backoffCeilingMs(policy, attempt);
    if (ceil_ms == 0) return 0;
    return random.intRangeAtMost(u64, 0, ceil_ms) * std.time.ns_per_ms;
}

/// One worker pool per site. Heap-pinned: workers hold the pointer and the
/// condition variable address must be stable.
pub const Lane = struct {
    site_id: u64,
    /// Waited on with the ENGINE mutex (one lock for all queue state).
    cond: std.Io.Condition = .init,
    /// Set on the first auth failure; cleared by resolveAuthPrompt(ok).
    /// While set, workers do not pick — auth storms collapse to one prompt.
    auth_blocked: bool = false,
    prompt_pending: bool = false,
    /// Per-site rate buckets (0 = unlimited until configured).
    up: rate_limit.TokenBucket,
    down: rate_limit.TokenBucket,
    threads: std.ArrayList(std.Thread) = .empty,
};

pub const Scheduler = struct {
    lanes: std.ArrayList(*Lane) = .empty,

    pub fn findLane(self: *Scheduler, site_id: u64) ?*Lane {
        for (self.lanes.items) |lane| {
            if (lane.site_id == site_id) return lane;
        }
        return null;
    }

    /// Engine lock held. Creates the lane and spawns its budgeted workers
    /// on first use of a site.
    pub fn ensureLaneLocked(self: *Scheduler, eng: *Engine, site_id: u64) !*Lane {
        if (self.findLane(site_id)) |lane| return lane;
        const gpa = eng.gpa;

        const lane = try gpa.create(Lane);
        errdefer gpa.destroy(lane);
        lane.* = .{
            .site_id = site_id,
            .up = .init(0, eng.config.rate_burst),
            .down = .init(0, eng.config.rate_burst),
        };
        const want: usize = @max(1, eng.config.budget.conns(site_id));
        try lane.threads.ensureTotalCapacity(gpa, want);
        errdefer lane.threads.deinit(gpa);
        try self.lanes.append(gpa, lane);
        errdefer _ = self.lanes.pop();

        var spawned: usize = 0;
        while (spawned < want) : (spawned += 1) {
            // Capacity is reserved: a spawned thread is always joinable.
            const thread = std.Thread.spawn(.{}, workerMain, .{ eng, lane }) catch |err| {
                if (spawned == 0) return err; // a lane with no workers is a black hole
                break; // degraded but functional
            };
            lane.threads.appendAssumeCapacity(thread);
        }
        return lane;
    }

    pub fn broadcastAll(self: *Scheduler, io: std.Io) void {
        for (self.lanes.items) |lane| lane.cond.broadcast(io);
    }

    /// Engine lock held. Timer tick: wake lanes whose backed-off items have
    /// come due (workers park on the condition; this is their alarm clock).
    pub fn signalDueLocked(self: *Scheduler, eng: *Engine, now_ns: i96) void {
        for (self.lanes.items) |lane| {
            if (lane.auth_blocked) continue;
            if (hasDueLocked(eng, lane.site_id, now_ns)) lane.cond.broadcast(eng.io);
        }
    }

    /// Engine lock must NOT be held (threads take it on their way out).
    pub fn joinAll(self: *Scheduler) void {
        for (self.lanes.items) |lane| {
            for (lane.threads.items) |thread| thread.join();
        }
    }

    /// All workers must be joined first.
    pub fn deinit(self: *Scheduler, gpa: std.mem.Allocator) void {
        for (self.lanes.items) |lane| {
            lane.threads.deinit(gpa);
            gpa.destroy(lane);
        }
        self.lanes.deinit(gpa);
        self.* = undefined;
    }
};

fn hasDueLocked(eng: *Engine, site_id: u64, now_ns: i96) bool {
    for (eng.items.items) |it| {
        if (it.state != .queued or it.removed or it.pending != .none) continue;
        if (it.siteId() != site_id) continue;
        if (it.not_before_ns <= now_ns) return true;
    }
    return false;
}

/// Engine lock held. Next runnable item for this lane in queue order;
/// transitions it to its active state (so concurrent pickers never collide)
/// and emits the state event.
fn pickRunnableLocked(eng: *Engine, lane: *Lane, now_ns: i96) ?*TransferItem {
    for (eng.items.items) |it| {
        if (it.state != .queued or it.removed or it.pending != .none) continue;
        if (it.siteId() != lane.site_id) continue;
        if (it.not_before_ns > now_ns) continue;
        it.token.reset();
        eng.setStateLocked(it, if (it.kind == .folder) .resolving else .connecting, null);
        return it;
    }
    return null;
}

fn workerMain(eng: *Engine, lane: *Lane) void {
    // Per-worker pump buffer: fixed for the worker's lifetime, zero
    // steady-state allocation in the transfer loop.
    const buf = eng.gpa.alloc(u8, eng.config.chunk_size) catch return;
    defer eng.gpa.free(buf);
    var prng: std.Random.DefaultPrng = .init(eng.config.seed ^ @intFromPtr(buf.ptr));

    while (true) {
        eng.lock();
        const it: *TransferItem = blk: while (true) {
            if (eng.shutdown) {
                eng.unlock();
                return;
            }
            if (!lane.auth_blocked) {
                if (pickRunnableLocked(eng, lane, eng.nowNs())) |found| break :blk found;
            }
            lane.cond.waitUncancelable(eng.io, &eng.mutex);
        };
        eng.unlock();

        const outcome = switch (it.kind) {
            .file => runTransfer(eng, lane, it, buf),
            .folder => runResolve(eng, it),
        };
        applyOutcome(eng, lane, it, outcome, prng.random());
    }
}

pub const Outcome = union(enum) {
    done,
    /// Conflict policy .skip with an existing destination: counts as done.
    skipped,
    /// The item's token fired; pause vs cancel resolves via item.pending.
    canceled,
    /// Conflict policy .ask with an existing destination: park as paused.
    conflict_hold,
    failed: FailureInfo,
};

/// Failure detail copied out of a stack Diagnostics so it survives until
/// applyOutcome runs (no allocation).
pub const FailureInfo = struct {
    class: diag_mod.ErrorClass = .permanent,
    code: u32 = 0,
    len: usize = 0,
    buf: [256]u8 = undefined,

    pub fn init(class: diag_mod.ErrorClass, code: u32, msg: []const u8) FailureInfo {
        var info: FailureInfo = .{ .class = class, .code = code };
        info.len = @min(msg.len, info.buf.len);
        @memcpy(info.buf[0..info.len], msg[0..info.len]);
        return info;
    }

    pub fn message(self: *const FailureInfo) []const u8 {
        return self.buf[0..self.len];
    }
};

fn failOutcome(class: diag_mod.ErrorClass, comptime fmt: []const u8, args: anytype) Outcome {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch &buf;
    return .{ .failed = .init(class, 0, msg) };
}

/// Map a failed Vfs call to an outcome. Trusts the callee's Diagnostics;
/// when the callee left it untouched (empty message), falls back to a
/// conservative mapping from the error value itself.
fn classifyVfs(
    err: vfs_mod.Error,
    diag: *const diag_mod.Diagnostics,
    token: *const cancel_mod.CancelToken,
) Outcome {
    if (err == error.Canceled or token.isCanceled()) return .canceled;
    var class = diag.class;
    var msg = diag.message;
    if (msg.len == 0) {
        class = switch (err) {
            error.ConnectionLost, error.Timeout, error.OutOfMemory => .transient,
            error.AuthRequired => .auth,
            else => .permanent,
        };
        msg = @errorName(err);
    }
    if (class == .cancel) return .canceled;
    return .{ .failed = .init(class, diag.protocol_code, msg) };
}

fn statEntry(
    v: vfs_mod.Vfs,
    io: std.Io,
    token: *cancel_mod.CancelToken,
    path: []const u8,
) ?vfs_mod.Entry {
    var diag: diag_mod.Diagnostics = .{};
    return v.stat(io, token, &diag, path) catch null;
}

fn runTransfer(eng: *Engine, lane: *Lane, it: *TransferItem, buf: []u8) Outcome {
    const io = eng.io;
    const token = &it.token;
    var diag: diag_mod.Diagnostics = .{};

    const src_vfs = eng.config.vfs_provider.get(it.src.site_id) orelse
        return failOutcome(.permanent, "no vfs for site {d}", .{it.src.site_id});
    const dst_vfs = eng.config.vfs_provider.get(it.dst.site_id) orelse
        return failOutcome(.permanent, "no vfs for site {d}", .{it.dst.site_id});

    const src_entry = src_vfs.stat(io, token, &diag, it.src.path) catch |err|
        return classifyVfs(err, &diag, token);
    if (src_entry.kind == .dir)
        return failOutcome(.permanent, "source is a directory: {s}", .{it.src.path});
    const total = src_entry.size orelse 0;
    it.bytes_total.store(total, .monotonic);

    const can_resume = src_vfs.caps().resume_read and dst_vfs.caps().resume_write;
    var offset: u64 = 0;

    if (it.attempts == 0 and !it.resume_hint) {
        // First run: the conflict policy decides.
        switch (it.conflict) {
            .overwrite => {},
            .resume_existing => if (can_resume) {
                if (statEntry(dst_vfs, io, token, it.dst.path)) |e| {
                    if (e.kind == .file) offset = e.size orelse 0;
                }
            },
            .skip => if (statEntry(dst_vfs, io, token, it.dst.path) != null) return .skipped,
            .ask => if (statEntry(dst_vfs, io, token, it.dst.path) != null) return .conflict_hold,
            .rename => if (statEntry(dst_vfs, io, token, it.dst.path) != null) {
                pickRenamedDst(eng, dst_vfs, it) catch
                    return failOutcome(.transient, "out of memory picking rename target", .{});
            },
        }
    } else if (can_resume) {
        // Retry (or resume after pause): continue from whatever the
        // destination already holds. Without Caps support we restart at 0.
        if (statEntry(dst_vfs, io, token, it.dst.path)) |e| {
            if (e.kind == .file) offset = e.size orelse 0;
        }
    }
    if (offset > total) offset = 0; // destination outgrew source: restart clean
    if (token.isCanceled()) return .canceled;

    it.bytes_done.store(offset, .monotonic);

    const rs = src_vfs.openRead(io, token, &diag, it.src.path, offset) catch |err|
        return classifyVfs(err, &diag, token);
    var rs_open = true;
    defer if (rs_open) rs.close(io);

    const mode: vfs_mod.OpenMode = if (offset > 0) .create_resume else .create_truncate;
    const ws = dst_vfs.openWrite(io, token, &diag, it.dst.path, offset, mode) catch |err|
        return classifyVfs(err, &diag, token);
    var ws_open = true;
    defer if (ws_open) ws.close(io) catch {};

    eng.lock();
    eng.setStateLocked(it, .transferring, null);
    eng.unlock();

    const global_bucket = switch (it.direction) {
        .upload => &eng.global_up,
        .download => &eng.global_down,
    };
    const lane_bucket = switch (it.direction) {
        .upload => &lane.up,
        .download => &lane.down,
    };

    while (true) {
        if (token.isCanceled()) return .canceled;
        const n = rs.reader.readSliceShort(buf) catch {
            if (token.isCanceled()) return .canceled;
            return failOutcome(.transient, "connection lost mid-read: {s}", .{it.src.path});
        };
        if (n == 0) break;
        global_bucket.acquire(io, token, n) catch return .canceled;
        lane_bucket.acquire(io, token, n) catch return .canceled;
        ws.writer.writeAll(buf[0..n]) catch {
            if (token.isCanceled()) return .canceled;
            return failOutcome(.transient, "connection lost mid-write: {s}", .{it.dst.path});
        };
        _ = it.bytes_done.fetchAdd(n, .monotonic);
        // readSliceShort returns short only at end of stream.
        if (n < buf.len) break;
    }

    ws_open = false;
    ws.close(io) catch {
        if (token.isCanceled()) return .canceled;
        return failOutcome(.transient, "final flush failed: {s}", .{it.dst.path});
    };
    rs_open = false;
    rs.close(io);

    if (eng.config.verify_size) {
        eng.lock();
        eng.setStateLocked(it, .verifying, null);
        eng.unlock();
        var vdiag: diag_mod.Diagnostics = .{};
        const e = dst_vfs.stat(io, token, &vdiag, it.dst.path) catch |err|
            return classifyVfs(err, &vdiag, token);
        const got = e.size orelse 0;
        const want = it.bytes_done.load(.monotonic);
        if (got != want)
            return failOutcome(.permanent, "size mismatch after transfer: {d} != {d}", .{ got, want });
    }
    return .done;
}

/// Conflict policy .rename: find a free "<path>.<n>" and point the item's
/// destination at it. Falls back to overwrite after 100 collisions.
fn pickRenamedDst(eng: *Engine, dst_vfs: vfs_mod.Vfs, it: *TransferItem) error{OutOfMemory}!void {
    var n: u32 = 1;
    while (n < 100) : (n += 1) {
        const candidate = try std.fmt.allocPrint(eng.gpa, "{s}.{d}", .{ it.dst.path, n });
        defer eng.gpa.free(candidate);
        if (statEntry(dst_vfs, eng.io, &it.token, candidate) == null) {
            try eng.replaceDstPath(it, candidate);
            return;
        }
    }
}

/// Folder item: mkdir the destination, then stream the source listing —
/// every sink batch enqueues child items immediately, so transfers start
/// while deep directories are still listing (never enumerate-all-first).
fn runResolve(eng: *Engine, it: *TransferItem) Outcome {
    const io = eng.io;
    const token = &it.token;
    var diag: diag_mod.Diagnostics = .{};

    const src_vfs = eng.config.vfs_provider.get(it.src.site_id) orelse
        return failOutcome(.permanent, "no vfs for site {d}", .{it.src.site_id});
    const dst_vfs = eng.config.vfs_provider.get(it.dst.site_id) orelse
        return failOutcome(.permanent, "no vfs for site {d}", .{it.dst.site_id});

    dst_vfs.mkdir(io, token, &diag, it.dst.path) catch |err| switch (err) {
        error.AlreadyExists => {},
        else => return classifyVfs(err, &diag, token),
    };

    var arena: std.heap.ArenaAllocator = .init(eng.gpa);
    defer arena.deinit();
    var sink: ResolveSink = .{ .eng = eng, .it = it };
    src_vfs.list(io, token, &diag, it.src.path, arena.allocator(), .{
        .context = &sink,
        .batchFn = ResolveSink.batch,
    }) catch |err| return classifyVfs(err, &diag, token);
    if (sink.enqueue_failed)
        return failOutcome(.transient, "child enqueue failed for {s}", .{it.src.path});
    return .done;
}

const ResolveSink = struct {
    eng: *Engine,
    it: *TransferItem,
    enqueue_failed: bool = false,

    fn batch(context: *anyopaque, entries: []const vfs_mod.Entry) void {
        const self: *ResolveSink = @ptrCast(@alignCast(context));
        for (entries) |entry| {
            // Listing names come from an UNTRUSTED server. Anything that is
            // not exactly one normal path component ("..", "x/y", NUL bytes,
            // invalid UTF-8) would escape it.dst.path when joined — for a
            // download that is an arbitrary local write — so drop it here.
            if (!isSafeChildName(entry.name)) continue;
            const kind: item_mod.Kind = switch (entry.kind) {
                .dir => .folder,
                .file => .file,
                // Symlinks and specials are not transferred (matching the
                // usual client behavior); the UI surfaces them in listings.
                else => continue,
            };
            self.enqueueChild(entry, kind) catch {
                self.enqueue_failed = true;
                return;
            };
        }
    }

    fn enqueueChild(self: *ResolveSink, entry: vfs_mod.Entry, kind: item_mod.Kind) !void {
        const gpa = self.eng.gpa;
        const src_path = try joinPath(gpa, self.it.src.path, entry.name);
        defer gpa.free(src_path);
        const dst_path = try joinPath(gpa, self.it.dst.path, entry.name);
        defer gpa.free(dst_path);
        _ = try self.eng.enqueue(.{
            .direction = self.it.direction,
            .kind = kind,
            .src = .{ .site_id = self.it.src.site_id, .path = src_path },
            .dst = .{ .site_id = self.it.dst.site_id, .path = dst_path },
            .conflict = self.it.conflict,
            .bytes_total = entry.size orelse 0,
            .parent = self.it.id,
        });
    }
};

fn joinPath(gpa: std.mem.Allocator, base: []const u8, name: []const u8) error{OutOfMemory}![]u8 {
    if (base.len == 0) return gpa.dupe(u8, name);
    if (base[base.len - 1] == '/') return std.fmt.allocPrint(gpa, "{s}{s}", .{ base, name });
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ base, name });
}

/// The confinement guard for untrusted listing names (shared with the
/// recursive-remove paths in the VFS backends): the listing parsers only
/// filter the literal "." / ".." strings, so a malicious "../../x" or
/// "a/b" must never reach the destination Vfs.
const isSafeChildName = @import("../vfs/path.zig").isSafeChildName;

fn applyOutcome(eng: *Engine, lane: *Lane, it: *TransferItem, raw_outcome: Outcome, random: std.Random) void {
    eng.lock();
    defer eng.unlock();
    // A pause/cancel request that raced the worker's unwind (the failure or
    // hold beat the token check) must still win — except over .done/.skipped,
    // where the work actually finished.
    const outcome: Outcome = switch (raw_outcome) {
        .done, .skipped, .canceled => raw_outcome,
        .conflict_hold, .failed => if (it.pending != .none) .canceled else raw_outcome,
    };
    switch (outcome) {
        .done, .skipped => {
            it.resume_hint = false;
            eng.setStateLocked(it, .done, null);
        },
        .conflict_hold => eng.setStateLocked(it, .paused, null),
        .canceled => applyCancelLocked(eng, it),
        .failed => |info| switch (info.class) {
            .cancel => applyCancelLocked(eng, it),
            .auth => {
                // Requeue without burning an attempt; the whole site pauses
                // and resumes when the user answers the (single) prompt.
                it.not_before_ns = 0;
                eng.setStateLocked(it, .queued, null);
                lane.auth_blocked = true;
                if (!lane.prompt_pending) {
                    lane.prompt_pending = true;
                    eng.postPromptLocked(lane.site_id);
                }
            },
            .transient => {
                it.attempts += 1;
                if (it.attempts >= eng.config.retry.max_attempts) {
                    eng.failLocked(it, &info);
                } else {
                    it.not_before_ns = eng.nowNs() + backoffNs(eng.config.retry, it.attempts, random);
                    eng.setStateLocked(it, .queued, null);
                    // The engine timer re-signals this lane when it's due.
                }
            },
            .permanent => eng.failLocked(it, &info),
        },
    }
    it.pending = .none;
    if (it.removed and !it.state.isActive()) {
        eng.unlinkDestroyLocked(it);
        // `it` is gone; only lane/engine state below.
    }
    eng.saver.markDirty();
    lane.cond.signal(eng.io);
}

fn applyCancelLocked(eng: *Engine, it: *TransferItem) void {
    if (it.pending == .pause) {
        // Keep partial progress resumable across the pause.
        if (it.bytes_done.load(.monotonic) > 0) it.resume_hint = true;
        eng.setStateLocked(it, .paused, null);
    } else {
        eng.setStateLocked(it, .canceled, null);
    }
}

test "backoff ceiling: exponential growth capped" {
    const policy: RetryPolicy = .{ .max_attempts = 5, .base_ms = 2_000, .cap_ms = 60_000 };
    try std.testing.expectEqual(@as(u64, 2_000), backoffCeilingMs(policy, 1));
    try std.testing.expectEqual(@as(u64, 4_000), backoffCeilingMs(policy, 2));
    try std.testing.expectEqual(@as(u64, 8_000), backoffCeilingMs(policy, 3));
    try std.testing.expectEqual(@as(u64, 32_000), backoffCeilingMs(policy, 5));
    try std.testing.expectEqual(@as(u64, 60_000), backoffCeilingMs(policy, 6)); // capped
    try std.testing.expectEqual(@as(u64, 60_000), backoffCeilingMs(policy, 100)); // shift-safe
    try std.testing.expectEqual(@as(u64, 0), backoffCeilingMs(.{ .base_ms = 0 }, 3));
}

test "backoff jitter: uniform within [0, ceiling], not constant" {
    const policy: RetryPolicy = .{ .base_ms = 1_000, .cap_ms = 60_000 };
    var prng: std.Random.DefaultPrng = .init(7);
    var min: u64 = std.math.maxInt(u64);
    var max: u64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const ns = backoffNs(policy, 2, prng.random());
        try std.testing.expect(ns <= 2_000 * std.time.ns_per_ms);
        min = @min(min, ns);
        max = @max(max, ns);
    }
    // Full jitter must actually spread; 200 draws landing in one quarter
    // of the window would be a broken RNG hookup.
    try std.testing.expect(max - min > 500 * std.time.ns_per_ms);
}

test "fixed budget plumbs through the interface" {
    var fixed: FixedBudget = .{ .n = 5 };
    const b = fixed.budget();
    try std.testing.expectEqual(@as(u8, 5), b.conns(0));
    try std.testing.expectEqual(@as(u8, 5), b.conns(42));
}

test "failure info truncates and preserves class" {
    const info: FailureInfo = .init(.auth, 530, "530 Login incorrect");
    try std.testing.expectEqualStrings("530 Login incorrect", info.message());
    const big: FailureInfo = .init(.transient, 0, "y" ** 999);
    try std.testing.expectEqual(@as(usize, 256), big.message().len);
}

test "unsafe listing names are rejected as child components" {
    try std.testing.expect(isSafeChildName("notes.txt"));
    try std.testing.expect(isSafeChildName("påse"));
    try std.testing.expect(isSafeChildName("a..b"));
    try std.testing.expect(isSafeChildName(".hidden"));
    try std.testing.expect(!isSafeChildName(""));
    try std.testing.expect(!isSafeChildName("."));
    try std.testing.expect(!isSafeChildName(".."));
    try std.testing.expect(!isSafeChildName("../../.ssh/authorized_keys"));
    try std.testing.expect(!isSafeChildName("a/b"));
    try std.testing.expect(!isSafeChildName("/abs"));
    try std.testing.expect(!isSafeChildName("a\x00b"));
    try std.testing.expect(!isSafeChildName("\xff\xfe"));
}

test "safe names joined onto a normalized base stay confined" {
    const path_mod = @import("../vfs/path.zig");
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "f.txt", "påse", "a..b", "with space" }) |name| {
        try std.testing.expect(isSafeChildName(name));
        const p = try joinPath(gpa, "/dl/dir", name);
        defer gpa.free(p);
        try std.testing.expect(path_mod.isNormalized(p));
        try std.testing.expect(std.mem.startsWith(u8, p, "/dl/dir/"));
    }
}

/// Hostile remote for the traversal regression test: delegates everything
/// to an inner MockVfs but answers list with attacker-controlled names,
/// bypassing the listing parsers (which only filter literal "." / "..").
const HostileListVfs = struct {
    inner: vfs_mod.Vfs,

    fn vfs(self: *HostileListVfs) vfs_mod.Vfs {
        return .{ .vtable = &vtable, .ctx = self };
    }

    const vtable: vfs_mod.VTable = .{
        .caps = capsFn,
        .defaultPath = defaultPathFn,
        .stat = statFn,
        .list = listFn,
        .openRead = openReadFn,
        .openWrite = openWriteFn,
        .mkdir = mkdirFn,
        .remove = removeFn,
        .rename = renameFn,
        .chmod = chmodFn,
    };

    fn fromCtx(ctx: *anyopaque) *HostileListVfs {
        return @ptrCast(@alignCast(ctx));
    }

    fn defaultPathFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, buf: []u8) vfs_mod.Error![]const u8 {
        return fromCtx(ctx).inner.defaultPath(io, cancel, diag, buf);
    }

    fn listFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, arena: std.mem.Allocator, sink: vfs_mod.ListingSink) vfs_mod.Error!void {
        _ = ctx;
        _ = io;
        _ = diag;
        _ = path;
        _ = arena;
        try cancel.check();
        sink.batch(&.{
            .{ .name = "../../pwned", .kind = .file, .size = 4 },
            .{ .name = "..", .kind = .dir },
            .{ .name = "evil/nested", .kind = .file, .size = 4 },
            .{ .name = "good.txt", .kind = .file, .size = 4 },
        });
    }

    fn capsFn(ctx: *anyopaque) vfs_mod.Caps {
        return fromCtx(ctx).inner.caps();
    }
    fn statFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) vfs_mod.Error!vfs_mod.Entry {
        return fromCtx(ctx).inner.stat(io, cancel, diag, path);
    }
    fn openReadFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64) vfs_mod.Error!vfs_mod.ReadStream {
        return fromCtx(ctx).inner.openRead(io, cancel, diag, path, offset);
    }
    fn openWriteFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64, mode: vfs_mod.OpenMode) vfs_mod.Error!vfs_mod.WriteStream {
        return fromCtx(ctx).inner.openWrite(io, cancel, diag, path, offset, mode);
    }
    fn mkdirFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) vfs_mod.Error!void {
        return fromCtx(ctx).inner.mkdir(io, cancel, diag, path);
    }
    fn removeFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, recursive: bool) vfs_mod.Error!void {
        return fromCtx(ctx).inner.remove(io, cancel, diag, path, recursive);
    }
    fn renameFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, from: []const u8, to: []const u8) vfs_mod.Error!void {
        return fromCtx(ctx).inner.rename(io, cancel, diag, from, to);
    }
    fn chmodFn(ctx: *anyopaque, io: std.Io, cancel: *cancel_mod.CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, mode: u16) vfs_mod.Error!void {
        return fromCtx(ctx).inner.chmod(io, cancel, diag, path, mode);
    }
};

test "hostile listing names cannot escape the destination directory" {
    const MockVfs = @import("../testutil/mock_vfs.zig").MockVfs;
    const events_mod = @import("../events.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var queue: events_mod.EventQueue = .init(gpa);
    defer queue.deinit();
    var local: MockVfs = .init(gpa);
    defer local.deinit();
    var remote_inner: MockVfs = .init(gpa);
    defer remote_inner.deinit();
    try remote_inner.addFile("/site/good.txt", "safe");
    var remote: HostileListVfs = .{ .inner = remote_inner.vfs() };

    var budget: FixedBudget = .{ .n = 1 };
    const Provider = struct {
        local: *MockVfs,
        remote: *HostileListVfs,
        fn get(context: *anyopaque, site_id: u64) ?vfs_mod.Vfs {
            const self: *@This() = @ptrCast(@alignCast(context));
            return switch (site_id) {
                0 => self.local.vfs(),
                1 => self.remote.vfs(),
                else => null,
            };
        }
    };
    var provider: Provider = .{ .local = &local, .remote = &remote };

    const eng = try Engine.create(gpa, io, &queue, .{
        .budget = budget.budget(),
        .vfs_provider = .{ .context = &provider, .getFn = Provider.get },
        .retry = .{ .max_attempts = 1, .base_ms = 1, .cap_ms = 2 },
        .seed = 7,
    });
    defer eng.destroy();

    _ = try eng.enqueue(.{
        .direction = .download,
        .kind = .folder,
        .src = .{ .site_id = 1, .path = "/site" },
        .dst = .{ .site_id = 0, .path = "/dl" },
    });

    // Wait (≤ 5 s) for the folder and every surviving child to finish.
    const deadline = std.Io.Clock.awake.now(io).nanoseconds + 5 * std.time.ns_per_s;
    while (true) {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const snap = try eng.snapshot(arena.allocator());
        var all_done = true;
        for (snap) |s| all_done = all_done and s.state == .done;
        if (all_done) break;
        try std.testing.expect(std.Io.Clock.awake.now(io).nanoseconds < deadline);
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }

    // Only the safe entry became a child item; nothing was written or
    // mkdir'd outside /dl.
    {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const snap = try eng.snapshot(arena.allocator());
        try std.testing.expectEqual(@as(usize, 2), snap.len); // folder + good.txt
    }
    const got = (try local.contentsAlloc(gpa, "/dl/good.txt")).?;
    defer gpa.free(got);
    try std.testing.expectEqualStrings("safe", got);
    try std.testing.expectEqual(@as(usize, 1), local.opCountContaining("open_write "));
    try std.testing.expectEqual(@as(usize, 0), local.opCountContaining("/dl/.."));
    try std.testing.expectEqual(@as(usize, 0), local.opCountContaining("evil"));
    try std.testing.expectEqual(@as(usize, 0), local.opCountContaining("pwned"));
}

test "join path handles trailing slash and empty base" {
    const gpa = std.testing.allocator;
    const a = try joinPath(gpa, "/srv/www", "index.html");
    defer gpa.free(a);
    try std.testing.expectEqualStrings("/srv/www/index.html", a);
    const b = try joinPath(gpa, "/", "f");
    defer gpa.free(b);
    try std.testing.expectEqualStrings("/f", b);
    const c = try joinPath(gpa, "", "f");
    defer gpa.free(c);
    try std.testing.expectEqualStrings("f", c);
}

test {
    std.testing.refAllDecls(@This());
}

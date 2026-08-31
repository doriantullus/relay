//! engine — the transfer queue's public API and owner of all queue state.
//!
//! One Io.Mutex guards items + lanes; workers (scheduler.zig) hold it only
//! to pick and to apply outcomes — never across I/O. Progress is published
//! through per-item atomics that a single timer thread snapshots at
//! ~30 Hz, coalescing transfer_progress events regardless of chunk rate;
//! the same timer wakes lanes whose backed-off retries are due and drives
//! the debounced autosave.
//!
//! The engine is heap-pinned (`create`/`destroy`): worker threads and the
//! timer hold the pointer, and the mutex/conditions must never move.

const std = @import("std");
const item_mod = @import("item.zig");
const scheduler = @import("scheduler.zig");
const rate_limit = @import("rate_limit.zig");
const persist = @import("persist.zig");
const events = @import("../events.zig");
const diag_mod = @import("../diag.zig");
const vfs_mod = @import("../vfs/vfs.zig");

const TransferItem = item_mod.TransferItem;
const ItemId = item_mod.ItemId;

pub const Config = struct {
    budget: scheduler.Budget,
    vfs_provider: scheduler.VfsProvider,
    retry: scheduler.RetryPolicy = .{},
    /// Stream pump chunk size; one rate-limiter acquire and one atomic
    /// progress update per chunk.
    chunk_size: usize = 64 * 1024,
    /// Progress/EWMA/retry-wakeup/autosave timer period (~30 Hz default).
    progress_interval_ms: u64 = 33,
    /// Stat the destination after the pump and compare sizes.
    verify_size: bool = false,
    /// Initial global rate limits in bytes/s; 0 = unlimited. Adjustable at
    /// runtime via setGlobalRateLimit/setSiteRateLimit.
    rate_up: u64 = 0,
    rate_down: u64 = 0,
    /// Burst capacity for every token bucket.
    rate_burst: u64 = 256 * 1024,
    /// When set, the timer autosaves pending+failed items (debounced) and
    /// destroy() writes a final snapshot.
    persist_dir: ?std.Io.Dir = null,
    persist_sub_path: []const u8 = "queue.zon",
    save_debounce_ms: u64 = 500,
    /// Backoff jitter seed (tests pin it for determinism).
    seed: u64 = 0x9e3779b97f4a7c15,
};

pub const Spec = struct {
    direction: item_mod.Direction,
    kind: item_mod.Kind = .file,
    src: item_mod.Endpoint,
    dst: item_mod.Endpoint,
    conflict: item_mod.ConflictPolicy = .overwrite,
    /// Known size hint (e.g. from the listing entry); 0 = unknown.
    bytes_total: u64 = 0,
    parent: ItemId = 0,
    /// Enqueue without starting (UI "add to queue", restored sessions).
    start_paused: bool = false,
};

pub const ItemSnapshot = struct {
    id: ItemId,
    parent: ItemId,
    direction: item_mod.Direction,
    kind: item_mod.Kind,
    conflict: item_mod.ConflictPolicy,
    state: item_mod.State,
    src: item_mod.Endpoint,
    dst: item_mod.Endpoint,
    bytes_done: u64,
    bytes_total: u64,
    rate_bps: u64,
    attempts: u32,
    failure_class: ?diag_mod.ErrorClass,
    failure_message: []const u8,
};

pub const Engine = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    events_q: *events.EventQueue,
    config: Config,
    mutex: std.Io.Mutex = .init,
    /// Queue order == priority order. Pointers are stable (heap items).
    items: std.ArrayList(*TransferItem) = .empty,
    sched: scheduler.Scheduler = .{},
    shutdown: bool = false,
    next_id: ItemId = 1,
    next_prompt_id: u64 = 1,
    global_up: rate_limit.TokenBucket,
    global_down: rate_limit.TokenBucket,
    saver: persist.Debounce,
    timer_thread: ?std.Thread = null,

    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        events_q: *events.EventQueue,
        config: Config,
    ) !*Engine {
        const self = try gpa.create(Engine);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .events_q = events_q,
            .config = config,
            .global_up = .init(config.rate_up, config.rate_burst),
            .global_down = .init(config.rate_down, config.rate_burst),
            .saver = .{ .interval_ns = config.save_debounce_ms * std.time.ns_per_ms },
        };
        self.timer_thread = try std.Thread.spawn(.{}, timerMain, .{self});
        return self;
    }

    /// Cancels everything, joins all threads, writes a final persist
    /// snapshot (when configured), frees all state.
    pub fn destroy(self: *Engine) void {
        self.lock();
        self.shutdown = true;
        for (self.items.items) |it| it.token.cancel();
        self.unlock();
        self.sched.broadcastAll(self.io);
        self.sched.joinAll();
        if (self.timer_thread) |t| t.join();

        if (self.config.persist_dir) |dir| {
            // Best effort: losing the final save must never block quit.
            var arena: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena.deinit();
            if (self.persistSnapshotLocked(arena.allocator())) |q| {
                persist.save(q, self.io, dir, self.config.persist_sub_path, self.gpa) catch {};
            } else |_| {}
        }

        for (self.items.items) |it| it.destroy(self.gpa);
        self.items.deinit(self.gpa);
        self.sched.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------
    // Internals shared with scheduler.zig
    // ------------------------------------------------------------------

    pub fn lock(self: *Engine) void {
        self.mutex.lockUncancelable(self.io);
    }

    pub fn unlock(self: *Engine) void {
        self.mutex.unlock(self.io);
    }

    pub fn nowNs(self: *Engine) i96 {
        return std.Io.Clock.awake.now(self.io).nanoseconds;
    }

    /// Events are best-effort towards the UI; an OOM drops the event, the
    /// queue state itself stays consistent (snapshot() always has truth).
    fn post(self: *Engine, event: events.CoreEvent) void {
        _ = self.events_q.post(event) catch {};
    }

    pub fn setStateLocked(self: *Engine, it: *TransferItem, new: item_mod.State, failure: ?events.Failure) void {
        std.debug.assert(item_mod.legalTransition(it.state, new));
        it.state = new;
        self.post(.{ .transfer_state = .{
            .item_id = it.id,
            .state = new.toEventState(),
            .failure = failure,
        } });
    }

    pub fn failLocked(self: *Engine, it: *TransferItem, info: *const scheduler.FailureInfo) void {
        var stored: item_mod.StoredFailure = .{};
        stored.set(info.class, info.code, info.message());
        it.failure = stored;
        self.setStateLocked(it, .failed, .{
            .class = info.class,
            .protocol_code = info.code,
            .message = info.message(),
        });
    }

    pub fn postPromptLocked(self: *Engine, site_id: u64) void {
        const prompt_id = self.next_prompt_id;
        self.next_prompt_id += 1;
        // The queue knows sites only by id; the UI resolves user/host from
        // its site list when presenting.
        self.post(.{ .prompt_needed = .{
            .site_id = site_id,
            .prompt_id = prompt_id,
            .prompt = .{ .password = .{ .user = "", .host = "" } },
        } });
    }

    pub fn unlinkDestroyLocked(self: *Engine, it: *TransferItem) void {
        for (self.items.items, 0..) |candidate, i| {
            if (candidate == it) {
                _ = self.items.orderedRemove(i);
                break;
            }
        }
        it.destroy(self.gpa);
    }

    /// Called by the worker that owns `it` (conflict policy .rename).
    pub fn replaceDstPath(self: *Engine, it: *TransferItem, new_path: []const u8) error{OutOfMemory}!void {
        const duped = try self.gpa.dupe(u8, new_path);
        self.lock();
        defer self.unlock();
        self.gpa.free(it.dst.path);
        it.dst.path = duped;
    }

    fn findLocked(self: *Engine, id: ItemId) ?*TransferItem {
        for (self.items.items) |it| {
            if (it.id == id and !it.removed) return it;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    pub fn enqueue(self: *Engine, spec: Spec) !ItemId {
        self.lock();
        defer self.unlock();
        if (self.shutdown) return error.ShutDown;
        const site_id = switch (spec.direction) {
            .upload => spec.dst.site_id,
            .download => spec.src.site_id,
        };
        const lane = try self.sched.ensureLaneLocked(self, site_id);
        const it = try TransferItem.create(self.gpa, .{
            .id = self.next_id,
            .direction = spec.direction,
            .kind = spec.kind,
            .src = spec.src,
            .dst = spec.dst,
            .conflict = spec.conflict,
            .parent = spec.parent,
            .bytes_total = spec.bytes_total,
            .state = if (spec.start_paused) .paused else .queued,
        });
        errdefer it.destroy(self.gpa);
        try self.items.append(self.gpa, it);
        self.next_id += 1;
        self.post(.{ .transfer_state = .{ .item_id = it.id, .state = it.state.toEventState() } });
        if (!spec.start_paused) lane.cond.signal(self.io);
        self.saver.markDirty();
        return it.id;
    }

    pub fn pauseItem(self: *Engine, id: ItemId) bool {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return false;
        return self.pauseLocked(it);
    }

    pub fn resumeItem(self: *Engine, id: ItemId) !bool {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return false;
        return self.resumeLocked(it);
    }

    pub fn cancelItem(self: *Engine, id: ItemId) bool {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return false;
        return self.cancelLocked(it);
    }

    pub fn pauseAll(self: *Engine) void {
        self.lock();
        defer self.unlock();
        for (self.items.items) |it| _ = self.pauseLocked(it);
    }

    pub fn resumeAll(self: *Engine) !void {
        self.lock();
        defer self.unlock();
        for (self.items.items) |it| _ = try self.resumeLocked(it);
    }

    pub fn cancelAll(self: *Engine) void {
        self.lock();
        defer self.unlock();
        // cancelLocked may unlink removed items; iterate a stable view.
        var i: usize = self.items.items.len;
        while (i > 0) {
            i -= 1;
            _ = self.cancelLocked(self.items.items[i]);
        }
    }

    pub fn pauseSite(self: *Engine, site_id: u64) void {
        self.lock();
        defer self.unlock();
        for (self.items.items) |it| {
            if (it.siteId() == site_id) _ = self.pauseLocked(it);
        }
    }

    pub fn resumeSite(self: *Engine, site_id: u64) !void {
        self.lock();
        defer self.unlock();
        for (self.items.items) |it| {
            if (it.siteId() == site_id) _ = try self.resumeLocked(it);
        }
    }

    pub fn cancelSite(self: *Engine, site_id: u64) void {
        self.lock();
        defer self.unlock();
        var i: usize = self.items.items.len;
        while (i > 0) {
            i -= 1;
            const it = self.items.items[i];
            if (it.siteId() == site_id) _ = self.cancelLocked(it);
        }
    }

    fn pauseLocked(self: *Engine, it: *TransferItem) bool {
        switch (it.state) {
            .queued => {
                self.setStateLocked(it, .paused, null);
                return true;
            },
            .resolving, .connecting, .transferring, .verifying => {
                it.pending = .pause;
                it.token.cancel();
                return true;
            },
            else => return false,
        }
    }

    fn resumeLocked(self: *Engine, it: *TransferItem) !bool {
        if (it.state != .paused) return false;
        it.pending = .none;
        it.not_before_ns = 0;
        it.token.reset();
        self.setStateLocked(it, .queued, null);
        self.saver.markDirty();
        const lane = try self.sched.ensureLaneLocked(self, it.siteId());
        lane.cond.signal(self.io);
        return true;
    }

    fn cancelLocked(self: *Engine, it: *TransferItem) bool {
        switch (it.state) {
            // queued/paused/conflict are parked — no worker owns the item.
            .queued, .paused, .conflict => {
                self.setStateLocked(it, .canceled, null);
                self.saver.markDirty();
                if (it.removed) self.unlinkDestroyLocked(it);
                return true;
            },
            .resolving, .connecting, .transferring, .verifying => {
                it.pending = .cancel;
                it.token.cancel();
                return true;
            },
            .done, .failed, .canceled => return false,
        }
    }

    /// Resolve a conflict-parked item (state `.conflict`): re-run it under a
    /// concrete `policy` (`.overwrite` / `.resume_existing` / `.rename`), or
    /// drop it (`.skip`). No-op unless the item is actually waiting on a
    /// conflict decision. Mirrors resumeLocked for the re-run path.
    pub fn resolveConflict(self: *Engine, id: ItemId, policy: item_mod.ConflictPolicy) !bool {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return false;
        if (it.state != .conflict) return false;
        if (policy == .skip or policy == .ask) return self.cancelLocked(it);
        it.conflict = policy;
        it.pending = .none;
        it.not_before_ns = 0;
        it.token.reset();
        self.setStateLocked(it, .queued, null);
        self.saver.markDirty();
        const lane = try self.sched.ensureLaneLocked(self, it.siteId());
        lane.cond.signal(self.io);
        return true;
    }

    /// Move item `id` to position `new_index` in the queue order.
    pub fn reorder(self: *Engine, id: ItemId, new_index: usize) bool {
        self.lock();
        defer self.unlock();
        const from = for (self.items.items, 0..) |it, i| {
            if (it.id == id and !it.removed) break i;
        } else return false;
        const to = @min(new_index, self.items.items.len - 1);
        if (from == to) return true;
        const it = self.items.orderedRemove(from);
        // Capacity unchanged by the remove, so this cannot fail.
        self.items.insertAssumeCapacity(to, it);
        self.saver.markDirty();
        self.sched.broadcastAll(self.io);
        return true;
    }

    /// Remove an item from the queue. Active items are canceled first and
    /// vanish when their worker unwinds.
    pub fn remove(self: *Engine, id: ItemId) bool {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return false;
        if (it.state.isActive()) {
            it.removed = true;
            it.pending = .cancel;
            it.token.cancel();
        } else {
            self.unlinkDestroyLocked(it);
        }
        self.saver.markDirty();
        return true;
    }

    /// Failed bucket → queued, attempts reset. Returns the requeue count.
    pub fn requeueFailed(self: *Engine) usize {
        self.lock();
        defer self.unlock();
        var count: usize = 0;
        for (self.items.items) |it| {
            if (it.state != .failed) continue;
            it.attempts = 0;
            it.failure = null;
            it.not_before_ns = 0;
            it.pending = .none;
            it.token.reset();
            self.setStateLocked(it, .queued, null);
            _ = self.sched.ensureLaneLocked(self, it.siteId()) catch continue;
            count += 1;
        }
        if (count > 0) {
            self.saver.markDirty();
            self.sched.broadcastAll(self.io);
        }
        return count;
    }

    /// UI answer to the (single) auth prompt for a site. On success the
    /// lane unblocks and every requeued item runs; on failure the lane
    /// stays blocked and the UI may re-prompt via this same path.
    pub fn resolveAuthPrompt(self: *Engine, site_id: u64, ok: bool) void {
        self.lock();
        defer self.unlock();
        const lane = self.sched.findLane(site_id) orelse return;
        lane.prompt_pending = false;
        if (ok) {
            lane.auth_blocked = false;
            lane.cond.broadcast(self.io);
        }
    }

    pub fn setGlobalRateLimit(self: *Engine, direction: item_mod.Direction, bytes_per_s: u64) void {
        switch (direction) {
            .upload => self.global_up.setRate(self.io, bytes_per_s),
            .download => self.global_down.setRate(self.io, bytes_per_s),
        }
    }

    pub fn setSiteRateLimit(self: *Engine, site_id: u64, direction: item_mod.Direction, bytes_per_s: u64) !void {
        self.lock();
        defer self.unlock();
        const lane = try self.sched.ensureLaneLocked(self, site_id);
        switch (direction) {
            .upload => lane.up.setRate(self.io, bytes_per_s),
            .download => lane.down.setRate(self.io, bytes_per_s),
        }
    }

    /// UI snapshot in queue order. All slices are duped into `alloc`
    /// (arena-per-result: pass an arena and free wholesale).
    pub fn snapshot(self: *Engine, alloc: std.mem.Allocator) error{OutOfMemory}![]ItemSnapshot {
        self.lock();
        defer self.unlock();
        const out = try alloc.alloc(ItemSnapshot, self.items.items.len);
        for (out, self.items.items) |*snap, it| {
            snap.* = .{
                .id = it.id,
                .parent = it.parent,
                .direction = it.direction,
                .kind = it.kind,
                .conflict = it.conflict,
                .state = it.state,
                .src = .{ .site_id = it.src.site_id, .path = try alloc.dupe(u8, it.src.path) },
                .dst = .{ .site_id = it.dst.site_id, .path = try alloc.dupe(u8, it.dst.path) },
                .bytes_done = it.bytes_done.load(.monotonic),
                .bytes_total = it.bytes_total.load(.monotonic),
                .rate_bps = it.rate_bps.load(.monotonic),
                .attempts = it.attempts,
                .failure_class = if (it.failure) |f| f.class else null,
                .failure_message = if (it.failure) |*f| try alloc.dupe(u8, f.message()) else "",
            };
        }
        return out;
    }

    pub fn stateOf(self: *Engine, id: ItemId) ?item_mod.State {
        self.lock();
        defer self.unlock();
        const it = self.findLocked(id) orelse return null;
        return it.state;
    }

    /// Pending + failed items in persistable form, slices owned by `alloc`.
    /// Callers hold the engine lock (timer tick + shutdown save path).
    fn persistSnapshotLocked(self: *Engine, alloc: std.mem.Allocator) error{OutOfMemory}!persist.PersistedQueue {
        var list: std.ArrayList(persist.PersistedItem) = .empty;
        defer list.deinit(alloc);
        for (self.items.items) |it| {
            if (it.removed) continue;
            const state: persist.PersistedState = switch (it.state) {
                .queued, .resolving, .connecting, .transferring, .verifying, .conflict => .queued,
                .paused => .paused,
                .failed => .failed,
                .done, .canceled => continue,
            };
            try list.append(alloc, .{
                .id = it.id,
                .direction = it.direction,
                .kind = it.kind,
                .src_site = it.src.site_id,
                .src_path = try alloc.dupe(u8, it.src.path),
                .dst_site = it.dst.site_id,
                .dst_path = try alloc.dupe(u8, it.dst.path),
                .conflict = it.conflict,
                .parent = it.parent,
                .state = state,
                .bytes_total = it.bytes_total.load(.monotonic),
                .attempts = it.attempts,
            });
        }
        return .{ .items = try list.toOwnedSlice(alloc) };
    }

    /// Re-create items from a persisted queue. Pending items come back
    /// PAUSED — resume-on-start is offered (resumeAll), never forced.
    /// Returns the number restored.
    pub fn restore(self: *Engine, queue: persist.PersistedQueue) !usize {
        self.lock();
        defer self.unlock();
        var count: usize = 0;
        for (queue.items) |p| {
            const state: item_mod.State = switch (p.state) {
                .queued, .paused => .paused,
                .failed => .failed,
            };
            const it = try TransferItem.create(self.gpa, .{
                .id = p.id,
                .direction = p.direction,
                .kind = p.kind,
                .src = .{ .site_id = p.src_site, .path = p.src_path },
                .dst = .{ .site_id = p.dst_site, .path = p.dst_path },
                .conflict = p.conflict,
                .parent = p.parent,
                .bytes_total = p.bytes_total,
                .state = state,
                .attempts = p.attempts,
            });
            errdefer it.destroy(self.gpa);
            if (state == .failed) {
                var stored: item_mod.StoredFailure = .{};
                stored.set(.permanent, 0, "failed in a previous session");
                it.failure = stored;
            }
            try self.items.append(self.gpa, it);
            self.next_id = @max(self.next_id, p.id + 1);
            count += 1;
        }
        return count;
    }

    // ------------------------------------------------------------------
    // Timer thread: progress coalescing, retry wakeups, autosave
    // ------------------------------------------------------------------

    fn timerMain(self: *Engine) void {
        var last_ns = self.nowNs();
        while (true) {
            self.io.sleep(.fromMilliseconds(@intCast(self.config.progress_interval_ms)), .awake) catch {};
            var save_arena: std.heap.ArenaAllocator = .init(self.gpa);
            defer save_arena.deinit();
            var to_save: ?persist.PersistedQueue = null;
            {
                self.lock();
                defer self.unlock();
                if (self.shutdown) return;
                const now = self.nowNs();
                const dt_ns: u64 = @intCast(@max(1, now - last_ns));
                last_ns = now;
                for (self.items.items) |it| {
                    if (it.state != .transferring and it.state != .verifying) continue;
                    const bytes = it.bytes_done.load(.monotonic);
                    const delta = bytes -| it.timer_last_bytes;
                    it.timer_last_bytes = bytes;
                    const inst: u64 = @intCast(@min(
                        @as(u128, delta) * std.time.ns_per_s / dt_ns,
                        std.math.maxInt(u64),
                    ));
                    const rate = item_mod.ewma(it.rate_bps.load(.monotonic), inst);
                    it.rate_bps.store(rate, .monotonic);
                    if (bytes != it.timer_emitted_bytes) {
                        it.timer_emitted_bytes = bytes;
                        self.post(.{ .transfer_progress = .{
                            .item_id = it.id,
                            .bytes_done = bytes,
                            .rate = rate,
                        } });
                    }
                }
                self.sched.signalDueLocked(self, now);
                if (self.config.persist_dir != null and self.saver.poll(now)) {
                    // OOM: skip this save, stay dirty for the next tick.
                    to_save = self.persistSnapshotLocked(save_arena.allocator()) catch blk: {
                        self.saver.markDirty();
                        break :blk null;
                    };
                }
            }
            if (to_save) |q| {
                // File I/O strictly outside the engine lock.
                persist.save(q, self.io, self.config.persist_dir.?, self.config.persist_sub_path, self.gpa) catch {};
            }
        }
    }
};

// ----------------------------------------------------------------------
// Tests — all against mock_vfs, fully offline. Site 1 is "remote", site 0
// is the local side. Timings are kept tiny (ms-scale) per the test budget.
// ----------------------------------------------------------------------

const MockVfs = @import("../testutil/mock_vfs.zig").MockVfs;
const testing = std.testing;

const test_timeout_ms: u64 = 5_000;

const TestRig = struct {
    queue: events.EventQueue,
    local: MockVfs,
    remote: MockVfs,
    budget: scheduler.FixedBudget,
    collected: std.ArrayList(Collected),
    eng: *Engine,

    const Collected = union(enum) {
        state: struct { id: u64, state: events.TransferState, class: ?diag_mod.ErrorClass },
        progress: struct { id: u64, rate: u64 },
        prompt: struct { site_id: u64 },
    };

    const Overrides = struct {
        conns: u8 = 2,
        chunk_size: usize = 4096,
        progress_interval_ms: u64 = 2,
        retry: scheduler.RetryPolicy = .{ .max_attempts = 3, .base_ms = 1, .cap_ms = 4 },
        verify_size: bool = false,
        rate_up: u64 = 0,
        rate_down: u64 = 0,
        persist_dir: ?std.Io.Dir = null,
        save_debounce_ms: u64 = 1,
    };

    /// In-place init: the rig is pinned (engine holds context pointers).
    fn start(rig: *TestRig, o: Overrides) !void {
        rig.queue = .init(testing.allocator);
        rig.local = .init(testing.allocator);
        rig.remote = .init(testing.allocator);
        rig.budget = .{ .n = o.conns };
        rig.collected = .empty;
        rig.eng = try Engine.create(testing.allocator, testing.io, &rig.queue, .{
            .budget = rig.budget.budget(),
            .vfs_provider = .{ .context = rig, .getFn = getVfs },
            .retry = o.retry,
            .chunk_size = o.chunk_size,
            .progress_interval_ms = o.progress_interval_ms,
            .verify_size = o.verify_size,
            .rate_up = o.rate_up,
            .rate_down = o.rate_down,
            .persist_dir = o.persist_dir,
            .save_debounce_ms = o.save_debounce_ms,
            .seed = 42,
        });
    }

    fn stop(rig: *TestRig) void {
        rig.eng.destroy();
        rig.collected.deinit(testing.allocator);
        rig.remote.deinit();
        rig.local.deinit();
        rig.queue.deinit();
    }

    fn getVfs(context: *anyopaque, site_id: u64) ?vfs_mod.Vfs {
        const rig: *TestRig = @ptrCast(@alignCast(context));
        return switch (site_id) {
            0 => rig.local.vfs(),
            1 => rig.remote.vfs(),
            else => null,
        };
    }

    fn drainEvents(rig: *TestRig) !void {
        for (rig.queue.drain()) |event| {
            switch (event) {
                .transfer_state => |e| try rig.collected.append(testing.allocator, .{ .state = .{
                    .id = e.item_id,
                    .state = e.state,
                    .class = if (e.failure) |f| f.class else null,
                } }),
                .transfer_progress => |e| try rig.collected.append(testing.allocator, .{ .progress = .{
                    .id = e.item_id,
                    .rate = e.rate,
                } }),
                .prompt_needed => |e| try rig.collected.append(testing.allocator, .{ .prompt = .{
                    .site_id = e.site_id,
                } }),
                else => {},
            }
        }
    }

    fn sleepMs(ms: u64) void {
        std.Io.sleep(testing.io, .fromMilliseconds(@intCast(ms)), .awake) catch {};
    }

    fn waitState(rig: *TestRig, id: ItemId, state: item_mod.State) !void {
        const deadline = std.Io.Clock.awake.now(testing.io).nanoseconds +
            test_timeout_ms * std.time.ns_per_ms;
        while (true) {
            try rig.drainEvents();
            if (rig.eng.stateOf(id) == state) return;
            if (std.Io.Clock.awake.now(testing.io).nanoseconds > deadline) {
                std.debug.print("waitState timeout: item {d} is {?t}, wanted {t}\n", .{
                    id, rig.eng.stateOf(id), state,
                });
                return error.Timeout;
            }
            sleepMs(1);
        }
    }

    /// Wait until every current item is in `state`.
    fn waitAllState(rig: *TestRig, state: item_mod.State) !void {
        const deadline = std.Io.Clock.awake.now(testing.io).nanoseconds +
            test_timeout_ms * std.time.ns_per_ms;
        outer: while (true) {
            try rig.drainEvents();
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();
            const snap = try rig.eng.snapshot(arena.allocator());
            for (snap) |s| {
                if (s.state != state) {
                    if (std.Io.Clock.awake.now(testing.io).nanoseconds > deadline) {
                        std.debug.print("waitAllState timeout: item {d} is {t}\n", .{ s.id, s.state });
                        return error.Timeout;
                    }
                    sleepMs(1);
                    continue :outer;
                }
            }
            return;
        }
    }

    fn promptCount(rig: *TestRig) usize {
        var n: usize = 0;
        for (rig.collected.items) |c| {
            if (c == .prompt) n += 1;
        }
        return n;
    }

    fn progressCount(rig: *TestRig, id: ItemId) usize {
        var n: usize = 0;
        for (rig.collected.items) |c| switch (c) {
            .progress => |p| {
                if (p.id == id) n += 1;
            },
            else => {},
        };
        return n;
    }

    fn expectFile(mock: *MockVfs, path: []const u8, expected: []const u8) !void {
        const got = try mock.contentsAlloc(testing.allocator, path) orelse {
            std.debug.print("expectFile: {s} missing\n", .{path});
            return error.TestUnexpectedResult;
        };
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, expected, got);
    }
};

fn patternBytes(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const buf = try gpa.alloc(u8, len);
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    return buf;
}

test "happy download and upload, full state sequence" {
    var rig: TestRig = undefined;
    try rig.start(.{});
    defer rig.stop();

    const payload = try patternBytes(testing.allocator, 20_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/pub/data.bin", payload);
    try rig.local.addFile("/up/notes.txt", "local payload");

    const dl = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/pub/data.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/data.bin" },
    });
    const ul = try rig.eng.enqueue(.{
        .direction = .upload,
        .src = .{ .site_id = 0, .path = "/up/notes.txt" },
        .dst = .{ .site_id = 1, .path = "/in/notes.txt" },
    });

    try rig.waitState(dl, .done);
    try rig.waitState(ul, .done);
    try TestRig.expectFile(&rig.local, "/dl/data.bin", payload);
    try TestRig.expectFile(&rig.remote, "/in/notes.txt", "local payload");

    // The download went through the canonical event sequence.
    var saw_queued = false;
    var saw_connecting = false;
    var saw_transferring = false;
    var saw_completed = false;
    for (rig.collected.items) |c| switch (c) {
        .state => |s| {
            if (s.id != dl) continue;
            switch (s.state) {
                .queued => saw_queued = true,
                .connecting => saw_connecting = true,
                .transferring => saw_transferring = true,
                .completed => saw_completed = true,
                else => {},
            }
        },
        else => {},
    };
    try testing.expect(saw_queued and saw_connecting and saw_transferring and saw_completed);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snap = try rig.eng.snapshot(arena.allocator());
    try testing.expectEqual(@as(usize, 2), snap.len);
    try testing.expectEqual(@as(u64, 20_000), snap[0].bytes_done);
    try testing.expectEqual(@as(u64, 20_000), snap[0].bytes_total);
    try testing.expectEqual(@as(u32, 0), snap[0].attempts);
}

test "folder download expands incrementally while listing streams" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 2 });
    defer rig.stop();

    // One entry per sink batch with a 10 ms stall between batches: children
    // from early batches finish while the walker is still listing.
    rig.remote.list_batch = 1;
    rig.remote.list_stall_ns = 10 * std.time.ns_per_ms;

    try rig.remote.addFile("/site/a.txt", "alpha");
    try rig.remote.addFile("/site/b.txt", "bravo");
    try rig.remote.addFile("/site/c.txt", "charlie");
    try rig.remote.addDir("/site/sub");
    try rig.remote.addFile("/site/sub/d.txt", "delta");

    const folder = try rig.eng.enqueue(.{
        .direction = .download,
        .kind = .folder,
        .src = .{ .site_id = 1, .path = "/site" },
        .dst = .{ .site_id = 0, .path = "/dl" },
    });
    try rig.waitState(folder, .done);
    try rig.waitAllState(.done); // children too (incl. nested folder)

    try TestRig.expectFile(&rig.local, "/dl/a.txt", "alpha");
    try TestRig.expectFile(&rig.local, "/dl/b.txt", "bravo");
    try TestRig.expectFile(&rig.local, "/dl/c.txt", "charlie");
    try TestRig.expectFile(&rig.local, "/dl/sub/d.txt", "delta");

    // Parent + 3 files + subfolder + nested file.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snap = try rig.eng.snapshot(arena.allocator());
    try testing.expectEqual(@as(usize, 6), snap.len);
    for (snap[1..]) |s| {
        if (std.mem.eql(u8, s.src.path, "/site/sub/d.txt")) continue; // nested: parent is the sub folder item
        try testing.expectEqual(folder, s.parent);
    }

    // Streaming proof: some child completed BEFORE the parent resolve
    // finished (the stalls make this deterministic).
    var first_child_done: ?usize = null;
    var parent_done: ?usize = null;
    for (rig.collected.items, 0..) |c, i| switch (c) {
        .state => |s| {
            if (s.state != .completed) continue;
            if (s.id == folder) {
                if (parent_done == null) parent_done = i;
            } else if (first_child_done == null) {
                first_child_done = i;
            }
        },
        else => {},
    };
    try testing.expect(first_child_done.? < parent_done.?);
}

test "transient mid-read failure resumes from offset" {
    var rig: TestRig = undefined;
    // chunk_size divides the fault offset so the flushed destination ends
    // exactly at the failure boundary.
    try rig.start(.{ .conns = 1, .chunk_size = 1000 });
    defer rig.stop();

    const payload = try patternBytes(testing.allocator, 30_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/big.bin", payload);
    try rig.remote.injectFault(.{ .path = "/big.bin", .op = .read, .at_bytes = 10_000 });

    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/big.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/big.bin" },
    });
    try rig.waitState(id, .done);
    try TestRig.expectFile(&rig.local, "/dl/big.bin", payload);

    // The retry resumed (REST-style) instead of restarting.
    try testing.expect(rig.remote.hasOp("open_read /big.bin off=10000"));
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snap = try rig.eng.snapshot(arena.allocator());
    try testing.expectEqual(@as(u32, 1), snap[0].attempts);
}

test "without resume caps a transient retry restarts from zero" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1, .chunk_size = 1000 });
    defer rig.stop();
    rig.remote.caps_value.resume_read = false; // server lacks REST

    const payload = try patternBytes(testing.allocator, 8_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/f.bin", payload);
    try rig.remote.injectFault(.{ .path = "/f.bin", .op = .read, .at_bytes = 3_000 });

    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/f.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/f.bin" },
    });
    try rig.waitState(id, .done);
    try TestRig.expectFile(&rig.local, "/dl/f.bin", payload);
    try testing.expect(rig.remote.hasOp("open_read /f.bin off=0"));
    try testing.expect(!rig.remote.hasOp("open_read /f.bin off=3000"));
}

test "permanent failure lands in the failed bucket; requeueFailed retries it" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1 });
    defer rig.stop();

    try rig.remote.addFile("/secret.txt", "classified");
    try rig.remote.injectFault(.{
        .path = "/secret.txt",
        .op = .open_read,
        .err = error.PermissionDenied,
        .class = .permanent,
        .code = 550,
        .message = "550 Permission denied",
    });

    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/secret.txt" },
        .dst = .{ .site_id = 0, .path = "/dl/secret.txt" },
    });
    try rig.waitState(id, .failed);
    TestRig.sleepMs(10); // would-be retry window
    try rig.drainEvents();

    // Never auto-retried: exactly one open attempt.
    try testing.expectEqual(@as(usize, 1), rig.remote.opCountContaining("open_read /secret.txt"));
    var failed_events: usize = 0;
    for (rig.collected.items) |c| switch (c) {
        .state => |s| if (s.state == .failed) {
            failed_events += 1;
            try testing.expectEqual(diag_mod.ErrorClass.permanent, s.class.?);
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), failed_events);

    {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const snap = try rig.eng.snapshot(arena.allocator());
        try testing.expectEqual(diag_mod.ErrorClass.permanent, snap[0].failure_class.?);
        try testing.expect(std.mem.indexOf(u8, snap[0].failure_message, "550") != null);
    }

    // The fault was one-shot, so an explicit requeue succeeds.
    try testing.expectEqual(@as(usize, 1), rig.eng.requeueFailed());
    try rig.waitState(id, .done);
    try TestRig.expectFile(&rig.local, "/dl/secret.txt", "classified");
}

test "auth failure pauses the site and raises exactly one prompt (8 workers)" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 8 });
    defer rig.stop();

    var name_buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const path = try std.fmt.bufPrint(&name_buf, "/files/f{d}", .{i});
        try rig.remote.addFile(path, "payload");
    }
    try rig.remote.injectFault(.{
        .path = "*",
        .op = .open_read,
        .times = std.math.maxInt(u32),
        .err = error.AuthRequired,
        .class = .auth,
        .code = 530,
        .message = "530 Please login with USER and PASS",
    });

    var ids: [10]ItemId = undefined;
    var dst_buf: [32]u8 = undefined;
    i = 0;
    while (i < 10) : (i += 1) {
        const src = try std.fmt.bufPrint(&name_buf, "/files/f{d}", .{i});
        const dst = try std.fmt.bufPrint(&dst_buf, "/dl/f{d}", .{i});
        ids[i] = try rig.eng.enqueue(.{
            .direction = .download,
            .src = .{ .site_id = 1, .path = src },
            .dst = .{ .site_id = 0, .path = dst },
        });
    }

    // The storm settles: every item back to queued, the lane blocked.
    try rig.waitAllState(.queued);
    TestRig.sleepMs(20); // let any straggler workers hit the wall too
    try rig.drainEvents();
    try testing.expectEqual(@as(usize, 1), rig.promptCount());

    // Login succeeds: the lane unblocks and everything drains.
    rig.remote.clearFaults();
    rig.eng.resolveAuthPrompt(1, true);
    try rig.waitAllState(.done);
    try rig.drainEvents();
    try testing.expectEqual(@as(usize, 1), rig.promptCount()); // still just one
    for (ids) |id| try testing.expectEqual(item_mod.State.done, rig.eng.stateOf(id).?);
}

test "cancel mid-transfer resolves within 150ms" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1 });
    defer rig.stop();

    // ~400 KiB at 2 KiB per mock read with a 2 ms stall ≈ 400 ms total —
    // plenty of runway to cancel mid-flight.
    rig.remote.read_chunk = 2048;
    rig.remote.read_stall_ns = 2 * std.time.ns_per_ms;
    const payload = try patternBytes(testing.allocator, 400_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/huge.bin", payload);

    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/huge.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/huge.bin" },
    });
    try rig.waitState(id, .transferring);
    // Make sure bytes are actually moving before we pull the plug.
    while ((rig.local.fileSize("/dl/huge.bin") orelse 0) == 0) TestRig.sleepMs(1);

    const start = std.Io.Clock.awake.now(testing.io).nanoseconds;
    try testing.expect(rig.eng.cancelItem(id));
    try rig.waitState(id, .canceled);
    const elapsed_ms = @divTrunc(std.Io.Clock.awake.now(testing.io).nanoseconds - start, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 150);

    // It really was mid-transfer.
    try testing.expect((rig.local.fileSize("/dl/huge.bin") orelse 0) < payload.len);
}

test "progress events are coalesced far below chunk count" {
    const interval_ms: u64 = 4;
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1, .chunk_size = 512, .progress_interval_ms = interval_ms });
    defer rig.stop();

    // 64 KiB in 512-byte mock reads with a 0.5 ms stall ≈ 64 ms transfer.
    rig.remote.read_chunk = 512;
    rig.remote.read_stall_ns = 500 * std.time.ns_per_us;
    const payload = try patternBytes(testing.allocator, 64_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/p.bin", payload);

    const started_ns = std.Io.Clock.awake.now(testing.io).nanoseconds;
    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/p.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/p.bin" },
    });
    try rig.waitState(id, .done);
    const elapsed_ms: u64 = @intCast(@divTrunc(
        std.Io.Clock.awake.now(testing.io).nanoseconds - started_ns,
        std.time.ns_per_ms,
    ));
    try rig.drainEvents();

    const reads = rig.remote.read_calls.load(.monotonic);
    const progress = rig.progressCount(id);
    try testing.expect(reads >= 125); // 64_000 / 512
    try testing.expect(progress >= 1);

    // Coalescing is TIMER-driven (timerMain sleeps progress_interval_ms),
    // so the honest invariant ties events to elapsed time, not to read
    // count: the ticker cannot emit more than one event per interval.
    //
    // Comparing against `reads` instead — the previous `progress * 4 <
    // reads` — silently required mean per-read wall time below
    // interval_ms/4 (1 ms here) while the mock only asks for a 0.5 ms
    // stall. That 2x margin is a property of the HOST, not the engine: it
    // holds on a quiet dev machine (~0.65 ms/read) and fails in a loaded
    // VM (~3 ms/read), where the engine coalesces just as correctly.
    const max_ticks = elapsed_ms / interval_ms + 2; // +2: partial ticks at both ends
    try testing.expect(progress <= max_ticks);
    // Still far below the per-chunk rate — the point of coalescing.
    try testing.expect(progress < reads);

    // The EWMA published a nonzero rate while moving.
    var max_rate: u64 = 0;
    for (rig.collected.items) |c| switch (c) {
        .progress => |p| max_rate = @max(max_rate, p.rate),
        else => {},
    };
    try testing.expect(max_rate > 0);
}

test "pause mid-transfer freezes, resume picks up from offset" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1, .chunk_size = 1024 });
    defer rig.stop();

    rig.remote.read_chunk = 1024;
    rig.remote.read_stall_ns = 2 * std.time.ns_per_ms;
    const payload = try patternBytes(testing.allocator, 100_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/pause.bin", payload);

    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/pause.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/pause.bin" },
    });
    try rig.waitState(id, .transferring);
    while ((rig.local.fileSize("/dl/pause.bin") orelse 0) == 0) TestRig.sleepMs(1);
    try testing.expect(rig.eng.pauseItem(id));
    try rig.waitState(id, .paused);

    const frozen = rig.local.fileSize("/dl/pause.bin").?;
    try testing.expect(frozen > 0 and frozen < payload.len);
    TestRig.sleepMs(10);
    try testing.expectEqual(frozen, rig.local.fileSize("/dl/pause.bin").?);

    // Speed up the remainder, then resume.
    rig.remote.read_stall_ns = 0;
    rig.remote.read_chunk = std.math.maxInt(usize);
    try testing.expect(try rig.eng.resumeItem(id));
    try rig.waitState(id, .done);
    try TestRig.expectFile(&rig.local, "/dl/pause.bin", payload);
    // Resumed, not restarted: some open_read with a nonzero offset.
    try testing.expectEqual(@as(usize, 1), rig.remote.opCountContaining("open_read /pause.bin off=0"));
    try testing.expectEqual(@as(usize, 2), rig.remote.opCountContaining("open_read /pause.bin"));
}

test "conflict policies: skip, rename, ask, resume_existing" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1 });
    defer rig.stop();

    try rig.remote.addFile("/src.txt", "0123456789");
    try rig.local.addFile("/keep.txt", "DO NOT TOUCH");
    try rig.local.addFile("/ren.txt", "old");
    try rig.local.addFile("/ask.txt", "old");
    try rig.local.addFile("/part.txt", "01234"); // valid prefix

    const skip = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/src.txt" },
        .dst = .{ .site_id = 0, .path = "/keep.txt" },
        .conflict = .skip,
    });
    try rig.waitState(skip, .done);
    try TestRig.expectFile(&rig.local, "/keep.txt", "DO NOT TOUCH");

    const ren = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/src.txt" },
        .dst = .{ .site_id = 0, .path = "/ren.txt" },
        .conflict = .rename,
    });
    try rig.waitState(ren, .done);
    try TestRig.expectFile(&rig.local, "/ren.txt", "old");
    try TestRig.expectFile(&rig.local, "/ren.txt.1", "0123456789");

    const ask = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/src.txt" },
        .dst = .{ .site_id = 0, .path = "/ask.txt" },
        .conflict = .ask,
    });
    try rig.waitState(ask, .conflict); // parked for the UI
    try TestRig.expectFile(&rig.local, "/ask.txt", "old");
    // Resolve with overwrite: it re-runs and replaces the file.
    try testing.expect(try rig.eng.resolveConflict(ask, .overwrite));
    try rig.waitState(ask, .done);
    try TestRig.expectFile(&rig.local, "/ask.txt", "0123456789");

    // A second .ask item resolved with .skip is dropped, leaving the file.
    try rig.local.addFile("/ask2.txt", "keep me");
    const ask2 = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/src.txt" },
        .dst = .{ .site_id = 0, .path = "/ask2.txt" },
        .conflict = .ask,
    });
    try rig.waitState(ask2, .conflict);
    try testing.expect(try rig.eng.resolveConflict(ask2, .skip));
    try rig.waitState(ask2, .canceled);
    try TestRig.expectFile(&rig.local, "/ask2.txt", "keep me");

    const part = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/src.txt" },
        .dst = .{ .site_id = 0, .path = "/part.txt" },
        .conflict = .resume_existing,
    });
    try rig.waitState(part, .done);
    try TestRig.expectFile(&rig.local, "/part.txt", "0123456789");
    try testing.expect(rig.remote.hasOp("open_read /src.txt off=5"));
}

test "reorder and remove on a paused queue" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1 });
    defer rig.stop();
    try rig.remote.addFile("/f", "x");

    var ids: [3]ItemId = undefined;
    var buf: [32]u8 = undefined;
    for (&ids, 0..) |*id, i| {
        const dst = try std.fmt.bufPrint(&buf, "/dl/f{d}", .{i});
        id.* = try rig.eng.enqueue(.{
            .direction = .download,
            .src = .{ .site_id = 1, .path = "/f" },
            .dst = .{ .site_id = 0, .path = dst },
            .start_paused = true,
        });
    }

    try testing.expect(rig.eng.reorder(ids[2], 0));
    {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const snap = try rig.eng.snapshot(arena.allocator());
        try testing.expectEqual(ids[2], snap[0].id);
        try testing.expectEqual(ids[0], snap[1].id);
        try testing.expectEqual(ids[1], snap[2].id);
    }

    try testing.expect(rig.eng.remove(ids[0]));
    try testing.expect(!rig.eng.remove(ids[0])); // already gone
    {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const snap = try rig.eng.snapshot(arena.allocator());
        try testing.expectEqual(@as(usize, 2), snap.len);
        try testing.expectEqual(ids[2], snap[0].id);
        try testing.expectEqual(ids[1], snap[1].id);
    }

    try testing.expectEqual(@as(?item_mod.State, null), rig.eng.stateOf(ids[0]));
    try testing.expect(try rig.eng.resumeItem(ids[1]));
    try testing.expect(try rig.eng.resumeItem(ids[2]));
    try rig.waitState(ids[1], .done);
    try rig.waitState(ids[2], .done);
}

test "rate limited download obeys the global cap" {
    var rig: TestRig = undefined;
    // 1 MB/s cap, 100 KB file with a small burst: expect ≥ ~70 ms.
    try rig.start(.{ .conns = 1, .chunk_size = 10_000, .rate_down = 1_000_000 });
    defer rig.stop();
    rig.eng.global_down.setCapacity(testing.io, 10_000);

    const payload = try patternBytes(testing.allocator, 100_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/limited.bin", payload);

    const start = std.Io.Clock.awake.now(testing.io).nanoseconds;
    const id = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/limited.bin" },
        .dst = .{ .site_id = 0, .path = "/dl/limited.bin" },
    });
    try rig.waitState(id, .done);
    const elapsed_ms = @divTrunc(std.Io.Clock.awake.now(testing.io).nanoseconds - start, std.time.ns_per_ms);

    try TestRig.expectFile(&rig.local, "/dl/limited.bin", payload);
    // Unlimited this takes ~1 ms; the cap must dominate (≥ 60 ms even with
    // generous scheduling slack on the lower bound).
    try testing.expect(elapsed_ms >= 60);
}

test "persistence: autosave, corrupt-safe load, restore, resume" {
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 1, .persist_dir = tmp.dir, .save_debounce_ms = 1 });

    try rig.remote.addFile("/keep/a.txt", "alpha");
    try rig.remote.addFile("/keep/b.txt", "bravo");
    const a = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/keep/a.txt" },
        .dst = .{ .site_id = 0, .path = "/dl/a.txt" },
        .start_paused = true,
    });
    const b = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/keep/b.txt" },
        .dst = .{ .site_id = 0, .path = "/dl/b.txt" },
        .conflict = .resume_existing,
        .start_paused = true,
    });

    // Debounced autosave lands without an explicit save call.
    {
        const deadline = std.Io.Clock.awake.now(io).nanoseconds + test_timeout_ms * std.time.ns_per_ms;
        while (true) {
            var loaded = persist.loadOrEmpty(io, tmp.dir, "queue.zon", testing.allocator);
            defer loaded.deinit();
            if (loaded.value.items.len == 2) break;
            try testing.expect(std.Io.Clock.awake.now(io).nanoseconds < deadline);
            TestRig.sleepMs(2);
        }
    }

    // "Restart": tear the engine down (final snapshot also saves) and
    // restore into a fresh one sharing the same rig mocks/queue.
    rig.eng.destroy();
    rig.eng = try Engine.create(testing.allocator, testing.io, &rig.queue, .{
        .budget = rig.budget.budget(),
        .vfs_provider = .{ .context = &rig, .getFn = TestRig.getVfs },
        .retry = .{ .max_attempts = 3, .base_ms = 1, .cap_ms = 4 },
        .progress_interval_ms = 2,
        .seed = 42,
    });
    defer rig.stop();

    var loaded = persist.loadOrEmpty(io, tmp.dir, "queue.zon", testing.allocator);
    defer loaded.deinit();
    try testing.expectEqual(@as(usize, 2), loaded.value.items.len);
    try testing.expectEqual(@as(usize, 2), try rig.eng.restore(loaded.value));

    {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const snap = try rig.eng.snapshot(arena.allocator());
        try testing.expectEqual(@as(usize, 2), snap.len);
        try testing.expectEqual(a, snap[0].id);
        try testing.expectEqual(item_mod.State.paused, snap[0].state); // offered, not forced
        try testing.expectEqualStrings("/keep/a.txt", snap[0].src.path);
        try testing.expectEqual(item_mod.ConflictPolicy.resume_existing, snap[1].conflict);
    }

    // Resume-on-start accepted: everything completes.
    try rig.eng.resumeAll();
    try rig.waitState(a, .done);
    try rig.waitState(b, .done);
    try TestRig.expectFile(&rig.local, "/dl/a.txt", "alpha");
    try TestRig.expectFile(&rig.local, "/dl/b.txt", "bravo");

    // A corrupt file on the next start degrades to a clean empty queue.
    try tmp.dir.writeFile(io, .{ .sub_path = "queue.zon", .data = "}}} torn write \x00" });
    var corrupt = persist.loadOrEmpty(io, tmp.dir, "queue.zon", testing.allocator);
    defer corrupt.deinit();
    try testing.expectEqual(@as(usize, 0), corrupt.value.items.len);
}

test "cancelAll silences a busy queue" {
    var rig: TestRig = undefined;
    try rig.start(.{ .conns = 2 });
    defer rig.stop();

    rig.remote.read_chunk = 1024;
    rig.remote.read_stall_ns = 2 * std.time.ns_per_ms;
    const payload = try patternBytes(testing.allocator, 200_000);
    defer testing.allocator.free(payload);
    try rig.remote.addFile("/c1", payload);
    try rig.remote.addFile("/c2", payload);

    const one = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/c1" },
        .dst = .{ .site_id = 0, .path = "/dl/c1" },
    });
    const two = try rig.eng.enqueue(.{
        .direction = .download,
        .src = .{ .site_id = 1, .path = "/c2" },
        .dst = .{ .site_id = 0, .path = "/dl/c2" },
    });
    try rig.waitState(one, .transferring);
    rig.eng.cancelAll();
    try rig.waitState(one, .canceled);
    try rig.waitState(two, .canceled);
}

test {
    std.testing.refAllDecls(@This());
}

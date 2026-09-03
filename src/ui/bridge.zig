//! bridge — relay_ui's AppCore, the ONLY core↔UI crossing.
//!
//! AppCore owns the process-lifetime core state: the std.Io.Threaded pool,
//! loaded settings + site list, the credential store (Keychain in the app,
//! injected fake in tests), the app-level transcript ring, the transfer
//! queue Engine, and a site-id → *SitePool registry (pools are created on
//! first connect). `init(gpa)` builds everything; `shutdown()` cancels all
//! site groups + queue workers, joins them, and deinits with zero leaks
//! under DebugAllocator (it runs on real quits).
//!
//! ## Event pump (core → UI)
//!
//! relay_core's EventQueue is the transport: producers post `CoreEvent`s;
//! the main thread drains them in batches, applied run-to-completion before
//! returning to the runloop. Scheduling, per the events.zig contract:
//!
//!  - Bridge-originated posts go through `postEvent`, which honors the
//!    queue's "caller must schedule" return by dispatching exactly ONE
//!    UI-loop drain (`pump_inflight` coalesces; the platform MainLoop owns
//!    toolkit-specific scheduling and callback lifetime).
//!  - Core-internal producers (SitePool status/keepalive, the Engine's
//!    progress timer and queue workers) post directly into the queue and
//!    DISCARD the schedule hint. The bridge recovers it two ways: every
//!    drain re-checks `EventQueue.drain_scheduled` when it finishes and
//!    reschedules itself, and a low-rate main-queue watchdog timer
//!    (`pump_watchdog_ms`) drains whenever the flag is set — so background
//!    events reach the UI within one watchdog period even when no bridge
//!    command is in flight.
//!  - `pump = .manual` (unit tests, headless) disables all dispatch wiring;
//!    tests call `drainNow()` synchronously on the test thread.
//!
//! ## Listener API (phase-2 controllers)
//!
//! `registerListener(core, comptime tag, ctx, handler)` — per-tag typed
//! listeners; any number per tag; main-thread only; listeners live for the
//! app lifetime (no unregister) and must NOT register further listeners
//! from inside a callback. `EventTag` is a bridge-level vocabulary richer
//! than the raw CoreEvent union:
//!
//!  - `.listing_progress` / `.listing_done` carry the pane token and, on
//!    success, the finished refcounted *DirSnapshot plus a default-sort
//!    index permutation (computed on the worker, allocated in the
//!    snapshot's own arena). Both are BORROWED for the duration of the
//!    dispatch: a listener that keeps the snapshot must `ref()` it; the
//!    sort index must be copied (or rebuilt) if kept.
//!  - `.op_done` reports mkdir/rename/chmod/delete/stat completion (these
//!    ride a bridge-side queue, not CoreEvent, which has no such variant).
//!    Mutating operations auto re-list the affected directory on success;
//!    stat is metadata-only and never re-lists.
//!  - The remaining tags map 1:1 onto CoreEvent payloads; slice payloads
//!    are owned by the event-queue arena and valid only during dispatch.
//!
//! ## Listings
//!
//! `listPath` streams: the worker feeds a snapshot Builder and posts
//! `listing_batch` progress counts as batches parse. Alongside the counts
//! it publishes coalesced PARTIAL snapshots (at most one per
//! `listing_partial_interval_ms`, deep-copied so they own their strings) so
//! the table shows the first rows of a huge directory immediately
//! (docs/UX.md); the finished immutable *DirSnapshot still arrives at
//! `listing_done` and is the only truth. `DirSnapshot.generation` == the
//! listing's RequestId, so stale results that land out of order are
//! detectable by controllers.
//!
//! ## Prompts
//!
//! Two producers share the `prompt_needed` event: the queue engine
//! (transfer-lane auth; ids below `bridge_prompt_id_base`, answered via
//! `Engine.resolveAuthPrompt`) and bridge `askPrompt` (connect-path host
//! key / password; ids at/above the base, answered by flagging the blocked
//! worker's PendingPrompt). `respondPrompt` routes by prompt id.
//!
//! ## Connect factories
//!
//! The full protocol connect sequence (dial, TLS, auth) is injected via
//! `Options.factory_provider` — main.zig wires the production factories
//! (factories.zig) via `setFactoryProvider` in normal runs; the default
//! factory fails with a classified diagnostic (headless tests).

const std = @import("std");
const relay = @import("relay_core");
const MainLoop = @import("platform/main_loop.zig").MainLoop;
const Paths = @import("platform/paths.zig").Paths;

const Allocator = std.mem.Allocator;

const events_mod = relay.events;
const settings_mod = relay.settings;
const sites_mod = relay.sites;
const transcript_mod = relay.transcript;
const diag_mod = relay.diag;
const CancelToken = relay.cancel.CancelToken;
const cred_store_mod = relay.cred.store;
const vfs_mod = relay.vfs.iface;
const local_mod = relay.vfs.local;
const snapshot_mod = relay.vfs.snapshot;
const path_mod = relay.vfs.path;
const site_pool_mod = relay.pool.site_pool;
const engine_mod = relay.queue.engine;
const item_mod = relay.queue.item;
const persist_mod = relay.queue.persist;

const DirSnapshot = snapshot_mod.DirSnapshot;
const Diagnostics = diag_mod.Diagnostics;

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

pub const app_support_bundle_id = "us.doriantull.relay";
pub const settings_file = "settings.zon";
pub const sites_file = "sites.zon";
pub const queue_file = "queue.zon";

/// Watchdog drain period (gcd pump). Core producers discard the queue's
/// schedule hint, so this bounds their event latency; the engine already
/// coalesces progress at ~30 Hz, so 25 ms adds no visible lag.
pub const pump_watchdog_ms: u64 = 25;

pub const PumpMode = enum {
    /// Real app: drains ride dispatch_async onto the main queue.
    gcd,
    /// Tests/headless: no dispatch; call `drainNow()` synchronously.
    manual,
};

pub const RequestId = u64;
pub const PaneToken = u64;
pub const TransferSpec = engine_mod.Spec;
pub const ItemId = item_mod.ItemId;
pub const RemoveResult = engine_mod.RemoveResult;
pub const ConflictPolicy = item_mod.ConflictPolicy;

/// Bridge-issued prompt ids start here; the queue engine's start at 1, so
/// `respondPrompt` can route an answer by id alone.
pub const bridge_prompt_id_base: u64 = 1 << 32;

/// Builds the per-site connection factory (the full connect sequence).
/// Injected so protocol wiring and tests stay out of the bridge.
pub const FactoryProvider = struct {
    ctx: *anyopaque,
    makeFn: *const fn (ctx: *anyopaque, site: *const sites_mod.Site) site_pool_mod.ConnFactory,
};

pub const Options = struct {
    pump: PumpMode = .gcd,
    /// Platform UI-loop service. Required for `.gcd`; omitted by manual
    /// headless tests. The name of the mode is retained for source
    /// compatibility, but the bridge no longer imports libdispatch.
    main_loop: ?MainLoop = null,
    /// Platform application directories. Required when `config_dir` is
    /// not overridden by a test or smoke run.
    paths: ?Paths = null,
    /// Override the Application Support dir (tests: a tmp dir). Borrowed;
    /// must outlive the AppCore. null = open/create the real one.
    config_dir: ?std.Io.Dir = null,
    /// Override the local-pane filesystem root (tests). Borrowed; must be
    /// opened with `.iterate = true`. null = "/".
    local_root: ?std.Io.Dir = null,
    /// Platform credential store (macOS Keychain, Linux backend, or fake).
    /// Required: relay_ui never selects a platform backend itself.
    cred_store: ?cred_store_mod.CredStore = null,
    factory_provider: ?FactoryProvider = null,
};

// --- listener payloads ------------------------------------------------------

pub const ListingProgress = struct {
    request_id: RequestId,
    pane_token: PaneToken,
    /// Entries parsed so far (the status bar count-up).
    entries_so_far: u64,
    /// Coalesced partial snapshot of the listing so far (docs/UX.md: first
    /// rows visible immediately). Owns every string (deep-copied), so it
    /// may outlive the listing. Borrowed for this dispatch; `ref()` to
    /// keep. null when no new partial was published since the last event.
    snapshot: ?*DirSnapshot = null,
    /// Default-sort permutation over `snapshot`, arena-owned by it.
    /// Borrowed for this dispatch; copy to keep.
    sort_index: []const u32 = &.{},
    /// Wall time spent inside the protocol list call so far (worker-
    /// bracketed) — the status bar's "latency honesty" (docs/UX.md).
    elapsed_ms: u64 = 0,
};

pub const ListingDone = struct {
    request_id: RequestId,
    pane_token: PaneToken,
    /// null exactly when `failure` is set. Borrowed for this dispatch;
    /// `ref()` to keep (`generation` == request_id for staleness checks).
    snapshot: ?*DirSnapshot,
    /// Default-sort permutation (name ascending, dirs first), arena-owned
    /// by the snapshot. Borrowed for this dispatch; copy to keep.
    sort_index: []const u32,
    /// Message is event-arena-owned; copy to keep.
    failure: ?events_mod.Failure,
    /// Total wall time of the protocol list call (worker-bracketed); 0 when
    /// the call never started. Drives "· {d} ms" in remote status bars.
    elapsed_ms: u64 = 0,
};

pub const OpKind = enum { mkdir, rename, chmod, delete, stat };

pub const OpDone = struct {
    op: OpKind,
    request_id: RequestId = 0,
    pane_token: PaneToken,
    site_id: u64,
    /// Primary path (`from` for rename). Borrowed for this dispatch.
    path: []const u8,
    success: bool,
    mtime: ?i64 = null,
    /// Set exactly when `!success`; message borrowed for this dispatch.
    failure: ?events_mod.Failure,
};

pub const EventTag = enum {
    listing_progress,
    listing_done,
    transfer_progress,
    transfer_state,
    site_status,
    prompt_needed,
    transcript_line,
    op_done,
};

pub fn Payload(comptime tag: EventTag) type {
    return switch (tag) {
        .listing_progress => ListingProgress,
        .listing_done => ListingDone,
        .transfer_progress => events_mod.CoreEvent.TransferProgress,
        .transfer_state => events_mod.CoreEvent.TransferStateChange,
        .site_status => events_mod.CoreEvent.SiteStatusChange,
        .prompt_needed => events_mod.CoreEvent.PromptNeeded,
        .transcript_line => events_mod.CoreEvent.TranscriptLine,
        .op_done => OpDone,
    };
}

const tag_count = @typeInfo(EventTag).@"enum".fields.len;

const Listener = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, payload: *const anyopaque) void,
};

// --- prompts -----------------------------------------------------------------

/// Routes a UI answer back to the prompt's producer. `prompt_needed`
/// events carry (site_id, prompt_id); echo them here.
pub const PromptToken = struct {
    site_id: u64,
    prompt_id: u64,
};

pub const PromptAnswer = union(enum) {
    /// password / keyboard_interactive: the UI updated the cred store (or
    /// gave up); true = retry (blocked queue lane / connect-path fetch).
    auth: bool,
    /// host_key: accept the fingerprint and continue?
    host_key: bool,
};

/// One bridge-issued prompt a worker is blocked on (askPrompt). The asker
/// owns it: it is created, registered, and — after the answer or a cancel —
/// unregistered and destroyed by the asking worker. `respondPrompt` only
/// flips the flags, and only while the entry is still registered (under
/// `prompts_mutex`), so the answer can never touch freed memory.
const PendingPrompt = struct {
    answered: std.atomic.Value(bool) = .init(false),
    accepted: std.atomic.Value(bool) = .init(false),
};

pub const SmokeReport = struct {
    drains: u64,
    events_dispatched: u64,
    pending_listings: usize,
    sites_loaded: usize,
};

// ---------------------------------------------------------------------------
// AppCore
// ---------------------------------------------------------------------------

/// The one live AppCore of a gcd-pumped process. Drain blocks and watchdog
/// ticks already sitting in the main queue when the app quits consult this
/// before touching the core — `shutdown()` clears it first, so a stale
/// block is a no-op instead of a use-after-free. Main-thread accesses are
/// serialized; atomic only because `schedulePump` runs on workers.
var g_live_core: std.atomic.Value(?*AppCore) = .init(null);

pub const AppCore = struct {
    gpa: Allocator,
    threaded: std.Io.Threaded,
    io: std.Io,
    pump_mode: PumpMode,
    main_loop: ?MainLoop,
    factory_provider: ?FactoryProvider,

    config_dir: std.Io.Dir,
    owns_config_dir: bool,
    settings: settings_mod.Settings,
    /// Owns every slice in `site_list` (single arena).
    sites_parsed: ?sites_mod.Parsed,
    site_list: sites_mod.SiteList,

    cred_store: cred_store_mod.CredStore,

    /// App-level protocol/transcript ring (pool reconnect notes etc.).
    transcript: transcript_mod.Transcript,
    events_q: events_mod.EventQueue,
    engine: *engine_mod.Engine,

    local_root: std.Io.Dir,
    owns_local_root: bool,
    local_vfs: local_mod.LocalVfs,

    /// Engine connection budget; mirrors settings.connections_per_site
    /// (atomic: read by queue workers, written on prefs save).
    budget_conns: std.atomic.Value(u8),

    /// Guards the runtime registry against worker-thread readers
    /// (VfsProvider, cred fetches). Mutation is main-thread-only.
    sites_mutex: std.Io.Mutex = .init,
    site_runtimes: std.AutoHashMapUnmanaged(u64, *SiteRuntime) = .empty,
    /// Replaced (reconnected) runtimes stay alive until shutdown so stale
    /// Vfs handles held by in-flight workers never dangle; their shut-down
    /// pools just fail fast.
    retired_runtimes: std.ArrayList(*SiteRuntime) = .empty,

    /// Owns all bridge workers (connect/disconnect/list/op).
    group: std.Io.Group = .init,

    // --- pump state ---
    pump_inflight: std.atomic.Value(bool) = .init(false),
    pump_timer: ?MainLoop.Timer = null,

    // --- main-thread-only state ---
    listeners: [tag_count]std.ArrayList(Listener),
    next_request_id: RequestId = 1,
    pending_listings: std.AutoHashMapUnmanaged(RequestId, *ListingJob) = .empty,
    drains: u64 = 0,
    events_dispatched: u64 = 0,
    shutdown_done: bool = false,

    // --- op results (worker → main); see events.zig for the lock choice ---
    ops_mutex: std.atomic.Mutex = .unlocked,
    pending_ops: std.ArrayList(*OpJob) = .empty,

    // --- prompts (worker ↔ main); ids namespaced above the engine's ---
    prompts_mutex: std.atomic.Mutex = .unlocked,
    next_prompt_id: u64 = bridge_prompt_id_base,
    pending_prompts: std.AutoHashMapUnmanaged(u64, *PendingPrompt) = .empty,
    /// prompt_needed listeners registered; 0 = headless, prompts auto-deny.
    prompt_listeners: std.atomic.Value(usize) = .init(0),

    /// Streaming listings: coalescing interval for intermediate (partial)
    /// snapshots. Tests set 0 to publish one per sink batch.
    listing_partial_interval_ms: u64 = 150,

    // ------------------------------------------------------------------ //
    // Lifecycle

    pub fn init(gpa: Allocator, paths: Paths, main_loop: MainLoop) !*AppCore {
        return initOptions(gpa, .{ .paths = paths, .main_loop = main_loop });
    }

    pub fn initOptions(gpa: Allocator, options: Options) !*AppCore {
        if (options.pump == .gcd and options.main_loop == null)
            return error.MainLoopRequired;
        if (options.config_dir == null and options.paths == null)
            return error.PathsRequired;
        if (options.cred_store == null)
            return error.CredStoreRequired;

        const self = try gpa.create(AppCore);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .threaded = .init(gpa, .{}),
            .io = undefined,
            .pump_mode = options.pump,
            .main_loop = options.main_loop,
            .factory_provider = options.factory_provider,
            .config_dir = undefined,
            .owns_config_dir = false,
            .settings = .{},
            .sites_parsed = null,
            .site_list = .{},
            .cred_store = undefined,
            .transcript = undefined,
            .events_q = undefined,
            .engine = undefined,
            .local_root = undefined,
            .owns_local_root = false,
            .local_vfs = undefined,
            .budget_conns = .init(3),
            .listeners = @splat(.empty),
        };
        self.io = self.threaded.io();
        errdefer self.threaded.deinit();
        const io = self.io;

        // Application Support dir, created on first run.
        if (options.config_dir) |dir| {
            self.config_dir = dir;
        } else {
            const dir_path = try options.paths.?.configDir(gpa);
            defer gpa.free(dir_path);
            self.config_dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
            self.owns_config_dir = true;
        }
        errdefer if (self.owns_config_dir) self.config_dir.close(io);

        // Settings/sites: a missing or corrupt file degrades to defaults —
        // a bad config must never block launch. Only OOM propagates.
        self.settings = settings_mod.load(io, self.config_dir, settings_file, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => settings_mod.Settings{},
        };
        self.budget_conns.store(clampConns(self.settings.connections_per_site), .monotonic);

        self.sites_parsed = sites_mod.load(io, self.config_dir, sites_file, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (self.sites_parsed) |parsed| self.site_list = parsed.value;
        errdefer if (self.sites_parsed) |*parsed| parsed.deinit();

        self.cred_store = options.cred_store.?;

        self.transcript = try transcript_mod.Transcript.init(gpa, .{});
        errdefer self.transcript.deinit();

        self.events_q = events_mod.EventQueue.init(gpa);
        errdefer self.events_q.deinit();

        if (options.local_root) |dir| {
            self.local_root = dir;
        } else {
            self.local_root = std.Io.Dir.cwd().openDir(io, "/", .{ .iterate = true }) catch
                return error.LocalRootUnavailable;
            self.owns_local_root = true;
        }
        errdefer if (self.owns_local_root) self.local_root.close(io);
        self.local_vfs = .init(gpa, self.local_root);

        self.engine = try engine_mod.Engine.create(gpa, io, &self.events_q, .{
            .budget = .{ .context = self, .connsFn = budgetConns },
            .vfs_provider = .{ .context = self, .getFn = vfsProviderGet },
            .rate_up = self.settings.rate_limit_up,
            .rate_down = self.settings.rate_limit_down,
            .persist_dir = self.config_dir,
            .persist_sub_path = queue_file,
        });

        if (self.pump_mode == .gcd) {
            g_live_core.store(self, .release);
            // Watchdog for core-posted events (see file header). Failure to
            // create it degrades to command-driven drains only.
            self.pump_timer = self.main_loop.?.startTimer(
                pump_watchdog_ms,
                self,
                pumpTimerTick,
            ) catch null;
        }
        return self;
    }

    /// Full graceful teardown: cancel + join every worker (site pools,
    /// queue engine, bridge group), persist the queue, free everything,
    /// destroy self. Main thread only; call exactly once (real quits).
    pub fn shutdown(self: *AppCore) void {
        std.debug.assert(!self.shutdown_done);
        self.shutdown_done = true;
        const gpa = self.gpa;
        const io = self.io;

        // Stale main-queue drain blocks become no-ops from here on.
        _ = g_live_core.cmpxchgStrong(self, null, .acq_rel, .acquire);

        if (self.pump_timer) |timer| {
            self.main_loop.?.cancelTimer(timer);
            self.pump_timer = null;
        }

        // Wake everything that could be blocked: listing tokens, then the
        // site pools (disconnect broadcasts checkout waiters and joins the
        // keepalive workers) so engine + bridge workers fail fast.
        var job_it = self.pending_listings.valueIterator();
        while (job_it.next()) |job| job.*.token.cancel();

        var rt_it = self.site_runtimes.valueIterator();
        while (rt_it.next()) |rt| rt.*.pool.disconnect(io);
        for (self.retired_runtimes.items) |rt| rt.pool.disconnect(io);

        self.group.cancel(io); // joins connect/disconnect/list/op workers
        self.engine.destroy(); // joins queue workers + timer; final persist

        var rt_free_it = self.site_runtimes.valueIterator();
        while (rt_free_it.next()) |rt| self.destroyRuntime(rt.*);
        self.site_runtimes.deinit(gpa);
        for (self.retired_runtimes.items) |rt| self.destroyRuntime(rt);
        self.retired_runtimes.deinit(gpa);

        // Undispatched listing results hold the only snapshot refs; clean
        // them here so nothing leaks when events never drained.
        var job_free_it = self.pending_listings.valueIterator();
        while (job_free_it.next()) |job| self.destroyListingJob(job.*);
        self.pending_listings.deinit(gpa);

        lockSpin(&self.ops_mutex);
        for (self.pending_ops.items) |op| self.destroyOpJob(op);
        self.pending_ops.deinit(gpa);
        self.ops_mutex.unlock();

        // Prompt waiters were canceled and joined with their workers above
        // (each asker frees its own entry on the way out), so the map is
        // empty here; reclaim defensively anyway.
        lockSpin(&self.prompts_mutex);
        var prompt_it = self.pending_prompts.valueIterator();
        while (prompt_it.next()) |pending| gpa.destroy(pending.*);
        self.pending_prompts.deinit(gpa);
        self.prompts_mutex.unlock();

        for (&self.listeners) |*list| list.deinit(gpa);

        self.events_q.deinit();
        self.transcript.deinit();
        if (self.sites_parsed) |*parsed| parsed.deinit();
        if (self.owns_local_root) self.local_root.close(io);
        if (self.owns_config_dir) self.config_dir.close(io);
        self.threaded.deinit();
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------ //
    // Listener registry (main thread only)

    /// Register `handler` for `tag`. `ctx` must be a (non-const) pointer
    /// that outlives its registration: listeners live until
    /// `unregisterListeners(ctx)` (a controller detaching, e.g. a tab
    /// closing) or shutdown. Multiple listeners per tag are dispatched in
    /// registration order. Never call from inside a listener callback.
    pub fn registerListener(
        self: *AppCore,
        comptime tag: EventTag,
        ctx: anytype,
        comptime handler: fn (@TypeOf(ctx), Payload(tag)) void,
    ) error{OutOfMemory}!void {
        const Ctx = @TypeOf(ctx);
        comptime {
            const info = @typeInfo(Ctx);
            if (info != .pointer or info.pointer.is_const)
                @compileError("listener ctx must be a mutable pointer");
        }
        const Thunk = struct {
            fn call(erased: *anyopaque, payload_ptr: *const anyopaque) void {
                const typed_ctx: Ctx = @ptrCast(@alignCast(erased));
                const typed_payload: *const Payload(tag) = @ptrCast(@alignCast(payload_ptr));
                handler(typed_ctx, typed_payload.*);
            }
        };
        try self.listeners[@intFromEnum(tag)].append(self.gpa, .{
            .ctx = @ptrCast(ctx),
            .call = Thunk.call,
        });
        if (tag == .prompt_needed) _ = self.prompt_listeners.fetchAdd(1, .monotonic);
    }

    /// Remove every listener registered with `ctx`, across all tags (a
    /// controller detaching, e.g. a tab closing). Main thread only, like
    /// registerListener; never call from inside a listener callback, and
    /// never after `shutdown()` (which destroys the AppCore). orderedRemove
    /// keeps the documented dispatch order of the remaining listeners.
    pub fn unregisterListeners(self: *AppCore, ctx: *anyopaque) void {
        std.debug.assert(!self.shutdown_done);
        for (&self.listeners, 0..) |*list, tag_idx| {
            var i = list.items.len;
            while (i > 0) {
                i -= 1;
                if (list.items[i].ctx != ctx) continue;
                _ = list.orderedRemove(i);
                if (tag_idx == @intFromEnum(EventTag.prompt_needed))
                    _ = self.prompt_listeners.fetchSub(1, .monotonic);
            }
        }
    }

    fn emit(self: *AppCore, comptime tag: EventTag, payload: Payload(tag)) void {
        self.events_dispatched += 1;
        for (self.listeners[@intFromEnum(tag)].items) |listener| {
            listener.call(listener.ctx, @ptrCast(&payload));
        }
    }

    // ------------------------------------------------------------------ //
    // Event pump

    /// Bridge-side post: honors the EventQueue scheduling contract.
    ///
    /// OOM policy (explicit, BACKLOG hygiene): DROP the event and warn.
    /// Events are best-effort towards the UI — the queue's own state stays
    /// consistent and every consumer reconciles from truth (snapshots,
    /// re-lists, engine.snapshot()), so a missed update self-heals; a
    /// crash on the event path would not. Core producers (engine.post,
    /// site_pool status posts) apply the same drop policy at their sites.
    fn postEvent(self: *AppCore, event: events_mod.CoreEvent) void {
        const must_schedule = self.events_q.post(event) catch {
            std.log.warn("bridge: event queue OOM; dropped a {s} event", .{@tagName(event)});
            return;
        };
        if (must_schedule) self.schedulePump();
    }

    /// Thread-safe. One dispatch_async per turn (`pump_inflight`).
    fn schedulePump(self: *AppCore) void {
        if (self.pump_mode != .gcd) return;
        if (self.pump_inflight.cmpxchgStrong(false, true, .seq_cst, .seq_cst) != null) return;
        self.main_loop.?.post(self, drainFromDispatch);
    }

    /// Worker-side nudge after operations whose events were posted by core
    /// code that discards the schedule hint (pool status, engine state).
    fn kickPump(self: *AppCore) void {
        if (self.pump_mode != .gcd) return;
        if (self.events_q.drain_scheduled.load(.seq_cst) and
            !self.pump_inflight.load(.seq_cst)) self.schedulePump();
    }

    fn drainFromDispatch(self: *AppCore) void {
        if (g_live_core.load(.acquire) != self) return; // dispatched pre-quit
        self.drainOnMain();
        self.pump_inflight.store(false, .seq_cst);
        // Posts that landed mid-drain re-armed the flag but their schedule
        // hint may have been discarded; pick them up now.
        if (self.events_q.drain_scheduled.load(.seq_cst)) self.schedulePump();
    }

    fn pumpTimerTick(self: *AppCore) void {
        if (g_live_core.load(.acquire) != self) return; // tick raced the quit
        if (self.events_q.drain_scheduled.load(.seq_cst) or self.hasPendingOps())
            self.drainOnMain();
    }

    /// Synchronous drain (manual pump, smoke). Main thread only; safe in
    /// gcd mode too because all drains are main-thread-serialized.
    pub fn drainNow(self: *AppCore) void {
        self.drainOnMain();
    }

    fn drainOnMain(self: *AppCore) void {
        self.drains += 1;
        const batch = self.events_q.drain();
        for (batch) |event| self.applyCoreEvent(event);
        self.applyPendingOps();
    }

    fn applyCoreEvent(self: *AppCore, event: events_mod.CoreEvent) void {
        switch (event) {
            .listing_batch => |e| {
                const job = self.pending_listings.get(e.request_id) orelse return;
                // Consume the newest unclaimed partial snapshot (if any);
                // it is dispatched borrowed and dropped right after.
                lockSpin(&job.partial_mutex);
                const partial = job.partial;
                const partial_sort = job.partial_sort;
                job.partial = null;
                job.partial_sort = &.{};
                job.partial_mutex.unlock();
                self.emit(.listing_progress, .{
                    .request_id = e.request_id,
                    .pane_token = job.pane_token,
                    .entries_so_far = e.entry_count,
                    .snapshot = partial,
                    .sort_index = partial_sort,
                    // Written by the worker before each batch post; the
                    // queue handoff orders the write before this read.
                    .elapsed_ms = job.elapsed_ms,
                });
                if (partial) |snap| snap.unref();
            },
            .listing_done => |e| {
                const kv = self.pending_listings.fetchRemove(e.request_id) orelse return;
                const job = kv.value;
                defer self.destroyListingJob(job);
                self.emit(.listing_done, .{
                    .request_id = e.request_id,
                    .pane_token = job.pane_token,
                    .snapshot = job.snapshot,
                    .sort_index = job.sort_index,
                    .failure = e.failure,
                    .elapsed_ms = job.elapsed_ms,
                });
            },
            .transfer_progress => |e| self.emit(.transfer_progress, e),
            .transfer_state => |e| self.emit(.transfer_state, e),
            .site_status => |e| self.emit(.site_status, e),
            .prompt_needed => |e| self.emit(.prompt_needed, e),
            .transcript_line => |e| self.emit(.transcript_line, e),
        }
    }

    fn takePendingOp(self: *AppCore) ?*OpJob {
        lockSpin(&self.ops_mutex);
        defer self.ops_mutex.unlock();
        if (self.pending_ops.items.len == 0) return null;
        return self.pending_ops.orderedRemove(0);
    }

    fn hasPendingOps(self: *AppCore) bool {
        lockSpin(&self.ops_mutex);
        defer self.ops_mutex.unlock();
        return self.pending_ops.items.len != 0;
    }

    fn applyPendingOps(self: *AppCore) void {
        while (self.takePendingOp()) |op| {
            defer self.destroyOpJob(op);
            self.emit(.op_done, .{
                .op = op.kind,
                .request_id = op.request_id,
                .pane_token = op.pane_token,
                .site_id = op.site_id,
                .path = op.path,
                .success = op.success,
                .mtime = op.mtime,
                .failure = if (op.success) null else .{
                    .class = op.failure_class,
                    .protocol_code = op.failure_code,
                    .message = op.failure_msg_buf[0..op.failure_msg_len],
                },
            });
            // Re-list on success so every pane showing the directory
            // refreshes from truth (optimistic UI reconciliation).
            if (op.success and op.kind != .stat) {
                _ = self.listPath(op.pane_token, op.site_id, op.refresh_dir) catch 0;
            }
        }
    }

    // ------------------------------------------------------------------ //
    // Commands: sites (all non-blocking, main thread)

    /// Install the protocol connect factories. The production provider
    /// (factories.zig) needs the AppCore pointer, so it cannot ride
    /// Options; main.zig calls this right after init, before any connect.
    pub fn setFactoryProvider(self: *AppCore, provider: FactoryProvider) void {
        self.factory_provider = provider;
    }

    pub fn findSite(self: *const AppCore, site_id: u64) ?*const sites_mod.Site {
        for (self.site_list.sites) |*site| {
            if (site.id == site_id) return site;
        }
        return null;
    }

    /// Spawns the connect probe (browse checkout + release) on the pool;
    /// `site_status` events flow back through the pump. Idempotent while
    /// connected; after a disconnect the pool is rebuilt.
    pub fn connectSite(self: *AppCore, site_id: u64) !void {
        const site = self.findSite(site_id) orelse return error.UnknownSite;

        self.sites_mutex.lockUncancelable(self.io);
        var locked = true;
        defer if (locked) self.sites_mutex.unlock(self.io);

        var existing = self.site_runtimes.get(site_id);
        if (existing) |rt| {
            // Racy read of pool.shutdown is fine: worst case we reuse a
            // pool mid-disconnect and the probe fails with "disconnected".
            if (rt.pool.shutdown) {
                try self.retired_runtimes.append(self.gpa, rt);
                _ = self.site_runtimes.remove(site_id);
                existing = null;
            }
        }
        const runtime = existing orelse try self.createRuntimeLocked(site);
        self.sites_mutex.unlock(self.io);
        locked = false;

        try self.group.concurrent(self.io, connectWorker, .{runtime});
    }

    /// Cancels the site's queued transfers, then disconnects the pool
    /// (worker-side: pool.disconnect joins the keepalive worker).
    pub fn disconnectSite(self: *AppCore, site_id: u64) void {
        self.sites_mutex.lockUncancelable(self.io);
        const runtime = self.site_runtimes.get(site_id);
        self.sites_mutex.unlock(self.io);
        const rt = runtime orelse return;
        self.group.concurrent(self.io, disconnectWorker, .{rt}) catch {
            // Spawn failed: do it inline (bounded — cancel + join keepalive).
            disconnectWorker(rt);
        };
    }

    fn createRuntimeLocked(self: *AppCore, site: *const sites_mod.Site) error{OutOfMemory}!*SiteRuntime {
        const rt = try self.gpa.create(SiteRuntime);
        errdefer self.gpa.destroy(rt);
        const pool = try self.gpa.create(site_pool_mod.SitePool);
        errdefer self.gpa.destroy(pool);

        rt.* = .{ .core = self, .site_id = site.id, .pool = pool, .backend = undefined };
        rt.backend = switch (site.protocol) {
            .ftp, .ftps => .{ .ftp = try self.gpa.create(relay.vfs.ftp_backend.FtpVfs) },
            .sftp => .{ .sftp = try self.gpa.create(relay.vfs.sftp_backend.SftpVfs) },
        };
        errdefer switch (rt.backend) {
            .ftp => |b| self.gpa.destroy(b),
            .sftp => |b| self.gpa.destroy(b),
        };
        try self.site_runtimes.put(self.gpa, site.id, rt);

        const factory = if (self.factory_provider) |provider|
            provider.makeFn(provider.ctx, site)
        else
            unwiredFactory();
        pool.* = site_pool_mod.SitePool.init(self.gpa, .{
            .site_id = site.id,
            .protocol = site.protocol,
            .host = site.host, // arena-owned by sites_parsed; outlives the pool
            .port = site.effectivePort(),
            .creds = .{ .ctx = rt, .fetchFn = SiteRuntime.fetchCreds },
            .factory = factory,
            .max_transfer_conns = self.budget_conns.load(.monotonic),
            .keepalive_interval_ms = @as(u64, self.settings.keepalive_interval_s) * std.time.ms_per_s,
        }, .{ .events = &self.events_q, .transcript = &self.transcript });
        switch (rt.backend) {
            .ftp => |b| b.* = .init(self.gpa, pool),
            .sftp => |b| b.* = .init(self.gpa, pool),
        }
        return rt;
    }

    fn destroyRuntime(self: *AppCore, rt: *SiteRuntime) void {
        rt.pool.disconnect(self.io); // idempotent
        rt.pool.deinit(self.io);
        self.gpa.destroy(rt.pool);
        switch (rt.backend) {
            .ftp => |b| self.gpa.destroy(b),
            .sftp => |b| self.gpa.destroy(b),
        }
        if (rt.secret) |secret| cred_store_mod.freeSecret(self.gpa, secret);
        for (rt.retired_secrets.items) |secret| cred_store_mod.freeSecret(self.gpa, secret);
        rt.retired_secrets.deinit(self.gpa);
        self.gpa.destroy(rt);
    }

    // ------------------------------------------------------------------ //
    // Commands: listings

    /// Start a streaming listing. Local pane: site_id ==
    /// `item_mod.local_site_id` (0); remote panes use the site id. Returns
    /// the RequestId that tags every resulting event (and the snapshot
    /// generation). Cancel with `cancelListing`.
    pub fn listPath(
        self: *AppCore,
        pane_token: PaneToken,
        site_id: u64,
        raw_path: []const u8,
    ) error{ InvalidPath, OutOfMemory, ConcurrencyUnavailable }!RequestId {
        const norm = try path_mod.normalize(self.gpa, raw_path);
        errdefer self.gpa.free(norm);
        return self.startListing(pane_token, site_id, norm);
    }

    /// Like listPath, but lists the site's default directory (FTP login
    /// dir, SFTP home) — for sites with no configured remote path. The
    /// worker resolves the real path via Vfs.defaultPath before listing,
    /// so the resulting snapshot carries the resolved absolute path.
    pub fn listDefaultPath(
        self: *AppCore,
        pane_token: PaneToken,
        site_id: u64,
    ) error{ OutOfMemory, ConcurrencyUnavailable }!RequestId {
        // Empty path = the worker-resolved sentinel (normalize never
        // produces "": it maps "" to "/").
        const sentinel = try self.gpa.alloc(u8, 0);
        errdefer self.gpa.free(sentinel);
        return self.startListing(pane_token, site_id, sentinel);
    }

    /// `owned_path` is gpa-owned and adopted by the job (freed with it).
    fn startListing(
        self: *AppCore,
        pane_token: PaneToken,
        site_id: u64,
        owned_path: []u8,
    ) error{ OutOfMemory, ConcurrencyUnavailable }!RequestId {
        const job = try self.gpa.create(ListingJob);
        errdefer self.gpa.destroy(job);
        const request_id = self.next_request_id;
        job.* = .{
            .core = self,
            .request_id = request_id,
            .pane_token = pane_token,
            .site_id = site_id,
            .path = owned_path,
        };
        try self.pending_listings.put(self.gpa, request_id, job);
        errdefer _ = self.pending_listings.remove(request_id);
        try self.group.concurrent(self.io, listWorker, .{job});
        self.next_request_id += 1;
        return request_id;
    }

    /// True if the listing was still pending; its `listing_done` then
    /// arrives with a `.cancel`-classified failure.
    pub fn cancelListing(self: *AppCore, request_id: RequestId) bool {
        const job = self.pending_listings.get(request_id) orelse return false;
        job.token.cancel();
        return true;
    }

    fn destroyListingJob(self: *AppCore, job: *ListingJob) void {
        if (job.snapshot) |snap| snap.unref();
        if (job.partial) |snap| snap.unref();
        self.gpa.free(job.path);
        self.gpa.destroy(job);
    }

    fn postListingFailure(self: *AppCore, request_id: RequestId, failure: events_mod.Failure) void {
        self.postEvent(.{ .listing_done = .{
            .request_id = request_id,
            .failure = failure,
        } });
    }

    // ------------------------------------------------------------------ //
    // Commands: file operations (re-list on success)

    pub const OpStartError = error{ InvalidPath, OutOfMemory, ConcurrencyUnavailable };

    pub fn mkdirPath(self: *AppCore, pane_token: PaneToken, site_id: u64, raw_path: []const u8) OpStartError!void {
        _ = try self.startOp(.mkdir, pane_token, site_id, raw_path, null, 0, false);
    }

    pub fn renamePath(self: *AppCore, pane_token: PaneToken, site_id: u64, raw_from: []const u8, raw_to: []const u8) OpStartError!void {
        _ = try self.startOp(.rename, pane_token, site_id, raw_from, raw_to, 0, false);
    }

    pub fn chmodPath(self: *AppCore, pane_token: PaneToken, site_id: u64, raw_path: []const u8, mode: u16) OpStartError!void {
        _ = try self.startOp(.chmod, pane_token, site_id, raw_path, null, mode, false);
    }

    pub fn deletePath(self: *AppCore, pane_token: PaneToken, site_id: u64, raw_path: []const u8, recursive: bool) OpStartError!void {
        _ = try self.startOp(.delete, pane_token, site_id, raw_path, null, 0, recursive);
    }

    pub fn statPath(self: *AppCore, site_id: u64, raw_path: []const u8) OpStartError!RequestId {
        return self.startOp(.stat, 0, site_id, raw_path, null, 0, false);
    }

    pub fn ensureLocalDir(self: *AppCore, raw_path: []const u8) !void {
        const normalized = try path_mod.normalize(self.gpa, raw_path);
        defer self.gpa.free(normalized);
        if (normalized.len > 1) try self.local_root.createDirPath(self.io, normalized[1..]);
    }

    fn startOp(
        self: *AppCore,
        kind: OpKind,
        pane_token: PaneToken,
        site_id: u64,
        raw_path: []const u8,
        raw_to: ?[]const u8,
        mode: u16,
        recursive: bool,
    ) OpStartError!RequestId {
        const norm = try path_mod.normalize(self.gpa, raw_path);
        errdefer self.gpa.free(norm);
        var to_norm: ?[]u8 = null;
        errdefer if (to_norm) |t| self.gpa.free(t);
        if (raw_to) |t| to_norm = try path_mod.normalize(self.gpa, t);
        const refresh = try self.gpa.dupe(u8, path_mod.parent(norm) orelse "/");
        errdefer self.gpa.free(refresh);
        const job = try self.gpa.create(OpJob);
        errdefer self.gpa.destroy(job);
        const request_id = self.next_request_id;
        job.* = .{
            .core = self,
            .kind = kind,
            .request_id = request_id,
            .pane_token = pane_token,
            .site_id = site_id,
            .path = norm,
            .to_path = to_norm,
            .mode = mode,
            .recursive = recursive,
            .refresh_dir = refresh,
        };
        try self.group.concurrent(self.io, opWorker, .{job});
        self.next_request_id += 1;
        return request_id;
    }

    fn destroyOpJob(self: *AppCore, op: *OpJob) void {
        self.gpa.free(op.path);
        if (op.to_path) |t| self.gpa.free(t);
        self.gpa.free(op.refresh_dir);
        self.gpa.destroy(op);
    }

    // ------------------------------------------------------------------ //
    // Commands: transfer queue (thin pass-throughs; the engine locks
    // briefly and never across I/O, so these are main-thread safe)

    pub fn enqueueTransfer(self: *AppCore, spec: TransferSpec) !ItemId {
        return self.engine.enqueue(spec);
    }

    pub fn pauseTransfer(self: *AppCore, id: ItemId) bool {
        return self.engine.pauseItem(id);
    }

    pub fn resumeTransfer(self: *AppCore, id: ItemId) !bool {
        return self.engine.resumeItem(id);
    }

    pub fn cancelTransfer(self: *AppCore, id: ItemId) bool {
        return self.engine.cancelItem(id);
    }

    /// Resolve a conflict-parked transfer (TransferState.conflict): re-run it
    /// under `policy` (.overwrite) or drop it (.skip). See engine.resolveConflict.
    pub fn resolveConflict(self: *AppCore, id: ItemId, policy: ConflictPolicy) !bool {
        return self.engine.resolveConflict(id, policy);
    }

    pub fn removeTransfer(self: *AppCore, id: ItemId) bool {
        return self.engine.remove(id);
    }

    pub fn removeTransferDetailed(self: *AppCore, id: ItemId) RemoveResult {
        return self.engine.removeDetailed(id);
    }

    pub fn reorderTransfer(self: *AppCore, id: ItemId, new_index: usize) bool {
        return self.engine.reorder(id, new_index);
    }

    pub fn pauseAllTransfers(self: *AppCore) void {
        self.engine.pauseAll();
    }

    pub fn resumeAllTransfers(self: *AppCore) !void {
        return self.engine.resumeAll();
    }

    pub fn cancelAllTransfers(self: *AppCore) void {
        self.engine.cancelAll();
    }

    pub fn requeueFailed(self: *AppCore) usize {
        return self.engine.requeueFailed();
    }

    pub fn requeueTransfer(self: *AppCore, id: ItemId) !bool {
        return self.engine.requeue(id);
    }

    /// UI snapshot of the queue in queue order (arena-per-result).
    pub fn queueSnapshot(self: *AppCore, alloc: Allocator) error{OutOfMemory}![]engine_mod.ItemSnapshot {
        return self.engine.snapshot(alloc);
    }

    /// Restore the persisted queue (items come back paused; resume-on-start
    /// is offered, never forced). Returns the restored count.
    pub fn restoreQueue(self: *AppCore) usize {
        var loaded = persist_mod.loadOrEmpty(self.io, self.config_dir, queue_file, self.gpa);
        defer loaded.deinit();
        return self.engine.restore(loaded.value) catch 0;
    }

    /// Apply global directional bandwidth caps at runtime and mirror them
    /// into settings so the native settings surface can persist them.
    pub fn setTransferRateLimits(self: *AppCore, upload: u64, download: u64) void {
        self.settings.rate_limit_up = upload;
        self.settings.rate_limit_down = download;
        self.engine.setGlobalRateLimit(.upload, upload);
        self.engine.setGlobalRateLimit(.download, download);
    }

    // ------------------------------------------------------------------ //
    // Commands: prompts, settings, transcript

    pub fn respondPrompt(self: *AppCore, token: PromptToken, answer: PromptAnswer) void {
        const accepted = switch (answer) {
            .auth, .host_key => |ok| ok,
        };
        // Bridge-issued prompts (connect-path password / host key): flag
        // the blocked worker's PendingPrompt. Flags are written under the
        // map lock so a worker that already gave up (cancel) and freed its
        // entry can never be touched. Stale answers are silently dropped.
        if (token.prompt_id >= bridge_prompt_id_base) {
            lockSpin(&self.prompts_mutex);
            defer self.prompts_mutex.unlock();
            const pending = self.pending_prompts.get(token.prompt_id) orelse return;
            pending.accepted.store(accepted, .release);
            pending.answered.store(true, .release);
            return;
        }
        // Engine-issued prompts (transfer-lane auth) route to the queue.
        switch (answer) {
            .auth => |ok| self.engine.resolveAuthPrompt(token.site_id, ok),
            .host_key => {},
        }
    }

    /// Worker-side blocking prompt: posts `prompt_needed` (echoing the
    /// fresh prompt id) and parks until the main thread answers through
    /// `respondPrompt` or `cancel` fires. When no prompt listener is
    /// registered (headless cores) it returns false immediately — a prompt
    /// nobody can see must read as a refusal, never a hang.
    pub fn askPrompt(
        self: *AppCore,
        site_id: u64,
        prompt: events_mod.Prompt,
        cancel: *CancelToken,
    ) error{ OutOfMemory, Canceled }!bool {
        if (self.prompt_listeners.load(.monotonic) == 0) return false;
        const pending = try self.gpa.create(PendingPrompt);
        pending.* = .{};
        lockSpin(&self.prompts_mutex);
        const prompt_id = self.next_prompt_id;
        self.next_prompt_id += 1;
        self.pending_prompts.put(self.gpa, prompt_id, pending) catch |err| {
            self.prompts_mutex.unlock();
            self.gpa.destroy(pending);
            return err;
        };
        self.prompts_mutex.unlock();
        defer {
            lockSpin(&self.prompts_mutex);
            _ = self.pending_prompts.remove(prompt_id);
            self.prompts_mutex.unlock();
            self.gpa.destroy(pending);
        }
        self.postEvent(.{ .prompt_needed = .{
            .site_id = site_id,
            .prompt_id = prompt_id,
            .prompt = prompt,
        } });
        while (!pending.answered.load(.acquire)) {
            try cancel.check();
            self.io.sleep(.fromMilliseconds(10), .awake) catch {};
        }
        return pending.accepted.load(.acquire);
    }

    pub const Login = struct { user: []const u8, host: []const u8 };

    /// Worker-safe copy of the site's (account, host) into caller buffers
    /// (prompt titles, SFTP usernames). null = unknown site.
    pub fn copySiteLogin(self: *AppCore, site_id: u64, user_buf: []u8, host_buf: []u8) ?Login {
        self.sites_mutex.lockUncancelable(self.io);
        defer self.sites_mutex.unlock(self.io);
        const site = self.findSite(site_id) orelse return null;
        const user_len = @min(site.account.len, user_buf.len);
        const host_len = @min(site.host.len, host_buf.len);
        @memcpy(user_buf[0..user_len], site.account[0..user_len]);
        @memcpy(host_buf[0..host_len], site.host[0..host_len]);
        return .{ .user = user_buf[0..user_len], .host = host_buf[0..host_len] };
    }

    /// Human label for `site_id`, copied into `buf` (UI titles like the
    /// connect-failure sheet "Couldn't connect to <label>"). Prefers the
    /// site nickname, falling back to the host; "" if the site is unknown or
    /// `buf` is empty. Caller owns `buf`; the returned slice points into it.
    pub fn siteLabel(self: *AppCore, site_id: u64, buf: []u8) []const u8 {
        self.sites_mutex.lockUncancelable(self.io);
        defer self.sites_mutex.unlock(self.io);
        const site = self.findSite(site_id) orelse return "";
        const src = if (site.name.len > 0) site.name else site.host;
        const n = @min(src.len, buf.len);
        @memcpy(buf[0..n], src[0..n]);
        return buf[0..n];
    }

    /// Worker-side password prompt for `site_id` with the real user/host.
    /// True = the sheet stored a secret and asked to retry; the caller
    /// re-fetches from the cred store (see `invalidateSiteSecret`).
    pub fn promptPassword(self: *AppCore, site_id: u64, cancel: *CancelToken) error{ OutOfMemory, Canceled }!bool {
        var user_buf: [256]u8 = undefined;
        var host_buf: [256]u8 = undefined;
        const login = self.copySiteLogin(site_id, &user_buf, &host_buf) orelse return false;
        return self.askPrompt(site_id, .{ .password = .{
            .user = login.user,
            .host = login.host,
        } }, cancel);
    }

    /// Drop the runtime's cached secret (wrong password) so the next
    /// CredProvider fetch reads the store again. The old buffer is retired,
    /// not freed: a concurrent connect may still hold the slice.
    pub fn invalidateSiteSecret(self: *AppCore, site_id: u64) void {
        self.sites_mutex.lockUncancelable(self.io);
        defer self.sites_mutex.unlock(self.io);
        const rt = self.site_runtimes.get(site_id) orelse return;
        if (rt.secret) |secret| {
            rt.retired_secrets.append(self.gpa, secret) catch return; // OOM: keep the cache
            rt.secret = null;
        }
    }

    /// Persist current settings and refresh derived knobs (prefs pane).
    pub fn saveSettings(self: *AppCore) !void {
        self.budget_conns.store(clampConns(self.settings.connections_per_site), .monotonic);
        try settings_mod.save(self.settings, self.io, self.config_dir, settings_file, self.gpa);
    }

    /// Copy of the transcript ring for the transcript pane (oldest first).
    pub fn transcriptSnapshot(self: *AppCore, gpa: Allocator) error{OutOfMemory}!transcript_mod.Transcript.Snapshot {
        return self.transcript.snapshot(gpa);
    }

    // ------------------------------------------------------------------ //
    // Self-test surface (phase 3's --auto-exit smoke)

    /// Posts a probe event and runs one synchronous drain; the smoke
    /// asserts the counters moved. Main thread only.
    pub fn smokeTick(self: *AppCore) SmokeReport {
        self.postEvent(.{ .transcript_line = .{
            .connection_id = 0,
            .seq = self.drains,
            .dir = .info,
            .verbose = true,
            .text = "bridge smoke tick",
        } });
        self.drainNow();
        return .{
            .drains = self.drains,
            .events_dispatched = self.events_dispatched,
            .pending_listings = self.pending_listings.count(),
            .sites_loaded = self.site_list.sites.len,
        };
    }

    // ------------------------------------------------------------------ //
    // Engine integration points (worker threads)

    fn budgetConns(context: *anyopaque, site_id: u64) u8 {
        _ = site_id;
        const self: *AppCore = @ptrCast(@alignCast(context));
        return self.budget_conns.load(.monotonic);
    }

    fn vfsProviderGet(context: *anyopaque, site_id: u64) ?vfs_mod.Vfs {
        const self: *AppCore = @ptrCast(@alignCast(context));
        return self.vfsForSite(site_id);
    }

    fn vfsForSite(self: *AppCore, site_id: u64) ?vfs_mod.Vfs {
        if (site_id == item_mod.local_site_id) return self.local_vfs.vfsInterface();
        self.sites_mutex.lockUncancelable(self.io);
        defer self.sites_mutex.unlock(self.io);
        const rt = self.site_runtimes.get(site_id) orelse return null;
        return rt.vfs();
    }
};

// ---------------------------------------------------------------------------
// Site runtime: pool + protocol Vfs backend + cached credential
// ---------------------------------------------------------------------------

const SiteRuntime = struct {
    core: *AppCore,
    site_id: u64,
    pool: *site_pool_mod.SitePool,
    backend: Backend,
    /// Fetched once per runtime, zeroed+freed at teardown. Guarded by
    /// core.sites_mutex (concurrent connect workers).
    secret: ?[]u8 = null,
    /// Secrets dropped by `invalidateSiteSecret` (wrong password). Kept
    /// alive until teardown: concurrent connects may still hold slices.
    retired_secrets: std.ArrayList([]u8) = .empty,

    const Backend = union(enum) {
        ftp: *relay.vfs.ftp_backend.FtpVfs,
        sftp: *relay.vfs.sftp_backend.SftpVfs,
    };

    fn vfs(rt: *SiteRuntime) vfs_mod.Vfs {
        return switch (rt.backend) {
            .ftp => |backend| backend.vfsInterface(),
            .sftp => |backend| backend.vfsInterface(),
        };
    }

    /// site_pool.CredProvider: secrets come from the CredStore keyed by
    /// (protocol, host, port, account) — never from the site list.
    fn fetchCreds(ctx: *anyopaque, diag: *Diagnostics) vfs_mod.Error!site_pool_mod.Credentials {
        const rt: *SiteRuntime = @ptrCast(@alignCast(ctx));
        const core = rt.core;
        core.sites_mutex.lockUncancelable(core.io);
        defer core.sites_mutex.unlock(core.io);
        const site = core.findSite(rt.site_id) orelse {
            diag.set(.permanent, 0, "site {d} is not in the site list", .{rt.site_id});
            return error.Unexpected;
        };
        if (rt.secret == null) {
            rt.secret = core.cred_store.get(core.gpa, diag, .{
                .protocol = switch (site.protocol) {
                    .ftp => .ftp,
                    .ftps => .ftps,
                    .sftp => .sftp,
                },
                .host = site.host,
                .port = site.effectivePort(),
                .account = site.account,
            }) catch |err| switch (err) {
                error.NotFound => {
                    diag.set(.auth, 0, "no stored credential for {s}@{s}", .{ site.account, site.host });
                    return error.AuthRequired;
                },
                error.AccessDenied => return error.AuthRequired,
                error.OutOfMemory => return error.OutOfMemory,
                error.Unexpected => return error.Unexpected,
            };
        }
        return .{ .user = site.account, .secret = rt.secret.? };
    }
};

fn connectWorker(rt: *SiteRuntime) void {
    const core = rt.core;
    defer core.kickPump();
    var diag: Diagnostics = .{};
    // The browse checkout drives the full connect sequence; the pool posts
    // `connected` itself on success and breaker transitions on repeated
    // failure. First-failure context is posted here so the UI always hears
    // back from a connect click.
    var lease = rt.pool.checkout(core.io, &rt.pool.cancel_token, &diag, .browse) catch |err| {
        if (err != error.Canceled) {
            // A user-initiated connect failed: carry both the verbatim reason
            // and the classified cause so the UI can surface (banner + sheet)
            // an unambiguous error rather than a bare "Offline" chip.
            core.postEvent(.{ .site_status = .{
                .site_id = rt.site_id,
                .status = .offline,
                .reason = diag.message,
                .error_class = diag.class,
            } });
        }
        return;
    };
    lease.release(core.io);
}

fn disconnectWorker(rt: *SiteRuntime) void {
    const core = rt.core;
    defer core.kickPump();
    // Site transfers first (predictable Cmd+Shift+K semantics), then the
    // pool: cancels the site token, joins keepalive, closes connections,
    // posts the offline status.
    core.engine.cancelSite(rt.site_id);
    rt.pool.disconnect(core.io);
}

// ---------------------------------------------------------------------------
// Listing worker
// ---------------------------------------------------------------------------

const ListingJob = struct {
    core: *AppCore,
    request_id: RequestId,
    pane_token: PaneToken,
    site_id: u64,
    /// Normalized; gpa-owned by the job.
    path: []u8,
    token: CancelToken = .{},
    /// Filled by the worker before it posts listing_done (the post's queue
    /// handoff orders these writes before the main thread reads them).
    snapshot: ?*DirSnapshot = null,
    /// Arena-owned by `snapshot` — freed by its final unref.
    sort_index: []const u32 = &.{},

    // Streaming partials: the worker swaps the newest one in (replacing an
    // unconsumed older one); the main thread takes it at listing_batch.
    partial_mutex: std.atomic.Mutex = .unlocked,
    partial: ?*DirSnapshot = null,
    /// Arena-owned by `partial`.
    partial_sort: []const u32 = &.{},
    // Worker-only coalescing state.
    last_partial_ns: i96 = 0,
    last_partial_count: usize = 0,

    // Latency honesty: the worker brackets the protocol list call. Both
    // fields are worker-written before an event post and main-read after
    // the queue handoff, so no extra synchronization is needed.
    list_started_ns: i96 = 0,
    elapsed_ms: u64 = 0,

    /// Milliseconds since the protocol call started; 0 before it did.
    fn elapsedNow(job: *const ListingJob, io: std.Io) u64 {
        if (job.list_started_ns == 0) return 0;
        const now = std.Io.Clock.awake.now(io).nanoseconds;
        const diff = now - job.list_started_ns;
        if (diff <= 0) return 0;
        return @intCast(@divTrunc(diff, std.time.ns_per_ms));
    }
};

/// Streams Vfs.list batches into the snapshot Builder while posting
/// progress counts.
const TeeSink = struct {
    job: *ListingJob,
    builder: *snapshot_mod.Builder,

    fn sink(self: *TeeSink) vfs_mod.ListingSink {
        return .{ .context = self, .batchFn = onBatch };
    }

    fn onBatch(ctx: *anyopaque, entries: []const vfs_mod.Entry) void {
        const self: *TeeSink = @ptrCast(@alignCast(ctx));
        self.builder.append(entries) catch {
            self.builder.failed = true; // finish() reports OutOfMemory
            return;
        };
        publishPartial(self.job, self.builder);
        self.job.elapsed_ms = self.job.elapsedNow(self.job.core.io);
        self.job.core.postEvent(.{ .listing_batch = .{
            .request_id = self.job.request_id,
            .entry_count = @intCast(@min(self.builder.count(), std.math.maxInt(u32))),
        } });
    }
};

/// Coalesced partial snapshot (docs/UX.md: "first rows visible
/// immediately"): deep-copies the entries parsed so far into a fresh
/// immutable snapshot at most once per `listing_partial_interval_ms`.
/// Best-effort — any failure is silent; truth still arrives at
/// listing_done.
fn publishPartial(job: *ListingJob, builder: *snapshot_mod.Builder) void {
    const core = job.core;
    const count = builder.count();
    if (count == 0 or count == job.last_partial_count) return;
    const now = std.Io.Clock.awake.now(core.io).nanoseconds;
    const interval_ns = @as(i96, @intCast(core.listing_partial_interval_ms)) * std.time.ns_per_ms;
    if (job.last_partial_ns != 0 and now - job.last_partial_ns < interval_ns) return;

    var partial_builder = snapshot_mod.Builder.init(core.gpa, job.path, job.request_id) catch return;
    copyEntriesDeep(&partial_builder, builder.entries.items) catch {
        partial_builder.abandon();
        return;
    };
    const snap = partial_builder.finish() catch return;
    const sort_index = snap.sortIndex(snap.arena.allocator(), .{}) catch {
        snap.unref();
        return;
    };
    lockSpin(&job.partial_mutex);
    const stale = job.partial;
    job.partial = snap;
    job.partial_sort = sort_index;
    job.partial_mutex.unlock();
    if (stale) |old| old.unref(); // replaced before the UI consumed it
    job.last_partial_ns = now;
    job.last_partial_count = count;
}

/// Deep copy into the partial's own arena: a kept partial may outlive the
/// source builder (whose arena dies with the FINAL snapshot — or with an
/// abandon on the failure path), so no string may be shared.
fn copyEntriesDeep(builder: *snapshot_mod.Builder, entries: []const vfs_mod.Entry) error{OutOfMemory}!void {
    const arena = builder.arena();
    for (entries) |entry| {
        var copy = entry;
        copy.name = try arena.dupe(u8, entry.name);
        if (entry.owner) |owner| copy.owner = try internCopy(builder, owner);
        if (entry.group) |group| copy.group = try internCopy(builder, group);
        if (entry.link_target) |target| copy.link_target = try arena.dupe(u8, target);
        try builder.append(&.{copy});
    }
}

/// Builder.intern assumes arena-owned input; this content-deduping variant
/// copies only the first occurrence.
fn internCopy(builder: *snapshot_mod.Builder, s: []const u8) error{OutOfMemory}![]const u8 {
    if (builder.intern_map.getKey(s)) |canonical| return canonical;
    return builder.intern(try builder.arena().dupe(u8, s));
}

fn listWorker(job: *ListingJob) void {
    const core = job.core;
    defer core.kickPump();
    var diag: Diagnostics = .{};

    const vfs = core.vfsForSite(job.site_id) orelse {
        diag.set(.permanent, 0, "site {d} is not connected", .{job.site_id});
        core.postListingFailure(job.request_id, .{ .class = diag.class, .message = diag.message });
        return;
    };

    // Empty path = "the site's default directory" (listDefaultPath):
    // resolve it on the backend before the listing proper so the snapshot
    // (and through it the path bar and history) carries the real path.
    if (job.path.len == 0) {
        var def_buf: [4096]u8 = undefined;
        const def = vfs.defaultPath(core.io, &job.token, &diag, &def_buf) catch {
            core.postListingFailure(job.request_id, .{
                .class = diag.class,
                .protocol_code = diag.protocol_code,
                .message = diag.message,
            });
            return;
        };
        const norm = path_mod.normalize(core.gpa, def) catch {
            core.postListingFailure(job.request_id, .{
                .class = .permanent,
                .message = "server reported an unusable default directory",
            });
            return;
        };
        core.gpa.free(job.path);
        job.path = norm;
    }

    var builder = snapshot_mod.Builder.init(core.gpa, job.path, job.request_id) catch {
        core.postListingFailure(job.request_id, .{ .class = .transient, .message = "out of memory" });
        return;
    };
    var tee: TeeSink = .{ .job = job, .builder = &builder };

    // Latency honesty: bracket the protocol call (and only it); the final
    // elapsed_ms rides both success and failure listing_done payloads.
    job.list_started_ns = std.Io.Clock.awake.now(core.io).nanoseconds;
    const list_result = vfs.list(core.io, &job.token, &diag, job.path, builder.arena(), tee.sink());
    job.elapsed_ms = job.elapsedNow(core.io);
    list_result catch {
        builder.abandon();
        core.postListingFailure(job.request_id, .{
            .class = diag.class,
            .protocol_code = diag.protocol_code,
            .message = diag.message,
        });
        return;
    };

    // finish() consumes the builder on success AND failure.
    const snap = builder.finish() catch {
        core.postListingFailure(job.request_id, .{ .class = .transient, .message = "out of memory finishing listing" });
        return;
    };
    // Default-sort permutation, computed off-main and allocated in the
    // snapshot's own arena (dies with the snapshot, zero extra frees).
    // Pre-publication: nothing else can see this snapshot yet.
    const sort_index = snap.sortIndex(snap.arena.allocator(), .{}) catch {
        snap.unref();
        core.postListingFailure(job.request_id, .{ .class = .transient, .message = "out of memory sorting listing" });
        return;
    };
    job.snapshot = snap;
    job.sort_index = sort_index;
    core.postEvent(.{ .listing_done = .{
        .request_id = job.request_id,
    } });
}

// ---------------------------------------------------------------------------
// File-operation worker
// ---------------------------------------------------------------------------

const OpJob = struct {
    core: *AppCore,
    kind: OpKind,
    request_id: RequestId,
    pane_token: PaneToken,
    site_id: u64,
    /// All paths normalized + gpa-owned by the job.
    path: []u8,
    to_path: ?[]u8 = null,
    mode: u16 = 0,
    recursive: bool = false,
    /// Directory to re-list on success (the path's parent).
    refresh_dir: []u8,
    token: CancelToken = .{},
    // Result (written by the worker before handoff to pending_ops).
    success: bool = false,
    mtime: ?i64 = null,
    failure_class: diag_mod.ErrorClass = .permanent,
    failure_code: u32 = 0,
    failure_msg_buf: [512]u8 = undefined,
    failure_msg_len: usize = 0,
};

fn opWorker(job: *OpJob) void {
    const core = job.core;
    var diag: Diagnostics = .{};
    run: {
        const vfs = core.vfsForSite(job.site_id) orelse {
            diag.set(.permanent, 0, "site {d} is not connected", .{job.site_id});
            break :run;
        };
        const io = core.io;
        switch (job.kind) {
            .mkdir => vfs.mkdir(io, &job.token, &diag, job.path) catch break :run,
            .rename => vfs.rename(io, &job.token, &diag, job.path, job.to_path.?) catch break :run,
            .chmod => vfs.chmod(io, &job.token, &diag, job.path, job.mode) catch break :run,
            .delete => vfs.remove(io, &job.token, &diag, job.path, job.recursive) catch break :run,
            .stat => {
                const entry = vfs.stat(io, &job.token, &diag, job.path) catch break :run;
                job.mtime = entry.mtime;
            },
        }
        job.success = true;
    }
    if (!job.success) {
        job.failure_class = diag.class;
        job.failure_code = diag.protocol_code;
        const n = @min(diag.message.len, job.failure_msg_buf.len);
        @memcpy(job.failure_msg_buf[0..n], diag.message[0..n]);
        job.failure_msg_len = n;
    }
    lockSpin(&core.ops_mutex);
    const appended = appended: {
        core.pending_ops.append(core.gpa, job) catch break :appended false;
        break :appended true;
    };
    core.ops_mutex.unlock();
    if (!appended) {
        core.destroyOpJob(job); // OOM: drop the result silently
        return;
    }
    core.schedulePump();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// See sync.zig for why a one-word spin mutex is the 0.16 lock of choice
/// for these nanosecond-window critical sections.
const lockSpin = relay.sync.lockSpin;

fn clampConns(v: u8) u8 {
    return @max(1, @min(v, 8));
}

var unwired_factory_ctx: u8 = 0;

fn unwiredFactoryConnect(
    ctx: *anyopaque,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
    role: site_pool_mod.Role,
) vfs_mod.Error!site_pool_mod.Conn {
    _ = ctx;
    _ = io;
    _ = cancel;
    _ = site;
    _ = role;
    diag.set(.permanent, 0, "protocol connect factory not wired into this build", .{});
    return error.NotSupported;
}

/// Fallback when no FactoryProvider was injected (headless tests). The
/// app always injects one: factories.zig in normal runs, the blind-accept
/// SFTP factory in --smoke-sftp.
fn unwiredFactory() site_pool_mod.ConnFactory {
    return .{ .ctx = @ptrCast(&unwired_factory_ctx), .connectFn = unwiredFactoryConnect };
}

// ---------------------------------------------------------------------------
// Tests — all headless: manual pump, tmp dirs, fake cred store. The gcd
// dispatch path is exercised by phase 3's app-level smoke (and the
// platform binding tests cover their scheduling primitives).
// ---------------------------------------------------------------------------

const testing = std.testing;
const FakeStore = relay.cred.fake.FakeStore;
const MockHub = site_pool_mod.MockHub;

const TestHarness = struct {
    tmp_conf: std.testing.TmpDir,
    tmp_root: std.testing.TmpDir,
    fake: FakeStore,
    core: *AppCore,

    /// In-place init; the harness must be pinned (`var h: TestHarness = undefined`).
    fn start(h: *TestHarness, factory_provider: ?FactoryProvider) !void {
        h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
        h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
        h.fake = .init(testing.allocator);
        h.core = try AppCore.initOptions(testing.allocator, .{
            .pump = .manual,
            .config_dir = h.tmp_conf.dir,
            .local_root = h.tmp_root.dir,
            .cred_store = h.fake.credStore(),
            .factory_provider = factory_provider,
        });
    }

    fn stop(h: *TestHarness) void {
        h.core.shutdown();
        h.fake.deinit();
        h.tmp_root.cleanup();
        h.tmp_conf.cleanup();
    }

    const wait_timeout_ms: u64 = 5_000;

    /// Drain-and-poll until `pred(ctx)` holds (manual pump).
    fn waitUntil(h: *TestHarness, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool) !void {
        const io = h.core.io;
        const deadline = std.Io.Clock.awake.now(io).nanoseconds +
            @as(i96, wait_timeout_ms) * std.time.ns_per_ms;
        while (true) {
            h.core.drainNow();
            if (pred(ctx)) return;
            if (std.Io.Clock.awake.now(io).nanoseconds > deadline) return error.Timeout;
            io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }
};

test "AppCore init/shutdown is leak-free without AppKit (defaults, first run)" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    // Missing config files degrade to defaults.
    try testing.expectEqual(@as(u8, 3), h.core.settings.connections_per_site);
    try testing.expectEqual(@as(usize, 0), h.core.site_list.sites.len);
    try testing.expectEqual(@as(?*const sites_mod.Site, null), h.core.findSite(1));
    try testing.expectEqual(@as(usize, 0), h.core.restoreQueue());
}

test "listener registry dispatches typed payloads to every registered listener" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    const Recorder = struct {
        calls: usize = 0,
        last_site: u64 = 0,
        last_status: events_mod.SiteStatus = .offline,
        reason_ok: bool = false,

        fn onStatus(self: *@This(), e: events_mod.CoreEvent.SiteStatusChange) void {
            self.calls += 1;
            self.last_site = e.site_id;
            self.last_status = e.status;
            self.reason_ok = std.mem.eql(u8, e.reason, "test reason");
        }
    };
    var a: Recorder = .{};
    var b: Recorder = .{};
    try h.core.registerListener(.site_status, &a, Recorder.onStatus);
    try h.core.registerListener(.site_status, &b, Recorder.onStatus);

    h.core.postEvent(.{ .site_status = .{ .site_id = 9, .status = .reconnecting, .reason = "test reason" } });
    h.core.drainNow();

    for ([_]*Recorder{ &a, &b }) |r| {
        try testing.expectEqual(@as(usize, 1), r.calls);
        try testing.expectEqual(@as(u64, 9), r.last_site);
        try testing.expectEqual(events_mod.SiteStatus.reconnecting, r.last_status);
        try testing.expect(r.reason_ok);
    }

    // Run-to-completion: a batch of N events applies in one drain.
    h.core.postEvent(.{ .site_status = .{ .site_id = 1, .status = .offline } });
    h.core.postEvent(.{ .site_status = .{ .site_id = 2, .status = .offline } });
    h.core.drainNow();
    try testing.expectEqual(@as(usize, 3), a.calls);
}

test "unregisterListeners detaches one ctx across all tags; the rest keep firing" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    const Recorder = struct {
        status_calls: usize = 0,
        prompt_calls: usize = 0,

        fn onStatus(self: *@This(), e: events_mod.CoreEvent.SiteStatusChange) void {
            _ = e;
            self.status_calls += 1;
        }
        fn onPrompt(self: *@This(), e: events_mod.CoreEvent.PromptNeeded) void {
            _ = e;
            self.prompt_calls += 1;
        }
    };
    var a: Recorder = .{};
    var b: Recorder = .{};
    try h.core.registerListener(.site_status, &a, Recorder.onStatus);
    try h.core.registerListener(.prompt_needed, &a, Recorder.onPrompt);
    try h.core.registerListener(.site_status, &b, Recorder.onStatus);
    try testing.expectEqual(@as(usize, 1), h.core.prompt_listeners.load(.monotonic));

    // The sweep covers EVERY tag the ctx registered for (and keeps the
    // prompt-wired count honest), without touching the other ctx.
    h.core.unregisterListeners(&a);
    try testing.expectEqual(@as(usize, 0), h.core.prompt_listeners.load(.monotonic));

    h.core.postEvent(.{ .site_status = .{ .site_id = 9, .status = .offline } });
    h.core.postEvent(.{ .prompt_needed = .{
        .site_id = 9,
        .prompt_id = 1,
        .prompt = .{ .password = .{ .user = "u", .host = "h" } },
    } });
    h.core.drainNow();
    try testing.expectEqual(@as(usize, 0), a.status_calls);
    try testing.expectEqual(@as(usize, 0), a.prompt_calls);
    try testing.expectEqual(@as(usize, 1), b.status_calls);

    // Unregistering a never-registered ctx is a harmless no-op.
    var stranger: Recorder = .{};
    h.core.unregisterListeners(&stranger);
    h.core.postEvent(.{ .site_status = .{ .site_id = 9, .status = .offline } });
    h.core.drainNow();
    try testing.expectEqual(@as(usize, 2), b.status_calls);
}

const ListingRecorder = struct {
    done: usize = 0,
    progress: usize = 0,
    pane: PaneToken = 0,
    request: RequestId = 0,
    entries: usize = 0,
    generation: u64 = 0,
    failure_class: ?diag_mod.ErrorClass = null,
    snapshot_was_null: bool = false,
    sort_ok: bool = false,
    elapsed_ms: u64 = std.math.maxInt(u64),
    first_sorted: [64]u8 = undefined,
    first_sorted_len: usize = 0,
    saw_name: bool = false,
    needle: []const u8 = "",
    path_buf: [256]u8 = undefined,
    path_len: usize = 0,

    fn onProgress(self: *@This(), p: ListingProgress) void {
        self.progress += 1;
        _ = p;
    }

    fn onDone(self: *@This(), d: ListingDone) void {
        self.done += 1;
        self.pane = d.pane_token;
        self.request = d.request_id;
        self.elapsed_ms = d.elapsed_ms;
        if (d.failure) |f| {
            self.failure_class = f.class;
            self.snapshot_was_null = d.snapshot == null;
            return;
        }
        const snap = d.snapshot.?;
        self.entries = snap.entries.len;
        self.generation = snap.generation;
        self.sort_ok = d.sort_index.len == snap.entries.len;
        self.path_len = @min(snap.path.len, self.path_buf.len);
        @memcpy(self.path_buf[0..self.path_len], snap.path[0..self.path_len]);
        if (d.sort_index.len > 0) {
            const name = snap.entries[d.sort_index[0]].name;
            const n = @min(name.len, self.first_sorted.len);
            @memcpy(self.first_sorted[0..n], name[0..n]);
            self.first_sorted_len = n;
        }
        if (self.needle.len > 0) {
            for (snap.entries) |entry| {
                if (std.mem.eql(u8, entry.name, self.needle)) self.saw_name = true;
            }
        }
    }

    fn gotDone(self: *@This()) bool {
        return self.done > 0;
    }
};

test "listPath round trip: local Vfs listing delivers snapshot + sort permutation" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "beta.txt", .data = "b" });
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "alpha.txt", .data = "a" });
    try h.tmp_root.dir.createDir(io, "zsub", .default_dir);

    var rec: ListingRecorder = .{};
    try h.core.registerListener(.listing_done, &rec, ListingRecorder.onDone);
    try h.core.registerListener(.listing_progress, &rec, ListingRecorder.onProgress);

    const request_id = try h.core.listPath(7, item_mod.local_site_id, "/");
    try h.waitUntil(&rec, ListingRecorder.gotDone);

    try testing.expectEqual(@as(usize, 1), rec.done);
    try testing.expectEqual(@as(PaneToken, 7), rec.pane);
    try testing.expectEqual(request_id, rec.request);
    try testing.expectEqual(@as(usize, 3), rec.entries);
    try testing.expectEqual(request_id, rec.generation);
    try testing.expect(rec.failure_class == null);
    try testing.expect(rec.progress >= 1);
    try testing.expect(rec.sort_ok);
    // Latency honesty: the worker-bracketed elapsed time was delivered
    // (a local listing is fast — sanity-bound it, don't race the clock).
    try testing.expect(rec.elapsed_ms < 60_000);
    // Default sort: dirs first, then natural name order.
    try testing.expectEqualStrings("zsub", rec.first_sorted[0..rec.first_sorted_len]);
    // The pending table emptied (job + snapshot reclaimed at dispatch).
    try testing.expectEqual(@as(usize, 0), h.core.pending_listings.count());
}

test "listDefaultPath resolves the backend's default dir; snapshot carries the real path" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();
    const io = h.core.io;

    // The local backend's default is $HOME. The harness's local root is a
    // tmp dir, so mirror HOME under it (HOME is absolute → root-relative
    // by stripping the leading '/') and drop a marker entry inside.
    const home_env = std.c.getenv("HOME") orelse return; // env-less runner: skip
    const home = std.mem.span(home_env);
    if (home.len < 2 or home[0] != '/') return;
    const norm = try path_mod.normalize(testing.allocator, home);
    defer testing.allocator.free(norm);
    try h.tmp_root.dir.createDirPath(io, norm[1..]);
    const marker = try std.fmt.allocPrint(testing.allocator, "{s}/marker.txt", .{norm[1..]});
    defer testing.allocator.free(marker);
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = marker, .data = "m" });

    var rec: ListingRecorder = .{ .needle = "marker.txt" };
    try h.core.registerListener(.listing_done, &rec, ListingRecorder.onDone);

    const request_id = try h.core.listDefaultPath(7, item_mod.local_site_id);
    try h.waitUntil(&rec, ListingRecorder.gotDone);

    try testing.expectEqual(request_id, rec.request);
    try testing.expect(rec.failure_class == null);
    // The snapshot's path is the RESOLVED default, not the "" sentinel.
    try testing.expectEqualStrings(norm, rec.path_buf[0..rec.path_len]);
    try testing.expect(rec.saw_name);
}

test "listPath failure carries classified diagnostics, null snapshot" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    var rec: ListingRecorder = .{};
    try h.core.registerListener(.listing_done, &rec, ListingRecorder.onDone);

    _ = try h.core.listPath(1, item_mod.local_site_id, "/does-not-exist");
    try h.waitUntil(&rec, ListingRecorder.gotDone);

    try testing.expectEqual(diag_mod.ErrorClass.permanent, rec.failure_class.?);
    try testing.expect(rec.snapshot_was_null);

    // Unknown site id: classified failure, not a crash.
    rec = .{};
    _ = try h.core.listPath(1, 424242, "/");
    try h.waitUntil(&rec, ListingRecorder.gotDone);
    try testing.expectEqual(diag_mod.ErrorClass.permanent, rec.failure_class.?);

    // cancelListing on an unknown request id is a no-op.
    try testing.expect(!h.core.cancelListing(999_999));
}

test "mkdir wrapper: op_done fires and the parent re-lists on success" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    const OpRecorder = struct {
        done: usize = 0,
        ok: bool = false,
        kind: ?OpKind = null,
        pane: PaneToken = 0,
        failure_class: ?diag_mod.ErrorClass = null,

        fn onOp(self: *@This(), op: OpDone) void {
            self.done += 1;
            self.ok = op.success;
            self.kind = op.op;
            self.pane = op.pane_token;
            self.failure_class = if (op.failure) |f| f.class else null;
        }
        fn gotOp(self: *@This()) bool {
            return self.done > 0;
        }
    };
    var ops: OpRecorder = .{};
    var listing: ListingRecorder = .{ .needle = "made" };
    try h.core.registerListener(.op_done, &ops, OpRecorder.onOp);
    try h.core.registerListener(.listing_done, &listing, ListingRecorder.onDone);

    try h.core.mkdirPath(3, item_mod.local_site_id, "/made");
    try h.waitUntil(&ops, OpRecorder.gotOp);
    try testing.expect(ops.ok);
    try testing.expectEqual(OpKind.mkdir, ops.kind.?);
    try testing.expectEqual(@as(PaneToken, 3), ops.pane);

    // The success auto re-listed "/" on the same pane and the new dir shows.
    try h.waitUntil(&listing, ListingRecorder.gotDone);
    try testing.expectEqual(@as(PaneToken, 3), listing.pane);
    try testing.expect(listing.saw_name);

    // Second mkdir of the same path: classified failure, no crash.
    ops = .{};
    try h.core.mkdirPath(3, item_mod.local_site_id, "/made");
    try h.waitUntil(&ops, OpRecorder.gotOp);
    try testing.expect(!ops.ok);
    try testing.expectEqual(diag_mod.ErrorClass.permanent, ops.failure_class.?);

    // rename + delete complete the wrapper quartet.
    ops = .{};
    try h.core.renamePath(3, item_mod.local_site_id, "/made", "/renamed");
    try h.waitUntil(&ops, OpRecorder.gotOp);
    try testing.expect(ops.ok);
    ops = .{};
    try h.core.deletePath(3, item_mod.local_site_id, "/renamed", false);
    try h.waitUntil(&ops, OpRecorder.gotOp);
    try testing.expect(ops.ok);
}

test "statPath returns fresh metadata and failures without re-listing" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "fresh.txt", .data = "fresh" });
    var file = try h.tmp_root.dir.openFile(io, "fresh.txt", .{});
    const expected_mtime = (try file.stat(io)).mtime.toSeconds();
    file.close(io);

    const Recorder = struct {
        done: usize = 0,
        listings: usize = 0,
        request_id: RequestId = 0,
        success: bool = false,
        mtime: ?i64 = null,
        failure_class: ?diag_mod.ErrorClass = null,
        failure_message_ok: bool = false,

        fn onOp(self: *@This(), op: OpDone) void {
            self.done += 1;
            self.request_id = op.request_id;
            self.success = op.success;
            self.mtime = op.mtime;
            self.failure_class = if (op.failure) |failure| failure.class else null;
            self.failure_message_ok = if (op.failure) |failure|
                std.mem.indexOf(u8, failure.message, "does-not-exist") != null
            else
                false;
        }

        fn onListing(self: *@This(), _: ListingDone) void {
            self.listings += 1;
        }

        fn gotFirst(self: *@This()) bool {
            return self.done >= 1;
        }

        fn gotSecond(self: *@This()) bool {
            return self.done >= 2;
        }
    };
    var rec: Recorder = .{};
    try h.core.registerListener(.op_done, &rec, Recorder.onOp);
    try h.core.registerListener(.listing_done, &rec, Recorder.onListing);

    const success_request = try h.core.statPath(item_mod.local_site_id, "/fresh.txt");
    try h.waitUntil(&rec, Recorder.gotFirst);
    try testing.expect(rec.success);
    try testing.expectEqual(success_request, rec.request_id);
    try testing.expectEqual(@as(?i64, expected_mtime), rec.mtime);
    try testing.expectEqual(@as(usize, 0), rec.listings);

    const failure_request = try h.core.statPath(item_mod.local_site_id, "/does-not-exist");
    try h.waitUntil(&rec, Recorder.gotSecond);
    try testing.expect(!rec.success);
    try testing.expectEqual(failure_request, rec.request_id);
    try testing.expectEqual(diag_mod.ErrorClass.permanent, rec.failure_class.?);
    try testing.expect(rec.failure_message_ok);
    try testing.expectEqual(@as(usize, 0), rec.listings);
}

test "enqueueTransfer: local→local copy through the real queue engine + pump" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.createDir(io, "src", .default_dir);
    try h.tmp_root.dir.createDir(io, "dl", .default_dir);
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "src/data.bin", .data = "relay transfer payload" });

    const StateRecorder = struct {
        completed: bool = false,
        item: ItemId = 0,

        fn onState(self: *@This(), e: events_mod.CoreEvent.TransferStateChange) void {
            if (e.item_id == self.item and e.state == .completed) self.completed = true;
        }
        fn isDone(self: *@This()) bool {
            return self.completed;
        }
    };
    var rec: StateRecorder = .{};
    try h.core.registerListener(.transfer_state, &rec, StateRecorder.onState);

    const id = try h.core.enqueueTransfer(.{
        .direction = .download,
        .src = .{ .site_id = item_mod.local_site_id, .path = "/src/data.bin" },
        .dst = .{ .site_id = item_mod.local_site_id, .path = "/dl/data.bin" },
    });
    rec.item = id;
    try h.waitUntil(&rec, StateRecorder.isDone);

    var file = try h.tmp_root.dir.openFile(io, "dl/data.bin", .{});
    defer file.close(io);
    var buf: [64]u8 = undefined;
    var reader = file.reader(io, &buf);
    const got = try reader.interface.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("relay transfer payload", got);

    // Queue snapshot reflects the finished item.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snap = try h.core.queueSnapshot(arena.allocator());
    try testing.expectEqual(@as(usize, 1), snap.len);
    try testing.expectEqual(item_mod.State.done, snap[0].state);
}

test "connectSite/disconnectSite: pool lifecycle + site_status via mock factory" {
    var hub = MockHub.init(testing.allocator);
    const Make = struct {
        fn make(ctx: *anyopaque, site: *const sites_mod.Site) site_pool_mod.ConnFactory {
            _ = site;
            const hub_ptr: *MockHub = @ptrCast(@alignCast(ctx));
            return hub_ptr.factory();
        }
    };

    var h: TestHarness = undefined;
    h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
    h.fake = .init(testing.allocator);
    // Site list + credential staged before init, exactly like a real run.
    try sites_mod.save(.{ .sites = &.{.{
        .id = 1,
        .name = "mock",
        .protocol = .ftp,
        .host = "test.example",
        .account = "alice",
    }} }, std.testing.io, h.tmp_conf.dir, sites_file, testing.allocator);
    var diag: Diagnostics = .{};
    try h.fake.set(&diag, .{ .protocol = .ftp, .host = "test.example", .port = 21, .account = "alice" }, "hunter2");
    h.core = try AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = h.tmp_conf.dir,
        .local_root = h.tmp_root.dir,
        .cred_store = h.fake.credStore(),
        .factory_provider = .{ .ctx = &hub, .makeFn = Make.make },
    });
    defer h.stop();

    try testing.expect(h.core.findSite(1) != null);
    try testing.expectError(error.UnknownSite, h.core.connectSite(77));

    const StatusRecorder = struct {
        connected: usize = 0,
        offline: usize = 0,

        fn onStatus(self: *@This(), e: events_mod.CoreEvent.SiteStatusChange) void {
            if (e.site_id != 1) return;
            switch (e.status) {
                .connected => self.connected += 1,
                .offline => self.offline += 1,
                .reconnecting => {},
            }
        }
        fn isConnected(self: *@This()) bool {
            return self.connected >= 1;
        }
        fn isOffline(self: *@This()) bool {
            return self.offline >= 1;
        }
        fn isReconnected(self: *@This()) bool {
            return self.connected >= 2;
        }
    };
    var rec: StatusRecorder = .{};
    try h.core.registerListener(.site_status, &rec, StatusRecorder.onStatus);

    try h.core.connectSite(1);
    try h.waitUntil(&rec, StatusRecorder.isConnected);
    try testing.expectEqual(@as(usize, 1), hub.connects.load(.monotonic));
    // The bridge's CredProvider adapter fetched from the (fake) store and
    // cached the secret on the runtime.
    try testing.expectEqualStrings("hunter2", h.core.site_runtimes.get(1).?.secret.?);

    // The browse connection is pooled: the queue's VfsProvider resolves the
    // site to its protocol backend now.
    try testing.expect(h.core.vfsForSite(1) != null);
    try testing.expect(h.core.vfsForSite(2) == null);

    h.core.disconnectSite(1);
    try h.waitUntil(&rec, StatusRecorder.isOffline);
    try testing.expectEqual(@as(usize, 0), hub.openConns());

    // Reconnect after disconnect rebuilds the pool (old one is retired,
    // kept alive for stale Vfs handles until shutdown).
    try h.core.connectSite(1);
    try h.waitUntil(&rec, StatusRecorder.isReconnected);
    try testing.expectEqual(@as(usize, 2), hub.connects.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), h.core.retired_runtimes.items.len);
    // The fresh runtime re-fetched and re-cached the credential.
    try testing.expectEqualStrings("hunter2", h.core.site_runtimes.get(1).?.secret.?);
}

test "connectSite without a wired factory reports a classified offline status" {
    var h: TestHarness = undefined;
    h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
    h.fake = .init(testing.allocator);
    try sites_mod.save(.{ .sites = &.{.{
        .id = 5,
        .protocol = .sftp,
        .host = "unwired.example",
        .account = "bob",
    }} }, std.testing.io, h.tmp_conf.dir, sites_file, testing.allocator);
    var diag: Diagnostics = .{};
    try h.fake.set(&diag, .{ .protocol = .sftp, .host = "unwired.example", .port = 22, .account = "bob" }, "pw");
    h.core = try AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = h.tmp_conf.dir,
        .local_root = h.tmp_root.dir,
        .cred_store = h.fake.credStore(),
    });
    defer h.stop();

    const StatusRecorder = struct {
        offline: usize = 0,
        reason_ok: bool = false,
        error_class: ?diag_mod.ErrorClass = null,

        fn onStatus(self: *@This(), e: events_mod.CoreEvent.SiteStatusChange) void {
            if (e.site_id != 5 or e.status != .offline) return;
            self.offline += 1;
            if (std.mem.indexOf(u8, e.reason, "factory not wired") != null) self.reason_ok = true;
            self.error_class = e.error_class;
        }
        fn isOffline(self: *@This()) bool {
            return self.offline >= 1;
        }
    };
    var rec: StatusRecorder = .{};
    try h.core.registerListener(.site_status, &rec, StatusRecorder.onStatus);

    try h.core.connectSite(5);
    try h.waitUntil(&rec, StatusRecorder.isOffline);
    try testing.expect(rec.reason_ok);
    // A failure carries a classified cause, not just a reason string.
    try testing.expect(rec.error_class != null);

    // siteLabel falls back to the host when no nickname is set.
    var label_buf: [128]u8 = undefined;
    try testing.expectEqualStrings("unwired.example", h.core.siteLabel(5, &label_buf));
    try testing.expectEqualStrings("", h.core.siteLabel(9999, &label_buf));
}

test "respondPrompt and queue control wrappers are safe no-ops on empty state" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    h.core.respondPrompt(.{ .site_id = 1, .prompt_id = 1 }, .{ .auth = true });
    h.core.respondPrompt(.{ .site_id = 1, .prompt_id = 2 }, .{ .host_key = false });
    try testing.expect(!h.core.pauseTransfer(42));
    try testing.expect(!(try h.core.resumeTransfer(42)));
    try testing.expect(!h.core.cancelTransfer(42));
    try testing.expect(!h.core.removeTransfer(42));
    try testing.expectEqual(@as(usize, 0), h.core.requeueFailed());
    h.core.pauseAllTransfers();
    try h.core.resumeAllTransfers();
    h.core.cancelAllTransfers();
}

test "smokeTick reports pump activity" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    const Recorder = struct {
        lines: usize = 0,
        fn onLine(self: *@This(), e: events_mod.CoreEvent.TranscriptLine) void {
            _ = e;
            self.lines += 1;
        }
    };
    var rec: Recorder = .{};
    try h.core.registerListener(.transcript_line, &rec, Recorder.onLine);

    const report = h.core.smokeTick(); // posts a probe + drains it
    try testing.expect(report.drains >= 1);
    try testing.expect(report.events_dispatched >= 1);
    try testing.expectEqual(@as(usize, 0), report.pending_listings);
    try testing.expectEqual(@as(usize, 1), rec.lines);

    const report2 = h.core.smokeTick();
    try testing.expect(report2.drains > report.drains);
    try testing.expectEqual(@as(usize, 2), rec.lines);
}

test "askPrompt parks a worker until respondPrompt routes the answer by prompt id" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    const Catcher = struct {
        token: ?PromptToken = null,
        is_host_key: bool = false,

        fn onPrompt(self: *@This(), e: events_mod.CoreEvent.PromptNeeded) void {
            self.token = .{ .site_id = e.site_id, .prompt_id = e.prompt_id };
            self.is_host_key = e.prompt == .host_key;
        }
        fn gotPrompt(self: *@This()) bool {
            return self.token != null;
        }
    };
    var catcher: Catcher = .{};
    try h.core.registerListener(.prompt_needed, &catcher, Catcher.onPrompt);

    const Asker = struct {
        core: *AppCore,
        cancel: CancelToken = .{},
        result: ?bool = null,
        canceled: bool = false,

        fn run(self: *@This()) void {
            self.result = self.core.askPrompt(5, .{ .host_key = .{
                .fingerprint = "SHA256:abc",
                .host = "box.example",
            } }, &self.cancel) catch {
                self.canceled = true;
                return;
            };
        }
    };

    // Accepted host-key answer reaches the worker.
    var asker: Asker = .{ .core = h.core };
    var thread = try std.Thread.spawn(.{}, Asker.run, .{&asker});
    try h.waitUntil(&catcher, Catcher.gotPrompt);
    try testing.expect(catcher.is_host_key);
    try testing.expect(catcher.token.?.prompt_id >= bridge_prompt_id_base);
    h.core.respondPrompt(catcher.token.?, .{ .host_key = true });
    thread.join();
    try testing.expectEqual(@as(?bool, true), asker.result);

    // Denied answer (auth kind routes by id too, not to the engine).
    catcher = .{};
    asker = .{ .core = h.core };
    thread = try std.Thread.spawn(.{}, Asker.run, .{&asker});
    try h.waitUntil(&catcher, Catcher.gotPrompt);
    h.core.respondPrompt(catcher.token.?, .{ .auth = false });
    thread.join();
    try testing.expectEqual(@as(?bool, false), asker.result);

    // Cancellation unblocks the worker without an answer.
    catcher = .{};
    asker = .{ .core = h.core };
    thread = try std.Thread.spawn(.{}, Asker.run, .{&asker});
    try h.waitUntil(&catcher, Catcher.gotPrompt);
    asker.cancel.cancel();
    thread.join();
    try testing.expect(asker.canceled);
    try testing.expectEqual(@as(usize, 0), h.core.pending_prompts.count());

    // A stale answer after the asker gave up is a safe no-op.
    h.core.respondPrompt(catcher.token.?, .{ .host_key = true });
}

test "askPrompt without any prompt listener refuses instead of hanging" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    var cancel: CancelToken = .{};
    try testing.expectEqual(false, try h.core.askPrompt(1, .{ .password = .{
        .user = "u",
        .host = "h",
    } }, &cancel));
}

test "connect with no stored credential prompts (real user/host) and retries after storeSecret" {
    const PromptingHub = struct {
        core: *AppCore = undefined,
        connects: std.atomic.Value(usize) = .init(0),
        var conn_ctx: u8 = 0;

        fn make(ctx: *anyopaque, site: *const sites_mod.Site) site_pool_mod.ConnFactory {
            _ = site;
            return .{ .ctx = ctx, .connectFn = connect };
        }

        // The production factories' credential pattern: fetch; on a missing
        // secret raise the password sheet and re-fetch.
        fn connect(
            ctx: *anyopaque,
            io: std.Io,
            cancel: *CancelToken,
            diag: *Diagnostics,
            site: *const site_pool_mod.SiteConfig,
            role: site_pool_mod.Role,
        ) vfs_mod.Error!site_pool_mod.Conn {
            _ = io;
            _ = role;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const provider = site.creds.?;
            const creds = provider.fetch(diag) catch |err| switch (err) {
                error.AuthRequired => blk: {
                    const retry = self.core.promptPassword(site.site_id, cancel) catch |prompt_err|
                        switch (prompt_err) {
                            error.Canceled => return error.Canceled,
                            error.OutOfMemory => return error.OutOfMemory,
                        };
                    if (!retry) return error.AuthRequired;
                    break :blk try provider.fetch(diag);
                },
                else => |e| return e,
            };
            if (!std.mem.eql(u8, creds.secret, "sesame")) {
                diag.set(.auth, 0, "wrong secret reached the factory", .{});
                return error.AuthRequired;
            }
            _ = self.connects.fetchAdd(1, .monotonic);
            return .{ .engine = .mock, .ctx = @ptrCast(&conn_ctx), .vtable = &conn_vtable };
        }

        const conn_vtable: site_pool_mod.Conn.VTable = .{
            .noop = connNoop,
            .alive = connAlive,
            .close = connClose,
        };
        fn connNoop(_: *anyopaque, _: std.Io, _: *CancelToken, _: *Diagnostics) vfs_mod.Error!void {}
        fn connAlive(_: *anyopaque) bool {
            return true;
        }
        fn connClose(_: *anyopaque, _: std.Io) void {}
    };

    var hub: PromptingHub = .{};
    var h: TestHarness = undefined;
    h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
    h.fake = .init(testing.allocator);
    // Site staged on disk; the fake store deliberately has NO secret.
    try sites_mod.save(.{ .sites = &.{.{
        .id = 9,
        .name = "prompted",
        .protocol = .ftp,
        .host = "prompt.example",
        .account = "carol",
    }} }, std.testing.io, h.tmp_conf.dir, sites_file, testing.allocator);
    h.core = try AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = h.tmp_conf.dir,
        .local_root = h.tmp_root.dir,
        .cred_store = h.fake.credStore(),
        .factory_provider = .{ .ctx = &hub, .makeFn = PromptingHub.make },
    });
    defer h.stop();
    hub.core = h.core;

    // The "UI": answers the password sheet by storing the secret first
    // (exactly what sites.zig's AuthSession does), then respondPrompt.
    const Sheet = struct {
        core: *AppCore,
        fake: *FakeStore,
        prompts: usize = 0,
        user_host_ok: bool = false,

        fn onPrompt(self: *@This(), e: events_mod.CoreEvent.PromptNeeded) void {
            self.prompts += 1;
            const p = e.prompt.password;
            self.user_host_ok = std.mem.eql(u8, p.user, "carol") and
                std.mem.eql(u8, p.host, "prompt.example");
            var diag: Diagnostics = .{};
            self.fake.set(&diag, .{
                .protocol = .ftp,
                .host = "prompt.example",
                .port = 21,
                .account = "carol",
            }, "sesame") catch {};
            self.core.respondPrompt(
                .{ .site_id = e.site_id, .prompt_id = e.prompt_id },
                .{ .auth = true },
            );
        }
    };
    var sheet: Sheet = .{ .core = h.core, .fake = &h.fake };
    try h.core.registerListener(.prompt_needed, &sheet, Sheet.onPrompt);

    const StatusRecorder = struct {
        connected: usize = 0,
        fn onStatus(self: *@This(), e: events_mod.CoreEvent.SiteStatusChange) void {
            if (e.site_id == 9 and e.status == .connected) self.connected += 1;
        }
        fn isConnected(self: *@This()) bool {
            return self.connected >= 1;
        }
    };
    var status: StatusRecorder = .{};
    try h.core.registerListener(.site_status, &status, StatusRecorder.onStatus);

    try h.core.connectSite(9);
    try h.waitUntil(&status, StatusRecorder.isConnected);

    try testing.expectEqual(@as(usize, 1), sheet.prompts);
    try testing.expect(sheet.user_host_ok);
    try testing.expectEqual(@as(usize, 1), hub.connects.load(.monotonic));
    // The retried fetch cached the freshly stored secret on the runtime.
    try testing.expectEqualStrings("sesame", h.core.site_runtimes.get(9).?.secret.?);

    // invalidateSiteSecret retires the cache so the next fetch re-reads.
    h.core.invalidateSiteSecret(9);
    try testing.expect(h.core.site_runtimes.get(9).?.secret == null);
    try testing.expectEqual(@as(usize, 1), h.core.site_runtimes.get(9).?.retired_secrets.items.len);
}

test "streaming listings publish coalesced partial snapshots before listing_done" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();
    const io = h.core.io;
    h.core.listing_partial_interval_ms = 0; // publish one partial per batch

    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "aa.txt", .data = "a" });
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "bb.txt", .data = "b" });
    try h.tmp_root.dir.createDir(io, "zdir", .default_dir);

    const Recorder = struct {
        done: bool = false,
        partial_entries: usize = 0,
        partial_sort_ok: bool = false,
        partial_before_done: bool = false,
        partial_first_name: [64]u8 = undefined,
        partial_first_len: usize = 0,

        fn onProgress(self: *@This(), p: ListingProgress) void {
            const snap = p.snapshot orelse return;
            self.partial_entries = snap.entries.len;
            self.partial_sort_ok = p.sort_index.len == snap.entries.len;
            if (!self.done) self.partial_before_done = true;
            if (p.sort_index.len > 0) {
                const name = snap.entries[p.sort_index[0]].name;
                const n = @min(name.len, self.partial_first_name.len);
                @memcpy(self.partial_first_name[0..n], name[0..n]);
                self.partial_first_len = n;
            }
        }
        fn onDone(self: *@This(), d: ListingDone) void {
            _ = d;
            self.done = true;
        }
        fn isDone(self: *@This()) bool {
            return self.done;
        }
    };
    var rec: Recorder = .{};
    try h.core.registerListener(.listing_progress, &rec, Recorder.onProgress);
    try h.core.registerListener(.listing_done, &rec, Recorder.onDone);

    _ = try h.core.listPath(4, item_mod.local_site_id, "/");
    try h.waitUntil(&rec, Recorder.isDone);

    try testing.expectEqual(@as(usize, 3), rec.partial_entries);
    try testing.expect(rec.partial_sort_ok);
    try testing.expect(rec.partial_before_done);
    // Partial carries the default sort: the directory leads.
    try testing.expectEqualStrings("zdir", rec.partial_first_name[0..rec.partial_first_len]);
    // No leaks: the job (and any unconsumed partial) was reclaimed.
    try testing.expectEqual(@as(usize, 0), h.core.pending_listings.count());
}

test "settings round-trip through saveSettings" {
    var h: TestHarness = undefined;
    try h.start(null);
    defer h.stop();

    h.core.settings.connections_per_site = 6;
    h.core.settings.verbose_transcript = true;
    try h.core.saveSettings();
    try testing.expectEqual(@as(u8, 6), h.core.budget_conns.load(.monotonic));

    const loaded = try settings_mod.load(h.core.io, h.tmp_conf.dir, settings_file, testing.allocator);
    try testing.expectEqual(@as(u8, 6), loaded.connections_per_site);
    try testing.expect(loaded.verbose_transcript);
}

test {
    std.testing.refAllDecls(@This());
}

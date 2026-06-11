//! transfers — the bottom transfer panel (docs/UX.md): segmented control
//! (Transfers · Failed · Transcript) swapping three content views, header
//! with aggregate progress + total rate + Pause All / Resume All / Retry
//! Failed / Clear Completed, Cmd+J collapse via the split_view wrapper, and
//! one-shot auto-expand when the first transfer of the session starts.
//!
//! M3 adds the bandwidth limits surface: a "Limits" header button toggling
//! a compact controls row (download/upload on/off + KB/s value) wired to
//! the queue engine's global token buckets. With a PrefsController
//! attached (`attachPrefs`) the strip routes through its `setRateLimit`,
//! so the Settings pane, settings.zon and the prefs change listeners all
//! stay coherent; standalone it falls back to `applyGlobalRateLimit`
//! below. Per-site concurrency stays in Settings (per the M3 brief).
//!
//! Tabs:
//!  - Transfers: table_source rows (filename, direction-arrow SF Symbol,
//!    flat progress tint, rate, ETA from the engine's EWMA rate, state),
//!    updated in place from coalesced transfer_progress events (id → row,
//!    reloadRange on the touched row only). Folder children render FLAT
//!    with a "parent/" name prefix. TODO(m2-followup): real tree grouping.
//!  - Failed: error class + verbatim server message (Diagnostics text from
//!    the transfer_state payload), Requeue All + per-row requeue.
//!  - Transcript: hosted TranscriptController (controllers/transcript.zig).
//!
//! Structure: `QueueModel` (rows, id→row map, aggregates) and the
//! formatting helpers are pure Zig, headless-tested; the controller owns
//! the AppKit surface, mutating UI state on the main thread only via the
//! bridge drain. Row membership truth is the engine queue: any event for an
//! unknown id (or any removal command) re-syncs from `queueSnapshot`.

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");
const transcript_mod = @import("transcript.zig");
const prefs_mod = @import("prefs.zig");

const controls = prefs_mod.controls;

const objc = mac.objc;
const c = objc.c;
const foundation = mac.foundation;
const runtime = mac.runtime;
const table_source = mac.appkit.table_source;
const split_view = mac.appkit.split_view;
const menu = mac.appkit.menu;

const uiglue = transcript_mod.uiglue;

const events_mod = relay.events;
const item_mod = relay.queue.item;
const engine_mod = relay.queue.engine;
const diag_mod = relay.diag;
const path_mod = relay.vfs.path;

const Allocator = std.mem.Allocator;
const ItemSnapshot = engine_mod.ItemSnapshot;
const TransferState = events_mod.TransferState;

// ---------------------------------------------------------------------------
// Formatting helpers (pure; headless-tested)
// ---------------------------------------------------------------------------

/// "532 B", "1.5 KB", "2.4 MB" — one decimal below 10 units, whole above.
pub fn humanBytes(buf: []u8, bytes: u64) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB", "PB" };
    if (bytes < 1024) return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "";
    var value: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    while (value >= 1024 and unit + 1 < units.len) : (unit += 1) value /= 1024;
    if (value < 10)
        return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "";
    return std.fmt.bufPrint(buf, "{d:.0} {s}", .{ value, units[unit] }) catch "";
}

/// "2.4 MB/s"; zero renders as an em dash (idle).
pub fn humanRate(buf: []u8, bytes_per_s: u64) []const u8 {
    if (bytes_per_s == 0) return "—";
    var tmp: [32]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/s", .{humanBytes(&tmp, bytes_per_s)}) catch "—";
}

/// Whole seconds remaining at the (EWMA-smoothed) rate; null = unknowable.
pub fn etaSeconds(bytes_done: u64, bytes_total: u64, rate_bps: u64) ?u64 {
    if (rate_bps == 0 or bytes_total == 0 or bytes_done >= bytes_total) return null;
    return std.math.divCeil(u64, bytes_total - bytes_done, rate_bps) catch null;
}

/// "0:42", "12:03", "1:02:03"; "—" when no estimate exists.
pub fn humanETA(buf: []u8, bytes_done: u64, bytes_total: u64, rate_bps: u64) []const u8 {
    const secs = etaSeconds(bytes_done, bytes_total, rate_bps) orelse return "—";
    const h = secs / 3600;
    const m = (secs % 3600) / 60;
    const s = secs % 60;
    if (h > 0)
        return std.fmt.bufPrint(buf, "{d}:{d:0>2}:{d:0>2}", .{ h, m, s }) catch "—";
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ m, s }) catch "—";
}

pub fn stateLabel(state: TransferState) []const u8 {
    return switch (state) {
        .queued => "Queued",
        .connecting => "Connecting",
        .transferring => "Transferring",
        .paused => "Paused",
        .completed => "Completed",
        .failed => "Failed",
        .canceled => "Canceled",
    };
}

pub fn errorClassLabel(class: diag_mod.ErrorClass) []const u8 {
    return switch (class) {
        .transient => "Transient",
        .permanent => "Permanent",
        .auth => "Auth",
        .cancel => "Canceled",
    };
}

// ---------------------------------------------------------------------------
// Bandwidth limits (M3): pure helpers + the apply seam
// ---------------------------------------------------------------------------

/// Checked-but-empty limit fields fall back here so the limiter is
/// observable instead of silently unlimited (same constant as the
/// Settings pane's applyRateRow).
pub const default_rate_bytes: u64 = 1024 * 1024;

/// Strip-field KB/s text → bytes/s; null = empty/invalid/zero (the caller
/// substitutes `default_rate_bytes`, mirroring the Settings pane).
pub fn rateFieldToBytes(text: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, text, " \t");
    const kb = std.fmt.parseInt(u64, trimmed, 10) catch 0;
    if (kb == 0) return null;
    return kb *| 1024;
}

/// Header-button caption summarizing the global caps (KB/s, the Settings
/// pane's unit). "Limits" when both directions are unlimited.
pub fn limitsButtonTitle(buf: []u8, down_bps: u64, up_bps: u64) []const u8 {
    if (down_bps == 0 and up_bps == 0) return "Limits";
    if (up_bps == 0)
        return std.fmt.bufPrint(buf, "Limits: ↓ {d} KB/s", .{down_bps / 1024}) catch "Limits";
    if (down_bps == 0)
        return std.fmt.bufPrint(buf, "Limits: ↑ {d} KB/s", .{up_bps / 1024}) catch "Limits";
    return std.fmt.bufPrint(buf, "Limits: ↓ {d} ↑ {d} KB/s", .{
        down_bps / 1024, up_bps / 1024,
    }) catch "Limits";
}

/// Persist + live-apply a global rate cap (0 = unlimited) when no
/// PrefsController is attached: settings slot → settings.zon → the queue
/// engine's token bucket (`Engine.setGlobalRateLimit` is main-thread safe;
/// it locks briefly, never across I/O).
///
/// TODO(m3-integrate): bridge.zig (not this task's file) still has no
/// setGlobalRateLimit pass-through — both this function and
/// prefs.PrefsController.setRateLimit reach `core.engine` directly (the
/// pre-existing TODO(m2-dedupe) in prefs.zig). When the integrator
/// promotes it to a bridge command, both call sites collapse onto it.
pub fn applyGlobalRateLimit(
    core: *bridge.AppCore,
    direction: prefs_mod.RateDirection,
    bytes_per_s: u64,
) void {
    const slot = switch (direction) {
        .download => &core.settings.rate_limit_down,
        .upload => &core.settings.rate_limit_up,
    };
    if (slot.* == bytes_per_s) return;
    slot.* = bytes_per_s;
    core.saveSettings() catch |err| {
        std.log.warn("transfers: failed to persist rate limits: {t}", .{err});
    };
    core.engine.setGlobalRateLimit(switch (direction) {
        .download => .download,
        .upload => .upload,
    }, bytes_per_s);
}

// ---------------------------------------------------------------------------
// Queue model (pure; headless-tested)
// ---------------------------------------------------------------------------

pub const name_cap = 200;
pub const fail_cap = 256;

pub const Row = struct {
    id: u64,
    parent: u64,
    direction: item_mod.Direction,
    kind: item_mod.Kind,
    conflict: item_mod.ConflictPolicy,
    state: TransferState,
    bytes_done: u64,
    bytes_total: u64,
    rate_bps: u64,
    src_site: u64,
    dst_site: u64,
    /// gpa-owned by the model (requeue + reveal need full endpoints).
    src_path: []u8,
    dst_path: []u8,
    name_buf: [name_cap]u8 = undefined,
    name_len: usize = 0,
    fail_class: ?diag_mod.ErrorClass = null,
    fail_buf: [fail_cap]u8 = undefined,
    fail_len: usize = 0,

    pub fn name(self: *const Row) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn failureMessage(self: *const Row) []const u8 {
        return self.fail_buf[0..self.fail_len];
    }

    /// The endpoint the transfer reads/writes on the remote-facing side
    /// (download: source; upload: destination) — reveal-in-pane target.
    pub fn remoteEndpoint(self: *const Row) item_mod.Endpoint {
        return switch (self.direction) {
            .download => .{ .site_id = self.src_site, .path = self.src_path },
            .upload => .{ .site_id = self.dst_site, .path = self.dst_path },
        };
    }

    fn setFailure(self: *Row, class: diag_mod.ErrorClass, message: []const u8) void {
        self.fail_class = class;
        self.fail_len = @min(message.len, fail_cap);
        @memcpy(self.fail_buf[0..self.fail_len], message[0..self.fail_len]);
    }

    fn setDisplayName(self: *Row, parent_base: ?[]const u8, base: []const u8) void {
        var n: usize = 0;
        if (parent_base) |pb| {
            const k = @min(pb.len, name_cap - 2);
            @memcpy(self.name_buf[0..k], pb[0..k]);
            n = k;
            self.name_buf[n] = '/';
            n += 1;
        }
        const k = @min(base.len, name_cap - n);
        @memcpy(self.name_buf[n..][0..k], base[0..k]);
        self.name_len = n + k;
    }

    pub fn progressFraction(self: *const Row) ?f64 {
        if (self.state == .completed) return 1.0;
        if (self.bytes_total == 0) return null;
        const done: f64 = @floatFromInt(self.bytes_done);
        const total: f64 = @floatFromInt(self.bytes_total);
        return @min(1.0, done / total);
    }
};

pub const Aggregate = struct {
    /// queued + connecting + transferring.
    active: usize = 0,
    /// Bytes over all non-terminal rows.
    done: u64 = 0,
    total: u64 = 0,
    /// Sum of EWMA rates over transferring rows.
    rate: u64 = 0,

    pub fn percent(self: Aggregate) ?u64 {
        if (self.total == 0) return null;
        return @min(100, self.done * 100 / self.total);
    }
};

pub const QueueModel = struct {
    gpa: Allocator,
    /// Queue order (== engine order at the last sync).
    rows: std.ArrayList(Row) = .empty,
    /// item id → index into `rows`.
    index: std.AutoHashMapUnmanaged(u64, usize) = .empty,

    pub fn deinit(self: *QueueModel) void {
        for (self.rows.items) |*row| self.freePaths(row);
        self.rows.deinit(self.gpa);
        self.index.deinit(self.gpa);
        self.* = undefined;
    }

    fn freePaths(self: *QueueModel, row: *Row) void {
        self.gpa.free(row.src_path);
        self.gpa.free(row.dst_path);
    }

    pub fn rowOf(self: *const QueueModel, id: u64) ?usize {
        return self.index.get(id);
    }

    /// Rebuild from an engine snapshot (queue order preserved). Display
    /// names are computed here: source basename, prefixed "parent/" for
    /// folder children (M2 renders groups flat).
    pub fn syncFromSnapshot(self: *QueueModel, snaps: []const ItemSnapshot) error{OutOfMemory}!void {
        for (self.rows.items) |*row| self.freePaths(row);
        self.rows.clearRetainingCapacity();
        self.index.clearRetainingCapacity();

        for (snaps, 0..) |snap, i| {
            // Reserve up front so the append after `index.put` cannot fail:
            // once a row holding the duped paths is in `rows`, deinit() owns
            // them, and an errdefer here would double-free.
            try self.rows.ensureUnusedCapacity(self.gpa, 1);
            const src_path = try self.gpa.dupe(u8, snap.src.path);
            errdefer self.gpa.free(src_path);
            const dst_path = try self.gpa.dupe(u8, snap.dst.path);
            errdefer self.gpa.free(dst_path);
            var row: Row = .{
                .id = snap.id,
                .parent = snap.parent,
                .direction = snap.direction,
                .kind = snap.kind,
                .conflict = snap.conflict,
                .state = snap.state.toEventState(),
                .bytes_done = snap.bytes_done,
                .bytes_total = snap.bytes_total,
                .rate_bps = snap.rate_bps,
                .src_site = snap.src.site_id,
                .dst_site = snap.dst.site_id,
                .src_path = src_path,
                .dst_path = dst_path,
            };
            const parent_base: ?[]const u8 = if (snap.parent != 0)
                parentBasename(snaps, snap.parent)
            else
                null;
            row.setDisplayName(parent_base, path_mod.basename(snap.src.path));
            if (snap.failure_class) |class| row.setFailure(class, snap.failure_message);
            try self.index.put(self.gpa, snap.id, i);
            self.rows.appendAssumeCapacity(row);
        }
    }

    fn parentBasename(snaps: []const ItemSnapshot, parent_id: u64) ?[]const u8 {
        for (snaps) |snap| {
            if (snap.id == parent_id) return path_mod.basename(snap.src.path);
        }
        return null;
    }

    /// Coalesced progress event → row in place. Returns the touched index.
    pub fn applyProgress(self: *QueueModel, id: u64, bytes_done: u64, rate: u64) ?usize {
        const idx = self.rowOf(id) orelse return null;
        const row = &self.rows.items[idx];
        row.bytes_done = bytes_done;
        row.rate_bps = rate;
        return idx;
    }

    /// State event → row in place; failure text (verbatim Diagnostics) is
    /// copied (the event payload is drain-arena-owned). Returns the index,
    /// or null for ids the model does not know (caller re-syncs).
    pub fn applyState(self: *QueueModel, id: u64, state: TransferState, failure: ?events_mod.Failure) ?usize {
        const idx = self.rowOf(id) orelse return null;
        const row = &self.rows.items[idx];
        row.state = state;
        if (failure) |f| row.setFailure(f.class, f.message);
        switch (state) {
            .completed => {
                if (row.bytes_total > 0) row.bytes_done = row.bytes_total;
                row.rate_bps = 0;
            },
            .canceled, .paused, .failed => row.rate_bps = 0,
            else => {},
        }
        return idx;
    }

    pub fn aggregate(self: *const QueueModel) Aggregate {
        var agg: Aggregate = .{};
        for (self.rows.items) |row| {
            switch (row.state) {
                .queued, .connecting, .transferring, .paused => {
                    agg.done += row.bytes_done;
                    agg.total += row.bytes_total;
                    if (row.state != .paused) agg.active += 1;
                    if (row.state == .transferring) agg.rate += row.rate_bps;
                },
                .completed, .failed, .canceled => {},
            }
        }
        return agg;
    }

    /// Indices of failed rows, queue order, into `out` (cleared first).
    pub fn failedIndices(self: *const QueueModel, gpa: Allocator, out: *std.ArrayList(usize)) error{OutOfMemory}!void {
        out.clearRetainingCapacity();
        for (self.rows.items, 0..) |row, i| {
            if (row.state == .failed) try out.append(gpa, i);
        }
    }
};

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

pub const Tab = enum(u2) { transfers, failed, transcript };

var g_target_class: ?runtime.DefinedClass = null;

fn targetClass() runtime.Error!runtime.DefinedClass {
    if (g_target_class) |dc| return dc;
    const dc = try runtime.defineClass("RelayTransfersTarget", "NSObject", &.{}, .{
        .{ "relayTransfersSegment:", impSegmentChanged },
        .{ "relayTransfersPauseAll:", impPauseAll },
        .{ "relayTransfersResumeAll:", impResumeAll },
        .{ "relayTransfersRetryFailed:", impRetryFailed },
        .{ "relayTransfersClearCompleted:", impClearCompleted },
    });
    g_target_class = dc;
    return dc;
}

const header_h: f64 = 30;
const limits_bar_h: f64 = 28;
const default_w: f64 = 980;
const default_h: f64 = 240;
const max_sel = 512;

const col_name = 0;
const col_progress = 1;
const col_rate = 2;
const col_eta = 3;
const col_state = 4;

const queue_columns = [_]table_source.ColumnSpec{
    .{ .id = "name", .title = "Name", .width = 280, .min_width = 120, .custom_draw = true },
    .{ .id = "progress", .title = "Progress", .width = 150, .min_width = 70, .custom_draw = true },
    .{ .id = "rate", .title = "Rate", .width = 84, .min_width = 60, .alignment = .right, .monospaced_digits = true },
    .{ .id = "eta", .title = "ETA", .width = 72, .min_width = 50, .alignment = .right, .monospaced_digits = true },
    .{ .id = "state", .title = "State", .width = 96, .min_width = 70 },
};

const fcol_name = 0;
const fcol_class = 1;
const fcol_message = 2;

const failed_columns = [_]table_source.ColumnSpec{
    .{ .id = "name", .title = "Name", .width = 240, .min_width = 120, .custom_draw = true },
    .{ .id = "class", .title = "Class", .width = 90, .min_width = 60 },
    .{ .id = "message", .title = "Server Message", .width = 430, .min_width = 150 },
};

pub const RevealFn = *const fn (ctx: ?*anyopaque, site_id: u64, dir: []const u8) void;

pub const TransfersController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    model: QueueModel,
    failed: std.ArrayList(usize) = .empty,

    transcript: *transcript_mod.TranscriptController,
    queue_table: *table_source.TableView,
    failed_table: *table_source.TableView,
    menu_reg: *menu.Registry,
    queue_menu: objc.Object,
    failed_menu: objc.Object,

    // AppKit handles (owned).
    root: objc.Object,
    header: objc.Object,
    content: objc.Object,
    seg: objc.Object,
    pause_btn: objc.Object,
    resume_btn: objc.Object,
    retry_btn: objc.Object,
    clear_btn: objc.Object,
    agg_label: objc.Object,
    target: objc.Object,
    icon_up: ?c.id,
    icon_down: ?c.id,

    // Panel collapse (the enclosing vertical split, attached by phase 3).
    panel_split: ?*split_view.SplitView = null,
    panel_index: usize = 0,
    did_auto_expand: bool = false,

    active_tab: Tab = .transfers,
    last_failed_count: usize = std.math.maxInt(usize),
    header_cache: [160]u8 = undefined,
    header_cache_len: usize = 0,

    // Reveal-in-pane hook (browser controller wires this in phase 3).
    reveal_ctx: ?*anyopaque = null,
    reveal_fn: ?RevealFn = null,

    // Bandwidth limits strip (M3). When a PrefsController is attached the
    // strip routes every change through its setRateLimit (single writer:
    // persist + engine + change listeners → the Settings pane stays in
    // sync); standalone it falls back to applyGlobalRateLimit.
    prefs: ?*prefs_mod.PrefsController = null,
    control_target: *controls.ControlTarget,
    limits_btn: objc.Object,
    limits_bar: objc.Object,
    limit_down_check: objc.Object,
    limit_down_field: objc.Object,
    limit_up_check: objc.Object,
    limit_up_field: objc.Object,
    limits_visible: bool = false,

    pub fn create(gpa: Allocator, core: *bridge.AppCore) !*TransfersController {
        const self = try gpa.create(TransfersController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .model = .{ .gpa = gpa },
            .transcript = undefined,
            .queue_table = undefined,
            .failed_table = undefined,
            .menu_reg = undefined,
            .queue_menu = undefined,
            .failed_menu = undefined,
            .root = undefined,
            .header = undefined,
            .content = undefined,
            .seg = undefined,
            .pause_btn = undefined,
            .resume_btn = undefined,
            .retry_btn = undefined,
            .clear_btn = undefined,
            .agg_label = undefined,
            .target = undefined,
            .icon_up = null,
            .icon_down = null,
            .control_target = undefined,
            .limits_btn = undefined,
            .limits_bar = undefined,
            .limit_down_check = undefined,
            .limit_down_field = undefined,
            .limit_up_check = undefined,
            .limit_up_field = undefined,
        };
        errdefer self.model.deinit();

        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        const dc = try targetClass();
        self.target = dc.newWithState(self);
        errdefer uiglue.release(self.target);

        self.menu_reg = try menu.Registry.create(gpa);
        errdefer self.menu_reg.destroy();

        self.transcript = try transcript_mod.TranscriptController.create(gpa, core);
        errdefer self.transcript.destroy();

        self.queue_table = try table_source.TableView.init(gpa, .{
            .columns = &queue_columns,
            .data_source = .{
                .ctx = self,
                .rowCount = qRowCount,
                .cellText = qCellText,
                .cellIcon = qCellIcon,
                .cellProgress = qCellProgress,
                .keyDown = qKeyDown,
                .contextMenu = qContextMenu,
            },
            .density = .compact,
            .autosave_name = "RelayTransfersQueue",
        });
        errdefer self.queue_table.deinit();

        self.failed_table = try table_source.TableView.init(gpa, .{
            .columns = &failed_columns,
            .data_source = .{
                .ctx = self,
                .rowCount = fRowCount,
                .cellText = fCellText,
                .cellIcon = fCellIcon,
                .keyDown = fKeyDown,
                .returnAction = fReturnAction,
                .contextMenu = fContextMenu,
            },
            .density = .compact,
            .autosave_name = "RelayTransfersFailed",
        });
        errdefer self.failed_table.deinit();

        const queue_items = [_]menu.Item{
            menu.Item.call("Cancel", .{ .ctx = self, .f = cmCancel }, "", .{}),
            menu.Item.call("Remove", .{ .ctx = self, .f = cmRemove }, "", .{}),
            .separator,
            menu.Item.call("Reveal in Pane", .{ .ctx = self, .f = cmReveal }, "", .{}),
        };
        self.queue_menu = try menu.buildContextMenu(self.menu_reg, &queue_items);
        errdefer uiglue.release(self.queue_menu);

        const failed_items = [_]menu.Item{
            menu.Item.call("Requeue", .{ .ctx = self, .f = cmRequeueSelected }, "", .{}),
            menu.Item.call("Requeue All", .{ .ctx = self, .f = cmRequeueAll }, "", .{}),
            .separator,
            menu.Item.call("Remove", .{ .ctx = self, .f = cmRemoveFailed }, "", .{}),
        };
        self.failed_menu = try menu.buildContextMenu(self.menu_reg, &failed_items);
        errdefer uiglue.release(self.failed_menu);

        self.icon_down = uiglue.retainId(table_source.systemSymbolImage("arrow.down.circle.fill"));
        self.icon_up = uiglue.retainId(table_source.systemSymbolImage("arrow.up.circle.fill"));

        self.control_target = try controls.ControlTarget.create(gpa);
        errdefer self.control_target.destroy();

        try self.buildViews();

        try core.registerListener(.transfer_state, self, onTransferState);
        try core.registerListener(.transfer_progress, self, onTransferProgress);
        self.refreshFromEngine();
        return self;
    }

    /// Tests/teardown only — listeners cannot unregister, so destroy only
    /// after the core stopped dispatching (post-shutdown).
    pub fn destroy(self: *TransfersController) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        uiglue.release(self.queue_menu);
        uiglue.release(self.failed_menu);
        self.queue_table.deinit();
        self.failed_table.deinit();
        self.transcript.destroy();
        self.menu_reg.destroy();
        uiglue.releaseId(self.icon_up);
        uiglue.releaseId(self.icon_down);
        uiglue.release(self.seg);
        uiglue.release(self.pause_btn);
        uiglue.release(self.resume_btn);
        uiglue.release(self.retry_btn);
        uiglue.release(self.clear_btn);
        uiglue.release(self.agg_label);
        uiglue.release(self.limits_bar);
        uiglue.release(self.header);
        uiglue.release(self.content);
        uiglue.release(self.root);
        uiglue.release(self.target);
        self.control_target.destroy();
        self.failed.deinit(self.gpa);
        self.model.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// The panel view to embed as the bottom split child.
    pub fn view(self: *TransfersController) c.id {
        return self.root.value;
    }

    /// Phase 3 wires the enclosing vertical split here so Cmd+J and the
    /// one-shot auto-expand can collapse/uncollapse the panel child.
    pub fn attachPanelSplit(self: *TransfersController, split: *split_view.SplitView, child_index: usize) void {
        self.panel_split = split;
        self.panel_index = child_index;
    }

    /// Cmd+J. Returns the new collapsed state (false = visible).
    pub fn togglePanel(self: *TransfersController) bool {
        const split = self.panel_split orelse return false;
        return split.toggleCollapse(self.panel_index);
    }

    pub fn setRevealHandler(self: *TransfersController, ctx: ?*anyopaque, f: RevealFn) void {
        self.reveal_ctx = ctx;
        self.reveal_fn = f;
    }

    pub fn showTab(self: *TransfersController, tab: Tab) void {
        self.active_tab = tab;
        uiglue.setHidden(objc.Object.fromId(self.queue_table.view()), tab != .transfers);
        uiglue.setHidden(objc.Object.fromId(self.failed_table.view()), tab != .failed);
        uiglue.setHidden(objc.Object.fromId(self.transcript.view()), tab != .transcript);
        self.seg.msgSend(void, "setSelectedSegment:", .{@as(foundation.NSInteger, @intFromEnum(tab))});
    }

    // --- view construction -------------------------------------------------

    fn buildViews(self: *TransfersController) error{OutOfMemory}!void {
        self.root = uiglue.makeView(foundation.rect(0, 0, default_w, default_h));

        // Header strip, pinned to the top edge.
        self.header = uiglue.makeView(foundation.rect(0, default_h - header_h, default_w, header_h));
        uiglue.setAutoresizing(self.header, uiglue.mask_width_sizable | uiglue.mask_min_y_margin);

        const seg_labels = [_][]const u8{ "Transfers", "Failed", "Transcript" };
        self.seg = uiglue.makeSegmented(
            &seg_labels,
            foundation.rect(8, 4, 280, 22),
            self.target.value,
            "relayTransfersSegment:",
        );
        self.pause_btn = uiglue.makeButton("Pause All", foundation.rect(300, 4, 84, 22), self.target.value, "relayTransfersPauseAll:");
        self.resume_btn = uiglue.makeButton("Resume All", foundation.rect(390, 4, 94, 22), self.target.value, "relayTransfersResumeAll:");
        self.retry_btn = uiglue.makeButton("Retry Failed", foundation.rect(490, 4, 96, 22), self.target.value, "relayTransfersRetryFailed:");
        self.clear_btn = uiglue.makeButton("Clear Completed", foundation.rect(592, 4, 120, 22), self.target.value, "relayTransfersClearCompleted:");
        self.agg_label = uiglue.makeLabel("Idle", foundation.rect(default_w - 158, 8, 150, 16), true);
        uiglue.setAutoresizing(self.agg_label, uiglue.mask_min_x_margin);

        // Bandwidth limits toggle (the strip below carries the controls).
        self.limits_btn = controls.makePushButton("Limits", foundation.rect(718, 4, 150, 22));
        try self.control_target.wire(self.limits_btn, self, onLimitsToggle);

        uiglue.addSubview(self.header, self.seg);
        uiglue.addSubview(self.header, self.pause_btn);
        uiglue.addSubview(self.header, self.resume_btn);
        uiglue.addSubview(self.header, self.retry_btn);
        uiglue.addSubview(self.header, self.clear_btn);
        uiglue.addSubview(self.header, self.limits_btn);
        uiglue.addSubview(self.header, self.agg_label);

        // Bandwidth limits strip (hidden until the Limits button shows it),
        // pinned right under the header.
        self.limits_bar = uiglue.makeView(foundation.rect(
            0,
            default_h - header_h - limits_bar_h,
            default_w,
            limits_bar_h,
        ));
        uiglue.setAutoresizing(self.limits_bar, uiglue.mask_width_sizable | uiglue.mask_min_y_margin);
        self.limit_down_check = controls.makeCheckbox("Limit download", foundation.rect(8, 5, 128, 18));
        self.limit_down_field = controls.makeTextField(foundation.rect(140, 3, 64, 22), "");
        self.limit_up_check = controls.makeCheckbox("Limit upload", foundation.rect(262, 5, 114, 18));
        self.limit_up_field = controls.makeTextField(foundation.rect(380, 3, 64, 22), "");
        try self.control_target.wire(self.limit_down_check, self, onLimitChanged);
        try self.control_target.wire(self.limit_down_field, self, onLimitChanged);
        try self.control_target.wire(self.limit_up_check, self, onLimitChanged);
        try self.control_target.wire(self.limit_up_field, self, onLimitChanged);
        controls.addSubview(self.limits_bar, self.limit_down_check);
        controls.addSubview(self.limits_bar, self.limit_down_field);
        controls.addSubview(self.limits_bar, controls.makeLabel(
            "KB/s",
            foundation.rect(208, 7, 40, 15),
            .{ .secondary = true, .small = true },
        ));
        controls.addSubview(self.limits_bar, self.limit_up_check);
        controls.addSubview(self.limits_bar, self.limit_up_field);
        controls.addSubview(self.limits_bar, controls.makeLabel(
            "KB/s",
            foundation.rect(448, 7, 40, 15),
            .{ .secondary = true, .small = true },
        ));
        controls.addSubview(self.limits_bar, controls.makeLabel(
            "Global caps · per-site concurrency lives in Settings",
            foundation.rect(508, 7, 340, 15),
            .{ .secondary = true, .small = true },
        ));
        uiglue.setHidden(self.limits_bar, true);

        // Content area hosting the three tab views.
        const content_frame = foundation.rect(0, 0, default_w, default_h - header_h);
        self.content = uiglue.makeView(content_frame);
        uiglue.setAutoresizing(self.content, uiglue.mask_width_sizable | uiglue.mask_height_sizable);

        const tabs = [_]c.id{ self.queue_table.view(), self.failed_table.view(), self.transcript.view() };
        for (tabs) |tab_view| {
            const obj = objc.Object.fromId(tab_view);
            uiglue.setFrame(obj, foundation.rect(0, 0, content_frame.size.width, content_frame.size.height));
            uiglue.setAutoresizing(obj, uiglue.mask_width_sizable | uiglue.mask_height_sizable);
            uiglue.addSubview(self.content, obj);
        }

        uiglue.addSubview(self.root, self.header);
        uiglue.addSubview(self.root, self.limits_bar);
        uiglue.addSubview(self.root, self.content);
        self.showTab(.transfers);
        self.syncLimitsUi();
    }

    // --- bandwidth limits strip ----------------------------------------------

    /// Phase 3: hand over the Settings controller so the strip and the
    /// Settings pane share one writer + change feed.
    pub fn attachPrefs(self: *TransfersController, pc: *prefs_mod.PrefsController) error{OutOfMemory}!void {
        self.prefs = pc;
        try pc.addChangeListener(self, onPrefsChanged);
        self.syncLimitsUi();
    }

    fn onPrefsChanged(ctx: ?*anyopaque) void {
        const self: *TransfersController = @ptrCast(@alignCast(ctx.?));
        self.syncLimitsUi();
    }

    /// Show/hide the limits strip, taking its height from the content area.
    pub fn setLimitsVisible(self: *TransfersController, visible: bool) void {
        if (self.limits_visible == visible) return;
        self.limits_visible = visible;
        var frame = self.content.msgSend(foundation.NSRect, "frame", .{});
        if (visible) {
            frame.size.height -= limits_bar_h;
        } else {
            frame.size.height += limits_bar_h;
        }
        uiglue.setFrame(self.content, frame);
        uiglue.setFrame(self.limits_bar, foundation.rect(
            frame.origin.x,
            frame.origin.y + frame.size.height,
            frame.size.width,
            limits_bar_h,
        ));
        uiglue.setHidden(self.limits_bar, !visible);
        if (visible) self.syncLimitsUi();
    }

    fn onLimitsToggle(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *TransfersController = @ptrCast(@alignCast(ctx.?));
        self.setLimitsVisible(!self.limits_visible);
    }

    fn onLimitChanged(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *TransfersController = @ptrCast(@alignCast(ctx.?));
        self.applyLimitRow(.download, self.limit_down_check, self.limit_down_field);
        self.applyLimitRow(.upload, self.limit_up_check, self.limit_up_field);
        self.syncLimitsUi();
    }

    /// Same semantics as the Settings pane's applyRateRow: unchecked = 0
    /// (unlimited); checked with no usable number = the observable 1 MB/s.
    fn applyLimitRow(
        self: *TransfersController,
        direction: prefs_mod.RateDirection,
        check: objc.Object,
        field: objc.Object,
    ) void {
        var bytes: u64 = 0;
        if (controls.isChecked(check)) {
            const text = controls.textValue(self.gpa, field) catch return;
            defer self.gpa.free(text);
            bytes = rateFieldToBytes(text) orelse default_rate_bytes;
        }
        self.setGlobalRate(direction, bytes);
    }

    fn setGlobalRate(self: *TransfersController, direction: prefs_mod.RateDirection, bytes_per_s: u64) void {
        if (self.prefs) |pc| {
            pc.setRateLimit(direction, bytes_per_s); // persists + engine + listeners
            return;
        }
        applyGlobalRateLimit(self.core, direction, bytes_per_s);
    }

    /// Push settings truth into the strip + the header button caption.
    fn syncLimitsUi(self: *TransfersController) void {
        const down = self.core.settings.rate_limit_down;
        const up = self.core.settings.rate_limit_up;
        var title_buf: [48]u8 = undefined;
        self.limits_btn.msgSend(void, "setTitle:", .{
            foundation.nsString(limitsButtonTitle(&title_buf, down, up)),
        });
        syncLimitRow(self.limit_down_check, self.limit_down_field, down);
        syncLimitRow(self.limit_up_check, self.limit_up_field, up);
    }

    fn syncLimitRow(check: objc.Object, field: objc.Object, bytes_per_s: u64) void {
        const on = bytes_per_s > 0;
        controls.setChecked(check, on);
        controls.setEnabled(field, on);
        if (on) {
            var buf: [24]u8 = undefined;
            controls.setTextValue(field, std.fmt.bufPrint(&buf, "{d}", .{bytes_per_s / 1024}) catch "?");
        }
    }

    // --- bridge events -------------------------------------------------------

    fn onTransferState(self: *TransfersController, e: events_mod.CoreEvent.TransferStateChange) void {
        // One-shot auto-expand when the session's first transfer starts
        // (paused restores must not pop the panel).
        if (!self.did_auto_expand and e.state != .paused) {
            self.did_auto_expand = true;
            if (self.panel_split) |split| {
                if (split.isCollapsed(self.panel_index)) split.uncollapse(self.panel_index);
            }
        }
        if (self.model.applyState(e.item_id, e.state, e.failure)) |idx| {
            self.queue_table.reloadRange(idx, 1);
        } else {
            // Unknown id: queue membership changed (enqueue, folder child,
            // restore) — the engine queue is truth.
            self.refreshFromEngine();
        }
        self.refreshFailedUi();
        self.updateAggregateLabel();
    }

    fn onTransferProgress(self: *TransfersController, e: events_mod.CoreEvent.TransferProgress) void {
        const idx = self.model.applyProgress(e.item_id, e.bytes_done, e.rate) orelse return;
        self.queue_table.reloadRange(idx, 1);
        self.updateAggregateLabel();
    }

    /// Re-sync rows from the engine queue (arena-per-call).
    pub fn refreshFromEngine(self: *TransfersController) void {
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena.deinit();
        const snaps = self.core.queueSnapshot(arena.allocator()) catch return;
        self.model.syncFromSnapshot(snaps) catch return;
        self.queue_table.reloadData();
        self.refreshFailedUi();
        self.updateAggregateLabel();
    }

    fn refreshFailedUi(self: *TransfersController) void {
        self.model.failedIndices(self.gpa, &self.failed) catch return;
        self.failed_table.reloadData();
        const count = self.failed.items.len;
        if (count != self.last_failed_count) {
            self.last_failed_count = count;
            var buf: [32]u8 = undefined;
            const label = if (count == 0)
                "Failed"
            else
                std.fmt.bufPrint(&buf, "Failed ({d})", .{count}) catch "Failed";
            uiglue.setSegmentLabel(self.seg, @intFromEnum(Tab.failed), label);
        }
    }

    fn updateAggregateLabel(self: *TransfersController) void {
        const agg = self.model.aggregate();
        var buf: [160]u8 = undefined;
        var text: []const u8 = "Idle";
        if (agg.active > 0) {
            var rate_buf: [32]u8 = undefined;
            const rate_s = humanRate(&rate_buf, agg.rate);
            text = if (agg.percent()) |pct|
                std.fmt.bufPrint(&buf, "{d} active · {d}% · {s}", .{ agg.active, pct, rate_s }) catch "…"
            else
                std.fmt.bufPrint(&buf, "{d} active · {s}", .{ agg.active, rate_s }) catch "…";
        }
        if (std.mem.eql(u8, text, self.header_cache[0..self.header_cache_len])) return;
        self.header_cache_len = @min(text.len, self.header_cache.len);
        @memcpy(self.header_cache[0..self.header_cache_len], text[0..self.header_cache_len]);
        uiglue.setLabelText(self.agg_label, text);
    }

    // --- actions ---------------------------------------------------------------

    /// Ids of the queue-table selection (the table scratch buffer is only
    /// valid until the next query, so ids are copied out first).
    fn selectedQueueIds(self: *TransfersController, buf: []u64) []const u64 {
        const rows = self.queue_table.selectedRows();
        var n: usize = 0;
        for (rows) |row| {
            if (row >= self.model.rows.items.len or n >= buf.len) continue;
            buf[n] = self.model.rows.items[row].id;
            n += 1;
        }
        return buf[0..n];
    }

    fn selectedFailedIds(self: *TransfersController, buf: []u64) []const u64 {
        const rows = self.failed_table.selectedRows();
        var n: usize = 0;
        for (rows) |frow| {
            if (frow >= self.failed.items.len or n >= buf.len) continue;
            const idx = self.failed.items[frow];
            if (idx >= self.model.rows.items.len) continue;
            buf[n] = self.model.rows.items[idx].id;
            n += 1;
        }
        return buf[0..n];
    }

    /// Space: pause running/queued, resume paused (terminal rows ignored).
    fn toggleSelectedPause(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        for (self.selectedQueueIds(&buf)) |id| {
            const idx = self.model.rowOf(id) orelse continue;
            switch (self.model.rows.items[idx].state) {
                .paused => _ = self.core.resumeTransfer(id) catch false,
                .queued, .connecting, .transferring => _ = self.core.pauseTransfer(id),
                .completed, .failed, .canceled => {},
            }
        }
    }

    fn removeSelected(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        for (self.selectedQueueIds(&buf)) |id| _ = self.core.removeTransfer(id);
        self.refreshFromEngine();
    }

    /// Cmd+. — cancel the selected transfers (state events follow).
    pub fn cancelSelected(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        for (self.selectedQueueIds(&buf)) |id| _ = self.core.cancelTransfer(id);
    }

    /// Menu/Transfers-header action: drop completed + canceled rows.
    pub fn clearCompleted(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        var n: usize = 0;
        for (self.model.rows.items) |row| {
            if (n >= buf.len) break;
            switch (row.state) {
                .completed, .canceled => {
                    buf[n] = row.id;
                    n += 1;
                },
                else => {},
            }
        }
        for (buf[0..n]) |id| _ = self.core.removeTransfer(id);
        self.refreshFromEngine();
    }

    /// Per-row requeue (Failed tab): fresh enqueue of the same spec, then
    /// drop the failed item. Folder children requeue as top-level items.
    /// TODO(m2-followup): engine-level per-item requeue keeping identity.
    fn requeueId(self: *TransfersController, id: u64) void {
        const idx = self.model.rowOf(id) orelse return;
        const row = &self.model.rows.items[idx];
        if (row.state != .failed) return;
        _ = self.core.enqueueTransfer(.{
            .direction = row.direction,
            .kind = row.kind,
            .src = .{ .site_id = row.src_site, .path = row.src_path },
            .dst = .{ .site_id = row.dst_site, .path = row.dst_path },
            .conflict = row.conflict,
            .bytes_total = row.bytes_total,
        }) catch return;
        _ = self.core.removeTransfer(id);
    }

    fn requeueSelectedFailed(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        for (self.selectedFailedIds(&buf)) |id| self.requeueId(id);
        self.refreshFromEngine();
    }

    fn removeSelectedFailed(self: *TransfersController) void {
        var buf: [max_sel]u64 = undefined;
        for (self.selectedFailedIds(&buf)) |id| _ = self.core.removeTransfer(id);
        self.refreshFromEngine();
    }

    /// Context menu: navigate the hosting pane to the item's directory.
    fn revealSelected(self: *TransfersController) void {
        const f = self.reveal_fn orelse return;
        const rows = self.queue_table.selectedRows();
        if (rows.len == 0 or rows[0] >= self.model.rows.items.len) return;
        const endpoint = self.model.rows.items[rows[0]].remoteEndpoint();
        f(self.reveal_ctx, endpoint.site_id, path_mod.parent(endpoint.path) orelse "/");
    }
};

// --- target class IMPs --------------------------------------------------------

fn controllerOf(target: c.id) *TransfersController {
    return g_target_class.?.state(TransfersController, target);
}

fn impSegmentChanged(target: c.id, _: c.SEL, sender: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const self = controllerOf(target);
    const seg = uiglue.selectedSegment(objc.Object.fromId(sender));
    const tab: Tab = switch (seg) {
        1 => .failed,
        2 => .transcript,
        else => .transfers,
    };
    self.showTab(tab);
}

fn impPauseAll(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).core.pauseAllTransfers();
}

fn impResumeAll(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).core.resumeAllTransfers() catch {};
}

fn impRetryFailed(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    _ = controllerOf(target).core.requeueFailed();
}

fn impClearCompleted(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).clearCompleted();
}

// --- context-menu callbacks -----------------------------------------------------

fn ctrl(ctx: ?*anyopaque) *TransfersController {
    return @ptrCast(@alignCast(ctx.?));
}

fn cmCancel(ctx: ?*anyopaque) void {
    ctrl(ctx).cancelSelected();
}

fn cmRemove(ctx: ?*anyopaque) void {
    ctrl(ctx).removeSelected();
}

fn cmReveal(ctx: ?*anyopaque) void {
    ctrl(ctx).revealSelected();
}

fn cmRequeueSelected(ctx: ?*anyopaque) void {
    ctrl(ctx).requeueSelectedFailed();
}

fn cmRequeueAll(ctx: ?*anyopaque) void {
    const self = ctrl(ctx);
    _ = self.core.requeueFailed();
}

fn cmRemoveFailed(ctx: ?*anyopaque) void {
    ctrl(ctx).removeSelectedFailed();
}

// --- queue table data source ------------------------------------------------------

fn qSelf(ctx: *anyopaque) *TransfersController {
    return @ptrCast(@alignCast(ctx));
}

fn qRowCount(ctx: *anyopaque) usize {
    return qSelf(ctx).model.rows.items.len;
}

fn qCellText(ctx: *anyopaque, row: usize, col: usize, buf: []u8) []const u8 {
    const self = qSelf(ctx);
    if (row >= self.model.rows.items.len) return "";
    const r = &self.model.rows.items[row];
    switch (col) {
        col_name => return r.name(),
        col_progress => {
            if (r.bytes_total > 0) {
                const pct = @min(@as(u64, 100), r.bytes_done * 100 / r.bytes_total);
                return std.fmt.bufPrint(buf, "{d}%", .{pct}) catch "";
            }
            if (r.bytes_done > 0) return humanBytes(buf, r.bytes_done);
            return "";
        },
        col_rate => {
            if (r.state != .transferring) return "—";
            return humanRate(buf, r.rate_bps);
        },
        col_eta => {
            if (r.state != .transferring) return "—";
            return humanETA(buf, r.bytes_done, r.bytes_total, r.rate_bps);
        },
        col_state => return stateLabel(r.state),
        else => return "",
    }
}

fn qCellIcon(ctx: *anyopaque, row: usize, col: usize) ?c.id {
    const self = qSelf(ctx);
    if (col != col_name or row >= self.model.rows.items.len) return null;
    return switch (self.model.rows.items[row].direction) {
        .upload => self.icon_up,
        .download => self.icon_down,
    };
}

fn qCellProgress(ctx: *anyopaque, row: usize, col: usize) ?f64 {
    const self = qSelf(ctx);
    if (col != col_progress or row >= self.model.rows.items.len) return null;
    return self.model.rows.items[row].progressFraction();
}

fn qKeyDown(ctx: *anyopaque, ev: table_source.KeyEvent) bool {
    const self = qSelf(ctx);
    if (ev.command and std.mem.eql(u8, ev.chars, ".")) {
        self.cancelSelected();
        return true;
    }
    if (ev.command or ev.control or ev.option) return false;
    switch (ev.key_code) {
        table_source.key_space => {
            self.toggleSelectedPause();
            return true;
        },
        table_source.key_delete, table_source.key_forward_delete => {
            self.removeSelected();
            return true;
        },
        else => return false,
    }
}

fn qContextMenu(ctx: *anyopaque, row: ?usize) ?c.id {
    const self = qSelf(ctx);
    if (row == null) return null;
    return self.queue_menu.value;
}

// --- failed table data source -------------------------------------------------------

fn fRowCount(ctx: *anyopaque) usize {
    return qSelf(ctx).failed.items.len;
}

fn fModelRow(self: *TransfersController, frow: usize) ?*const Row {
    if (frow >= self.failed.items.len) return null;
    const idx = self.failed.items[frow];
    if (idx >= self.model.rows.items.len) return null;
    return &self.model.rows.items[idx];
}

fn fCellText(ctx: *anyopaque, row: usize, col: usize, buf: []u8) []const u8 {
    _ = buf;
    const self = qSelf(ctx);
    const r = fModelRow(self, row) orelse return "";
    return switch (col) {
        fcol_name => r.name(),
        fcol_class => if (r.fail_class) |class| errorClassLabel(class) else "—",
        fcol_message => r.failureMessage(),
        else => "",
    };
}

fn fCellIcon(ctx: *anyopaque, row: usize, col: usize) ?c.id {
    const self = qSelf(ctx);
    if (col != fcol_name) return null;
    const r = fModelRow(self, row) orelse return null;
    return switch (r.direction) {
        .upload => self.icon_up,
        .download => self.icon_down,
    };
}

fn fKeyDown(ctx: *anyopaque, ev: table_source.KeyEvent) bool {
    const self = qSelf(ctx);
    if (ev.command or ev.control or ev.option) return false;
    switch (ev.key_code) {
        table_source.key_delete, table_source.key_forward_delete => {
            self.removeSelectedFailed();
            return true;
        },
        else => return false,
    }
}

fn fReturnAction(ctx: *anyopaque, row: ?usize) void {
    _ = row;
    qSelf(ctx).requeueSelectedFailed();
}

fn fContextMenu(ctx: *anyopaque, row: ?usize) ?c.id {
    const self = qSelf(ctx);
    if (row == null) return null;
    return self.failed_menu.value;
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
const testing = std.testing;

test "humanBytes formatting" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0 B", humanBytes(&buf, 0));
    try testing.expectEqualStrings("532 B", humanBytes(&buf, 532));
    try testing.expectEqualStrings("1.5 KB", humanBytes(&buf, 1536));
    try testing.expectEqualStrings("250 KB", humanBytes(&buf, 256_000));
    try testing.expectEqualStrings("2.4 MB", humanBytes(&buf, 2_516_582));
    try testing.expectEqualStrings("5.0 MB", humanBytes(&buf, 5 * 1024 * 1024));
    try testing.expectEqualStrings("3.0 GB", humanBytes(&buf, 3 * 1024 * 1024 * 1024));
}

test "humanRate formatting" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("—", humanRate(&buf, 0));
    try testing.expectEqualStrings("2.4 MB/s", humanRate(&buf, 2_516_582));
    try testing.expectEqualStrings("512 B/s", humanRate(&buf, 512));
}

test "etaSeconds math" {
    try testing.expectEqual(@as(?u64, null), etaSeconds(0, 100, 0)); // no rate
    try testing.expectEqual(@as(?u64, null), etaSeconds(0, 0, 10)); // unknown total
    try testing.expectEqual(@as(?u64, null), etaSeconds(100, 100, 10)); // done
    try testing.expectEqual(@as(?u64, 10), etaSeconds(0, 100, 10));
    try testing.expectEqual(@as(?u64, 13), etaSeconds(0, 100, 8)); // ceil
}

test "humanETA formatting" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("—", humanETA(&buf, 0, 100, 0));
    try testing.expectEqualStrings("0:10", humanETA(&buf, 0, 100, 10));
    try testing.expectEqualStrings("12:30", humanETA(&buf, 0, 7500, 10));
    try testing.expectEqualStrings("1:01:40", humanETA(&buf, 0, 37000, 10));
}

fn snapItem(
    id: u64,
    parent: u64,
    kind: item_mod.Kind,
    state: item_mod.State,
    src_site: u64,
    src: []const u8,
    dst: []const u8,
    total: u64,
) ItemSnapshot {
    return .{
        .id = id,
        .parent = parent,
        .direction = .download,
        .kind = kind,
        .conflict = .overwrite,
        .state = state,
        .src = .{ .site_id = src_site, .path = src },
        .dst = .{ .site_id = 0, .path = dst },
        .bytes_done = 0,
        .bytes_total = total,
        .rate_bps = 0,
        .attempts = 0,
        .failure_class = null,
        .failure_message = "",
    };
}

test "queue model: sync builds id mapping, names, and parent prefixes" {
    var model: QueueModel = .{ .gpa = testing.allocator };
    defer model.deinit();

    const snaps = [_]ItemSnapshot{
        snapItem(1, 0, .folder, .resolving, 4, "/pub/photos", "/dl/photos", 0),
        snapItem(2, 1, .file, .queued, 4, "/pub/photos/a.jpg", "/dl/photos/a.jpg", 100),
        snapItem(3, 0, .file, .transferring, 4, "/pub/b.iso", "/dl/b.iso", 1000),
    };
    try model.syncFromSnapshot(&snaps);

    try testing.expectEqual(@as(usize, 3), model.rows.items.len);
    try testing.expectEqual(@as(?usize, 0), model.rowOf(1));
    try testing.expectEqual(@as(?usize, 1), model.rowOf(2));
    try testing.expectEqual(@as(?usize, 2), model.rowOf(3));
    try testing.expectEqualStrings("photos", model.rows.items[0].name());
    // Folder child renders flat with the parent prefix (M2).
    try testing.expectEqualStrings("photos/a.jpg", model.rows.items[1].name());
    try testing.expectEqualStrings("b.iso", model.rows.items[2].name());
    // item.State projects onto the event vocabulary.
    try testing.expectEqual(TransferState.connecting, model.rows.items[0].state);
    try testing.expectEqual(TransferState.transferring, model.rows.items[2].state);
}

test "queue model: id mapping survives insert, remove, and reorder" {
    var model: QueueModel = .{ .gpa = testing.allocator };
    defer model.deinit();

    const first = [_]ItemSnapshot{
        snapItem(10, 0, .file, .queued, 1, "/a", "/la", 1),
        snapItem(11, 0, .file, .queued, 1, "/b", "/lb", 1),
    };
    try model.syncFromSnapshot(&first);
    try testing.expectEqual(@as(?usize, 0), model.rowOf(10));
    try testing.expectEqual(@as(?usize, 1), model.rowOf(11));

    // Reorder + insert.
    const second = [_]ItemSnapshot{
        snapItem(11, 0, .file, .queued, 1, "/b", "/lb", 1),
        snapItem(12, 0, .file, .queued, 1, "/c", "/lc", 1),
        snapItem(10, 0, .file, .queued, 1, "/a", "/la", 1),
    };
    try model.syncFromSnapshot(&second);
    try testing.expectEqual(@as(?usize, 2), model.rowOf(10));
    try testing.expectEqual(@as(?usize, 0), model.rowOf(11));
    try testing.expectEqual(@as(?usize, 1), model.rowOf(12));

    // Progress routes through the map, not stale positions.
    try testing.expectEqual(@as(?usize, 2), model.applyProgress(10, 5, 50));
    try testing.expectEqual(@as(u64, 5), model.rows.items[2].bytes_done);

    // Remove.
    const third = [_]ItemSnapshot{
        snapItem(12, 0, .file, .queued, 1, "/c", "/lc", 1),
    };
    try model.syncFromSnapshot(&third);
    try testing.expectEqual(@as(?usize, null), model.rowOf(10));
    try testing.expectEqual(@as(?usize, null), model.rowOf(11));
    try testing.expectEqual(@as(?usize, 0), model.rowOf(12));
    try testing.expectEqual(@as(?usize, null), model.applyProgress(10, 9, 9));
}

test "queue model: state events copy verbatim failure text" {
    var model: QueueModel = .{ .gpa = testing.allocator };
    defer model.deinit();

    const snaps = [_]ItemSnapshot{
        snapItem(7, 0, .file, .transferring, 2, "/x.bin", "/lx.bin", 100),
    };
    try model.syncFromSnapshot(&snaps);

    var msg_buf: [32]u8 = undefined;
    @memcpy(msg_buf[0..21], "550 Permission denied");
    const idx = model.applyState(7, .failed, .{
        .class = .permanent,
        .protocol_code = 550,
        .message = msg_buf[0..21],
    });
    try testing.expectEqual(@as(?usize, 0), idx);
    @memset(&msg_buf, 'x'); // event arena dies after dispatch; model copied
    try testing.expectEqualStrings("550 Permission denied", model.rows.items[0].failureMessage());
    try testing.expectEqual(diag_mod.ErrorClass.permanent, model.rows.items[0].fail_class.?);

    var failed: std.ArrayList(usize) = .empty;
    defer failed.deinit(testing.allocator);
    try model.failedIndices(testing.allocator, &failed);
    try testing.expectEqualSlices(usize, &.{0}, failed.items);

    // Unknown ids report null so the controller re-syncs.
    try testing.expectEqual(@as(?usize, null), model.applyState(999, .queued, null));
}

test "queue model: aggregate covers non-terminal rows only" {
    var model: QueueModel = .{ .gpa = testing.allocator };
    defer model.deinit();

    const snaps = [_]ItemSnapshot{
        snapItem(1, 0, .file, .transferring, 1, "/a", "/la", 1000),
        snapItem(2, 0, .file, .queued, 1, "/b", "/lb", 1000),
        snapItem(3, 0, .file, .paused, 1, "/c", "/lc", 1000),
        snapItem(4, 0, .file, .done, 1, "/d", "/ld", 1000),
        snapItem(5, 0, .file, .failed, 1, "/e", "/le", 1000),
    };
    try model.syncFromSnapshot(&snaps);
    _ = model.applyProgress(1, 500, 64);

    const agg = model.aggregate();
    try testing.expectEqual(@as(usize, 2), agg.active); // transferring + queued
    try testing.expectEqual(@as(u64, 500), agg.done);
    try testing.expectEqual(@as(u64, 3000), agg.total); // paused still counts
    try testing.expectEqual(@as(u64, 64), agg.rate);
    try testing.expectEqual(@as(?u64, 16), agg.percent());

    // Completed pins progress; terminal states zero the rate.
    _ = model.applyState(1, .completed, null);
    try testing.expectEqual(@as(u64, 1000), model.rows.items[0].bytes_done);
    try testing.expectEqual(@as(u64, 0), model.rows.items[0].rate_bps);
    try testing.expectEqual(@as(?f64, 1.0), model.rows.items[0].progressFraction());
}

test "row helpers: progress fraction, remote endpoint, name truncation" {
    var model: QueueModel = .{ .gpa = testing.allocator };
    defer model.deinit();

    var up = snapItem(1, 0, .file, .transferring, 0, "/local/f.bin", "/remote/f.bin", 200);
    up.direction = .upload;
    up.dst = .{ .site_id = 9, .path = "/remote/f.bin" };
    const snaps = [_]ItemSnapshot{up};
    try model.syncFromSnapshot(&snaps);

    _ = model.applyProgress(1, 50, 10);
    try testing.expectEqual(@as(?f64, 0.25), model.rows.items[0].progressFraction());
    const endpoint = model.rows.items[0].remoteEndpoint();
    try testing.expectEqual(@as(u64, 9), endpoint.site_id);
    try testing.expectEqualStrings("/remote/f.bin", endpoint.path);

    var row: Row = model.rows.items[0];
    const long = "n" ** (name_cap + 50);
    row.setDisplayName("parent", long);
    try testing.expectEqual(@as(usize, name_cap), row.name().len);
    try testing.expect(std.mem.startsWith(u8, row.name(), "parent/"));
}

test "state and error-class labels" {
    try testing.expectEqualStrings("Transferring", stateLabel(.transferring));
    try testing.expectEqualStrings("Failed", stateLabel(.failed));
    try testing.expectEqualStrings("Auth", errorClassLabel(.auth));
    try testing.expectEqualStrings("Transient", errorClassLabel(.transient));
}

test "queue model: allocation failures neither leak nor corrupt" {
    const Fns = struct {
        fn cycle(gpa: Allocator) !void {
            var model: QueueModel = .{ .gpa = gpa };
            defer model.deinit();
            const snaps = [_]ItemSnapshot{
                snapItem(1, 0, .folder, .queued, 1, "/dir", "/ldir", 0),
                snapItem(2, 1, .file, .queued, 1, "/dir/a", "/ldir/a", 10),
            };
            try model.syncFromSnapshot(&snaps);
            try model.syncFromSnapshot(&snaps); // resync path frees + rebuilds
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Fns.cycle, .{});
}

test "rate field parsing mirrors the Settings pane semantics" {
    try testing.expectEqual(@as(?u64, 512 * 1024), rateFieldToBytes("512"));
    try testing.expectEqual(@as(?u64, 1024), rateFieldToBytes(" 1 "));
    try testing.expectEqual(@as(?u64, null), rateFieldToBytes(""));
    try testing.expectEqual(@as(?u64, null), rateFieldToBytes("0"));
    try testing.expectEqual(@as(?u64, null), rateFieldToBytes("banana"));
    try testing.expectEqual(@as(?u64, null), rateFieldToBytes("-3"));
    // Saturating multiply: absurd input cannot overflow.
    try testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        rateFieldToBytes("18446744073709551615"),
    );
}

test "limits button title summarizes the caps" {
    var buf: [48]u8 = undefined;
    try testing.expectEqualStrings("Limits", limitsButtonTitle(&buf, 0, 0));
    try testing.expectEqualStrings("Limits: ↓ 500 KB/s", limitsButtonTitle(&buf, 500 * 1024, 0));
    try testing.expectEqualStrings("Limits: ↑ 250 KB/s", limitsButtonTitle(&buf, 0, 250 * 1024));
    try testing.expectEqualStrings(
        "Limits: ↓ 500 ↑ 250 KB/s",
        limitsButtonTitle(&buf, 500 * 1024, 250 * 1024),
    );
}

test "applyGlobalRateLimit persists settings and retunes the engine buckets" {
    const gpa = testing.allocator;
    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = relay.cred.fake.FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });
    defer core.shutdown();

    // Defaults: unlimited both ways.
    try testing.expectEqual(@as(u64, 0), core.engine.global_down.rate);
    try testing.expectEqual(@as(u64, 0), core.engine.global_up.rate);

    applyGlobalRateLimit(core, .download, 512 * 1024);
    applyGlobalRateLimit(core, .upload, 256 * 1024);
    try testing.expectEqual(@as(u64, 512 * 1024), core.settings.rate_limit_down);
    try testing.expectEqual(@as(u64, 512 * 1024), core.engine.global_down.rate);
    try testing.expectEqual(@as(u64, 256 * 1024), core.engine.global_up.rate);

    // Persisted: a fresh settings load sees both caps.
    const on_disk = try relay.settings.load(core.io, tmp_conf.dir, bridge.settings_file, gpa);
    try testing.expectEqual(@as(u64, 512 * 1024), on_disk.rate_limit_down);
    try testing.expectEqual(@as(u64, 256 * 1024), on_disk.rate_limit_up);

    // No-change calls are no-ops; switching off returns to unlimited.
    applyGlobalRateLimit(core, .download, 512 * 1024);
    try testing.expectEqual(@as(u64, 512 * 1024), core.engine.global_down.rate);
    applyGlobalRateLimit(core, .download, 0);
    try testing.expectEqual(@as(u64, 0), core.engine.global_down.rate);
    try testing.expectEqual(@as(u64, 0), core.settings.rate_limit_down);
}

test "target class defines and round-trips state (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const dc = try targetClass();
    var probe: TransfersController = undefined;
    probe.panel_index = 3;
    const obj = dc.newWithState(&probe);
    defer obj.msgSend(void, "release", .{});
    try testing.expectEqual(&probe, dc.state(TransfersController, obj.value));
}

// ---------------------------------------------------------------------------
// Visual smoke (window on screen; opt-in): RELAY_VISUAL_SMOKE=1 zig build test
// ---------------------------------------------------------------------------
test "visual smoke: transfer panel with synthetic events (set RELAY_VISUAL_SMOKE=1)" {
    if (std.c.getenv("RELAY_VISUAL_SMOKE") == null) return error.SkipZigTest;
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = relay.cred.fake.FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    const app = mac.appkit.window.App.shared();
    app.setRegularActivationPolicy();

    const tc = try TransfersController.create(gpa, core);
    const win = mac.appkit.window.Window.create(
        foundation.rect(200, 200, 980, 320),
        "Relay — transfer panel smoke",
        mac.appkit.window.StyleMask.standard,
    );
    win.setContentView(objc.Object.fromId(tc.view()));
    win.makeKeyAndOrderFront();
    app.activate();
    tc.setLimitsVisible(true); // bandwidth strip visible for the eyeball pass

    // Real queue items: two paused (driven synthetically below) and one
    // live local transfer whose source is missing → a real Failed row with
    // the verbatim errno message.
    const id_a = try core.enqueueTransfer(.{
        .direction = .download,
        .src = .{ .site_id = 4, .path = "/pub/relay-big.iso" },
        .dst = .{ .path = "/Users/demo/Downloads/relay-big.iso" },
        .bytes_total = 700 * 1024 * 1024,
        .start_paused = true,
    });
    const id_b = try core.enqueueTransfer(.{
        .direction = .upload,
        .src = .{ .path = "/Users/demo/site/index.html" },
        .dst = .{ .site_id = 4, .path = "/www/index.html" },
        .bytes_total = 48 * 1024,
        .start_paused = true,
    });
    _ = try core.enqueueTransfer(.{
        .direction = .download,
        .src = .{ .path = "/missing-source.bin" },
        .dst = .{ .path = "/missing-dest.bin" },
    });
    core.drainNow();

    var done_a: u64 = 0;
    for (0..70) |i| {
        if (i == 2) {
            _ = core.events_q.post(.{ .transfer_state = .{ .item_id = id_a, .state = .transferring } }) catch {};
            _ = core.events_q.post(.{ .transfer_state = .{ .item_id = id_b, .state = .connecting } }) catch {};
        }
        done_a = @min(done_a + 9 * 1024 * 1024, 700 * 1024 * 1024);
        _ = core.events_q.post(.{ .transfer_progress = .{
            .item_id = id_a,
            .bytes_done = done_a,
            .rate = 9 * 1024 * 1024,
        } }) catch {};

        var line_buf: [64]u8 = undefined;
        const dir: relay.transcript.Direction = if (i % 3 == 0) .client else .server;
        const text = std.fmt.bufPrint(&line_buf, "{s} synthetic line {d}", .{
            if (dir == .client) "STOR" else "150", i,
        }) catch "";
        _ = core.events_q.post(.{ .transcript_line = .{
            .connection_id = 1 + (i % 2),
            .seq = i,
            .dir = dir,
            .verbose = false,
            .text = text,
        } }) catch {};
        if (i == 10) {
            _ = core.events_q.post(.{ .transcript_line = .{
                .connection_id = 1,
                .seq = 1000,
                .dir = .server,
                .verbose = false,
                .text = "550 Failed to open file.",
            } }) catch {};
        }

        core.drainNow();
        uiglue.runLoopSpin(0.05);
    }

    try testing.expect(tc.model.rows.items.len >= 3);
    try testing.expect(tc.model.rowOf(id_a) != null);
    try testing.expectEqual(TransferState.transferring, tc.model.rows.items[tc.model.rowOf(id_a).?].state);
    try testing.expect(tc.transcript.model.count() > 0);
    try testing.expect(tc.transcript.model.connCount() >= 2);

    win.orderOut();
    win.release();
    core.shutdown();
    tc.destroy();
}

test {
    std.testing.refAllDecls(@This());
}

//! browser — the dual-pane file browser (M2, docs/UX.md).
//!
//! Two `BrowserPane`s in an autosaved horizontal split. Each pane owns its
//! chrome (path bar, filter field, status bar) plus a relay_mac
//! table_source.TableView over the pane's current `DirSnapshot`:
//!
//!  - The UI never copies entries: the pane holds a snapshot ref, a
//!    gpa-owned sort permutation, and a derived *visible* permutation
//!    (hidden-files toggle + Cmd+F live filter + optimistic overlay).
//!  - Listings stream: `listing_progress` drives the "Listing… N" status
//!    count-up; the finished snapshot swaps in at `listing_done` (stale
//!    results are dropped by request id / generation).
//!  - File ops are optimistic (UX.md): rename shows the new name and delete
//!    hides rows immediately; a pending-set drives the 60%-alpha row
//!    treatment; `op_done` failure rolls back + presents an error sheet;
//!    success reconciles through the bridge's automatic re-list.
//!  - Cmd+Return / drags enqueue transfers to the other pane via the bridge.
//!
//! Phase 2 power features (all toggles exposed as pub methods for the
//! menu/palette owner to bind):
//!  - Synchronized browsing (Cmd+Shift+B; command "view.syncBrowsing"):
//!    relative path changes mirror into the other pane; a missing mirrored
//!    dir stops the link gracefully with a status hint.
//!  - Directory comparison (Cmd+Shift+D; command "view.comparePanes"):
//!    rows tint by cross-pane presence/size/mtime delta (semantic colors at
//!    low alpha), computed off-main over both snapshots.
//!  - Per-site accent strip + prod safeguards: a 2pt strip under the remote
//!    path bar (striped warning for environment == .prod); prod deletes
//!    need Cmd held in the confirm sheet whose default button is Cancel.
//!  - Vim mode (pref "ui.vimMode", off by default; setVimMode): a keymap
//!    layer in the table keyDown hook — see vim.zig for the state machine.
//!
//! Threading: everything here runs on the main thread; core results arrive
//! through AppCore's listener dispatch (run-to-completion drains). The one
//! exception is the compare diff, computed on a GCD global queue over two
//! ref'd immutable snapshots and applied back via the main queue.
//!
//! Lifetime: a BrowserController can be torn down while the AppCore keeps
//! running — `core.unregisterListeners(controller)` then `destroy()`
//! (closing a tab) — or after `AppCore.shutdown()` (app quit; shutdown
//! frees the listener lists, and the core pointer, itself).

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("relay_ui").bridge;

/// The vim-mode keymap layer (pure state machine; instances live on the
/// panes). Kept a separate file, imported ONLY from here.
pub const vim = @import("relay_ui").vim;

const objc = mac.objc;
const c = objc.c;
const foundation = mac.foundation;
const runtime = mac.runtime;
const dispatch = mac.dispatch;
const table_source = mac.appkit.table_source;
const split_view = mac.appkit.split_view;
const panels = mac.appkit.panels;
const window_mod = mac.appkit.window;
const drag = mac.appkit.drag;
const banner_mod = mac.appkit.banner;

const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;
const snapshot_mod = relay.vfs.snapshot;
const item_mod = relay.queue.item;
const events_mod = relay.events;
const sites_mod = relay.sites;

const DirSnapshot = snapshot_mod.DirSnapshot;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Pure pane logic (headless-tested): history, optimistic overlay, the
// visible permutation, path-bar parsing, formatting, type-select.
// ---------------------------------------------------------------------------

/// Per-pane back/forward navigation history. All paths are owned copies.
/// `goBack`/`goForward` mutate immediately (the navigation they trigger is
/// issued with `.replace` so it records nothing on completion).
pub const History = struct {
    back: std.ArrayList([]u8) = .empty,
    fwd: std.ArrayList([]u8) = .empty,
    cur: ?[]u8 = null,

    pub fn deinit(h: *History, gpa: Allocator) void {
        for (h.back.items) |p| gpa.free(p);
        for (h.fwd.items) |p| gpa.free(p);
        h.back.deinit(gpa);
        h.fwd.deinit(gpa);
        if (h.cur) |p| gpa.free(p);
        h.* = undefined;
    }

    pub fn current(h: *const History) ?[]const u8 {
        return h.cur;
    }

    pub fn canGoBack(h: *const History) bool {
        return h.back.items.len > 0;
    }

    pub fn canGoForward(h: *const History) bool {
        return h.fwd.items.len > 0;
    }

    /// Record a successful navigation: pushes the old current onto the back
    /// stack and clears the forward stack. Re-visiting the current path is
    /// a no-op.
    pub fn visit(h: *History, gpa: Allocator, path: []const u8) error{OutOfMemory}!void {
        if (h.cur) |cur| {
            if (std.mem.eql(u8, cur, path)) return;
        }
        const copy = try gpa.dupe(u8, path);
        if (h.cur) |cur| {
            h.back.append(gpa, cur) catch |err| {
                gpa.free(copy);
                return err;
            };
            h.cur = null;
        }
        for (h.fwd.items) |p| gpa.free(p);
        h.fwd.clearRetainingCapacity();
        h.cur = copy;
    }

    /// Step back; returns the new current path (borrowed) or null.
    pub fn goBack(h: *History, gpa: Allocator) ?[]const u8 {
        const prev = h.back.pop() orelse return null;
        if (h.cur) |cur| h.fwd.append(gpa, cur) catch gpa.free(cur);
        h.cur = prev;
        return prev;
    }

    /// Step forward; returns the new current path (borrowed) or null.
    pub fn goForward(h: *History, gpa: Allocator) ?[]const u8 {
        const next = h.fwd.pop() orelse return null;
        if (h.cur) |cur| h.back.append(gpa, cur) catch gpa.free(cur);
        h.cur = next;
        return next;
    }
};

/// Visible-row slot value marking the optimistic "new folder" virtual row
/// (mkdir in flight; the snapshot is immutable so the row cannot live in it).
pub const virtual_new_folder_row: u32 = std.math.maxInt(u32);

/// Optimistic mutations layered over the immutable snapshot, plus the
/// pending-set the row treatment consults. Cleared whole on snapshot swap
/// (the re-list after a successful op reconciles from truth).
pub const Overlay = struct {
    /// entry index -> optimistic display name (owned).
    renames: std.AutoHashMapUnmanaged(u32, []u8) = .empty,
    /// entry indexes optimistically removed (delete in flight).
    hidden: std.AutoHashMapUnmanaged(u32, void) = .empty,
    /// entry index -> staged mode (chmod in flight; inspector Apply).
    modes: std.AutoHashMapUnmanaged(u32, u16) = .empty,
    /// Optimistic mkdir row (owned name); at most one in flight per pane.
    new_folder: ?[]u8 = null,

    pub fn deinit(o: *Overlay, gpa: Allocator) void {
        o.clear(gpa);
        o.renames.deinit(gpa);
        o.hidden.deinit(gpa);
        o.modes.deinit(gpa);
        o.* = undefined;
    }

    pub fn clear(o: *Overlay, gpa: Allocator) void {
        o.clearRenames(gpa);
        o.hidden.clearRetainingCapacity();
        o.modes.clearRetainingCapacity();
        o.clearNewFolder(gpa);
    }

    pub fn isEmpty(o: *const Overlay) bool {
        return o.renames.count() == 0 and o.hidden.count() == 0 and
            o.modes.count() == 0 and o.new_folder == null;
    }

    pub fn setRename(o: *Overlay, gpa: Allocator, entry_index: u32, new_name: []const u8) error{OutOfMemory}!void {
        const copy = try gpa.dupe(u8, new_name);
        errdefer gpa.free(copy);
        const gop = try o.renames.getOrPut(gpa, entry_index);
        if (gop.found_existing) gpa.free(gop.value_ptr.*);
        gop.value_ptr.* = copy;
    }

    pub fn clearRenames(o: *Overlay, gpa: Allocator) void {
        var it = o.renames.valueIterator();
        while (it.next()) |name| gpa.free(name.*);
        o.renames.clearRetainingCapacity();
    }

    pub fn hide(o: *Overlay, gpa: Allocator, entry_index: u32) error{OutOfMemory}!void {
        try o.hidden.put(gpa, entry_index, {});
    }

    pub fn unhide(o: *Overlay, entry_index: u32) void {
        _ = o.hidden.remove(entry_index);
    }

    pub fn unhideAll(o: *Overlay) void {
        o.hidden.clearRetainingCapacity();
    }

    pub fn isHidden(o: *const Overlay, entry_index: u32) bool {
        return o.hidden.contains(entry_index);
    }

    pub fn setNewFolder(o: *Overlay, gpa: Allocator, name: []const u8) error{OutOfMemory}!void {
        const copy = try gpa.dupe(u8, name);
        if (o.new_folder) |old| gpa.free(old);
        o.new_folder = copy;
    }

    pub fn clearNewFolder(o: *Overlay, gpa: Allocator) void {
        if (o.new_folder) |old| gpa.free(old);
        o.new_folder = null;
    }

    pub fn displayName(o: *const Overlay, entries: []const vfs_mod.Entry, entry_index: u32) []const u8 {
        if (o.renames.get(entry_index)) |name| return name;
        return entries[entry_index].name;
    }

    /// Optimistic chmod (inspector Apply): stage the new mode so the
    /// Permissions column shows it immediately at pending alpha.
    pub fn setMode(o: *Overlay, gpa: Allocator, entry_index: u32, mode: u16) error{OutOfMemory}!void {
        try o.modes.put(gpa, entry_index, mode);
    }

    pub fn clearModes(o: *Overlay) void {
        o.modes.clearRetainingCapacity();
    }

    /// Permissions column value: the staged mode, else the listing's.
    pub fn displayMode(o: *const Overlay, entries: []const vfs_mod.Entry, entry_index: u32) ?u16 {
        if (o.modes.get(entry_index)) |mode| return mode;
        return entries[entry_index].mode;
    }

    /// Pending treatment (60% alpha): rows with an op in flight.
    pub fn isPendingRow(o: *const Overlay, slot: u32) bool {
        if (slot == virtual_new_folder_row) return true;
        return o.renames.contains(slot) or o.modes.contains(slot);
    }
};

pub const ViewFilter = struct {
    show_hidden: bool = false,
    /// Cmd+F live filter; empty = off. ASCII-case-insensitive substring.
    needle: []const u8 = "",

    pub fn matchesName(f: ViewFilter, name: []const u8) bool {
        if (!f.show_hidden and name.len > 0 and name[0] == '.') return false;
        if (f.needle.len > 0 and std.ascii.findIgnoreCase(name, f.needle) == null) return false;
        return true;
    }
};

/// Builds the display permutation: sort order, minus overlay-hidden rows
/// and rows failing the filter, with the optimistic new-folder row first.
pub fn buildVisible(
    gpa: Allocator,
    entries: []const vfs_mod.Entry,
    sort_index: []const u32,
    overlay: *const Overlay,
    filter: ViewFilter,
    out: *std.ArrayList(u32),
) error{OutOfMemory}!void {
    out.clearRetainingCapacity();
    if (overlay.new_folder) |name| {
        if (filter.matchesName(name)) try out.append(gpa, virtual_new_folder_row);
    }
    for (sort_index) |idx| {
        if (overlay.isHidden(idx)) continue;
        if (!filter.matchesName(overlay.displayName(entries, idx))) continue;
        try out.append(gpa, idx);
    }
}

/// Path-bar / Go-to-Path input -> normalized absolute path. Relative input
/// resolves against `base` (the pane's current path, normalized); "~" and
/// "~/…" expand against `home` when provided (local panes). Caller frees.
pub fn parsePathInput(
    gpa: Allocator,
    input: []const u8,
    base: []const u8,
    home: ?[]const u8,
) error{ InvalidPath, OutOfMemory }![]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;
    if (home) |h| {
        if (std.mem.eql(u8, trimmed, "~")) return path_mod.normalize(gpa, h);
        if (std.mem.startsWith(u8, trimmed, "~/")) {
            const raw = try std.mem.concat(gpa, u8, &.{ h, trimmed[1..] });
            defer gpa.free(raw);
            return path_mod.normalize(gpa, raw);
        }
    }
    if (trimmed[0] == '/') return path_mod.normalize(gpa, trimmed);
    return path_mod.join(gpa, base, trimmed);
}

/// "98412" -> "98,412".
pub fn formatCount(buf: []u8, n: u64) []const u8 {
    var digits_buf: [24]u8 = undefined;
    const digits = std.fmt.bufPrint(&digits_buf, "{d}", .{n}) catch return buf[0..0];
    const commas = (digits.len - 1) / 3;
    const total = digits.len + commas;
    if (total > buf.len) {
        const m = @min(digits.len, buf.len);
        @memcpy(buf[0..m], digits[0..m]);
        return buf[0..m];
    }
    var src = digits.len;
    var dst = total;
    var group: usize = 0;
    while (src > 0) {
        src -= 1;
        dst -= 1;
        buf[dst] = digits[src];
        group += 1;
        if (group == 3 and src > 0) {
            dst -= 1;
            buf[dst] = ',';
            group = 0;
        }
    }
    return buf[0..total];
}

/// Shared with transfers.zig and others via src/app/format.zig.
pub const humanBytes = @import("relay_ui").format.humanBytes;

/// Size column: "—" for directories, blank for unknown, human bytes else.
pub fn formatSize(buf: []u8, is_dir: bool, size: ?u64) []const u8 {
    if (is_dir) return "—";
    const n = size orelse return "";
    return humanBytes(buf, n);
}

/// Modified column, ISO 8601 to the minute (UTC), per docs/UX.md.
pub fn formatMtime(buf: []u8, mtime: ?i64) []const u8 {
    const t = mtime orelse return "";
    if (t < 0) return "";
    const ep: std.time.epoch.EpochSeconds = .{ .secs = @intCast(t) };
    const year_day = ep.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = ep.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
    }) catch buf[0..0];
}

/// Settings → "Date format" (ui.zon date_format; mapped from prefs.zig in
/// main.zig exactly like Density).
pub const DateFormat = enum { iso, relative };

/// Relative variant of the Modified column. Anything a week old or older —
/// and clock skew into the future — falls back to the ISO rendering.
pub fn formatMtimeRelative(buf: []u8, mtime: ?i64, now: i64) []const u8 {
    const t = mtime orelse return "";
    if (t < 0) return "";
    const diff = now - t;
    if (diff < 0) return formatMtime(buf, mtime); // future: clock skew
    if (diff < std.time.s_per_min) return "just now";
    if (diff < std.time.s_per_hour)
        return std.fmt.bufPrint(buf, "{d} min ago", .{@divTrunc(diff, std.time.s_per_min)}) catch buf[0..0];
    if (diff < std.time.s_per_day)
        return std.fmt.bufPrint(buf, "{d} hr ago", .{@divTrunc(diff, std.time.s_per_hour)}) catch buf[0..0];
    if (diff < 7 * std.time.s_per_day) {
        const days = @divTrunc(diff, std.time.s_per_day);
        if (days == 1) return "1 day ago";
        return std.fmt.bufPrint(buf, "{d} days ago", .{days}) catch buf[0..0];
    }
    return formatMtime(buf, mtime);
}

pub fn formatMtimeAs(buf: []u8, mtime: ?i64, format: DateFormat, now: i64) []const u8 {
    return switch (format) {
        .iso => formatMtime(buf, mtime),
        .relative => formatMtimeRelative(buf, mtime, now),
    };
}

/// Permissions column: octal mode ("644", "755", "1777"), blank if unknown.
pub fn formatMode(buf: []u8, mode: ?u16) []const u8 {
    const m = mode orelse return "";
    return std.fmt.bufPrint(buf, "{o:0>3}", .{m & 0o7777}) catch buf[0..0];
}

pub const StatusModel = struct {
    /// Unbound remote pane: the empty-state hint replaces everything else.
    hint: ?[]const u8 = null,
    /// Remote connection chip text ("Connected" / "Reconnecting…" / "Offline").
    chip: ?[]const u8 = null,
    listing: bool = false,
    listing_count: u64 = 0,
    item_count: usize = 0,
    sel_count: usize = 0,
    sel_bytes: u64 = 0,
    /// Last protocol round-trip (remote panes only) — "latency honesty",
    /// docs/UX.md status sketch ("… items · 12ms").
    latency_ms: ?u64 = null,
    /// Compare mode active: append the tint legend.
    compare: bool = false,
};

pub const compare_legend = "Compare: blue = only here · yellow = differs";

pub fn formatStatus(buf: []u8, m: StatusModel) []const u8 {
    if (m.hint) |hint| {
        const n = @min(hint.len, buf.len);
        @memcpy(buf[0..n], hint[0..n]);
        return buf[0..n];
    }
    var w: std.Io.Writer = .fixed(buf);
    out: {
        var nb: [32]u8 = undefined;
        if (m.chip) |chip| w.print("{s} · ", .{chip}) catch break :out;
        if (m.listing) {
            w.print("Listing… {s}", .{formatCount(&nb, m.listing_count)}) catch break :out;
        } else {
            w.print("{s} {s}", .{
                formatCount(&nb, @intCast(m.item_count)),
                if (m.item_count == 1) "item" else "items",
            }) catch break :out;
        }
        if (m.latency_ms) |ms| w.print(" · {d} ms", .{ms}) catch break :out;
        if (m.sel_count > 0) {
            var hb: [32]u8 = undefined;
            w.print(" · {s} selected ({s})", .{
                formatCount(&nb, @intCast(m.sel_count)),
                humanBytes(&hb, m.sel_bytes),
            }) catch break :out;
        }
        if (m.compare) w.print(" · {s}", .{compare_legend}) catch break :out;
    }
    return w.buffered();
}

fn rowDisplayName(entries: []const vfs_mod.Entry, overlay: *const Overlay, slot: u32) []const u8 {
    if (slot == virtual_new_folder_row) return overlay.new_folder orelse "";
    return overlay.displayName(entries, slot);
}

/// Type-select: first visible row at/after `start_row` (wrapping) whose
/// display name starts with `prefix` (ASCII-case-insensitive).
pub fn typeSelectRow(
    entries: []const vfs_mod.Entry,
    overlay: *const Overlay,
    visible: []const u32,
    prefix: []const u8,
    start_row: usize,
) ?usize {
    if (visible.len == 0 or prefix.len == 0) return null;
    var i: usize = 0;
    while (i < visible.len) : (i += 1) {
        const row = (start_row + i) % visible.len;
        if (std.ascii.startsWithIgnoreCase(rowDisplayName(entries, overlay, visible[row]), prefix))
            return row;
    }
    return null;
}

/// Re-resolve a snapshot-entry index by its real (non-overlay) name. Sheet
/// completions need this: bridge drains keep running while a sheet is up,
/// so an unsolicited re-list can swap the pane's snapshot and remap the
/// entry indexes captured at sheet-open time.
pub fn findEntryByName(entries: []const vfs_mod.Entry, name: []const u8) ?u32 {
    for (entries, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) return @intCast(i);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Synchronized browsing (pure core): mirror a relative path change.
// ---------------------------------------------------------------------------

/// Apply the relative change `src_old` → `src_new` to `dst_base`: strip the
/// common prefix of the source paths, walk the remaining `src_old`
/// components UP from `dst_base`, then descend the remaining `src_new`
/// components. Null = the change cannot be mirrored (more ups than
/// `dst_base` has components — the panes' trees diverged above the link
/// point). All inputs are normalized absolute paths; the gpa-owned result
/// is normalized by construction.
pub fn syncTarget(
    gpa: Allocator,
    src_old: []const u8,
    src_new: []const u8,
    dst_base: []const u8,
) error{OutOfMemory}!?[]u8 {
    var old_parts: std.ArrayList([]const u8) = .empty;
    defer old_parts.deinit(gpa);
    var new_parts: std.ArrayList([]const u8) = .empty;
    defer new_parts.deinit(gpa);
    var dst_parts: std.ArrayList([]const u8) = .empty;
    defer dst_parts.deinit(gpa);

    var old_it = path_mod.components(src_old);
    while (old_it.next()) |p| try old_parts.append(gpa, p);
    var new_it = path_mod.components(src_new);
    while (new_it.next()) |p| try new_parts.append(gpa, p);
    var dst_it = path_mod.components(dst_base);
    while (dst_it.next()) |p| try dst_parts.append(gpa, p);

    var common: usize = 0;
    while (common < old_parts.items.len and common < new_parts.items.len and
        std.mem.eql(u8, old_parts.items[common], new_parts.items[common]))
        common += 1;

    const ups = old_parts.items.len - common;
    if (ups > dst_parts.items.len) return null;
    const keep = dst_parts.items.len - ups;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (dst_parts.items[0..keep]) |p| {
        try out.append(gpa, '/');
        try out.appendSlice(gpa, p);
    }
    for (new_parts.items[common..]) |p| {
        try out.append(gpa, '/');
        try out.appendSlice(gpa, p);
    }
    if (out.items.len == 0) try out.append(gpa, '/');
    return try out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Directory comparison (pure core): name-keyed cross-pane diff.
// ---------------------------------------------------------------------------

/// Compare-mode row class. Tints (semantic colors at low alpha):
/// .missing = the name has no counterpart in the other pane (systemBlue);
/// .differs = size or mtime delta (systemYellow); .same = untinted.
pub const RowTint = enum(u8) { same, missing, differs };

/// mtime slack: FTP listings carry minute (sometimes 2-second) resolution,
/// so exact equality across protocols would tint everything yellow.
pub const compare_mtime_slack_s: i64 = 2;

pub const CompareTints = struct {
    /// Tint per snapshot ENTRY index (not visible row) for each pane.
    a: []RowTint,
    b: []RowTint,

    pub fn deinit(t: *CompareTints, gpa: Allocator) void {
        gpa.free(t.a);
        gpa.free(t.b);
        t.* = undefined;
    }
};

fn compareEntryPair(x: *const vfs_mod.Entry, y: *const vfs_mod.Entry) RowTint {
    const x_dir = x.kind == .dir;
    const y_dir = y.kind == .dir;
    if (x_dir != y_dir) return .differs;
    if (x_dir) return .same; // directories: presence only
    if (x.size != null and y.size != null and x.size.? != y.size.?) return .differs;
    if (x.mtime != null and y.mtime != null) {
        const delta = x.mtime.? - y.mtime.?;
        if (delta > compare_mtime_slack_s or delta < -compare_mtime_slack_s) return .differs;
    }
    return .same;
}

/// Name-keyed diff over two snapshots' entries. Pure and allocator-clean —
/// the off-main compare job calls this, tests call it directly.
pub fn compareSnapshots(
    gpa: Allocator,
    a: []const vfs_mod.Entry,
    b: []const vfs_mod.Entry,
) error{OutOfMemory}!CompareTints {
    var by_name: std.StringHashMapUnmanaged(u32) = .empty;
    defer by_name.deinit(gpa);
    try by_name.ensureTotalCapacity(gpa, @intCast(b.len));
    for (b, 0..) |*entry, i| by_name.putAssumeCapacity(entry.name, @intCast(i));

    const a_t = try gpa.alloc(RowTint, a.len);
    errdefer gpa.free(a_t);
    const b_t = try gpa.alloc(RowTint, b.len);
    @memset(b_t, .missing);
    for (a, 0..) |*entry, i| {
        if (by_name.get(entry.name)) |j| {
            const class = compareEntryPair(entry, &b[j]);
            a_t[i] = class;
            b_t[j] = class;
        } else {
            a_t[i] = .missing;
        }
    }
    return .{ .a = a_t, .b = b_t };
}

// ---------------------------------------------------------------------------
// Prod safeguards + per-site accent (pure parts).
// ---------------------------------------------------------------------------

/// Production confirm-sheet decision: the destructive button counts ONLY
/// while Cmd is held (the sheet's default button is Cancel).
pub fn prodConfirmAllowed(confirm_clicked: bool, cmd_held: bool) bool {
    return confirm_clicked and cmd_held;
}

/// Site accent → semantic color. This is the small pub hook sites.zig
/// needs for the sidebar dot (and what the path-bar strip draws with);
/// null = untinted. Semantic NSColors only, per docs/UX.md.
pub fn accentUiColor(accent: sites_mod.Accent) ?foundation.Color {
    return switch (accent) {
        .none => null,
        .blue => .system_blue,
        .purple => .system_purple,
        .red => .system_red,
        .orange => .system_orange,
        .yellow => .system_yellow,
        .green => .system_green,
        .graphite => .system_gray,
    };
}

// ---------------------------------------------------------------------------
// TODO(m2-dedupe): plain NSView/NSTextField control helpers belong in
// relay_mac (an appkit/controls.zig); phase 1 shipped no wrapper for them,
// so — exactly like table_source/split_view/toolbar did for the ABI types —
// they are quarantined HERE, the only place in this file with selector
// strings. Phase 3 dedupes into relay_mac.
// ---------------------------------------------------------------------------
const chrome = struct {
    const NSUInteger = foundation.NSUInteger;

    // NSAutoresizingMaskOptions bits.
    const width_sizable: NSUInteger = 2;
    const height_sizable: NSUInteger = 16;
    const min_x_margin: NSUInteger = 1;
    const min_y_margin: NSUInteger = 8;
    const max_y_margin: NSUInteger = 32;

    /// Caller-owned (rc 1) plain NSView.
    fn makeView(frame: foundation.NSRect) objc.Object {
        return foundation.class("NSView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{frame});
    }

    /// Caller-owned (rc 1) editable single-line text field.
    fn makeTextField(frame: foundation.NSRect, font_size: f64) objc.Object {
        const field = foundation.class("NSTextField").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{frame});
        field.msgSend(void, "setBezeled:", .{true});
        field.msgSend(void, "setBezelStyle:", .{@as(NSUInteger, 1)}); // rounded
        field.msgSend(void, "setEditable:", .{true});
        field.msgSend(void, "setSelectable:", .{true});
        field.msgSend(void, "setUsesSingleLineMode:", .{true});
        field.msgSend(void, "setFont:", .{foundation.systemFont(font_size)});
        return field;
    }

    /// Caller-owned (retained) small secondary-color label.
    fn makeLabel(frame: foundation.NSRect) objc.Object {
        const label = foundation.class("NSTextField")
            .msgSend(objc.Object, "labelWithString:", .{foundation.nsString("")});
        _ = label.msgSend(c.id, "retain", .{});
        label.msgSend(void, "setFrame:", .{frame});
        label.msgSend(void, "setFont:", .{foundation.systemFont(11)});
        label.msgSend(void, "setTextColor:", .{foundation.secondaryLabelColor()});
        return label;
    }

    fn addSubview(parent: objc.Object, child: objc.Object) void {
        parent.msgSend(void, "addSubview:", .{child});
    }

    fn setFrame(view: objc.Object, frame: foundation.NSRect) void {
        view.msgSend(void, "setFrame:", .{frame});
    }

    fn setAutoresizing(view: objc.Object, mask: NSUInteger) void {
        view.msgSend(void, "setAutoresizingMask:", .{mask});
    }

    fn setText(view: objc.Object, text_value: []const u8) void {
        view.msgSend(void, "setStringValue:", .{foundation.nsString(text_value)});
    }

    fn text(gpa: Allocator, view: objc.Object) error{OutOfMemory}![]u8 {
        return foundation.utf8FromNSString(gpa, view.msgSend(objc.Object, "stringValue", .{}));
    }

    fn setPlaceholder(view: objc.Object, s: []const u8) void {
        view.msgSend(void, "setPlaceholderString:", .{foundation.nsString(s)});
    }

    fn setHidden(view: objc.Object, hidden: bool) void {
        view.msgSend(void, "setHidden:", .{hidden});
    }

    fn isHidden(view: objc.Object) bool {
        return foundation.toBool(view.msgSend(foundation.BOOL, "isHidden", .{}));
    }

    fn setTargetAction(view: objc.Object, target: objc.Object, action: [:0]const u8) void {
        view.msgSend(void, "setTarget:", .{target});
        view.msgSend(void, "setAction:", .{objc.sel(action)});
    }

    fn setDelegate(view: objc.Object, target: objc.Object) void {
        view.msgSend(void, "setDelegate:", .{target});
    }

    fn clearControlWiring(view: objc.Object) void {
        view.msgSend(void, "setTarget:", .{@as(c.id, null)});
        view.msgSend(void, "setDelegate:", .{@as(c.id, null)});
    }

    fn notificationObject(note: c.id) c.id {
        const obj = note orelse return null;
        return objc.Object.fromId(obj).msgSend(c.id, "object", .{});
    }

    /// Pending treatment: alpha on the materialized row view (null when the
    /// row is not on screen — fine, it draws fresh when it scrolls in).
    fn setRowAlpha(table_id: c.id, row: usize, alpha: f64) void {
        const row_view = objc.Object.fromId(table_id).msgSend(
            c.id,
            "rowViewAtRow:makeIfNecessary:",
            .{ @as(foundation.NSInteger, @intCast(row)), false },
        );
        if (row_view) |rv| objc.Object.fromId(rv).msgSend(void, "setAlphaValue:", .{alpha});
    }

    /// Compare-mode treatment: a low-alpha semantic background on the
    /// materialized row view (same on-screen-only caveat as setRowAlpha).
    fn setRowTint(table_id: c.id, row: usize, tint: RowTint) void {
        const row_view = objc.Object.fromId(table_id).msgSend(
            c.id,
            "rowViewAtRow:makeIfNecessary:",
            .{ @as(foundation.NSInteger, @intCast(row)), false },
        ) orelse return;
        const color = switch (tint) {
            .same => foundation.class("NSColor").msgSend(objc.Object, "clearColor", .{}),
            .missing => foundation.Color.system_blue.object()
                .msgSend(objc.Object, "colorWithAlphaComponent:", .{@as(f64, 0.15)}),
            .differs => foundation.Color.system_yellow.object()
                .msgSend(objc.Object, "colorWithAlphaComponent:", .{@as(f64, 0.18)}),
        };
        objc.Object.fromId(row_view).msgSend(void, "setBackgroundColor:", .{color});
    }

    fn setTextColor(view: objc.Object, color: objc.Object) void {
        view.msgSend(void, "setTextColor:", .{color});
    }

    fn setToolTip(view: objc.Object, tip: []const u8) void {
        view.msgSend(void, "setToolTip:", .{foundation.nsString(tip)});
    }

    fn setNeedsDisplay(view: objc.Object) void {
        view.msgSend(void, "setNeedsDisplay:", .{true});
    }

    /// Height of the table's scrolled-in viewport (vim half-page motions).
    fn visibleHeight(table_id: c.id) f64 {
        const r = objc.Object.fromId(table_id).msgSend(foundation.NSRect, "visibleRect", .{});
        return r.size.height;
    }

    fn boundsOf(view: objc.Object) foundation.NSRect {
        return view.msgSend(foundation.NSRect, "bounds", .{});
    }

    fn fillRect(color: objc.Object, r: foundation.NSRect) void {
        color.msgSend(void, "setFill", .{});
        foundation.class("NSBezierPath")
            .msgSend(objc.Object, "bezierPathWithRect:", .{r})
            .msgSend(void, "fill", .{});
    }

    /// Cmd held RIGHT NOW (+[NSEvent modifierFlags]) — the prod confirm
    /// sheet consults this when its destructive button is clicked.
    fn commandKeyHeld() bool {
        const flags = foundation.class("NSEvent").msgSend(NSUInteger, "modifierFlags", .{});
        return flags & table_source.flag_command != 0;
    }

    /// vim 'y': the selection's full path onto the general pasteboard.
    fn copyToPasteboard(text_value: []const u8) void {
        foundation.writeStringToPasteboard(text_value);
    }

    fn release(obj: objc.Object) void {
        obj.msgSend(void, "release", .{});
    }
};

// ---------------------------------------------------------------------------
// Per-site accent strip (2pt under the path bar; runtime view class, state =
// the pane): solid accent tint normally, striped warning treatment when the
// site's environment tag is prod. Semantic colors only.
// ---------------------------------------------------------------------------
var g_strip_class: ?runtime.DefinedClass = null;

fn stripClass() runtime.DefinedClass {
    if (g_strip_class) |dc| return dc;
    const dc = runtime.defineClass("RelayBrowserAccentStrip", "NSView", &.{}, .{
        .{ "drawRect:", impStripDraw },
    }) catch @panic("browser: failed to define RelayBrowserAccentStrip");
    g_strip_class = dc;
    return dc;
}

fn impStripDraw(target: c.id, _: c.SEL, _: foundation.NSRect) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const pane = stripClass().state(BrowserPane, target);
    const bounds = chrome.boundsOf(objc.Object.fromId(target));
    if (pane.env_prod) {
        // Caution-tape stripes in semantic colors: systemYellow/systemRed.
        const seg: f64 = 8;
        var x: f64 = 0;
        var odd = false;
        while (x < bounds.size.width) : (x += seg) {
            const color: foundation.Color = if (odd) .system_red else .system_yellow;
            chrome.fillRect(
                color.object(),
                foundation.rect(x, 0, @min(seg, bounds.size.width - x), bounds.size.height),
            );
            odd = !odd;
        }
        return;
    }
    if (accentUiColor(pane.accent)) |color| chrome.fillRect(color.object(), bounds);
}

// Virtual key codes table_source does not export.
const key_left_arrow: u16 = 123;
const key_right_arrow: u16 = 124;

/// AppKit reports the arrow keys, Page Up/Down, Home/End, the function row and
/// forward-delete as Unicode scalars in the function-key private range
/// (NSUpArrowFunctionKey == 0xF700 … 0xF8FF). Type-to-select must ignore these
/// so they fall through to NSTableView's built-in keyboard navigation — most
/// visibly Shift+arrow, which extends the selection. `chars` is UTF-8.
fn isFunctionKeyChars(chars: []const u8) bool {
    if (chars.len == 0) return false;
    const len = std.unicode.utf8ByteSequenceLength(chars[0]) catch return false;
    if (chars.len < len) return false;
    const cp = std.unicode.utf8Decode(chars[0..len]) catch return false;
    return cp >= 0xF700 and cp <= 0xF8FF;
}

// ---------------------------------------------------------------------------
// Path-bar / filter-field target class (runtime kit; one instance per pane).
// ---------------------------------------------------------------------------
var g_field_target_class: ?runtime.DefinedClass = null;

fn fieldTargetClass() runtime.DefinedClass {
    if (g_field_target_class) |dc| return dc;
    const dc = runtime.defineClass("RelayBrowserFieldTarget", "NSObject", &.{}, .{
        .{ "relayBrowserPathSubmit:", impPathSubmit },
        .{ "relayBrowserFilterSubmit:", impFilterSubmit },
        .{ "controlTextDidChange:", impControlTextChanged },
        .{ "control:textView:doCommandBySelector:", impControlDoCommand },
    }) catch @panic("browser: failed to define RelayBrowserFieldTarget");
    g_field_target_class = dc;
    return dc;
}

fn impPathSubmit(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    fieldTargetClass().state(BrowserPane, target).submitPathField();
}

fn impFilterSubmit(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    fieldTargetClass().state(BrowserPane, target).focusTable();
}

fn impControlTextChanged(target: c.id, _: c.SEL, note: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const pane = fieldTargetClass().state(BrowserPane, target);
    if (chrome.notificationObject(note) == pane.filter_field.value) pane.onFilterFieldChanged();
}

/// Esc WHILE TYPING in the Cmd+F filter field clears/dismisses it (the
/// field editor routes Esc as cancelOperation: through this delegate hook;
/// the table-focused Esc path lives in dsKeyDown). Selectors are uniqued
/// by the runtime, so pointer comparison is exact.
fn impControlDoCommand(target: c.id, _: c.SEL, control: c.id, _: c.id, command: c.SEL) callconv(.c) foundation.BOOL {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const pane = fieldTargetClass().state(BrowserPane, target);
    if (control != pane.filter_field.value) return foundation.NO;
    if (command != objc.sel("cancelOperation:").value) return foundation.NO;
    pane.clearFilter();
    return foundation.YES;
}

// ---------------------------------------------------------------------------
// Columns (docs/UX.md): Name/Size/Modified, + Permissions for remote panes.
// Both panes are built with the full set; the Permissions column is HIDDEN
// while a pane plays the local role (either pane can host either role —
// active-pane connects swap a local pane to remote and back).
// ---------------------------------------------------------------------------
const mode_column_id: [:0]const u8 = "mode";
const local_columns = [_]table_source.ColumnSpec{
    .{ .id = "name", .title = "Name", .width = 240, .min_width = 120, .custom_draw = true, .sortable = true },
    .{ .id = "size", .title = "Size", .width = 80, .min_width = 60, .alignment = .right, .monospaced_digits = true, .sortable = true },
    .{ .id = "modified", .title = "Modified", .width = 130, .min_width = 110, .monospaced_digits = true, .sortable = true },
};
const remote_columns = local_columns ++ [_]table_source.ColumnSpec{
    .{ .id = mode_column_id, .title = "Permissions", .width = 84, .min_width = 60, .monospaced_digits = true },
};

// Pane chrome geometry (fixed-height bars; the table flexes).
const pane_w: f64 = 480;
const pane_h: f64 = 420;
const bar_h: f64 = 26;
const field_h: f64 = 21;
const status_h: f64 = 18;
const pad: f64 = 6;
const filter_w: f64 = 150;
/// Width reserved for the "⇄" sync-browsing indicator in the path bar.
const sync_w: f64 = 22;
/// Per-site accent strip height (under the path bar).
const strip_h: f64 = 2;

pub const PaneRole = enum { local, remote };

pub const NavMode = enum {
    /// Record in history on success (normal navigation).
    push,
    /// Back/forward/refresh: history already points at the target.
    replace,
};

// ---------------------------------------------------------------------------
// BrowserPane
// ---------------------------------------------------------------------------

/// Pane-token allocator (main thread only, like all pane create/teardown):
/// every pane created by ANY BrowserController gets a process-unique token,
/// so bridge events (pane_token routing) can never cross panes — or, with
/// multiple controllers per window (tabs), cross tabs.
var g_next_pane_token: bridge.PaneToken = 1;

/// Process-wide pane registry (main thread only): unique token → live pane.
/// Maintained by createPane/destroyPane. Drag drops resolve their SOURCE
/// pane through it, because the source may belong to another controller
/// (tab) than the receiving table's. All panes share the app gpa, so the
/// backing is freed through whichever pane leaves last.
var g_pane_registry: std.AutoHashMapUnmanaged(bridge.PaneToken, *BrowserPane) = .empty;

fn unregisterPane(pane: *BrowserPane) void {
    _ = g_pane_registry.remove(pane.token());
    // Leak hygiene (leak-checked tests): the backing goes with the last pane.
    if (g_pane_registry.count() == 0) {
        g_pane_registry.deinit(pane.gpa);
        g_pane_registry = .empty;
    }
}

pub const BrowserPane = struct {
    controller: *BrowserController,
    gpa: Allocator,
    /// CURRENT role — either pane can host either role (active-pane
    /// connects): a local pane switches to .remote when a site binds to
    /// it and restores on disconnect. `home_role` is the constructed one.
    role: PaneRole,
    home_role: PaneRole,
    index: u32,
    /// Process-unique bridge routing token (from g_next_pane_token at
    /// creation; never index-derived — indexes repeat across controllers).
    pane_token: bridge.PaneToken,
    /// item_mod.local_site_id (0) for the local pane; the connected site id
    /// for a bound remote pane; null while the remote pane is unbound.
    site: ?u64,

    // Views (created in buildChrome; container/fields are rc-1 owned here).
    container: objc.Object = undefined,
    path_field: objc.Object = undefined,
    filter_field: objc.Object = undefined,
    status_label: objc.Object = undefined,
    field_target: objc.Object = undefined,
    /// "⇄" path-bar indicator, visible while synchronized browsing links
    /// the panes.
    sync_label: objc.Object = undefined,
    /// 2pt per-site accent strip under the path bar (striped when prod).
    strip_view: objc.Object = undefined,
    /// Inline, non-modal error/warning bar drawn ABOVE the file table. The
    /// always-visible surface for async failures (connect refused/timeout,
    /// the FTPS data-channel listing timeout, listing failures on the current
    /// dir). Hidden (height 0) until shown; auto-clears on a successful
    /// (re)list/connect or the user's dismiss "×".
    banner: *banner_mod.Banner = undefined,
    table: *table_source.TableView = undefined,

    // Listing state.
    snapshot: ?*DirSnapshot = null,
    sort_index: []u32 = @constCast(&[_]u32{}),
    sort_opts: DirSnapshot.SortOptions = .{},
    visible: std.ArrayList(u32) = .empty,
    overlay: Overlay = .{},
    history: History = .{},
    show_hidden: bool = false,
    filter_buf: std.ArrayList(u8) = .empty,

    pending_request: ?bridge.RequestId = null,
    record_history: bool = true,
    /// Path of the in-flight listing (owned); the path bar shows it.
    loading_path: ?[]u8 = null,
    listing_count: u64 = 0,

    // Selection summary (status bar).
    sel_count: usize = 0,
    sel_bytes: u64 = 0,
    /// Last site status for the bound site (the connection chip).
    chip: ?events_mod.SiteStatus = null,
    /// Last protocol round-trip (latency honesty; rendered remote-only).
    last_latency_ms: ?u64 = null,
    /// Local path remembered when a local-role pane switches to remote;
    /// the restore-on-disconnect navigates back here (owned).
    saved_local_path: ?[]u8 = null,

    // Pending-alpha bookkeeping (avoid walking rows when nothing pending).
    had_pending_alpha: bool = false,

    // Per-site style (applied on remote bind from the Site record).
    accent: sites_mod.Accent = .none,
    env_prod: bool = false,

    // Compare mode: tint per snapshot ENTRY index (gpa-owned; cleared on
    // snapshot swap, recomputed off-main), plus clear-walk bookkeeping.
    compare_tints: []RowTint = @constCast(&[_]RowTint{}),
    had_compare_tint: bool = false,

    /// The in-flight listing was issued by synchronized browsing: a failure
    /// stops the link gracefully (status hint, no error sheet).
    mirror_pending: bool = false,

    // Vim mode (controller.vim_mode gates feeding these).
    vim_state: vim.Keymap = .{},
    /// 'v' visual-range anchor (visible-row index).
    vim_anchor: ?usize = null,
    /// Cursor row vim motions move; falls back to the table's selection.
    vim_cursor: ?usize = null,

    // Sheet scratch (one sheet at a time per window). Op targets are
    // captured by NAME (gpa-owned) plus the snapshot generation: bridge
    // drains keep running while a sheet is up, so an unsolicited re-list
    // can swap the snapshot and remap entry indexes. Completions re-resolve
    // via findEntryByName and skip targets that no longer exist.
    rename_target: ?[]u8 = null,
    op_names: std.ArrayList([]u8) = .empty,
    op_generation: u64 = 0,

    // Type-select accumulator.
    ts_buf: [24]u8 = undefined,
    ts_len: usize = 0,
    ts_last_ns: i96 = 0,

    pub fn token(pane: *const BrowserPane) bridge.PaneToken {
        return pane.pane_token;
    }

    /// The directory entry shown at visible-list `row`, or null when the row
    /// is out of range, the virtual "new folder" row, or the pane has no
    /// snapshot. Centralizes the row → slot → entry resolution that the
    /// main.zig selection / Quick Look / edit / terminal seams would
    /// otherwise each open-code.
    pub fn entryAtRow(pane: *const BrowserPane, row: usize) ?*const vfs_mod.Entry {
        const snap = pane.snapshot orelse return null;
        if (row >= pane.visible.items.len) return null;
        const slot = pane.visible.items[row];
        if (slot == virtual_new_folder_row or slot >= snap.entries.len) return null;
        return &snap.entries[slot];
    }

    /// True when this pane currently hosts a connected remote site (not the
    /// local filesystem and not empty).
    pub fn isRemote(pane: *const BrowserPane) bool {
        const site = pane.site orelse return false;
        return site != item_mod.local_site_id;
    }

    pub fn currentPath(pane: *const BrowserPane) ?[]const u8 {
        return pane.history.current();
    }

    /// True when this pane's containing view is currently displayed in the
    /// window (i.e. the tab is active). Background tabs have no window —
    /// presentErrorSheet on a detached view SIGABRTs, so all sheet calls
    /// should guard on this.
    pub fn isVisible(pane: *const BrowserPane) bool {
        const container = pane.container;
        const win_id = container.msgSend(c.id, "window", .{});
        return win_id != null;
    }

    // ------------------------------------------------------------------ //
    // Navigation

    pub fn navigateTo(pane: *BrowserPane, raw: []const u8, mode: NavMode) void {
        const site = pane.site orelse {
            pane.updateStatus();
            return;
        };
        const gpa = pane.gpa;
        const ctrl = pane.controller;
        const core = ctrl.core;
        const norm = path_mod.normalize(gpa, raw) catch {
            panels.presentErrorSheet(pane.controller.win, "Invalid path", raw);
            return;
        };
        if (pane.pending_request) |req| _ = core.cancelListing(req);
        if (pane.loading_path) |lp| gpa.free(lp);
        pane.loading_path = norm;
        pane.record_history = mode == .push;
        pane.listing_count = 0;
        // Sync browsing: the path this pane is leaving, captured BEFORE the
        // request (history updates only on completion). A fresh navigation
        // also supersedes any mirror attribution on this pane.
        pane.mirror_pending = false;
        const sync_old: ?[]const u8 = if (ctrl.sync_browsing and !ctrl.mirroring)
            pane.history.current()
        else
            null;
        const req = core.listPath(pane.token(), site, norm) catch |err| {
            gpa.free(norm);
            pane.loading_path = null;
            pane.pending_request = null;
            pane.updatePathBar();
            panels.presentErrorSheet(pane.controller.win, "Couldn't open folder", @errorName(err));
            return;
        };
        pane.pending_request = req;
        pane.updatePathBar();
        pane.updateStatus();
        if (sync_old) |old| ctrl.mirrorNavigation(pane, old, norm);
    }

    /// Navigate to the bound site's default directory (FTP login dir,
    /// SFTP home) — the first listing of a site with no configured remote
    /// path. The worker resolves the real path; until the snapshot lands
    /// there is no loading_path, so the path bar keeps its placeholder.
    pub fn navigateToDefault(pane: *BrowserPane) void {
        const site = pane.site orelse {
            pane.updateStatus();
            return;
        };
        const gpa = pane.gpa;
        const core = pane.controller.core;
        if (pane.pending_request) |req| _ = core.cancelListing(req);
        if (pane.loading_path) |lp| gpa.free(lp);
        pane.loading_path = null;
        pane.record_history = true;
        pane.listing_count = 0;
        pane.mirror_pending = false;
        const req = core.listDefaultPath(pane.token(), site) catch |err| {
            pane.pending_request = null;
            pane.updatePathBar();
            panels.presentErrorSheet(pane.controller.win, "Couldn't open folder", @errorName(err));
            return;
        };
        pane.pending_request = req;
        pane.updatePathBar();
        pane.updateStatus();
    }

    pub fn refresh(pane: *BrowserPane) void {
        const cur = pane.history.current() orelse return;
        pane.navigateTo(cur, .replace);
    }

    pub fn goUp(pane: *BrowserPane) void {
        const cur = pane.history.current() orelse return;
        const parent = path_mod.parent(cur) orelse return;
        pane.navigateTo(parent, .push);
    }

    pub fn goBack(pane: *BrowserPane) void {
        const old = pane.dupeCurrentForMirror();
        defer if (old) |o| pane.gpa.free(o);
        const target = pane.history.goBack(pane.gpa) orelse return;
        pane.navigateTo(target, .replace);
        pane.mirrorHistoryNav(old);
    }

    pub fn goForward(pane: *BrowserPane) void {
        const old = pane.dupeCurrentForMirror();
        defer if (old) |o| pane.gpa.free(o);
        const target = pane.history.goForward(pane.gpa) orelse return;
        pane.navigateTo(target, .replace);
        pane.mirrorHistoryNav(old);
    }

    /// Back/forward mutate history BEFORE navigateTo, so the in-navigate
    /// mirror capture sees old == new and skips; these two helpers re-run
    /// the mirror with the pre-step path.
    fn dupeCurrentForMirror(pane: *BrowserPane) ?[]u8 {
        const ctrl = pane.controller;
        if (!ctrl.sync_browsing or ctrl.mirroring) return null;
        const cur = pane.history.current() orelse return null;
        return pane.gpa.dupe(u8, cur) catch null;
    }

    fn mirrorHistoryNav(pane: *BrowserPane, old: ?[]const u8) void {
        const o = old orelse return;
        const new_path = pane.loading_path orelse return; // issue failed: skip
        pane.controller.mirrorNavigation(pane, o, new_path);
    }

    pub fn openSelection(pane: *BrowserPane) void {
        pane.openRow(pane.table.selectedRow() orelse return);
    }

    fn openRow(pane: *BrowserPane, row: usize) void {
        if (row >= pane.visible.items.len) return;
        const slot = pane.visible.items[row];
        if (slot == virtual_new_folder_row) return;
        const snap = pane.snapshot orelse return;
        if (slot >= snap.entries.len) return;
        const kind = snap.entries[slot].kind;
        if (kind != .dir and kind != .symlink) return; // M2: descend, don't open files
        const name = pane.overlay.displayName(snap.entries, slot);
        const target = path_mod.join(pane.gpa, snap.path, name) catch return;
        defer pane.gpa.free(target);
        if (kind == .symlink and !pane.isRemote()) {
            // Local: one follow-stat picks dir-links to descend and keeps
            // file-link behavior identical to plain files (no-op). Remote
            // links descend optimistically instead — the server resolves
            // them, and a file target surfaces the server's verbatim
            // refusal in the pane banner.
            const core = pane.controller.core;
            if (!localPathIsDir(core.io, core.local_root, target)) return;
        }
        pane.navigateTo(target, .push);
    }

    pub fn cancelActiveListing(pane: *BrowserPane) void {
        const req = pane.pending_request orelse return;
        _ = pane.controller.core.cancelListing(req);
    }

    // ------------------------------------------------------------------ //
    // Listing events (routed by the controller)

    fn handleListingProgress(pane: *BrowserPane, p: bridge.ListingProgress) void {
        const pending = pane.pending_request orelse return;
        if (p.request_id != pending) return;
        pane.listing_count = p.entries_so_far;
        pane.last_latency_ms = p.elapsed_ms;
        // Streaming: adopt the coalesced partial snapshot so the first
        // rows show immediately (docs/UX.md). pending_request stays set —
        // the status bar keeps counting up until listing_done.
        if (p.snapshot) |snap| {
            pane.adoptSnapshot(snap, p.sort_index);
            return; // adoptSnapshot refreshed the status bar
        }
        pane.updateStatus();
    }

    fn handleListingDone(pane: *BrowserPane, d: bridge.ListingDone) void {
        const expected = if (pane.pending_request) |req| req == d.request_id else false;
        // Latency honesty: every completed protocol call on this pane's
        // token (including the bridge's post-op re-lists) is a real
        // round trip.
        pane.last_latency_ms = d.elapsed_ms;

        if (d.failure) |failure| {
            if (!expected) return; // background re-list failed; stay on truth
            const was_mirror = pane.mirror_pending;
            pane.mirror_pending = false;
            pane.pending_request = null;
            if (pane.loading_path) |lp| {
                pane.gpa.free(lp);
                pane.loading_path = null;
            }
            pane.updatePathBar();
            pane.updateStatus();
            if (failure.class == .cancel) return;
            if (was_mirror) {
                // Sync browsing: the mirrored dir is missing here — stop
                // the link gracefully (status hint, no error sheet).
                pane.controller.stopSyncBrowsing("Sync stopped — folder missing in this pane");
                return;
            }
            // Surface on the inline banner so the reason persists visibly after
            // the sheet is dismissed (auto-clears on the next successful list).
            // The sheet still fires for immediate, in-context attention.
            pane.showBanner(.@"error", failure.message);
            // Background-tab hygiene: the pane's container has no window when
            // its tab is not active; presentErrorSheet on a detached view
            // SIGABRTs (CRITICAL finding). The banner above is unconditional.
            if (pane.isVisible())
                panels.presentErrorSheet(pane.controller.win, "Couldn't open folder", failure.message);
            return;
        }

        const snap = d.snapshot.?;
        if (expected) {
            pane.mirror_pending = false;
            pane.pending_request = null;
            if (pane.loading_path) |lp| {
                pane.gpa.free(lp);
                pane.loading_path = null;
            }
            pane.adoptSnapshot(snap, d.sort_index);
            if (pane.record_history or pane.history.cur == null) {
                pane.history.visit(pane.gpa, snap.path) catch {};
                // Palette frecency feed (M3): user navigations only — the
                // same condition that records browser history.
                if (pane.controller.visit_hook.notify) |notify| {
                    notify(
                        pane.controller.visit_hook.ctx,
                        pane.site orelse item_mod.local_site_id,
                        snap.path,
                    );
                }
            }
            pane.updatePathBar();
            return;
        }
        // Unsolicited result (the bridge re-lists after a successful op):
        // adopt only a NEWER snapshot of the directory we are showing.
        const current = pane.snapshot orelse return;
        if (!std.mem.eql(u8, current.path, snap.path)) return;
        if (snap.generation <= current.generation) return;
        pane.adoptSnapshot(snap, d.sort_index);
    }

    /// Swap in a finished snapshot: ref it, copy the sort permutation
    /// (re-sorting in place when the pane's sort differs from the default),
    /// drop the optimistic overlay, rebuild + redraw.
    fn adoptSnapshot(pane: *BrowserPane, snap: *DirSnapshot, sort: []const u32) void {
        const new_sort = pane.gpa.dupe(u32, sort) catch return; // OOM: keep the old view
        const held = snap.ref();
        if (pane.snapshot) |old| old.unref();
        pane.snapshot = held;
        pane.gpa.free(pane.sort_index);
        pane.sort_index = new_sort;
        if (!std.meta.eql(pane.sort_opts, DirSnapshot.SortOptions{}))
            held.sortIndexInPlace(pane.sort_index, pane.sort_opts);
        pane.overlay.clear(pane.gpa);
        pane.clearCompareTints(); // entry indexes remapped; recompute below
        pane.vim_cursor = null;
        pane.vim_anchor = null;
        // A successful (re)list of this pane retires any stale error banner.
        pane.hideBanner();
        pane.rebuildVisible();
        pane.table.reloadData();
        pane.applyPendingAlpha();
        pane.applyCompareTints();
        pane.updateStatus();
        pane.controller.notifySelection(pane); // slots remapped under the selection
        // Compare mode re-applies on snapshot adoption (off-main diff).
        pane.controller.scheduleCompare();
    }

    fn rebuildVisible(pane: *BrowserPane) void {
        const entries: []const vfs_mod.Entry = if (pane.snapshot) |s| s.entries else &.{};
        buildVisible(pane.gpa, entries, pane.sort_index, &pane.overlay, .{
            .show_hidden = pane.show_hidden,
            .needle = pane.filter_buf.items,
        }, &pane.visible) catch {};
    }

    fn redraw(pane: *BrowserPane) void {
        pane.rebuildVisible();
        pane.table.reloadData();
        pane.applyPendingAlpha();
        pane.applyCompareTints();
        pane.updateStatus();
    }

    fn applyPendingAlpha(pane: *BrowserPane) void {
        const has_pending = !pane.overlay.isEmpty();
        if (!has_pending and !pane.had_pending_alpha) return;
        const table_id = pane.table.tableHandle();
        for (pane.visible.items, 0..) |slot, row| {
            const alpha: f64 = if (pane.overlay.isPendingRow(slot)) 0.6 else 1.0;
            chrome.setRowAlpha(table_id, row, alpha);
        }
        pane.had_pending_alpha = has_pending;
    }

    // ------------------------------------------------------------------ //
    // Compare mode (per-pane application; the diff lives on the controller)

    fn clearCompareTints(pane: *BrowserPane) void {
        pane.gpa.free(pane.compare_tints);
        pane.compare_tints = @constCast(&[_]RowTint{});
    }

    /// Paint the row tints over the materialized row views (same on-screen
    /// caveat as the pending alpha; rows scrolling in draw untinted until
    /// the next application).
    fn applyCompareTints(pane: *BrowserPane) void {
        const active = pane.controller.compare_mode and pane.compare_tints.len > 0;
        if (!active and !pane.had_compare_tint) return;
        const table_id = pane.table.tableHandle();
        for (pane.visible.items, 0..) |slot, row| {
            const tint: RowTint = if (active and slot != virtual_new_folder_row and
                slot < pane.compare_tints.len)
                pane.compare_tints[slot]
            else
                .same;
            chrome.setRowTint(table_id, row, tint);
        }
        pane.had_compare_tint = active;
    }

    // ------------------------------------------------------------------ //
    // Hidden files / filter

    pub fn toggleHidden(pane: *BrowserPane) void {
        pane.show_hidden = !pane.show_hidden;
        pane.redraw();
    }

    pub fn showFilterField(pane: *BrowserPane) void {
        chrome.setHidden(pane.filter_field, false);
        _ = pane.controller.win.makeFirstResponder(pane.filter_field);
    }

    pub fn clearFilter(pane: *BrowserPane) void {
        pane.filter_buf.clearRetainingCapacity();
        chrome.setText(pane.filter_field, "");
        chrome.setHidden(pane.filter_field, true);
        pane.redraw();
        pane.focusTable();
    }

    /// Live filter (controlTextDidChange:); narrows the permutation.
    pub fn applyFilter(pane: *BrowserPane, needle: []const u8) void {
        pane.filter_buf.clearRetainingCapacity();
        pane.filter_buf.appendSlice(pane.gpa, needle) catch {};
        pane.redraw();
    }

    fn onFilterFieldChanged(pane: *BrowserPane) void {
        const raw = chrome.text(pane.gpa, pane.filter_field) catch return;
        defer pane.gpa.free(raw);
        pane.applyFilter(raw);
    }

    // ------------------------------------------------------------------ //
    // Path bar

    fn submitPathField(pane: *BrowserPane) void {
        const gpa = pane.gpa;
        const raw = chrome.text(gpa, pane.path_field) catch return;
        defer gpa.free(raw);
        const base = pane.history.current() orelse "/";
        const home: ?[]const u8 = if (pane.role == .local) homePath() else null;
        const parsed = parsePathInput(gpa, raw, base, home) catch {
            pane.updatePathBar(); // revert the field to truth
            return;
        };
        defer gpa.free(parsed);
        pane.navigateTo(parsed, .push);
        pane.focusTable();
    }

    fn updatePathBar(pane: *BrowserPane) void {
        const text: []const u8 = pane.loading_path orelse (pane.history.current() orelse "");
        chrome.setText(pane.path_field, text);
    }

    fn focusTable(pane: *BrowserPane) void {
        _ = pane.controller.win.makeFirstResponder(objc.Object.fromId(pane.table.tableHandle()));
    }

    // ------------------------------------------------------------------ //
    // Status bar

    fn updateStatus(pane: *BrowserPane) void {
        var buf: [256]u8 = undefined;
        var model: StatusModel = .{};
        if (pane.role == .remote and pane.site == null) {
            model.hint = "Not connected — choose a server in the sidebar (Cmd+K)";
        } else {
            if (pane.role == .remote) {
                if (pane.chip) |chip| model.chip = switch (chip) {
                    .connected => "Connected",
                    .reconnecting => "Reconnecting…",
                    .offline => "Offline",
                };
            }
            model.listing = pane.pending_request != null;
            model.listing_count = pane.listing_count;
            model.item_count = pane.visible.items.len;
            model.sel_count = pane.sel_count;
            model.sel_bytes = pane.sel_bytes;
            // Latency honesty: remote panes only (docs/UX.md).
            if (pane.role == .remote) model.latency_ms = pane.last_latency_ms;
            // Compare-mode legend rides the status bar while active.
            model.compare = pane.controller.compare_mode;
        }
        chrome.setText(pane.status_label, formatStatus(&buf, model));
    }

    /// Sync-browsing link indicator in the path bar (both panes).
    fn updateSyncIndicator(pane: *BrowserPane) void {
        chrome.setHidden(pane.sync_label, !pane.controller.sync_browsing);
    }

    /// Show/hide + repaint the per-site accent strip (remote role only).
    fn updateAccentStrip(pane: *BrowserPane) void {
        const visible = pane.role == .remote and pane.site != null and
            (pane.accent != .none or pane.env_prod);
        chrome.setHidden(pane.strip_view, !visible);
        chrome.setNeedsDisplay(pane.strip_view);
    }

    // ------------------------------------------------------------------ //
    // Inline error banner (the always-visible async-failure surface)

    /// Surface `message` on the pane's inline banner and reflow the table to
    /// reserve banner_height. Empty messages are ignored (nothing to show).
    fn showBanner(pane: *BrowserPane, kind: banner_mod.Kind, message: []const u8) void {
        if (message.len == 0) return;
        pane.banner.show(kind, message);
        pane.layoutBannerArea();
    }

    /// Hide the banner (auto-clear on a successful (re)list/connect, or the
    /// user's dismiss "×") and give the reclaimed strip back to the table.
    fn hideBanner(pane: *BrowserPane) void {
        if (!pane.banner.isVisible()) return;
        pane.banner.hide();
        pane.layoutBannerArea();
    }

    /// Reframe the table so its top edge sits below the banner while the
    /// banner is visible, and fills the reserved strip again once it hides.
    /// Computed from the container's CURRENT bounds so it stays correct after
    /// the split view resizes the pane.
    fn layoutBannerArea(pane: *BrowserPane) void {
        const bounds = chrome.boundsOf(pane.container);
        const w = bounds.size.width;
        const h = bounds.size.height;
        const bh: f64 = if (pane.banner.isVisible()) banner_mod.banner_height else 0;
        // Path bar/strip live in the top `bar_h`; status bar in the bottom
        // `status_h`. The banner takes `bh` just under the path bar; the
        // table gets whatever is left between the banner and the status bar.
        const table_view = objc.Object.fromId(pane.table.view());
        chrome.setFrame(table_view, foundation.rect(0, status_h, w, h - bar_h - status_h - bh));
        if (pane.banner.isVisible()) {
            const banner_view = objc.Object.fromId(pane.banner.view());
            chrome.setFrame(banner_view, foundation.rect(0, h - bar_h - bh, w, bh));
        }
    }

    /// Dismiss "×": hide the banner and clear the chip's explanatory tooltip
    /// (the error is acknowledged; the chip text stays "Offline").
    fn onBannerDismiss(ctx: *anyopaque) void {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        pane.hideBanner();
        chrome.setToolTip(pane.status_label, "");
    }

    // ------------------------------------------------------------------ //
    // File operations (optimistic, docs/UX.md)

    pub fn renameSelection(pane: *BrowserPane) void {
        const snap = pane.snapshot orelse return;
        const row = pane.table.selectedRow() orelse return;
        if (row >= pane.visible.items.len) return;
        const slot = pane.visible.items[row];
        if (slot == virtual_new_folder_row or slot >= snap.entries.len) return;
        const target = pane.gpa.dupe(u8, snap.entries[slot].name) catch return;
        if (pane.rename_target) |old| pane.gpa.free(old);
        pane.rename_target = target;
        pane.op_generation = snap.generation;
        const fields = [_]panels.FormField{.{
            .label = "Name",
            .initial = pane.overlay.displayName(snap.entries, slot),
        }};
        _ = panels.beginFormSheet(pane.controller.win, "Rename", "Rename", &fields, pane, onRenameSheetDone);
    }

    fn onRenameSheetDone(pane: *BrowserPane, result: ?panels.FormResult) void {
        const old_name = pane.rename_target orelse return;
        defer {
            pane.gpa.free(old_name);
            pane.rename_target = null;
        }
        const res = result orelse return;
        if (res.values.len < 1) return;
        const new_name = std.mem.trim(u8, res.values[0], " \t");
        const snap = pane.snapshot orelse return;
        // The snapshot may have been swapped while the sheet was up:
        // re-resolve the target by name; refuse if it no longer exists.
        const slot = findEntryByName(snap.entries, old_name) orelse {
            if (snap.generation != pane.op_generation)
                chrome.setText(pane.status_label, "Folder changed — rename skipped");
            return;
        };
        if (new_name.len == 0 or std.mem.eql(u8, new_name, old_name)) return;
        if (!path_mod.isSafeChildName(new_name)) {
            panels.presentErrorSheet(pane.controller.win, "Invalid name", new_name);
            return;
        }
        const gpa = pane.gpa;
        const site = pane.site orelse return;
        const from = path_mod.join(gpa, snap.path, old_name) catch return;
        defer gpa.free(from);
        const to = path_mod.join(gpa, snap.path, new_name) catch return;
        defer gpa.free(to);
        pane.overlay.setRename(gpa, slot, new_name) catch return; // optimistic apply
        pane.controller.core.renamePath(pane.token(), site, from, to) catch |err| {
            pane.overlay.clearRenames(gpa); // rollback
            pane.redraw();
            panels.presentErrorSheet(pane.controller.win, "Rename failed", @errorName(err));
            return;
        };
        pane.redraw();
    }

    pub fn deleteSelection(pane: *BrowserPane) void {
        const snap = pane.snapshot orelse return;
        pane.clearOpNames();
        var first_slot: u32 = 0;
        for (pane.table.selectedRows()) |row| {
            if (row >= pane.visible.items.len) continue;
            const slot = pane.visible.items[row];
            if (slot == virtual_new_folder_row or slot >= snap.entries.len) continue;
            const name = pane.gpa.dupe(u8, snap.entries[slot].name) catch return;
            pane.op_names.append(pane.gpa, name) catch {
                pane.gpa.free(name);
                return;
            };
            if (pane.op_names.items.len == 1) first_slot = slot;
        }
        if (pane.op_names.items.len == 0) return;
        pane.op_generation = snap.generation;
        // Settings → "Ask before deleting" off: skip the sheet entirely —
        // EXCEPT on prod-tagged sites, where the safeguard is not skippable.
        if (!pane.controller.confirm_delete and !pane.env_prod) {
            onDeleteConfirmed(pane, true);
            return;
        }
        var msg_buf: [160]u8 = undefined;
        const msg: []const u8 = if (pane.op_names.items.len == 1)
            std.fmt.bufPrint(&msg_buf, "Delete “{s}”?", .{
                pane.overlay.displayName(snap.entries, first_slot),
            }) catch "Delete 1 item?"
        else
            std.fmt.bufPrint(&msg_buf, "Delete {d} items?", .{pane.op_names.items.len}) catch "Delete items?";
        if (pane.env_prod) {
            // Prod safeguard: the DEFAULT button is Cancel, and Delete only
            // counts while Cmd is held (checked at completion).
            panels.beginAlertSheet(pane.controller.win, .{
                .style = .critical,
                .message = msg,
                .informative = "Production server — hold ⌘ and choose Delete to confirm. This cannot be undone.",
                .buttons = &.{ "Cancel", "Delete" },
                .destructive_button = 1,
            }, pane, onProdDeleteSheet);
            return;
        }
        panels.confirmSheet(
            pane.controller.win,
            msg,
            "This cannot be undone.",
            "Delete",
            true,
            pane,
            onDeleteConfirmed,
        );
    }

    fn onProdDeleteSheet(pane: *BrowserPane, result: panels.AlertResult) void {
        const delete_clicked = result.button == 1;
        const allowed = prodConfirmAllowed(delete_clicked, chrome.commandKeyHeld());
        if (delete_clicked and !allowed)
            chrome.setText(pane.status_label, "Hold ⌘ to confirm destructive actions on production");
        onDeleteConfirmed(pane, allowed);
    }

    fn clearOpNames(pane: *BrowserPane) void {
        for (pane.op_names.items) |name| pane.gpa.free(name);
        pane.op_names.clearRetainingCapacity();
    }

    fn onDeleteConfirmed(pane: *BrowserPane, confirmed: bool) void {
        defer pane.clearOpNames();
        if (!confirmed) return;
        const snap = pane.snapshot orelse return;
        const site = pane.site orelse return;
        const core = pane.controller.core;
        var missing = false;
        for (pane.op_names.items) |name| {
            // The snapshot may have been swapped while the sheet was up:
            // re-resolve each target by name; skip ones that are gone.
            const slot = findEntryByName(snap.entries, name) orelse {
                missing = true;
                continue;
            };
            const entry = &snap.entries[slot];
            const target = path_mod.join(pane.gpa, snap.path, entry.name) catch continue;
            defer pane.gpa.free(target);
            pane.overlay.hide(pane.gpa, slot) catch continue; // optimistic apply
            core.deletePath(pane.token(), site, target, entry.kind == .dir) catch {
                pane.overlay.unhide(slot); // rollback this row
                continue;
            };
        }
        pane.redraw();
        if (missing and snap.generation != pane.op_generation)
            chrome.setText(pane.status_label, "Folder changed — some items were skipped");
    }

    pub fn newFolderSheet(pane: *BrowserPane) void {
        if (pane.snapshot == null) return;
        const fields = [_]panels.FormField{.{ .label = "Name", .initial = "untitled folder" }};
        _ = panels.beginFormSheet(pane.controller.win, "New Folder", "Create", &fields, pane, onNewFolderDone);
    }

    fn onNewFolderDone(pane: *BrowserPane, result: ?panels.FormResult) void {
        const res = result orelse return;
        if (res.values.len < 1) return;
        const name = std.mem.trim(u8, res.values[0], " \t");
        const snap = pane.snapshot orelse return;
        const site = pane.site orelse return;
        if (!path_mod.isSafeChildName(name)) {
            panels.presentErrorSheet(pane.controller.win, "Invalid name", name);
            return;
        }
        const gpa = pane.gpa;
        const target = path_mod.join(gpa, snap.path, name) catch return;
        defer gpa.free(target);
        pane.overlay.setNewFolder(gpa, name) catch return; // optimistic apply
        pane.controller.core.mkdirPath(pane.token(), site, target) catch |err| {
            pane.overlay.clearNewFolder(gpa); // rollback
            pane.redraw();
            panels.presentErrorSheet(pane.controller.win, "New Folder failed", @errorName(err));
            return;
        };
        pane.redraw();
    }

    pub fn goToPathSheet(pane: *BrowserPane) void {
        const fields = [_]panels.FormField{.{
            .label = "Path",
            .initial = pane.history.current() orelse "/",
            .placeholder = "/path/to/folder",
        }};
        _ = panels.beginFormSheet(pane.controller.win, "Go to Path", "Go", &fields, pane, onGoToPathDone);
    }

    fn onGoToPathDone(pane: *BrowserPane, result: ?panels.FormResult) void {
        const res = result orelse return;
        if (res.values.len < 1) return;
        const gpa = pane.gpa;
        const base = pane.history.current() orelse "/";
        const home: ?[]const u8 = if (pane.role == .local) homePath() else null;
        const parsed = parsePathInput(gpa, res.values[0], base, home) catch {
            panels.presentErrorSheet(pane.controller.win, "Invalid path", res.values[0]);
            return;
        };
        defer gpa.free(parsed);
        pane.navigateTo(parsed, .push);
    }

    fn handleOpDone(pane: *BrowserPane, d: bridge.OpDone) void {
        if (d.success) return; // the bridge already re-listed; adopt reconciles
        const gpa = pane.gpa;
        switch (d.op) {
            .rename => pane.overlay.clearRenames(gpa),
            .delete => pane.overlay.unhideAll(),
            .mkdir => pane.overlay.clearNewFolder(gpa),
            .chmod => pane.overlay.clearModes(), // rollback the staged modes
        }
        pane.redraw();
        const title: []const u8 = switch (d.op) {
            .mkdir => "New Folder failed",
            .rename => "Rename failed",
            .chmod => "Change Permissions failed",
            .delete => "Delete failed",
        };
        const detail: []const u8 = if (d.failure) |f| f.message else "";
        // Background-tab hygiene: only present a sheet when the pane is visible.
        if (pane.isVisible())
            panels.presentErrorSheet(pane.controller.win, title, detail);
    }

    /// Optimistic chmod (inspector Apply dispatched core.chmodPath): stage
    /// the mode override so the Permissions column shows it immediately at
    /// pending alpha. Rolled back on op_done failure, reconciled by the
    /// bridge's post-success re-list (adoptSnapshot clears the overlay).
    fn stageChmodOverlay(pane: *BrowserPane, path: []const u8, mode: u16) void {
        const snap = pane.snapshot orelse return;
        const parent = path_mod.parent(path) orelse "/";
        if (!std.mem.eql(u8, parent, snap.path)) return;
        const slot = findEntryByName(snap.entries, std.fs.path.basename(path)) orelse return;
        pane.overlay.setMode(pane.gpa, slot, mode) catch return;
        pane.redraw();
    }

    // ------------------------------------------------------------------ //
    // Transfers (Cmd+Return + drags)

    /// Enqueue the entry at `row` (this pane) into `dst_dir` on `dst_pane`.
    fn enqueueRowTo(src_pane: *BrowserPane, row: usize, dst_pane: *BrowserPane, dst_dir: []const u8) bool {
        if (row >= src_pane.visible.items.len) return false;
        const slot = src_pane.visible.items[row];
        if (slot == virtual_new_folder_row) return false;
        const snap = src_pane.snapshot orelse return false;
        if (slot >= snap.entries.len) return false;
        const entry = &snap.entries[slot];
        const name = src_pane.overlay.displayName(snap.entries, slot);
        if (!path_mod.isSafeChildName(name)) return false;
        const src_site = src_pane.site orelse return false;
        const dst_site = dst_pane.site orelse return false;
        const gpa = src_pane.gpa;
        const src_path = path_mod.join(gpa, snap.path, name) catch return false;
        defer gpa.free(src_path);
        const dst_path = path_mod.join(gpa, dst_dir, name) catch return false;
        defer gpa.free(dst_path);
        const direction: item_mod.Direction =
            if (dst_site != item_mod.local_site_id) .upload else .download;
        _ = src_pane.controller.core.enqueueTransfer(.{
            .direction = direction,
            .kind = if (entry.kind == .dir) .folder else .file,
            .src = .{ .site_id = src_site, .path = src_path },
            .dst = .{ .site_id = dst_site, .path = dst_path },
            .bytes_total = entry.size orelse 0,
            // Prompt before clobbering an existing destination file.
            .conflict = .ask,
        }) catch return false;
        return true;
    }

    /// Finder drop: upload (or copy) one absolute local path into `dst_dir`.
    fn enqueueLocalFile(pane: *BrowserPane, abs_path: []const u8, dst_dir: []const u8) bool {
        const gpa = pane.gpa;
        const core = pane.controller.core;
        const name = std.fs.path.basename(abs_path);
        if (!path_mod.isSafeChildName(name)) return false;
        const dst_site = pane.site orelse return false;
        const src_norm = path_mod.normalize(gpa, abs_path) catch return false;
        defer gpa.free(src_norm);
        const dst_path = path_mod.join(gpa, dst_dir, name) catch return false;
        defer gpa.free(dst_path);
        var kind: item_mod.Kind = .file;
        if (std.Io.Dir.cwd().openDir(core.io, src_norm, .{})) |opened| {
            var dir = opened;
            dir.close(core.io);
            kind = .folder;
        } else |_| {}
        const direction: item_mod.Direction =
            if (dst_site != item_mod.local_site_id) .upload else .download;
        _ = core.enqueueTransfer(.{
            .direction = direction,
            .kind = kind,
            .src = .{ .site_id = item_mod.local_site_id, .path = src_norm },
            .dst = .{ .site_id = dst_site, .path = dst_path },
            // Prompt before clobbering an existing destination file.
            .conflict = .ask,
        }) catch return false;
        return true;
    }

    /// Drop destination: the hovered directory row, else the current dir.
    fn dropDirOwned(pane: *BrowserPane, target: drag.DropTarget) ?[]u8 {
        const snap = pane.snapshot orelse return null;
        if (target.on_row) {
            if (target.row) |row| {
                if (row < pane.visible.items.len) {
                    const slot = pane.visible.items[row];
                    if (slot != virtual_new_folder_row and slot < snap.entries.len and
                        snap.entries[slot].kind == .dir)
                    {
                        return path_mod.join(pane.gpa, snap.path, snap.entries[slot].name) catch null;
                    }
                }
            }
        }
        return pane.gpa.dupe(u8, snap.path) catch null;
    }

    // ------------------------------------------------------------------ //
    // Type-select

    fn typeSelect(pane: *BrowserPane, chars: []const u8) bool {
        const snap = pane.snapshot orelse return false;
        if (pane.visible.items.len == 0) return false;
        const now = std.Io.Clock.awake.now(pane.controller.core.io).nanoseconds;
        const timeout_ns: i96 = 800 * std.time.ns_per_ms;
        if (now - pane.ts_last_ns > timeout_ns) pane.ts_len = 0;
        pane.ts_last_ns = now;
        const room = pane.ts_buf.len - pane.ts_len;
        const n = @min(room, chars.len);
        @memcpy(pane.ts_buf[pane.ts_len..][0..n], chars[0..n]);
        pane.ts_len += n;
        const start = pane.table.selectedRow() orelse 0;
        const row = typeSelectRow(
            snap.entries,
            &pane.overlay,
            pane.visible.items,
            pane.ts_buf[0..pane.ts_len],
            start,
        ) orelse return true;
        pane.table.setSelectedRows(&.{row});
        pane.table.scrollRowToVisible(row);
        return true;
    }

    // ------------------------------------------------------------------ //
    // Vim mode (pref "ui.vimMode"): the keymap layer over the keyDown hook.
    // The state machine lives in vim.zig; this is the executor.

    fn vimHandle(pane: *BrowserPane, ev: table_source.KeyEvent) bool {
        var key: vim.Key = undefined;
        if (ev.key_code == table_source.key_escape) {
            key = .{ .escape = true };
        } else if (ev.key_code == table_source.key_return or
            ev.key_code == table_source.key_keypad_enter)
        {
            key = .{ .enter = true };
        } else if (ev.chars.len == 1 and ev.chars[0] >= 0x20 and ev.chars[0] != 0x7f) {
            key = .{
                .char = std.ascii.toLower(ev.chars[0]),
                .shift = ev.shift or std.ascii.isUpper(ev.chars[0]),
                .control = ev.control,
            };
        } else if (ev.control and ev.chars.len == 1 and ev.chars[0] >= 1 and ev.chars[0] <= 26) {
            // Control characters (Ctrl+D arrives as 0x04) decode to letters.
            key = .{ .char = ev.chars[0] - 1 + 'a', .control = true };
        } else return false;

        switch (pane.vim_state.feed(key)) {
            .none => {
                if (key.escape) {
                    if (pane.vim_anchor != null) {
                        pane.vim_anchor = null; // leave "visual" mode
                        return true;
                    }
                    return false; // default Esc path (filter clear)
                }
                // Unbound printables are swallowed: type-to-select stays
                // disabled while the layer is on. Control chords pass.
                return key.char != 0 and !key.control;
            },
            .consumed => {},
            .move_down => pane.vimMoveBy(1),
            .move_up => pane.vimMoveBy(-1),
            .parent => pane.goUp(),
            .open => pane.openSelection(),
            .top => pane.vimSelect(0),
            .bottom => if (pane.visible.items.len > 0) pane.vimSelect(pane.visible.items.len - 1),
            .half_page_down => pane.vimMoveBy(pane.vimHalfPage()),
            .half_page_up => pane.vimMoveBy(-pane.vimHalfPage()),
            .focus_filter => pane.showFilterField(),
            .next_match => pane.vimCycleMatch(1),
            .prev_match => pane.vimCycleMatch(-1),
            .toggle_select => pane.vimToggleSelect(),
            .range_anchor => pane.vim_anchor = if (pane.vim_anchor == null) pane.vimCursor() else null,
            .delete => pane.deleteSelection(),
            .yank => pane.vimYankPath(),
            .rename => pane.renameSelection(),
        }
        return true;
    }

    /// The row vim motions move from: the tracked cursor when still valid,
    /// else the table's own selection.
    fn vimCursor(pane: *BrowserPane) usize {
        if (pane.vim_cursor) |cur| {
            if (cur < pane.visible.items.len) return cur;
        }
        return pane.table.selectedRow() orelse 0;
    }

    fn vimMoveBy(pane: *BrowserPane, delta: isize) void {
        if (pane.visible.items.len == 0) return;
        const last: isize = @intCast(pane.visible.items.len - 1);
        const cur: isize = @intCast(pane.vimCursor());
        pane.vimSelect(@intCast(std.math.clamp(cur + delta, 0, last)));
    }

    /// Move the cursor; with a 'v' anchor the selection extends as a range.
    fn vimSelect(pane: *BrowserPane, row: usize) void {
        if (row >= pane.visible.items.len) return;
        pane.vim_cursor = row;
        if (pane.vim_anchor) |anchor_raw| {
            const anchor = @min(anchor_raw, pane.visible.items.len - 1);
            const lo = @min(anchor, row);
            const hi = @max(anchor, row);
            if (pane.gpa.alloc(usize, hi - lo + 1)) |rows| {
                defer pane.gpa.free(rows);
                for (rows, 0..) |*r, i| r.* = lo + i;
                pane.table.setSelectedRows(rows);
            } else |_| {
                pane.table.setSelectedRows(&.{row});
            }
        } else {
            pane.table.setSelectedRows(&.{row});
        }
        pane.table.scrollRowToVisible(row);
    }

    /// Ctrl+d/u step: half the scrolled-in viewport, in rows.
    fn vimHalfPage(pane: *BrowserPane) isize {
        const h = chrome.visibleHeight(pane.table.tableHandle());
        const rh = pane.controller.density.rowHeight();
        if (h <= 0 or rh <= 0) return 10; // not laid out (headless): fallback
        const rows: isize = @intFromFloat(h / rh);
        return @max(1, @divTrunc(rows, 2));
    }

    /// n/N: cycle through the live-filter matches (the visible rows ARE
    /// the match set) with wraparound. No filter, no cycling.
    fn vimCycleMatch(pane: *BrowserPane, dir: isize) void {
        if (pane.filter_buf.items.len == 0) return;
        const n: isize = @intCast(pane.visible.items.len);
        if (n == 0) return;
        const cur: isize = @intCast(pane.vimCursor());
        pane.vimSelect(@intCast(@mod(cur + dir, n)));
    }

    /// x: toggle the cursor row's membership in the selection.
    fn vimToggleSelect(pane: *BrowserPane) void {
        if (pane.visible.items.len == 0) return;
        const row = pane.vimCursor();
        var rows: std.ArrayList(usize) = .empty;
        defer rows.deinit(pane.gpa);
        var had = false;
        for (pane.table.selectedRows()) |r| {
            if (r == row) {
                had = true;
                continue;
            }
            rows.append(pane.gpa, r) catch return;
        }
        if (!had) rows.append(pane.gpa, row) catch return;
        pane.table.setSelectedRows(rows.items);
        pane.vim_cursor = row;
    }

    /// y: full path of the selected entry onto the clipboard.
    fn vimYankPath(pane: *BrowserPane) void {
        const snap = pane.snapshot orelse return;
        const row = pane.table.selectedRow() orelse pane.vimCursor();
        if (row >= pane.visible.items.len) return;
        const slot = pane.visible.items[row];
        if (slot == virtual_new_folder_row or slot >= snap.entries.len) return;
        const name = pane.overlay.displayName(snap.entries, slot);
        const full = path_mod.join(pane.gpa, snap.path, name) catch return;
        defer pane.gpa.free(full);
        chrome.copyToPasteboard(full);
        chrome.setText(pane.status_label, "Path copied");
    }

    // ------------------------------------------------------------------ //
    // table_source.DataSource vtable

    fn dsRowCount(ctx: *anyopaque) usize {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        return pane.visible.items.len;
    }

    fn dsCellText(ctx: *anyopaque, row: usize, col: usize, buf: []u8) []const u8 {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        if (row >= pane.visible.items.len) return "";
        const slot = pane.visible.items[row];
        if (slot == virtual_new_folder_row) {
            return switch (col) {
                0 => pane.overlay.new_folder orelse "",
                1 => "—",
                else => "",
            };
        }
        const snap = pane.snapshot orelse return "";
        if (slot >= snap.entries.len) return "";
        const entry = &snap.entries[slot];
        return switch (col) {
            0 => pane.overlay.displayName(snap.entries, slot),
            1 => formatSize(buf, entry.kind == .dir, entry.size),
            2 => formatMtimeAs(buf, entry.mtime, pane.controller.date_format, nowEpochSeconds(pane.controller.core.io)),
            3 => formatMode(buf, pane.overlay.displayMode(snap.entries, slot)),
            else => "",
        };
    }

    fn dsCellIcon(ctx: *anyopaque, row: usize, col: usize) ?c.id {
        if (col != 0) return null;
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        if (row >= pane.visible.items.len) return null;
        const slot = pane.visible.items[row];
        const ctrl = pane.controller;
        if (slot == virtual_new_folder_row) return ctrl.icon_folder;
        const snap = pane.snapshot orelse return null;
        if (slot >= snap.entries.len) return null;
        return switch (snap.entries[slot].kind) {
            .dir => ctrl.icon_folder,
            .symlink => ctrl.icon_link,
            else => ctrl.icon_file,
        };
    }

    fn dsSortChanged(ctx: *anyopaque, col: usize, ascending: bool) void {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        const key: DirSnapshot.SortKey = switch (col) {
            0 => .name,
            1 => .size,
            2 => .mtime,
            else => return,
        };
        pane.sort_opts = .{ .key = key, .ascending = ascending, .dirs_first = true };
        const snap = pane.snapshot orelse return;
        snap.sortIndexInPlace(pane.sort_index, pane.sort_opts);
        pane.rebuildVisible();
        pane.updateStatus();
        // The wrapper reloads the table after this callback returns.
    }

    fn dsSelectionChanged(ctx: *anyopaque, rows: []const usize) void {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        pane.controller.focused = pane.index;
        var count: usize = 0;
        var bytes: u64 = 0;
        for (rows) |row| {
            if (row >= pane.visible.items.len) continue;
            count += 1;
            const slot = pane.visible.items[row];
            if (slot == virtual_new_folder_row) continue;
            if (pane.snapshot) |snap| {
                if (slot < snap.entries.len) bytes += snap.entries[slot].size orelse 0;
            }
        }
        pane.sel_count = count;
        pane.sel_bytes = bytes;
        pane.updateStatus();
        pane.controller.notifySelection(pane);
    }

    fn dsDoubleAction(ctx: *anyopaque, row: ?usize) void {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        pane.controller.focused = pane.index;
        pane.openRow(row orelse return);
    }

    fn dsReturnAction(ctx: *anyopaque, row: ?usize) void {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        _ = row;
        pane.renameSelection(); // Return = rename (Finder parity, M2 sheet)
    }

    fn dsKeyDown(ctx: *anyopaque, ev: table_source.KeyEvent) bool {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        const ctrl = pane.controller;
        ctrl.focused = pane.index;
        const ch: u8 = if (ev.chars.len == 1) std.ascii.toLower(ev.chars[0]) else 0;

        if (ev.command and ev.option) {
            switch (ev.key_code) {
                key_left_arrow => {
                    ctrl.focusPane(0);
                    return true;
                },
                key_right_arrow => {
                    ctrl.focusPane(1);
                    return true;
                },
                else => {},
            }
            return false;
        }

        if (ev.command and !ev.control and !ev.option) {
            switch (ev.key_code) {
                table_source.key_up_arrow => {
                    pane.goUp();
                    return true;
                },
                table_source.key_down_arrow => {
                    pane.openSelection();
                    return true;
                },
                table_source.key_return, table_source.key_keypad_enter => {
                    ctrl.transferSelection();
                    return true;
                },
                table_source.key_delete => {
                    pane.deleteSelection();
                    return true;
                },
                else => {},
            }
            switch (ch) {
                '[' => {
                    pane.goBack();
                    return true;
                },
                ']' => {
                    pane.goForward();
                    return true;
                },
                'r' => {
                    pane.refresh();
                    return true;
                },
                'f' => {
                    pane.showFilterField();
                    return true;
                },
                'g' => if (ev.shift) {
                    pane.goToPathSheet();
                    return true;
                },
                'n' => if (ev.shift) {
                    pane.newFolderSheet();
                    return true;
                },
                'b' => if (ev.shift) {
                    ctrl.toggleSyncBrowsing(); // "view.syncBrowsing"
                    return true;
                },
                'd' => if (ev.shift) {
                    ctrl.toggleComparePanes(); // "view.comparePanes"
                    return true;
                },
                '.', '>' => {
                    if (ev.shift or ch == '>') pane.toggleHidden() else pane.cancelActiveListing();
                    return true;
                },
                else => {},
            }
            return false;
        }

        // Quick Look (M3): plain Space, Finder-style. Checked BEFORE the
        // vim layer (which would swallow the printable) and before
        // type-select. Falls through when no hook is bound.
        if (!ev.command and !ev.control and !ev.option and
            ev.key_code == table_source.key_space)
        {
            if (ctrl.space_hook.handle) |handle| {
                if (handle(ctrl.space_hook.ctx, pane)) return true;
            }
        }

        // Vim layer (pref "ui.vimMode"): plain keys + Ctrl chords, never
        // Cmd/Opt. Handles Return/Esc itself; swallows printables so
        // type-to-select stays disabled while on.
        if (ctrl.vim_mode and !ev.command and !ev.option) {
            if (pane.vimHandle(ev)) return true;
        }

        if (!ev.command and !ev.control and !ev.option) {
            switch (ev.key_code) {
                table_source.key_tab => {
                    ctrl.focusOtherPane();
                    return true;
                },
                table_source.key_escape => {
                    if (pane.filter_buf.items.len > 0 or !chrome.isHidden(pane.filter_field)) {
                        pane.clearFilter();
                        return true;
                    }
                    return false;
                },
                else => {},
            }
            // Printables feed type-to-select; control chars, DEL and the
            // function-key range (arrows, Page/Home/End, …) fall through to
            // NSTableView so its native keyboard navigation — including
            // Shift+arrow to extend the selection — keeps working.
            if (ev.chars.len > 0 and ev.chars[0] >= 0x20 and ev.chars[0] != 0x7f and
                !isFunctionKeyChars(ev.chars))
                return pane.typeSelect(ev.chars);
        }
        return false;
    }

    /// Right-click menu (M3): focus follows the click (menu commands act
    /// on the focused pane), then main.zig's hook serves the shared file
    /// context menu.
    fn dsContextMenu(ctx: *anyopaque, row: ?usize) ?c.id {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        const ctrl = pane.controller;
        ctrl.focusPane(pane.index);
        const provide = ctrl.context_menu_hook.provide orelse return null;
        return provide(ctrl.context_menu_hook.ctx, pane, row);
    }

    // ------------------------------------------------------------------ //
    // drag.DropHandler vtable

    fn dropValidate(ctx: *anyopaque, payload: drag.Payload, target: drag.DropTarget) drag.Operation {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        _ = payload;
        _ = target;
        if (pane.site == null or pane.snapshot == null) return .none;
        return .copy;
    }

    fn dropAcceptFiles(ctx: *anyopaque, paths: []const []const u8, target: drag.DropTarget) bool {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        const dst_dir = pane.dropDirOwned(target) orelse return false;
        defer pane.gpa.free(dst_dir);
        var any = false;
        for (paths) |p| {
            if (pane.enqueueLocalFile(p, dst_dir)) any = true;
        }
        return any;
    }

    fn dropAcceptPaneRows(ctx: *anyopaque, source_token: u64, rows: []const u32, target: drag.DropTarget) bool {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        // The pasteboard carries the source's unique pane token; the
        // registry resolves it process-wide, so the source pane may belong
        // to another controller (tab) than this table's.
        const src = g_pane_registry.get(source_token) orelse return false;
        if (src == pane) return false; // M2: cross-pane drags only
        const dst_dir = pane.dropDirOwned(target) orelse return false;
        defer pane.gpa.free(dst_dir);
        var any = false;
        for (rows) |row| {
            if (src.enqueueRowTo(row, pane, dst_dir)) any = true;
        }
        return any;
    }
};

/// Follow-stat through the core's local root: true when `abs` (a
/// pane-coordinate absolute path) resolves to a directory, symlinks
/// followed. Main-thread sync stat — local only, never a remote VFS.
fn localPathIsDir(io: std.Io, root: std.Io.Dir, abs: []const u8) bool {
    if (abs.len == 0 or abs[0] != '/') return false;
    const sub: []const u8 = if (abs.len == 1) "." else abs[1..];
    const st = root.statFile(io, sub, .{}) catch return false;
    return st.kind == .directory;
}

// ---------------------------------------------------------------------------
// BrowserController
// ---------------------------------------------------------------------------
pub const BrowserController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    win: window_mod.Window,
    split: *split_view.SplitView,
    panes: [2]*BrowserPane,
    /// The pane that drives menu/toolbar actions (Tab / Cmd+Opt+arrows /
    /// last interaction).
    focused: u32 = 0,
    density: table_source.Density = .compact,
    /// Settings consumers (pushed from main.zig's prefs-changed listener).
    date_format: DateFormat = .iso,
    confirm_delete: bool = true,
    monospace_lists: bool = false,
    /// Vim keymap layer (pref "ui.vimMode", off by default; setVimMode).
    vim_mode: bool = false,
    /// Synchronized browsing (Cmd+Shift+B; command "view.syncBrowsing").
    sync_browsing: bool = false,
    /// Re-entrancy guard while a mirrored navigation is being issued.
    mirroring: bool = false,
    /// Directory comparison (Cmd+Shift+D; command "view.comparePanes").
    compare_mode: bool = false,
    /// Async compare-job token: stale off-main results are dropped.
    compare_gen: u64 = 0,
    /// Tests flip this off to run the diff inline: headless tests pump
    /// manually (no live main queue) and use the non-thread-safe testing
    /// allocator, so the GCD hop must not happen there.
    compare_async: bool = true,
    /// Selection feed for the inspector (docs/UX.md): fired for the FOCUSED
    /// pane on selection changes, snapshot swaps, and pane-focus switches.
    selection_hook: SelectionHook = .{},
    /// Successful user navigations (history-recorded listings) feed the
    /// command palette's frecency store through this (main.zig → palette
    /// recordVisit). M3 seam.
    visit_hook: VisitHook = .{},
    /// Plain Space on a pane table (no modifiers): Quick Look (M3 seam;
    /// main.zig binds the relay_mac quicklook panel). Return true to
    /// consume the key (it never reaches type-select then).
    space_hook: SpaceHook = .{},
    /// Right-click menu provider for the pane tables (M3 seam; main.zig
    /// serves the shared file context menu: Quick Look / Edit / Copy as /
    /// Open in Terminal). null row = click on empty area.
    context_menu_hook: ContextMenuHook = .{},

    // Cached, retained SF Symbol images for the Name column.
    icon_folder: ?c.id = null,
    icon_file: ?c.id = null,
    icon_link: ?c.id = null,

    pub const Options = struct {
        /// Local pane start directory; null = $HOME (docs/UX.md).
        initial_local_path: ?[]const u8 = null,
        density: table_source.Density = .compact,
        date_format: DateFormat = .iso,
        confirm_delete: bool = true,
        monospace_lists: bool = false,
        /// Pref "ui.vimMode" (opt-in, off by default).
        vim_mode: bool = false,
    };

    /// main.zig binds this to the inspector (it owns both controllers);
    /// the receiver reads the pane's selected rows/snapshot synchronously.
    pub const SelectionHook = struct {
        ctx: ?*anyopaque = null,
        notify: ?*const fn (ctx: ?*anyopaque, pane: *BrowserPane) void = null,
    };

    /// M3 seams (all main.zig-injected, all main thread).
    pub const VisitHook = struct {
        ctx: ?*anyopaque = null,
        notify: ?*const fn (ctx: ?*anyopaque, site_id: u64, path: []const u8) void = null,
    };

    pub const SpaceHook = struct {
        ctx: ?*anyopaque = null,
        handle: ?*const fn (ctx: ?*anyopaque, pane: *BrowserPane) bool = null,
    };

    pub const ContextMenuHook = struct {
        ctx: ?*anyopaque = null,
        provide: ?*const fn (ctx: ?*anyopaque, pane: *BrowserPane, row: ?usize) ?c.id = null,
    };

    pub fn setSelectionHook(self: *BrowserController, hook: SelectionHook) void {
        self.selection_hook = hook;
    }

    pub fn setVisitHook(self: *BrowserController, hook: VisitHook) void {
        self.visit_hook = hook;
    }

    pub fn setSpaceHook(self: *BrowserController, hook: SpaceHook) void {
        self.space_hook = hook;
    }

    pub fn setContextMenuHook(self: *BrowserController, hook: ContextMenuHook) void {
        self.context_menu_hook = hook;
    }

    fn notifySelection(self: *BrowserController, pane: *BrowserPane) void {
        if (pane.index != self.focused) return; // background re-list, not the user
        const notify = self.selection_hook.notify orelse return;
        notify(self.selection_hook.ctx, pane);
    }

    pub fn create(
        gpa: Allocator,
        core: *bridge.AppCore,
        win: window_mod.Window,
        options: Options,
    ) !*BrowserController {
        const self = try gpa.create(BrowserController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .win = win,
            .split = undefined,
            .panes = undefined,
            .density = options.density,
            .date_format = options.date_format,
            .confirm_delete = options.confirm_delete,
            .monospace_lists = options.monospace_lists,
            .vim_mode = options.vim_mode,
        };
        self.icon_folder = retainSymbol("folder");
        self.icon_file = retainSymbol("doc");
        self.icon_link = retainSymbol("link");
        errdefer self.releaseIcons();

        self.panes[0] = try self.createPane(0, .local);
        errdefer destroyPane(self.panes[0]);
        self.panes[1] = try self.createPane(1, .remote);
        errdefer destroyPane(self.panes[1]);

        self.split = try split_view.hSplit(gpa, &.{
            .{ .view = self.panes[0].container.value, .min_size = 320 },
            .{ .view = self.panes[1].container.value, .min_size = 320 },
        }, .{ .autosave_name = "RelayBrowserPanes" });
        errdefer self.split.deinit();

        try core.registerListener(.listing_progress, self, onListingProgress);
        try core.registerListener(.listing_done, self, onListingDone);
        try core.registerListener(.op_done, self, onOpDone);
        try core.registerListener(.site_status, self, onSiteStatus);

        self.panes[0].navigateTo(options.initial_local_path orelse homePath(), .push);
        self.panes[1].updateStatus(); // empty-state hint
        return self;
    }

    /// Tear down views + state. Never touches the AppCore: `shutdown()`
    /// destroys the core (the pointer dangles afterwards), so detaching
    /// while the core keeps running (closing a tab) requires
    /// `core.unregisterListeners(controller)` BEFORE this call.
    pub fn destroy(self: *BrowserController) void {
        self.split.deinit();
        for (self.panes) |pane| destroyPane(pane);
        self.releaseIcons();
        self.gpa.destroy(self);
    }

    /// The horizontal split to embed as the window's browser area.
    pub fn view(self: *BrowserController) c.id {
        return self.split.view();
    }

    // ------------------------------------------------------------------ //
    // Pane focus (Tab / Cmd+Opt+arrows; menu actions follow `focused`)

    pub fn activePane(self: *BrowserController) *BrowserPane {
        return self.panes[self.focused];
    }

    pub fn localPane(self: *BrowserController) *BrowserPane {
        return self.panes[0];
    }

    pub fn remotePane(self: *BrowserController) *BrowserPane {
        return self.panes[1];
    }

    pub fn focusPane(self: *BrowserController, index: u32) void {
        if (index >= self.panes.len) return;
        self.focused = index;
        _ = self.win.makeFirstResponder(objc.Object.fromId(self.panes[index].table.tableHandle()));
        self.notifySelection(self.panes[index]); // the inspector follows focus
    }

    pub fn focusOtherPane(self: *BrowserController) void {
        self.focusPane(self.focused ^ 1);
    }

    // ------------------------------------------------------------------ //
    // Remote-pane binding (called by the sites controller on connect).
    // Active-pane connects (docs/UX.md): EITHER pane can host the site; a
    // local-role pane switches to remote (Permissions column appears) and
    // restores its local role + path on disconnect.

    /// Sites-controller `connecting` hook: point the pane at the site
    /// BEFORE status events flow so the chip binds correctly.
    pub fn prepareRemoteBind(self: *BrowserController, pane_token: bridge.PaneToken, site_id: u64) void {
        const pane = self.paneForToken(pane_token) orelse self.panes[1];
        self.ensureRemoteRole(pane);
        pane.site = site_id;
        pane.chip = null;
        self.applySiteStyle(pane);
        pane.updateStatus();
    }

    /// Sites-controller `navigate` hook: bind + list the initial directory.
    pub fn bindRemoteToPane(self: *BrowserController, pane_token: bridge.PaneToken, site_id: u64, initial_path: []const u8) void {
        const pane = self.paneForToken(pane_token) orelse self.panes[1];
        self.ensureRemoteRole(pane);
        pane.site = site_id;
        pane.chip = null;
        self.applySiteStyle(pane);
        self.resetPaneListing(pane);
        // No configured path: list the server's default directory (its
        // home), not "/".
        if (initial_path.len > 0)
            pane.navigateTo(initial_path, .push)
        else
            pane.navigateToDefault();
    }

    /// Historical convenience: bind into the right-hand (home-remote) pane.
    pub fn bindRemote(self: *BrowserController, site_id: u64, initial_path: []const u8) void {
        self.bindRemoteToPane(self.panes[1].token(), site_id, initial_path);
    }

    /// Reset a home-remote pane to the empty "Not connected" state: drop the
    /// site binding and the listing, keep the remote role. (A home-local pane
    /// that role-switched goes through restoreLocalRole instead.)
    fn unbindRemotePane(self: *BrowserController, pane: *BrowserPane) void {
        pane.site = null;
        pane.chip = null;
        pane.last_latency_ms = null;
        self.applySiteStyle(pane);
        self.resetPaneListing(pane);
        pane.updatePathBar();
        pane.table.reloadData();
        pane.updateStatus();
        self.notifySelection(pane);
    }

    /// Switch a local-role pane to remote: remember the local spot, show
    /// the Permissions column. No-op for panes already remote.
    fn ensureRemoteRole(self: *BrowserController, pane: *BrowserPane) void {
        _ = self;
        if (pane.role == .remote) return;
        if (pane.saved_local_path == null) {
            if (pane.history.current()) |cur|
                pane.saved_local_path = pane.gpa.dupe(u8, cur) catch null;
        }
        pane.role = .remote;
        pane.table.setColumnHidden(mode_column_id, false);
        chrome.setPlaceholder(pane.path_field, "Not connected");
    }

    /// Disconnect of a role-switched pane: back to local, at the path the
    /// pane showed before the site bound to it.
    fn restoreLocalRole(self: *BrowserController, pane: *BrowserPane) void {
        if (pane.role == .local or pane.home_role != .local) return;
        pane.role = .local;
        pane.site = item_mod.local_site_id;
        pane.chip = null;
        pane.last_latency_ms = null;
        self.applySiteStyle(pane);
        self.resetPaneListing(pane);
        pane.table.setColumnHidden(mode_column_id, true);
        chrome.setPlaceholder(pane.path_field, "Path");
        pane.navigateTo(pane.saved_local_path orelse homePath(), .push);
        if (pane.saved_local_path) |p| {
            pane.gpa.free(p);
            pane.saved_local_path = null;
        }
    }

    fn resetPaneListing(self: *BrowserController, pane: *BrowserPane) void {
        _ = self;
        const gpa = pane.gpa;
        if (pane.pending_request != null) pane.cancelActiveListing();
        pane.pending_request = null;
        if (pane.loading_path) |lp| {
            gpa.free(lp);
            pane.loading_path = null;
        }
        if (pane.snapshot) |snap| {
            snap.unref();
            pane.snapshot = null;
        }
        gpa.free(pane.sort_index);
        pane.sort_index = @constCast(&[_]u32{});
        pane.visible.clearRetainingCapacity();
        pane.overlay.clear(gpa);
        pane.history.deinit(gpa);
        pane.history = .{};
        pane.sel_count = 0;
        pane.sel_bytes = 0;
        pane.listing_count = 0;
        pane.clearCompareTints();
        pane.mirror_pending = false;
        pane.vim_state = .{};
        pane.vim_anchor = null;
        pane.vim_cursor = null;
        // Fresh bind/unbind/role-restore: drop any stale error banner.
        pane.hideBanner();
    }

    // ------------------------------------------------------------------ //
    // Menu/toolbar command surface (phase 3 wires menus to these)

    pub fn goBack(self: *BrowserController) void {
        self.activePane().goBack();
    }

    pub fn goForward(self: *BrowserController) void {
        self.activePane().goForward();
    }

    pub fn goUp(self: *BrowserController) void {
        self.activePane().goUp();
    }

    pub fn openSelection(self: *BrowserController) void {
        self.activePane().openSelection();
    }

    pub fn refresh(self: *BrowserController) void {
        self.activePane().refresh();
    }

    pub fn goToPathSheet(self: *BrowserController) void {
        self.activePane().goToPathSheet();
    }

    pub fn toggleHiddenFiles(self: *BrowserController) void {
        self.activePane().toggleHidden();
    }

    pub fn showFilter(self: *BrowserController) void {
        self.activePane().showFilterField();
    }

    pub fn renameSelection(self: *BrowserController) void {
        self.activePane().renameSelection();
    }

    pub fn deleteSelection(self: *BrowserController) void {
        self.activePane().deleteSelection();
    }

    pub fn newFolderSheet(self: *BrowserController) void {
        self.activePane().newFolderSheet();
    }

    pub fn cancelActiveListing(self: *BrowserController) void {
        self.activePane().cancelActiveListing();
    }

    /// Cmd+Return: enqueue the focused pane's selection into the other
    /// pane's current directory (direction-aware).
    pub fn transferSelection(self: *BrowserController) void {
        const src = self.activePane();
        const dst = self.panes[src.index ^ 1];
        const dst_snap = dst.snapshot orelse return;
        for (src.table.selectedRows()) |row| {
            _ = src.enqueueRowTo(row, dst, dst_snap.path);
        }
    }

    /// View menu density (Comfortable/Compact/Dense).
    pub fn setDensity(self: *BrowserController, density: table_source.Density) void {
        self.density = density;
        for (self.panes) |pane| pane.table.setDensity(density);
    }

    /// Settings → "Date format" (Modified column rendering).
    pub fn setDateFormat(self: *BrowserController, format: DateFormat) void {
        if (self.date_format == format) return;
        self.date_format = format;
        for (self.panes) |pane| pane.table.reloadData();
    }

    /// Settings → "Ask before deleting" (deleteSelection sheet skip).
    pub fn setConfirmDelete(self: *BrowserController, confirm: bool) void {
        self.confirm_delete = confirm;
    }

    /// Settings → "Monospaced file lists" (table_source font hook).
    pub fn setMonospaceLists(self: *BrowserController, mono: bool) void {
        self.monospace_lists = mono;
        for (self.panes) |pane| pane.table.setMonospaced(mono);
    }

    /// Inspector Apply hook: stage the optimistic chmod overlay on the
    /// pane that owns the selection (routed from main.zig).
    pub fn stageChmod(self: *BrowserController, pane_token: bridge.PaneToken, path: []const u8, mode: u16) void {
        const pane = self.paneForToken(pane_token) orelse return;
        pane.stageChmodOverlay(path, mode);
    }

    /// Pref "ui.vimMode" consumer (push from the prefs-changed listener,
    /// exactly like setMonospaceLists). Toggling resets per-pane vim state.
    pub fn setVimMode(self: *BrowserController, enabled: bool) void {
        if (self.vim_mode == enabled) return;
        self.vim_mode = enabled;
        for (self.panes) |pane| {
            pane.vim_state = .{};
            pane.vim_anchor = null;
            pane.vim_cursor = null;
        }
    }

    /// Prod-safeguard surface for sibling controllers (the transfers
    /// panel's overwrite-confirm, the inspector's recursive chmod): true
    /// when the pane's site carries the prod environment tag, so their
    /// confirm sheets should demand a held Cmd exactly like delete here.
    pub fn paneNeedsProdGuard(self: *BrowserController, pane_token: bridge.PaneToken) bool {
        const pane = self.paneForToken(pane_token) orelse return false;
        return pane.env_prod;
    }

    /// Resolve a pane token to its BrowserPane via the process-global
    /// registry (main thread only). Used by main.zig's PaneHost glue to route
    /// connect callbacks to the OWNING controller when multiple tabs are open
    /// (CRITICAL finding 1: paneForToken only checks THIS controller's panes).
    pub fn paneByToken(token: bridge.PaneToken) ?*BrowserPane {
        return g_pane_registry.get(token);
    }

    // ------------------------------------------------------------------ //
    // Synchronized browsing ("view.syncBrowsing", Cmd+Shift+B)

    /// Toggle the pane link: while on, relative path changes in one pane
    /// mirror into the other, and "⇄" shows in both path bars.
    pub fn toggleSyncBrowsing(self: *BrowserController) void {
        self.sync_browsing = !self.sync_browsing;
        for (self.panes) |pane| {
            pane.updateSyncIndicator();
            pane.updateStatus(); // wipe a stale stop-hint
        }
    }

    /// Graceful stop (mirrored dir missing / trees diverged): unlink and
    /// hint in both status bars instead of presenting an error sheet.
    fn stopSyncBrowsing(self: *BrowserController, hint: []const u8) void {
        if (!self.sync_browsing) return;
        self.sync_browsing = false;
        for (self.panes) |pane| {
            pane.updateSyncIndicator();
            chrome.setText(pane.status_label, hint);
        }
    }

    /// Apply src's relative path change (src_old → src_new) to the other
    /// pane. Issued navigations are flagged so a failure stops the link
    /// gracefully; `mirroring` keeps the mirror from echoing back.
    fn mirrorNavigation(
        self: *BrowserController,
        src: *BrowserPane,
        src_old: []const u8,
        src_new: []const u8,
    ) void {
        if (!self.sync_browsing or self.mirroring) return;
        if (std.mem.eql(u8, src_old, src_new)) return; // refresh: in place
        const dst = self.panes[src.index ^ 1];
        if (dst.site == null) return;
        const dst_base = dst.history.current() orelse return;
        const target = (syncTarget(self.gpa, src_old, src_new, dst_base) catch return) orelse {
            self.stopSyncBrowsing("Sync stopped — panes diverged above the link point");
            return;
        };
        defer self.gpa.free(target);
        self.mirroring = true;
        defer self.mirroring = false;
        dst.navigateTo(target, .push);
        if (dst.pending_request != null) dst.mirror_pending = true;
    }

    // ------------------------------------------------------------------ //
    // Directory comparison ("view.comparePanes", Cmd+Shift+D)

    /// Toggle compare mode: rows tint by cross-pane presence/size/mtime
    /// delta; the legend rides both status bars while active. The diff is
    /// computed off-main and re-applied on every snapshot adoption.
    pub fn toggleComparePanes(self: *BrowserController) void {
        self.compare_mode = !self.compare_mode;
        self.compare_gen +%= 1; // drop any in-flight diff either way
        if (self.compare_mode) {
            self.scheduleCompare();
        } else {
            for (self.panes) |pane| pane.clearCompareTints();
        }
        for (self.panes) |pane| {
            pane.applyCompareTints();
            pane.updateStatus();
        }
    }

    /// Kick an off-main diff over both panes' current snapshots (refs are
    /// taken; DirSnapshot rc is atomic and the entries are immutable).
    fn scheduleCompare(self: *BrowserController) void {
        if (!self.compare_mode) return;
        self.compare_gen +%= 1;
        const snap_a = self.panes[0].snapshot orelse return;
        const snap_b = self.panes[1].snapshot orelse return;
        const job = self.gpa.create(CompareJob) catch return;
        job.* = .{
            .ctrl = self,
            .token = self.compare_gen,
            .snap_a = snap_a.ref(),
            .snap_b = snap_b.ref(),
        };
        if (self.compare_async) {
            dispatch.asyncOnQueue(dispatch.globalQueue(), job, CompareJob.computeOffMain);
        } else {
            // Headless tests: no live main queue and a non-thread-safe gpa,
            // so compute + adopt inline on the caller's (main) thread.
            job.compute();
            CompareJob.finish(job);
        }
    }

    const CompareJob = struct {
        ctrl: *BrowserController,
        token: u64,
        snap_a: *DirSnapshot,
        snap_b: *DirSnapshot,
        tints: ?CompareTints = null,

        /// The pure diff — runs on a GCD global queue in production (the
        /// gpa there is the thread-safe c_allocator), on the main thread
        /// in tests.
        fn compute(job: *CompareJob) void {
            job.tints = compareSnapshots(job.ctrl.gpa, job.snap_a.entries, job.snap_b.entries) catch null;
        }

        fn computeOffMain(job: *CompareJob) void {
            job.compute();
            dispatch.mainQueueAsync(job, CompareJob.finish);
        }

        /// Main thread: adopt the result if nothing moved underneath
        /// (mode still on, newest job, both snapshots still current).
        fn finish(job: *CompareJob) void {
            const ctrl = job.ctrl;
            defer {
                job.snap_a.unref();
                job.snap_b.unref();
                ctrl.gpa.destroy(job);
            }
            var tints = job.tints orelse return;
            const fresh = ctrl.compare_mode and job.token == ctrl.compare_gen and
                ctrl.panes[0].snapshot == job.snap_a and ctrl.panes[1].snapshot == job.snap_b;
            if (!fresh) {
                tints.deinit(ctrl.gpa);
                return;
            }
            ctrl.panes[0].clearCompareTints();
            ctrl.panes[0].compare_tints = tints.a;
            ctrl.panes[1].clearCompareTints();
            ctrl.panes[1].compare_tints = tints.b;
            for (ctrl.panes) |pane| {
                pane.applyCompareTints();
                pane.updateStatus();
            }
        }
    };

    // ------------------------------------------------------------------ //
    // Per-site accent + environment (the Site record drives the strip)

    /// Pull accent + environment from the bound Site (sites.zon fields)
    /// into the pane and refresh the path-bar strip.
    fn applySiteStyle(self: *BrowserController, pane: *BrowserPane) void {
        pane.accent = .none;
        pane.env_prod = false;
        if (pane.site) |site_id| {
            if (site_id != item_mod.local_site_id) {
                if (self.core.findSite(site_id)) |site| {
                    pane.accent = site.accent;
                    pane.env_prod = site.environment == .prod;
                }
            }
        }
        pane.updateAccentStrip();
    }

    // ------------------------------------------------------------------ //
    // Bridge listeners (main thread, run-to-completion)

    fn paneForToken(self: *BrowserController, pane_token: bridge.PaneToken) ?*BrowserPane {
        for (self.panes) |pane| {
            if (pane.token() == pane_token) return pane;
        }
        return null;
    }

    fn onListingProgress(self: *BrowserController, p: bridge.ListingProgress) void {
        const pane = self.paneForToken(p.pane_token) orelse return;
        pane.handleListingProgress(p);
    }

    fn onListingDone(self: *BrowserController, d: bridge.ListingDone) void {
        const pane = self.paneForToken(d.pane_token) orelse return;
        pane.handleListingDone(d);
    }

    fn onOpDone(self: *BrowserController, d: bridge.OpDone) void {
        const pane = self.paneForToken(d.pane_token) orelse return;
        pane.handleOpDone(d);
    }

    fn onSiteStatus(self: *BrowserController, e: events_mod.CoreEvent.SiteStatusChange) void {
        for (self.panes) |pane| {
            if (pane.role != .remote) continue;
            const site = pane.site orelse continue;
            if (site != e.site_id) continue;
            pane.chip = e.status;
            pane.updateStatus();
            // Error surfacing: a `.offline`/`.reconnecting` carrying an
            // `error_class` is a real failure (connect refused/timeout/auth/
            // dropped link) — distinct from a clean user disconnect (no class,
            // even if `reason` is non-empty). Show it on the inline banner and
            // explain the chip via its NSView tooltip. `.connected` clears both
            // (the subsequent successful (re)list also clears the banner).
            switch (e.status) {
                .connected => {
                    pane.hideBanner();
                    chrome.setToolTip(pane.status_label, "");
                },
                .offline, .reconnecting => {
                    if (e.error_class != null and e.reason.len > 0) {
                        pane.showBanner(.@"error", e.reason);
                        chrome.setToolTip(pane.status_label, e.reason);
                    } else if (e.status == .offline) {
                        // Clean disconnect (no error_class): nothing to surface.
                        chrome.setToolTip(pane.status_label, "");
                    }
                },
            }
            // Active-pane connects: a role-switched local pane returns to
            // its local role (and path) when the site disconnects. (That
            // navigates a local listing whose success clears the banner.)
            if (e.status == .offline) self.restoreLocalRole(pane);
            // A home-remote pane has no local role to fall back to. On a clean
            // user disconnect (no error_class) drop the binding + stale listing
            // so it shows the empty "Not connected" state. An unexpected drop
            // (error_class set) keeps the listing + banner so context survives
            // and a reconnect re-lists in place.
            if (e.status == .offline and e.error_class == null and
                pane.role == .remote and pane.home_role == .remote)
                self.unbindRemotePane(pane);
        }
    }

    // ------------------------------------------------------------------ //
    // Construction internals

    fn createPane(self: *BrowserController, index: u32, role: PaneRole) !*BrowserPane {
        const gpa = self.gpa;
        const pane = try gpa.create(BrowserPane);
        errdefer gpa.destroy(pane);
        pane.* = .{
            .controller = self,
            .gpa = gpa,
            .role = role,
            .home_role = role,
            .index = index,
            .pane_token = g_next_pane_token,
            .site = if (role == .local) item_mod.local_site_id else null,
            .show_hidden = self.core.settings.show_hidden_files,
        };
        g_next_pane_token += 1;
        try g_pane_registry.put(gpa, pane.token(), pane);
        errdefer unregisterPane(pane);

        // Full column set for BOTH panes (role switching just toggles the
        // Permissions column's visibility).
        pane.table = try table_source.TableView.init(gpa, .{
            .columns = &remote_columns,
            .data_source = .{
                .ctx = pane,
                .rowCount = BrowserPane.dsRowCount,
                .cellText = BrowserPane.dsCellText,
                .cellIcon = BrowserPane.dsCellIcon,
                .sortChanged = BrowserPane.dsSortChanged,
                .selectionChanged = BrowserPane.dsSelectionChanged,
                .doubleAction = BrowserPane.dsDoubleAction,
                .returnAction = BrowserPane.dsReturnAction,
                .keyDown = BrowserPane.dsKeyDown,
                .contextMenu = BrowserPane.dsContextMenu,
            },
            .density = self.density,
            .autosave_name = if (index == 0) "RelayBrowserTableLeft" else "RelayBrowserTableRight",
        });
        if (role == .local) pane.table.setColumnHidden(mode_column_id, true);
        pane.table.setMonospaced(self.monospace_lists);

        buildChrome(pane);

        drag.attachDropHandler(pane.table, .{
            .ctx = pane,
            .validate = BrowserPane.dropValidate,
            .acceptFiles = BrowserPane.dropAcceptFiles,
            .acceptPaneRows = BrowserPane.dropAcceptPaneRows,
        });
        drag.enableRowDragSource(pane.table, pane.token());

        pane.updateStatus();
        return pane;
    }

    fn buildChrome(pane: *BrowserPane) void {
        pane.container = chrome.makeView(foundation.rect(0, 0, pane_w, pane_h));

        const top_y = pane_h - bar_h + (bar_h - field_h) / 2;
        pane.path_field = chrome.makeTextField(
            foundation.rect(pad, top_y, pane_w - filter_w - sync_w - 4 * pad, field_h),
            12,
        );
        chrome.setAutoresizing(pane.path_field, chrome.width_sizable | chrome.min_y_margin);
        chrome.setPlaceholder(pane.path_field, if (pane.role == .remote) "Not connected" else "Path");

        // "⇄" between the path bar and the filter: visible while
        // synchronized browsing links the panes.
        pane.sync_label = chrome.makeLabel(
            foundation.rect(pane_w - filter_w - sync_w - 2 * pad, top_y, sync_w, field_h - 2),
        );
        chrome.setAutoresizing(pane.sync_label, chrome.min_x_margin | chrome.min_y_margin);
        chrome.setText(pane.sync_label, "⇄");
        chrome.setTextColor(pane.sync_label, foundation.controlAccentColor());
        chrome.setToolTip(pane.sync_label, "Synchronized browsing (⌘⇧B)");
        chrome.setHidden(pane.sync_label, true);

        pane.filter_field = chrome.makeTextField(
            foundation.rect(pane_w - filter_w - pad, top_y, filter_w, field_h),
            12,
        );
        chrome.setAutoresizing(pane.filter_field, chrome.min_x_margin | chrome.min_y_margin);
        chrome.setPlaceholder(pane.filter_field, "Filter");
        chrome.setHidden(pane.filter_field, true);

        // Per-site accent strip, 2pt under the path bar (remote role only;
        // striped warning treatment when the site is tagged prod).
        pane.strip_view = stripClass().newWithFrame(
            foundation.rect(0, pane_h - bar_h - strip_h, pane_w, strip_h),
        );
        stripClass().attach(pane.strip_view.value, pane);
        chrome.setAutoresizing(pane.strip_view, chrome.width_sizable | chrome.min_y_margin);
        chrome.setHidden(pane.strip_view, true);

        // Inline error banner, pinned just below the path bar/strip and ABOVE
        // the table. Created hidden (banner_height reserved only while shown);
        // its dismiss "×" routes back here to hide it + clear the chip tooltip.
        pane.banner = banner_mod.Banner.create(pane.gpa) catch
            @panic("relay/browser: failed to create error banner");
        const banner_view = objc.Object.fromId(pane.banner.view());
        chrome.setFrame(banner_view, foundation.rect(
            0,
            pane_h - bar_h - banner_mod.banner_height,
            pane_w,
            banner_mod.banner_height,
        ));
        // Top-pinned: width tracks the pane; the strip stays just under the
        // path bar as the container grows downward.
        chrome.setAutoresizing(banner_view, chrome.width_sizable | chrome.min_y_margin);
        pane.banner.setDismissHandler(pane, BrowserPane.onBannerDismiss);

        const table_view = objc.Object.fromId(pane.table.view());
        chrome.setFrame(table_view, foundation.rect(0, status_h, pane_w, pane_h - bar_h - status_h));
        chrome.setAutoresizing(table_view, chrome.width_sizable | chrome.height_sizable);

        pane.status_label = chrome.makeLabel(foundation.rect(pad, 2, pane_w - 2 * pad, status_h - 4));
        chrome.setAutoresizing(pane.status_label, chrome.width_sizable | chrome.max_y_margin);

        pane.field_target = fieldTargetClass().newWithState(pane);
        chrome.setTargetAction(pane.path_field, pane.field_target, "relayBrowserPathSubmit:");
        chrome.setTargetAction(pane.filter_field, pane.field_target, "relayBrowserFilterSubmit:");
        chrome.setDelegate(pane.filter_field, pane.field_target);

        chrome.addSubview(pane.container, pane.path_field);
        chrome.addSubview(pane.container, pane.sync_label);
        chrome.addSubview(pane.container, pane.filter_field);
        chrome.addSubview(pane.container, table_view);
        chrome.addSubview(pane.container, banner_view); // above the table
        chrome.addSubview(pane.container, pane.strip_view); // over the table edge
        chrome.addSubview(pane.container, pane.status_label);
    }

    fn destroyPane(pane: *BrowserPane) void {
        const gpa = pane.gpa;
        unregisterPane(pane);
        chrome.clearControlWiring(pane.path_field);
        chrome.clearControlWiring(pane.filter_field);
        pane.banner.deinit();
        pane.table.deinit();
        chrome.release(pane.path_field);
        chrome.release(pane.filter_field);
        chrome.release(pane.sync_label);
        chrome.release(pane.strip_view);
        chrome.release(pane.status_label);
        chrome.release(pane.field_target);
        chrome.release(pane.container);
        if (pane.snapshot) |snap| snap.unref();
        gpa.free(pane.compare_tints);
        gpa.free(pane.sort_index);
        pane.visible.deinit(gpa);
        pane.overlay.deinit(gpa);
        pane.history.deinit(gpa);
        pane.filter_buf.deinit(gpa);
        if (pane.rename_target) |name| gpa.free(name);
        for (pane.op_names.items) |name| gpa.free(name);
        pane.op_names.deinit(gpa);
        if (pane.loading_path) |lp| gpa.free(lp);
        if (pane.saved_local_path) |p| gpa.free(p);
        gpa.destroy(pane);
    }

    fn retainSymbol(name: [*:0]const u8) ?c.id {
        const img = table_source.systemSymbolImage(name) orelse return null;
        _ = objc.Object.fromId(img).msgSend(c.id, "retain", .{});
        return img;
    }

    fn releaseIcons(self: *BrowserController) void {
        for ([_]?c.id{ self.icon_folder, self.icon_file, self.icon_link }) |icon| {
            if (icon) |img| objc.Object.fromId(img).msgSend(void, "release", .{});
        }
        self.icon_folder = null;
        self.icon_file = null;
        self.icon_link = null;
    }
};

fn homePath() []const u8 {
    const home = std.c.getenv("HOME") orelse return "/";
    return std.mem.span(home);
}

/// Wall-clock Unix seconds (relative Modified rendering).
fn nowEpochSeconds(io: std.Io) i64 {
    const ns = std.Io.Clock.real.now(io).nanoseconds;
    return @intCast(@divFloor(ns, std.time.ns_per_s));
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
const testing = std.testing;

test "history stack: visit, back, forward, truncation" {
    const gpa = testing.allocator;
    var h: History = .{};
    defer h.deinit(gpa);

    try testing.expectEqual(@as(?[]const u8, null), h.current());
    try testing.expect(!h.canGoBack());

    try h.visit(gpa, "/a");
    try h.visit(gpa, "/a"); // revisit dedups
    try h.visit(gpa, "/a/b");
    try h.visit(gpa, "/a/b/c");
    try testing.expectEqualStrings("/a/b/c", h.current().?);
    try testing.expect(h.canGoBack());
    try testing.expect(!h.canGoForward());

    try testing.expectEqualStrings("/a/b", h.goBack(gpa).?);
    try testing.expectEqualStrings("/a", h.goBack(gpa).?);
    try testing.expect(h.goBack(gpa) == null);
    try testing.expect(h.canGoForward());

    try testing.expectEqualStrings("/a/b", h.goForward(gpa).?);
    // A fresh visit truncates the forward stack.
    try h.visit(gpa, "/z");
    try testing.expect(!h.canGoForward());
    try testing.expectEqualStrings("/a/b", h.goBack(gpa).?);
    try testing.expectEqualStrings("/a", h.goBack(gpa).?);
    try testing.expectEqualStrings("/a/b", h.goForward(gpa).?);
    try testing.expectEqualStrings("/z", h.goForward(gpa).?);
}

fn buildTestSnapshot(gpa: Allocator) !*DirSnapshot {
    var b = try snapshot_mod.Builder.init(gpa, "/pub", 11);
    var finishing = false;
    errdefer if (!finishing) b.abandon();
    const a = b.arena();
    const batch = [_]vfs_mod.Entry{
        .{ .name = try a.dupe(u8, "Docs"), .kind = .dir, .mtime = 50 },
        .{ .name = try a.dupe(u8, "alpha.txt"), .kind = .file, .size = 1024, .mtime = 10, .mode = 0o644 },
        .{ .name = try a.dupe(u8, ".hidden"), .kind = .file, .size = 1 },
        .{ .name = try a.dupe(u8, "Beta.txt"), .kind = .file, .size = 2048, .mtime = 20 },
    };
    try b.append(&batch);
    finishing = true;
    return b.finish();
}

test "visible permutation: dotfiles, live filter, optimistic overlay" {
    const gpa = testing.allocator;
    const snap = try buildTestSnapshot(gpa);
    defer snap.unref();

    const sort = try snap.sortIndex(gpa, .{});
    defer gpa.free(sort);

    var overlay: Overlay = .{};
    defer overlay.deinit(gpa);
    var visible: std.ArrayList(u32) = .empty;
    defer visible.deinit(gpa);

    // Default: dirs first, dotfiles hidden.
    try buildVisible(gpa, snap.entries, sort, &overlay, .{}, &visible);
    try testing.expectEqual(@as(usize, 3), visible.items.len);
    try testing.expectEqualStrings("Docs", snap.entries[visible.items[0]].name);
    try testing.expectEqualStrings("alpha.txt", snap.entries[visible.items[1]].name);
    try testing.expectEqualStrings("Beta.txt", snap.entries[visible.items[2]].name);

    // Cmd+Shift+. shows dotfiles.
    try buildVisible(gpa, snap.entries, sort, &overlay, .{ .show_hidden = true }, &visible);
    try testing.expectEqual(@as(usize, 4), visible.items.len);

    // Cmd+F filter narrows case-insensitively.
    try buildVisible(gpa, snap.entries, sort, &overlay, .{ .needle = "BET" }, &visible);
    try testing.expectEqual(@as(usize, 1), visible.items.len);
    try testing.expectEqualStrings("Beta.txt", snap.entries[visible.items[0]].name);

    // Optimistic delete hides; optimistic rename filters on the new name.
    const alpha_idx: u32 = 1;
    try overlay.hide(gpa, alpha_idx);
    try buildVisible(gpa, snap.entries, sort, &overlay, .{}, &visible);
    try testing.expectEqual(@as(usize, 2), visible.items.len);
    overlay.unhideAll();

    const beta_idx: u32 = 3;
    try overlay.setRename(gpa, beta_idx, "zulu.txt");
    try buildVisible(gpa, snap.entries, sort, &overlay, .{ .needle = "zulu" }, &visible);
    try testing.expectEqual(@as(usize, 1), visible.items.len);
    try testing.expectEqual(beta_idx, visible.items[0]);
    try testing.expectEqualStrings("zulu.txt", overlay.displayName(snap.entries, beta_idx));

    // Optimistic mkdir prepends the virtual row.
    try overlay.setNewFolder(gpa, "incoming");
    try buildVisible(gpa, snap.entries, sort, &overlay, .{}, &visible);
    try testing.expectEqual(virtual_new_folder_row, visible.items[0]);
}

test "pending-set semantics drive the 60%-alpha treatment" {
    const gpa = testing.allocator;
    var overlay: Overlay = .{};
    defer overlay.deinit(gpa);

    try testing.expect(overlay.isEmpty());
    try testing.expect(!overlay.isPendingRow(2));

    try overlay.setRename(gpa, 2, "first");
    try overlay.setRename(gpa, 2, "second"); // replaces (no leak)
    try testing.expect(overlay.isPendingRow(2));
    try testing.expect(!overlay.isPendingRow(3));
    try testing.expect(overlay.isPendingRow(virtual_new_folder_row));
    try testing.expect(!overlay.isEmpty());

    try overlay.hide(gpa, 5);
    try testing.expect(overlay.isHidden(5));
    overlay.unhide(5);
    try testing.expect(!overlay.isHidden(5));

    try overlay.setNewFolder(gpa, "a");
    try overlay.setNewFolder(gpa, "b"); // replaces (no leak)
    try testing.expectEqualStrings("b", overlay.new_folder.?);

    // Rollback paths.
    overlay.clearRenames(gpa);
    try testing.expect(!overlay.isPendingRow(2));
    overlay.clearNewFolder(gpa);
    try testing.expect(overlay.isEmpty());

    // chmod staging: mode override + pending treatment + rollback.
    const entries = [_]vfs_mod.Entry{
        .{ .name = "a", .kind = .file, .mode = 0o644 },
        .{ .name = "b", .kind = .file },
    };
    try overlay.setMode(gpa, 0, 0o600);
    try testing.expect(overlay.isPendingRow(0));
    try testing.expect(!overlay.isEmpty());
    try testing.expectEqual(@as(?u16, 0o600), overlay.displayMode(&entries, 0));
    try testing.expectEqual(@as(?u16, null), overlay.displayMode(&entries, 1)); // no override, no mode
    overlay.clearModes();
    try testing.expect(!overlay.isPendingRow(0));
    try testing.expectEqual(@as(?u16, 0o644), overlay.displayMode(&entries, 0));
    try testing.expect(overlay.isEmpty());

    // Snapshot swap clears everything at once.
    try overlay.setRename(gpa, 1, "x");
    try overlay.hide(gpa, 2);
    try overlay.setMode(gpa, 3, 0o755);
    try overlay.setNewFolder(gpa, "y");
    overlay.clear(gpa);
    try testing.expect(overlay.isEmpty());
}

test "path-bar parse: absolute, relative, tilde, whitespace, garbage" {
    const gpa = testing.allocator;

    const abs = try parsePathInput(gpa, "  /var//log/ ", "/anywhere", null);
    defer gpa.free(abs);
    try testing.expectEqualStrings("/var/log", abs);

    const rel = try parsePathInput(gpa, "sub/dir", "/base", null);
    defer gpa.free(rel);
    try testing.expectEqualStrings("/base/sub/dir", rel);

    const up = try parsePathInput(gpa, "../sibling", "/a/b", null);
    defer gpa.free(up);
    try testing.expectEqualStrings("/a/sibling", up);

    const tilde = try parsePathInput(gpa, "~", "/", "/Users/relay");
    defer gpa.free(tilde);
    try testing.expectEqualStrings("/Users/relay", tilde);

    const tilde_sub = try parsePathInput(gpa, "~/Downloads", "/", "/Users/relay");
    defer gpa.free(tilde_sub);
    try testing.expectEqualStrings("/Users/relay/Downloads", tilde_sub);

    // Remote panes get no tilde expansion: "~" is a relative name there.
    const remote_tilde = try parsePathInput(gpa, "~", "/home", null);
    defer gpa.free(remote_tilde);
    try testing.expectEqualStrings("/home/~", remote_tilde);

    try testing.expectError(error.InvalidPath, parsePathInput(gpa, "   ", "/", null));
    try testing.expectError(error.InvalidPath, parsePathInput(gpa, "../..", "/a", null));
}

test "formatters: counts, sizes, mtime, mode, status line" {
    var buf: [64]u8 = undefined;

    try testing.expectEqualStrings("0", formatCount(&buf, 0));
    try testing.expectEqualStrings("999", formatCount(&buf, 999));
    try testing.expectEqualStrings("1,000", formatCount(&buf, 1000));
    try testing.expectEqualStrings("98,412", formatCount(&buf, 98_412));
    try testing.expectEqualStrings("1,234,567", formatCount(&buf, 1_234_567));

    // humanBytes itself is tested in src/app/format.zig (shared helper).
    try testing.expectEqualStrings("—", formatSize(&buf, true, 12345));
    try testing.expectEqualStrings("", formatSize(&buf, false, null));

    // 2024-06-11 12:00:00 UTC.
    try testing.expectEqualStrings("2024-06-11 12:00", formatMtime(&buf, 1_718_107_200));
    try testing.expectEqualStrings("", formatMtime(&buf, null));
    try testing.expectEqualStrings("", formatMtime(&buf, -5));

    // Relative date format (Settings → Date format).
    const now: i64 = 1_718_107_200; // 2024-06-11 12:00 UTC
    try testing.expectEqualStrings("just now", formatMtimeRelative(&buf, now - 30, now));
    try testing.expectEqualStrings("5 min ago", formatMtimeRelative(&buf, now - 5 * 60, now));
    try testing.expectEqualStrings("3 hr ago", formatMtimeRelative(&buf, now - 3 * 3600, now));
    try testing.expectEqualStrings("1 day ago", formatMtimeRelative(&buf, now - 30 * 3600, now));
    try testing.expectEqualStrings("6 days ago", formatMtimeRelative(&buf, now - 6 * 86_400, now));
    // A week or older — and future skew — fall back to ISO.
    try testing.expectEqualStrings("2024-06-04 12:00", formatMtimeRelative(&buf, now - 7 * 86_400, now));
    try testing.expectEqualStrings("2024-06-11 12:01", formatMtimeRelative(&buf, now + 60, now));
    try testing.expectEqualStrings("", formatMtimeRelative(&buf, null, now));
    try testing.expectEqualStrings("", formatMtimeRelative(&buf, -5, now));
    try testing.expectEqualStrings("just now", formatMtimeAs(&buf, now - 1, .relative, now));
    try testing.expectEqualStrings("2024-06-11 12:00", formatMtimeAs(&buf, now, .iso, now));

    try testing.expectEqualStrings("644", formatMode(&buf, 0o644));
    try testing.expectEqualStrings("1777", formatMode(&buf, 0o1777));
    try testing.expectEqualStrings("", formatMode(&buf, null));

    var sbuf: [256]u8 = undefined;
    try testing.expectEqualStrings("1,204 items", formatStatus(&sbuf, .{ .item_count = 1204 }));
    try testing.expectEqualStrings("1 item", formatStatus(&sbuf, .{ .item_count = 1 }));
    try testing.expectEqualStrings(
        "Listing… 12,400",
        formatStatus(&sbuf, .{ .listing = true, .listing_count = 12_400 }),
    );
    try testing.expectEqualStrings(
        "Connected · 2 items · 1 selected (2.0 KB)",
        formatStatus(&sbuf, .{ .chip = "Connected", .item_count = 2, .sel_count = 1, .sel_bytes = 2048 }),
    );
    try testing.expectEqualStrings("hint", formatStatus(&sbuf, .{ .hint = "hint", .item_count = 9 }));
    // Latency honesty (docs/UX.md): remote panes append the round trip.
    try testing.expectEqualStrings(
        "Connected · 2 items · 12 ms",
        formatStatus(&sbuf, .{ .chip = "Connected", .item_count = 2, .latency_ms = 12 }),
    );
    try testing.expectEqualStrings(
        "1 item · 0 ms · 1 selected (1023 B)",
        formatStatus(&sbuf, .{ .item_count = 1, .latency_ms = 0, .sel_count = 1, .sel_bytes = 1023 }),
    );
}

test "type-select finds the next prefix match with wraparound" {
    const gpa = testing.allocator;
    const snap = try buildTestSnapshot(gpa);
    defer snap.unref();
    const sort = try snap.sortIndex(gpa, .{});
    defer gpa.free(sort);

    var overlay: Overlay = .{};
    defer overlay.deinit(gpa);
    var visible: std.ArrayList(u32) = .empty;
    defer visible.deinit(gpa);
    try buildVisible(gpa, snap.entries, sort, &overlay, .{}, &visible);
    // Visible order: Docs, alpha.txt, Beta.txt.

    try testing.expectEqual(@as(?usize, 2), typeSelectRow(snap.entries, &overlay, visible.items, "be", 0));
    try testing.expectEqual(@as(?usize, 1), typeSelectRow(snap.entries, &overlay, visible.items, "AL", 2)); // wraps
    try testing.expectEqual(@as(?usize, 0), typeSelectRow(snap.entries, &overlay, visible.items, "do", 0));
    try testing.expectEqual(@as(?usize, null), typeSelectRow(snap.entries, &overlay, visible.items, "zzz", 0));
    try testing.expectEqual(@as(?usize, null), typeSelectRow(snap.entries, &overlay, visible.items, "", 0));
}

test "findEntryByName re-resolves sheet targets after a snapshot swap" {
    const gpa = testing.allocator;
    const snap = try buildTestSnapshot(gpa);
    defer snap.unref();

    // Sheet-open time: the target is entry 1 ("alpha.txt").
    try testing.expectEqual(@as(?u32, 1), findEntryByName(snap.entries, "alpha.txt"));

    // While the sheet is up, an unsolicited re-list swaps in a newer
    // snapshot whose indexes are remapped ("zero.txt" inserted first).
    var b = try snapshot_mod.Builder.init(gpa, "/pub", 12);
    var finishing = false;
    errdefer if (!finishing) b.abandon();
    const a = b.arena();
    const batch = [_]vfs_mod.Entry{
        .{ .name = try a.dupe(u8, "zero.txt"), .kind = .file, .size = 3 },
        .{ .name = try a.dupe(u8, "Docs"), .kind = .dir, .mtime = 50 },
        .{ .name = try a.dupe(u8, "alpha.txt"), .kind = .file, .size = 1024 },
    };
    try b.append(&batch);
    finishing = true;
    const newer = try b.finish();
    defer newer.unref();

    // The stale index (1) now points at "Docs"; by-name resolution finds
    // the real target at its new index, and deleted targets resolve null.
    try testing.expectEqual(@as(?u32, 2), findEntryByName(newer.entries, "alpha.txt"));
    try testing.expectEqual(@as(?u32, null), findEntryByName(newer.entries, "Beta.txt"));
    try testing.expectEqual(@as(?u32, null), findEntryByName(&.{}, "alpha.txt"));
}

test "syncTarget mirrors relative path changes onto the other pane" {
    const gpa = testing.allocator;

    // Descend: /a → /a/x against /b mirrors to /b/x.
    {
        const t = (try syncTarget(gpa, "/a", "/a/x", "/b")).?;
        defer gpa.free(t);
        try testing.expectEqualStrings("/b/x", t);
    }
    // Up one: /a/x → /a against /b/x mirrors to /b.
    {
        const t = (try syncTarget(gpa, "/a/x", "/a", "/b/x")).?;
        defer gpa.free(t);
        try testing.expectEqualStrings("/b", t);
    }
    // Sibling hop (one up, one down).
    {
        const t = (try syncTarget(gpa, "/a/x", "/a/y", "/b/x")).?;
        defer gpa.free(t);
        try testing.expectEqualStrings("/b/y", t);
    }
    // Multi-component descent carries every new component over.
    {
        const t = (try syncTarget(gpa, "/srv/www", "/srv/www/site/htdocs", "/var")).?;
        defer gpa.free(t);
        try testing.expectEqualStrings("/var/site/htdocs", t);
    }
    // Walking up to the source root can land on the destination root.
    {
        const t = (try syncTarget(gpa, "/a", "/", "/b")).?;
        defer gpa.free(t);
        try testing.expectEqualStrings("/", t);
    }
    // More ups than the destination has components: trees diverged → null.
    try testing.expect((try syncTarget(gpa, "/a/b", "/", "/c")) == null);
    try testing.expect((try syncTarget(gpa, "/a/b/c", "/a", "/x")) == null);
}

test "compareSnapshots classifies presence, size, mtime, and kind deltas" {
    const gpa = testing.allocator;
    const a = [_]vfs_mod.Entry{
        .{ .name = "same.txt", .kind = .file, .size = 100, .mtime = 1000 },
        .{ .name = "size.txt", .kind = .file, .size = 100, .mtime = 1000 },
        .{ .name = "mtime.txt", .kind = .file, .size = 100, .mtime = 1000 },
        .{ .name = "slack.txt", .kind = .file, .size = 100, .mtime = 1000 },
        .{ .name = "dir", .kind = .dir, .mtime = 1 },
        .{ .name = "kind", .kind = .file, .size = 1 },
        .{ .name = "only-a", .kind = .file, .size = 1 },
        .{ .name = "nulls.txt", .kind = .file, .size = null, .mtime = null },
    };
    const b = [_]vfs_mod.Entry{
        .{ .name = "same.txt", .kind = .file, .size = 100, .mtime = 1000 },
        .{ .name = "size.txt", .kind = .file, .size = 200, .mtime = 1000 },
        .{ .name = "mtime.txt", .kind = .file, .size = 100, .mtime = 5000 },
        .{ .name = "slack.txt", .kind = .file, .size = 100, .mtime = 1000 + compare_mtime_slack_s },
        .{ .name = "dir", .kind = .dir, .mtime = 99_999 },
        .{ .name = "kind", .kind = .dir },
        .{ .name = "only-b", .kind = .file, .size = 1 },
        .{ .name = "nulls.txt", .kind = .file, .size = 100, .mtime = 7777 },
    };

    var tints = try compareSnapshots(gpa, &a, &b);
    defer tints.deinit(gpa);
    try testing.expectEqual(RowTint.same, tints.a[0]);
    try testing.expectEqual(RowTint.differs, tints.a[1]); // size delta
    try testing.expectEqual(RowTint.differs, tints.a[2]); // mtime delta
    try testing.expectEqual(RowTint.same, tints.a[3]); // within the slack
    try testing.expectEqual(RowTint.same, tints.a[4]); // dirs: presence only
    try testing.expectEqual(RowTint.differs, tints.a[5]); // file vs dir
    try testing.expectEqual(RowTint.missing, tints.a[6]); // no counterpart
    try testing.expectEqual(RowTint.same, tints.a[7]); // null fields skip the check
    // b mirrors the shared classes; its unmatched name is missing there.
    try testing.expectEqual(RowTint.same, tints.b[0]);
    try testing.expectEqual(RowTint.differs, tints.b[1]);
    try testing.expectEqual(RowTint.missing, tints.b[6]);

    // Empty other pane: everything here is missing, nothing there.
    var lop = try compareSnapshots(gpa, &a, &.{});
    defer lop.deinit(gpa);
    for (lop.a) |t| try testing.expectEqual(RowTint.missing, t);
    try testing.expectEqual(@as(usize, 0), lop.b.len);
}

test "prodConfirmAllowed: destructive click counts only while Cmd is held" {
    try testing.expect(prodConfirmAllowed(true, true));
    try testing.expect(!prodConfirmAllowed(true, false)); // click without Cmd
    try testing.expect(!prodConfirmAllowed(false, true)); // Cancel with Cmd
    try testing.expect(!prodConfirmAllowed(false, false));
}

test "localPathIsDir follows symlinks: dir-links descend, file-links don't" {
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "d", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "f.txt", .data = "x" });
    tmp.dir.symLink(io, "d", "dlink", .{}) catch |err| switch (err) {
        // Filesystems without symlink support skip the test body.
        error.AccessDenied => return,
        else => return err,
    };
    try tmp.dir.symLink(io, "f.txt", "flink", .{});
    try tmp.dir.symLink(io, "gone", "dangling", .{});

    try testing.expect(localPathIsDir(io, tmp.dir, "/d"));
    try testing.expect(localPathIsDir(io, tmp.dir, "/dlink"));
    try testing.expect(!localPathIsDir(io, tmp.dir, "/f.txt"));
    try testing.expect(!localPathIsDir(io, tmp.dir, "/flink"));
    try testing.expect(!localPathIsDir(io, tmp.dir, "/dangling"));
    try testing.expect(!localPathIsDir(io, tmp.dir, "/missing"));
    try testing.expect(!localPathIsDir(io, tmp.dir, "relative"));
    try testing.expect(!localPathIsDir(io, tmp.dir, ""));
}

test "accentUiColor maps site accents to semantic colors" {
    try testing.expectEqual(@as(?foundation.Color, null), accentUiColor(.none));
    try testing.expectEqual(@as(?foundation.Color, .system_blue), accentUiColor(.blue));
    try testing.expectEqual(@as(?foundation.Color, .system_purple), accentUiColor(.purple));
    try testing.expectEqual(@as(?foundation.Color, .system_red), accentUiColor(.red));
    try testing.expectEqual(@as(?foundation.Color, .system_orange), accentUiColor(.orange));
    try testing.expectEqual(@as(?foundation.Color, .system_yellow), accentUiColor(.yellow));
    try testing.expectEqual(@as(?foundation.Color, .system_green), accentUiColor(.green));
    try testing.expectEqual(@as(?foundation.Color, .system_gray), accentUiColor(.graphite));
}

// --- end-to-end (headless): real AppCore, real views, no window shown -----

const FakeStore = relay.cred.fake.FakeStore;

fn drainUntil(core: *bridge.AppCore, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool) !void {
    const io = core.io;
    const deadline = std.Io.Clock.awake.now(io).nanoseconds +
        @as(i96, 5 * std.time.ns_per_s);
    while (true) {
        core.drainNow();
        if (pred(ctx)) return;
        if (std.Io.Clock.awake.now(io).nanoseconds > deadline) return error.Timeout;
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
}

const PaneSettled = struct {
    pane: *BrowserPane,
    path: []const u8,

    fn ready(self: *@This()) bool {
        if (self.pane.pending_request != null) return false;
        const snap = self.pane.snapshot orelse return false;
        return std.mem.eql(u8, snap.path, self.path);
    }
};

test "dual-pane controller: local listing, navigation history, filters (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    const io = core.io;
    try tmp_root.dir.writeFile(io, .{ .sub_path = "alpha.txt", .data = "aaaaa" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "beta.txt", .data = "bb" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = ".dotfile", .data = "." });
    try tmp_root.dir.createDir(io, "sub", .default_dir);
    try tmp_root.dir.writeFile(io, .{ .sub_path = "sub/inner.txt", .data = "i" });

    const win = window_mod.Window.create(
        foundation.rect(0, 0, 1000, 600),
        "relay-browser-test",
        window_mod.StyleMask.standard,
    );

    const bc = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/" });
    win.setContentView(objc.Object.fromId(bc.view()));

    const local = bc.localPane();
    var settled: PaneSettled = .{ .pane = local, .path = "/" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // Selection hook (the inspector feed): fires on selection change,
    // snapshot swap, and focus switch — for the FOCUSED pane only.
    const HookRecorder = struct {
        calls: usize = 0,
        last_pane: ?*BrowserPane = null,

        fn onSelection(ctx: ?*anyopaque, pane: *BrowserPane) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.last_pane = pane;
        }
    };
    var hook_rec: HookRecorder = .{};
    bc.setSelectionHook(.{ .ctx = &hook_rec, .notify = HookRecorder.onSelection });

    bc.focused = 0;
    BrowserPane.dsSelectionChanged(@ptrCast(local), &[_]usize{0});
    try testing.expectEqual(@as(usize, 1), hook_rec.calls);
    try testing.expectEqual(@as(?*BrowserPane, local), hook_rec.last_pane);
    try testing.expectEqual(@as(usize, 1), local.sel_count);

    // A table interaction takes focus, so its pane feeds the inspector...
    BrowserPane.dsSelectionChanged(@ptrCast(bc.remotePane()), &[_]usize{});
    try testing.expectEqual(@as(?*BrowserPane, bc.remotePane()), hook_rec.last_pane);
    // ...but background events for an UNfocused pane never clobber it.
    bc.focused = 0;
    hook_rec.last_pane = null;
    bc.notifySelection(bc.remotePane());
    try testing.expectEqual(@as(?*BrowserPane, null), hook_rec.last_pane);
    BrowserPane.dsSelectionChanged(@ptrCast(local), &[_]usize{ 0, 1 });
    try testing.expectEqual(@as(usize, 2), local.sel_count);

    // Focus switch re-feeds with the newly focused pane.
    const calls_before_focus = hook_rec.calls;
    bc.focusPane(1);
    try testing.expect(hook_rec.calls > calls_before_focus);
    try testing.expectEqual(@as(?*BrowserPane, bc.remotePane()), hook_rec.last_pane);
    bc.focusPane(0);
    try testing.expectEqual(@as(?*BrowserPane, local), hook_rec.last_pane);

    // Initial listing: dirs-first default sort, dotfile hidden.
    try testing.expectEqual(@as(usize, 3), local.visible.items.len);
    try testing.expectEqualStrings("sub", local.snapshot.?.entries[local.visible.items[0]].name);
    try testing.expectEqualStrings("/", local.history.current().?);
    const status = try chrome.text(gpa, local.status_label);
    defer gpa.free(status);
    try testing.expect(std.mem.indexOf(u8, status, "3 items") != null);

    // Hidden-files toggle (Cmd+Shift+.) is a pure client-side re-filter.
    local.toggleHidden();
    try testing.expectEqual(@as(usize, 4), local.visible.items.len);
    local.toggleHidden();
    try testing.expectEqual(@as(usize, 3), local.visible.items.len);

    // Cmd+F live filter narrows; clearing restores.
    local.applyFilter("alp");
    try testing.expectEqual(@as(usize, 1), local.visible.items.len);
    try testing.expectEqualStrings("alpha.txt", local.snapshot.?.entries[local.visible.items[0]].name);
    local.applyFilter("");
    try testing.expectEqual(@as(usize, 3), local.visible.items.len);

    // Streaming partials: a listing_progress that carries a snapshot
    // populates the table while the listing is still pending (docs/UX.md
    // "first rows visible immediately").
    {
        local.pending_request = 4242;
        const partial = try buildTestSnapshot(gpa);
        defer partial.unref();
        const partial_sort = try partial.sortIndex(gpa, .{});
        defer gpa.free(partial_sort);
        local.handleListingProgress(.{
            .request_id = 4242,
            .pane_token = local.token(),
            .entries_so_far = partial.entries.len,
            .snapshot = partial,
            .sort_index = partial_sort,
        });
        try testing.expectEqual(@as(?*DirSnapshot, partial), local.snapshot);
        try testing.expectEqual(@as(?bridge.RequestId, 4242), local.pending_request);
        try testing.expectEqual(@as(usize, 3), local.visible.items.len); // dotfile hidden
        const streaming_status = try chrome.text(gpa, local.status_label);
        defer gpa.free(streaming_status);
        try testing.expect(std.mem.indexOf(u8, streaming_status, "Listing…") != null);
        local.pending_request = null;
    }

    // Visit hook (M3 palette frecency feed): fires for history-recorded
    // navigations with the pane's site id + landed path.
    const VisitRecorder = struct {
        calls: usize = 0,
        last_site: u64 = 99,
        last_path: [64]u8 = undefined,
        last_path_len: usize = 0,

        fn onVisit(ctx: ?*anyopaque, site_id: u64, path: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.last_site = site_id;
            self.last_path_len = @min(path.len, self.last_path.len);
            @memcpy(self.last_path[0..self.last_path_len], path[0..self.last_path_len]);
        }
    };
    var visit_rec: VisitRecorder = .{};
    bc.setVisitHook(.{ .ctx = &visit_rec, .notify = VisitRecorder.onVisit });

    // Descend + history: back returns, forward re-descends.
    local.navigateTo("/sub", .push);
    settled = .{ .pane = local, .path = "/sub" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expectEqual(@as(usize, 1), local.visible.items.len);
    try testing.expect(local.history.canGoBack());
    try testing.expectEqual(@as(usize, 1), visit_rec.calls);
    try testing.expectEqual(item_mod.local_site_id, visit_rec.last_site);
    try testing.expectEqualStrings("/sub", visit_rec.last_path[0..visit_rec.last_path_len]);

    local.goBack();
    settled = .{ .pane = local, .path = "/" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expect(local.history.canGoForward());

    local.goForward();
    settled = .{ .pane = local, .path = "/sub" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expectEqualStrings("/sub", local.history.current().?);

    // Cmd+Up.
    local.goUp();
    settled = .{ .pane = local, .path = "/" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // The path bar mirrors the current path.
    const path_text = try chrome.text(gpa, local.path_field);
    defer gpa.free(path_text);
    try testing.expectEqualStrings("/", path_text);

    // Remote pane: unbound empty state shows the hint.
    const remote = bc.remotePane();
    try testing.expect(remote.site == null);
    const remote_status = try chrome.text(gpa, remote.status_label);
    defer gpa.free(remote_status);
    try testing.expect(std.mem.indexOf(u8, remote_status, "Not connected") != null);

    // Active-pane connects: binding a site to the LOCAL pane switches its
    // role to remote (Permissions column shows), remembers the local path,
    // and restores both when the site goes offline.
    {
        try testing.expectEqual(PaneRole.local, local.role);
        bc.prepareRemoteBind(local.token(), item_mod.local_site_id);
        try testing.expectEqual(PaneRole.remote, local.role);
        try testing.expectEqualStrings("/", local.saved_local_path.?);
        bc.bindRemoteToPane(local.token(), item_mod.local_site_id, "/sub");
        settled = .{ .pane = local, .path = "/sub" };
        try drainUntil(core, &settled, PaneSettled.ready);
        try testing.expectEqual(PaneRole.remote, local.role);
        // The pane-token listing delivered a latency reading for the chip.
        try testing.expect(local.last_latency_ms != null);

        // Disconnect: the offline status restores the local role + path.
        _ = core.events_q.post(.{ .site_status = .{
            .site_id = item_mod.local_site_id,
            .status = .offline,
        } }) catch {};
        core.drainNow();
        try testing.expectEqual(PaneRole.local, local.role);
        try testing.expectEqual(@as(?u64, item_mod.local_site_id), local.site);
        try testing.expect(local.saved_local_path == null);
        settled = .{ .pane = local, .path = "/" };
        try drainUntil(core, &settled, PaneSettled.ready);
        try testing.expectEqualStrings("/", local.history.current().?);
        // The home-remote pane keeps its role across foreign disconnects.
        try testing.expectEqual(PaneRole.remote, remote.role);
    }

    // Optional visual harness: RELAY_BROWSER_HARNESS=1 shows the window
    // briefly (docs: window-dependent behavior is verified by running).
    if (std.c.getenv("RELAY_BROWSER_HARNESS") != null) {
        const app = window_mod.App.shared();
        app.setRegularActivationPolicy();
        win.makeKeyAndOrderFront();
        app.activate();
        var ticks: usize = 0;
        while (ticks < 150) : (ticks += 1) {
            core.drainNow();
            io.sleep(.fromMilliseconds(10), .awake) catch {};
        }
        win.orderOut();
    }

    // Teardown order matters: stop all drains, then free the controller.
    core.shutdown();
    bc.destroy();
    win.release();
}

/// Compare-tint lookup by entry name (test helper).
fn tintOf(pane: *BrowserPane, name: []const u8) ?RowTint {
    const snap = pane.snapshot orelse return null;
    const idx = findEntryByName(snap.entries, name) orelse return null;
    if (idx >= pane.compare_tints.len) return null;
    return pane.compare_tints[idx];
}

fn kev(chars: []const u8) table_source.KeyEvent {
    return .{ .key_code = 0, .chars = chars };
}

test "isFunctionKeyChars: arrows/function keys yes, real text no" {
    // The four arrows (U+F700–U+F703) and forward-delete (U+F728) — all UTF-8.
    try testing.expect(isFunctionKeyChars("\xEF\x9C\x80")); // up    U+F700
    try testing.expect(isFunctionKeyChars("\xEF\x9C\x81")); // down  U+F701
    try testing.expect(isFunctionKeyChars("\xEF\x9C\x82")); // left  U+F702
    try testing.expect(isFunctionKeyChars("\xEF\x9C\x83")); // right U+F703
    try testing.expect(isFunctionKeyChars("\xEF\x9C\xA8")); // fwd-delete U+F728
    // Real type-to-select input is never treated as a function key.
    try testing.expect(!isFunctionKeyChars("a"));
    try testing.expect(!isFunctionKeyChars("Z"));
    try testing.expect(!isFunctionKeyChars("7"));
    try testing.expect(!isFunctionKeyChars("é")); // U+00E9, 2-byte UTF-8
    try testing.expect(!isFunctionKeyChars("漢")); // U+6F22, 3-byte but < 0xF700
    try testing.expect(!isFunctionKeyChars("")); // no chars
}

test "sync browsing, compare mode, vim layer (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    // Pane 0 browses /a, pane 1 binds to /b (same local backend):
    //   /a/x  /a/y  (dirs; only x exists under /b — the sync-stop trigger)
    //   same.txt identical, diff.txt different size, only-a / only-b unique.
    const io = core.io;
    try tmp_root.dir.createDir(io, "a", .default_dir);
    try tmp_root.dir.createDir(io, "a/x", .default_dir);
    try tmp_root.dir.createDir(io, "a/y", .default_dir);
    try tmp_root.dir.createDir(io, "b", .default_dir);
    try tmp_root.dir.createDir(io, "b/x", .default_dir);
    try tmp_root.dir.writeFile(io, .{ .sub_path = "a/same.txt", .data = "12345" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "b/same.txt", .data = "12345" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "a/diff.txt", .data = "123" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "b/diff.txt", .data = "1234567" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "a/only-a.txt", .data = "z" });
    try tmp_root.dir.writeFile(io, .{ .sub_path = "b/only-b.txt", .data = "q" });

    const win = window_mod.Window.create(
        foundation.rect(0, 0, 1000, 600),
        "relay-browser-power-test",
        window_mod.StyleMask.standard,
    );

    const bc = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/a" });
    win.setContentView(objc.Object.fromId(bc.view()));

    const p0 = bc.localPane();
    const p1 = bc.remotePane();
    var settled: PaneSettled = .{ .pane = p0, .path = "/a" };
    try drainUntil(core, &settled, PaneSettled.ready);
    bc.bindRemoteToPane(p1.token(), item_mod.local_site_id, "/b");
    settled = .{ .pane = p1, .path = "/b" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // --- Synchronized browsing -------------------------------------------
    try testing.expect(chrome.isHidden(p0.sync_label));
    bc.toggleSyncBrowsing();
    try testing.expect(bc.sync_browsing);
    try testing.expect(!chrome.isHidden(p0.sync_label)); // "⇄" in both bars
    try testing.expect(!chrome.isHidden(p1.sync_label));

    // A navigation in pane 0 mirrors the relative change into pane 1.
    p0.navigateTo("/a/x", .push);
    settled = .{ .pane = p0, .path = "/a/x" };
    try drainUntil(core, &settled, PaneSettled.ready);
    settled = .{ .pane = p1, .path = "/b/x" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expectEqualStrings("/b/x", p1.history.current().?);

    // Mirroring into a missing dir stops the link gracefully (status hint,
    // indicator gone, no error sheet).
    p0.navigateTo("/a/y", .push);
    settled = .{ .pane = p0, .path = "/a/y" };
    try drainUntil(core, &settled, PaneSettled.ready);
    const SyncStopped = struct {
        bc: *BrowserController,
        fn ready(self: *@This()) bool {
            return !self.bc.sync_browsing;
        }
    };
    var stopped: SyncStopped = .{ .bc = bc };
    try drainUntil(core, &stopped, SyncStopped.ready);
    try testing.expect(chrome.isHidden(p0.sync_label));
    try testing.expect(chrome.isHidden(p1.sync_label));
    {
        const hint = try chrome.text(gpa, p1.status_label);
        defer gpa.free(hint);
        try testing.expect(std.mem.indexOf(u8, hint, "Sync stopped") != null);
    }
    try testing.expectEqualStrings("/b/x", p1.history.current().?); // stayed put

    // --- Directory comparison --------------------------------------------
    p0.navigateTo("/a", .push);
    settled = .{ .pane = p0, .path = "/a" };
    try drainUntil(core, &settled, PaneSettled.ready);
    p1.navigateTo("/b", .push);
    settled = .{ .pane = p1, .path = "/b" };
    try drainUntil(core, &settled, PaneSettled.ready);

    bc.compare_async = false; // run the diff inline (manual pump, testing gpa)
    bc.toggleComparePanes();
    try testing.expect(bc.compare_mode);
    try testing.expectEqual(@as(?RowTint, .same), tintOf(p0, "same.txt"));
    try testing.expectEqual(@as(?RowTint, .differs), tintOf(p0, "diff.txt"));
    try testing.expectEqual(@as(?RowTint, .missing), tintOf(p0, "only-a.txt"));
    try testing.expectEqual(@as(?RowTint, .same), tintOf(p0, "x")); // dir in both
    try testing.expectEqual(@as(?RowTint, .missing), tintOf(p0, "y"));
    try testing.expectEqual(@as(?RowTint, .missing), tintOf(p1, "only-b.txt"));
    try testing.expectEqual(@as(?RowTint, .differs), tintOf(p1, "diff.txt"));
    {
        const status = try chrome.text(gpa, p0.status_label);
        defer gpa.free(status);
        try testing.expect(std.mem.indexOf(u8, status, "Compare:") != null); // legend
    }

    // Snapshot adoption recomputes the diff (refresh keeps the tints fresh).
    p0.refresh();
    settled = .{ .pane = p0, .path = "/a" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expectEqual(@as(?RowTint, .differs), tintOf(p0, "diff.txt"));

    bc.toggleComparePanes(); // off: tints drop, legend leaves the status bar
    try testing.expect(!bc.compare_mode);
    try testing.expectEqual(@as(usize, 0), p0.compare_tints.len);
    try testing.expectEqual(@as(usize, 0), p1.compare_tints.len);
    {
        const status = try chrome.text(gpa, p0.status_label);
        defer gpa.free(status);
        try testing.expect(std.mem.indexOf(u8, status, "Compare:") == null);
    }

    // --- Vim layer through the real keyDown hook ---------------------------
    // Visible order in /a: x, y, diff.txt, only-a.txt, same.txt.
    bc.setVimMode(true);
    const ctx0: *anyopaque = @ptrCast(p0);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("j")));
    try testing.expectEqual(@as(?usize, 1), p0.table.selectedRow());
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("k")));
    try testing.expectEqual(@as(?usize, 0), p0.table.selectedRow());
    try testing.expect(BrowserPane.dsKeyDown(ctx0, .{ .key_code = 0, .chars = "G", .shift = true }));
    try testing.expectEqual(@as(?usize, 4), p0.table.selectedRow());
    try testing.expectEqualStrings(
        "same.txt",
        p0.snapshot.?.entries[p0.visible.items[4]].name,
    );

    // y: yank the full path (status confirms the copy).
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("y")));
    {
        const status = try chrome.text(gpa, p0.status_label);
        defer gpa.free(status);
        try testing.expect(std.mem.indexOf(u8, status, "Path copied") != null);
    }

    // gg → top; Ctrl+d/u → clamped half pages.
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("g")));
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("g")));
    try testing.expectEqual(@as(?usize, 0), p0.table.selectedRow());
    try testing.expect(BrowserPane.dsKeyDown(ctx0, .{ .key_code = 0, .chars = "\x04", .control = true }));
    try testing.expectEqual(@as(?usize, 4), p0.table.selectedRow());
    try testing.expect(BrowserPane.dsKeyDown(ctx0, .{ .key_code = 0, .chars = "\x15", .control = true }));
    try testing.expectEqual(@as(?usize, 0), p0.table.selectedRow());

    // v anchors a range; Esc leaves visual mode; x toggles the cursor row.
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("v")));
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("j")));
    try testing.expectEqual(@as(usize, 2), p0.table.selectedRows().len);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, .{ .key_code = table_source.key_escape, .chars = "" }));
    try testing.expect(p0.vim_anchor == null);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("x"))); // deselect row 1
    try testing.expectEqual(@as(usize, 1), p0.table.selectedRows().len);
    try testing.expectEqual(@as(?usize, 0), p0.table.selectedRow());

    // Unbound printables are swallowed — type-to-select stays off.
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("q")));
    try testing.expectEqual(@as(usize, 0), p0.ts_len);

    // l descends the selected dir; h returns to the parent.
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("g")));
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("g")));
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("l"))); // open "x"
    settled = .{ .pane = p0, .path = "/a/x" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("h")));
    settled = .{ .pane = p0, .path = "/a" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // / focuses the filter; n cycles the match set.
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("/")));
    try testing.expect(!chrome.isHidden(p0.filter_field));
    p0.applyFilter("same");
    try testing.expectEqual(@as(usize, 1), p0.visible.items.len);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("n")));
    try testing.expectEqual(@as(?usize, 0), p0.table.selectedRow());
    p0.clearFilter();
    try testing.expectEqual(@as(usize, 5), p0.visible.items.len);

    // Even with vim mode ON, an arrow key is not a vim binding (its chars are
    // the 3-byte function-key scalar, not a single printable), so vimHandle
    // declines it and it falls through to NSTableView's native selection —
    // Shift+arrow extension works in both modes.
    try testing.expect(!BrowserPane.dsKeyDown(ctx0, .{
        .key_code = table_source.key_up_arrow,
        .chars = "\xEF\x9C\x80", // NSUpArrowFunctionKey (U+F700), UTF-8
        .shift = true,
    }));

    // Vim off: the same key now feeds type-to-select again.
    bc.setVimMode(false);
    try testing.expect(BrowserPane.dsKeyDown(ctx0, kev("j")));
    try testing.expectEqual(@as(usize, 1), p0.ts_len);

    // Arrow keys are NOT swallowed: dsKeyDown returns false so the event
    // falls through to NSTableView's native keyboard selection (Shift+down
    // extends the selection). The function-key char must not type-to-select.
    try testing.expect(!BrowserPane.dsKeyDown(ctx0, .{
        .key_code = table_source.key_down_arrow,
        .chars = "\xEF\x9C\x81", // NSDownArrowFunctionKey (U+F701), UTF-8
        .shift = true,
    }));
    try testing.expectEqual(@as(usize, 1), p0.ts_len); // unchanged: no type-select

    core.shutdown();
    bc.destroy();
    win.release();
}

/// Read an NSView's toolTip back as an owned UTF-8 slice ("" when unset).
fn toolTipOf(gpa: Allocator, view: objc.Object) ![]u8 {
    const tip = view.msgSend(objc.Object, "toolTip", .{});
    if (tip.value == null) return gpa.dupe(u8, "");
    return foundation.utf8FromNSString(gpa, tip);
}

test "inline error banner + chip tooltip: status/listing event transitions (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    const io = core.io;
    try tmp_root.dir.createDir(io, "srv", .default_dir);
    try tmp_root.dir.writeFile(io, .{ .sub_path = "srv/file.txt", .data = "x" });

    const win = window_mod.Window.create(
        foundation.rect(0, 0, 1000, 600),
        "relay-browser-banner-test",
        window_mod.StyleMask.standard,
    );

    const bc = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/" });
    win.setContentView(objc.Object.fromId(bc.view()));

    // Bind the right pane to the local backend so it is a real .remote-role
    // pane (home_role .remote, so an offline never role-restores it away).
    const remote = bc.remotePane();
    bc.bindRemoteToPane(remote.token(), item_mod.local_site_id, "/srv");
    var settled: PaneSettled = .{ .pane = remote, .path = "/srv" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // Baseline: a successful initial listing leaves no banner.
    try testing.expect(!remote.banner.isVisible());

    // --- Real connect failure: offline WITH an error_class --------------
    // Shows the banner with the reason and sets the chip tooltip.
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id,
        .status = .offline,
        .reason = "Connection refused",
        .error_class = .transient,
    });
    try testing.expect(remote.banner.isVisible());
    try testing.expectEqualStrings("Connection refused", remote.banner.currentMessage());
    {
        const tip = try toolTipOf(gpa, remote.status_label);
        defer gpa.free(tip);
        try testing.expectEqualStrings("Connection refused", tip);
    }

    // --- Reconnect succeeds: connected clears banner + tooltip ----------
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id,
        .status = .connected,
        .reason = "",
    });
    try testing.expect(!remote.banner.isVisible());
    {
        const tip = try toolTipOf(gpa, remote.status_label);
        defer gpa.free(tip);
        try testing.expectEqualStrings("", tip);
    }

    // --- Clean user disconnect: offline with NO error_class -------------
    // (a non-empty reason is allowed but must NOT raise the banner). A clean
    // disconnect also unbinds this home-remote pane to the "Not connected"
    // state, so reconnect (rebind) before exercising further transitions.
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id,
        .status = .offline,
        .reason = "disconnected",
    });
    try testing.expect(!remote.banner.isVisible());
    try testing.expectEqual(@as(?u64, null), remote.site);
    bc.bindRemoteToPane(remote.token(), item_mod.local_site_id, "/srv");
    settled = .{ .pane = remote, .path = "/srv" };
    try drainUntil(core, &settled, PaneSettled.ready);

    // --- Failure again, then a successful (re)list auto-clears it -------
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id,
        .status = .offline,
        .reason = "421 service not available",
        .error_class = .transient,
    });
    try testing.expect(remote.banner.isVisible());
    // A real re-list of the current dir runs through adoptSnapshot → clears.
    remote.refresh();
    settled = .{ .pane = remote, .path = "/srv" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expect(!remote.banner.isVisible());

    // --- A listing failure on the current dir leaves a visible banner ---
    // (drive handleListingDone with a failure for a pending request; the
    // sheet is non-blocking with a window, the banner persists after it).
    {
        remote.pending_request = 9988;
        remote.mirror_pending = false;
        remote.handleListingDone(.{
            .request_id = 9988,
            .pane_token = remote.token(),
            .snapshot = null,
            .sort_index = &.{},
            .failure = .{ .class = .permanent, .protocol_code = 550, .message = "550 permission denied" },
        });
        try testing.expect(remote.banner.isVisible());
        try testing.expectEqualStrings("550 permission denied", remote.banner.currentMessage());
    }

    // --- Dismiss "×" hides the banner and clears the chip tooltip -------
    chrome.setToolTip(remote.status_label, "lingering reason");
    BrowserPane.onBannerDismiss(@ptrCast(remote));
    try testing.expect(!remote.banner.isVisible());
    {
        const tip = try toolTipOf(gpa, remote.status_label);
        defer gpa.free(tip);
        try testing.expectEqualStrings("", tip);
    }

    // --- A background (unmatched site) status never touches this pane ---
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id + 4242,
        .status = .offline,
        .reason = "other site",
        .error_class = .transient,
    });
    try testing.expect(!remote.banner.isVisible());

    core.shutdown();
    bc.destroy();
    win.release();
}

test "clean disconnect clears a home-remote pane; an error drop keeps the listing" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    const io = core.io;
    try tmp_root.dir.createDir(io, "srv", .default_dir);
    try tmp_root.dir.writeFile(io, .{ .sub_path = "srv/file.txt", .data = "x" });

    const win = window_mod.Window.create(
        foundation.rect(0, 0, 1000, 600),
        "relay-browser-disconnect-test",
        window_mod.StyleMask.standard,
    );
    const bc = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/" });
    win.setContentView(objc.Object.fromId(bc.view()));

    const remote = bc.remotePane();
    bc.bindRemoteToPane(remote.token(), item_mod.local_site_id, "/srv");
    var settled: PaneSettled = .{ .pane = remote, .path = "/srv" };
    try drainUntil(core, &settled, PaneSettled.ready);
    bc.onSiteStatus(.{ .site_id = item_mod.local_site_id, .status = .connected, .reason = "" });

    // Connected: a real listing is on screen.
    try testing.expect(remote.snapshot != null);
    try testing.expect(remote.visible.items.len > 0);

    // Clean user disconnect (no error_class): the pane resets to the empty
    // "Not connected" state — site + listing dropped, remote role kept.
    bc.onSiteStatus(.{ .site_id = item_mod.local_site_id, .status = .offline, .reason = "disconnected" });
    try testing.expectEqual(@as(?u64, null), remote.site);
    try testing.expectEqual(@as(?*DirSnapshot, null), remote.snapshot);
    try testing.expectEqual(@as(usize, 0), remote.visible.items.len);
    try testing.expectEqual(PaneRole.remote, remote.role);

    // Reconnect, then an unexpected DROP (error_class set): the listing and
    // binding survive so context is preserved for an in-place reconnect.
    bc.bindRemoteToPane(remote.token(), item_mod.local_site_id, "/srv");
    settled = .{ .pane = remote, .path = "/srv" };
    try drainUntil(core, &settled, PaneSettled.ready);
    bc.onSiteStatus(.{
        .site_id = item_mod.local_site_id,
        .status = .offline,
        .reason = "Connection reset",
        .error_class = .transient,
    });
    try testing.expectEqual(@as(?u64, item_mod.local_site_id), remote.site);
    try testing.expect(remote.snapshot != null);

    core.shutdown();
    bc.destroy();
    win.release();
}

test "pane tokens are process-unique; the drag registry tracks pane lifetime" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const gpa = testing.allocator;

    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(gpa);
    defer fake.deinit();

    const core = try bridge.AppCore.initOptions(gpa, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });

    const win = window_mod.Window.create(
        foundation.rect(0, 0, 1000, 600),
        "relay-browser-token-test",
        window_mod.StyleMask.standard,
    );

    // Two controllers on one core (the multi-tab shape): four panes must
    // hold four distinct tokens (index-derived tokens would collide).
    const bc1 = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/" });
    const bc2 = try BrowserController.create(gpa, core, win, .{ .initial_local_path = "/" });

    const all = [_]*BrowserPane{ bc1.panes[0], bc1.panes[1], bc2.panes[0], bc2.panes[1] };
    for (all, 0..) |pa, i| {
        for (all[i + 1 ..]) |pb| try testing.expect(pa.token() != pb.token());
    }

    // Drag routing: the registry resolves every live token to its pane —
    // including panes of the OTHER controller.
    for (all) |pane|
        try testing.expectEqual(@as(?*BrowserPane, pane), g_pane_registry.get(pane.token()));

    // Detaching one controller while the core keeps running (closing a
    // tab): unregister its listeners, destroy it — its tokens leave the
    // registry and the surviving controller still receives its listings.
    const dead_token = bc2.panes[0].token();
    core.unregisterListeners(bc2);
    bc2.destroy();
    try testing.expectEqual(@as(?*BrowserPane, null), g_pane_registry.get(dead_token));
    try testing.expectEqual(
        @as(?*BrowserPane, bc1.panes[1]),
        g_pane_registry.get(bc1.panes[1].token()),
    );
    var settled: PaneSettled = .{ .pane = bc1.panes[0], .path = "/" };
    try drainUntil(core, &settled, PaneSettled.ready);

    core.shutdown();
    bc1.destroy();
    win.release();
}

test {
    std.testing.refAllDecls(@This());
}

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
//! Threading: everything here runs on the main thread; core results arrive
//! through AppCore's listener dispatch (run-to-completion drains).
//!
//! Lifetime: listeners cannot unregister, so a BrowserController must only
//! be destroyed after `AppCore.shutdown()` (or never — app lifetime).

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");

const objc = mac.objc;
const c = objc.c;
const foundation = mac.foundation;
const runtime = mac.runtime;
const table_source = mac.appkit.table_source;
const split_view = mac.appkit.split_view;
const panels = mac.appkit.panels;
const window_mod = mac.appkit.window;
const drag = mac.appkit.drag;

const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;
const snapshot_mod = relay.vfs.snapshot;
const item_mod = relay.queue.item;
const events_mod = relay.events;

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
    /// Optimistic mkdir row (owned name); at most one in flight per pane.
    new_folder: ?[]u8 = null,

    pub fn deinit(o: *Overlay, gpa: Allocator) void {
        o.clear(gpa);
        o.renames.deinit(gpa);
        o.hidden.deinit(gpa);
        o.* = undefined;
    }

    pub fn clear(o: *Overlay, gpa: Allocator) void {
        o.clearRenames(gpa);
        o.hidden.clearRetainingCapacity();
        o.clearNewFolder(gpa);
    }

    pub fn isEmpty(o: *const Overlay) bool {
        return o.renames.count() == 0 and o.hidden.count() == 0 and o.new_folder == null;
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

    /// Pending treatment (60% alpha): rows with an op in flight.
    pub fn isPendingRow(o: *const Overlay, slot: u32) bool {
        if (slot == virtual_new_folder_row) return true;
        return o.renames.contains(slot);
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

pub fn humanBytes(buf: []u8, n: u64) []const u8 {
    if (n < 1024) return std.fmt.bufPrint(buf, "{d} B", .{n}) catch buf[0..0];
    const units = [_][]const u8{ "KB", "MB", "GB", "TB", "PB" };
    var value = @as(f64, @floatFromInt(n)) / 1024.0;
    var unit: usize = 0;
    while (value >= 1024.0 and unit + 1 < units.len) : (unit += 1) value /= 1024.0;
    if (value < 10.0)
        return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch buf[0..0];
    return std.fmt.bufPrint(buf, "{d:.0} {s}", .{ value, units[unit] }) catch buf[0..0];
}

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
};

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
        if (m.sel_count > 0) {
            var hb: [32]u8 = undefined;
            w.print(" · {s} selected ({s})", .{
                formatCount(&nb, @intCast(m.sel_count)),
                humanBytes(&hb, m.sel_bytes),
            }) catch break :out;
        }
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

    fn release(obj: objc.Object) void {
        obj.msgSend(void, "release", .{});
    }
};

// Virtual key codes table_source does not export.
const key_left_arrow: u16 = 123;
const key_right_arrow: u16 = 124;

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

// ---------------------------------------------------------------------------
// Columns (docs/UX.md): Name/Size/Modified, + Permissions for remote panes.
// ---------------------------------------------------------------------------
const local_columns = [_]table_source.ColumnSpec{
    .{ .id = "name", .title = "Name", .width = 240, .min_width = 120, .custom_draw = true, .sortable = true },
    .{ .id = "size", .title = "Size", .width = 80, .min_width = 60, .alignment = .right, .monospaced_digits = true, .sortable = true },
    .{ .id = "modified", .title = "Modified", .width = 130, .min_width = 110, .monospaced_digits = true, .sortable = true },
};
const remote_columns = local_columns ++ [_]table_source.ColumnSpec{
    .{ .id = "mode", .title = "Permissions", .width = 84, .min_width = 60, .monospaced_digits = true },
};

// Pane chrome geometry (fixed-height bars; the table flexes).
const pane_w: f64 = 480;
const pane_h: f64 = 420;
const bar_h: f64 = 26;
const field_h: f64 = 21;
const status_h: f64 = 18;
const pad: f64 = 6;
const filter_w: f64 = 150;

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
pub const BrowserPane = struct {
    controller: *BrowserController,
    gpa: Allocator,
    role: PaneRole,
    index: u32,
    /// item_mod.local_site_id (0) for the local pane; the connected site id
    /// for a bound remote pane; null while the remote pane is unbound.
    site: ?u64,

    // Views (created in buildChrome; container/fields are rc-1 owned here).
    container: objc.Object = undefined,
    path_field: objc.Object = undefined,
    filter_field: objc.Object = undefined,
    status_label: objc.Object = undefined,
    field_target: objc.Object = undefined,
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

    // Pending-alpha bookkeeping (avoid walking rows when nothing pending).
    had_pending_alpha: bool = false,

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
        return @as(bridge.PaneToken, pane.index) + 1;
    }

    pub fn currentPath(pane: *const BrowserPane) ?[]const u8 {
        return pane.history.current();
    }

    // ------------------------------------------------------------------ //
    // Navigation

    pub fn navigateTo(pane: *BrowserPane, raw: []const u8, mode: NavMode) void {
        const site = pane.site orelse {
            pane.updateStatus();
            return;
        };
        const gpa = pane.gpa;
        const core = pane.controller.core;
        const norm = path_mod.normalize(gpa, raw) catch {
            panels.presentErrorSheet(pane.controller.win, "Invalid path", raw);
            return;
        };
        if (pane.pending_request) |req| _ = core.cancelListing(req);
        if (pane.loading_path) |lp| gpa.free(lp);
        pane.loading_path = norm;
        pane.record_history = mode == .push;
        pane.listing_count = 0;
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
        const target = pane.history.goBack(pane.gpa) orelse return;
        pane.navigateTo(target, .replace);
    }

    pub fn goForward(pane: *BrowserPane) void {
        const target = pane.history.goForward(pane.gpa) orelse return;
        pane.navigateTo(target, .replace);
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
        if (snap.entries[slot].kind != .dir) return; // M2: descend dirs only
        const name = pane.overlay.displayName(snap.entries, slot);
        const target = path_mod.join(pane.gpa, snap.path, name) catch return;
        defer pane.gpa.free(target);
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

        if (d.failure) |failure| {
            if (!expected) return; // background re-list failed; stay on truth
            pane.pending_request = null;
            if (pane.loading_path) |lp| {
                pane.gpa.free(lp);
                pane.loading_path = null;
            }
            pane.updatePathBar();
            pane.updateStatus();
            if (failure.class != .cancel)
                panels.presentErrorSheet(pane.controller.win, "Couldn't open folder", failure.message);
            return;
        }

        const snap = d.snapshot.?;
        if (expected) {
            pane.pending_request = null;
            if (pane.loading_path) |lp| {
                pane.gpa.free(lp);
                pane.loading_path = null;
            }
            pane.adoptSnapshot(snap, d.sort_index);
            if (pane.record_history or pane.history.cur == null)
                pane.history.visit(pane.gpa, snap.path) catch {};
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
        pane.rebuildVisible();
        pane.table.reloadData();
        pane.applyPendingAlpha();
        pane.updateStatus();
        pane.controller.notifySelection(pane); // slots remapped under the selection
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
        }
        chrome.setText(pane.status_label, formatStatus(&buf, model));
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
        var msg_buf: [160]u8 = undefined;
        const msg: []const u8 = if (pane.op_names.items.len == 1)
            std.fmt.bufPrint(&msg_buf, "Delete “{s}”?", .{
                pane.overlay.displayName(snap.entries, first_slot),
            }) catch "Delete 1 item?"
        else
            std.fmt.bufPrint(&msg_buf, "Delete {d} items?", .{pane.op_names.items.len}) catch "Delete items?";
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
            .chmod => {},
        }
        pane.redraw();
        const title: []const u8 = switch (d.op) {
            .mkdir => "New Folder failed",
            .rename => "Rename failed",
            .chmod => "Change Permissions failed",
            .delete => "Delete failed",
        };
        const detail: []const u8 = if (d.failure) |f| f.message else "";
        panels.presentErrorSheet(pane.controller.win, title, detail);
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
            2 => formatMtime(buf, entry.mtime),
            3 => formatMode(buf, entry.mode),
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
                '.', '>' => {
                    if (ev.shift or ch == '>') pane.toggleHidden() else pane.cancelActiveListing();
                    return true;
                },
                else => {},
            }
            return false;
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
            if (ev.chars.len > 0 and ev.chars[0] >= 0x20 and ev.chars[0] != 0x7f)
                return pane.typeSelect(ev.chars);
        }
        return false;
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

    fn dropAcceptPaneRows(ctx: *anyopaque, source_pane: u32, rows: []const u32, target: drag.DropTarget) bool {
        const pane: *BrowserPane = @ptrCast(@alignCast(ctx));
        const ctrl = pane.controller;
        if (source_pane >= ctrl.panes.len) return false;
        const src = ctrl.panes[source_pane];
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
    /// Selection feed for the inspector (docs/UX.md): fired for the FOCUSED
    /// pane on selection changes, snapshot swaps, and pane-focus switches.
    selection_hook: SelectionHook = .{},

    // Cached, retained SF Symbol images for the Name column.
    icon_folder: ?c.id = null,
    icon_file: ?c.id = null,
    icon_link: ?c.id = null,

    pub const Options = struct {
        /// Local pane start directory; null = $HOME (docs/UX.md).
        initial_local_path: ?[]const u8 = null,
        density: table_source.Density = .compact,
    };

    /// main.zig binds this to the inspector (it owns both controllers);
    /// the receiver reads the pane's selected rows/snapshot synchronously.
    pub const SelectionHook = struct {
        ctx: ?*anyopaque = null,
        notify: ?*const fn (ctx: ?*anyopaque, pane: *BrowserPane) void = null,
    };

    pub fn setSelectionHook(self: *BrowserController, hook: SelectionHook) void {
        self.selection_hook = hook;
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

    /// Tear down views + state. Listeners cannot unregister, so call this
    /// only after `AppCore.shutdown()` (no further drains), or never.
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
    // Remote-pane binding (called by the sites controller on connect)

    pub fn bindRemote(self: *BrowserController, site_id: u64, initial_path: []const u8) void {
        const pane = self.panes[1];
        pane.site = site_id;
        pane.chip = null;
        self.resetPaneListing(pane);
        pane.navigateTo(if (initial_path.len > 0) initial_path else "/", .push);
    }

    pub fn unbindRemote(self: *BrowserController) void {
        const pane = self.panes[1];
        pane.site = null;
        pane.chip = null;
        self.resetPaneListing(pane);
        pane.updatePathBar();
        pane.table.reloadData();
        pane.updateStatus();
        self.notifySelection(pane);
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
        const pane = self.panes[1];
        const site = pane.site orelse return;
        if (site != e.site_id) return;
        pane.chip = e.status;
        pane.updateStatus();
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
            .index = index,
            .site = if (role == .local) item_mod.local_site_id else null,
            .show_hidden = self.core.settings.show_hidden_files,
        };

        const columns: []const table_source.ColumnSpec =
            if (role == .remote) &remote_columns else &local_columns;
        pane.table = try table_source.TableView.init(gpa, .{
            .columns = columns,
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
            },
            .density = self.density,
            .autosave_name = if (index == 0) "RelayBrowserTableLeft" else "RelayBrowserTableRight",
        });

        buildChrome(pane);

        drag.attachDropHandler(pane.table, .{
            .ctx = pane,
            .validate = BrowserPane.dropValidate,
            .acceptFiles = BrowserPane.dropAcceptFiles,
            .acceptPaneRows = BrowserPane.dropAcceptPaneRows,
        });
        drag.enableRowDragSource(pane.table, index);

        pane.updateStatus();
        return pane;
    }

    fn buildChrome(pane: *BrowserPane) void {
        pane.container = chrome.makeView(foundation.rect(0, 0, pane_w, pane_h));

        const top_y = pane_h - bar_h + (bar_h - field_h) / 2;
        pane.path_field = chrome.makeTextField(
            foundation.rect(pad, top_y, pane_w - filter_w - 3 * pad, field_h),
            12,
        );
        chrome.setAutoresizing(pane.path_field, chrome.width_sizable | chrome.min_y_margin);
        chrome.setPlaceholder(pane.path_field, if (pane.role == .remote) "Not connected" else "Path");

        pane.filter_field = chrome.makeTextField(
            foundation.rect(pane_w - filter_w - pad, top_y, filter_w, field_h),
            12,
        );
        chrome.setAutoresizing(pane.filter_field, chrome.min_x_margin | chrome.min_y_margin);
        chrome.setPlaceholder(pane.filter_field, "Filter");
        chrome.setHidden(pane.filter_field, true);

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
        chrome.addSubview(pane.container, pane.filter_field);
        chrome.addSubview(pane.container, table_view);
        chrome.addSubview(pane.container, pane.status_label);
    }

    fn destroyPane(pane: *BrowserPane) void {
        const gpa = pane.gpa;
        chrome.clearControlWiring(pane.path_field);
        chrome.clearControlWiring(pane.filter_field);
        pane.table.deinit();
        chrome.release(pane.path_field);
        chrome.release(pane.filter_field);
        chrome.release(pane.status_label);
        chrome.release(pane.field_target);
        chrome.release(pane.container);
        if (pane.snapshot) |snap| snap.unref();
        gpa.free(pane.sort_index);
        pane.visible.deinit(gpa);
        pane.overlay.deinit(gpa);
        pane.history.deinit(gpa);
        pane.filter_buf.deinit(gpa);
        if (pane.rename_target) |name| gpa.free(name);
        for (pane.op_names.items) |name| gpa.free(name);
        pane.op_names.deinit(gpa);
        if (pane.loading_path) |lp| gpa.free(lp);
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

    // Snapshot swap clears everything at once.
    try overlay.setRename(gpa, 1, "x");
    try overlay.hide(gpa, 2);
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

    try testing.expectEqualStrings("0 B", humanBytes(&buf, 0));
    try testing.expectEqualStrings("1023 B", humanBytes(&buf, 1023));
    try testing.expectEqualStrings("1.5 KB", humanBytes(&buf, 1536));
    try testing.expectEqualStrings("1.0 MB", humanBytes(&buf, 1 << 20));
    try testing.expectEqualStrings("10 MB", humanBytes(&buf, 10 << 20));

    try testing.expectEqualStrings("—", formatSize(&buf, true, 12345));
    try testing.expectEqualStrings("", formatSize(&buf, false, null));

    // 2024-06-11 12:00:00 UTC.
    try testing.expectEqualStrings("2024-06-11 12:00", formatMtime(&buf, 1_718_107_200));
    try testing.expectEqualStrings("", formatMtime(&buf, null));
    try testing.expectEqualStrings("", formatMtime(&buf, -5));

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

    // Descend + history: back returns, forward re-descends.
    local.navigateTo("/sub", .push);
    settled = .{ .pane = local, .path = "/sub" };
    try drainUntil(core, &settled, PaneSettled.ready);
    try testing.expectEqual(@as(usize, 1), local.visible.items.len);
    try testing.expect(local.history.canGoBack());

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

test {
    std.testing.refAllDecls(@This());
}

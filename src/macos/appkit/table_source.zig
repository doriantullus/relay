//! table_source — view-based NSTableView wrapper driven by a Zig vtable.
//!
//! Generalizes src/spikes/ui_spike.zig (the M0 gate reference): one reused
//! custom-DRAWN cell view class (text + optional icon + optional flat
//! progress tint for the transfers queue), fixed row heights from a density
//! enum, makeViewWithIdentifier: reuse, header sorting, selection plumbing,
//! keyDown + context-menu hooks. ALL selector strings live here (law).
//!
//! Threading: every public method and every callback runs on the main
//! thread only.

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

// drag.zig owns the drop/drag-source vtables; TableView only stores them.
// (Cyclic file import is intentional and legal; drag.zig imports us back.)
const drag = @import("drag.zig");

// ---------------------------------------------------------------------------
// Shared AppKit ABI types + tiny helpers — single definitions live in
// relay_mac foundation.zig; re-exported here because the sibling appkit
// files (toolbar/split_view/outline_view/drag) import them via this module.
// (Deduped in M2 phase 3; previously duplicated while foundation.zig was a
// stub.)
// ---------------------------------------------------------------------------
const foundation = @import("../foundation.zig");

pub const NSInteger = foundation.NSInteger; // i64: LP64 long, encoder emits 'q'
pub const NSUInteger = foundation.NSUInteger;
pub const NSPoint = foundation.NSPoint;
pub const NSSize = foundation.NSSize;
pub const NSRect = foundation.NSRect;
pub const NSRange = foundation.NSRange;
pub const rect = foundation.rect;
pub const getClass = foundation.class;

/// NSNotFound (== NSIntegerMax) as seen through NSUInteger-returning APIs.
pub const ns_not_found: NSUInteger = @intCast(std.math.maxInt(NSInteger));

/// Autoreleased NSString from a zero-terminated UTF-8 string.
pub fn nsStr(s: [*:0]const u8) objc.Object {
    return foundation.nsStringZ(std.mem.span(s));
}

/// Autoreleased NSString from a Zig slice (no NUL needed).
pub const nsStrBytes = foundation.nsString;

/// Autoreleased NSImage for an SF Symbol name; null if the symbol is unknown.
/// Callers that cache the image must retain it.
pub fn systemSymbolImage(name: [*:0]const u8) ?c.id {
    const img = getClass("NSImage").msgSend(
        objc.Object,
        "imageWithSystemSymbolName:accessibilityDescription:",
        .{ nsStr(name), @as(c.id, null) },
    );
    return img.value;
}

// Virtual key codes (kVK_*) the app shortcuts care about.
pub const key_return: u16 = 36;
pub const key_keypad_enter: u16 = 76;
pub const key_tab: u16 = 48;
pub const key_space: u16 = 49;
pub const key_delete: u16 = 51; // backspace
pub const key_escape: u16 = 53;
pub const key_forward_delete: u16 = 117;
pub const key_down_arrow: u16 = 125;
pub const key_up_arrow: u16 = 126;

// NSEventModifierFlags bits.
pub const flag_shift: u64 = 1 << 17;
pub const flag_control: u64 = 1 << 18;
pub const flag_option: u64 = 1 << 19;
pub const flag_command: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------
pub const Alignment = enum { left, right, center };

/// Row density (View menu). Fixed row heights per docs/UX.md.
pub const Density = enum {
    comfortable,
    compact,
    dense,

    pub fn rowHeight(self: Density) f64 {
        return switch (self) {
            .comfortable => 28,
            .compact => 22,
            .dense => 18,
        };
    }

    pub fn fontSize(self: Density) f64 {
        return switch (self) {
            .comfortable => 13,
            .compact => 12,
            .dense => 11,
        };
    }

    pub fn iconSize(self: Density) f64 {
        return switch (self) {
            .comfortable => 16,
            .compact => 14,
            .dense => 12,
        };
    }
};

pub const ColumnSpec = struct {
    /// Identifier; doubles as the sort-descriptor key. Must outlive the view.
    id: [:0]const u8,
    title: [:0]const u8,
    width: f64,
    min_width: f64 = 40,
    max_width: f64 = 100_000,
    alignment: Alignment = .left,
    monospaced_digits: bool = false,
    /// When true, the cellIcon/cellProgress hooks are consulted for this
    /// column (Name column icon, queue progress bar).
    custom_draw: bool = false,
    sortable: bool = false,
};

/// One key press as seen by the keyDown hook. `chars` points at a stack
/// buffer and is only valid for the duration of the callback.
pub const KeyEvent = struct {
    key_code: u16,
    chars: []const u8,
    shift: bool = false,
    control: bool = false,
    option: bool = false,
    command: bool = false,
};

pub fn keyEventFrom(key_code: u16, modifier_flags: u64, chars: []const u8) KeyEvent {
    return .{
        .key_code = key_code,
        .chars = chars,
        .shift = modifier_flags & flag_shift != 0,
        .control = modifier_flags & flag_control != 0,
        .option = modifier_flags & flag_option != 0,
        .command = modifier_flags & flag_command != 0,
    };
}

/// The vtable the app implements. All callbacks fire on the main thread.
/// `buf`-taking callbacks write into the caller-provided buffer and return
/// the written slice (the wrapper never holds on to it past the call).
pub const DataSource = struct {
    ctx: *anyopaque,
    rowCount: *const fn (ctx: *anyopaque) usize,
    cellText: *const fn (ctx: *anyopaque, row: usize, col: usize, buf: []u8) []const u8,
    /// Optional leading icon (an NSImage the app owns/caches; see
    /// systemSymbolImage). Consulted only for custom_draw columns.
    cellIcon: ?*const fn (ctx: *anyopaque, row: usize, col: usize) ?c.id = null,
    /// Optional progress fraction in [0,1] drawn as a flat tinted rect
    /// behind the text (controlAccentColor at reduced alpha) — queue rows.
    cellProgress: ?*const fn (ctx: *anyopaque, row: usize, col: usize) ?f64 = null,
    /// Header sort clicked. The app re-sorts its permutation; the wrapper
    /// calls reloadData afterwards.
    sortChanged: ?*const fn (ctx: *anyopaque, col: usize, ascending: bool) void = null,
    /// `rows` is valid only for the duration of the callback.
    selectionChanged: ?*const fn (ctx: *anyopaque, rows: []const usize) void = null,
    doubleAction: ?*const fn (ctx: *anyopaque, row: ?usize) void = null,
    returnAction: ?*const fn (ctx: *anyopaque, row: ?usize) void = null,
    /// Return true if handled; false falls through to NSTableView's default
    /// keyDown (type-select, arrow keys, …).
    keyDown: ?*const fn (ctx: *anyopaque, ev: KeyEvent) bool = null,
    /// Return an NSMenu (built via relay_mac menu wrappers) or null.
    contextMenu: ?*const fn (ctx: *anyopaque, row: ?usize) ?c.id = null,
};

pub const Config = struct {
    columns: []const ColumnSpec,
    data_source: DataSource,
    density: Density = .compact,
    allows_multiple_selection: bool = true,
    header_visible: bool = true,
    /// NSTableView autosave name for column widths/order.
    autosave_name: ?[:0]const u8 = null,
};

// ---------------------------------------------------------------------------
// Runtime-defined classes (cached-Ivar state convention; defined once).
// ---------------------------------------------------------------------------
var g_classes_ready = false;
var g_helper_class: objc.Class = undefined; // NSObject: dataSource+delegate+actions
var g_table_class: objc.Class = undefined; // NSTableView subclass: keyDown/menu
var g_cell_class: objc.Class = undefined; // NSView subclass: custom-drawn cell
var g_helper_state_ivar: c.Ivar = null;
var g_table_state_ivar: c.Ivar = null;
var g_cell_state_ivar: c.Ivar = null;
var g_cell_row_ivar: c.Ivar = null;
var g_cell_col_ivar: c.Ivar = null;

const state_ivar_name = "relayState";

/// Recover a Zig pointer stored in an id-sized ivar (plain store; runtime
/// classes have no ARC layout).
fn stateFromIvar(comptime T: type, target: c.id, ivar: c.Ivar) *T {
    const raw = c.object_getIvar(target, ivar) orelse @panic("relay state ivar is null");
    return @ptrCast(@alignCast(raw));
}

/// Integers ride in id-sized ivars as (value+1)<<3 so the fake pointer stays
/// non-null and 8-byte aligned (Debug @ptrFromInt checks both).
pub fn indexToIvar(index: usize) c.id {
    return @ptrFromInt((index + 1) << 3);
}

pub fn indexFromIvar(raw: usize) ?usize {
    if (raw == 0) return null;
    return (raw >> 3) - 1;
}

fn readIndexIvar(target: c.id, ivar: c.Ivar) ?usize {
    return indexFromIvar(@intFromPtr(c.object_getIvar(target, ivar)));
}

/// Idempotent; must run on the main thread before the first instance.
pub fn ensureClasses() void {
    if (g_classes_ready) return;
    g_classes_ready = true;

    // Helper: NSTableViewDataSource + NSTableViewDelegate + action target.
    {
        const cls = objc.allocateClassPair(getClass("NSObject"), "RelayTableHelper") orelse
            @panic("allocateClassPair(RelayTableHelper)");
        if (!cls.addIvar(state_ivar_name)) @panic("addIvar(RelayTableHelper)");
        if (!cls.addMethod("numberOfRowsInTableView:", helperNumberOfRows))
            @panic("addMethod(numberOfRowsInTableView:)");
        if (!cls.addMethod("tableView:viewForTableColumn:row:", helperViewForColumnRow))
            @panic("addMethod(tableView:viewForTableColumn:row:)");
        if (!cls.addMethod("tableView:sortDescriptorsDidChange:", helperSortDescriptorsDidChange))
            @panic("addMethod(tableView:sortDescriptorsDidChange:)");
        if (!cls.addMethod("tableViewSelectionDidChange:", helperSelectionDidChange))
            @panic("addMethod(tableViewSelectionDidChange:)");
        if (!cls.addMethod("onRelayTableDouble:", helperOnDouble))
            @panic("addMethod(onRelayTableDouble:)");
        objc.registerClassPair(cls);
        g_helper_state_ivar = c.class_getInstanceVariable(cls.value, state_ivar_name);
        if (g_helper_state_ivar == null) @panic("ivar lookup (RelayTableHelper)");
        g_helper_class = cls;
    }

    // NSTableView subclass for keyDown + context-menu hooks.
    {
        const cls = objc.allocateClassPair(getClass("NSTableView"), "RelayTableView") orelse
            @panic("allocateClassPair(RelayTableView)");
        if (!cls.addIvar(state_ivar_name)) @panic("addIvar(RelayTableView)");
        if (!cls.addMethod("keyDown:", tableKeyDown)) @panic("addMethod(keyDown:)");
        if (!cls.addMethod("menuForEvent:", tableMenuForEvent)) @panic("addMethod(menuForEvent:)");
        objc.registerClassPair(cls);
        g_table_state_ivar = c.class_getInstanceVariable(cls.value, state_ivar_name);
        if (g_table_state_ivar == null) @panic("ivar lookup (RelayTableView)");
        g_table_class = cls;
    }

    // Custom-drawn cell view (one class for every column).
    {
        const cls = objc.allocateClassPair(getClass("NSView"), "RelayTableCellView") orelse
            @panic("allocateClassPair(RelayTableCellView)");
        if (!cls.addIvar(state_ivar_name)) @panic("addIvar(RelayTableCellView)");
        if (!cls.addIvar("relayRow")) @panic("addIvar(relayRow)");
        if (!cls.addIvar("relayCol")) @panic("addIvar(relayCol)");
        if (!cls.addMethod("drawRect:", cellDrawRect)) @panic("addMethod(drawRect:)");
        if (!cls.addMethod("isFlipped", cellIsFlipped)) @panic("addMethod(isFlipped)");
        objc.registerClassPair(cls);
        g_cell_state_ivar = c.class_getInstanceVariable(cls.value, state_ivar_name);
        g_cell_row_ivar = c.class_getInstanceVariable(cls.value, "relayRow");
        g_cell_col_ivar = c.class_getInstanceVariable(cls.value, "relayCol");
        if (g_cell_state_ivar == null or g_cell_row_ivar == null or g_cell_col_ivar == null)
            @panic("ivar lookup (RelayTableCellView)");
        g_cell_class = cls;
    }

    drag.addTableDropMethods(g_helper_class);
}

/// Exposed for tests and for drag.zig.
pub fn helperClass() objc.Class {
    ensureClasses();
    return g_helper_class;
}

pub fn helperStateIvar() c.Ivar {
    return g_helper_state_ivar;
}

pub fn columnIndexForId(columns: []const ColumnSpec, id: []const u8) ?usize {
    for (columns, 0..) |col, i| {
        if (std.mem.eql(u8, col.id, id)) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// TableView
// ---------------------------------------------------------------------------
pub const TableView = struct {
    alloc: std.mem.Allocator,
    columns: []ColumnSpec,
    ds: DataSource,
    density: Density,
    scroll: objc.Object,
    table: objc.Object,
    helper: objc.Object,
    sel_buf: std.ArrayList(usize) = .empty,
    /// Font hook: true renders EVERY cell in the monospaced system font
    /// (Settings → "Monospaced file lists"); false keeps the per-column
    /// system / monospaced-digit fonts.
    monospaced: bool = false,
    /// Set by drag.attachDropHandler / drag.enableRowDragSource.
    drop: ?drag.DropHandler = null,
    drag_pane_id: ?u32 = null,
    // Reuse telemetry (main-thread only; smoke/tests assert on these).
    made_views: u64 = 0,
    reuse_hits: u64 = 0,

    pub fn init(alloc: std.mem.Allocator, config: Config) !*TableView {
        ensureClasses();

        const self = try alloc.create(TableView);
        errdefer alloc.destroy(self);
        const columns = try alloc.dupe(ColumnSpec, config.columns);
        errdefer alloc.free(columns);

        self.* = .{
            .alloc = alloc,
            .columns = columns,
            .ds = config.data_source,
            .density = config.density,
            .scroll = undefined,
            .table = undefined,
            .helper = undefined,
        };

        const table = g_table_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 400, 300)});
        c.object_setIvar(table.value, g_table_state_ivar, @ptrCast(self));
        table.msgSend(void, "setRowHeight:", .{config.density.rowHeight()});
        table.msgSend(void, "setUsesAutomaticRowHeights:", .{false});
        table.msgSend(void, "setAllowsMultipleSelection:", .{config.allows_multiple_selection});
        table.msgSend(void, "setAllowsColumnReordering:", .{false});
        self.table = table;

        for (columns) |spec| {
            const col = getClass("NSTableColumn").msgSend(objc.Object, "alloc", .{})
                .msgSend(objc.Object, "initWithIdentifier:", .{nsStr(spec.id.ptr)});
            col.msgSend(void, "setTitle:", .{nsStr(spec.title.ptr)});
            col.msgSend(void, "setWidth:", .{spec.width});
            col.msgSend(void, "setMinWidth:", .{spec.min_width});
            col.msgSend(void, "setMaxWidth:", .{spec.max_width});
            if (spec.sortable) {
                const proto = getClass("NSSortDescriptor").msgSend(
                    objc.Object,
                    "sortDescriptorWithKey:ascending:",
                    .{ nsStr(spec.id.ptr), true },
                );
                col.msgSend(void, "setSortDescriptorPrototype:", .{proto});
            }
            table.msgSend(void, "addTableColumn:", .{col});
            col.msgSend(void, "release", .{});
        }

        if (!config.header_visible)
            table.msgSend(void, "setHeaderView:", .{@as(c.id, null)});
        if (config.autosave_name) |name| {
            table.msgSend(void, "setAutosaveName:", .{nsStr(name.ptr)});
            table.msgSend(void, "setAutosaveTableColumns:", .{true});
        }

        const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});
        c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(self));
        self.helper = helper;

        // Delegate before dataSource: NSTableView probes respondsToSelector:
        // at set time to decide it is a view-based table (docs/spikes/ui.md).
        table.msgSend(void, "setDelegate:", .{helper});
        table.msgSend(void, "setDataSource:", .{helper});
        table.msgSend(void, "setTarget:", .{helper});
        table.msgSend(void, "setDoubleAction:", .{objc.sel("onRelayTableDouble:")});

        const scroll = getClass("NSScrollView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 400, 300)});
        scroll.msgSend(void, "setHasVerticalScroller:", .{true});
        scroll.msgSend(void, "setAutohidesScrollers:", .{true});
        scroll.msgSend(void, "setDocumentView:", .{table});
        self.scroll = scroll;

        return self;
    }

    pub fn deinit(self: *TableView) void {
        self.table.msgSend(void, "setDelegate:", .{@as(c.id, null)});
        self.table.msgSend(void, "setDataSource:", .{@as(c.id, null)});
        self.table.msgSend(void, "setTarget:", .{@as(c.id, null)});
        self.scroll.msgSend(void, "release", .{});
        self.table.msgSend(void, "release", .{});
        self.helper.msgSend(void, "release", .{});
        self.sel_buf.deinit(self.alloc);
        self.alloc.free(self.columns);
        self.alloc.destroy(self);
    }

    /// The view to embed (the NSScrollView wrapping the table).
    pub fn view(self: *TableView) c.id {
        return self.scroll.value;
    }

    pub fn reloadData(self: *TableView) void {
        self.table.msgSend(void, "reloadData", .{});
    }

    pub fn noteNumberOfRowsChanged(self: *TableView) void {
        self.table.msgSend(void, "noteNumberOfRowsChanged", .{});
    }

    /// Redraw `len` rows starting at `start` (all columns).
    pub fn reloadRange(self: *TableView, start: usize, len: usize) void {
        const rows = getClass("NSIndexSet").msgSend(
            objc.Object,
            "indexSetWithIndexesInRange:",
            .{NSRange{ .location = start, .length = len }},
        );
        const cols = getClass("NSIndexSet").msgSend(
            objc.Object,
            "indexSetWithIndexesInRange:",
            .{NSRange{ .location = 0, .length = self.columns.len }},
        );
        self.table.msgSend(void, "reloadDataForRowIndexes:columnIndexes:", .{ rows, cols });
    }

    pub fn scrollRowToVisible(self: *TableView, row: usize) void {
        self.table.msgSend(void, "scrollRowToVisible:", .{@as(NSInteger, @intCast(row))});
    }

    pub fn setDensity(self: *TableView, density: Density) void {
        self.density = density;
        self.table.msgSend(void, "setRowHeight:", .{density.rowHeight()});
        self.reloadData();
    }

    /// Minimal font hook (Settings → "Monospaced file lists").
    pub fn setMonospaced(self: *TableView, monospaced: bool) void {
        if (self.monospaced == monospaced) return;
        self.monospaced = monospaced;
        self.reloadData();
    }

    /// Show/hide a column by identifier (pane role swaps: the Permissions
    /// column appears only while a pane hosts a remote site).
    pub fn setColumnHidden(self: *TableView, id: [:0]const u8, hidden: bool) void {
        const col = self.table.msgSend(c.id, "tableColumnWithIdentifier:", .{nsStr(id.ptr)});
        if (col) |column| objc.Object.fromId(column).msgSend(void, "setHidden:", .{hidden});
    }

    /// Selected row indexes, ascending. The slice is owned by the TableView
    /// scratch buffer and valid until the next selection query/callback.
    pub fn selectedRows(self: *TableView) []const usize {
        const set = self.table.msgSend(objc.Object, "selectedRowIndexes", .{});
        collectIndexSet(set, &self.sel_buf, self.alloc);
        return self.sel_buf.items;
    }

    /// Single selected row (the table's anchor row; null when empty).
    pub fn selectedRow(self: *TableView) ?usize {
        const row = self.table.msgSend(NSInteger, "selectedRow", .{});
        if (row < 0) return null;
        return @intCast(row);
    }

    pub fn setSelectedRows(self: *TableView, rows: []const usize) void {
        if (rows.len == 0) {
            self.table.msgSend(void, "deselectAll:", .{@as(c.id, null)});
            return;
        }
        const set = getClass("NSMutableIndexSet").msgSend(objc.Object, "indexSet", .{});
        for (rows) |row| set.msgSend(void, "addIndex:", .{@as(NSUInteger, row)});
        self.table.msgSend(void, "selectRowIndexes:byExtendingSelection:", .{ set, false });
    }

    /// Raw NSTableView handle for sibling wrappers (drag.zig).
    pub fn tableHandle(self: *TableView) c.id {
        return self.table.value;
    }
};

fn collectIndexSet(
    set: objc.Object,
    buf: *std.ArrayList(usize),
    alloc: std.mem.Allocator,
) void {
    buf.clearRetainingCapacity();
    var idx = set.msgSend(NSUInteger, "firstIndex", .{});
    while (idx != ns_not_found) : (idx = set.msgSend(NSUInteger, "indexGreaterThanIndex:", .{idx})) {
        buf.append(alloc, @intCast(idx)) catch return;
    }
}

// ---------------------------------------------------------------------------
// Helper class IMPs (dataSource / delegate / action target)
// ---------------------------------------------------------------------------
fn helperNumberOfRows(target: c.id, _: c.SEL, _: c.id) callconv(.c) NSInteger {
    const tv = stateFromIvar(TableView, target, g_helper_state_ivar);
    return @intCast(tv.ds.rowCount(tv.ds.ctx));
}

fn helperViewForColumnRow(
    target: c.id,
    _: c.SEL,
    _: c.id,
    column_id: c.id,
    row: NSInteger,
) callconv(.c) c.id {
    const tv = stateFromIvar(TableView, target, g_helper_state_ivar);

    // Pool + the retain/pop/autorelease dance for the returned view
    // (docs/spikes/ui.md, returning autoreleased objects across pools).
    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const column = objc.Object.fromId(column_id);
        const ident = column.msgSend(objc.Object, "identifier", .{});
        const ident_s = std.mem.span(ident.msgSend([*:0]const u8, "UTF8String", .{}));
        const col = columnIndexForId(tv.columns, ident_s) orelse {
            pool.deinit();
            return null;
        };

        var view = tv.table.msgSend(c.id, "makeViewWithIdentifier:owner:", .{
            ident, @as(c.id, null),
        });
        if (view == null) {
            tv.made_views += 1;
            const v = g_cell_class.msgSend(objc.Object, "alloc", .{})
                .msgSend(objc.Object, "initWithFrame:", .{
                rect(0, 0, tv.columns[col].width, tv.density.rowHeight()),
            });
            // Hand the alloc/init +1 to the inner pool so both branches
            // transfer exactly one reference through the dance below.
            _ = v.msgSend(c.id, "autorelease", .{});
            v.msgSend(void, "setIdentifier:", .{ident});
            c.object_setIvar(v.value, g_cell_state_ivar, @ptrCast(tv));
            view = v.value;
        } else {
            tv.reuse_hits += 1;
        }
        c.object_setIvar(view, g_cell_row_ivar, indexToIvar(@intCast(row)));
        c.object_setIvar(view, g_cell_col_ivar, indexToIvar(col));
        objc.Object.fromId(view).msgSend(void, "setNeedsDisplay:", .{true});
        result = view;
    }
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

fn helperSortDescriptorsDidChange(target: c.id, _: c.SEL, table_id: c.id, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = stateFromIvar(TableView, target, g_helper_state_ivar);
    const cb = tv.ds.sortChanged orelse return;

    const table = objc.Object.fromId(table_id);
    const descs = table.msgSend(objc.Object, "sortDescriptors", .{});
    if (descs.msgSend(NSUInteger, "count", .{}) == 0) return;
    const first = descs.msgSend(objc.Object, "objectAtIndex:", .{@as(NSUInteger, 0)});
    const key = first.msgSend(objc.Object, "key", .{});
    const key_s = std.mem.span(key.msgSend([*:0]const u8, "UTF8String", .{}));
    const col = columnIndexForId(tv.columns, key_s) orelse return;
    const ascending = first.msgSend(c.BOOL, "ascending", .{}) != 0;

    cb(tv.ds.ctx, col, ascending);
    table.msgSend(void, "reloadData", .{});
}

fn helperSelectionDidChange(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = stateFromIvar(TableView, target, g_helper_state_ivar);
    const cb = tv.ds.selectionChanged orelse return;
    const set = tv.table.msgSend(objc.Object, "selectedRowIndexes", .{});
    collectIndexSet(set, &tv.sel_buf, tv.alloc);
    cb(tv.ds.ctx, tv.sel_buf.items);
}

fn helperOnDouble(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = stateFromIvar(TableView, target, g_helper_state_ivar);
    const cb = tv.ds.doubleAction orelse return;
    const clicked = tv.table.msgSend(NSInteger, "clickedRow", .{});
    cb(tv.ds.ctx, if (clicked < 0) null else @intCast(clicked));
}

// ---------------------------------------------------------------------------
// RelayTableView IMPs (keyDown hook + context menu)
// ---------------------------------------------------------------------------
fn tableKeyDown(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = stateFromIvar(TableView, target, g_table_state_ivar);
    const event = objc.Object.fromId(event_id);
    const key_code: u16 = event.msgSend(c_ushort, "keyCode", .{});
    const flags = event.msgSend(NSUInteger, "modifierFlags", .{});

    var chars_buf: [16]u8 = undefined;
    var chars: []const u8 = chars_buf[0..0];
    const chars_ns = event.msgSend(c.id, "characters", .{});
    if (chars_ns != null) {
        const utf8 = objc.Object.fromId(chars_ns).msgSend([*:0]const u8, "UTF8String", .{});
        const span = std.mem.span(utf8);
        const n = @min(span.len, chars_buf.len);
        @memcpy(chars_buf[0..n], span[0..n]);
        chars = chars_buf[0..n];
    }

    const ev = keyEventFrom(key_code, flags, chars);
    var handled = false;
    if (tv.ds.keyDown) |hook| handled = hook(tv.ds.ctx, ev);

    if (!handled and (key_code == key_return or key_code == key_keypad_enter) and
        !ev.command and !ev.control and !ev.option)
    {
        if (tv.ds.returnAction) |cb| {
            cb(tv.ds.ctx, tv.selectedRow());
            handled = true;
        }
    }

    if (!handled) {
        // Pass through to NSTableView for type-select, arrows, page keys.
        objc.Object.fromId(target).msgSendSuper(
            getClass("NSTableView"),
            void,
            "keyDown:",
            .{event_id},
        );
    }
}

fn tableMenuForEvent(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) c.id {
    const tv = stateFromIvar(TableView, target, g_table_state_ivar);
    const hook = tv.ds.contextMenu orelse {
        return objc.Object.fromId(target).msgSendSuper(
            getClass("NSTableView"),
            c.id,
            "menuForEvent:",
            .{event_id},
        );
    };

    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const event = objc.Object.fromId(event_id);
        const table = objc.Object.fromId(target);
        const loc = event.msgSend(NSPoint, "locationInWindow", .{});
        const point = table.msgSend(NSPoint, "convertPoint:fromView:", .{ loc, @as(c.id, null) });
        const row = table.msgSend(NSInteger, "rowAtPoint:", .{point});

        // Finder parity: right-clicking an unselected row selects it first.
        if (row >= 0 and table.msgSend(c.BOOL, "isRowSelected:", .{row}) == 0) {
            const set = getClass("NSIndexSet").msgSend(
                objc.Object,
                "indexSetWithIndex:",
                .{@as(NSUInteger, @intCast(row))},
            );
            table.msgSend(void, "selectRowIndexes:byExtendingSelection:", .{ set, false });
        }
        result = hook(tv.ds.ctx, if (row < 0) null else @intCast(row)) orelse null;
    }
    if (result) |m| _ = objc.Object.fromId(m).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |m| _ = objc.Object.fromId(m).msgSend(c.id, "autorelease", .{});
    return result;
}

// ---------------------------------------------------------------------------
// RelayTableCellView IMPs (custom drawing)
// ---------------------------------------------------------------------------
fn cellIsFlipped(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1;
}

const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });

const h_pad: f64 = 8;
const icon_text_gap: f64 = 6;
const compositing_source_over: NSUInteger = 2;

fn cellDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = stateFromIvar(TableView, target, g_cell_state_ivar);
    const row = readIndexIvar(target, g_cell_row_ivar) orelse return;
    const col = readIndexIvar(target, g_cell_col_ivar) orelse return;
    if (col >= tv.columns.len) return;
    if (row >= tv.ds.rowCount(tv.ds.ctx)) return; // stale cell during shrink
    const spec = &tv.columns[col];

    const self = objc.Object.fromId(target);
    const bounds = self.msgSend(NSRect, "bounds", .{});

    // Queue progress: flat tinted rect behind the text, accent at low alpha.
    if (spec.custom_draw) {
        if (tv.ds.cellProgress) |progress_fn| {
            if (progress_fn(tv.ds.ctx, row, col)) |fraction| {
                const f = std.math.clamp(fraction, 0.0, 1.0);
                const tint = getClass("NSColor")
                    .msgSend(objc.Object, "controlAccentColor", .{})
                    .msgSend(objc.Object, "colorWithAlphaComponent:", .{@as(f64, 0.25)});
                tint.msgSend(void, "setFill", .{});
                const bar = rect(0, 1, bounds.size.width * f, bounds.size.height - 2);
                getClass("NSBezierPath")
                    .msgSend(objc.Object, "bezierPathWithRect:", .{bar})
                    .msgSend(void, "fill", .{});
            }
        }
    }

    var text_x: f64 = h_pad;

    // Leading icon (NSImage owned by the app, e.g. systemSymbolImage).
    if (spec.custom_draw) {
        if (tv.ds.cellIcon) |icon_fn| {
            if (icon_fn(tv.ds.ctx, row, col)) |img_id| {
                const edge = tv.density.iconSize();
                const icon_rect = rect(text_x, (bounds.size.height - edge) / 2, edge, edge);
                objc.Object.fromId(img_id).msgSend(
                    void,
                    "drawInRect:fromRect:operation:fraction:respectFlipped:hints:",
                    .{
                        icon_rect,
                        rect(0, 0, 0, 0),
                        compositing_source_over,
                        @as(f64, 1.0),
                        true,
                        @as(c.id, null),
                    },
                );
                text_x += edge + icon_text_gap;
            }
        }
    }

    // Text via the vtable, drawn with semantic colors only.
    var buf: [512]u8 = undefined;
    const text = tv.ds.cellText(tv.ds.ctx, row, col, &buf);
    if (text.len == 0) return;
    const str = nsStrBytes(text);

    const font = if (tv.monospaced)
        getClass("NSFont").msgSend(objc.Object, "monospacedSystemFontOfSize:weight:", .{
            tv.density.fontSize(), @as(f64, 0.0),
        })
    else if (spec.monospaced_digits)
        getClass("NSFont").msgSend(objc.Object, "monospacedDigitSystemFontOfSize:weight:", .{
            tv.density.fontSize(), @as(f64, 0.0),
        })
    else
        getClass("NSFont").msgSend(objc.Object, "systemFontOfSize:", .{tv.density.fontSize()});

    const color = textColorForCell(self);
    const attrs = getClass("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
    attrs.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ color.value, NSForegroundColorAttributeName.* });

    const size = str.msgSend(NSSize, "sizeWithAttributes:", .{attrs});
    const x = switch (spec.alignment) {
        .left => text_x,
        .right => @max(text_x, bounds.size.width - h_pad - size.width),
        .center => @max(text_x, (bounds.size.width - size.width) / 2),
    };
    const y = (bounds.size.height - size.height) / 2;
    str.msgSend(void, "drawAtPoint:withAttributes:", .{ NSPoint{ .x = x, .y = y }, attrs });
}

/// labelColor normally; alternateSelectedControlTextColor when the enclosing
/// row is selected with the emphasized (accent) highlight. Semantic only.
fn textColorForCell(cell: objc.Object) objc.Object {
    const row_view = cell.msgSend(objc.Object, "superview", .{});
    if (row_view.value != null) {
        const responds = row_view.msgSend(c.BOOL, "respondsToSelector:", .{objc.sel("isSelected")});
        if (responds != 0) {
            const selected = row_view.msgSend(c.BOOL, "isSelected", .{}) != 0;
            const emphasized = row_view.msgSend(c.BOOL, "isEmphasized", .{}) != 0;
            if (selected and emphasized)
                return getClass("NSColor").msgSend(objc.Object, "alternateSelectedControlTextColor", .{});
        }
    }
    return getClass("NSColor").msgSend(objc.Object, "labelColor", .{});
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
test "density math" {
    try std.testing.expectEqual(@as(f64, 28), Density.comfortable.rowHeight());
    try std.testing.expectEqual(@as(f64, 22), Density.compact.rowHeight());
    try std.testing.expectEqual(@as(f64, 18), Density.dense.rowHeight());
    try std.testing.expect(Density.dense.fontSize() < Density.comfortable.fontSize());
}

test "column index lookup" {
    const cols = [_]ColumnSpec{
        .{ .id = "name", .title = "Name", .width = 300 },
        .{ .id = "size", .title = "Size", .width = 100 },
    };
    try std.testing.expectEqual(@as(?usize, 0), columnIndexForId(&cols, "name"));
    try std.testing.expectEqual(@as(?usize, 1), columnIndexForId(&cols, "size"));
    try std.testing.expectEqual(@as(?usize, null), columnIndexForId(&cols, "modified"));
}

test "index ivar smuggling round-trip" {
    try std.testing.expectEqual(@as(?usize, 0), indexFromIvar(@intFromPtr(indexToIvar(0))));
    try std.testing.expectEqual(@as(?usize, 41), indexFromIvar(@intFromPtr(indexToIvar(41))));
    try std.testing.expectEqual(@as(?usize, null), indexFromIvar(0));
}

test "key event modifier decode" {
    const ev = keyEventFrom(key_return, flag_command | flag_shift, "x");
    try std.testing.expect(ev.command and ev.shift and !ev.option and !ev.control);
    try std.testing.expectEqual(key_return, ev.key_code);
    try std.testing.expectEqualStrings("x", ev.chars);
}

test "nsStr round-trips" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const s = nsStr("relay-table");
    const back = std.mem.span(s.msgSend([*:0]const u8, "UTF8String", .{}));
    try std.testing.expectEqualStrings("relay-table", back);
    const s2 = nsStrBytes("relay"[0..5]);
    const back2 = std.mem.span(s2.msgSend([*:0]const u8, "UTF8String", .{}));
    try std.testing.expectEqualStrings("relay", back2);
}

test "vtable plumbing through ObjC dispatch (headless, no NSTableView)" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    ensureClasses();

    const Fake = struct {
        rows: usize,
        fn rowCount(ctx: *anyopaque) usize {
            const fake: *@This() = @ptrCast(@alignCast(ctx));
            return fake.rows;
        }
        fn cellText(_: *anyopaque, _: usize, _: usize, buf: []u8) []const u8 {
            return std.fmt.bufPrint(buf, "x", .{}) catch unreachable;
        }
    };
    var fake = Fake{ .rows = 4242 };

    var tv: TableView = undefined;
    tv.ds = .{ .ctx = &fake, .rowCount = Fake.rowCount, .cellText = Fake.cellText };

    const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    defer helper.msgSend(void, "release", .{});
    c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(&tv));

    // Real objc_msgSend dispatch into the Zig IMP.
    const n = helper.msgSend(NSInteger, "numberOfRowsInTableView:", .{@as(c.id, null)});
    try std.testing.expectEqual(@as(NSInteger, 4242), n);
}

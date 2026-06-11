//! outline_view — source-list sidebar wrapper (NSOutlineView) driven by a
//! Zig vtable: non-selectable section headers + rows with SF Symbol icon,
//! title, and optional badge count. Single selection. Custom-drawn cells
//! (law: no per-row subview stacks).
//!
//! Item identity: NSOutlineView keys its internal state on the item pointers
//! the data source hands out, so each visible section/row gets a tiny
//! retained RelayOutlineItem (NSObject subclass) holding section/row indexes
//! in smuggled-integer ivars. Rebuilt items are parked in a graveyard until
//! deinit so AppKit never sees a dangling item mid-reload (sidebar scale:
//! tens of rows, the cost is irrelevant).
//!
//! Main thread only. All selector strings live in relay_mac (law).

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

// Shared ABI helpers: single definitions live in relay_mac foundation.zig,
// re-exported through table_source.zig (deduped in M2 phase 3).
const ts = @import("table_source.zig");
const NSInteger = ts.NSInteger;
const NSUInteger = ts.NSUInteger;
const NSPoint = ts.NSPoint;
const NSSize = ts.NSSize;
const NSRect = ts.NSRect;
const rect = ts.rect;
const getClass = ts.getClass;
const nsStr = ts.nsStr;
const nsStrBytes = ts.nsStrBytes;

pub const SectionRow = struct { section: usize, row: usize };

/// One sidebar row as produced by the vtable. `title` points into the
/// caller-provided buffer and is only read during the call.
pub const Item = struct {
    title: []const u8,
    /// SF Symbol name (NSImage(systemSymbolName:)); null for no icon.
    symbol: ?[*:0]const u8 = null,
    badge: ?u64 = null,
};

/// The vtable the app implements. All callbacks fire on the main thread.
pub const DataSource = struct {
    ctx: *anyopaque,
    sectionCount: *const fn (ctx: *anyopaque) usize,
    sectionTitle: *const fn (ctx: *anyopaque, section: usize, buf: []u8) []const u8,
    rowCount: *const fn (ctx: *anyopaque, section: usize) usize,
    rowItem: *const fn (ctx: *anyopaque, section: usize, row: usize, buf: []u8) Item,
    /// null = selection cleared.
    selectionChanged: ?*const fn (ctx: *anyopaque, selected: ?SectionRow) void = null,
    doubleAction: ?*const fn (ctx: *anyopaque, item: SectionRow) void = null,
    returnAction: ?*const fn (ctx: *anyopaque, item: SectionRow) void = null,
    /// Return an NSMenu (built via relay_mac menu wrappers) or null.
    contextMenu: ?*const fn (ctx: *anyopaque, item: ?SectionRow) ?c.id = null,
};

pub const Config = struct {
    data_source: DataSource,
    row_height: f64 = 24,
    /// NSOutlineView autosave name (expansion state is app policy; M2 keeps
    /// everything expanded).
    autosave_name: ?[:0]const u8 = null,
};

// ---------------------------------------------------------------------------
// Item ivar encoding: one id-sized ivar packs (section, row|header) as
// ((section+1) << 20 | (row+1)) << 3 — non-null, 8-byte aligned, row==0
// meaning "section header". Pure fns, unit-tested headless.
// ---------------------------------------------------------------------------
const section_shift: usize = 20;
const max_rows_per_section = (1 << section_shift) - 2;

pub const ItemRef = union(enum) {
    header: usize, // section index
    row: SectionRow,
};

pub fn itemRefToIvar(ref: ItemRef) usize {
    return switch (ref) {
        .header => |s| ((s + 1) << section_shift) << 3,
        .row => |sr| (((sr.section + 1) << section_shift) | (sr.row + 1)) << 3,
    };
}

pub fn itemRefFromIvar(raw: usize) ?ItemRef {
    if (raw == 0) return null;
    const v = raw >> 3;
    const section = (v >> section_shift) - 1;
    const row_plus1 = v & ((1 << section_shift) - 1);
    if (row_plus1 == 0) return .{ .header = section };
    return .{ .row = .{ .section = section, .row = row_plus1 - 1 } };
}

// ---------------------------------------------------------------------------
// Runtime classes
// ---------------------------------------------------------------------------
var g_classes_ready = false;
var g_item_class: objc.Class = undefined; // NSObject: identity token
var g_helper_class: objc.Class = undefined; // NSObject: dataSource+delegate
var g_outline_class: objc.Class = undefined; // NSOutlineView: keyDown/menu
var g_cell_class: objc.Class = undefined; // NSView: custom-drawn cell
var g_item_ref_ivar: c.Ivar = null;
var g_helper_state_ivar: c.Ivar = null;
var g_outline_state_ivar: c.Ivar = null;
var g_cell_state_ivar: c.Ivar = null;
var g_cell_ref_ivar: c.Ivar = null;

fn stateFromIvar(comptime T: type, target: c.id, ivar: c.Ivar) *T {
    const raw = c.object_getIvar(target, ivar) orelse @panic("relay outline state ivar is null");
    return @ptrCast(@alignCast(raw));
}

pub fn ensureClasses() void {
    if (g_classes_ready) return;
    g_classes_ready = true;

    {
        const cls = objc.allocateClassPair(getClass("NSObject"), "RelayOutlineItem") orelse
            @panic("allocateClassPair(RelayOutlineItem)");
        if (!cls.addIvar("relayItemRef")) @panic("addIvar(relayItemRef)");
        objc.registerClassPair(cls);
        g_item_ref_ivar = c.class_getInstanceVariable(cls.value, "relayItemRef");
        if (g_item_ref_ivar == null) @panic("ivar lookup (RelayOutlineItem)");
        g_item_class = cls;
    }

    {
        const cls = objc.allocateClassPair(getClass("NSObject"), "RelayOutlineHelper") orelse
            @panic("allocateClassPair(RelayOutlineHelper)");
        if (!cls.addIvar("relayState")) @panic("addIvar(RelayOutlineHelper)");
        if (!cls.addMethod("outlineView:numberOfChildrenOfItem:", helperNumberOfChildren))
            @panic("addMethod(outlineView:numberOfChildrenOfItem:)");
        if (!cls.addMethod("outlineView:isItemExpandable:", helperIsExpandable))
            @panic("addMethod(outlineView:isItemExpandable:)");
        if (!cls.addMethod("outlineView:child:ofItem:", helperChildOfItem))
            @panic("addMethod(outlineView:child:ofItem:)");
        if (!cls.addMethod("outlineView:viewForTableColumn:item:", helperViewForItem))
            @panic("addMethod(outlineView:viewForTableColumn:item:)");
        if (!cls.addMethod("outlineView:isGroupItem:", helperIsGroupItem))
            @panic("addMethod(outlineView:isGroupItem:)");
        if (!cls.addMethod("outlineView:shouldSelectItem:", helperShouldSelectItem))
            @panic("addMethod(outlineView:shouldSelectItem:)");
        if (!cls.addMethod("outlineViewSelectionDidChange:", helperSelectionDidChange))
            @panic("addMethod(outlineViewSelectionDidChange:)");
        if (!cls.addMethod("onRelayOutlineDouble:", helperOnDouble))
            @panic("addMethod(onRelayOutlineDouble:)");
        objc.registerClassPair(cls);
        g_helper_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
        if (g_helper_state_ivar == null) @panic("ivar lookup (RelayOutlineHelper)");
        g_helper_class = cls;
    }

    {
        const cls = objc.allocateClassPair(getClass("NSOutlineView"), "RelayOutlineView") orelse
            @panic("allocateClassPair(RelayOutlineView)");
        if (!cls.addIvar("relayState")) @panic("addIvar(RelayOutlineView)");
        if (!cls.addMethod("keyDown:", outlineKeyDown)) @panic("addMethod(outline keyDown:)");
        if (!cls.addMethod("menuForEvent:", outlineMenuForEvent))
            @panic("addMethod(outline menuForEvent:)");
        objc.registerClassPair(cls);
        g_outline_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
        if (g_outline_state_ivar == null) @panic("ivar lookup (RelayOutlineView)");
        g_outline_class = cls;
    }

    {
        const cls = objc.allocateClassPair(getClass("NSView"), "RelayOutlineCellView") orelse
            @panic("allocateClassPair(RelayOutlineCellView)");
        if (!cls.addIvar("relayState")) @panic("addIvar(RelayOutlineCellView)");
        if (!cls.addIvar("relayItemRef")) @panic("addIvar(cell relayItemRef)");
        if (!cls.addMethod("drawRect:", cellDrawRect)) @panic("addMethod(outline drawRect:)");
        if (!cls.addMethod("isFlipped", cellIsFlipped)) @panic("addMethod(outline isFlipped)");
        objc.registerClassPair(cls);
        g_cell_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
        g_cell_ref_ivar = c.class_getInstanceVariable(cls.value, "relayItemRef");
        if (g_cell_state_ivar == null or g_cell_ref_ivar == null)
            @panic("ivar lookup (RelayOutlineCellView)");
        g_cell_class = cls;
    }
}

// ---------------------------------------------------------------------------
// OutlineView
// ---------------------------------------------------------------------------
pub const OutlineView = struct {
    alloc: std.mem.Allocator,
    ds: DataSource,
    row_height: f64,
    scroll: objc.Object,
    outline: objc.Object,
    helper: objc.Object,
    /// section_items[s] is the header token; row_items[s][r] the row tokens.
    section_items: std.ArrayList(c.id) = .empty,
    row_items: std.ArrayList(std.ArrayList(c.id)) = .empty,
    /// Replaced tokens, released at deinit (see header comment).
    graveyard: std.ArrayList(c.id) = .empty,
    /// SF Symbol image cache: symbol name -> retained, tinted NSImage.
    symbol_cache: std.StringHashMap(c.id),

    pub fn init(alloc: std.mem.Allocator, config: Config) !*OutlineView {
        ensureClasses();

        const self = try alloc.create(OutlineView);
        errdefer alloc.destroy(self);
        self.* = .{
            .alloc = alloc,
            .ds = config.data_source,
            .row_height = config.row_height,
            .scroll = undefined,
            .outline = undefined,
            .helper = undefined,
            .symbol_cache = .init(alloc),
        };

        const outline = g_outline_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 220, 400)});
        c.object_setIvar(outline.value, g_outline_state_ivar, @ptrCast(self));
        outline.msgSend(void, "setRowHeight:", .{config.row_height});
        outline.msgSend(void, "setUsesAutomaticRowHeights:", .{false});
        outline.msgSend(void, "setAllowsMultipleSelection:", .{false});
        outline.msgSend(void, "setAllowsEmptySelection:", .{true});
        outline.msgSend(void, "setHeaderView:", .{@as(c.id, null)});
        outline.msgSend(void, "setFloatsGroupRows:", .{false});
        outline.msgSend(void, "setIndentationPerLevel:", .{@as(f64, 4)});
        if (config.autosave_name) |name|
            outline.msgSend(void, "setAutosaveName:", .{nsStr(name.ptr)});
        self.outline = outline;

        const col = getClass("NSTableColumn").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithIdentifier:", .{nsStr("RelaySidebarColumn")});
        col.msgSend(void, "setWidth:", .{@as(f64, 200)});
        outline.msgSend(void, "addTableColumn:", .{col});
        outline.msgSend(void, "setOutlineTableColumn:", .{col});
        col.msgSend(void, "release", .{});

        const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});
        c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(self));
        self.helper = helper;

        // Delegate first (view-based detection), then data source.
        outline.msgSend(void, "setDelegate:", .{helper});
        outline.msgSend(void, "setDataSource:", .{helper});
        outline.msgSend(void, "setTarget:", .{helper});
        outline.msgSend(void, "setDoubleAction:", .{objc.sel("onRelayOutlineDouble:")});

        const scroll = getClass("NSScrollView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 220, 400)});
        scroll.msgSend(void, "setHasVerticalScroller:", .{true});
        scroll.msgSend(void, "setAutohidesScrollers:", .{true});
        scroll.msgSend(void, "setDrawsBackground:", .{false});
        scroll.msgSend(void, "setDocumentView:", .{outline});
        self.scroll = scroll;

        try self.rebuildItems();
        outline.msgSend(void, "reloadData", .{});
        self.expandAll();

        return self;
    }

    pub fn deinit(self: *OutlineView) void {
        self.outline.msgSend(void, "setDelegate:", .{@as(c.id, null)});
        self.outline.msgSend(void, "setDataSource:", .{@as(c.id, null)});
        self.outline.msgSend(void, "setTarget:", .{@as(c.id, null)});
        self.scroll.msgSend(void, "release", .{});
        self.outline.msgSend(void, "release", .{});
        self.helper.msgSend(void, "release", .{});

        for (self.section_items.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
        for (self.row_items.items) |*rows| {
            for (rows.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
            rows.deinit(self.alloc);
        }
        for (self.graveyard.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
        self.section_items.deinit(self.alloc);
        self.row_items.deinit(self.alloc);
        self.graveyard.deinit(self.alloc);

        var it = self.symbol_cache.iterator();
        while (it.next()) |entry| {
            objc.Object.fromId(entry.value_ptr.*).msgSend(void, "release", .{});
            self.alloc.free(entry.key_ptr.*);
        }
        self.symbol_cache.deinit();
        self.alloc.destroy(self);
    }

    /// The view to embed (the NSScrollView wrapping the outline).
    pub fn view(self: *OutlineView) c.id {
        return self.scroll.value;
    }

    /// Full reload: re-query the vtable for every section and row.
    pub fn reload(self: *OutlineView) void {
        self.rebuildItems() catch return;
        self.outline.msgSend(void, "reloadData", .{});
        self.expandAll();
    }

    /// Reload one section's rows (badge/count changes, History updates).
    pub fn reloadSection(self: *OutlineView, section: usize) void {
        if (section >= self.section_items.items.len) return;
        self.rebuildSectionRows(section) catch return;
        const header = objc.Object.fromId(self.section_items.items[section]);
        self.outline.msgSend(void, "reloadItem:reloadChildren:", .{ header, true });
        self.outline.msgSend(void, "expandItem:", .{header});
    }

    pub fn selected(self: *OutlineView) ?SectionRow {
        const row = self.outline.msgSend(NSInteger, "selectedRow", .{});
        if (row < 0) return null;
        const item = self.outline.msgSend(c.id, "itemAtRow:", .{row});
        return refOfItem(item orelse return null);
    }

    pub fn select(self: *OutlineView, target: ?SectionRow) void {
        const sr = target orelse {
            self.outline.msgSend(void, "deselectAll:", .{@as(c.id, null)});
            return;
        };
        if (sr.section >= self.row_items.items.len) return;
        const rows = &self.row_items.items[sr.section];
        if (sr.row >= rows.items.len) return;
        const item = objc.Object.fromId(rows.items[sr.row]);
        const row = self.outline.msgSend(NSInteger, "rowForItem:", .{item});
        if (row < 0) return;
        const set = getClass("NSIndexSet").msgSend(objc.Object, "indexSetWithIndex:", .{
            @as(NSUInteger, @intCast(row)),
        });
        self.outline.msgSend(void, "selectRowIndexes:byExtendingSelection:", .{ set, false });
    }

    fn expandAll(self: *OutlineView) void {
        self.outline.msgSend(void, "expandItem:expandChildren:", .{ @as(c.id, null), true });
    }

    fn rebuildItems(self: *OutlineView) !void {
        // Reserve the graveyard space for the whole batch up front: an OOM
        // mid-move must never leave a token in BOTH lists (double release
        // at deinit).
        var moved: usize = self.section_items.items.len;
        for (self.row_items.items) |rows| moved += rows.items.len;
        try self.graveyard.ensureUnusedCapacity(self.alloc, moved);
        for (self.section_items.items) |item| self.graveyard.appendAssumeCapacity(item);
        for (self.row_items.items) |*rows| {
            for (rows.items) |item| self.graveyard.appendAssumeCapacity(item);
            rows.deinit(self.alloc);
        }
        self.section_items.clearRetainingCapacity();
        self.row_items.clearRetainingCapacity();

        const sections = self.ds.sectionCount(self.ds.ctx);
        var s: usize = 0;
        while (s < sections) : (s += 1) {
            try self.section_items.append(self.alloc, newItemToken(.{ .header = s }));
            var rows: std.ArrayList(c.id) = .empty;
            const n = self.ds.rowCount(self.ds.ctx, s);
            std.debug.assert(n <= max_rows_per_section);
            var r: usize = 0;
            while (r < n) : (r += 1) {
                try rows.append(self.alloc, newItemToken(.{ .row = .{ .section = s, .row = r } }));
            }
            try self.row_items.append(self.alloc, rows);
        }
    }

    fn rebuildSectionRows(self: *OutlineView, section: usize) !void {
        const rows = &self.row_items.items[section];
        // Same batch reservation as rebuildItems: no token may end up in
        // both lists if the move runs out of memory.
        try self.graveyard.ensureUnusedCapacity(self.alloc, rows.items.len);
        for (rows.items) |item| self.graveyard.appendAssumeCapacity(item);
        rows.clearRetainingCapacity();
        const n = self.ds.rowCount(self.ds.ctx, section);
        std.debug.assert(n <= max_rows_per_section);
        var r: usize = 0;
        while (r < n) : (r += 1) {
            try rows.append(self.alloc, newItemToken(.{
                .row = .{ .section = section, .row = r },
            }));
        }
    }

    /// Retained, secondaryLabelColor-tinted SF Symbol image (cached).
    fn tintedSymbol(self: *OutlineView, name: [*:0]const u8) ?c.id {
        const key = std.mem.span(name);
        if (self.symbol_cache.get(key)) |cached| return cached;

        const base = ts.systemSymbolImage(name) orelse return null;
        const tint = getClass("NSColor").msgSend(objc.Object, "secondaryLabelColor", .{});
        const colors = getClass("NSArray").msgSend(objc.Object, "arrayWithObject:", .{tint});
        const config = getClass("NSImageSymbolConfiguration").msgSend(
            objc.Object,
            "configurationWithPaletteColors:",
            .{colors},
        );
        var img = objc.Object.fromId(base).msgSend(objc.Object, "imageWithSymbolConfiguration:", .{config});
        if (img.value == null) img = objc.Object.fromId(base);
        _ = img.msgSend(c.id, "retain", .{});

        const owned_key = self.alloc.dupe(u8, key) catch {
            return img.value; // cache miss is fine; image stays retained
        };
        self.symbol_cache.put(owned_key, img.value) catch {
            self.alloc.free(owned_key);
        };
        return img.value;
    }
};

/// Retained RelayOutlineItem identity token carrying an encoded ItemRef.
fn newItemToken(ref: ItemRef) c.id {
    const item = g_item_class.msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    c.object_setIvar(item.value, g_item_ref_ivar, @ptrFromInt(itemRefToIvar(ref)));
    return item.value;
}

fn refOfItem(item: c.id) ?SectionRow {
    const raw = @intFromPtr(c.object_getIvar(item, g_item_ref_ivar));
    return switch (itemRefFromIvar(raw) orelse return null) {
        .header => null,
        .row => |sr| sr,
    };
}

fn fullRefOfItem(item: c.id) ?ItemRef {
    return itemRefFromIvar(@intFromPtr(c.object_getIvar(item, g_item_ref_ivar)));
}

// ---------------------------------------------------------------------------
// Helper IMPs (NSOutlineViewDataSource / Delegate)
// ---------------------------------------------------------------------------
fn helperNumberOfChildren(target: c.id, _: c.SEL, _: c.id, item: c.id) callconv(.c) NSInteger {
    const ov = stateFromIvar(OutlineView, target, g_helper_state_ivar);
    if (item == null) return @intCast(ov.section_items.items.len);
    return switch (fullRefOfItem(item) orelse return 0) {
        // Bounds-guard like cellDrawRect: a graveyard token can outlive
        // the section it pointed at.
        .header => |s| if (s < ov.row_items.items.len)
            @intCast(ov.row_items.items[s].items.len)
        else
            0,
        .row => 0,
    };
}

fn helperIsExpandable(_: c.id, _: c.SEL, _: c.id, item: c.id) callconv(.c) c.BOOL {
    if (item == null) return 0;
    return switch (fullRefOfItem(item) orelse return 0) {
        .header => 1,
        .row => 0,
    };
}

fn helperChildOfItem(target: c.id, _: c.SEL, _: c.id, index: NSInteger, item: c.id) callconv(.c) c.id {
    const ov = stateFromIvar(OutlineView, target, g_helper_state_ivar);
    const i: usize = @intCast(index);
    if (item == null) {
        if (i >= ov.section_items.items.len) return null;
        return ov.section_items.items[i];
    }
    return switch (fullRefOfItem(item) orelse return null) {
        .header => |s| blk: {
            // Bounds-guard like cellDrawRect: a graveyard token can
            // outlive the section it pointed at.
            if (s >= ov.row_items.items.len) break :blk null;
            const rows = &ov.row_items.items[s];
            break :blk if (i < rows.items.len) rows.items[i] else null;
        },
        .row => null,
    };
}

fn helperIsGroupItem(_: c.id, _: c.SEL, _: c.id, item: c.id) callconv(.c) c.BOOL {
    if (item == null) return 0;
    return switch (fullRefOfItem(item) orelse return 0) {
        .header => 1,
        .row => 0,
    };
}

fn helperShouldSelectItem(_: c.id, _: c.SEL, _: c.id, item: c.id) callconv(.c) c.BOOL {
    if (item == null) return 0;
    return switch (fullRefOfItem(item) orelse return 0) {
        .header => 0,
        .row => 1,
    };
}

fn helperViewForItem(target: c.id, _: c.SEL, _: c.id, _: c.id, item: c.id) callconv(.c) c.id {
    const ov = stateFromIvar(OutlineView, target, g_helper_state_ivar);
    const ref = fullRefOfItem(item orelse return null) orelse return null;

    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const ident = nsStr("RelaySidebarCell");
        var view = ov.outline.msgSend(c.id, "makeViewWithIdentifier:owner:", .{
            ident, @as(c.id, null),
        });
        if (view == null) {
            const v = g_cell_class.msgSend(objc.Object, "alloc", .{})
                .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 200, ov.row_height)});
            // Hand the alloc/init +1 to the inner pool so both branches
            // transfer exactly one reference through the dance below.
            _ = v.msgSend(c.id, "autorelease", .{});
            v.msgSend(void, "setIdentifier:", .{ident});
            c.object_setIvar(v.value, g_cell_state_ivar, @ptrCast(ov));
            view = v.value;
        }
        c.object_setIvar(view, g_cell_ref_ivar, @ptrFromInt(itemRefToIvar(ref)));
        objc.Object.fromId(view).msgSend(void, "setNeedsDisplay:", .{true});
        result = view;
    }
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

fn helperSelectionDidChange(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const ov = stateFromIvar(OutlineView, target, g_helper_state_ivar);
    const cb = ov.ds.selectionChanged orelse return;
    cb(ov.ds.ctx, ov.selected());
}

fn helperOnDouble(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const ov = stateFromIvar(OutlineView, target, g_helper_state_ivar);
    const cb = ov.ds.doubleAction orelse return;
    const clicked = ov.outline.msgSend(NSInteger, "clickedRow", .{});
    if (clicked < 0) return;
    const item = ov.outline.msgSend(c.id, "itemAtRow:", .{clicked}) orelse return;
    const sr = refOfItem(item) orelse return; // headers don't activate
    cb(ov.ds.ctx, sr);
}

// ---------------------------------------------------------------------------
// RelayOutlineView IMPs (Return key + context menu)
// ---------------------------------------------------------------------------
fn outlineKeyDown(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const ov = stateFromIvar(OutlineView, target, g_outline_state_ivar);
    const event = objc.Object.fromId(event_id);
    const key_code: u16 = event.msgSend(c_ushort, "keyCode", .{});
    const flags = event.msgSend(NSUInteger, "modifierFlags", .{});
    const plain = flags & (ts.flag_command | ts.flag_control | ts.flag_option) == 0;

    if (plain and (key_code == ts.key_return or key_code == ts.key_keypad_enter)) {
        if (ov.ds.returnAction) |cb| {
            if (ov.selected()) |sr| {
                cb(ov.ds.ctx, sr);
                return;
            }
        }
    }
    objc.Object.fromId(target).msgSendSuper(getClass("NSOutlineView"), void, "keyDown:", .{event_id});
}

fn outlineMenuForEvent(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) c.id {
    const ov = stateFromIvar(OutlineView, target, g_outline_state_ivar);
    const hook = ov.ds.contextMenu orelse {
        return objc.Object.fromId(target).msgSendSuper(
            getClass("NSOutlineView"),
            c.id,
            "menuForEvent:",
            .{event_id},
        );
    };

    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const event = objc.Object.fromId(event_id);
        const outline = objc.Object.fromId(target);
        const loc = event.msgSend(NSPoint, "locationInWindow", .{});
        const point = outline.msgSend(NSPoint, "convertPoint:fromView:", .{ loc, @as(c.id, null) });
        const row = outline.msgSend(NSInteger, "rowAtPoint:", .{point});
        var sr: ?SectionRow = null;
        if (row >= 0) {
            if (outline.msgSend(c.id, "itemAtRow:", .{row})) |item| sr = refOfItem(item);
        }
        result = hook(ov.ds.ctx, sr) orelse null;
    }
    if (result) |m| _ = objc.Object.fromId(m).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |m| _ = objc.Object.fromId(m).msgSend(c.id, "autorelease", .{});
    return result;
}

// ---------------------------------------------------------------------------
// RelayOutlineCellView IMPs (custom drawing: header / icon+title+badge)
// ---------------------------------------------------------------------------
fn cellIsFlipped(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1;
}

const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });

const h_pad: f64 = 6;
const icon_edge: f64 = 15;
const icon_text_gap: f64 = 6;
const compositing_source_over: NSUInteger = 2;

fn cellDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const ov = stateFromIvar(OutlineView, target, g_cell_state_ivar);
    const ref = itemRefFromIvar(@intFromPtr(c.object_getIvar(target, g_cell_ref_ivar))) orelse return;
    const self = objc.Object.fromId(target);
    const bounds = self.msgSend(NSRect, "bounds", .{});

    var buf: [256]u8 = undefined;
    switch (ref) {
        .header => |s| {
            if (s >= ov.ds.sectionCount(ov.ds.ctx)) return;
            const title = ov.ds.sectionTitle(ov.ds.ctx, s, &buf);
            if (title.len == 0) return;
            const attrs = makeAttrs(
                getClass("NSFont").msgSend(objc.Object, "boldSystemFontOfSize:", .{@as(f64, 11)}),
                getClass("NSColor").msgSend(objc.Object, "secondaryLabelColor", .{}),
            );
            const str = nsStrBytes(title);
            const size = str.msgSend(NSSize, "sizeWithAttributes:", .{attrs});
            str.msgSend(void, "drawAtPoint:withAttributes:", .{
                NSPoint{ .x = h_pad, .y = (bounds.size.height - size.height) / 2 },
                attrs,
            });
        },
        .row => |sr| {
            if (sr.section >= ov.ds.sectionCount(ov.ds.ctx)) return;
            if (sr.row >= ov.ds.rowCount(ov.ds.ctx, sr.section)) return;
            const item = ov.ds.rowItem(ov.ds.ctx, sr.section, sr.row, &buf);

            var text_x: f64 = h_pad;
            if (item.symbol) |symbol| {
                if (ov.tintedSymbol(symbol)) |img| {
                    const icon_rect = rect(text_x, (bounds.size.height - icon_edge) / 2, icon_edge, icon_edge);
                    objc.Object.fromId(img).msgSend(
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
                }
                text_x += icon_edge + icon_text_gap;
            }

            // Badge (right-aligned, monospaced digits, secondary color).
            if (item.badge) |badge| {
                var bbuf: [24]u8 = undefined;
                const btext = std.fmt.bufPrint(&bbuf, "{d}", .{badge}) catch "";
                if (btext.len > 0) {
                    const battrs = makeAttrs(
                        getClass("NSFont").msgSend(objc.Object, "monospacedDigitSystemFontOfSize:weight:", .{
                            @as(f64, 11), @as(f64, 0.0),
                        }),
                        getClass("NSColor").msgSend(objc.Object, "secondaryLabelColor", .{}),
                    );
                    const bstr = nsStrBytes(btext);
                    const bsize = bstr.msgSend(NSSize, "sizeWithAttributes:", .{battrs});
                    bstr.msgSend(void, "drawAtPoint:withAttributes:", .{
                        NSPoint{
                            .x = bounds.size.width - h_pad - bsize.width,
                            .y = (bounds.size.height - bsize.height) / 2,
                        },
                        battrs,
                    });
                }
            }

            // Title starts after the icon; badge overlap is impossible at
            // sidebar widths (M2 simplification).
            if (item.title.len == 0) return;
            const attrs = makeAttrs(
                getClass("NSFont").msgSend(objc.Object, "systemFontOfSize:", .{@as(f64, 13)}),
                rowTextColor(self),
            );
            const str = nsStrBytes(item.title);
            const size = str.msgSend(NSSize, "sizeWithAttributes:", .{attrs});
            str.msgSend(void, "drawAtPoint:withAttributes:", .{
                NSPoint{ .x = text_x, .y = (bounds.size.height - size.height) / 2 },
                attrs,
            });
        },
    }
}

fn makeAttrs(font: objc.Object, color: objc.Object) objc.Object {
    const attrs = getClass("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
    attrs.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ color.value, NSForegroundColorAttributeName.* });
    return attrs;
}

/// Same semantic selection-aware color rule as the table cells.
fn rowTextColor(cell: objc.Object) objc.Object {
    const row_view = cell.msgSend(objc.Object, "superview", .{});
    if (row_view.value != null) {
        const responds = row_view.msgSend(c.BOOL, "respondsToSelector:", .{objc.sel("isSelected")});
        if (responds != 0) {
            const is_selected = row_view.msgSend(c.BOOL, "isSelected", .{}) != 0;
            const emphasized = row_view.msgSend(c.BOOL, "isEmphasized", .{}) != 0;
            if (is_selected and emphasized)
                return getClass("NSColor").msgSend(objc.Object, "alternateSelectedControlTextColor", .{});
        }
    }
    return getClass("NSColor").msgSend(objc.Object, "labelColor", .{});
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
test "item ref ivar encoding round-trips" {
    const h = itemRefToIvar(.{ .header = 2 });
    const hr = itemRefFromIvar(h) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), hr.header);

    const r = itemRefToIvar(.{ .row = .{ .section = 1, .row = 12345 } });
    const rr = itemRefFromIvar(r) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), rr.row.section);
    try std.testing.expectEqual(@as(usize, 12345), rr.row.row);

    try std.testing.expectEqual(@as(?ItemRef, null), itemRefFromIvar(0));
    // Non-null + 8-byte aligned (Debug @ptrFromInt requirement).
    try std.testing.expect(h != 0 and h % 8 == 0);
    try std.testing.expect(r != 0 and r % 8 == 0);
}

test "vtable plumbing through ObjC dispatch (headless, no NSOutlineView)" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    ensureClasses();

    const Fake = struct {
        fn sectionCount(_: *anyopaque) usize {
            return 3;
        }
        fn sectionTitle(_: *anyopaque, _: usize, buf: []u8) []const u8 {
            return std.fmt.bufPrint(buf, "S", .{}) catch unreachable;
        }
        fn rowCount(_: *anyopaque, section: usize) usize {
            return section + 1;
        }
        fn rowItem(_: *anyopaque, _: usize, _: usize, buf: []u8) Item {
            return .{ .title = std.fmt.bufPrint(buf, "r", .{}) catch unreachable };
        }
    };
    var fake: u8 = 0;

    var ov: OutlineView = undefined;
    ov.alloc = std.testing.allocator;
    ov.ds = .{
        .ctx = &fake,
        .sectionCount = Fake.sectionCount,
        .sectionTitle = Fake.sectionTitle,
        .rowCount = Fake.rowCount,
        .rowItem = Fake.rowItem,
    };
    ov.section_items = .empty;
    ov.row_items = .empty;
    ov.graveyard = .empty;
    try ov.rebuildItems();
    defer {
        for (ov.section_items.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
        for (ov.row_items.items) |*rows| {
            for (rows.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
            rows.deinit(ov.alloc);
        }
        for (ov.graveyard.items) |item| objc.Object.fromId(item).msgSend(void, "release", .{});
        ov.section_items.deinit(ov.alloc);
        ov.row_items.deinit(ov.alloc);
        ov.graveyard.deinit(ov.alloc);
    }

    const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{});
    defer helper.msgSend(void, "release", .{});
    c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(&ov));

    // Root: 3 sections.
    const n = helper.msgSend(NSInteger, "outlineView:numberOfChildrenOfItem:", .{
        @as(c.id, null), @as(c.id, null),
    });
    try std.testing.expectEqual(@as(NSInteger, 3), n);

    // Section 2 header token: expandable group with 3 children.
    const header = helper.msgSend(c.id, "outlineView:child:ofItem:", .{
        @as(c.id, null), @as(NSInteger, 2), @as(c.id, null),
    });
    try std.testing.expect(header != null);
    try std.testing.expectEqual(@as(NSInteger, 3), helper.msgSend(
        NSInteger,
        "outlineView:numberOfChildrenOfItem:",
        .{ @as(c.id, null), header },
    ));
    try std.testing.expect(helper.msgSend(c.BOOL, "outlineView:isItemExpandable:", .{ @as(c.id, null), header }) == 1);
    try std.testing.expect(helper.msgSend(c.BOOL, "outlineView:isGroupItem:", .{ @as(c.id, null), header }) == 1);
    try std.testing.expect(helper.msgSend(c.BOOL, "outlineView:shouldSelectItem:", .{ @as(c.id, null), header }) == 0);

    // Row token (section 2, row 1): selectable leaf.
    const row = helper.msgSend(c.id, "outlineView:child:ofItem:", .{
        @as(c.id, null), @as(NSInteger, 1), header,
    });
    try std.testing.expect(row != null);
    try std.testing.expect(helper.msgSend(c.BOOL, "outlineView:shouldSelectItem:", .{ @as(c.id, null), row }) == 1);
    const sr = refOfItem(row) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), sr.section);
    try std.testing.expectEqual(@as(usize, 1), sr.row);
}

//! M0 spike 2 + 3 (THE GATE): drive AppKit from pure Zig via zig-objc.
//! Proofs implemented here:
//!   1. NSApplication + NSWindow created and run from Zig main(),
//!   2. view-based NSTableView (3 columns, fixed 24pt rows, automatic row
//!      heights off) whose dataSource AND delegate is an ObjC class defined
//!      from Zig (allocateClassPair/addMethod) backed by 100k Zig-owned rows,
//!   3. the "name" column cell is a custom NSView subclass defined from Zig
//!      whose drawRect: draws the row text + a colored badge,
//!   4. header-click sorting via sortDescriptorPrototype +
//!      tableView:sortDescriptorsDidChange: (sorts a Zig index array),
//!   5. a background std.Thread ticks ~30Hz and appends 1000 rows/s,
//!      marshaled to the main thread with dispatch_async + zig-objc Block,
//!   6. autorelease pools around every callback body and worker iteration.
//!
//! State-pointer recovery convention (app-wide going forward): each
//! runtime-defined class gets an id-sized ivar that stores a raw `*AppState`
//! pointer; the Ivar handle is looked up once after registerClassPair and
//! cached in a global, so callbacks recover state with one object_getIvar
//! call (no string lookup, no associated-object overhead, supports multiple
//! instances unlike a global).
//!
//! Run with: zig build spike-ui -- --auto-exit-seconds 6

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

// ---------------------------------------------------------------------------
// AppKit ABI types (LP64: NSInteger == long == i64; geometry uses f64).
// NSInteger is declared as i64 (not c_long) so zig-objc's type-encoder emits
// 'q', which is what Apple's runtime emits for long on LP64.
// ---------------------------------------------------------------------------
const NSInteger = i64;
const NSUInteger = u64;
const NSPoint = extern struct { x: f64, y: f64 };
const NSSize = extern struct { width: f64, height: f64 };
const NSRect = extern struct { origin: NSPoint, size: NSSize };

fn rect(x: f64, y: f64, w: f64, h: f64) NSRect {
    return .{ .origin = .{ .x = x, .y = y }, .size = .{ .width = w, .height = h } };
}

const style_mask: NSUInteger = 1 | 2 | 4 | 8; // titled|closable|miniaturizable|resizable
const backing_store_buffered: NSUInteger = 2;
const activation_policy_regular: NSInteger = 0;

// ---------------------------------------------------------------------------
// libdispatch / libc externs (ghostty pkg/macos/dispatch.zig pattern: the main
// queue is the address of the exported _dispatch_main_q variable).
// ---------------------------------------------------------------------------
extern "c" fn dispatch_async(queue: *anyopaque, block: *anyopaque) void;
const dispatch_main_q = @extern(*opaque {}, .{ .name = "_dispatch_main_q" });
extern "c" fn usleep(usec: c_uint) c_int;
extern "c" fn clock_gettime_nsec_np(clock_id: c_int) u64;
const CLOCK_UPTIME_RAW: c_int = 8;

// AppKit-exported NSString* constants (the symbol holds the pointer value).
const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });

// ---------------------------------------------------------------------------
// Zig-owned data model: 100k synthetic rows + a sortable index array.
// All mutation happens on the main thread (the worker only dispatches blocks).
// ---------------------------------------------------------------------------
const initial_rows = 100_000;

const Row = struct {
    name: [19]u8,
    name_len: u8,
    size: u64,
    year: u16,
    month: u8,
    day: u8,

    fn nameSlice(self: *const Row) []const u8 {
        return self.name[0..self.name_len];
    }
};

const AppState = struct {
    alloc: std.mem.Allocator,
    prng: std.Random.DefaultPrng,
    rows: std.ArrayList(Row) = .empty,
    order: std.ArrayList(u32) = .empty,
    window: c.id = null,
    table: c.id = null,
    auto_exit_seconds: ?u32 = null,
    should_stop: std.atomic.Value(bool) = .init(false),
    // Main-thread-only counters (mutated exclusively from main-queue blocks
    // and AppKit callbacks, so no synchronization is needed).
    updates_received: u64 = 0,
    rows_appended: u64 = 0,
    viewfor_calls: u64 = 0,
    made_views: u64 = 0,
    reuse_hits: u64 = 0,
    sort_events: u64 = 0,
};

var g_state: AppState = undefined;

// Cached after registerClassPair: Ivar handles + classes for the two
// runtime-defined classes (see header comment for the convention).
var g_ds_state_ivar: c.Ivar = null;
var g_cell_state_ivar: c.Ivar = null;
var g_cell_row_ivar: c.Ivar = null;
var g_cell_class: objc.Class = undefined;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
fn failTest(reason: []const u8) noreturn {
    std.debug.print("SPIKE-UI FAIL {s}\n", .{reason});
    std.process.exit(1);
}

fn getClass(name: [:0]const u8) objc.Class {
    return objc.getClass(name) orelse failTest("objc class not found");
}

fn nsStr(s: [*:0]const u8) objc.Object {
    return getClass("NSString").msgSend(objc.Object, "stringWithUTF8String:", .{s});
}

/// Recover the Zig state pointer stored in an id-sized ivar (raw pointer,
/// never retained/released: runtime-allocated classes have no ARC layout,
/// so object_setIvar is a plain store).
fn stateFromIvar(target: c.id, ivar: c.Ivar) *AppState {
    const raw = c.object_getIvar(target, ivar) orelse failTest("state ivar is null");
    return @ptrCast(@alignCast(raw));
}

/// Row indexes ride in an id-sized ivar as (index+1)<<3 so the fake pointer
/// stays non-null and 8-byte aligned (Debug-mode @ptrFromInt checks both).
fn rowIndexToIvar(index: usize) c.id {
    return @ptrFromInt((index + 1) << 3);
}

fn rowIndexFromIvar(target: c.id) ?usize {
    const raw = @intFromPtr(c.object_getIvar(target, g_cell_row_ivar));
    if (raw == 0) return null;
    return (raw >> 3) - 1;
}

fn makeRow(st: *AppState, index: usize) Row {
    var row: Row = undefined;
    const s = std.fmt.bufPrint(&row.name, "file_{d:0>6}.txt", .{index}) catch
        failTest("row name overflow");
    row.name_len = @intCast(s.len);
    const rand = st.prng.random();
    row.size = rand.uintLessThan(u64, 4 * 1024 * 1024 * 1024);
    row.year = 2020 + rand.uintLessThan(u16, 7);
    row.month = 1 + rand.uintLessThan(u8, 12);
    row.day = 1 + rand.uintLessThan(u8, 28);
    return row;
}

fn appendRows(st: *AppState, count: usize) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const index = st.rows.items.len;
        st.rows.append(st.alloc, makeRow(st, index)) catch failTest("oom appending rows");
        st.order.append(st.alloc, @intCast(index)) catch failTest("oom appending order");
    }
    st.rows_appended += count;
}

// ---------------------------------------------------------------------------
// SpikeDataSource: ObjC class defined from Zig. Implements both
// NSTableViewDataSource (numberOfRowsInTableView:, sortDescriptorsDidChange:)
// and NSTableViewDelegate (tableView:viewForTableColumn:row:), plus the
// NSTimer callback used by --auto-exit-seconds.
// ---------------------------------------------------------------------------
fn defineDataSourceClass() objc.Class {
    const cls = objc.allocateClassPair(getClass("NSObject"), "SpikeDataSource") orelse
        failTest("allocateClassPair(SpikeDataSource)");
    if (!cls.addIvar("relayState")) failTest("addIvar(relayState)");
    if (!cls.addMethod("numberOfRowsInTableView:", dsNumberOfRows))
        failTest("addMethod(numberOfRowsInTableView:)");
    if (!cls.addMethod("tableView:viewForTableColumn:row:", dsViewForColumnRow))
        failTest("addMethod(tableView:viewForTableColumn:row:)");
    if (!cls.addMethod("tableView:sortDescriptorsDidChange:", dsSortDescriptorsDidChange))
        failTest("addMethod(tableView:sortDescriptorsDidChange:)");
    if (!cls.addMethod("onAutoExit:", dsOnAutoExit))
        failTest("addMethod(onAutoExit:)");
    objc.registerClassPair(cls);
    g_ds_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
    if (g_ds_state_ivar == null) failTest("class_getInstanceVariable(relayState)");
    return cls;
}

fn dsNumberOfRows(target: c.id, _: c.SEL, _: c.id) callconv(.c) NSInteger {
    const st = stateFromIvar(target, g_ds_state_ivar);
    return @intCast(st.order.items.len);
}

fn dsViewForColumnRow(
    target: c.id,
    _: c.SEL,
    table_id: c.id,
    column_id: c.id,
    row: NSInteger,
) callconv(.c) c.id {
    const st = stateFromIvar(target, g_ds_state_ivar);
    st.viewfor_calls += 1;

    // Pool around the callback body. The returned view must outlive our pool,
    // so it is retained before the pop and re-autoreleased into the caller's
    // (AppKit event-loop) pool afterwards — the textbook MRR pattern for
    // returning autoreleased objects across pool boundaries.
    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const column = objc.Object.fromId(column_id);
        const ident = column.msgSend(objc.Object, "identifier", .{});
        const ident_s = std.mem.span(ident.msgSend([*:0]const u8, "UTF8String", .{}));
        const data_index: usize = st.order.items[@intCast(row)];
        const r = &st.rows.items[data_index];

        if (std.mem.eql(u8, ident_s, "name")) {
            result = makeNameCell(st, table_id, data_index);
        } else if (std.mem.eql(u8, ident_s, "size")) {
            var buf: [32]u8 = undefined;
            const text = formatSize(&buf, r.size);
            result = makeTextCell(st, table_id, "SizeCell", text.ptr);
        } else {
            var buf: [32]u8 = undefined;
            const text = std.fmt.bufPrintZ(&buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
                r.year, r.month, r.day,
            }) catch failTest("date format");
            result = makeTextCell(st, table_id, "DateCell", text.ptr);
        }
    }
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

fn formatSize(buf: []u8, size: u64) [:0]const u8 {
    const fsize: f64 = @floatFromInt(size);
    return (if (size < 1024)
        std.fmt.bufPrintZ(buf, "{d} B", .{size})
    else if (size < 1024 * 1024)
        std.fmt.bufPrintZ(buf, "{d:.1} KB", .{fsize / 1024.0})
    else if (size < 1024 * 1024 * 1024)
        std.fmt.bufPrintZ(buf, "{d:.1} MB", .{fsize / (1024.0 * 1024.0)})
    else
        std.fmt.bufPrintZ(buf, "{d:.2} GB", .{fsize / (1024.0 * 1024.0 * 1024.0)})) catch
        failTest("size format");
}

/// Custom-drawn cell for the "name" column (reused via makeViewWithIdentifier).
fn makeNameCell(st: *AppState, table_id: c.id, data_index: usize) c.id {
    const table = objc.Object.fromId(table_id);
    const ident = nsStr("NameCell");
    var view = table.msgSend(c.id, "makeViewWithIdentifier:owner:", .{ ident, @as(c.id, null) });
    if (view == null) {
        st.made_views += 1;
        const v = g_cell_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 320, 24)});
        v.msgSend(void, "setIdentifier:", .{ident});
        c.object_setIvar(v.value, g_cell_state_ivar, @ptrCast(st));
        view = v.value;
    } else {
        st.reuse_hits += 1;
    }
    c.object_setIvar(view, g_cell_row_ivar, rowIndexToIvar(data_index));
    objc.Object.fromId(view).msgSend(void, "setNeedsDisplay:", .{true});
    return view;
}

/// Plain NSTextField label cell for the size/modified columns.
fn makeTextCell(
    st: *AppState,
    table_id: c.id,
    comptime ident_z: [*:0]const u8,
    text: [*:0]const u8,
) c.id {
    const table = objc.Object.fromId(table_id);
    const ident = nsStr(ident_z);
    var view = table.msgSend(c.id, "makeViewWithIdentifier:owner:", .{ ident, @as(c.id, null) });
    if (view == null) {
        st.made_views += 1;
        const v = getClass("NSTextField").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 140, 24)});
        v.msgSend(void, "setBezeled:", .{false});
        v.msgSend(void, "setBordered:", .{false});
        v.msgSend(void, "setDrawsBackground:", .{false});
        v.msgSend(void, "setEditable:", .{false});
        v.msgSend(void, "setSelectable:", .{false});
        v.msgSend(void, "setIdentifier:", .{ident});
        view = v.value;
    } else {
        st.reuse_hits += 1;
    }
    objc.Object.fromId(view).msgSend(void, "setStringValue:", .{nsStr(text)});
    return view;
}

fn dsSortDescriptorsDidChange(target: c.id, _: c.SEL, table_id: c.id, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const st = stateFromIvar(target, g_ds_state_ivar);
    const table = objc.Object.fromId(table_id);
    const descs = table.msgSend(objc.Object, "sortDescriptors", .{});
    if (descs.msgSend(NSUInteger, "count", .{}) == 0) return;
    const first = descs.msgSend(objc.Object, "objectAtIndex:", .{@as(NSUInteger, 0)});
    const key = first.msgSend(objc.Object, "key", .{});
    const key_s = std.mem.span(key.msgSend([*:0]const u8, "UTF8String", .{}));
    if (!std.mem.eql(u8, key_s, "name")) return;
    const ascending = first.msgSend(c.BOOL, "ascending", .{}) != 0;

    const Ctx = struct {
        st: *AppState,
        asc: bool,
        fn lessThan(ctx: @This(), a: u32, b: u32) bool {
            const oa = std.mem.order(
                u8,
                ctx.st.rows.items[a].nameSlice(),
                ctx.st.rows.items[b].nameSlice(),
            );
            return if (ctx.asc) oa == .lt else oa == .gt;
        }
    };
    std.mem.sortUnstable(u32, st.order.items, Ctx{ .st = st, .asc = ascending }, Ctx.lessThan);
    st.sort_events += 1;
    table.msgSend(void, "reloadData", .{});
}

// ---------------------------------------------------------------------------
// SpikeNameCellView: NSView subclass defined from Zig; drawRect: paints the
// file name plus a colored badge — the pattern the real file list needs.
// ---------------------------------------------------------------------------
fn defineNameCellClass() objc.Class {
    const cls = objc.allocateClassPair(getClass("NSView"), "SpikeNameCellView") orelse
        failTest("allocateClassPair(SpikeNameCellView)");
    if (!cls.addIvar("relayState")) failTest("addIvar(cell relayState)");
    if (!cls.addIvar("relayRowIndex")) failTest("addIvar(relayRowIndex)");
    if (!cls.addMethod("drawRect:", cellDrawRect)) failTest("addMethod(drawRect:)");
    if (!cls.addMethod("isFlipped", cellIsFlipped)) failTest("addMethod(isFlipped)");
    objc.registerClassPair(cls);
    g_cell_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
    g_cell_row_ivar = c.class_getInstanceVariable(cls.value, "relayRowIndex");
    if (g_cell_state_ivar == null or g_cell_row_ivar == null)
        failTest("class_getInstanceVariable(cell ivars)");
    return cls;
}

fn cellIsFlipped(_: c.id, _: c.SEL) callconv(.c) c.BOOL {
    return 1; // c.BOOL is i8 in the translated runtime headers
}

fn cellDrawRect(target: c.id, _: c.SEL, _: NSRect) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const st = stateFromIvar(target, g_cell_state_ivar);
    const data_index = rowIndexFromIvar(target) orelse return;
    if (data_index >= st.rows.items.len) return;
    const row = &st.rows.items[data_index];

    const self = objc.Object.fromId(target);
    const bounds = self.msgSend(NSRect, "bounds", .{});

    // Colored badge via NSBezierPath.
    const color_sel: [:0]const u8 = switch (data_index % 3) {
        0 => "systemBlueColor",
        1 => "systemOrangeColor",
        else => "systemGreenColor",
    };
    const color = getClass("NSColor").msgSend(objc.Object, color_sel, .{});
    color.msgSend(void, "setFill", .{});
    const badge = rect(6, (bounds.size.height - 9) / 2, 9, 9);
    getClass("NSBezierPath")
        .msgSend(objc.Object, "bezierPathWithOvalInRect:", .{badge})
        .msgSend(void, "fill", .{});

    // Name string via NSString drawing with explicit attributes.
    const attrs = getClass("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
    const font = getClass("NSFont").msgSend(objc.Object, "systemFontOfSize:", .{@as(f64, 12)});
    const label_color = getClass("NSColor").msgSend(objc.Object, "labelColor", .{});
    attrs.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
    attrs.msgSend(void, "setObject:forKey:", .{ label_color.value, NSForegroundColorAttributeName.* });

    var buf: [24]u8 = undefined;
    const name_z = std.fmt.bufPrintZ(&buf, "{s}", .{row.nameSlice()}) catch return;
    nsStr(name_z.ptr).msgSend(void, "drawAtPoint:withAttributes:", .{
        NSPoint{ .x = 22, .y = (bounds.size.height - 15) / 2 },
        attrs,
    });
}

// ---------------------------------------------------------------------------
// Spike 3: background worker → main-thread marshaling via dispatch_async.
// The worker owns no UI state; it only dispatches zig-objc Blocks to the main
// queue (dispatch_async Block_copy's the stack block before returning).
// ---------------------------------------------------------------------------
const MainBlock = objc.Block(struct { state: usize }, .{}, void);

fn onTickMain(ctx: *const MainBlock.Context) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const st: *AppState = @ptrFromInt(ctx.state);
    st.updates_received += 1;
    var buf: [96]u8 = undefined;
    const title = std.fmt.bufPrintZ(&buf, "Relay UI Spike — ticks {d}, rows {d}", .{
        st.updates_received, st.order.items.len,
    }) catch return;
    objc.Object.fromId(st.window).msgSend(void, "setTitle:", .{nsStr(title.ptr)});
}

fn onAppendMain(ctx: *const MainBlock.Context) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const st: *AppState = @ptrFromInt(ctx.state);
    appendRows(st, 1000);
    objc.Object.fromId(st.table).msgSend(void, "noteNumberOfRowsChanged", .{});
}

fn workerMain(st: *AppState) void {
    var tick: u64 = 0;
    while (!st.should_stop.load(.acquire)) {
        const pool = objc.AutoreleasePool.init();
        defer pool.deinit();

        tick += 1;
        var tick_block = MainBlock.init(.{ .state = @intFromPtr(st) }, onTickMain);
        dispatch_async(@ptrCast(dispatch_main_q), @ptrCast(&tick_block));
        if (tick % 30 == 0) {
            var append_block = MainBlock.init(.{ .state = @intFromPtr(st) }, onAppendMain);
            dispatch_async(@ptrCast(dispatch_main_q), @ptrCast(&append_block));
        }
        _ = usleep(33_000); // ~30Hz
    }
}

// ---------------------------------------------------------------------------
// Automated self-test (--auto-exit-seconds N): fired by an NSTimer on the
// main run loop; scrolls the full table, exercises sorting, then terminates.
// ---------------------------------------------------------------------------
fn dsOnAutoExit(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const st = stateFromIvar(target, g_ds_state_ivar);
    const table = objc.Object.fromId(st.table);
    const window = objc.Object.fromId(st.window);

    if (window.msgSend(c.BOOL, "isVisible", .{}) == 0) failTest("window is not visible");
    if (table.msgSend(f64, "rowHeight", .{}) != 24.0) failTest("rowHeight is not 24.0");

    const n = table.msgSend(NSInteger, "numberOfRows", .{});
    if (n != @as(NSInteger, @intCast(st.order.items.len)))
        failTest("numberOfRows does not match Zig model");
    if (n < initial_rows + 1000)
        failTest("background appends did not arrive (rows <= 100k)");
    if (st.updates_received < 10)
        failTest("too few main-thread updates received from worker");

    // Scroll the full table, forcing layout+draw at each step so row views
    // are actually materialized (this is what exercises the reuse queue).
    const t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    var row: NSInteger = 0;
    while (row < n) : (row += 1000) {
        table.msgSend(void, "scrollRowToVisible:", .{row});
        window.msgSend(void, "displayIfNeeded", .{});
    }
    table.msgSend(void, "scrollRowToVisible:", .{n - 1});
    window.msgSend(void, "displayIfNeeded", .{});
    const scroll_ms = (clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - t0) / std.time.ns_per_ms;

    if (st.made_views == 0) failTest("no cell views were created");
    if (st.reuse_hits == 0) failTest("makeViewWithIdentifier never reused a view");
    if (st.reuse_hits <= st.made_views)
        failTest("view reuse not dominating (reuse <= created)");

    // Sorting proof: programmatically set a descending name sort, which goes
    // through the same tableView:sortDescriptorsDidChange: path as a header
    // click (the prototype on the column makes the click path work manually).
    const before_first = st.order.items[0];
    const desc = getClass("NSSortDescriptor").msgSend(
        objc.Object,
        "sortDescriptorWithKey:ascending:",
        .{ nsStr("name"), false },
    );
    const desc_array = getClass("NSArray").msgSend(objc.Object, "arrayWithObject:", .{desc});
    table.msgSend(void, "setSortDescriptors:", .{desc_array});
    if (st.sort_events == 0) failTest("sortDescriptorsDidChange was not called");
    if (st.order.items[0] == before_first) failTest("sort did not reorder rows");
    window.msgSend(void, "displayIfNeeded", .{});

    std.debug.print(
        "SPIKE-UI PASS rows={d} scroll_ms={d} updates_received={d} " ++
            "(views created={d} reused={d} viewFor calls={d} sort_events={d})\n",
        .{ n, scroll_ms, st.updates_received, st.made_views, st.reuse_hits, st.viewfor_calls, st.sort_events },
    );

    st.should_stop.store(true, .release);
    const app = getClass("NSApplication").msgSend(objc.Object, "sharedApplication", .{});
    app.msgSend(void, "terminate:", .{@as(c.id, null)}); // exits 0
}

// ---------------------------------------------------------------------------
// UI construction + main
// ---------------------------------------------------------------------------
fn addColumn(
    table: objc.Object,
    ident: [*:0]const u8,
    title: [*:0]const u8,
    width: f64,
    sortable: bool,
) void {
    const col = getClass("NSTableColumn").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithIdentifier:", .{nsStr(ident)});
    col.msgSend(void, "setTitle:", .{nsStr(title)});
    col.msgSend(void, "setWidth:", .{width});
    if (sortable) {
        const proto = getClass("NSSortDescriptor").msgSend(
            objc.Object,
            "sortDescriptorWithKey:ascending:",
            .{ nsStr(ident), true },
        );
        col.msgSend(void, "setSortDescriptorPrototype:", .{proto});
    }
    table.msgSend(void, "addTableColumn:", .{col});
}

pub fn main(init: std.process.Init.Minimal) !void {
    // --- args ---
    var auto_exit: ?u32 = null;
    var it = std.process.Args.Iterator.init(init.args);
    _ = it.next(); // argv0
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--auto-exit-seconds")) {
            const v = it.next() orelse failTest("--auto-exit-seconds needs a value");
            auto_exit = std.fmt.parseInt(u32, v, 10) catch
                failTest("--auto-exit-seconds value is not an integer");
        }
    }

    // --- Zig-owned data model ---
    g_state = .{
        .alloc = std.heap.c_allocator,
        .prng = std.Random.DefaultPrng.init(0x52656c6179), // "Relay"
        .auto_exit_seconds = auto_exit,
    };
    const st = &g_state;
    try st.rows.ensureTotalCapacity(st.alloc, initial_rows * 2);
    try st.order.ensureTotalCapacity(st.alloc, initial_rows * 2);
    appendRows(st, initial_rows);
    st.rows_appended = 0; // only count worker-driven appends

    const pool = objc.AutoreleasePool.init();

    // --- NSApplication ---
    const app = getClass("NSApplication").msgSend(objc.Object, "sharedApplication", .{});
    _ = app.msgSend(c.BOOL, "setActivationPolicy:", .{activation_policy_regular});

    // --- runtime-defined classes (before any instance exists) ---
    g_cell_class = defineNameCellClass();
    const ds_class = defineDataSourceClass();

    // --- window + scroll view + table ---
    const window = getClass("NSWindow").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithContentRect:styleMask:backing:defer:", .{
        rect(240, 240, 900, 600), style_mask, backing_store_buffered, false,
    });
    window.msgSend(void, "setReleasedWhenClosed:", .{false});
    window.msgSend(void, "setTitle:", .{nsStr("Relay UI Spike")});
    st.window = window.value;

    const scroll = getClass("NSScrollView").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 900, 600)});
    scroll.msgSend(void, "setHasVerticalScroller:", .{true});

    const table = getClass("NSTableView").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{rect(0, 0, 900, 600)});
    table.msgSend(void, "setRowHeight:", .{@as(f64, 24.0)});
    table.msgSend(void, "setUsesAutomaticRowHeights:", .{false});
    st.table = table.value;

    addColumn(table, "name", "Name", 360, true);
    addColumn(table, "size", "Size", 140, false);
    addColumn(table, "modified", "Modified", 180, false);

    // --- data source instance with the Zig state pointer in its ivar ---
    const ds = ds_class.msgSend(objc.Object, "alloc", .{}).msgSend(objc.Object, "init", .{});
    c.object_setIvar(ds.value, g_ds_state_ivar, @ptrCast(st));
    table.msgSend(void, "setDelegate:", .{ds}); // delegate first → view-based table
    table.msgSend(void, "setDataSource:", .{ds});

    scroll.msgSend(void, "setDocumentView:", .{table});
    window.msgSend(void, "setContentView:", .{scroll});
    table.msgSend(void, "reloadData", .{});

    // --- background worker (spike 3) ---
    const worker = try std.Thread.spawn(.{}, workerMain, .{st});
    worker.detach();

    // --- self-test timer ---
    if (auto_exit) |secs| {
        _ = getClass("NSTimer").msgSend(
            objc.Object,
            "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
            .{ @as(f64, @floatFromInt(secs)), ds, objc.sel("onAutoExit:"), @as(c.id, null), false },
        );
    }

    window.msgSend(void, "makeKeyAndOrderFront:", .{@as(c.id, null)});
    app.msgSend(void, "activateIgnoringOtherApps:", .{true});

    std.debug.print("spike-ui: window up with {d} rows (auto-exit: {?d}s)\n", .{
        st.order.items.len, auto_exit,
    });

    pool.deinit();
    app.msgSend(void, "run", .{}); // never returns; terminate: exits the process
}

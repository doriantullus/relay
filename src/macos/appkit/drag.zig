//! drag — drag & drop glue for table panes (M2 scope).
//!
//! Incoming: Finder file drops (public.file-url) and internal pane-to-pane
//! row drags (custom pasteboard type carrying pane id + row indexes) onto a
//! table_source.TableView. Outgoing: row drag source for pane-to-pane moves.
//!
//! Outgoing NSFilePromiseProvider (drag a remote file *to* Finder) is a
//! documented stub — see enableOutgoingFilePromises.
//!
//! All selector strings live in relay_mac (law). Main thread only.

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

const table_source = @import("table_source.zig");
const TableView = table_source.TableView;
const NSInteger = table_source.NSInteger;
const NSUInteger = table_source.NSUInteger;
const nsStr = table_source.nsStr;
const getClass = table_source.getClass;

/// UTI of Finder file drops.
pub const file_url_type: [*:0]const u8 = "public.file-url";
/// Custom pasteboard type for internal pane-to-pane row drags. Each dragged
/// row is one pasteboard item whose data is encodePaneRow(pane, row).
pub const pane_rows_type: [*:0]const u8 = "us.doriantull.relay.pane-rows";

// NSDragOperation values (AppKit).
const ns_drag_none: NSUInteger = 0;
const ns_drag_copy: NSUInteger = 1;
const ns_drag_move: NSUInteger = 16;

// NSTableViewDropOperation: on = 0, above = 1.
const ns_drop_on: NSUInteger = 0;

pub const Operation = enum {
    none,
    copy,
    move,

    fn toNSDragOperation(self: Operation) NSUInteger {
        return switch (self) {
            .none => ns_drag_none,
            .copy => ns_drag_copy,
            .move => ns_drag_move,
        };
    }
};

pub const Payload = enum { files, pane_rows };

/// Where the drop landed. `on_row=true` means dropped ON the row (e.g. into
/// a directory); false means above/between rows or on the whole table
/// (`row=null` for whole-table drops).
pub const DropTarget = struct {
    row: ?usize,
    on_row: bool,
};

/// Drop vtable the app implements; stored on the TableView. All slices are
/// valid only for the duration of the callback.
pub const DropHandler = struct {
    ctx: *anyopaque,
    /// Called repeatedly while the drag hovers. Return .none to refuse.
    validate: *const fn (ctx: *anyopaque, payload: Payload, target: DropTarget) Operation,
    /// Finder files dropped; absolute filesystem paths.
    acceptFiles: ?*const fn (ctx: *anyopaque, paths: []const []const u8, target: DropTarget) bool = null,
    /// Internal rows dropped from another (or the same) pane.
    acceptPaneRows: ?*const fn (ctx: *anyopaque, source_pane: u32, rows: []const u32, target: DropTarget) bool = null,
};

// ---------------------------------------------------------------------------
// Pane-row payload codec (pure; unit-tested headless).
// ---------------------------------------------------------------------------
pub const PaneRow = struct { pane: u32, row: u32 };

pub fn encodePaneRow(pane: u32, row: u32) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], pane, .little);
    std.mem.writeInt(u32, out[4..8], row, .little);
    return out;
}

pub fn decodePaneRow(bytes: []const u8) ?PaneRow {
    if (bytes.len != 8) return null;
    return .{
        .pane = std.mem.readInt(u32, bytes[0..4], .little),
        .row = std.mem.readInt(u32, bytes[4..8], .little),
    };
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

/// Adds the NSTableViewDataSource drag/drop IMPs to the RelayTableHelper
/// class. Called exactly once by table_source.ensureClasses() (the class may
/// already be registered; class_addMethod after registration is legal).
pub fn addTableDropMethods(helper_class: objc.Class) void {
    if (!helper_class.addMethod(
        "tableView:validateDrop:proposedRow:proposedDropOperation:",
        helperValidateDrop,
    )) @panic("addMethod(tableView:validateDrop:...)");
    if (!helper_class.addMethod(
        "tableView:acceptDrop:row:dropOperation:",
        helperAcceptDrop,
    )) @panic("addMethod(tableView:acceptDrop:...)");
    if (!helper_class.addMethod(
        "tableView:pasteboardWriterForRow:",
        helperPasteboardWriterForRow,
    )) @panic("addMethod(tableView:pasteboardWriterForRow:)");
}

/// Accept incoming drops (Finder files + internal pane rows) on a table.
pub fn attachDropHandler(tv: *TableView, handler: DropHandler) void {
    tv.drop = handler;
    const types = getClass("NSMutableArray").msgSend(objc.Object, "array", .{});
    types.msgSend(void, "addObject:", .{nsStr(file_url_type)});
    types.msgSend(void, "addObject:", .{nsStr(pane_rows_type)});
    objc.Object.fromId(tv.tableHandle()).msgSend(void, "registerForDraggedTypes:", .{types});
}

/// Make the table's rows draggable as internal pane-to-pane payloads.
/// `pane_id` identifies this pane in the receiver's acceptPaneRows callback.
pub fn enableRowDragSource(tv: *TableView, pane_id: u32) void {
    tv.drag_pane_id = pane_id;
    const table = objc.Object.fromId(tv.tableHandle());
    table.msgSend(void, "setDraggingSourceOperationMask:forLocal:", .{
        ns_drag_copy | ns_drag_move, true,
    });
}

/// OUTGOING file promises (dragging a remote file to Finder) — NOT
/// IMPLEMENTED in M2; budget went to the incoming paths. Returns
/// error.NotImplemented so callers cannot silently depend on it.
///
/// What phase 3 must add, precisely:
///   1. A runtime-defined NSFilePromiseProvider delegate class implementing
///      `filePromiseProvider:fileNameForType:` (map row -> remote file name)
///      and `filePromiseProvider:writePromiseToURL:completionHandler:`
///      (enqueue a download to the destination URL on the transfer queue,
///      then invoke the ObjC completion block with nil-or-NSError — needs a
///      Block *invocation* helper, i.e. calling block->invoke(block, ...),
///      which zig-objc does not provide; ~10 lines of extern struct).
///   2. `tableView:pasteboardWriterForRow:` must return an
///      NSFilePromiseProvider (initWithFileType:delegate:) instead of the
///      plain NSPasteboardItem when the drag may leave the app; the file
///      type should be the UTType of the remote entry (fallback
///      "public.data").
///   3. An NSOperationQueue for `operationQueueForFilePromiseProvider...`
///      marshaled back onto the core event loop, and cancellation plumbed
///      through relay_core's CancelToken when the promise is abandoned.
pub fn enableOutgoingFilePromises(tv: *TableView) error{NotImplemented}!void {
    _ = tv;
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// IMPs (added to RelayTableHelper)
// ---------------------------------------------------------------------------
fn tvFromHelper(target: c.id) *TableView {
    const raw = c.object_getIvar(target, table_source.helperStateIvar()) orelse
        @panic("relay drag: helper state ivar is null");
    return @ptrCast(@alignCast(raw));
}

fn payloadKind(pasteboard: objc.Object) ?Payload {
    const pane_arr = getClass("NSArray").msgSend(objc.Object, "arrayWithObject:", .{nsStr(pane_rows_type)});
    if (pasteboard.msgSend(c.id, "availableTypeFromArray:", .{pane_arr}) != null)
        return .pane_rows;
    const file_arr = getClass("NSArray").msgSend(objc.Object, "arrayWithObject:", .{nsStr(file_url_type)});
    if (pasteboard.msgSend(c.id, "availableTypeFromArray:", .{file_arr}) != null)
        return .files;
    return null;
}

fn dropTarget(row: NSInteger, drop_op: NSUInteger) DropTarget {
    return .{
        .row = if (row < 0) null else @intCast(row),
        .on_row = drop_op == ns_drop_on,
    };
}

fn helperValidateDrop(
    target: c.id,
    _: c.SEL,
    _: c.id,
    info_id: c.id,
    row: NSInteger,
    drop_op: NSUInteger,
) callconv(.c) NSUInteger {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = tvFromHelper(target);
    const handler = tv.drop orelse return ns_drag_none;
    const pasteboard = objc.Object.fromId(info_id).msgSend(objc.Object, "draggingPasteboard", .{});
    const payload = payloadKind(pasteboard) orelse return ns_drag_none;
    const op = handler.validate(handler.ctx, payload, dropTarget(row, drop_op));
    return op.toNSDragOperation();
}

fn helperAcceptDrop(
    target: c.id,
    _: c.SEL,
    _: c.id,
    info_id: c.id,
    row: NSInteger,
    drop_op: NSUInteger,
) callconv(.c) c.BOOL {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tv = tvFromHelper(target);
    const handler = tv.drop orelse return 0;
    const pasteboard = objc.Object.fromId(info_id).msgSend(objc.Object, "draggingPasteboard", .{});
    const payload = payloadKind(pasteboard) orelse return 0;
    const where = dropTarget(row, drop_op);

    var arena = std.heap.ArenaAllocator.init(tv.alloc);
    defer arena.deinit();
    const alloc = arena.allocator();

    const items = pasteboard.msgSend(objc.Object, "pasteboardItems", .{});
    const count = items.msgSend(NSUInteger, "count", .{});

    switch (payload) {
        .files => {
            const cb = handler.acceptFiles orelse return 0;
            var paths: std.ArrayList([]const u8) = .empty;
            var i: NSUInteger = 0;
            while (i < count) : (i += 1) {
                const item = items.msgSend(objc.Object, "objectAtIndex:", .{i});
                const url_str = item.msgSend(c.id, "stringForType:", .{nsStr(file_url_type)});
                if (url_str == null) continue;
                const url = getClass("NSURL").msgSend(objc.Object, "URLWithString:", .{
                    objc.Object.fromId(url_str),
                });
                if (url.value == null) continue;
                const path_ns = url.msgSend(c.id, "path", .{});
                if (path_ns == null) continue;
                const path = std.mem.span(
                    objc.Object.fromId(path_ns).msgSend([*:0]const u8, "UTF8String", .{}),
                );
                const owned = alloc.dupe(u8, path) catch return 0;
                paths.append(alloc, owned) catch return 0;
            }
            if (paths.items.len == 0) return 0;
            return if (cb(handler.ctx, paths.items, where)) 1 else 0;
        },
        .pane_rows => {
            const cb = handler.acceptPaneRows orelse return 0;
            var rows: std.ArrayList(u32) = .empty;
            var source_pane: ?u32 = null;
            var i: NSUInteger = 0;
            while (i < count) : (i += 1) {
                const item = items.msgSend(objc.Object, "objectAtIndex:", .{i});
                const data = item.msgSend(c.id, "dataForType:", .{nsStr(pane_rows_type)});
                if (data == null) continue;
                const data_obj = objc.Object.fromId(data);
                const len = data_obj.msgSend(NSUInteger, "length", .{});
                const bytes_ptr = data_obj.msgSend(?[*]const u8, "bytes", .{}) orelse continue;
                const decoded = decodePaneRow(bytes_ptr[0..@intCast(len)]) orelse continue;
                if (source_pane == null) source_pane = decoded.pane;
                rows.append(alloc, decoded.row) catch return 0;
            }
            const pane = source_pane orelse return 0;
            return if (cb(handler.ctx, pane, rows.items, where)) 1 else 0;
        },
    }
}

fn helperPasteboardWriterForRow(
    target: c.id,
    _: c.SEL,
    _: c.id,
    row: NSInteger,
) callconv(.c) c.id {
    const tv = tvFromHelper(target);
    const pane_id = tv.drag_pane_id orelse return null;
    if (row < 0) return null;

    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const payload = encodePaneRow(pane_id, @intCast(row));
        const data = getClass("NSData").msgSend(objc.Object, "dataWithBytes:length:", .{
            @as(?*const anyopaque, @ptrCast(&payload)), @as(NSUInteger, payload.len),
        });
        const item = getClass("NSPasteboardItem").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});
        _ = item.msgSend(c.BOOL, "setData:forType:", .{ data, nsStr(pane_rows_type) });
        result = item.value;
    }
    // The item was alloc/init'd (rc 1, not autoreleased): pop our pool, then
    // hand ownership to the caller's pool (retain is unnecessary here).
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
test "pane-row payload codec round-trip" {
    const bytes = encodePaneRow(2, 98_412);
    const decoded = decodePaneRow(&bytes) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 2), decoded.pane);
    try std.testing.expectEqual(@as(u32, 98_412), decoded.row);
    try std.testing.expectEqual(@as(?PaneRow, null), decodePaneRow(bytes[0..7]));
    try std.testing.expectEqual(@as(?PaneRow, null), decodePaneRow(""));
}

test "operation mapping" {
    try std.testing.expectEqual(ns_drag_none, Operation.none.toNSDragOperation());
    try std.testing.expectEqual(ns_drag_copy, Operation.copy.toNSDragOperation());
    try std.testing.expectEqual(ns_drag_move, Operation.move.toNSDragOperation());
}

test "drop target mapping" {
    const on = dropTarget(5, ns_drop_on);
    try std.testing.expectEqual(@as(?usize, 5), on.row);
    try std.testing.expect(on.on_row);
    const whole = dropTarget(-1, 1);
    try std.testing.expectEqual(@as(?usize, null), whole.row);
    try std.testing.expect(!whole.on_row);
}

test "file promises are a documented stub" {
    var tv: TableView = undefined;
    try std.testing.expectError(error.NotImplemented, enableOutgoingFilePromises(&tv));
}

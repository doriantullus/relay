//! quicklook — QLPreviewPanel wrapper (QuickLookUI framework).
//!
//! One process-wide `Preview` owns the panel's data source/delegate: a
//! runtime-kit ObjC object whose callbacks serve file URLs straight from a
//! Zig-owned path list (the temp-cache copies of remote files, or local
//! paths verbatim). The shared QLPreviewPanel itself is AppKit's; we drive
//! it directly (dataSource + makeKeyAndOrderFront) instead of through the
//! responder-chain `acceptsPreviewPanelControl:` dance — Relay has exactly
//! one preview source, so there is nothing to negotiate.
//!
//! Spacebar integration: the integrator binds the `file.quickLook` command
//! to `Preview.toggleCommand` (CommandRegistry handler shape) and feeds the
//! current selection through `setItems` whenever it changes — the panel
//! follows live via reloadData, exactly like Finder.
//!
//! Headless-safe: everything except `show` (which fronts a real panel
//! window) is exercised by unit tests, including the data-source IMPs.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("foundation.zig");
const runtime = @import("runtime.zig");

const c = objc.c;
const Allocator = std.mem.Allocator;
const NSInteger = foundation.NSInteger;

const log = std.log.scoped(.quicklook);

// ---------------------------------------------------------------------------
// Data source / delegate class (defined once per process)
// ---------------------------------------------------------------------------

var g_source_class: ?runtime.DefinedClass = null;

fn sourceClass() runtime.DefinedClass {
    if (g_source_class) |dc| return dc;
    const dc = runtime.defineClass("RelayQLSource", "NSObject", &.{}, .{
        // QLPreviewPanelDataSource
        .{ "numberOfPreviewItemsInPreviewPanel:", srcCount },
        .{ "previewPanel:previewItemAtIndex:", srcItemAt },
        // QLPreviewPanelDelegate (zoom-from rect; zero = center zoom)
        .{ "previewPanel:sourceFrameOnScreenForPreviewItem:", srcZoomFrame },
    }) catch @panic("relay_mac/quicklook: failed to define RelayQLSource");
    g_source_class = dc;
    return dc;
}

fn srcCount(target: c.id, _: c.SEL, _: c.id) callconv(.c) NSInteger {
    const self = sourceClass().state(Preview, target);
    return @intCast(self.items.items.len);
}

/// Returns an autoreleased NSURL (id<QLPreviewItem>); the retain/pop/
/// autorelease dance keeps it alive in the panel's event-loop pool.
fn srcItemAt(target: c.id, _: c.SEL, _: c.id, index: NSInteger) callconv(.c) c.id {
    const pool = foundation.AutoreleasePool.init();
    const self = sourceClass().state(Preview, target);
    if (index < 0 or index >= self.items.items.len) {
        pool.deinit();
        return foundation.nil;
    }
    const url = foundation.fileURL(self.items.items[@intCast(index)]);
    return foundation.keepAcrossPool(pool, url.value);
}

fn srcZoomFrame(_: c.id, _: c.SEL, _: c.id, _: c.id) callconv(.c) foundation.NSRect {
    return .{}; // no source rect: the panel zooms from the center
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

pub const Preview = struct {
    gpa: Allocator,
    /// Local file paths in panel order; every slice gpa-owned.
    items: std.ArrayList([]u8) = .empty,
    /// Retained RelayQLSource instance (rc 1, ours).
    source: objc.Object,

    /// Heap-pinned: the relayState ivar in `source` points back at this.
    pub fn create(gpa: Allocator) error{OutOfMemory}!*Preview {
        const self = try gpa.create(Preview);
        self.* = .{ .gpa = gpa, .source = undefined };
        self.source = sourceClass().newWithState(self);
        return self;
    }

    pub fn destroy(self: *Preview) void {
        self.close();
        // Detach from a live panel so AppKit never calls into freed state.
        if (panelExists()) {
            const panel = sharedPanel();
            if (panel.msgSend(c.id, "dataSource", .{}) == self.source.value) {
                panel.msgSend(void, "setDataSource:", .{foundation.nil});
                panel.msgSend(void, "setDelegate:", .{foundation.nil});
            }
        }
        self.source.msgSend(void, "release", .{});
        self.clearItems();
        self.items.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    // ------------------------------------------------------------------ //
    // Item list

    /// Replace the panel's item list with copies of `paths` (absolute local
    /// file paths). A visible panel reloads in place; a hidden one just
    /// picks the list up on the next `show`.
    pub fn setItems(self: *Preview, paths: []const []const u8) error{OutOfMemory}!void {
        var fresh: std.ArrayList([]u8) = .empty;
        errdefer {
            for (fresh.items) |p| self.gpa.free(p);
            fresh.deinit(self.gpa);
        }
        try fresh.ensureTotalCapacityPrecise(self.gpa, paths.len);
        for (paths) |p| fresh.appendAssumeCapacity(try self.gpa.dupe(u8, p));

        self.clearItems();
        self.items.deinit(self.gpa);
        self.items = fresh;
        self.refresh();
    }

    pub fn itemCount(self: *const Preview) usize {
        return self.items.items.len;
    }

    fn clearItems(self: *Preview) void {
        for (self.items.items) |p| self.gpa.free(p);
        self.items.clearRetainingCapacity();
    }

    // ------------------------------------------------------------------ //
    // Panel control

    /// Front the shared panel over the current item list. No-op (logged)
    /// when QuickLookUI is unavailable — never a crash.
    pub fn show(self: *Preview) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        if (panelClass() == null) {
            log.warn("QLPreviewPanel unavailable; Quick Look disabled", .{});
            return;
        }
        const panel = sharedPanel();
        panel.msgSend(void, "setDataSource:", .{self.source});
        panel.msgSend(void, "setDelegate:", .{self.source});
        panel.msgSend(void, "reloadData", .{});
        panel.msgSend(void, "setCurrentPreviewItemIndex:", .{@as(NSInteger, 0)});
        panel.msgSend(void, "makeKeyAndOrderFront:", .{foundation.nil});
    }

    /// Reload a visible panel after the item list changed (selection moved,
    /// download finished). Hidden/never-created panels: no-op.
    pub fn refresh(self: *Preview) void {
        _ = self;
        if (!isVisible()) return;
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        sharedPanel().msgSend(void, "reloadData", .{});
    }

    /// Dismiss the panel if it is up. Safe when it never existed.
    pub fn close(self: *Preview) void {
        _ = self;
        if (!isVisible()) return;
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        sharedPanel().msgSend(void, "orderOut:", .{foundation.nil});
    }

    /// Finder spacebar semantics: visible → close, hidden → show.
    pub fn toggle(self: *Preview) void {
        if (isVisible()) self.close() else self.show();
    }

    /// CommandRegistry handler (`*const fn (?*anyopaque) void`): the
    /// integrator binds this to the `file.quickLook` command and routes the
    /// browser's spacebar key to that command.
    pub fn toggleCommand(ctx: ?*anyopaque) void {
        const self: *Preview = @ptrCast(@alignCast(ctx.?));
        self.toggle();
    }
};

// ---------------------------------------------------------------------------
// Shared-panel helpers
// ---------------------------------------------------------------------------

/// Null when QuickLookUI is not linked/loaded (lookup, not panic: Quick
/// Look degrades to a no-op instead of taking the app down).
fn panelClass() ?objc.Class {
    return objc.getClass("QLPreviewPanel");
}

fn sharedPanel() objc.Object {
    const cls = panelClass() orelse unreachable; // callers check first
    return cls.msgSend(objc.Object, "sharedPreviewPanel", .{});
}

/// True once any code touched the shared panel (AppKit allocates lazily).
pub fn panelExists() bool {
    const cls = panelClass() orelse return false;
    return foundation.toBool(cls.msgSend(foundation.BOOL, "sharedPreviewPanelExists", .{}));
}

/// True while the shared panel is on screen.
pub fn isVisible() bool {
    if (!panelExists()) return false;
    return foundation.toBool(sharedPanel().msgSend(foundation.BOOL, "isVisible", .{}));
}

// ---------------------------------------------------------------------------
// Tests (headless: class + IMPs + item bookkeeping; the panel itself is
// only fronted by the app / the visual check, never by unit tests).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "QuickLookUI is linked: QLPreviewPanel resolves, no panel side effects" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    try testing.expect(panelClass() != null);
    // Asking "exists" must not create the panel.
    _ = panelExists();
    try testing.expect(!isVisible());
}

test "data source IMPs serve count and file URLs from Zig state" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const qv = try Preview.create(testing.allocator);
    defer qv.destroy();

    // Empty list: count 0, out-of-range index answers nil.
    try testing.expectEqual(
        @as(NSInteger, 0),
        qv.source.msgSend(NSInteger, "numberOfPreviewItemsInPreviewPanel:", .{foundation.nil}),
    );
    try testing.expectEqual(
        foundation.nil,
        qv.source.msgSend(c.id, "previewPanel:previewItemAtIndex:", .{ foundation.nil, @as(NSInteger, 0) }),
    );

    try qv.setItems(&.{ "/usr/bin/true", "/etc/hosts" });
    try testing.expectEqual(@as(usize, 2), qv.itemCount());
    try testing.expectEqual(
        @as(NSInteger, 2),
        qv.source.msgSend(NSInteger, "numberOfPreviewItemsInPreviewPanel:", .{foundation.nil}),
    );

    const item = qv.source.msgSend(c.id, "previewPanel:previewItemAtIndex:", .{
        foundation.nil, @as(NSInteger, 1),
    });
    try testing.expect(item != null);
    const back = try foundation.pathFromURL(testing.allocator, objc.Object.fromId(item));
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("/etc/hosts", back);

    try testing.expectEqual(
        foundation.nil,
        qv.source.msgSend(c.id, "previewPanel:previewItemAtIndex:", .{ foundation.nil, @as(NSInteger, 2) }),
    );
    try testing.expectEqual(
        foundation.nil,
        qv.source.msgSend(c.id, "previewPanel:previewItemAtIndex:", .{ foundation.nil, @as(NSInteger, -1) }),
    );

    // Delegate zoom-frame override dispatches and yields the zero rect.
    const frame = qv.source.msgSend(foundation.NSRect, "previewPanel:sourceFrameOnScreenForPreviewItem:", .{
        foundation.nil, foundation.nil,
    });
    try testing.expectEqual(@as(foundation.CGFloat, 0), frame.size.width);
}

test "setItems replaces the list (old paths freed, new ones served)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const qv = try Preview.create(testing.allocator);
    defer qv.destroy();

    try qv.setItems(&.{"/tmp/a.txt"});
    try qv.setItems(&.{ "/tmp/b.txt", "/tmp/c.txt", "/tmp/d.txt" });
    try testing.expectEqual(@as(usize, 3), qv.itemCount());

    const item = qv.source.msgSend(c.id, "previewPanel:previewItemAtIndex:", .{
        foundation.nil, @as(NSInteger, 0),
    });
    const back = try foundation.pathFromURL(testing.allocator, objc.Object.fromId(item));
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("/tmp/b.txt", back);

    try qv.setItems(&.{});
    try testing.expectEqual(@as(usize, 0), qv.itemCount());
}

test "close on a never-created panel is a no-op (toggle precondition)" {
    const qv = try Preview.create(testing.allocator);
    defer qv.destroy();
    qv.close();
    try testing.expect(!isVisible());
}

test {
    testing.refAllDecls(@This());
}

//! toolbar — NSToolbar wrapper: items by identifier (label, SF Symbol, Zig
//! action), flexible space, install on window, per-item enable/disable.
//!
//! Main thread only. All selector strings live in relay_mac (law).

const std = @import("std");
const objc = @import("objc");
const c = objc.c;

// Shared ABI helpers: single definitions live in relay_mac foundation.zig,
// re-exported through table_source.zig (deduped in M2 phase 3).
const ts = @import("table_source.zig");
const getClass = ts.getClass;
const nsStr = ts.nsStr;

/// AppKit's standard flexible-space identifier (NSToolbarFlexibleSpaceItemIdentifier).
pub const flexible_space_identifier: [:0]const u8 = "NSToolbarFlexibleSpaceItem";
/// AppKit's standard fixed-space identifier (NSToolbarSpaceItemIdentifier).
pub const space_identifier: [:0]const u8 = "NSToolbarSpaceItem";

pub const ItemSpec = struct {
    /// Unique within the toolbar; also the customization identity.
    identifier: [:0]const u8,
    label: [:0]const u8 = "",
    /// SF Symbol name for the item image.
    symbol: ?[:0]const u8 = null,
    tooltip: ?[:0]const u8 = null,
    action: ?*const fn (ctx: *anyopaque) void = null,
    /// Popup item: returns an NSMenu (owned by the app/menu registry; null
    /// = plain button after all). The item materializes as an
    /// NSMenuToolbarItem showing the menu on click; `action` is ignored.
    menu_provider: ?*const fn (ctx: *anyopaque) ?c.id = null,
    /// Standard AppKit space items are instantiated by AppKit itself.
    standard: bool = false,
};

pub fn flexibleSpace() ItemSpec {
    return .{ .identifier = flexible_space_identifier, .standard = true };
}

pub fn space() ItemSpec {
    return .{ .identifier = space_identifier, .standard = true };
}

pub fn specIndexForIdentifier(items: []const ItemSpec, identifier: []const u8) ?usize {
    for (items, 0..) |spec, i| {
        if (std.mem.eql(u8, spec.identifier, identifier)) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Runtime delegate class
// ---------------------------------------------------------------------------
var g_classes_ready = false;
var g_helper_class: objc.Class = undefined;
var g_helper_state_ivar: c.Ivar = null;

fn ensureClasses() void {
    if (g_classes_ready) return;
    g_classes_ready = true;

    const cls = objc.allocateClassPair(getClass("NSObject"), "RelayToolbarHelper") orelse
        @panic("allocateClassPair(RelayToolbarHelper)");
    if (!cls.addIvar("relayState")) @panic("addIvar(RelayToolbarHelper)");
    if (!cls.addMethod("toolbarAllowedItemIdentifiers:", helperAllowedIdentifiers))
        @panic("addMethod(toolbarAllowedItemIdentifiers:)");
    if (!cls.addMethod("toolbarDefaultItemIdentifiers:", helperDefaultIdentifiers))
        @panic("addMethod(toolbarDefaultItemIdentifiers:)");
    if (!cls.addMethod(
        "toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:",
        helperItemForIdentifier,
    )) @panic("addMethod(toolbar:itemForItemIdentifier:...)");
    if (!cls.addMethod("onRelayToolbarAction:", helperOnAction))
        @panic("addMethod(onRelayToolbarAction:)");
    objc.registerClassPair(cls);
    g_helper_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
    if (g_helper_state_ivar == null) @panic("ivar lookup (RelayToolbarHelper)");
    g_helper_class = cls;
}

fn stateFromIvar(target: c.id) *Toolbar {
    const raw = c.object_getIvar(target, g_helper_state_ivar) orelse
        @panic("relay toolbar state ivar is null");
    return @ptrCast(@alignCast(raw));
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------
pub const Toolbar = struct {
    alloc: std.mem.Allocator,
    ctx: *anyopaque,
    items: []ItemSpec,
    enabled: []bool,
    toolbar: objc.Object,
    helper: objc.Object,

    /// `items` is duplicated; the identifier/label strings must outlive the
    /// Toolbar (string literals in practice).
    pub fn init(
        alloc: std.mem.Allocator,
        identifier: [:0]const u8,
        ctx: *anyopaque,
        items: []const ItemSpec,
    ) !*Toolbar {
        ensureClasses();

        const self = try alloc.create(Toolbar);
        errdefer alloc.destroy(self);
        const owned_items = try alloc.dupe(ItemSpec, items);
        errdefer alloc.free(owned_items);
        const enabled = try alloc.alloc(bool, items.len);
        errdefer alloc.free(enabled);
        @memset(enabled, true);

        const helper = g_helper_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});

        self.* = .{
            .alloc = alloc,
            .ctx = ctx,
            .items = owned_items,
            .enabled = enabled,
            .toolbar = undefined,
            .helper = helper,
        };
        c.object_setIvar(helper.value, g_helper_state_ivar, @ptrCast(self));

        const toolbar = getClass("NSToolbar").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithIdentifier:", .{nsStr(identifier.ptr)});
        toolbar.msgSend(void, "setAllowsUserCustomization:", .{false});
        toolbar.msgSend(void, "setDelegate:", .{helper});
        self.toolbar = toolbar;

        return self;
    }

    pub fn deinit(self: *Toolbar) void {
        self.toolbar.msgSend(void, "setDelegate:", .{@as(c.id, null)});
        self.toolbar.msgSend(void, "release", .{});
        self.helper.msgSend(void, "release", .{});
        self.alloc.free(self.items);
        self.alloc.free(self.enabled);
        self.alloc.destroy(self);
    }

    pub fn installOnWindow(self: *Toolbar, window: c.id) void {
        objc.Object.fromId(window).msgSend(void, "setToolbar:", .{self.toolbar});
    }

    /// Enable/disable a button item; remembered for items AppKit has not
    /// materialized yet.
    pub fn setItemEnabled(self: *Toolbar, identifier: []const u8, enabled: bool) void {
        const idx = specIndexForIdentifier(self.items, identifier) orelse return;
        self.enabled[idx] = enabled;

        const pool = objc.AutoreleasePool.init();
        defer pool.deinit();
        const live = self.toolbar.msgSend(objc.Object, "items", .{});
        const count = live.msgSend(ts.NSUInteger, "count", .{});
        var i: ts.NSUInteger = 0;
        while (i < count) : (i += 1) {
            const item = live.msgSend(objc.Object, "objectAtIndex:", .{i});
            const ident = item.msgSend(objc.Object, "itemIdentifier", .{});
            const ident_s = std.mem.span(ident.msgSend([*:0]const u8, "UTF8String", .{}));
            if (std.mem.eql(u8, ident_s, identifier)) {
                item.msgSend(void, "setEnabled:", .{enabled});
                return;
            }
        }
    }

    fn identifierArray(self: *Toolbar) objc.Object {
        const arr = getClass("NSMutableArray").msgSend(objc.Object, "array", .{});
        for (self.items) |spec| arr.msgSend(void, "addObject:", .{nsStr(spec.identifier.ptr)});
        return arr;
    }
};

// ---------------------------------------------------------------------------
// Delegate IMPs
// ---------------------------------------------------------------------------
fn identifiersImp(target: c.id) c.id {
    const tb = stateFromIvar(target);
    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        result = tb.identifierArray().value;
    }
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

fn helperAllowedIdentifiers(target: c.id, _: c.SEL, _: c.id) callconv(.c) c.id {
    return identifiersImp(target);
}

fn helperDefaultIdentifiers(target: c.id, _: c.SEL, _: c.id) callconv(.c) c.id {
    return identifiersImp(target);
}

fn helperItemForIdentifier(
    target: c.id,
    _: c.SEL,
    _: c.id,
    identifier_id: c.id,
    _: c.BOOL,
) callconv(.c) c.id {
    const tb = stateFromIvar(target);

    const pool = objc.AutoreleasePool.init();
    var result: c.id = null;
    {
        const ident = objc.Object.fromId(identifier_id);
        const ident_s = std.mem.span(ident.msgSend([*:0]const u8, "UTF8String", .{}));
        if (specIndexForIdentifier(tb.items, ident_s)) |i| {
            const spec = tb.items[i];
            // Standard space items are instantiated by AppKit itself.
            if (!spec.standard) {
                // Popup specs become NSMenuToolbarItem (an NSToolbarItem
                // subclass that shows its menu on click).
                const item_class = if (spec.menu_provider != null)
                    getClass("NSMenuToolbarItem")
                else
                    getClass("NSToolbarItem");
                const item = item_class.msgSend(objc.Object, "alloc", .{})
                    .msgSend(objc.Object, "initWithItemIdentifier:", .{ident});
                // Hand the alloc/init +1 to the inner pool so the dance
                // below transfers exactly one reference to the caller.
                _ = item.msgSend(c.id, "autorelease", .{});
                item.msgSend(void, "setLabel:", .{nsStr(spec.label.ptr)});
                item.msgSend(void, "setPaletteLabel:", .{nsStr(spec.label.ptr)});
                if (spec.tooltip) |tip| item.msgSend(void, "setToolTip:", .{nsStr(tip.ptr)});
                if (spec.symbol) |symbol| {
                    if (ts.systemSymbolImage(symbol.ptr)) |img| {
                        item.msgSend(void, "setImage:", .{objc.Object.fromId(img)});
                    }
                }
                item.msgSend(void, "setBordered:", .{true});
                if (spec.menu_provider) |provider| {
                    if (provider(tb.ctx)) |menu_id| {
                        item.msgSend(void, "setMenu:", .{objc.Object.fromId(menu_id)});
                        item.msgSend(void, "setShowsIndicator:", .{true});
                    }
                } else {
                    item.msgSend(void, "setTarget:", .{objc.Object.fromId(target)});
                    item.msgSend(void, "setAction:", .{objc.sel("onRelayToolbarAction:")});
                }
                item.msgSend(void, "setAutovalidates:", .{false});
                item.msgSend(void, "setEnabled:", .{tb.enabled[i]});
                result = item.value;
            }
        }
    }
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "retain", .{});
    pool.deinit();
    if (result) |v| _ = objc.Object.fromId(v).msgSend(c.id, "autorelease", .{});
    return result;
}

fn helperOnAction(target: c.id, _: c.SEL, sender: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const tb = stateFromIvar(target);
    if (sender == null) return;
    const ident = objc.Object.fromId(sender).msgSend(objc.Object, "itemIdentifier", .{});
    const ident_s = std.mem.span(ident.msgSend([*:0]const u8, "UTF8String", .{}));
    const idx = specIndexForIdentifier(tb.items, ident_s) orelse return;
    const action = tb.items[idx].action orelse return;
    action(tb.ctx);
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
test "spec lookup by identifier" {
    const items = [_]ItemSpec{
        .{ .identifier = "connect", .label = "Connect" },
        flexibleSpace(),
        .{ .identifier = "transfers", .label = "Transfers" },
    };
    try std.testing.expectEqual(@as(?usize, 0), specIndexForIdentifier(&items, "connect"));
    try std.testing.expectEqual(@as(?usize, 2), specIndexForIdentifier(&items, "transfers"));
    try std.testing.expectEqual(@as(?usize, null), specIndexForIdentifier(&items, "nope"));
    try std.testing.expect(items[1].standard);
    try std.testing.expectEqualStrings(flexible_space_identifier, items[1].identifier);
}

test "toolbar init/deinit + identifier arrays through ObjC dispatch (headless)" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const Hooks = struct {
        var fired: usize = 0;
        fn onConnect(_: *anyopaque) void {
            fired += 1;
        }
    };
    var ctx: u8 = 0;

    const tb = try Toolbar.init(std.testing.allocator, "RelayMainToolbar", &ctx, &.{
        .{ .identifier = "connect", .label = "Connect", .symbol = "bolt", .action = Hooks.onConnect },
        flexibleSpace(),
    });
    defer tb.deinit();

    // Delegate methods through real objc_msgSend dispatch.
    const allowed = tb.helper.msgSend(objc.Object, "toolbarAllowedItemIdentifiers:", .{@as(c.id, null)});
    try std.testing.expectEqual(@as(ts.NSUInteger, 2), allowed.msgSend(ts.NSUInteger, "count", .{}));

    const item = tb.helper.msgSend(
        c.id,
        "toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:",
        .{ @as(c.id, null), nsStr("connect").value, @as(c.BOOL, 1) },
    );
    try std.testing.expect(item != null);

    // Standard items are left to AppKit.
    const std_item = tb.helper.msgSend(
        c.id,
        "toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:",
        .{ @as(c.id, null), nsStr(flexible_space_identifier.ptr).value, @as(c.BOOL, 1) },
    );
    try std.testing.expect(std_item == null);

    // Action dispatch via the target/action pair.
    tb.helper.msgSend(void, "onRelayToolbarAction:", .{item});
    try std.testing.expectEqual(@as(usize, 1), Hooks.fired);

    tb.setItemEnabled("connect", false);
    try std.testing.expect(!tb.enabled[0]);
}

test "menu_provider specs materialize as NSMenuToolbarItem carrying the menu" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const Hooks = struct {
        var menu_obj: c.id = null;
        fn provide(_: *anyopaque) ?c.id {
            return menu_obj;
        }
    };
    const menu = getClass("NSMenu").msgSend(objc.Object, "new", .{});
    defer menu.msgSend(void, "release", .{});
    Hooks.menu_obj = menu.value;

    var ctx: u8 = 0;
    const tb = try Toolbar.init(std.testing.allocator, "RelayMenuToolbarTest", &ctx, &.{
        .{ .identifier = "view", .label = "View", .menu_provider = Hooks.provide },
    });
    defer tb.deinit();

    const item = tb.helper.msgSend(
        c.id,
        "toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:",
        .{ @as(c.id, null), nsStr("view").value, @as(c.BOOL, 1) },
    );
    try std.testing.expect(item != null);
    const got = objc.Object.fromId(item).msgSend(c.id, "menu", .{});
    try std.testing.expectEqual(menu.value, got);
}

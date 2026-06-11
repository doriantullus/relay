//! menu — declarative NSMenu builder + the shared MenuTarget dispatcher.
//!
//! Feature code describes menus as a Zig tree of Items; actions are either
//! first-responder selectors (nil target, validated through the responder
//! chain — every selector string still lives in relay_mac call sites) or Zig
//! callbacks dispatched through ONE shared runtime-defined MenuTarget class:
//! each callback registers in a Registry and rides on the NSMenuItem tag.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");

const c = objc.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;

// ---------------------------------------------------------------------------
// Item tree
// ---------------------------------------------------------------------------
pub const Modifiers = packed struct {
    command: bool = true,
    shift: bool = false,
    option: bool = false,
    control: bool = false,

    pub fn mask(self: Modifiers) NSUInteger {
        var m: NSUInteger = 0;
        if (self.shift) m |= 1 << 17;
        if (self.control) m |= 1 << 18;
        if (self.option) m |= 1 << 19;
        if (self.command) m |= 1 << 20;
        return m;
    }
};

/// Key-equivalent strings for non-printing keys (NSEvent function keys).
pub const Keys = struct {
    pub const up: [:0]const u8 = "\u{F700}";
    pub const down: [:0]const u8 = "\u{F701}";
    pub const left: [:0]const u8 = "\u{F702}";
    pub const right: [:0]const u8 = "\u{F703}";
    pub const backspace: [:0]const u8 = "\u{0008}";
    pub const delete_forward: [:0]const u8 = "\u{F728}";
    pub const escape: [:0]const u8 = "\u{001B}";
    pub const ret: [:0]const u8 = "\r";
    pub const tab: [:0]const u8 = "\t";
};

pub const Callback = struct {
    ctx: ?*anyopaque = null,
    f: *const fn (ctx: ?*anyopaque) void,
};

pub const Action = union(enum) {
    /// No action (disabled under autoenable unless it has a submenu).
    none,
    /// First-responder action: nil target, resolved via the responder chain.
    sel: [:0]const u8,
    /// Zig callback via the shared MenuTarget.
    call: Callback,
};

pub const Leaf = struct {
    title: [:0]const u8,
    action: Action = .none,
    key: [:0]const u8 = "",
    mods: Modifiers = .{},
};

pub const Submenu = struct {
    title: [:0]const u8,
    items: []const Item,
};

pub const Item = union(enum) {
    separator,
    leaf: Leaf,
    submenu: Submenu,

    pub fn sel(title: [:0]const u8, selector: [:0]const u8, key: [:0]const u8, mods: Modifiers) Item {
        return .{ .leaf = .{ .title = title, .action = .{ .sel = selector }, .key = key, .mods = mods } };
    }

    pub fn call(title: [:0]const u8, cb: Callback, key: [:0]const u8, mods: Modifiers) Item {
        return .{ .leaf = .{ .title = title, .action = .{ .call = cb }, .key = key, .mods = mods } };
    }

    pub fn sub(title: [:0]const u8, items: []const Item) Item {
        return .{ .submenu = .{ .title = title, .items = items } };
    }
};

/// A top-level menu in the menu bar.
pub const MenuSpec = struct {
    title: [:0]const u8,
    items: []const Item,
};

// ---------------------------------------------------------------------------
// Registry + shared MenuTarget class
// ---------------------------------------------------------------------------
var g_target_class: ?runtime.DefinedClass = null;

fn targetClass() runtime.DefinedClass {
    if (g_target_class) |dc| return dc;
    const dc = runtime.defineClass("RelayMenuTarget", "NSObject", &.{}, .{
        .{ "relayMenuAction:", menuActionImp },
    }) catch @panic("relay_mac/menu: failed to define RelayMenuTarget");
    g_target_class = dc;
    return dc;
}

fn menuActionImp(target: c.id, _: c.SEL, sender: c.id) callconv(.c) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const reg = targetClass().state(Registry, target);
    const tag = objc.Object.fromId(sender).msgSend(NSInteger, "tag", .{});
    if (tag < 0 or tag >= @as(NSInteger, @intCast(reg.entries.items.len))) return;
    const cb = reg.entries.items[@intCast(tag)];
    cb.f(cb.ctx);
}

/// Owns the tag→callback table and the shared MenuTarget instance. One per
/// window controller is typical; must outlive every menu built against it.
pub const Registry = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayList(Callback) = .empty,
    target: objc.Object,

    pub fn create(gpa: std.mem.Allocator) std.mem.Allocator.Error!*Registry {
        const self = try gpa.create(Registry);
        self.* = .{ .gpa = gpa, .target = undefined };
        self.target = targetClass().newWithState(self);
        return self;
    }

    pub fn destroy(self: *Registry) void {
        self.target.msgSend(void, "release", .{});
        self.entries.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    fn register(self: *Registry, cb: Callback) std.mem.Allocator.Error!NSInteger {
        try self.entries.append(self.gpa, cb);
        return @intCast(self.entries.items.len - 1);
    }
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------
/// Build an NSMenu (retain count 1, caller-owned) from an item tree.
pub fn buildMenu(
    reg: *Registry,
    title: [:0]const u8,
    items: []const Item,
) std.mem.Allocator.Error!objc.Object {
    const menu = foundation.class("NSMenu").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithTitle:", .{foundation.nsStringZ(title)});
    for (items) |item| try addItem(menu, reg, item);
    return menu;
}

/// Context menu for tables/outlines (docs/UX.md): same tree, no title.
pub fn buildContextMenu(reg: *Registry, items: []const Item) std.mem.Allocator.Error!objc.Object {
    return buildMenu(reg, "", items);
}

fn addItem(menu: objc.Object, reg: *Registry, item: Item) std.mem.Allocator.Error!void {
    switch (item) {
        .separator => {
            const sep = foundation.class("NSMenuItem").msgSend(objc.Object, "separatorItem", .{});
            menu.msgSend(void, "addItem:", .{sep});
        },
        .leaf => |leaf| _ = try addLeaf(menu, reg, leaf),
        .submenu => |sub| {
            const holder = newMenuItem(sub.title, null, "");
            const submenu = try buildMenu(reg, sub.title, sub.items);
            holder.msgSend(void, "setSubmenu:", .{submenu});
            submenu.msgSend(void, "release", .{}); // holder retains it
            menu.msgSend(void, "addItem:", .{holder});
            holder.msgSend(void, "release", .{}); // menu retains it
        },
    }
}

fn newMenuItem(title: [:0]const u8, action_sel: ?objc.Sel, key: [:0]const u8) objc.Object {
    const sel_val: c.SEL = if (action_sel) |s| s.value else null;
    return foundation.class("NSMenuItem").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithTitle:action:keyEquivalent:", .{
        foundation.nsStringZ(title), sel_val, foundation.nsStringZ(key),
    });
}

fn addLeaf(menu: objc.Object, reg: *Registry, leaf: Leaf) std.mem.Allocator.Error!objc.Object {
    const action_sel: ?objc.Sel = switch (leaf.action) {
        .none => null,
        .sel => |s| objc.sel(s),
        .call => objc.sel("relayMenuAction:"),
    };
    const item = newMenuItem(leaf.title, action_sel, leaf.key);
    if (leaf.key.len > 0) {
        item.msgSend(void, "setKeyEquivalentModifierMask:", .{leaf.mods.mask()});
    }
    if (leaf.action == .call) {
        const tag = try reg.register(leaf.action.call);
        item.msgSend(void, "setTag:", .{tag});
        item.msgSend(void, "setTarget:", .{reg.target});
    }
    menu.msgSend(void, "addItem:", .{item});
    item.msgSend(void, "release", .{}); // menu retains it
    return item;
}

// ---------------------------------------------------------------------------
// Main menu installation
// ---------------------------------------------------------------------------
pub const AppMenuSpec = struct {
    app_name: [:0]const u8,
    /// Settings… (Cmd+,) — docs/UX.md shortcut table.
    settings: Action = .none,
    about: Action = .{ .sel = "orderFrontStandardAboutPanel:" },
};

/// Build and install the whole menu bar: the app menu (About/Settings…/Quit
/// + Hide group), then `menus` in order, then a Window menu (a provided
/// MenuSpec titled "Window" is used and registered as the windows menu;
/// otherwise a standard one is appended).
pub fn installMainMenu(
    reg: *Registry,
    app_spec: AppMenuSpec,
    menus: []const MenuSpec,
) std.mem.Allocator.Error!void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const main_menu = foundation.class("NSMenu").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithTitle:", .{foundation.nsStringZ("MainMenu")});

    // --- app menu ---
    var about_buf: [96]u8 = undefined;
    var hide_buf: [96]u8 = undefined;
    var quit_buf: [96]u8 = undefined;
    const about_title = std.fmt.bufPrintZ(&about_buf, "About {s}", .{app_spec.app_name}) catch "About";
    const hide_title = std.fmt.bufPrintZ(&hide_buf, "Hide {s}", .{app_spec.app_name}) catch "Hide";
    const quit_title = std.fmt.bufPrintZ(&quit_buf, "Quit {s}", .{app_spec.app_name}) catch "Quit";

    const app_items = [_]Item{
        .{ .leaf = .{ .title = about_title, .action = app_spec.about, .key = "" } },
        .separator,
        .{ .leaf = .{ .title = "Settings…", .action = app_spec.settings, .key = "," } },
        .separator,
        Item.sel(hide_title, "hide:", "h", .{}),
        Item.sel("Hide Others", "hideOtherApplications:", "h", .{ .option = true }),
        Item.sel("Show All", "unhideAllApplications:", "", .{}),
        .separator,
        Item.sel(quit_title, "terminate:", "q", .{}),
    };
    _ = try installTopLevel(main_menu, reg, app_spec.app_name, &app_items);

    // --- feature menus ---
    var windows_menu: ?objc.Object = null;
    for (menus) |spec| {
        const built = try installTopLevel(main_menu, reg, spec.title, spec.items);
        if (std.mem.eql(u8, spec.title, "Window")) windows_menu = built;
    }

    // --- Window menu (AppKit appends the open-windows list) ---
    if (windows_menu == null) {
        const window_items = [_]Item{
            Item.sel("Minimize", "performMiniaturize:", "m", .{}),
            Item.sel("Zoom", "performZoom:", "", .{}),
            .separator,
            Item.sel("Bring All to Front", "arrangeInFront:", "", .{}),
        };
        windows_menu = try installTopLevel(main_menu, reg, "Window", &window_items);
    }

    const app = foundation.class("NSApplication").msgSend(objc.Object, "sharedApplication", .{});
    app.msgSend(void, "setMainMenu:", .{main_menu});
    app.msgSend(void, "setWindowsMenu:", .{windows_menu.?});
    main_menu.msgSend(void, "release", .{}); // app retains it
}

fn installTopLevel(
    main_menu: objc.Object,
    reg: *Registry,
    title: [:0]const u8,
    items: []const Item,
) std.mem.Allocator.Error!objc.Object {
    const holder = newMenuItem(title, null, "");
    const submenu = try buildMenu(reg, title, items);
    holder.msgSend(void, "setSubmenu:", .{submenu});
    submenu.msgSend(void, "release", .{});
    main_menu.msgSend(void, "addItem:", .{holder});
    holder.msgSend(void, "release", .{});
    return submenu;
}

// ---------------------------------------------------------------------------
// Tests (headless: build trees, inspect NSMenuItem state, drive the target
// action exactly as AppKit would — no menu bar installation required).
// ---------------------------------------------------------------------------
const testing = std.testing;

var g_cb_hits: u32 = 0;

fn testCallback(ctx: ?*anyopaque) void {
    g_cb_hits += 1;
    const v: *u32 = @ptrCast(@alignCast(ctx.?));
    v.* += 10;
}

test "buildMenu: titles, keys, separators, submenus, tags" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const reg = try Registry.create(testing.allocator);
    defer reg.destroy();

    var cb_state: u32 = 0;
    const sub_items = [_]Item{
        Item.sel("Back", "goBack:", "[", .{}),
    };
    const items = [_]Item{
        Item.sel("Connect to Server…", "relayConnect:", "k", .{}),
        .separator,
        Item.call("Refresh", .{ .ctx = &cb_state, .f = testCallback }, "r", .{}),
        Item.sub("Go", &sub_items),
        Item.sel("Hidden Files", "relayToggleHidden:", ".", .{ .shift = true }),
    };
    const menu = try buildMenu(reg, "File", &items);
    defer menu.msgSend(void, "release", .{});

    try testing.expectEqual(@as(NSInteger, 5), menu.msgSend(NSInteger, "numberOfItems", .{}));

    const first = menu.msgSend(objc.Object, "itemAtIndex:", .{@as(NSInteger, 0)});
    const first_title = try foundation.utf8FromNSString(
        testing.allocator,
        first.msgSend(objc.Object, "title", .{}),
    );
    defer testing.allocator.free(first_title);
    try testing.expectEqualStrings("Connect to Server…", first_title);
    const key = try foundation.utf8FromNSString(
        testing.allocator,
        first.msgSend(objc.Object, "keyEquivalent", .{}),
    );
    defer testing.allocator.free(key);
    try testing.expectEqualStrings("k", key);
    try testing.expectEqual(@as(NSUInteger, 1 << 20), first.msgSend(NSUInteger, "keyEquivalentModifierMask", .{}));
    try testing.expect(first.msgSend(c.id, "target", .{}) == null); // responder chain

    const sep = menu.msgSend(objc.Object, "itemAtIndex:", .{@as(NSInteger, 1)});
    try testing.expect(foundation.toBool(sep.msgSend(foundation.BOOL, "isSeparatorItem", .{})));

    const cb_item = menu.msgSend(objc.Object, "itemAtIndex:", .{@as(NSInteger, 2)});
    try testing.expectEqual(@as(NSInteger, 0), cb_item.msgSend(NSInteger, "tag", .{}));
    try testing.expectEqual(reg.target.value, cb_item.msgSend(c.id, "target", .{}).?);

    const sub_item = menu.msgSend(objc.Object, "itemAtIndex:", .{@as(NSInteger, 3)});
    try testing.expect(foundation.toBool(sub_item.msgSend(foundation.BOOL, "hasSubmenu", .{})));
    const submenu = sub_item.msgSend(objc.Object, "submenu", .{});
    try testing.expectEqual(@as(NSInteger, 1), submenu.msgSend(NSInteger, "numberOfItems", .{}));

    const shifted = menu.msgSend(objc.Object, "itemAtIndex:", .{@as(NSInteger, 4)});
    try testing.expectEqual(
        @as(NSUInteger, (1 << 17) | (1 << 20)),
        shifted.msgSend(NSUInteger, "keyEquivalentModifierMask", .{}),
    );

    // Drive the action exactly as AppKit would: [target relayMenuAction:item].
    reg.target.msgSend(void, "relayMenuAction:", .{cb_item});
    try testing.expectEqual(@as(u32, 1), g_cb_hits);
    try testing.expectEqual(@as(u32, 10), cb_state);

    // Out-of-range tags are ignored.
    cb_item.msgSend(void, "setTag:", .{@as(NSInteger, 999)});
    reg.target.msgSend(void, "relayMenuAction:", .{cb_item});
    try testing.expectEqual(@as(u32, 1), g_cb_hits);
}

test "modifier masks" {
    try testing.expectEqual(@as(NSUInteger, 1 << 20), (Modifiers{}).mask());
    try testing.expectEqual(
        @as(NSUInteger, (1 << 19) | (1 << 20)),
        (Modifiers{ .option = true }).mask(),
    );
    try testing.expectEqual(
        @as(NSUInteger, (1 << 17) | (1 << 18)),
        (Modifiers{ .command = false, .shift = true, .control = true }).mask(),
    );
}

test "context menu builder" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const reg = try Registry.create(testing.allocator);
    defer reg.destroy();

    var cb_state: u32 = 0;
    const items = [_]Item{
        Item.call("Get Info", .{ .ctx = &cb_state, .f = testCallback }, "", .{}),
        .separator,
        Item.sel("Delete", "relayDelete:", "", .{}),
    };
    const menu = try buildContextMenu(reg, &items);
    defer menu.msgSend(void, "release", .{});
    try testing.expectEqual(@as(NSInteger, 3), menu.msgSend(NSInteger, "numberOfItems", .{}));
}

test {
    testing.refAllDecls(@This());
}

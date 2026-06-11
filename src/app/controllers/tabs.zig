//! tabs — TabsController: multiple browsing contexts (Phase B).
//!
//! Owns a list of BrowserController instances, a TabBar strip, and a
//! container NSView that swaps the active tab's browser view in and out.
//! The strip is hidden when only one tab is open (standard macOS behavior).
//!
//! Teardown order per CRITICAL finding 2: core.unregisterListeners(ctrl)
//! BEFORE ctrl.destroy(). Never touch core after AppCore.shutdown().
//!
//! Title format: "{left_label} ⇄ {right_label}" where left = "Local" for the
//! local pane and site label for a bound remote; right = "—" when unbound.
//!
//! Threading: everything here is main-thread only.

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");

const objc = mac.objc;
const c = objc.c;
const foundation = mac.foundation;
const tab_bar_mod = mac.appkit.tab_bar;
const window_mod = mac.appkit.window;
const events_mod = relay.events;
const item_mod = relay.queue.item;

const browser_mod = @import("browser.zig");
const sites_mod_ctrl = @import("sites.zig");
const prefs_mod = @import("prefs.zig");

const BrowserController = browser_mod.BrowserController;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Per-tab slot
// ---------------------------------------------------------------------------
const Tab = struct {
    browser: *BrowserController,
};

// ---------------------------------------------------------------------------
// TabsController
// ---------------------------------------------------------------------------
pub const TabsController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    win: window_mod.Window,
    tabs: std.ArrayListUnmanaged(Tab) = .empty,
    active: usize = 0,
    /// Plain NSView placed at inner_split child 0; swaps in the active tab's
    /// browser view as its sole subview.
    container: objc.Object,
    /// Tab strip; hidden when tabs.items.len == 1.
    bar: *tab_bar_mod.TabBar,
    /// Borrowed reference to the sites store for title derivation.
    sites_store: ?*sites_mod_ctrl.SiteStore = null,
    /// App-level hook wiring (selection/visit/space/context-menu) for every
    /// browser this controller creates. newTab calls it so tabs opened from
    /// the strip's "+" button get the same seams as Cmd+T tabs.
    on_tab_created: ?*const fn (*BrowserController) void = null,
    /// New-tab request from the strip's "+" button. Routed back to the app
    /// (the same path as Cmd+T) so the new browser gets the CURRENT prefs
    /// (density, date format, vim mode…) — TabsController doesn't know them.
    on_new_request: ?*const fn () void = null,

    // ------------------------------------------------------------------ //
    // Lifecycle

    /// Create: adopts `first_browser` as tab 0 (already created by
    /// main.zig). `container_frame` is the frame for the swapping NSView.
    pub fn create(
        gpa: Allocator,
        core: *bridge.AppCore,
        win: window_mod.Window,
        first_browser: *BrowserController,
    ) !*TabsController {
        const self = try gpa.create(TabsController);
        errdefer gpa.destroy(self);

        // Build the container view (plain NSView, fills via autoresizing).
        const ns_view_class = foundation.class("NSView");
        const container = ns_view_class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{foundation.rect(0, 0, 800, 600)});
        // Width + height sizable so the inner_split resizes it correctly.
        const ns_autoresize_all: foundation.NSUInteger = (1 << 1) | (1 << 4); // widthSizable | heightSizable
        container.msgSend(void, "setAutoresizingMask:", .{ns_autoresize_all});
        errdefer container.msgSend(void, "release", .{});

        // Build the tab bar.
        const bar = try tab_bar_mod.TabBar.init(
            gpa,
            foundation.rect(0, 0, 800, tab_bar_mod.bar_height),
            .{
                .ctx = self,
                .onSelect = tabBarOnSelect,
                .onClose = tabBarOnClose,
                .onNew = tabBarOnNew,
            },
        );
        errdefer bar.deinit();

        self.* = .{
            .gpa = gpa,
            .core = core,
            .win = win,
            .container = container,
            .bar = bar,
        };

        // Adopt the first browser (swaps its view into the container).
        try self.tabs.append(gpa, .{ .browser = first_browser });
        self.swapViewIn(first_browser);

        // Register a site_status listener so title chips update on connect.
        try core.registerListener(.site_status, self, onSiteStatus);

        self.bar.setHidden(true); // single tab: strip hidden
        try self.refreshTitles();

        return self;
    }

    /// Tear down every surviving browser (tests/teardown paths only — the
    /// app quit path never calls this; the process exits after
    /// AppCore.shutdown()). MUST run while the core is alive: the body
    /// calls core.unregisterListeners, which asserts !shutdown_done. The
    /// caller is responsible for core.unregisterListeners(self) for the
    /// site_status listener registered in create().
    pub fn destroy(self: *TabsController) void {
        for (self.tabs.items) |tab| {
            self.core.unregisterListeners(tab.browser);
            tab.browser.destroy();
        }
        self.tabs.deinit(self.gpa);
        self.bar.deinit();
        self.container.msgSend(void, "removeFromSuperview", .{});
        self.container.msgSend(void, "release", .{});
        self.gpa.destroy(self);
    }

    // ------------------------------------------------------------------ //
    // Active browser accessor

    pub fn activeBrowser(self: *TabsController) *BrowserController {
        return self.tabs.items[self.active].browser;
    }

    // ------------------------------------------------------------------ //
    // Tab operations

    /// New tab: local $HOME left, unbound remote right.
    pub fn newTab(self: *TabsController, options: BrowserController.Options) !void {
        const browser = try BrowserController.create(self.gpa, self.core, self.win, options);
        errdefer {
            self.core.unregisterListeners(browser);
            browser.destroy();
        }
        try self.tabs.append(self.gpa, .{ .browser = browser });
        if (self.on_tab_created) |hook| hook(browser);
        self.active = self.tabs.items.len - 1;
        self.swapViewIn(browser);
        self.bar.setHidden(false);
        try self.refreshTitles();
        browser.focusPane(0);
    }

    /// Close the tab at `index`. Returns false if it was the last tab (caller
    /// should then perform-close the window). CRITICAL finding 2: unregister
    /// BEFORE destroy.
    pub fn closeTab(self: *TabsController, index: usize) bool {
        if (self.tabs.items.len <= 1) return false;
        const tab = self.tabs.items[index];

        // Detach the view before tearing down the controller.
        const view_obj = objc.Object.fromId(tab.browser.view());
        view_obj.msgSend(void, "removeFromSuperview", .{});

        self.core.unregisterListeners(tab.browser);
        tab.browser.destroy();
        _ = self.tabs.orderedRemove(index);

        self.active = activeAfterClose(self.active, index, self.tabs.items.len);
        // Re-swap unconditionally: closing the active tab needs the new
        // active view in; closing a background tab makes this a no-op
        // re-add of the already-displayed view.
        self.swapViewIn(self.tabs.items[self.active].browser);
        if (self.tabs.items.len == 1) self.bar.setHidden(true);
        self.refreshTitles() catch {};
        self.activeBrowser().focusPane(self.activeBrowser().focused);
        return true;
    }

    /// Close the active tab. Returns false when it's the last tab.
    pub fn closeActiveTab(self: *TabsController) bool {
        return self.closeTab(self.active);
    }

    pub fn selectTab(self: *TabsController, index: usize) void {
        if (index >= self.tabs.items.len) return;
        if (index == self.active) return;
        // Detach current.
        const cur_view = objc.Object.fromId(self.tabs.items[self.active].browser.view());
        cur_view.msgSend(void, "removeFromSuperview", .{});
        self.active = index;
        self.swapViewIn(self.tabs.items[self.active].browser);
        self.refreshTitles() catch {};
        self.activeBrowser().focusPane(self.activeBrowser().focused);
    }

    pub fn nextTab(self: *TabsController) void {
        if (self.tabs.items.len <= 1) return;
        self.selectTab((self.active + 1) % self.tabs.items.len);
    }

    pub fn prevTab(self: *TabsController) void {
        if (self.tabs.items.len <= 1) return;
        const n = self.tabs.items.len;
        self.selectTab((self.active + n - 1) % n);
    }

    // ------------------------------------------------------------------ //
    // Title derivation

    /// Recompute titles from pane site bindings and push to the bar.
    pub fn refreshTitles(self: *TabsController) !void {
        const count = self.tabs.items.len;
        const titles = try self.gpa.alloc([]const u8, count);
        defer self.gpa.free(titles);

        var bufs: [][]u8 = try self.gpa.alloc([]u8, count);
        defer {
            for (bufs) |buf| self.gpa.free(buf);
            self.gpa.free(bufs);
        }

        for (self.tabs.items, 0..) |tab, i| {
            const left = paneLabel(self.sites_store, tab.browser.panes[0]);
            const right = paneLabel(self.sites_store, tab.browser.panes[1]);
            // "{left} ⇄ {right}" — ⇄ is U+21C4 (3 UTF-8 bytes).
            const arrow = " \u{21C4} ";
            const buf = try std.fmt.allocPrint(self.gpa, "{s}{s}{s}", .{ left, arrow, right });
            bufs[i] = buf;
            titles[i] = buf;
        }

        try self.bar.setTabs(titles, self.active);
    }

    // ------------------------------------------------------------------ //
    // View for layout (the swapping container)

    pub fn containerView(self: *TabsController) c.id {
        return self.container.value;
    }

    // ------------------------------------------------------------------ //
    // Private helpers

    /// Remove any existing subview and add `browser.view()` as the sole child
    /// of the container, with autoresizing to fill.
    fn swapViewIn(self: *TabsController, browser: *BrowserController) void {
        // Remove old subviews.
        const subviews = self.container.msgSend(objc.Object, "subviews", .{});
        const count = subviews.msgSend(foundation.NSUInteger, "count", .{});
        var i: foundation.NSUInteger = count;
        while (i > 0) {
            i -= 1;
            const sub = subviews.msgSend(objc.Object, "objectAtIndex:", .{i});
            sub.msgSend(void, "removeFromSuperview", .{});
        }

        // Add new subview filling the container.
        const new_view = objc.Object.fromId(browser.view());
        const ns_autoresize_all: foundation.NSUInteger = (1 << 1) | (1 << 4); // widthSizable | heightSizable
        new_view.msgSend(void, "setAutoresizingMask:", .{ns_autoresize_all});
        // Match the container's current bounds.
        const bounds = self.container.msgSend(foundation.NSRect, "bounds", .{});
        new_view.msgSend(void, "setFrame:", .{bounds});
        self.container.msgSend(void, "addSubview:", .{new_view});
    }

    // ------------------------------------------------------------------ //
    // site_status listener (refreshes titles on connect/disconnect)

    fn onSiteStatus(self: *TabsController, _: events_mod.CoreEvent.SiteStatusChange) void {
        self.refreshTitles() catch {};
    }

    // ------------------------------------------------------------------ //
    // TabBar delegate callbacks

    fn tabBarOnSelect(ctx: *anyopaque, index: usize) void {
        const self: *TabsController = @ptrCast(@alignCast(ctx));
        self.selectTab(index);
    }

    fn tabBarOnClose(ctx: *anyopaque, index: usize) void {
        const self: *TabsController = @ptrCast(@alignCast(ctx));
        _ = self.closeTab(index);
    }

    fn tabBarOnNew(ctx: *anyopaque) void {
        const self: *TabsController = @ptrCast(@alignCast(ctx));
        // Route through the app so the tab gets current prefs; the direct
        // fallback (default options) only serves headless tests.
        if (self.on_new_request) |request| {
            request();
            return;
        }
        self.newTab(.{}) catch {};
    }
};

// ---------------------------------------------------------------------------
// Title helpers
// ---------------------------------------------------------------------------

/// Human-readable label for a pane: "Local" for local, site label for a
/// bound remote, "—" for an unbound remote.
fn paneLabel(store: ?*sites_mod_ctrl.SiteStore, pane: *browser_mod.BrowserPane) []const u8 {
    const site_id = pane.site orelse return "\u{2014}"; // "—"
    if (site_id == item_mod.local_site_id) return "Local";
    const s = store orelse return "\u{2014}";
    const site_ptr = s.get(site_id) orelse return "\u{2014}";
    return sites_mod_ctrl.siteLabel(site_ptr.*);
}

// ---------------------------------------------------------------------------
// Index helpers
// ---------------------------------------------------------------------------

/// Active index after removing `closed` from a list now `new_len` long
/// (new_len >= 1). Tabs right of the closed one shift left, so an active
/// index past the closed slot moves with them; closing the active tab
/// selects its right neighbor (or the new last tab when it was last).
fn activeAfterClose(active: usize, closed: usize, new_len: usize) usize {
    var a = active;
    if (closed < a) a -= 1;
    if (a >= new_len) a = new_len - 1;
    return a;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

test "activeAfterClose keeps the displayed tab stable" {
    // [A,B,C] showing B(1): closing A(0) shifts B to 0.
    try testing.expectEqual(@as(usize, 0), activeAfterClose(1, 0, 2));
    // [A,B,C] showing B(1): closing C(2) leaves B at 1.
    try testing.expectEqual(@as(usize, 1), activeAfterClose(1, 2, 2));
    // [A,B,C] showing B(1): closing B selects its right neighbor (C, now 1).
    try testing.expectEqual(@as(usize, 1), activeAfterClose(1, 1, 2));
    // [A,B] showing B(1): closing B (last) selects the new last tab (A).
    try testing.expectEqual(@as(usize, 0), activeAfterClose(1, 1, 1));
    // [A,B] showing A(0): closing B leaves A displayed.
    try testing.expectEqual(@as(usize, 0), activeAfterClose(0, 1, 1));
}

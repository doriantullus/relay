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
const panels = mac.appkit.panels;
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
    /// Last site_status per site id, tracked from the site_status listener
    /// (the core exposes no synchronous query; the sidebar tracks its own
    /// copy the same way). Drives the per-tab dot and the close-confirm.
    statuses: std.AutoHashMapUnmanaged(u64, events_mod.SiteStatus) = .empty,
    /// The tab awaiting a close-confirm answer (held by browser pointer so a
    /// reorder between prompt and answer can't close the wrong tab).
    pending_close: ?*BrowserController = null,

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
                .onReorder = tabBarOnReorder,
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
        self.statuses.deinit(self.gpa);
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

    // ------------------------------------------------------------------ //
    // Close + disconnect (close button "×" and Cmd+W). Closing a tab drops
    // the server connection(s) it owns; if a connection is live, a confirm
    // sheet guards against disconnecting by mistake.

    /// Close the active tab (Cmd+W), confirming first if it holds a live
    /// connection. The last tab closes the window after disconnecting.
    pub fn requestCloseActiveTab(self: *TabsController) void {
        self.requestCloseTab(self.active);
    }

    /// Entry point for both the "×" button and Cmd+W: confirm when the tab
    /// has a live connection, else close immediately.
    pub fn requestCloseTab(self: *TabsController, index: usize) void {
        if (index >= self.tabs.items.len) return;
        // A confirm sheet is already up (it is window-modal): ignore a second
        // request rather than stack sheets / overwrite pending_close.
        if (self.pending_close != null) return;
        const browser = self.tabs.items[index].browser;
        if (!self.tabHasLiveConnection(browser)) {
            self.finishClose(browser);
            return;
        }
        // Hold the target by pointer: a reorder before the answer must not
        // close the wrong tab. The sheet copies its strings synchronously, so
        // a stack-buffered message is safe.
        self.pending_close = browser;
        const label = self.liveSiteLabel(browser);
        var msg_buf: [256]u8 = undefined;
        var info_buf: [320]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Disconnect from {s}?", .{label}) catch "Disconnect this server?";
        const info = std.fmt.bufPrint(&info_buf, "Closing this tab will disconnect the connection to {s}.", .{label}) catch
            "Closing this tab will disconnect its server.";
        panels.confirmSheet(self.win, msg, info, "Close & Disconnect", true, self, onCloseConfirmed);
    }

    fn onCloseConfirmed(self: *TabsController, confirmed: bool) void {
        const browser = self.pending_close;
        self.pending_close = null;
        if (!confirmed) return;
        self.finishClose(browser orelse return);
    }

    /// Tear the tab down and disconnect any of its remote sites that no
    /// surviving tab still uses. The last tab can't be removed, so it
    /// disconnects and closes the window instead.
    fn finishClose(self: *TabsController, browser: *BrowserController) void {
        const idx = self.indexOfBrowser(browser) orelse return;
        // Snapshot this tab's remote bindings before any teardown. Sized from
        // panes.len so a future pane-count change can't overflow.
        var sites: [browser.panes.len]?u64 = @splat(@as(?u64, null));
        for (browser.panes, 0..) |pane, i| {
            const sid = pane.site orelse continue;
            if (sid != item_mod.local_site_id) sites[i] = sid;
        }

        if (self.tabs.items.len <= 1) {
            // Last tab: nothing else can hold these sites — disconnect each
            // (deduped: both panes may bind the same site) and close.
            for (sites, 0..) |maybe_sid, i| if (maybe_sid) |sid| {
                if (!sidAppearsBefore(sites[0..i], sid)) self.core.disconnectSite(sid);
            };
            self.win.performClose();
            return;
        }

        _ = self.closeTab(idx); // removes the tab and tears down the browser
        for (sites, 0..) |maybe_sid, i| if (maybe_sid) |sid| {
            if (!sidAppearsBefore(sites[0..i], sid) and !self.siteInUse(sid))
                self.core.disconnectSite(sid);
        };
    }

    /// True if any surviving tab still binds a pane to `site_id`.
    fn siteInUse(self: *TabsController, site_id: u64) bool {
        for (self.tabs.items) |tab| {
            for (tab.browser.panes) |pane| {
                if (pane.site == site_id) return true;
            }
        }
        return false;
    }

    /// Label of the first live-or-connecting remote pane in the tab, for the
    /// confirm message; a generic fallback otherwise. Matches the
    /// tabHasLiveConnection notion of "live" (absent status = in-flight).
    fn liveSiteLabel(self: *TabsController, browser: *BrowserController) []const u8 {
        for (browser.panes) |pane| {
            const sid = pane.site orelse continue;
            if (sid == item_mod.local_site_id) continue;
            const status = self.statuses.get(sid);
            if (status == null or status.? != .offline) return paneLabel(self.sites_store, pane);
        }
        return "this server";
    }

    /// Free helper: does `sid` already appear in `prev`? Used to disconnect
    /// each unique site at most once when a tab binds the same site twice.
    fn sidAppearsBefore(prev: []const ?u64, sid: u64) bool {
        for (prev) |m| if (m == sid) return true;
        return false;
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

    /// Drag-reorder: move the tab at `from` to position `to`. The displayed
    /// view is unchanged — only the order and the (re-derived) active index
    /// move — so no view swap is needed, just a title/dot refresh.
    pub fn reorderTab(self: *TabsController, from: usize, to: usize) void {
        const n = self.tabs.items.len;
        if (from >= n or to >= n or from == to) return;
        const active_browser = self.tabs.items[self.active].browser;
        // In-place shift (no allocation, can't fail): slide the span between
        // `from` and `to` over by one and drop the moved tab at `to`.
        const items = self.tabs.items;
        const moved = items[from];
        if (from < to) {
            std.mem.copyForwards(Tab, items[from..to], items[from + 1 .. to + 1]);
        } else {
            std.mem.copyBackwards(Tab, items[to + 1 .. from + 1], items[to..from]);
        }
        items[to] = moved;
        // Keep `active` pointing at the same displayed browser.
        self.active = self.indexOfBrowser(active_browser) orelse self.active;
        self.refreshTitles() catch {};
    }

    fn indexOfBrowser(self: *TabsController, browser: *BrowserController) ?usize {
        for (self.tabs.items, 0..) |tab, i| if (tab.browser == browser) return i;
        return null;
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

    /// Recompute titles + connection dots from pane site bindings and push to
    /// the bar.
    pub fn refreshTitles(self: *TabsController) !void {
        const count = self.tabs.items.len;
        const titles = try self.gpa.alloc([]const u8, count);
        defer self.gpa.free(titles);
        const tab_statuses = try self.gpa.alloc(tab_bar_mod.Status, count);
        defer self.gpa.free(tab_statuses);

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
            tab_statuses[i] = self.tabStatus(tab.browser);
        }

        try self.bar.setTabs(titles, tab_statuses, self.active);
    }

    /// The dot status for a tab: orange if any bound remote pane is
    /// reconnecting, else green if any is connected, else none. Unbound and
    /// offline panes contribute nothing (matches the sidebar dots).
    fn tabStatus(self: *TabsController, browser: *BrowserController) tab_bar_mod.Status {
        var result: tab_bar_mod.Status = .none;
        for (browser.panes) |pane| {
            const site_id = pane.site orelse continue;
            if (site_id == item_mod.local_site_id) continue;
            switch (self.statuses.get(site_id) orelse continue) {
                .reconnecting => return .reconnecting, // most urgent: short-circuit
                .connected => result = .connected,
                .offline => {},
            }
        }
        return result;
    }

    /// True when a tab holds a remote binding that is live or still
    /// connecting — used to warn before a close drops it. A binding whose last
    /// recorded status is .offline does not count (nothing live to lose);
    /// unbound/local panes never count. The core has no interim "connecting"
    /// status, so an in-flight connect shows as an ABSENT status entry —
    /// treated as live here so closing mid-connect still warns.
    fn tabHasLiveConnection(self: *TabsController, browser: *BrowserController) bool {
        for (browser.panes) |pane| {
            const sid = pane.site orelse continue;
            if (sid == item_mod.local_site_id) continue;
            const status = self.statuses.get(sid);
            if (status == null or status.? != .offline) return true;
        }
        return false;
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

    fn onSiteStatus(self: *TabsController, e: events_mod.CoreEvent.SiteStatusChange) void {
        self.statuses.put(self.gpa, e.site_id, e.status) catch {};
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
        self.requestCloseTab(index);
    }

    fn tabBarOnReorder(ctx: *anyopaque, from: usize, to: usize) void {
        const self: *TabsController = @ptrCast(@alignCast(ctx));
        self.reorderTab(from, to);
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
const FakeStore = relay.cred.fake.FakeStore;

test {
    testing.refAllDecls(@This());
}

test "tabs: status dots, siteInUse, and drag reorder track the active tab" {
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
        "relay-tabs-test",
        window_mod.StyleMask.standard,
    );

    const first = try BrowserController.create(gpa, core, win, .{});
    const tabs = try TabsController.create(gpa, core, win, first);
    try tabs.newTab(.{});
    try tabs.newTab(.{});
    try testing.expectEqual(@as(usize, 3), tabs.tabs.items.len);
    core.drainNow();

    // Bind remote panes without connecting: tabs 0 and 1 share site 100; tab
    // 2 uses site 200. Statuses come straight from the (manually seeded) map.
    tabs.tabs.items[0].browser.panes[1].site = 100;
    tabs.tabs.items[1].browser.panes[1].site = 100;
    tabs.tabs.items[2].browser.panes[1].site = 200;
    try tabs.statuses.put(gpa, 100, .connected);
    try tabs.statuses.put(gpa, 200, .reconnecting);

    // Per-tab dot: connected → green, reconnecting → orange (most urgent).
    try testing.expectEqual(tab_bar_mod.Status.connected, tabs.tabStatus(tabs.tabs.items[0].browser));
    try testing.expectEqual(tab_bar_mod.Status.reconnecting, tabs.tabStatus(tabs.tabs.items[2].browser));
    try testing.expect(tabs.tabHasLiveConnection(tabs.tabs.items[1].browser));

    // siteInUse: 100 spans two tabs, 200 one, 999 none.
    try testing.expect(tabs.siteInUse(100));
    try testing.expect(tabs.siteInUse(200));
    try testing.expect(!tabs.siteInUse(999));

    // Close-confirm gate covers the in-flight window: a binding with NO
    // recorded status yet (initial connect) still counts as live, while an
    // explicitly-offline binding does not. (The dot stays .none either way.)
    tabs.tabs.items[2].browser.panes[1].site = 300; // no status entry yet
    try testing.expect(tabs.tabHasLiveConnection(tabs.tabs.items[2].browser));
    try testing.expectEqual(tab_bar_mod.Status.none, tabs.tabStatus(tabs.tabs.items[2].browser));
    try tabs.statuses.put(gpa, 300, .offline);
    try testing.expect(!tabs.tabHasLiveConnection(tabs.tabs.items[2].browser));

    // Drag the active tab to the end: active follows it to index 2.
    tabs.selectTab(0);
    const moved = tabs.tabs.items[0].browser;
    tabs.reorderTab(0, 2);
    try testing.expectEqual(@as(usize, 2), tabs.active);
    try testing.expectEqual(moved, tabs.tabs.items[2].browser);

    // Reordering other tabs leaves the displayed (active) browser unchanged.
    tabs.selectTab(0);
    const active_browser = tabs.tabs.items[0].browser;
    tabs.reorderTab(2, 1);
    try testing.expectEqual(active_browser, tabs.tabs.items[tabs.active].browser);

    // Teardown (destroy() doc: unregister the site_status listener first, and
    // it must run while the core is still alive).
    core.unregisterListeners(tabs);
    tabs.destroy();
    core.shutdown();
    win.release();
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

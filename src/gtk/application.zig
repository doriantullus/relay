//! GTK application/window assembly for the Linux frontend.
//!
//! The executable owns relay_ui's AppCore; this module owns every GTK object
//! and translates AppCore listing events into native widgets. Keeping that
//! boundary here means src/app_gtk never imports GTK directly.

const std = @import("std");
const gtk = @import("gtk");
const gdk = @import("gdk");
const gio = @import("gio");
const glib = @import("glib");
const gobject = @import("gobject");
const relay = @import("relay_core");
const ui = @import("relay_ui");

const Allocator = std.mem.Allocator;
const AppCore = ui.bridge.AppCore;
const DirSnapshot = relay.vfs.snapshot.DirSnapshot;
const Entry = relay.vfs.iface.Entry;
const SiteStore = ui.sites.SiteStore;
const SiteFields = ui.sites.SiteFields;
const SiteStatus = relay.events.SiteStatus;

const app_id = "us.doriantull.relay";
const max_visible_rows = 2_000;
const local_site_id = relay.queue.item.local_site_id;
const remote_pane_index: usize = 1;
const PendingFileKind = enum { open, preview, edit };
const PendingFile = struct {
    path: []u8,
    kind: PendingFileKind,
    site_id: u64 = local_site_id,
    remote_path: ?[]u8 = null,
    remote_mtime: ?i64 = null,
    cleanup_temp: bool = false,

    fn deinit(self: *PendingFile, gpa: Allocator, io: std.Io) void {
        if (self.cleanup_temp) std.Io.Dir.cwd().deleteFile(io, self.path) catch {};
        gpa.free(self.path);
        if (self.remote_path) |path| gpa.free(path);
        self.* = undefined;
    }
};

extern fn relay_gtk_set_accels(
    application: *gtk.Application,
    action: [*:0]const u8,
    first: ?[*:0]const u8,
    second: ?[*:0]const u8,
) void;
extern fn relay_gtk_accessible_label(widget: *gtk.Widget, label: [*:0]const u8) void;
extern fn g_value_take_boxed(value: *gobject.Value, boxed: ?*anyopaque) void;
extern fn g_slist_free(list: ?*glib.SList) void;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

fn allocPrintZ(gpa: Allocator, comptime format: []const u8, args: anytype) error{OutOfMemory}![:0]u8 {
    const text = try std.fmt.allocPrint(gpa, format, args);
    defer gpa.free(text);
    return gpa.dupeZ(u8, text);
}

fn createPrivateTempDir(gpa: Allocator) ![:0]u8 {
    const template = try allocPrintZ(gpa, "/tmp/relay-{d}-XXXXXX", .{std.c.getpid()});
    errdefer gpa.free(template);
    if (mkdtemp(template.ptr) == null) return error.TempDirectoryUnavailable;
    return template;
}

/// Run the GTK frontend until the last application window closes.
pub fn run(
    gpa: Allocator,
    core: *AppCore,
    site_store: *SiteStore,
    history: *ui.sites.History,
    auth_meta: *ui.sites.AuthMetaStore,
    prefs: *ui.prefs.UiPrefs,
    init: std.process.Init.Minimal,
) !void {
    const gtk_app = gtk.Application.new(app_id, .{ .non_unique = true });
    defer gtk_app.unref();

    var services: @import("services.zig").Services = .{
        .gpa = gpa,
        .application = gtk_app.as(gio.Application),
    };
    var app: Application = .{
        .gpa = gpa,
        .core = core,
        .site_store = site_store,
        .history = history,
        .auth_meta = auth_meta,
        .prefs = prefs,
        .services = &services,
        .native = gtk_app,
        .smoke_mode = smokeRequested(),
    };
    defer if (app.window) |window| window.destroy();
    defer {
        if (app.smoke_timer != 0) _ = glib.Source.remove(app.smoke_timer);
    }
    _ = gio.Application.signals.activate.connect(gtk_app, *Application, activate, &app, .{});

    var argv: std.ArrayList([*:0]u8) = .empty;
    defer argv.deinit(gpa);
    var args = init.args.iterate();
    while (args.next()) |arg| try argv.append(gpa, @ptrCast(@constCast(arg.ptr)));

    const status = gtk_app.as(gio.Application).run(@intCast(argv.items.len), argv.items.ptr);
    if (status != 0) return error.GtkApplicationFailed;
    if (app.init_failed) return error.GtkWindowInitializationFailed;
    if (app.smoke_mode and !app.smoke_passed) return error.GtkSmokeFailed;
}

const Application = struct {
    gpa: Allocator,
    core: *AppCore,
    site_store: *SiteStore,
    history: *ui.sites.History,
    auth_meta: *ui.sites.AuthMetaStore,
    prefs: *ui.prefs.UiPrefs,
    services: *@import("services.zig").Services,
    native: *gtk.Application,
    window: ?*Window = null,
    smoke_mode: bool,
    smoke_timer: c_uint = 0,
    smoke_passed: bool = false,
    smoke_listings_ready: bool = false,
    smoke_operation_done: bool = false,
    init_failed: bool = false,

    fn maybeSmokeSucceeded(self: *Application) void {
        if (!self.smoke_listings_ready or !self.smoke_operation_done) return;
        if (!self.smoke_mode or self.smoke_passed) return;
        self.smoke_passed = true;
        if (self.smoke_timer != 0) {
            _ = glib.Source.remove(self.smoke_timer);
            self.smoke_timer = 0;
        }
        self.native.as(gio.Application).quit();
    }

    fn smokeFailed(self: *Application) void {
        if (!self.smoke_mode) return;
        if (self.smoke_timer != 0) {
            _ = glib.Source.remove(self.smoke_timer);
            self.smoke_timer = 0;
        }
        self.native.as(gio.Application).quit();
    }
};

fn smokeRequested() bool {
    const value = std.c.getenv("RELAY_GTK_SMOKE") orelse return false;
    return std.mem.eql(u8, std.mem.span(value), "1");
}

fn smokeTimedOut(raw: ?*anyopaque) callconv(.c) c_int {
    const app: *Application = @ptrCast(@alignCast(raw.?));
    app.smoke_timer = 0;
    app.native.as(gio.Application).quit();
    return @intFromBool(glib.SOURCE_REMOVE);
}

fn activate(gtk_app: *gtk.Application, app: *Application) callconv(.c) void {
    if (app.window) |window| {
        window.native.as(gtk.Window).present();
        return;
    }
    app.window = Window.create(app, gtk_app) catch |err| {
        std.log.err("GTK window initialization failed: {s}", .{@errorName(err)});
        app.init_failed = true;
        gtk_app.as(gio.Application).quit();
        return;
    };
    app.window.?.native.as(gtk.Window).present();
    if (app.smoke_mode) {
        app.smoke_timer = glib.timeoutAdd(5_000, smokeTimedOut, app);
        if (app.smoke_timer == 0) {
            app.init_failed = true;
            gtk_app.as(gio.Application).quit();
        }
    }
}

const Window = struct {
    gpa: Allocator,
    core: *AppCore,
    site_store: *SiteStore,
    history: *ui.sites.History,
    auth_meta: *ui.sites.AuthMetaStore,
    prefs: *ui.prefs.UiPrefs,
    services: *@import("services.zig").Services,
    application: *Application,
    native: *gtk.ApplicationWindow,
    sidebar: SitesSidebar = undefined,
    sidebar_initialized: bool = false,
    inspector: InspectorPanel = undefined,
    inspector_initialized: bool = false,
    panes: [2]Pane = undefined,
    panes_initialized: usize = 0,
    transfers: TransferPanel = undefined,
    transfers_initialized: bool = false,
    listeners_registered: bool = false,
    site_model: *gtk.StringList,
    site_picker: *gtk.DropDown,
    connect_button: *gtk.Button,
    disconnect_button: *gtk.Button,
    subtitle: *gtk.Label,
    site_ids: std.ArrayList(u64) = .empty,
    statuses: std.AutoHashMapUnmanaged(u64, SiteStatus) = .empty,
    pane_sites: [2]?u64 = .{ null, null },
    transients: std.ArrayList(TransientCred) = .empty,
    quick_dialog: ?*QuickDialog = null,
    prompt_dialogs: std.ArrayList(*PromptDialog) = .empty,
    ssh: ui.sites.SshGroup,
    smoke_op_path: [128]u8 = undefined,
    smoke_op_path_len: usize = 0,
    smoke_op_stage: SmokeOpStage = .idle,
    active_pane_index: usize = 0,
    site_dialog: ?*SiteDialog = null,
    import_dialog: ?*ImportDialog = null,
    settings_dialog: ?*SettingsDialog = null,
    palette_dialog: ?*PaletteDialog = null,
    actions: std.ArrayList(*gio.SimpleAction) = .empty,
    pending_files: std.AutoHashMapUnmanaged(u64, PendingFile) = .empty,
    active_edits: std.ArrayList(*ActiveEdit) = .empty,
    edit_uploads: std.AutoHashMapUnmanaged(u64, *ActiveEdit) = .empty,
    edit_stats: std.AutoHashMapUnmanaged(ui.bridge.RequestId, *ActiveEdit) = .empty,
    temp_dir: [:0]u8,
    next_temp_id: u64 = 1,
    frecency: ui.fuzzy.Frecency,
    sync_browsing: bool = false,
    syncing_navigation: bool = false,
    compare_panes: bool = false,

    const SmokeOpStage = enum { idle, creating, deleting, done };

    fn create(application: *Application, app: *gtk.Application) !*Window {
        const gpa = application.gpa;
        const core = application.core;
        const self = try gpa.create(Window);
        errdefer gpa.destroy(self);
        const temp_dir = try createPrivateTempDir(gpa);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .site_store = application.site_store,
            .history = application.history,
            .auth_meta = application.auth_meta,
            .prefs = application.prefs,
            .services = application.services,
            .application = application,
            .native = gtk.ApplicationWindow.new(app),
            .site_model = gtk.StringList.new(null),
            .site_picker = undefined,
            .connect_button = undefined,
            .disconnect_button = undefined,
            .subtitle = undefined,
            .ssh = .init(gpa),
            .frecency = .init(gpa),
            .temp_dir = temp_dir,
        };
        errdefer self.cleanup();

        const window = self.native.as(gtk.Window);
        installCss();
        window.setTitle("Relay");
        window.setDefaultSize(1280, 800);

        const header = gtk.HeaderBar.new();
        const title_box = gtk.Box.new(.vertical, 0);
        const title = gtk.Label.new("Relay");
        title.as(gtk.Widget).addCssClass("title");
        const subtitle = gtk.Label.new("Linux · local");
        subtitle.as(gtk.Widget).addCssClass("dim-label");
        title_box.append(title.as(gtk.Widget));
        title_box.append(subtitle.as(gtk.Widget));
        header.setTitleWidget(title_box.as(gtk.Widget));

        const site_picker = gtk.DropDown.new(self.site_model.as(gio.ListModel), null);
        site_picker.as(gtk.Widget).setTooltipText("Saved site for the right pane");
        const connect_button = gtk.Button.newWithLabel("Connect");
        const quick_button = gtk.Button.newWithLabel("Connect…");
        const disconnect_button = gtk.Button.newWithLabel("Disconnect");
        const menu_button = gtk.MenuButton.new();
        menu_button.setIconName("open-menu-symbolic");
        menu_button.as(gtk.Widget).setTooltipText("Main menu");
        relay_gtk_accessible_label(menu_button.as(gtk.Widget), "Main menu");
        disconnect_button.as(gtk.Widget).setSensitive(0);
        header.packStart(site_picker.as(gtk.Widget));
        header.packStart(connect_button.as(gtk.Widget));
        header.packEnd(disconnect_button.as(gtk.Widget));
        header.packEnd(quick_button.as(gtk.Widget));
        header.packEnd(menu_button.as(gtk.Widget));
        window.setTitlebar(header.as(gtk.Widget));

        self.site_picker = site_picker;
        self.connect_button = connect_button;
        self.disconnect_button = disconnect_button;
        self.subtitle = subtitle;
        try self.installActions(app, menu_button);
        const home = if (std.c.getenv("HOME")) |value| std.mem.span(value) else "/";
        self.ssh.refresh(core.io, home);
        try self.rebuildSitePicker();
        try self.frecency.load(core.io, core.config_dir, "palette-frecency.zon");
        _ = gtk.Button.signals.clicked.connect(connect_button, *Window, onConnectSaved, self, .{});
        _ = gtk.Button.signals.clicked.connect(quick_button, *Window, onQuickConnect, self, .{});
        _ = gtk.Button.signals.clicked.connect(disconnect_button, *Window, onDisconnect, self, .{});

        const pane_split = gtk.Paned.new(.horizontal);
        pane_split.setWideHandle(1);
        pane_split.setPosition(520);
        pane_split.setResizeStartChild(1);
        pane_split.setResizeEndChild(1);
        pane_split.setShrinkStartChild(0);
        pane_split.setShrinkEndChild(0);

        self.panes[0].init(self, 1);
        self.panes_initialized = 1;
        self.panes[1].init(self, 2);
        self.panes_initialized = 2;
        pane_split.setStartChild(self.panes[0].root.as(gtk.Widget));
        pane_split.setEndChild(self.panes[1].root.as(gtk.Widget));

        self.inspector.init(self);
        self.inspector_initialized = true;
        const content_split = gtk.Paned.new(.horizontal);
        content_split.setWideHandle(1);
        content_split.setPosition(800);
        content_split.setResizeStartChild(1);
        content_split.setResizeEndChild(0);
        content_split.setShrinkStartChild(0);
        content_split.setShrinkEndChild(0);
        content_split.setStartChild(pane_split.as(gtk.Widget));
        content_split.setEndChild(self.inspector.root.as(gtk.Widget));

        self.sidebar.init(self);
        self.sidebar_initialized = true;
        self.setActivePane(&self.panes[0]);
        const browser_split = gtk.Paned.new(.horizontal);
        browser_split.setWideHandle(1);
        browser_split.setPosition(250);
        browser_split.setResizeStartChild(0);
        browser_split.setResizeEndChild(1);
        browser_split.setShrinkStartChild(0);
        browser_split.setShrinkEndChild(0);
        browser_split.setStartChild(self.sidebar.root.as(gtk.Widget));
        browser_split.setEndChild(content_split.as(gtk.Widget));

        self.transfers.init(self);
        self.transfers_initialized = true;
        const content = gtk.Box.new(.vertical, 0);
        content.append(browser_split.as(gtk.Widget));
        content.append(self.transfers.root.as(gtk.Widget));
        window.setChild(content.as(gtk.Widget));

        // Mark registration live before the first append so errdefer cleanup
        // also removes a partially registered listener set.
        self.listeners_registered = true;
        try core.registerListener(.listing_progress, self, onListingProgress);
        try core.registerListener(.listing_done, self, onListingDone);
        try core.registerListener(.site_status, self, onSiteStatus);
        try core.registerListener(.prompt_needed, self, onPromptNeeded);
        try core.registerListener(.transfer_state, self, onTransferState);
        try core.registerListener(.transfer_progress, self, onTransferProgress);
        try core.registerListener(.transcript_line, self, onTranscriptLine);
        try core.registerListener(.op_done, self, onOpDone);

        self.applyPreferences();
        if (self.prefs.session.restore_queue) _ = self.core.restoreQueue();
        self.transfers.syncFromEngine();

        self.restoreSession();
        if (application.smoke_mode) self.startSmokeOperation() catch {
            application.smokeFailed();
        };
        return self;
    }

    fn destroy(self: *Window) void {
        const gpa = self.gpa;
        self.cleanup();
        gpa.destroy(self);
    }

    fn cleanup(self: *Window) void {
        self.saveSession();
        if (self.listeners_registered) {
            self.core.unregisterListeners(@ptrCast(self));
            self.listeners_registered = false;
        }
        if (self.quick_dialog) |dialog| dialog.destroy();
        if (self.site_dialog) |dialog| dialog.destroy();
        if (self.import_dialog) |dialog| dialog.destroy();
        if (self.settings_dialog) |dialog| dialog.destroy();
        if (self.palette_dialog) |dialog| dialog.destroy();
        while (self.prompt_dialogs.pop()) |dialog| dialog.destroy(false);
        self.clearTransients();
        self.transients.deinit(self.gpa);
        self.statuses.deinit(self.gpa);
        self.site_ids.deinit(self.gpa);
        var pending_key_it = self.pending_files.keyIterator();
        while (pending_key_it.next()) |item_id| _ = self.core.cancelTransfer(item_id.*);
        var upload_key_it = self.edit_uploads.keyIterator();
        while (upload_key_it.next()) |item_id| _ = self.core.cancelTransfer(item_id.*);
        var pending_it = self.pending_files.valueIterator();
        while (pending_it.next()) |pending| pending.deinit(self.gpa, self.core.io);
        self.pending_files.deinit(self.gpa);
        while (self.active_edits.pop()) |edit| edit.destroy(false);
        self.active_edits.deinit(self.gpa);
        self.edit_uploads.deinit(self.gpa);
        self.edit_stats.deinit(self.gpa);
        std.Io.Dir.cwd().deleteTree(self.core.io, self.temp_dir) catch {};
        self.gpa.free(self.temp_dir);
        for (self.actions.items) |action| action.unref();
        self.actions.deinit(self.gpa);
        self.ssh.deinit();
        self.frecency.save(self.core.io, self.core.config_dir, "palette-frecency.zon") catch {};
        self.frecency.deinit();
        self.site_model.unref();
        if (self.transfers_initialized) {
            self.transfers.deinit();
            self.transfers_initialized = false;
        }
        if (self.sidebar_initialized) {
            self.sidebar.deinit();
            self.sidebar_initialized = false;
        }
        if (self.inspector_initialized) {
            self.inspector.deinit();
            self.inspector_initialized = false;
        }
        var i = self.panes_initialized;
        while (i > 0) {
            i -= 1;
            self.panes[i].deinit();
        }
        self.panes_initialized = 0;
    }

    fn applyPreferences(self: *Window) void {
        for (&self.panes) |*pane| {
            pane.density.setSelected(switch (self.prefs.density) {
                .comfortable => 0,
                .compact => 1,
                .dense => 2,
            });
            pane.monospace.setActive(@intFromBool(self.prefs.monospace_lists));
        }
        self.sidebar.root.as(gtk.Widget).setVisible(@intFromBool(!self.prefs.session.sidebar_collapsed));
        self.inspector.root.as(gtk.Widget).setVisible(@intFromBool(!self.prefs.session.inspector_collapsed));
        self.transfers.root.setExpanded(@intFromBool(!self.prefs.session.transfers_collapsed));
    }

    fn restoreSession(self: *Window) void {
        const session = self.prefs.session;
        self.restorePane(0, session.pane0_site, session.pane0_path);
        self.restorePane(1, session.pane1_site, session.pane1_path);
        self.setActivePane(&self.panes[if (session.focused_pane == 1) 1 else 0]);
    }

    fn restorePane(self: *Window, index: usize, site_id: u64, path: []const u8) void {
        if (site_id == local_site_id or !self.prefs.reconnect_on_launch or !self.reconnectIsPromptFree(site_id)) {
            self.panes[index].navigate(if (site_id == local_site_id and path.len > 0) path else "/") catch {
                self.panes[index].navigate("/") catch {};
            };
            return;
        }
        const previous = self.active_pane_index;
        self.active_pane_index = index;
        self.connectToSite(site_id, if (path.len > 0) path else null);
        self.active_pane_index = previous;
    }

    fn reconnectIsPromptFree(self: *Window, site_id: u64) bool {
        const site = self.site_store.get(site_id) orelse return false;
        if (site.protocol != .sftp) return false;
        const meta = self.auth_meta.get(site_id) orelse return false;
        return meta.method == .agent;
    }

    fn saveSession(self: *Window) void {
        if (self.panes_initialized != self.panes.len or !self.sidebar_initialized or
            !self.inspector_initialized or !self.transfers_initialized) return;
        var persisted = self.prefs.*;
        persisted.session = .{
            .pane0_site = self.panes[0].site_id,
            .pane0_path = self.panes[0].currentPath(),
            .pane1_site = self.panes[1].site_id,
            .pane1_path = self.panes[1].currentPath(),
            .focused_pane = @intCast(self.active_pane_index),
            .sidebar_collapsed = self.sidebar.root.as(gtk.Widget).getVisible() == 0,
            .transfers_collapsed = self.transfers.root.getExpanded() == 0,
            .inspector_collapsed = self.inspector.root.as(gtk.Widget).getVisible() == 0,
            .restore_queue = self.prefs.session.restore_queue,
        };
        ui.prefs.save(persisted, self.core.io, self.core.config_dir, self.gpa) catch |err| {
            std.log.warn("could not save Linux UI session: {s}", .{@errorName(err)});
        };
    }

    fn paneFor(self: *Window, token: ui.bridge.PaneToken) ?*Pane {
        for (&self.panes) |*pane| if (pane.token == token) return pane;
        return null;
    }

    fn onListingProgress(self: *Window, event: ui.bridge.ListingProgress) void {
        const pane = self.paneFor(event.pane_token) orelse return;
        if (pane.pending_request != event.request_id) return;
        pane.setStatus("Loading {d} items…", .{event.entries_so_far});
        if (event.snapshot) |snapshot| {
            pane.last_latency_ms = event.elapsed_ms;
            pane.replaceSnapshot(snapshot, event.sort_index) catch {};
            pane.pending_request = event.request_id;
            pane.spinner.as(gtk.Widget).setVisible(1);
            pane.spinner.start();
        }
    }

    fn onListingDone(self: *Window, event: ui.bridge.ListingDone) void {
        const pane = self.paneFor(event.pane_token) orelse return;
        if (pane.pending_request != event.request_id) return;
        pane.pending_request = null;
        pane.spinner.stop();
        pane.spinner.as(gtk.Widget).setVisible(0);

        if (event.failure) |failure| {
            pane.setStatus("{s}: {s}", .{ @tagName(failure.class), failure.message });
            self.application.smokeFailed();
            return;
        }
        const snapshot = event.snapshot orelse {
            pane.setStatus("Listing returned no data", .{});
            return;
        };
        pane.last_latency_ms = event.elapsed_ms;
        pane.replaceSnapshot(snapshot, event.sort_index) catch {
            pane.setStatus("Not enough memory to display this directory", .{});
            self.application.smokeFailed();
            return;
        };
        if (pane.site_id != local_site_id) {
            const site = self.site_store.get(pane.site_id);
            const label = if (site) |value| ui.sites.siteLabel(value.*) else "Server";
            self.history.push(pane.site_id, label, snapshot.path) catch {};
            self.history.save(self.core.io, self.core.config_dir, ui.sites.history_file) catch {};
            if (self.sidebar_initialized) self.sidebar.rebuild() catch {};
        }
        if (self.panes[0].snapshot != null and self.panes[0].pending_request == null and
            self.panes[1].snapshot != null and self.panes[1].pending_request == null)
        {
            self.application.smoke_listings_ready = true;
            self.application.maybeSmokeSucceeded();
        }
    }

    fn rebuildSitePicker(self: *Window) !void {
        const old_count = self.site_model.as(gio.ListModel).getNItems();
        if (old_count > 0) self.site_model.splice(0, old_count, null);
        self.site_ids.clearRetainingCapacity();

        var row: usize = 0;
        while (self.site_store.persistedAt(row)) |entry| : (row += 1) {
            const site = entry.site;
            const label = try allocPrintZ(self.gpa, "{s} · {s}", .{
                ui.sites.siteLabel(site), @tagName(site.protocol),
            });
            defer self.gpa.free(label);
            self.site_model.append(label);
            try self.site_ids.append(self.gpa, site.id);
        }
        const have_sites = self.site_ids.items.len > 0;
        self.site_picker.as(gtk.Widget).setSensitive(@intFromBool(have_sites));
        self.connect_button.as(gtk.Widget).setSensitive(@intFromBool(have_sites));
        self.site_picker.setSelected(if (have_sites) 0 else gtk.INVALID_LIST_POSITION);
        self.setHeaderStatus(if (have_sites) "choose a saved site or Connect…" else "Connect… to add a server");
        if (self.sidebar_initialized) try self.sidebar.rebuild();
    }

    fn setHeaderStatus(self: *Window, text: []const u8) void {
        const text_z = allocPrintZ(self.gpa, "Linux · {s}", .{text}) catch return;
        defer self.gpa.free(text_z);
        self.subtitle.setText(text_z);
    }

    fn installCss() void {
        const display = gdk.Display.getDefault() orelse return;
        const provider = gtk.CssProvider.new();
        provider.loadFromString(
            ".relay-pending { opacity: 0.60; }" ++
                ".relay-production { border: 2px solid @warning_color; }" ++
                ".relay-insecure { color: @error_color; font-weight: bold; }",
        );
        gtk.StyleContext.addProviderForDisplay(
            display,
            provider.as(gtk.StyleProvider),
            gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        provider.unref();
    }

    fn installActions(self: *Window, app: *gtk.Application, button: *gtk.MenuButton) !void {
        try self.addAction(app, "settings", onSettingsAction, &.{"<Control>comma"});
        try self.addAction(app, "new-window", onNewWindowAction, &.{"<Control>n"});
        try self.addAction(app, "close-window", onCloseWindowAction, &.{"<Control>w"});
        try self.addAction(app, "connect", onConnectAction, &.{"<Control>k"});
        try self.addAction(app, "disconnect", onDisconnectAction, &.{"<Control><Shift>k"});
        try self.addAction(app, "new-folder", onNewFolderAction, &.{"<Control><Shift>n"});
        try self.addAction(app, "rename", onRenameAction, &.{"F2"});
        try self.addAction(app, "delete", onDeleteAction, &.{"Delete"});
        try self.addAction(app, "refresh", onRefreshAction, &.{ "<Control>r", "F5" });
        try self.addAction(app, "filter", onFilterAction, &.{"<Control>f"});
        try self.addAction(app, "open-terminal", onOpenTerminalAction, &.{"<Control><Alt>t"});
        try self.addAction(app, "copy-scp", onCopyScpAction, &.{});
        try self.addAction(app, "copy-rsync", onCopyRsyncAction, &.{});
        try self.addAction(app, "copy-sftp", onCopySftpAction, &.{});
        try self.addAction(app, "copy-curl", onCopyCurlAction, &.{});
        try self.addAction(app, "palette", onPaletteAction, &.{"<Control><Shift>p"});
        try self.addAction(app, "path-palette", onPathPaletteAction, &.{"<Control>p"});
        try self.addAction(app, "sync-browsing", onSyncBrowsingAction, &.{"<Control><Shift>b"});
        try self.addAction(app, "compare-panes", onComparePanesAction, &.{"<Control><Shift>d"});
        try self.addAction(app, "preview", onPreviewAction, &.{"<Control>y"});
        try self.addAction(app, "edit-external", onEditExternalAction, &.{"<Control>e"});
        try self.addAction(app, "toggle-sidebar", onToggleSidebarAction, &.{"<Control><Alt>s"});
        try self.addAction(app, "toggle-transfers", onToggleTransfersAction, &.{"<Control>j"});
        try self.addAction(app, "toggle-inspector", onToggleInspectorAction, &.{"<Control>i"});
        try self.addAction(app, "pause-all", onPauseAllAction, &.{});
        try self.addAction(app, "resume-all", onResumeAllAction, &.{});
        try self.addAction(app, "retry-failed", onRetryFailedAction, &.{});
        try self.addAction(app, "clear-finished", onClearFinishedAction, &.{});

        const menu = gio.Menu.new();
        defer menu.unref();
        const file = gio.Menu.new();
        defer file.unref();
        file.append("New Window", "app.new-window");
        file.append("Close Window", "app.close-window");
        file.append("Connect to Server…", "app.connect");
        file.append("Disconnect", "app.disconnect");
        file.append("New Folder", "app.new-folder");
        file.append("Rename", "app.rename");
        file.append("Delete", "app.delete");
        file.append("Refresh", "app.refresh");
        menu.appendSection(null, file.as(gio.MenuModel));
        const view = gio.Menu.new();
        defer view.unref();
        view.append("Filter", "app.filter");
        view.append("Sidebar", "app.toggle-sidebar");
        view.append("Transfers", "app.toggle-transfers");
        view.append("Inspector", "app.toggle-inspector");
        view.append("Synchronized Browsing", "app.sync-browsing");
        view.append("Compare Panes", "app.compare-panes");
        view.append("Command Palette…", "app.palette");
        view.append("Go to Path…", "app.path-palette");
        menu.appendSection(null, view.as(gio.MenuModel));
        const server = gio.Menu.new();
        defer server.unref();
        server.append("Open in Terminal", "app.open-terminal");
        server.append("Quick Preview", "app.preview");
        server.append("Edit with External Editor", "app.edit-external");
        const copy_as = gio.Menu.new();
        defer copy_as.unref();
        copy_as.append("scp Command", "app.copy-scp");
        copy_as.append("rsync Command", "app.copy-rsync");
        copy_as.append("SFTP URL", "app.copy-sftp");
        copy_as.append("curl Command", "app.copy-curl");
        server.appendSubmenu("Copy as", copy_as.as(gio.MenuModel));
        menu.appendSection(null, server.as(gio.MenuModel));
        const transfers = gio.Menu.new();
        defer transfers.unref();
        transfers.append("Pause All", "app.pause-all");
        transfers.append("Resume All", "app.resume-all");
        transfers.append("Retry Failed", "app.retry-failed");
        transfers.append("Clear Finished", "app.clear-finished");
        menu.appendSubmenu("Transfers", transfers.as(gio.MenuModel));
        menu.append("Settings…", "app.settings");
        button.setMenuModel(menu.as(gio.MenuModel));
    }

    fn addAction(
        self: *Window,
        app: *gtk.Application,
        name: [*:0]const u8,
        callback: *const fn (*gio.SimpleAction, ?*glib.Variant, *Window) callconv(.c) void,
        comptime accelerators: []const [*:0]const u8,
    ) !void {
        const action = gio.SimpleAction.new(name, null);
        errdefer action.unref();
        _ = gio.SimpleAction.signals.activate.connect(action, *Window, callback, self, .{});
        app.as(gio.ActionMap).addAction(action.as(gio.Action));
        try self.actions.append(self.gpa, action);
        if (accelerators.len > 0) {
            const detailed = try allocPrintZ(self.gpa, "app.{s}", .{std.mem.span(name)});
            defer self.gpa.free(detailed);
            relay_gtk_set_accels(
                app,
                detailed,
                accelerators[0],
                if (accelerators.len > 1) accelerators[1] else null,
            );
        }
    }

    fn activePane(self: *Window) *Pane {
        return &self.panes[self.active_pane_index];
    }

    fn nowEpoch(self: *Window) i64 {
        return @intCast(@divFloor(std.Io.Clock.real.now(self.core.io).nanoseconds, std.time.ns_per_s));
    }

    fn downloadDirectory(self: *Window) ![]u8 {
        const configured = std.mem.trim(u8, self.prefs.download_dir, " \t\r\n");
        const home = if (std.c.getenv("HOME")) |value| std.mem.span(value) else "/";
        const raw = if (configured.len == 0)
            try std.fmt.allocPrint(self.gpa, "{s}/Downloads", .{std.mem.trimEnd(u8, home, "/")})
        else if (std.mem.eql(u8, configured, "~"))
            try self.gpa.dupe(u8, home)
        else if (std.mem.startsWith(u8, configured, "~/"))
            try std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ std.mem.trimEnd(u8, home, "/"), configured[2..] })
        else
            try self.gpa.dupe(u8, configured);
        defer self.gpa.free(raw);
        const normalized = try relay.vfs.path.normalize(self.gpa, raw);
        errdefer self.gpa.free(normalized);
        try self.core.ensureLocalDir(normalized);
        return normalized;
    }

    fn onSettingsAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        SettingsDialog.create(self) catch {};
    }

    fn onNewWindowAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.services.launchNewInstance() catch |err| {
            self.activePane().setStatus("Could not open a new window: {s}", .{@errorName(err)});
        };
    }

    fn onCloseWindowAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.native.as(gtk.Window).close();
    }

    fn onConnectAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        onQuickConnect(undefined, self);
    }

    fn onDisconnectAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.disconnectActivePane();
    }

    fn onNewFolderAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().beginNewFolder();
    }

    fn onRenameAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().beginRename();
    }

    fn onDeleteAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().beginDelete();
    }

    fn onRefreshAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().navigate(self.activePane().currentPath()) catch {};
    }

    fn onFilterAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        _ = self.activePane().filter_entry.as(gtk.Widget).grabFocus();
    }

    fn onOpenTerminalAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        const pane = self.activePane();
        const site = self.site_store.get(pane.site_id) orelse {
            pane.setStatus("Open in Terminal requires a connected SFTP pane", .{});
            return;
        };
        if (site.protocol != .sftp) {
            pane.setStatus("Open in Terminal requires an SFTP site", .{});
            return;
        }
        const spec = ui.terminal.hostSpecForSite(site);
        if (!ui.terminal.destinationSafe(spec)) {
            pane.setStatus("The site host or account is unsafe for a terminal command", .{});
            return;
        }
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const argv = ui.terminal.sshArgv(arena_state.allocator(), spec, pane.currentPath()) catch return;
        self.services.terminal().launch(argv) catch |err| {
            pane.setStatus("Could not launch a terminal: {s}", .{@errorName(err)});
        };
    }

    fn copyAs(self: *Window, kind: ui.terminal.CopyKind) void {
        const pane = self.activePane();
        const site = self.site_store.get(pane.site_id) orelse {
            pane.setStatus("Copy as requires a connected server pane", .{});
            return;
        };
        const selected = pane.selectedPath() catch return;
        defer self.gpa.free(selected.path);
        const spec = ui.terminal.hostSpecForSite(site);
        if (!ui.terminal.destinationSafe(spec)) {
            pane.setStatus("The site host or account is unsafe for a command", .{});
            return;
        }
        const text = switch (kind) {
            .scp => ui.terminal.scpCommandLine(self.gpa, spec, selected.path, selected.is_dir),
            .rsync => ui.terminal.rsyncCommandLine(self.gpa, spec, selected.path),
            .sftp_url => ui.terminal.sftpUrlText(self.gpa, spec, selected.path),
            .curl => ui.terminal.curlCommandLine(self.gpa, site.protocol, spec, selected.path, selected.is_dir),
        } catch return;
        defer self.gpa.free(text);
        self.services.copyText(text);
        pane.setStatus("Copied command to the clipboard", .{});
    }

    fn onCopyScpAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.copyAs(.scp);
    }

    fn onCopyRsyncAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.copyAs(.rsync);
    }

    fn onCopySftpAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.copyAs(.sftp_url);
    }

    fn onCopyCurlAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.copyAs(.curl);
    }

    fn onPaletteAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        PaletteDialog.create(self, .commands) catch {};
    }

    fn onPathPaletteAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        PaletteDialog.create(self, .paths) catch {};
    }

    fn onSyncBrowsingAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.sync_browsing = !self.sync_browsing;
        self.activePane().setStatus("Synchronized browsing {s}", .{if (self.sync_browsing) "enabled" else "disabled"});
    }

    fn onComparePanesAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.compare_panes = !self.compare_panes;
        for (&self.panes) |*pane| pane.list.as(gtk.Widget).queueDraw();
        self.activePane().setStatus("Pane comparison {s}", .{if (self.compare_panes) "enabled" else "disabled"});
    }

    fn onPreviewAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().openSelected(.preview);
    }

    fn onEditExternalAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.activePane().openSelected(.edit);
    }

    fn mirrorNavigation(self: *Window, source: *Pane, old_path: []const u8, new_path: []const u8) void {
        if (!self.sync_browsing or self.syncing_navigation or std.mem.eql(u8, old_path, new_path)) return;
        const destination = if (source == &self.panes[0]) &self.panes[1] else &self.panes[0];
        const destination_path = destination.currentPath();
        var target: ?[]u8 = null;
        if (relay.vfs.path.parent(new_path)) |new_parent| {
            if (std.mem.eql(u8, new_parent, old_path)) {
                target = relay.vfs.path.join(self.gpa, destination_path, relay.vfs.path.basename(new_path)) catch null;
            }
        }
        if (target == null) {
            if (relay.vfs.path.parent(old_path)) |old_parent| {
                if (std.mem.eql(u8, old_parent, new_path)) {
                    const parent = relay.vfs.path.parent(destination_path) orelse "/";
                    target = self.gpa.dupe(u8, parent) catch null;
                }
            }
        }
        const mirrored = target orelse return;
        defer self.gpa.free(mirrored);
        self.syncing_navigation = true;
        defer self.syncing_navigation = false;
        destination.navigate(mirrored) catch |err| {
            destination.setStatus("Synchronized navigation failed: {s}", .{@errorName(err)});
        };
    }

    fn entryDiffers(self: *Window, source: *Pane, entry: Entry) bool {
        if (!self.compare_panes) return false;
        const other = if (source == &self.panes[0]) &self.panes[1] else &self.panes[0];
        const snapshot = other.snapshot orelse return true;
        for (snapshot.entries) |candidate| {
            if (!std.mem.eql(u8, candidate.name, entry.name)) continue;
            return candidate.kind != entry.kind or candidate.size != entry.size or candidate.mtime != entry.mtime;
        }
        return true;
    }

    fn onToggleSidebarAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        const widget = self.sidebar.root.as(gtk.Widget);
        widget.setVisible(@intFromBool(widget.getVisible() == 0));
    }

    fn onToggleTransfersAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.transfers.root.setExpanded(@intFromBool(self.transfers.root.getExpanded() == 0));
    }

    fn onToggleInspectorAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        const widget = self.inspector.root.as(gtk.Widget);
        widget.setVisible(@intFromBool(widget.getVisible() == 0));
    }

    fn onPauseAllAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.core.pauseAllTransfers();
        self.transfers.syncFromEngine();
    }

    fn onResumeAllAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.core.resumeAllTransfers() catch {};
        self.transfers.syncFromEngine();
    }

    fn onRetryFailedAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        _ = self.core.requeueFailed();
        self.transfers.syncFromEngine();
    }

    fn onClearFinishedAction(_: *gio.SimpleAction, _: ?*glib.Variant, self: *Window) callconv(.c) void {
        self.transfers.clearFinished();
    }

    fn onConnectSaved(_: *gtk.Button, self: *Window) callconv(.c) void {
        const selected = self.site_picker.getSelected();
        if (selected == gtk.INVALID_LIST_POSITION or selected >= self.site_ids.items.len) return;
        self.connectToSite(self.site_ids.items[selected], null);
    }

    fn onQuickConnect(_: *gtk.Button, self: *Window) callconv(.c) void {
        if (self.quick_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        QuickDialog.create(self) catch {
            self.panes[remote_pane_index].setStatus("Not enough memory to open Connect", .{});
        };
    }

    fn onDisconnect(_: *gtk.Button, self: *Window) callconv(.c) void {
        self.disconnectActivePane();
    }

    fn connectToSite(self: *Window, site_id: u64, path_override: ?[]const u8) void {
        const site = self.site_store.get(site_id) orelse return;
        const pane_index = self.active_pane_index;
        const pane = &self.panes[pane_index];
        const previous = self.pane_sites[pane_index];
        self.core.connectSite(site_id) catch |err| {
            pane.setStatus("Could not start connection: {s}", .{@errorName(err)});
            return;
        };
        const path = path_override orelse site.initial_remote_path;
        pane.bindSite(site_id, ui.sites.siteLabel(site.*), path) catch |err| {
            self.core.disconnectSite(site_id);
            pane.setStatus("Could not list server: {s}", .{@errorName(err)});
            return;
        };
        if (previous) |old_site_id| {
            if (old_site_id != site_id) self.core.disconnectSite(old_site_id);
        }
        self.pane_sites[pane_index] = site_id;
        self.disconnect_button.as(gtk.Widget).setSensitive(1);
        self.setHeaderStatus("connecting");
    }

    fn disconnectActivePane(self: *Window) void {
        const pane_index = self.active_pane_index;
        if (self.pane_sites[pane_index]) |site_id| self.core.disconnectSite(site_id);
        self.pane_sites[pane_index] = null;
        self.panes[pane_index].bindSite(local_site_id, "Local", "/") catch |err| {
            self.panes[pane_index].setStatus("Could not restore local pane: {s}", .{@errorName(err)});
        };
        self.disconnect_button.as(gtk.Widget).setSensitive(@intFromBool(self.pane_sites[self.active_pane_index] != null));
        self.setHeaderStatus("local");
    }

    fn setActivePane(self: *Window, pane: *Pane) void {
        self.active_pane_index = if (pane == &self.panes[1]) 1 else 0;
        for (&self.panes, 0..) |*candidate, i| {
            if (i == self.active_pane_index) {
                candidate.root.as(gtk.Widget).addCssClass("card");
            } else {
                candidate.root.as(gtk.Widget).removeCssClass("card");
            }
        }
        self.disconnect_button.as(gtk.Widget).setSensitive(@intFromBool(self.pane_sites[self.active_pane_index] != null));
    }

    fn onSiteStatus(self: *Window, event: relay.events.CoreEvent.SiteStatusChange) void {
        self.statuses.put(self.gpa, event.site_id, event.status) catch {};
        self.resolveTransients(event.site_id, event.status);
        var matching_pane: ?*Pane = null;
        for (self.pane_sites, 0..) |pane_site, i| {
            if (pane_site == event.site_id) matching_pane = &self.panes[i];
        }
        const pane = matching_pane orelse return;
        switch (event.status) {
            .connected => {
                self.setHeaderStatus("connected");
                self.disconnect_button.as(gtk.Widget).setSensitive(1);
            },
            .reconnecting => {
                self.setHeaderStatus("reconnecting");
                pane.setStatus("Reconnecting: {s}", .{event.reason});
            },
            .offline => {
                self.setHeaderStatus("offline");
                // The pane stays bound so the failure remains readable;
                // Disconnect still returns it to the local filesystem.
                self.disconnect_button.as(gtk.Widget).setSensitive(1);
                pane.setStatus("Offline{s}{s}", .{
                    if (event.reason.len > 0) ": " else "",
                    event.reason,
                });
            },
        }
    }

    fn onPromptNeeded(self: *Window, event: relay.events.CoreEvent.PromptNeeded) void {
        PromptDialog.create(self, event) catch {
            const token: ui.bridge.PromptToken = .{ .site_id = event.site_id, .prompt_id = event.prompt_id };
            self.core.respondPrompt(token, switch (event.prompt) {
                .host_key => .{ .host_key = false },
                else => .{ .auth = false },
            });
        };
    }

    fn onTransferState(self: *Window, event: relay.events.CoreEvent.TransferStateChange) void {
        self.transfers.applyState(event);
        if (self.edit_uploads.get(event.item_id)) |edit| {
            switch (event.state) {
                .queued, .connecting, .transferring, .conflict => {
                    edit.uploading = true;
                    edit.failed_upload = null;
                },
                .failed => {
                    edit.uploading = false;
                    edit.failed_upload = event.item_id;
                    edit.continuePendingSave();
                },
                else => {},
            }
        }
        if (event.state == .completed or event.state == .failed or event.state == .canceled) {
            const title = if (event.state == .completed) "Transfer complete" else "Transfer failed";
            const body = if (event.failure) |failure| failure.message else if (event.state == .completed)
                "Relay finished a queued transfer."
            else
                "A queued transfer did not complete.";
            self.services.notifier().send(title, body);
        }
        if (event.state == .completed or event.state == .canceled) {
            if (self.edit_uploads.fetchRemove(event.item_id)) |upload| {
                upload.value.uploading = false;
                upload.value.failed_upload = null;
                if (event.state == .completed) {
                    if (!upload.value.requestStat(.baseline)) {
                        upload.value.recorded_mtime = null;
                        upload.value.continuePendingSave();
                    }
                } else {
                    upload.value.continuePendingSave();
                }
            }
        }
        if (event.state == .completed or event.state == .canceled) {
            if (self.pending_files.fetchRemove(event.item_id)) |entry| {
                var pending = entry.value;
                defer pending.deinit(self.gpa, self.core.io);
                if (event.state == .completed) {
                    switch (pending.kind) {
                        .open => self.services.opener().openPath(pending.path) catch {
                            self.activePane().setStatus("Downloaded, but no application could open the file", .{});
                        },
                        .preview => PreviewWindow.create(self, pending.path) catch {
                            self.activePane().setStatus("Downloaded, but the preview could not be shown", .{});
                        },
                        .edit => {
                            self.services.opener().openPath(pending.path) catch {
                                self.activePane().setStatus("Downloaded, but no editor could open the file", .{});
                                return;
                            };
                            // The editor now owns a live path. Keep it until
                            // window cleanup even if watcher setup fails.
                            pending.cleanup_temp = false;
                            ActiveEdit.create(
                                self,
                                pending.path,
                                pending.site_id,
                                pending.remote_path orelse return,
                                pending.remote_mtime,
                            ) catch {
                                self.activePane().setStatus("The file opened, but changes cannot be watched", .{});
                                return;
                            };
                        },
                    }
                }
            }
        }
    }

    fn abandonTransfer(self: *Window, item_id: ui.bridge.ItemId) void {
        if (self.pending_files.fetchRemove(item_id)) |entry| {
            var pending = entry.value;
            pending.deinit(self.gpa, self.core.io);
        }
        if (self.edit_uploads.fetchRemove(item_id)) |entry| {
            entry.value.uploading = false;
            if (entry.value.failed_upload == item_id) entry.value.failed_upload = null;
            entry.value.continuePendingSave();
        }
    }

    fn onTransferProgress(self: *Window, event: relay.events.CoreEvent.TransferProgress) void {
        self.transfers.applyProgress(event);
    }

    fn onTranscriptLine(self: *Window, event: relay.events.CoreEvent.TranscriptLine) void {
        self.transfers.appendTranscript(event);
    }

    fn onOpDone(self: *Window, event: ui.bridge.OpDone) void {
        if (event.op == .stat) {
            if (self.edit_stats.fetchRemove(event.request_id)) |entry| {
                entry.value.handleStat(event);
            }
            return;
        }
        const pane = self.paneFor(event.pane_token) orelse return;
        pane.handleOpDone(event);
        if (self.inspector_initialized) self.inspector.handleOpDone(event);
        self.advanceSmokeOperation(event);
    }

    fn startSmokeOperation(self: *Window) !void {
        const path = try std.fmt.bufPrint(&self.smoke_op_path, "/tmp/relay-gtk-smoke-{d}", .{std.c.getpid()});
        self.smoke_op_path_len = path.len;
        self.smoke_op_stage = .creating;
        try self.core.mkdirPath(self.panes[0].token, local_site_id, path);
    }

    fn advanceSmokeOperation(self: *Window, event: ui.bridge.OpDone) void {
        if (!self.application.smoke_mode or self.smoke_op_stage == .idle or self.smoke_op_stage == .done) return;
        const smoke_path = self.smoke_op_path[0..self.smoke_op_path_len];
        if (event.site_id != local_site_id or !std.mem.eql(u8, event.path, smoke_path)) return;
        if (!event.success) {
            self.application.smokeFailed();
            return;
        }
        switch (self.smoke_op_stage) {
            .creating => {
                self.smoke_op_stage = .deleting;
                self.core.deletePath(self.panes[0].token, local_site_id, smoke_path, true) catch {
                    self.application.smokeFailed();
                };
            },
            .deleting => {
                self.smoke_op_stage = .done;
                self.application.smoke_operation_done = true;
                self.application.maybeSmokeSucceeded();
            },
            .idle, .done => {},
        }
    }

    fn ensureSite(self: *Window, fields: SiteFields, persist: bool) !u64 {
        if (self.site_store.findMatching(fields)) |existing| {
            if (persist and self.site_store.setPersisted(existing, true)) {
                self.site_store.saveTo(self.core.io, self.core.config_dir, ui.bridge.sites_file, self.gpa) catch |err| {
                    _ = self.site_store.setPersisted(existing, false);
                    return err;
                };
                try self.rebuildSitePicker();
            }
            return existing;
        }
        // Publish as ephemeral first. A failed disk write must not leave an
        // entry claiming to be persisted when it is absent from sites.zon.
        const id = try self.site_store.add(fields, false);
        self.syncCore() catch |err| {
            _ = self.site_store.remove(id);
            return err;
        };
        if (persist) {
            _ = self.site_store.setPersisted(id, true);
            self.site_store.saveTo(self.core.io, self.core.config_dir, ui.bridge.sites_file, self.gpa) catch |err| {
                _ = self.site_store.setPersisted(id, false);
                return err;
            };
            try self.rebuildSitePicker();
        }
        return id;
    }

    fn syncCore(self: *Window) !void {
        const slice = try self.site_store.coreSlice();
        self.core.sites_mutex.lockUncancelable(self.core.io);
        self.core.site_list = .{ .sites = slice };
        self.core.sites_mutex.unlock(self.core.io);
    }

    fn storeSecret(self: *Window, site_id: u64, secret: []const u8, keep: bool) bool {
        const site = self.site_store.get(site_id) orelse return false;
        if (site.account.len == 0 or secret.len == 0) return false;
        const key: relay.cred.store.Key = .{
            .protocol = ui.sites.credProtocol(site.protocol),
            .host = site.host,
            .port = site.effectivePort(),
            .account = site.account,
        };
        var diag: relay.diag.Diagnostics = .{};
        self.core.cred_store.set(&diag, key, secret) catch {
            self.panes[remote_pane_index].setStatus("Could not store credential: {s}", .{diag.message});
            return false;
        };
        if (!keep) self.rememberTransient(site_id, key) catch {
            // If we cannot remember how to delete a transient credential,
            // remove it immediately rather than silently making it durable.
            self.deleteCredential(key);
            return false;
        };
        return true;
    }

    fn rememberTransient(self: *Window, site_id: u64, key: relay.cred.store.Key) !void {
        const host = try self.gpa.dupe(u8, key.host);
        errdefer self.gpa.free(host);
        const account = try self.gpa.dupe(u8, key.account);
        errdefer self.gpa.free(account);
        try self.transients.append(self.gpa, .{
            .site_id = site_id,
            .protocol = key.protocol,
            .host = host,
            .port = key.port,
            .account = account,
        });
    }

    fn resolveTransients(self: *Window, site_id: u64, status: SiteStatus) void {
        if (status == .reconnecting) return;
        var i: usize = 0;
        while (i < self.transients.items.len) {
            const transient = self.transients.items[i];
            if (transient.site_id != site_id) {
                i += 1;
                continue;
            }
            self.deleteTransient(transient);
            _ = self.transients.orderedRemove(i);
        }
    }

    fn deleteTransient(self: *Window, transient: TransientCred) void {
        self.deleteCredential(.{
            .protocol = transient.protocol,
            .host = transient.host,
            .port = transient.port,
            .account = transient.account,
        });
        self.gpa.free(transient.host);
        self.gpa.free(transient.account);
    }

    fn deleteCredential(self: *Window, key: relay.cred.store.Key) void {
        var diag: relay.diag.Diagnostics = .{};
        self.core.cred_store.delete(&diag, key) catch {};
    }

    fn clearTransients(self: *Window) void {
        for (self.transients.items) |transient| self.deleteTransient(transient);
        self.transients.clearRetainingCapacity();
    }

    fn removePromptDialog(self: *Window, dialog: *PromptDialog) void {
        for (self.prompt_dialogs.items, 0..) |candidate, i| {
            if (candidate != dialog) continue;
            _ = self.prompt_dialogs.orderedRemove(i);
            return;
        }
    }

    fn persistSites(self: *Window) !void {
        try self.site_store.saveTo(self.core.io, self.core.config_dir, ui.bridge.sites_file, self.gpa);
        try self.syncCore();
        try self.rebuildSitePicker();
    }

    fn deleteSite(self: *Window, site_id: u64) !void {
        const site = (self.site_store.get(site_id) orelse return).*;
        var pane_index: usize = 0;
        while (pane_index < self.pane_sites.len) : (pane_index += 1) {
            if (self.pane_sites[pane_index] != site_id) continue;
            self.core.disconnectSite(site_id);
            self.pane_sites[pane_index] = null;
            try self.panes[pane_index].bindSite(local_site_id, "Local", "/");
        }
        self.deleteCredential(.{
            .protocol = ui.sites.credProtocol(site.protocol),
            .host = site.host,
            .port = site.effectivePort(),
            .account = site.account,
        });
        if (!self.site_store.remove(site_id)) return;
        _ = self.auth_meta.remove(site_id);
        try self.auth_meta.save(self.core.io, self.core.config_dir, ui.sites.meta_file);
        _ = self.statuses.remove(site_id);
        try self.persistSites();
    }

    fn applyImport(self: *Window, result: *const ui.sites.ImportResult, import_passwords: bool) ui.sites.ImportStats {
        var stats: ui.sites.ImportStats = .{ .skipped = result.skipped };
        for (result.sites) |imported| {
            if (!ui.sites.importedFieldSafe(imported.fields.host) or
                !ui.sites.importedFieldSafe(imported.fields.account))
            {
                stats.skipped += 1;
                continue;
            }
            if (self.site_store.findMatching(imported.fields) != null) {
                stats.duplicates += 1;
                continue;
            }
            const site_id = self.site_store.add(imported.fields, true) catch {
                stats.skipped += 1;
                continue;
            };
            stats.imported += 1;
            if (import_passwords) {
                if (imported.password) |password| {
                    if (password.len > 0 and self.storeSecret(site_id, password, true)) {
                        stats.passwords_stored += 1;
                    }
                }
            }
        }
        if (stats.imported > 0) {
            self.persistSites() catch {
                self.panes[self.active_pane_index].setStatus("Imported sites could not be saved", .{});
            };
        }
        return stats;
    }

    fn presentInfo(self: *Window, title: []const u8, detail: []const u8) void {
        const alert = gtk.AlertDialog.new("Relay");
        const title_z = allocPrintZ(self.gpa, "{s}", .{title}) catch null;
        if (title_z) |text| {
            defer self.gpa.free(text);
            alert.setMessage(text);
        }
        const detail_z = allocPrintZ(self.gpa, "{s}", .{detail}) catch null;
        if (detail_z) |text| {
            defer self.gpa.free(text);
            alert.setDetail(text);
        }
        alert.show(self.native.as(gtk.Window));
        alert.unref();
    }
};

const SidebarKind = union(enum) {
    header,
    server: u64,
    ssh: usize,
    history: usize,
};

const SitesSidebar = struct {
    owner: *Window,
    root: *gtk.Box,
    list: *gtk.ListBox,
    edit_button: *gtk.Button,
    duplicate_button: *gtk.Button,
    delete_button: *gtk.Button,
    rows: std.ArrayList(SidebarKind) = .empty,

    fn init(self: *SitesSidebar, owner: *Window) void {
        const root = gtk.Box.new(.vertical, 6);
        root.as(gtk.Widget).setSizeRequest(220, -1);
        root.as(gtk.Widget).setMarginTop(8);
        root.as(gtk.Widget).setMarginBottom(8);
        root.as(gtk.Widget).setMarginStart(8);
        root.as(gtk.Widget).setMarginEnd(8);

        const heading = gtk.Label.new("Connections");
        heading.setXalign(0);
        heading.as(gtk.Widget).addCssClass("title-3");
        const list = gtk.ListBox.new();
        list.setSelectionMode(.single);
        list.as(gtk.Widget).setVexpand(1);
        const scroller = gtk.ScrolledWindow.new();
        scroller.setPolicy(.never, .automatic);
        scroller.setChild(list.as(gtk.Widget));
        scroller.as(gtk.Widget).setVexpand(1);

        const controls = gtk.Box.new(.horizontal, 4);
        const add = gtk.Button.newFromIconName("list-add-symbolic");
        add.as(gtk.Widget).setTooltipText("Add Site");
        const edit = gtk.Button.newFromIconName("document-edit-symbolic");
        edit.as(gtk.Widget).setTooltipText("Edit Site");
        edit.as(gtk.Widget).setSensitive(0);
        const duplicate = gtk.Button.newFromIconName("edit-copy-symbolic");
        duplicate.as(gtk.Widget).setTooltipText("Duplicate Site");
        duplicate.as(gtk.Widget).setSensitive(0);
        const delete = gtk.Button.newFromIconName("user-trash-symbolic");
        delete.as(gtk.Widget).setTooltipText("Delete Site");
        delete.as(gtk.Widget).setSensitive(0);
        controls.append(add.as(gtk.Widget));
        controls.append(edit.as(gtk.Widget));
        controls.append(duplicate.as(gtk.Widget));
        controls.append(delete.as(gtk.Widget));

        const import_fz = gtk.Button.newWithLabel("Import FileZilla");
        const import_duck = gtk.Button.newWithLabel("Import Cyberduck");
        root.append(heading.as(gtk.Widget));
        root.append(scroller.as(gtk.Widget));
        root.append(controls.as(gtk.Widget));
        root.append(import_fz.as(gtk.Widget));
        root.append(import_duck.as(gtk.Widget));

        self.* = .{
            .owner = owner,
            .root = root,
            .list = list,
            .edit_button = edit,
            .duplicate_button = duplicate,
            .delete_button = delete,
        };
        self.rebuild() catch {};

        _ = gtk.ListBox.signals.row_activated.connect(list, *SitesSidebar, onActivated, self, .{});
        _ = gtk.ListBox.signals.selected_rows_changed.connect(list, *SitesSidebar, onSelectionChanged, self, .{});
        _ = gtk.Button.signals.clicked.connect(add, *SitesSidebar, onAdd, self, .{});
        _ = gtk.Button.signals.clicked.connect(edit, *SitesSidebar, onEdit, self, .{});
        _ = gtk.Button.signals.clicked.connect(duplicate, *SitesSidebar, onDuplicate, self, .{});
        _ = gtk.Button.signals.clicked.connect(delete, *SitesSidebar, onDelete, self, .{});
        _ = gtk.Button.signals.clicked.connect(import_fz, *SitesSidebar, onImportFileZilla, self, .{});
        _ = gtk.Button.signals.clicked.connect(import_duck, *SitesSidebar, onImportCyberduck, self, .{});
    }

    fn deinit(self: *SitesSidebar) void {
        self.rows.deinit(self.owner.gpa);
    }

    fn append(self: *SitesSidebar, label_text: []const u8, kind: SidebarKind, selectable: bool) !void {
        const text = try allocPrintZ(self.owner.gpa, "{s}", .{label_text});
        defer self.owner.gpa.free(text);
        const label = gtk.Label.new(text);
        label.setXalign(0);
        label.setEllipsize(.end);
        label.as(gtk.Widget).setMarginTop(if (selectable) 5 else 10);
        label.as(gtk.Widget).setMarginBottom(if (selectable) 5 else 3);
        label.as(gtk.Widget).setMarginStart(if (selectable) 8 else 2);
        label.as(gtk.Widget).setMarginEnd(6);
        if (!selectable) label.as(gtk.Widget).addCssClass("heading");
        self.list.append(label.as(gtk.Widget));
        try self.rows.append(self.owner.gpa, kind);
        if (!selectable) {
            const row = self.list.getRowAtIndex(@intCast(self.rows.items.len - 1)) orelse return;
            row.setSelectable(0);
            row.setActivatable(0);
        }
    }

    fn rebuild(self: *SitesSidebar) !void {
        self.list.removeAll();
        self.rows.clearRetainingCapacity();
        try self.append("SERVERS", .header, false);
        var row: usize = 0;
        while (self.owner.site_store.persistedAt(row)) |entry| : (row += 1) {
            var buf: [512]u8 = undefined;
            const suffix = switch (self.owner.statuses.get(entry.site.id) orelse .offline) {
                .connected => " · connected",
                .reconnecting => " · reconnecting",
                .offline => "",
            };
            const text = std.fmt.bufPrint(&buf, "{s}{s}", .{ ui.sites.siteLabel(entry.site), suffix }) catch ui.sites.siteLabel(entry.site);
            try self.append(text, .{ .server = entry.site.id }, true);
        }
        if (row == 0) try self.append("No saved sites", .header, false);

        try self.append("SSH CONFIG · READ ONLY", .header, false);
        for (self.owner.ssh.aliases.items, 0..) |alias, index| {
            try self.append(alias, .{ .ssh = index }, true);
        }
        if (self.owner.ssh.aliases.items.len == 0) try self.append("No concrete aliases", .header, false);

        try self.append("HISTORY", .header, false);
        for (self.owner.history.entries.items, 0..) |entry, index| {
            var buf: [512]u8 = undefined;
            const text = if (entry.path.len == 0)
                entry.label
            else
                std.fmt.bufPrint(&buf, "{s} · {s}", .{ entry.label, entry.path }) catch entry.label;
            try self.append(text, .{ .history = index }, true);
        }
        if (self.owner.history.entries.items.len == 0) try self.append("No recent locations", .header, false);
        self.updateButtons();
    }

    fn selectedKind(self: *SitesSidebar) ?SidebarKind {
        const row = self.list.getSelectedRow() orelse return null;
        const index = row.getIndex();
        if (index < 0 or @as(usize, @intCast(index)) >= self.rows.items.len) return null;
        return self.rows.items[@intCast(index)];
    }

    fn updateButtons(self: *SitesSidebar) void {
        const is_server = if (self.selectedKind()) |kind| switch (kind) {
            .server => true,
            else => false,
        } else false;
        self.edit_button.as(gtk.Widget).setSensitive(@intFromBool(is_server));
        self.duplicate_button.as(gtk.Widget).setSensitive(@intFromBool(is_server));
        self.delete_button.as(gtk.Widget).setSensitive(@intFromBool(is_server));
    }

    fn activate(self: *SitesSidebar, kind: SidebarKind) void {
        switch (kind) {
            .server => |site_id| self.owner.connectToSite(site_id, null),
            .ssh => |index| {
                if (index >= self.owner.ssh.aliases.items.len) return;
                const alias = self.owner.ssh.aliases.items[index];
                const home = if (std.c.getenv("HOME")) |value| std.mem.span(value) else "/";
                var materialized = self.owner.ssh.materialize(self.owner.gpa, alias, home) catch return;
                defer materialized.deinit();
                const site_id = self.owner.ensureSite(materialized.fields(), false) catch return;
                self.owner.connectToSite(site_id, null);
            },
            .history => |index| {
                if (index >= self.owner.history.entries.items.len) return;
                const entry = self.owner.history.entries.items[index];
                if (self.owner.site_store.get(entry.site_id) == null) {
                    self.owner.panes[self.owner.active_pane_index].setStatus("This history site's saved connection no longer exists", .{});
                    return;
                }
                self.owner.connectToSite(entry.site_id, if (entry.path.len > 0) entry.path else null);
            },
            .header => {},
        }
    }

    fn onActivated(_: *gtk.ListBox, row: *gtk.ListBoxRow, self: *SitesSidebar) callconv(.c) void {
        const index = row.getIndex();
        if (index < 0 or @as(usize, @intCast(index)) >= self.rows.items.len) return;
        self.activate(self.rows.items[@intCast(index)]);
    }

    fn onSelectionChanged(_: *gtk.ListBox, self: *SitesSidebar) callconv(.c) void {
        self.updateButtons();
    }

    fn onAdd(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        SiteDialog.create(self.owner, null, false) catch {};
    }

    fn onEdit(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        const kind = self.selectedKind() orelse return;
        const site_id = switch (kind) {
            .server => |value| value,
            else => return,
        };
        SiteDialog.create(self.owner, site_id, false) catch {};
    }

    fn onDuplicate(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        const kind = self.selectedKind() orelse return;
        const site_id = switch (kind) {
            .server => |value| value,
            else => return,
        };
        SiteDialog.create(self.owner, site_id, true) catch {};
    }

    fn onDelete(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        const kind = self.selectedKind() orelse return;
        const site_id = switch (kind) {
            .server => |value| value,
            else => return,
        };
        SiteDeleteDialog.create(self.owner, site_id) catch {};
    }

    fn onImportFileZilla(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        ImportDialog.create(self.owner, .filezilla) catch {};
    }

    fn onImportCyberduck(_: *gtk.Button, self: *SitesSidebar) callconv(.c) void {
        ImportDialog.create(self.owner, .cyberduck) catch {};
    }
};

fn addFormRow(grid: *gtk.Grid, row: c_int, label_text: [*:0]const u8, widget: *gtk.Widget) void {
    const label = gtk.Label.new(label_text);
    label.setXalign(1);
    label.as(gtk.Widget).setHalign(.end);
    label.as(gtk.Widget).setMarginEnd(10);
    grid.attach(label.as(gtk.Widget), 0, row, 1, 1);
    widget.setHexpand(1);
    grid.attach(widget, 1, row, 1, 1);
}

fn dropdown(options: []const [:0]const u8, selected: usize) *gtk.DropDown {
    const model = gtk.StringList.new(null);
    defer model.unref();
    for (options) |option| model.append(option);
    const result = gtk.DropDown.new(model.as(gio.ListModel), null);
    result.setSelected(@intCast(selected));
    return result;
}

fn setEditableText(gpa: Allocator, editable: *gtk.Editable, text: []const u8) void {
    const text_z = allocPrintZ(gpa, "{s}", .{text}) catch return;
    defer gpa.free(text_z);
    editable.setText(text_z);
}

const SiteDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    source_site_id: ?u64,
    duplicate: bool,
    name: *gtk.Entry,
    protocol: *gtk.DropDown,
    host: *gtk.Entry,
    port: *gtk.Entry,
    account: *gtk.Entry,
    remote_path: *gtk.Entry,
    local_path: *gtk.Entry,
    insecure: *gtk.CheckButton,
    accent: *gtk.DropDown,
    environment: *gtk.DropDown,
    auth: *gtk.DropDown,
    key_path: *gtk.Entry,
    password: *gtk.PasswordEntry,
    error_label: *gtk.Label,

    const protocols = [_][:0]const u8{ "SFTP", "FTPS", "FTP" };
    const accents = [_][:0]const u8{ "None", "Blue", "Purple", "Red", "Orange", "Yellow", "Green", "Graphite" };
    const environments = [_][:0]const u8{ "None", "Development", "Staging", "Production" };
    const auth_methods = [_][:0]const u8{ "SSH Agent", "Key File", "Password" };

    fn create(owner: *Window, source_site_id: ?u64, duplicate: bool) !void {
        if (owner.site_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        const self = try owner.gpa.create(SiteDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle(if (duplicate) "Duplicate Site" else if (source_site_id == null) "Add Site" else "Edit Site");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Save", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.accept));

        const grid = gtk.Grid.new();
        grid.setRowSpacing(8);
        grid.setColumnSpacing(8);
        const grid_widget = grid.as(gtk.Widget);
        grid_widget.setMarginTop(16);
        grid_widget.setMarginBottom(16);
        grid_widget.setMarginStart(16);
        grid_widget.setMarginEnd(16);
        grid_widget.setSizeRequest(560, -1);

        const name = gtk.Entry.new();
        const protocol = dropdown(&protocols, 0);
        const host = gtk.Entry.new();
        const port = gtk.Entry.new();
        port.setPlaceholderText("Protocol default");
        const account = gtk.Entry.new();
        const remote_path = gtk.Entry.new();
        const local_path = gtk.Entry.new();
        const insecure = gtk.CheckButton.newWithLabel("Allow insecure TLS certificates");
        const accent = dropdown(&accents, 0);
        const environment = dropdown(&environments, 0);
        const auth = dropdown(&auth_methods, 0);
        const key_path = gtk.Entry.new();
        key_path.setPlaceholderText("/home/user/.ssh/id_ed25519");
        const password = gtk.PasswordEntry.new();
        password.setShowPeekIcon(1);
        const error_label = gtk.Label.new("");
        error_label.setXalign(0);
        error_label.setWrap(1);
        error_label.as(gtk.Widget).addCssClass("error");
        error_label.as(gtk.Widget).setVisible(0);

        addFormRow(grid, 0, "Display name", name.as(gtk.Widget));
        addFormRow(grid, 1, "Protocol", protocol.as(gtk.Widget));
        addFormRow(grid, 2, "Host", host.as(gtk.Widget));
        addFormRow(grid, 3, "Port", port.as(gtk.Widget));
        addFormRow(grid, 4, "Account", account.as(gtk.Widget));
        addFormRow(grid, 5, "Remote path", remote_path.as(gtk.Widget));
        addFormRow(grid, 6, "Local path", local_path.as(gtk.Widget));
        addFormRow(grid, 7, "TLS", insecure.as(gtk.Widget));
        addFormRow(grid, 8, "Accent", accent.as(gtk.Widget));
        addFormRow(grid, 9, "Environment", environment.as(gtk.Widget));
        addFormRow(grid, 10, "Authentication", auth.as(gtk.Widget));
        addFormRow(grid, 11, "Key file", key_path.as(gtk.Widget));
        addFormRow(grid, 12, "Password", password.as(gtk.Widget));
        grid.attach(error_label.as(gtk.Widget), 1, 13, 1, 1);
        dialog.getContentArea().append(grid_widget);

        self.* = .{
            .owner = owner,
            .native = dialog,
            .source_site_id = source_site_id,
            .duplicate = duplicate,
            .name = name,
            .protocol = protocol,
            .host = host,
            .port = port,
            .account = account,
            .remote_path = remote_path,
            .local_path = local_path,
            .insecure = insecure,
            .accent = accent,
            .environment = environment,
            .auth = auth,
            .key_path = key_path,
            .password = password,
            .error_label = error_label,
        };
        owner.site_dialog = self;
        self.populate();
        _ = gtk.Dialog.signals.response.connect(dialog, *SiteDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        _ = name.as(gtk.Widget).grabFocus();
    }

    fn populate(self: *SiteDialog) void {
        const source_id = self.source_site_id orelse return;
        const site = self.owner.site_store.get(source_id) orelse return;
        var name_buf: [512]u8 = undefined;
        const display_name = if (self.duplicate and site.name.len > 0)
            std.fmt.bufPrintZ(&name_buf, "Copy of {s}", .{site.name}) catch site.name
        else
            site.name;
        const display_name_z = allocPrintZ(self.owner.gpa, "{s}", .{display_name}) catch return;
        defer self.owner.gpa.free(display_name_z);
        self.name.as(gtk.Editable).setText(display_name_z);
        self.protocol.setSelected(switch (site.protocol) {
            .sftp => 0,
            .ftps => 1,
            .ftp => 2,
        });
        setEditableText(self.owner.gpa, self.host.as(gtk.Editable), site.host);
        if (site.port != 0) {
            var port_buf: [8]u8 = undefined;
            const text = std.fmt.bufPrintZ(&port_buf, "{d}", .{site.port}) catch "";
            self.port.as(gtk.Editable).setText(text);
        }
        setEditableText(self.owner.gpa, self.account.as(gtk.Editable), site.account);
        setEditableText(self.owner.gpa, self.remote_path.as(gtk.Editable), site.initial_remote_path);
        setEditableText(self.owner.gpa, self.local_path.as(gtk.Editable), site.initial_local_path);
        self.insecure.setActive(@intFromBool(site.insecure_skip_verify));
        self.accent.setSelected(@intFromEnum(site.accent));
        self.environment.setSelected(@intFromEnum(site.environment));
        if (self.owner.auth_meta.get(source_id)) |meta| {
            self.auth.setSelected(switch (meta.method) {
                .agent => 0,
                .key_file => 1,
                .password => 2,
            });
            setEditableText(self.owner.gpa, self.key_path.as(gtk.Editable), meta.key_path);
        }
    }

    fn showError(self: *SiteDialog, message: []const u8) void {
        const text = allocPrintZ(self.owner.gpa, "{s}", .{message}) catch return;
        defer self.owner.gpa.free(text);
        self.error_label.setText(text);
        self.error_label.as(gtk.Widget).setVisible(1);
    }

    fn protocolValue(self: *SiteDialog) relay.sites.Protocol {
        return switch (self.protocol.getSelected()) {
            1 => .ftps,
            2 => .ftp,
            else => .sftp,
        };
    }

    fn authValue(self: *SiteDialog) ui.sites.AuthMethod {
        return switch (self.auth.getSelected()) {
            1 => .key_file,
            2 => .password,
            else => .agent,
        };
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *SiteDialog) callconv(.c) void {
        if (response != @intFromEnum(gtk.ResponseType.accept)) {
            self.destroy();
            return;
        }
        const host = std.mem.trim(u8, std.mem.span(self.host.as(gtk.Editable).getText()), " \t\r\n");
        if (!ui.sites.hostValid(host)) {
            self.showError("Host is required and may not contain spaces or slashes.");
            return;
        }
        const port_text = std.mem.trim(u8, std.mem.span(self.port.as(gtk.Editable).getText()), " \t\r\n");
        const port = ui.sites.portFromText(port_text) orelse {
            self.showError("Port must be between 1 and 65535, or left empty.");
            return;
        };
        const fields: SiteFields = .{
            .name = std.mem.trim(u8, std.mem.span(self.name.as(gtk.Editable).getText()), " \t\r\n"),
            .protocol = self.protocolValue(),
            .host = host,
            .port = port,
            .account = std.mem.trim(u8, std.mem.span(self.account.as(gtk.Editable).getText()), " \t\r\n"),
            .initial_remote_path = std.mem.trim(u8, std.mem.span(self.remote_path.as(gtk.Editable).getText()), " \t\r\n"),
            .initial_local_path = std.mem.trim(u8, std.mem.span(self.local_path.as(gtk.Editable).getText()), " \t\r\n"),
            .insecure_skip_verify = self.insecure.getActive() != 0,
            .accent = @enumFromInt(@min(self.accent.getSelected(), @intFromEnum(relay.sites.Accent.graphite))),
            .environment = @enumFromInt(@min(self.environment.getSelected(), @intFromEnum(relay.sites.Environment.prod))),
        };

        const edit_id = if (self.duplicate) null else self.source_site_id;
        var site_id: u64 = undefined;
        var old_site: ?relay.sites.Site = null;
        if (edit_id) |id| {
            old_site = (self.owner.site_store.get(id) orelse {
                self.showError("The site no longer exists.");
                return;
            }).*;
            if (!(self.owner.site_store.update(id, fields) catch false)) {
                self.showError("Not enough memory to update this site.");
                return;
            }
            site_id = id;
        } else {
            site_id = self.owner.site_store.add(fields, true) catch {
                self.showError("Not enough memory to add this site.");
                return;
            };
        }

        self.owner.site_store.saveTo(
            self.owner.core.io,
            self.owner.core.config_dir,
            ui.bridge.sites_file,
            self.owner.gpa,
        ) catch |err| {
            if (old_site) |old| {
                _ = self.owner.site_store.update(site_id, .{
                    .name = old.name,
                    .protocol = old.protocol,
                    .host = old.host,
                    .port = old.port,
                    .account = old.account,
                    .initial_remote_path = old.initial_remote_path,
                    .initial_local_path = old.initial_local_path,
                    .insecure_skip_verify = old.insecure_skip_verify,
                    .accent = old.accent,
                    .environment = old.environment,
                }) catch false;
            } else {
                _ = self.owner.site_store.remove(site_id);
            }
            self.showError(@errorName(err));
            return;
        };
        self.owner.syncCore() catch |err| {
            self.showError(@errorName(err));
            return;
        };

        const method = self.authValue();
        const key_path = std.mem.trim(u8, std.mem.span(self.key_path.as(gtk.Editable).getText()), " \t\r\n");
        self.owner.auth_meta.set(site_id, method, key_path) catch {
            self.showError("Site saved, but authentication settings could not be updated.");
            return;
        };
        self.owner.auth_meta.save(self.owner.core.io, self.owner.core.config_dir, ui.sites.meta_file) catch |err| {
            self.showError(@errorName(err));
            return;
        };
        const password = std.mem.span(self.password.as(gtk.Editable).getText());
        if (method == .password and password.len > 0 and !self.owner.storeSecret(site_id, password, true)) {
            self.showError("Site saved, but its password could not be stored in Secret Service.");
            return;
        }
        self.owner.rebuildSitePicker() catch {};
        self.destroy();
    }

    fn destroy(self: *SiteDialog) void {
        const owner = self.owner;
        if (owner.site_dialog == self) owner.site_dialog = null;
        const password = std.mem.span(self.password.as(gtk.Editable).getText());
        std.crypto.secureZero(u8, @constCast(password));
        self.native.as(gtk.Window).destroy();
        owner.gpa.destroy(self);
    }
};

const SiteDeleteDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    site_id: u64,

    fn create(owner: *Window, site_id: u64) !void {
        const site = owner.site_store.get(site_id) orelse return;
        const self = try owner.gpa.create(SiteDeleteDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle("Delete Site");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Delete", @intFromEnum(gtk.ResponseType.accept));
        var buf: [512]u8 = undefined;
        const text = std.fmt.bufPrintZ(&buf, "Delete “{s}”? This removes the saved connection and its Relay credential.", .{
            ui.sites.siteLabel(site.*),
        }) catch "Delete this saved site?";
        const label = gtk.Label.new(text);
        label.setWrap(1);
        label.as(gtk.Widget).setMarginTop(16);
        label.as(gtk.Widget).setMarginBottom(16);
        label.as(gtk.Widget).setMarginStart(16);
        label.as(gtk.Widget).setMarginEnd(16);
        dialog.getContentArea().append(label.as(gtk.Widget));
        self.* = .{ .owner = owner, .native = dialog, .site_id = site_id };
        _ = gtk.Dialog.signals.response.connect(dialog, *SiteDeleteDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *SiteDeleteDialog) callconv(.c) void {
        if (response == @intFromEnum(gtk.ResponseType.accept)) {
            self.owner.deleteSite(self.site_id) catch |err| {
                self.owner.presentInfo("Could not delete site", @errorName(err));
            };
        }
        self.native.as(gtk.Window).destroy();
        self.owner.gpa.destroy(self);
    }
};

const ImportDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    kind: Kind,
    path: *gtk.Entry,
    review: *gtk.Label,
    import_sites: *gtk.Widget,
    import_passwords: *gtk.Widget,
    result: ?ui.sites.ImportResult = null,

    const Kind = enum { filezilla, cyberduck };
    const response_review = 100;
    const response_sites = 101;
    const response_passwords = 102;

    fn create(owner: *Window, kind: Kind) !void {
        if (owner.import_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        const self = try owner.gpa.create(ImportDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle(if (kind == .filezilla) "Import FileZilla Sites" else "Import Cyberduck Bookmarks");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Review", response_review);
        const import_sites = dialog.addButton("Import Sites", response_sites);
        const import_passwords = dialog.addButton("Import Sites and Passwords", response_passwords);
        import_sites.setVisible(0);
        import_passwords.setVisible(0);

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);
        const help = gtk.Label.new(if (kind == .filezilla)
            "Enter the path to FileZilla's sitemanager.xml. Sites are reviewed before import."
        else
            "Enter a .duck file or Cyberduck Bookmarks directory. Sites are reviewed before import.");
        help.setWrap(1);
        help.setXalign(0);
        const path = gtk.Entry.new();
        path.setPlaceholderText(if (kind == .filezilla) "/path/to/sitemanager.xml" else "/path/to/Bookmarks");
        path.setActivatesDefault(1);
        const review = gtk.Label.new("");
        review.setWrap(1);
        review.setXalign(0);
        review.as(gtk.Widget).setVisible(0);
        content.append(help.as(gtk.Widget));
        content.append(path.as(gtk.Widget));
        content.append(review.as(gtk.Widget));

        self.* = .{
            .owner = owner,
            .native = dialog,
            .kind = kind,
            .path = path,
            .review = review,
            .import_sites = import_sites,
            .import_passwords = import_passwords,
        };
        owner.import_dialog = self;
        dialog.setDefaultResponse(response_review);
        _ = gtk.Dialog.signals.response.connect(dialog, *ImportDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        _ = path.as(gtk.Widget).grabFocus();
    }

    fn parse(self: *ImportDialog) !ui.sites.ImportResult {
        const raw_path = std.mem.trim(u8, std.mem.span(self.path.as(gtk.Editable).getText()), " \t\r\n");
        if (raw_path.len == 0) return error.PathRequired;
        return switch (self.kind) {
            .filezilla => blk: {
                const text = try ui.sites.readWholeFile(self.owner.gpa, self.owner.core.io, raw_path);
                defer self.owner.gpa.free(text);
                break :blk try ui.sites.parseFileZilla(self.owner.gpa, text);
            },
            .cyberduck => try self.parseCyberduck(raw_path),
        };
    }

    fn parseCyberduck(self: *ImportDialog, path: []const u8) !ui.sites.ImportResult {
        var files: std.ArrayList([]u8) = .empty;
        defer {
            for (files.items) |file| self.owner.gpa.free(file);
            files.deinit(self.owner.gpa);
        }
        if (std.mem.endsWith(u8, path, ".duck")) {
            try files.append(self.owner.gpa, try ui.sites.readWholeFile(self.owner.gpa, self.owner.core.io, path));
        } else {
            var dir = try std.Io.Dir.cwd().openDir(self.owner.core.io, path, .{ .iterate = true });
            defer dir.close(self.owner.core.io);
            var it = dir.iterate();
            var path_buf: [2048]u8 = undefined;
            while (try it.next(self.owner.core.io)) |entry| {
                if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".duck")) continue;
                const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ path, entry.name }) catch continue;
                const text = ui.sites.readWholeFile(self.owner.gpa, self.owner.core.io, full) catch continue;
                files.append(self.owner.gpa, text) catch {
                    self.owner.gpa.free(text);
                    return error.OutOfMemory;
                };
            }
        }
        if (files.items.len == 0) return error.NoBookmarks;
        return ui.sites.parseCyberduck(self.owner.gpa, @ptrCast(files.items));
    }

    fn showReview(self: *ImportDialog) void {
        if (self.result) |*result| result.deinit();
        self.result = self.parse() catch |err| {
            const text = allocPrintZ(self.owner.gpa, "Could not review import: {s}", .{@errorName(err)}) catch return;
            defer self.owner.gpa.free(text);
            self.review.setText(text);
            self.review.as(gtk.Widget).setVisible(1);
            return;
        };
        const result = &self.result.?;
        var preview: [2048]u8 = undefined;
        var stream = std.Io.Writer.fixed(&preview);
        stream.print("{d} supported site{s}; {d} unsupported entr{s}.", .{
            result.sites.len,
            if (result.sites.len == 1) "" else "s",
            result.skipped,
            if (result.skipped == 1) "y" else "ies",
        }) catch {};
        const shown = @min(result.sites.len, 8);
        for (result.sites[0..shown]) |site| {
            stream.print("\n• {s} — {s}@{s}", .{
                if (site.fields.name.len > 0) site.fields.name else site.fields.host,
                site.fields.account,
                site.fields.host,
            }) catch break;
        }
        if (shown < result.sites.len) stream.print("\n…and {d} more", .{result.sites.len - shown}) catch {};
        const text = allocPrintZ(self.owner.gpa, "{s}", .{stream.buffered()}) catch return;
        defer self.owner.gpa.free(text);
        self.review.setText(text);
        self.review.as(gtk.Widget).setVisible(1);
        self.path.as(gtk.Widget).setSensitive(0);
        self.import_sites.setVisible(1);
        self.import_passwords.setVisible(@intFromBool(self.kind == .filezilla and result.passwordCount() > 0));
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *ImportDialog) callconv(.c) void {
        switch (response) {
            response_review => self.showReview(),
            response_sites, response_passwords => {
                const result = &(self.result orelse return);
                const stats = self.owner.applyImport(result, response == response_passwords);
                var detail_buf: [256]u8 = undefined;
                const detail = std.fmt.bufPrint(&detail_buf, "{d} imported · {d} duplicates · {d} skipped · {d} passwords stored", .{
                    stats.imported,
                    stats.duplicates,
                    stats.skipped,
                    stats.passwords_stored,
                }) catch "Import finished";
                self.owner.presentInfo("Import complete", detail);
                self.destroy();
            },
            else => self.destroy(),
        }
    }

    fn destroy(self: *ImportDialog) void {
        const owner = self.owner;
        if (owner.import_dialog == self) owner.import_dialog = null;
        if (self.result) |*result| result.deinit();
        self.native.as(gtk.Window).destroy();
        owner.gpa.destroy(self);
    }
};

const TransientCred = struct {
    site_id: u64,
    protocol: relay.cred.store.Protocol,
    host: []u8,
    port: u16,
    account: []u8,
};

const QuickDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    target: *gtk.Entry,
    save: *gtk.CheckButton,
    error_label: *gtk.Label,

    fn create(owner: *Window) !void {
        const self = try owner.gpa.create(QuickDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        dialog.as(gtk.Window).setTitle("Connect to Server");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Connect", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.accept));

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);

        const help = gtk.Label.new("Enter sftp://user@host/path, ftps://…, ftp://…, or an SSH config alias.");
        help.setWrap(1);
        help.setXalign(0);
        const target = gtk.Entry.new();
        target.setPlaceholderText("sftp://user@example.com");
        target.setActivatesDefault(1);
        const save = gtk.CheckButton.newWithLabel("Save as site");
        const error_label = gtk.Label.new("");
        error_label.setWrap(1);
        error_label.setXalign(0);
        error_label.as(gtk.Widget).addCssClass("error");
        error_label.as(gtk.Widget).setVisible(0);
        content.append(help.as(gtk.Widget));
        content.append(target.as(gtk.Widget));
        content.append(save.as(gtk.Widget));
        content.append(error_label.as(gtk.Widget));

        self.* = .{ .owner = owner, .native = dialog, .target = target, .save = save, .error_label = error_label };
        owner.quick_dialog = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *QuickDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        _ = target.as(gtk.Widget).grabFocus();
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *QuickDialog) callconv(.c) void {
        if (response != @intFromEnum(gtk.ResponseType.accept)) {
            self.destroy();
            return;
        }
        const raw = std.mem.span(self.target.as(gtk.Editable).getText());
        const target = ui.sites.parseTarget(raw) catch |err| {
            self.showError(ui.sites.parseErrorMessage(err));
            return;
        };
        const persist = self.save.getActive() != 0;
        const owner = self.owner;
        var site_id: u64 = undefined;
        var path: []const u8 = "";
        switch (target) {
            .url => |url| {
                site_id = owner.ensureSite(.{
                    .protocol = url.protocol,
                    .host = url.host,
                    .port = url.port,
                    .account = url.user,
                    .initial_remote_path = url.path,
                }, persist) catch |err| {
                    self.showError(@errorName(err));
                    return;
                };
                path = url.path;
            },
            .alias => |alias| {
                const home = if (std.c.getenv("HOME")) |value| std.mem.span(value) else "/";
                var materialized = owner.ssh.materialize(owner.gpa, alias, home) catch |err| {
                    self.showError(@errorName(err));
                    return;
                };
                defer materialized.deinit();
                site_id = owner.ensureSite(materialized.fields(), persist) catch |err| {
                    self.showError(@errorName(err));
                    return;
                };
            },
        }
        // connectToSite synchronously copies the requested path into its
        // listing job; do it before destroying the entry that owns `path`.
        owner.connectToSite(site_id, if (path.len > 0) path else null);
        self.destroy();
    }

    fn showError(self: *QuickDialog, message: []const u8) void {
        const message_z = allocPrintZ(self.owner.gpa, "{s}", .{message}) catch return;
        defer self.owner.gpa.free(message_z);
        self.error_label.setText(message_z);
        self.error_label.as(gtk.Widget).setVisible(1);
    }

    fn destroy(self: *QuickDialog) void {
        const owner = self.owner;
        if (owner.quick_dialog == self) owner.quick_dialog = null;
        self.native.as(gtk.Window).destroy();
        owner.gpa.destroy(self);
    }
};

const PromptDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    token: ui.bridge.PromptToken,
    kind: Kind,
    secret_entry: ?*gtk.Editable = null,
    save: ?*gtk.CheckButton = null,

    const Kind = enum { host_key, auth, auth_without_secret };

    fn create(owner: *Window, event: relay.events.CoreEvent.PromptNeeded) !void {
        const self = try owner.gpa.create(PromptDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Continue", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.accept));

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);

        self.* = .{
            .owner = owner,
            .native = dialog,
            .token = .{ .site_id = event.site_id, .prompt_id = event.prompt_id },
            .kind = undefined,
        };
        switch (event.prompt) {
            .host_key => |host_key| self.buildHostKey(content, host_key),
            .password => |password| self.buildPassword(content, password),
            .keyboard_interactive => |interactive| self.buildInteractive(content, interactive),
        }
        try owner.prompt_dialogs.append(owner.gpa, self);
        _ = gtk.Dialog.signals.response.connect(dialog, *PromptDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        if (self.secret_entry) |entry| _ = entry.as(gtk.Widget).grabFocus();
    }

    fn buildHostKey(self: *PromptDialog, content: *gtk.Box, host_key: relay.events.Prompt.HostKey) void {
        self.kind = .host_key;
        self.native.as(gtk.Window).setTitle("Verify Host Key");
        var buf: [1024]u8 = undefined;
        const text = std.fmt.bufPrintZ(&buf, "Verify the host key for {s}\n\nFingerprint:\n{s}\n\nAccepting remembers this key for future connections.", .{
            host_key.host, host_key.fingerprint,
        }) catch "Verify this server host key?";
        const label = gtk.Label.new(text);
        label.setWrap(1);
        label.setXalign(0);
        content.append(label.as(gtk.Widget));
    }

    fn buildPassword(self: *PromptDialog, content: *gtk.Box, password: relay.events.Prompt.Password) void {
        self.kind = .auth;
        self.native.as(gtk.Window).setTitle("Password Required");
        var buf: [512]u8 = undefined;
        const text = std.fmt.bufPrintZ(&buf, "Password for {s}@{s}", .{ password.user, password.host }) catch "Password required";
        const label = gtk.Label.new(text);
        label.setXalign(0);
        const entry = gtk.PasswordEntry.new();
        entry.setShowPeekIcon(1);
        const save = gtk.CheckButton.newWithLabel("Remember in Secret Service");
        save.setActive(1);
        content.append(label.as(gtk.Widget));
        content.append(entry.as(gtk.Widget));
        content.append(save.as(gtk.Widget));
        self.secret_entry = entry.as(gtk.Editable);
        self.save = save;
    }

    fn buildInteractive(self: *PromptDialog, content: *gtk.Box, interactive: relay.events.Prompt.KeyboardInteractive) void {
        self.native.as(gtk.Window).setTitle("Authentication Required");
        if (interactive.instruction.len > 0) {
            const instruction_z = allocPrintZ(self.owner.gpa, "{s}", .{interactive.instruction}) catch null;
            if (instruction_z) |text| {
                defer self.owner.gpa.free(text);
                const label = gtk.Label.new(text);
                label.setWrap(1);
                label.setXalign(0);
                content.append(label.as(gtk.Widget));
            }
        }
        if (interactive.prompts.len == 0) {
            self.kind = .auth_without_secret;
            return;
        }
        self.kind = .auth;
        const prompt = interactive.prompts[0];
        const prompt_z = allocPrintZ(self.owner.gpa, "{s}", .{prompt.text}) catch null;
        if (prompt_z) |text| {
            defer self.owner.gpa.free(text);
            const label = gtk.Label.new(text);
            label.setXalign(0);
            content.append(label.as(gtk.Widget));
        }
        if (prompt.echo) {
            const entry = gtk.Entry.new();
            content.append(entry.as(gtk.Widget));
            self.secret_entry = entry.as(gtk.Editable);
        } else {
            const entry = gtk.PasswordEntry.new();
            entry.setShowPeekIcon(1);
            content.append(entry.as(gtk.Widget));
            self.secret_entry = entry.as(gtk.Editable);
        }
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *PromptDialog) callconv(.c) void {
        const accepted = response == @intFromEnum(gtk.ResponseType.accept);
        const answer: ui.bridge.PromptAnswer = switch (self.kind) {
            .host_key => .{ .host_key = accepted },
            .auth_without_secret => .{ .auth = accepted },
            .auth => blk: {
                if (!accepted) break :blk .{ .auth = false };
                const entry = self.secret_entry orelse break :blk .{ .auth = false };
                const secret = std.mem.span(entry.getText());
                const keep = if (self.save) |save| save.getActive() != 0 else false;
                break :blk .{ .auth = self.owner.storeSecret(self.token.site_id, secret, keep) };
            },
        };
        self.owner.core.respondPrompt(self.token, answer);
        self.finish();
    }

    fn finish(self: *PromptDialog) void {
        const owner = self.owner;
        owner.removePromptDialog(self);
        self.native.as(gtk.Window).destroy();
        owner.gpa.destroy(self);
    }

    fn destroy(self: *PromptDialog, respond: bool) void {
        if (!respond) self.owner.core.respondPrompt(self.token, switch (self.kind) {
            .host_key => .{ .host_key = false },
            else => .{ .auth = false },
        });
        self.native.as(gtk.Window).destroy();
        self.owner.gpa.destroy(self);
    }
};

const PreviewWindow = struct {
    fn create(owner: *Window, path: []const u8) !void {
        const contents = try std.Io.Dir.cwd().readFileAlloc(owner.core.io, path, owner.gpa, .limited(1 << 20));
        defer owner.gpa.free(contents);
        const window = gtk.Window.new();
        window.setApplication(owner.application.native);
        window.setTransientFor(owner.native.as(gtk.Window));
        window.setDestroyWithParent(1);
        window.setDefaultSize(760, 560);
        const title = try allocPrintZ(owner.gpa, "Preview — {s}", .{std.fs.path.basename(path)});
        defer owner.gpa.free(title);
        window.setTitle(title);
        const scroller = gtk.ScrolledWindow.new();
        scroller.as(gtk.Widget).setHexpand(1);
        scroller.as(gtk.Widget).setVexpand(1);
        if (std.mem.indexOfScalar(u8, contents, 0) != null) {
            const message = gtk.Label.new("Binary preview is not available. Use Open to launch the default application.");
            message.setWrap(1);
            scroller.setChild(message.as(gtk.Widget));
        } else {
            const buffer = gtk.TextBuffer.new(null);
            const text = gtk.TextView.newWithBuffer(buffer);
            text.setEditable(0);
            text.setCursorVisible(0);
            text.setMonospace(1);
            const text_z = try owner.gpa.dupeZ(u8, contents);
            defer owner.gpa.free(text_z);
            buffer.setText(text_z, @intCast(contents.len));
            scroller.setChild(text.as(gtk.Widget));
        }
        window.setChild(scroller.as(gtk.Widget));
        window.present();
    }
};

const ActiveEdit = struct {
    owner: *Window,
    local_path: []u8,
    remote_path: []u8,
    site_id: u64,
    recorded_mtime: ?i64,
    watcher: ui.platform.services.WatchHandle,
    uploading: bool = false,
    dirty: bool = false,
    failed_upload: ?ui.bridge.ItemId = null,
    stat_request: ?ui.bridge.RequestId = null,
    stat_mode: StatMode = .before_upload,
    conflict: ?*EditConflictDialog = null,

    const StatMode = enum { before_upload, baseline };

    fn create(owner: *Window, local_path: []const u8, site_id: u64, remote_path: []const u8, mtime: ?i64) !void {
        const self = try owner.gpa.create(ActiveEdit);
        errdefer owner.gpa.destroy(self);
        const local = try owner.gpa.dupe(u8, local_path);
        errdefer owner.gpa.free(local);
        const remote = try owner.gpa.dupe(u8, remote_path);
        errdefer owner.gpa.free(remote);
        self.* = .{
            .owner = owner,
            .local_path = local,
            .remote_path = remote,
            .site_id = site_id,
            .recorded_mtime = mtime,
            .watcher = undefined,
        };
        self.watcher = try owner.services.watcher().watch(local, .{ .context = self, .notifyFn = changed });
        errdefer self.watcher.destroy();
        try owner.active_edits.append(owner.gpa, self);
    }

    fn changed(raw: *anyopaque, event: ui.platform.services.WatchEvent) void {
        const self: *ActiveEdit = @ptrCast(@alignCast(raw));
        if (event == .deleted) return;
        self.dirty = true;
        self.continuePendingSave();
    }

    fn continuePendingSave(self: *ActiveEdit) void {
        if (!self.dirty or self.uploading or self.stat_request != null or self.conflict != null) return;
        self.dirty = false;
        if (!self.requestStat(.before_upload)) self.dirty = true;
    }

    fn requestStat(self: *ActiveEdit, mode: StatMode) bool {
        if (self.stat_request != null) return false;
        const request_id = self.owner.core.statPath(self.site_id, self.remote_path) catch |err| {
            self.owner.activePane().setStatus("Could not check the remote file: {s}", .{@errorName(err)});
            return false;
        };
        self.stat_request = request_id;
        self.stat_mode = mode;
        self.owner.edit_stats.put(self.owner.gpa, request_id, self) catch {
            self.stat_request = null;
            self.owner.activePane().setStatus("Could not track the remote file check", .{});
            return false;
        };
        return true;
    }

    fn handleStat(self: *ActiveEdit, event: ui.bridge.OpDone) void {
        const mode = self.stat_mode;
        self.stat_request = null;
        if (!event.success) {
            if (mode == .baseline) {
                self.recorded_mtime = null;
                self.continuePendingSave();
            } else {
                self.dirty = true;
            }
            const message = if (event.failure) |failure| failure.message else "Unknown error";
            self.owner.activePane().setStatus("Could not check the remote file: {s}", .{message});
            return;
        }
        if (mode == .baseline) {
            self.recorded_mtime = event.mtime;
            self.continuePendingSave();
            return;
        }
        if (self.uploading) {
            self.dirty = true;
            return;
        }
        if (ui.edit_sessions.decideOnSave(self.recorded_mtime, event.mtime) == .conflict) {
            EditConflictDialog.create(self) catch {
                self.dirty = true;
                self.owner.activePane().setStatus("Could not show the remote edit conflict", .{});
            };
            return;
        }
        if (!self.enqueue(self.remote_path)) self.dirty = true;
    }

    fn enqueue(self: *ActiveEdit, target: []const u8) bool {
        if (self.failed_upload) |item_id| {
            switch (self.owner.core.removeTransferDetailed(item_id)) {
                .not_found, .removed => {
                    _ = self.owner.edit_uploads.remove(item_id);
                    self.failed_upload = null;
                },
                .canceling => return false,
            }
        }
        const item_id = self.owner.core.enqueueTransfer(.{
            .direction = .upload,
            .kind = .file,
            .src = .{ .site_id = local_site_id, .path = self.local_path },
            .dst = .{ .site_id = self.site_id, .path = target },
            .conflict = .overwrite,
        }) catch |err| {
            self.owner.activePane().setStatus("Could not upload edited file: {s}", .{@errorName(err)});
            return false;
        };
        self.uploading = true;
        self.owner.edit_uploads.put(self.owner.gpa, item_id, self) catch {
            self.uploading = false;
            _ = self.owner.core.cancelTransfer(item_id);
            return false;
        };
        self.owner.transfers.root.setExpanded(1);
        self.owner.transfers.syncFromEngine();
        self.owner.activePane().setStatus("Uploading external edit…", .{});
        return true;
    }

    fn destroy(self: *ActiveEdit, remove: bool) void {
        if (self.conflict) |dialog| dialog.destroy(false);
        if (self.stat_request) |request_id| _ = self.owner.edit_stats.remove(request_id);
        self.watcher.destroy();
        if (remove) {
            for (self.owner.active_edits.items, 0..) |candidate, i| {
                if (candidate == self) {
                    _ = self.owner.active_edits.swapRemove(i);
                    break;
                }
            }
        }
        std.Io.Dir.cwd().deleteFile(self.owner.core.io, self.local_path) catch {};
        self.owner.gpa.free(self.local_path);
        self.owner.gpa.free(self.remote_path);
        const gpa = self.owner.gpa;
        gpa.destroy(self);
    }
};

const EditConflictDialog = struct {
    edit: *ActiveEdit,
    native: *gtk.Dialog,

    fn create(edit: *ActiveEdit) !void {
        if (edit.conflict) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        const self = try edit.owner.gpa.create(EditConflictDialog);
        errdefer edit.owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle("Remote file changed");
        dialog.as(gtk.Window).setTransientFor(edit.owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Upload Copy", 2);
        _ = dialog.addButton("Overwrite Remote", 1);
        const label = gtk.Label.new("The remote file changed after editing began. Overwrite it, upload a copy, or cancel.");
        label.setWrap(1);
        const content = dialog.getContentArea();
        content.as(gtk.Widget).setMarginTop(16);
        content.as(gtk.Widget).setMarginBottom(16);
        content.as(gtk.Widget).setMarginStart(16);
        content.as(gtk.Widget).setMarginEnd(16);
        content.append(label.as(gtk.Widget));
        self.* = .{ .edit = edit, .native = dialog };
        edit.conflict = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *EditConflictDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *EditConflictDialog) callconv(.c) void {
        if (response == 1) {
            if (!self.edit.enqueue(self.edit.remote_path)) self.edit.dirty = true;
        } else if (response == 2) {
            const parent = relay.vfs.path.parent(self.edit.remote_path) orelse "/";
            const duplicate_name = ui.edit_sessions.duplicateName(
                self.edit.owner.gpa,
                relay.vfs.path.basename(self.edit.remote_path),
            ) catch {
                self.destroy(true);
                return;
            };
            defer self.edit.owner.gpa.free(duplicate_name);
            const target = relay.vfs.path.join(self.edit.owner.gpa, parent, duplicate_name) catch {
                self.destroy(true);
                return;
            };
            defer self.edit.owner.gpa.free(target);
            if (!self.edit.enqueue(target)) self.edit.dirty = true;
        }
        self.destroy(true);
    }

    fn destroy(self: *EditConflictDialog, clear: bool) void {
        if (clear) {
            self.edit.conflict = null;
            self.edit.continuePendingSave();
        }
        self.native.as(gtk.Window).destroy();
        self.edit.owner.gpa.destroy(self);
    }
};

const PaletteDialog = struct {
    const Mode = enum { commands, paths };
    const Command = enum {
        connect,
        disconnect,
        new_folder,
        rename,
        delete,
        refresh,
        settings,
        open_terminal,
        toggle_sidebar,
        toggle_transfers,
        toggle_inspector,
        pause_all,
        resume_all,
        retry_failed,
    };
    const Candidate = struct {
        title: []const u8,
        hint: []const u8 = "",
        key: []const u8 = "",
        path: []const u8 = "",
        command: ?Command = null,
    };
    const Model = ui.palette.Model(Candidate, 64);

    owner: *Window,
    native: *gtk.Dialog,
    search: *gtk.SearchEntry,
    list: *gtk.ListBox,
    mode: Mode,
    model: Model,

    fn create(owner: *Window, mode: Mode) !void {
        if (owner.palette_dialog) |dialog| dialog.destroy();
        const self = try owner.gpa.create(PaletteDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle(if (mode == .commands) "Command Palette" else "Go to Path");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDefaultSize(520, 420);
        _ = dialog.addButton("Close", @intFromEnum(gtk.ResponseType.close));
        const content = dialog.getContentArea();
        content.setSpacing(8);
        const widget = content.as(gtk.Widget);
        widget.setMarginTop(12);
        widget.setMarginBottom(12);
        widget.setMarginStart(12);
        widget.setMarginEnd(12);
        const search = gtk.SearchEntry.new();
        search.setPlaceholderText(if (mode == .commands) "Type a command" else "Type a folder");
        const list = gtk.ListBox.new();
        list.setSelectionMode(.single);
        list.setActivateOnSingleClick(0);
        const scroller = gtk.ScrolledWindow.new();
        scroller.as(gtk.Widget).setVexpand(1);
        scroller.setChild(list.as(gtk.Widget));
        content.append(search.as(gtk.Widget));
        content.append(scroller.as(gtk.Widget));

        self.* = .{
            .owner = owner,
            .native = dialog,
            .search = search,
            .list = list,
            .mode = mode,
            .model = .init(owner.gpa),
        };
        errdefer self.model.deinit();
        try self.populate();
        self.filter();
        owner.palette_dialog = self;
        _ = gtk.SearchEntry.signals.search_changed.connect(search, *PaletteDialog, onSearchChanged, self, .{});
        _ = gtk.SearchEntry.signals.activate.connect(search, *PaletteDialog, onActivate, self, .{});
        _ = gtk.ListBox.signals.row_activated.connect(list, *PaletteDialog, onRowActivated, self, .{});
        _ = gtk.Dialog.signals.response.connect(dialog, *PaletteDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        _ = search.as(gtk.Widget).grabFocus();
    }

    fn populate(self: *PaletteDialog) !void {
        if (self.mode == .commands) {
            const commands = [_]Candidate{
                .{ .title = "Connect to Server", .hint = "Ctrl+K", .key = "connect", .command = .connect },
                .{ .title = "Disconnect", .hint = "Ctrl+Shift+K", .key = "disconnect", .command = .disconnect },
                .{ .title = "New Folder", .hint = "Ctrl+Shift+N", .key = "new-folder", .command = .new_folder },
                .{ .title = "Rename", .hint = "F2", .key = "rename", .command = .rename },
                .{ .title = "Delete", .hint = "Delete", .key = "delete", .command = .delete },
                .{ .title = "Refresh", .hint = "Ctrl+R", .key = "refresh", .command = .refresh },
                .{ .title = "Settings", .hint = "Ctrl+,", .key = "settings", .command = .settings },
                .{ .title = "Open in Terminal", .hint = "Ctrl+Alt+T", .key = "terminal", .command = .open_terminal },
                .{ .title = "Toggle Sidebar", .key = "sidebar", .command = .toggle_sidebar },
                .{ .title = "Toggle Transfers", .key = "transfers", .command = .toggle_transfers },
                .{ .title = "Toggle Inspector", .key = "inspector", .command = .toggle_inspector },
                .{ .title = "Pause All Transfers", .key = "pause-all", .command = .pause_all },
                .{ .title = "Resume All Transfers", .key = "resume-all", .command = .resume_all },
                .{ .title = "Retry Failed Transfers", .key = "retry-failed", .command = .retry_failed },
            };
            for (commands) |candidate| try self.model.add(candidate);
            return;
        }
        const pane = self.owner.activePane();
        if (pane.snapshot) |snapshot| {
            try self.model.add(.{ .title = snapshot.path, .key = snapshot.path, .path = snapshot.path });
            for (snapshot.entries) |entry| {
                if (entry.kind != .dir or !relay.vfs.path.isSafeChildName(entry.name)) continue;
                const path = relay.vfs.path.join(self.owner.gpa, snapshot.path, entry.name) catch continue;
                defer self.owner.gpa.free(path);
                try self.model.add(.{ .title = path, .key = path, .path = path });
            }
        }
        for (self.owner.history.entries.items) |entry| {
            if (entry.path.len == 0 or self.model.hasKey(entry.path)) continue;
            try self.model.add(.{ .title = entry.path, .hint = entry.label, .key = entry.path, .path = entry.path });
        }
    }

    fn filter(self: *PaletteDialog) void {
        const query = std.mem.trim(u8, std.mem.span(self.search.as(gtk.Editable).getText()), " \t\r\n");
        self.model.filter(query, &self.owner.frecency, self.owner.nowEpoch());
        self.list.removeAll();
        var row: usize = 0;
        while (row < self.model.resultCount()) : (row += 1) {
            const candidate = self.model.resultAt(row) orelse continue;
            const box = gtk.Box.new(.horizontal, 8);
            const title_z = allocPrintZ(self.owner.gpa, "{s}", .{candidate.title}) catch continue;
            defer self.owner.gpa.free(title_z);
            const title = gtk.Label.new(title_z);
            title.setXalign(0);
            title.as(gtk.Widget).setHexpand(1);
            box.append(title.as(gtk.Widget));
            if (candidate.hint.len > 0) {
                const hint_z = allocPrintZ(self.owner.gpa, "{s}", .{candidate.hint}) catch continue;
                defer self.owner.gpa.free(hint_z);
                const hint = gtk.Label.new(hint_z);
                hint.as(gtk.Widget).addCssClass("dim-label");
                box.append(hint.as(gtk.Widget));
            }
            self.list.append(box.as(gtk.Widget));
        }
        if (self.list.getRowAtIndex(0)) |first| self.list.selectRow(first);
    }

    fn execute(self: *PaletteDialog, index: usize) void {
        const candidate = self.model.resultAt(index) orelse return;
        self.owner.frecency.bump(candidate.key, self.owner.nowEpoch()) catch {};
        if (self.mode == .paths) {
            self.owner.activePane().navigate(candidate.path) catch |err| {
                self.owner.activePane().setStatus("Cannot open path: {s}", .{@errorName(err)});
            };
            self.destroy();
            return;
        }
        switch (candidate.command orelse return) {
            .connect => Window.onQuickConnect(undefined, self.owner),
            .disconnect => self.owner.disconnectActivePane(),
            .new_folder => self.owner.activePane().beginNewFolder(),
            .rename => self.owner.activePane().beginRename(),
            .delete => self.owner.activePane().beginDelete(),
            .refresh => self.owner.activePane().navigate(self.owner.activePane().currentPath()) catch {},
            .settings => SettingsDialog.create(self.owner) catch {},
            .open_terminal => Window.onOpenTerminalAction(undefined, null, self.owner),
            .toggle_sidebar => Window.onToggleSidebarAction(undefined, null, self.owner),
            .toggle_transfers => Window.onToggleTransfersAction(undefined, null, self.owner),
            .toggle_inspector => Window.onToggleInspectorAction(undefined, null, self.owner),
            .pause_all => Window.onPauseAllAction(undefined, null, self.owner),
            .resume_all => Window.onResumeAllAction(undefined, null, self.owner),
            .retry_failed => Window.onRetryFailedAction(undefined, null, self.owner),
        }
        self.destroy();
    }

    fn onSearchChanged(_: *gtk.SearchEntry, self: *PaletteDialog) callconv(.c) void {
        self.filter();
    }

    fn onActivate(_: *gtk.SearchEntry, self: *PaletteDialog) callconv(.c) void {
        const row = self.list.getSelectedRow() orelse self.list.getRowAtIndex(0) orelse return;
        self.execute(@intCast(row.getIndex()));
    }

    fn onRowActivated(_: *gtk.ListBox, row: *gtk.ListBoxRow, self: *PaletteDialog) callconv(.c) void {
        self.execute(@intCast(row.getIndex()));
    }

    fn onResponse(_: *gtk.Dialog, _: c_int, self: *PaletteDialog) callconv(.c) void {
        self.destroy();
    }

    fn destroy(self: *PaletteDialog) void {
        self.owner.palette_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.model.deinit();
        self.owner.gpa.destroy(self);
    }
};

const SettingsDialog = struct {
    owner: *Window,
    native: *gtk.Dialog,
    download_dir: *gtk.Entry,
    confirm_delete: *gtk.CheckButton,
    reconnect: *gtk.CheckButton,
    restore_queue: *gtk.CheckButton,
    hidden: *gtk.CheckButton,
    monospace: *gtk.CheckButton,
    vim: *gtk.CheckButton,
    density: *gtk.DropDown,
    date_format: *gtk.DropDown,
    connections: *gtk.SpinButton,
    upload: *gtk.SpinButton,
    download: *gtk.SpinButton,
    error_label: *gtk.Label,

    fn create(owner: *Window) !void {
        if (owner.settings_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        const self = try owner.gpa.create(SettingsDialog);
        errdefer owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle("Relay Settings");
        dialog.as(gtk.Window).setTransientFor(owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDefaultSize(520, 520);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Save", @intFromEnum(gtk.ResponseType.accept));

        const grid = gtk.Grid.new();
        grid.setColumnSpacing(12);
        grid.setRowSpacing(10);
        const grid_widget = grid.as(gtk.Widget);
        grid_widget.setMarginTop(16);
        grid_widget.setMarginBottom(16);
        grid_widget.setMarginStart(16);
        grid_widget.setMarginEnd(16);

        const download_dir = gtk.Entry.new();
        setEditableText(owner.gpa, download_dir.as(gtk.Editable), owner.prefs.download_dir);
        download_dir.setPlaceholderText("~/Downloads");
        const confirm_delete = gtk.CheckButton.newWithLabel("Confirm file deletions");
        confirm_delete.setActive(@intFromBool(owner.prefs.confirm_delete));
        const reconnect = gtk.CheckButton.newWithLabel("Reconnect prompt-free servers at launch");
        reconnect.setActive(@intFromBool(owner.prefs.reconnect_on_launch));
        const restore_queue = gtk.CheckButton.newWithLabel("Restore the transfer queue at launch");
        restore_queue.setActive(@intFromBool(owner.prefs.session.restore_queue));
        const hidden = gtk.CheckButton.newWithLabel("Show hidden files by default");
        hidden.setActive(@intFromBool(owner.core.settings.show_hidden_files));
        const monospace = gtk.CheckButton.newWithLabel("Use monospace file names");
        monospace.setActive(@intFromBool(owner.prefs.monospace_lists));
        const vim = gtk.CheckButton.newWithLabel("Enable Vim browser keys");
        vim.setActive(@intFromBool(owner.prefs.vim_mode));
        const density = dropdown(&.{ "Comfortable", "Compact", "Dense" }, switch (owner.prefs.density) {
            .comfortable => 0,
            .compact => 1,
            .dense => 2,
        });
        const date_format = dropdown(&.{ "ISO 8601", "Relative" }, if (owner.prefs.date_format == .iso) 0 else 1);
        const connections = gtk.SpinButton.newWithRange(1, 8, 1);
        connections.setValue(@floatFromInt(owner.core.settings.connections_per_site));
        const upload = gtk.SpinButton.newWithRange(0, 10_000_000, 100);
        upload.setValue(@floatFromInt(owner.core.settings.rate_limit_up / 1024));
        const download = gtk.SpinButton.newWithRange(0, 10_000_000, 100);
        download.setValue(@floatFromInt(owner.core.settings.rate_limit_down / 1024));
        const error_label = gtk.Label.new("");
        error_label.setXalign(0);
        error_label.setWrap(1);
        error_label.as(gtk.Widget).addCssClass("error");

        attachSetting(grid, 0, "Default download directory", download_dir.as(gtk.Widget));
        attachSetting(grid, 1, "Connections per site", connections.as(gtk.Widget));
        attachSetting(grid, 2, "Upload limit (KB/s)", upload.as(gtk.Widget));
        attachSetting(grid, 3, "Download limit (KB/s)", download.as(gtk.Widget));
        attachSetting(grid, 4, "File-list density", density.as(gtk.Widget));
        attachSetting(grid, 5, "Modified date format", date_format.as(gtk.Widget));
        grid.attach(confirm_delete.as(gtk.Widget), 0, 6, 2, 1);
        grid.attach(reconnect.as(gtk.Widget), 0, 7, 2, 1);
        grid.attach(restore_queue.as(gtk.Widget), 0, 8, 2, 1);
        grid.attach(hidden.as(gtk.Widget), 0, 9, 2, 1);
        grid.attach(monospace.as(gtk.Widget), 0, 10, 2, 1);
        grid.attach(vim.as(gtk.Widget), 0, 11, 2, 1);
        grid.attach(error_label.as(gtk.Widget), 0, 12, 2, 1);
        dialog.getContentArea().append(grid.as(gtk.Widget));

        self.* = .{
            .owner = owner,
            .native = dialog,
            .download_dir = download_dir,
            .confirm_delete = confirm_delete,
            .reconnect = reconnect,
            .restore_queue = restore_queue,
            .hidden = hidden,
            .monospace = monospace,
            .vim = vim,
            .density = density,
            .date_format = date_format,
            .connections = connections,
            .upload = upload,
            .download = download,
            .error_label = error_label,
        };
        owner.settings_dialog = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *SettingsDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
    }

    fn attachSetting(grid: *gtk.Grid, row: c_int, title: [*:0]const u8, control: *gtk.Widget) void {
        const label = gtk.Label.new(title);
        label.setXalign(0);
        label.as(gtk.Widget).setHalign(.start);
        control.setHexpand(1);
        grid.attach(label.as(gtk.Widget), 0, row, 1, 1);
        grid.attach(control, 1, row, 1, 1);
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *SettingsDialog) callconv(.c) void {
        if (response != @intFromEnum(gtk.ResponseType.accept)) {
            self.destroy();
            return;
        }
        self.save() catch |err| {
            const message = allocPrintZ(self.owner.gpa, "Could not save settings: {s}", .{@errorName(err)}) catch return;
            defer self.owner.gpa.free(message);
            self.error_label.setText(message);
            return;
        };
        self.destroy();
    }

    fn save(self: *SettingsDialog) !void {
        const new_download_dir = try self.owner.gpa.dupe(
            u8,
            std.mem.trim(u8, std.mem.span(self.download_dir.as(gtk.Editable).getText()), " \t\r\n"),
        );
        self.owner.gpa.free(self.owner.prefs.download_dir);
        self.owner.prefs.download_dir = new_download_dir;
        self.owner.prefs.confirm_delete = self.confirm_delete.getActive() != 0;
        self.owner.prefs.reconnect_on_launch = self.reconnect.getActive() != 0;
        self.owner.prefs.session.restore_queue = self.restore_queue.getActive() != 0;
        self.owner.prefs.monospace_lists = self.monospace.getActive() != 0;
        self.owner.prefs.vim_mode = self.vim.getActive() != 0;
        self.owner.prefs.density = switch (self.density.getSelected()) {
            0 => .comfortable,
            2 => .dense,
            else => .compact,
        };
        self.owner.prefs.date_format = if (self.date_format.getSelected() == 1) .relative else .iso;

        self.owner.core.settings.show_hidden_files = self.hidden.getActive() != 0;
        self.owner.core.settings.connections_per_site = @intCast(self.connections.getValueAsInt());
        const upload = @as(u64, @intCast(self.upload.getValueAsInt())) * 1024;
        const download = @as(u64, @intCast(self.download.getValueAsInt())) * 1024;
        self.owner.core.setTransferRateLimits(upload, download);
        try self.owner.core.saveSettings();
        try ui.prefs.save(self.owner.prefs.*, self.owner.core.io, self.owner.core.config_dir, self.owner.gpa);
        self.owner.applyPreferences();
        for (&self.owner.panes) |*pane| {
            pane.hidden_toggle.setActive(@intFromBool(self.owner.core.settings.show_hidden_files));
            pane.filter.as(gtk.Filter).changed(.different);
            pane.list.as(gtk.Widget).queueDraw();
        }
        self.owner.transfers.upload_limit.setValue(@floatFromInt(upload / 1024));
        self.owner.transfers.download_limit.setValue(@floatFromInt(download / 1024));
    }

    fn destroy(self: *SettingsDialog) void {
        self.owner.settings_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.owner.gpa.destroy(self);
    }
};

const InspectorPanel = struct {
    owner: *Window,
    root: *gtk.Box,
    summary: *gtk.Label,
    details: *gtk.Label,
    mode_entry: *gtk.Entry,
    apply_button: *gtk.Button,
    stage: *gtk.Label,
    pane: ?*Pane = null,
    pending_path: ?[]u8 = null,
    pending_site: u64 = 0,

    fn init(self: *InspectorPanel, owner: *Window) void {
        const root = gtk.Box.new(.vertical, 8);
        root.as(gtk.Widget).setSizeRequest(230, -1);
        root.as(gtk.Widget).setMarginTop(12);
        root.as(gtk.Widget).setMarginBottom(12);
        root.as(gtk.Widget).setMarginStart(12);
        root.as(gtk.Widget).setMarginEnd(12);
        const title = gtk.Label.new("Inspector");
        title.setXalign(0);
        title.as(gtk.Widget).addCssClass("title-3");
        const summary = gtk.Label.new("No selection");
        summary.setXalign(0);
        summary.setWrap(1);
        const details = gtk.Label.new("");
        details.setXalign(0);
        details.setWrap(1);
        details.setSelectable(1);
        const separator = gtk.Separator.new(.horizontal);
        const mode_label = gtk.Label.new("Remote permissions (octal)");
        mode_label.setXalign(0);
        const mode_entry = gtk.Entry.new();
        mode_entry.setPlaceholderText("644");
        mode_entry.setMaxLength(3);
        const apply_button = gtk.Button.newWithLabel("Apply Permissions");
        apply_button.as(gtk.Widget).setSensitive(0);
        const stage = gtk.Label.new("");
        stage.setXalign(0);
        stage.setWrap(1);
        stage.as(gtk.Widget).addCssClass("dim-label");
        root.append(title.as(gtk.Widget));
        root.append(summary.as(gtk.Widget));
        root.append(details.as(gtk.Widget));
        root.append(separator.as(gtk.Widget));
        root.append(mode_label.as(gtk.Widget));
        root.append(mode_entry.as(gtk.Widget));
        root.append(apply_button.as(gtk.Widget));
        root.append(stage.as(gtk.Widget));
        self.* = .{
            .owner = owner,
            .root = root,
            .summary = summary,
            .details = details,
            .mode_entry = mode_entry,
            .apply_button = apply_button,
            .stage = stage,
        };
        _ = gtk.Button.signals.clicked.connect(apply_button, *InspectorPanel, onApply, self, .{});
        _ = gtk.Editable.signals.changed.connect(mode_entry.as(gtk.Editable), *InspectorPanel, onModeChanged, self, .{});
    }

    fn deinit(self: *InspectorPanel) void {
        if (self.pending_path) |path| self.owner.gpa.free(path);
        self.pending_path = null;
    }

    fn update(self: *InspectorPanel, pane: *Pane) void {
        self.pane = pane;
        const snapshot = pane.snapshot orelse {
            self.summary.setText("No selection");
            self.details.setText("");
            self.apply_button.as(gtk.Widget).setSensitive(0);
            return;
        };
        var count: usize = 0;
        var total_size: u64 = 0;
        var first: ?*const relay.vfs.iface.Entry = null;
        const model = pane.selection.as(gtk.SelectionModel);
        const item_count = pane.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < item_count) : (position += 1) {
            if (model.isSelected(position) == 0) continue;
            const entry_index = pane.entryIndexAt(position) orelse continue;
            if (entry_index >= snapshot.entries.len) continue;
            const entry = &snapshot.entries[entry_index];
            if (first == null) first = entry;
            count += 1;
            total_size +|= entry.size orelse 0;
        }
        if (count == 0) {
            self.summary.setText("No selection");
            self.details.setText("");
            self.mode_entry.as(gtk.Editable).setText("");
            self.apply_button.as(gtk.Widget).setSensitive(0);
            self.stage.setText("");
            return;
        }
        var size_buf: [32]u8 = undefined;
        var summary_buf: [160]u8 = undefined;
        const summary = std.fmt.bufPrintZ(&summary_buf, "{d} item{s} · {s}", .{
            count,
            if (count == 1) "" else "s",
            ui.inspector.formatBytes(total_size, &size_buf),
        }) catch "Selection";
        self.summary.setText(summary);
        if (count != 1) {
            self.details.setText("Multiple selection");
            self.mode_entry.as(gtk.Editable).setText("");
            self.apply_button.as(gtk.Widget).setSensitive(0);
            return;
        }
        const entry = first.?;
        var mtime_buf: [32]u8 = undefined;
        const modified = ui.format.mtimeIso(&mtime_buf, entry.mtime);
        var detail_buf: [768]u8 = undefined;
        const detail = std.fmt.bufPrintZ(&detail_buf, "Name: {s}\nType: {s}\nSize: {s}\nModified: {s}\nPermissions: {s}", .{
            entry.name,
            @tagName(entry.kind),
            ui.inspector.formatBytes(entry.size orelse 0, &size_buf),
            if (modified.len > 0) modified else "Unknown",
            if (entry.mode != null) "available" else "Unknown",
        }) catch "Selection details";
        self.details.setText(detail);
        if (entry.mode) |mode| {
            var mode_buf: [3]u8 = undefined;
            setEditableText(self.owner.gpa, self.mode_entry.as(gtk.Editable), ui.inspector.octalTextFromMode(mode, &mode_buf));
        } else {
            self.mode_entry.as(gtk.Editable).setText("");
        }
        self.updateApplyState();
    }

    fn updateApplyState(self: *InspectorPanel) void {
        const pane = self.pane orelse {
            self.apply_button.as(gtk.Widget).setSensitive(0);
            return;
        };
        const text = std.mem.span(self.mode_entry.as(gtk.Editable).getText());
        const valid = ui.inspector.modeFromOctalText(text) != null;
        const one = pane.selectionCount() == 1;
        self.apply_button.as(gtk.Widget).setSensitive(@intFromBool(valid and one and pane.site_id != local_site_id and self.pending_path == null));
    }

    fn onModeChanged(_: *gtk.Editable, self: *InspectorPanel) callconv(.c) void {
        self.stage.setText("Staged");
        self.updateApplyState();
    }

    fn onApply(_: *gtk.Button, self: *InspectorPanel) callconv(.c) void {
        const pane = self.pane orelse return;
        const snapshot = pane.snapshot orelse return;
        const selection = pane.selectionInfo();
        if (selection.count != 1) return;
        const entry_index = pane.entryIndexAt(selection.first.?) orelse return;
        if (entry_index >= snapshot.entries.len) return;
        const entry = snapshot.entries[entry_index];
        const mode = ui.inspector.modeFromOctalText(std.mem.span(self.mode_entry.as(gtk.Editable).getText())) orelse return;
        const path = relay.vfs.path.join(self.owner.gpa, snapshot.path, entry.name) catch return;
        self.owner.core.chmodPath(pane.token, pane.site_id, path, mode) catch |err| {
            self.owner.gpa.free(path);
            const message = allocPrintZ(self.owner.gpa, "Could not apply: {s}", .{@errorName(err)}) catch return;
            defer self.owner.gpa.free(message);
            self.stage.setText(message);
            return;
        };
        if (self.pending_path) |old| self.owner.gpa.free(old);
        self.pending_path = path;
        self.pending_site = pane.site_id;
        self.stage.setText("Applying…");
        self.updateApplyState();
    }

    fn handleOpDone(self: *InspectorPanel, event: ui.bridge.OpDone) void {
        if (event.op != .chmod) return;
        const pending = self.pending_path orelse return;
        if (event.site_id != self.pending_site or !std.mem.eql(u8, pending, event.path)) return;
        self.owner.gpa.free(pending);
        self.pending_path = null;
        if (event.success) {
            self.stage.setText("Permissions applied");
        } else {
            const message = if (event.failure) |failure| failure.message else "Unknown error";
            const text = allocPrintZ(self.owner.gpa, "Apply failed: {s}", .{message}) catch return;
            defer self.owner.gpa.free(text);
            self.stage.setText(text);
        }
        self.updateApplyState();
    }
};

const Pane = struct {
    const Column = enum { name, size, modified, permissions };
    const ColumnBinding = struct {
        pane: *Pane,
        column: Column,
    };

    owner: *Window,
    token: ui.bridge.PaneToken,
    root: *gtk.Box,
    path_entry: *gtk.Entry,
    filter_entry: *gtk.SearchEntry,
    hidden_toggle: *gtk.CheckButton,
    density: *gtk.DropDown,
    monospace: *gtk.CheckButton,
    list: *gtk.ColumnView,
    model: *gtk.StringList,
    filter: *gtk.CustomFilter,
    filter_model: *gtk.FilterListModel,
    sort_model: *gtk.SortListModel,
    selection: *gtk.MultiSelection,
    column_bindings: [4]ColumnBinding = undefined,
    spinner: *gtk.Spinner,
    status: *gtk.Label,
    site_label: *gtk.Label,
    rename_button: *gtk.Button,
    delete_button: *gtk.Button,
    context_menu: *gtk.Popover,
    context_rename: *gtk.Button,
    context_copy: *gtk.Button,
    context_delete: *gtk.Button,
    site_id: u64 = local_site_id,
    pending_request: ?ui.bridge.RequestId = null,
    snapshot: ?*DirSnapshot = null,
    navigation: std.ArrayList([]u8) = .empty,
    navigation_index: usize = 0,
    navigating_history: bool = false,
    last_latency_ms: u64 = 0,
    pending_ops: usize = 0,
    name_dialog: ?*NameDialog = null,
    delete_dialog: ?*DeleteDialog = null,
    vim_keymap: ui.vim.Keymap = .{},

    fn init(self: *Pane, owner: *Window, token: ui.bridge.PaneToken) void {
        const root = gtk.Box.new(.vertical, 0);
        root.as(gtk.Widget).setHexpand(1);
        root.as(gtk.Widget).setVexpand(1);

        const toolbar = gtk.Box.new(.horizontal, 6);
        const toolbar_widget = toolbar.as(gtk.Widget);
        toolbar_widget.setMarginTop(8);
        toolbar_widget.setMarginBottom(8);
        toolbar_widget.setMarginStart(8);
        toolbar_widget.setMarginEnd(8);
        const back = gtk.Button.newFromIconName("go-previous-symbolic");
        back.as(gtk.Widget).setTooltipText("Back (Ctrl+[)");
        relay_gtk_accessible_label(back.as(gtk.Widget), "Back");
        const forward = gtk.Button.newFromIconName("go-next-symbolic");
        forward.as(gtk.Widget).setTooltipText("Forward (Ctrl+])");
        relay_gtk_accessible_label(forward.as(gtk.Widget), "Forward");
        const up = gtk.Button.newFromIconName("go-up-symbolic");
        up.as(gtk.Widget).setTooltipText("Enclosing folder");
        relay_gtk_accessible_label(up.as(gtk.Widget), "Enclosing folder");
        const refresh = gtk.Button.newFromIconName("view-refresh-symbolic");
        refresh.as(gtk.Widget).setTooltipText("Refresh");
        relay_gtk_accessible_label(refresh.as(gtk.Widget), "Refresh");
        const site_label = gtk.Label.new("Local");
        site_label.as(gtk.Widget).addCssClass("heading");
        const path_entry = gtk.Entry.new();
        path_entry.setPlaceholderText("Absolute path");
        path_entry.as(gtk.Widget).setHexpand(1);
        const new_folder = gtk.Button.newFromIconName("folder-new-symbolic");
        new_folder.as(gtk.Widget).setTooltipText("New Folder (Ctrl+Shift+N)");
        relay_gtk_accessible_label(new_folder.as(gtk.Widget), "New folder");
        const rename = gtk.Button.newFromIconName("document-edit-symbolic");
        rename.as(gtk.Widget).setTooltipText("Rename (F2)");
        relay_gtk_accessible_label(rename.as(gtk.Widget), "Rename selected item");
        rename.as(gtk.Widget).setSensitive(0);
        const delete = gtk.Button.newFromIconName("user-trash-symbolic");
        delete.as(gtk.Widget).setTooltipText("Delete");
        relay_gtk_accessible_label(delete.as(gtk.Widget), "Delete selected items");
        delete.as(gtk.Widget).setSensitive(0);
        const copy = gtk.Button.newWithLabel(if (token == 1) "Copy →" else "← Copy");
        copy.as(gtk.Widget).setTooltipText("Copy selected items to the other pane");
        const spinner = gtk.Spinner.new();
        spinner.as(gtk.Widget).setVisible(0);
        const filter_entry = gtk.SearchEntry.new();
        filter_entry.setPlaceholderText("Filter");
        filter_entry.as(gtk.Widget).setSizeRequest(130, -1);
        const hidden_toggle = gtk.CheckButton.newWithLabel("Hidden");
        hidden_toggle.setActive(@intFromBool(owner.core.settings.show_hidden_files));
        const density = dropdown(&.{ "Comfortable", "Compact", "Dense" }, 1);
        density.as(gtk.Widget).setTooltipText("Row density");
        const monospace = gtk.CheckButton.newWithLabel("Mono");
        monospace.as(gtk.Widget).setTooltipText("Monospace file names");
        toolbar.append(back.as(gtk.Widget));
        toolbar.append(forward.as(gtk.Widget));
        toolbar.append(up.as(gtk.Widget));
        toolbar.append(refresh.as(gtk.Widget));
        toolbar.append(site_label.as(gtk.Widget));
        toolbar.append(path_entry.as(gtk.Widget));
        toolbar.append(new_folder.as(gtk.Widget));
        toolbar.append(rename.as(gtk.Widget));
        toolbar.append(delete.as(gtk.Widget));
        toolbar.append(copy.as(gtk.Widget));
        toolbar.append(spinner.as(gtk.Widget));

        const model = gtk.StringList.new(null);
        const filter = gtk.CustomFilter.new(filterEntry, self, null);
        const filter_model = gtk.FilterListModel.new(model.as(gio.ListModel), filter.as(gtk.Filter));
        const sort_model = gtk.SortListModel.new(filter_model.as(gio.ListModel), null);
        sort_model.setIncremental(1);
        const selection = gtk.MultiSelection.new(sort_model.as(gio.ListModel));
        const list = gtk.ColumnView.new(selection.as(gtk.SelectionModel));
        list.setEnableRubberband(1);
        list.setShowColumnSeparators(1);
        list.setShowRowSeparators(1);
        list.setReorderable(1);

        const context_menu = gtk.Popover.new();
        context_menu.setAutohide(1);
        context_menu.setHasArrow(1);
        const context_box = gtk.Box.new(.vertical, 2);
        const context_new = gtk.Button.newWithLabel("New Folder");
        const context_rename = gtk.Button.newWithLabel("Rename");
        const context_copy = gtk.Button.newWithLabel("Copy to Other Pane");
        const context_delete = gtk.Button.newWithLabel("Delete");
        context_rename.as(gtk.Widget).setSensitive(0);
        context_copy.as(gtk.Widget).setSensitive(0);
        context_delete.as(gtk.Widget).setSensitive(0);
        context_box.append(context_new.as(gtk.Widget));
        context_box.append(context_rename.as(gtk.Widget));
        context_box.append(context_copy.as(gtk.Widget));
        context_box.append(context_delete.as(gtk.Widget));
        context_menu.setChild(context_box.as(gtk.Widget));
        // GtkListBox.removeAll assumes every direct child is a row, so the
        // popover belongs to the pane container rather than the list itself.
        context_menu.as(gtk.Widget).setParent(root.as(gtk.Widget));

        const right_click = gtk.GestureClick.new();
        right_click.as(gtk.GestureSingle).setButton(3);
        list.as(gtk.Widget).addController(right_click.as(gtk.EventController));
        const keys = gtk.EventControllerKey.new();
        list.as(gtk.Widget).addController(keys.as(gtk.EventController));
        const focus = gtk.EventControllerFocus.new();
        list.as(gtk.Widget).addController(focus.as(gtk.EventController));
        const drag_source = gtk.DragSource.new();
        drag_source.setActions(gdk.DragAction.flags_copy);
        list.as(gtk.Widget).addController(drag_source.as(gtk.EventController));
        const string_type = gobject.typeFromName("gchararray");
        const drop_target = gtk.DropTarget.new(string_type, gdk.DragAction.flags_copy);
        list.as(gtk.Widget).addController(drop_target.as(gtk.EventController));
        const file_drop_target = gtk.DropTarget.new(gdk.FileList.getGObjectType(), gdk.DragAction.flags_copy);
        list.as(gtk.Widget).addController(file_drop_target.as(gtk.EventController));
        const scroller = gtk.ScrolledWindow.new();
        scroller.as(gtk.Widget).setHexpand(1);
        scroller.as(gtk.Widget).setVexpand(1);
        scroller.setPolicy(.automatic, .automatic);
        scroller.setChild(list.as(gtk.Widget));

        const status = gtk.Label.new("Ready");
        status.setXalign(0);
        status.as(gtk.Widget).addCssClass("dim-label");
        status.as(gtk.Widget).setMarginTop(6);
        status.as(gtk.Widget).setMarginBottom(6);
        status.as(gtk.Widget).setMarginStart(10);
        status.as(gtk.Widget).setMarginEnd(10);

        root.append(toolbar.as(gtk.Widget));
        root.append(scroller.as(gtk.Widget));
        root.append(status.as(gtk.Widget));
        self.* = .{
            .owner = owner,
            .token = token,
            .root = root,
            .path_entry = path_entry,
            .filter_entry = filter_entry,
            .hidden_toggle = hidden_toggle,
            .density = density,
            .monospace = monospace,
            .list = list,
            .model = model,
            .filter = filter,
            .filter_model = filter_model,
            .sort_model = sort_model,
            .selection = selection,
            .spinner = spinner,
            .status = status,
            .site_label = site_label,
            .rename_button = rename,
            .delete_button = delete,
            .context_menu = context_menu,
            .context_rename = context_rename,
            .context_copy = context_copy,
            .context_delete = context_delete,
        };
        self.column_bindings = .{
            .{ .pane = self, .column = .name },
            .{ .pane = self, .column = .size },
            .{ .pane = self, .column = .modified },
            .{ .pane = self, .column = .permissions },
        };
        self.addColumn("Name", .name, true);
        self.addColumn("Size", .size, false);
        self.addColumn("Modified", .modified, false);
        self.addColumn("Permissions", .permissions, false);
        sort_model.setSorter(list.getSorter());

        _ = gtk.Button.signals.clicked.connect(back, *Pane, onBack, self, .{});
        _ = gtk.Button.signals.clicked.connect(forward, *Pane, onForward, self, .{});
        _ = gtk.Button.signals.clicked.connect(up, *Pane, onUp, self, .{});
        _ = gtk.Button.signals.clicked.connect(refresh, *Pane, onRefresh, self, .{});
        _ = gtk.Button.signals.clicked.connect(new_folder, *Pane, onNewFolder, self, .{});
        _ = gtk.Button.signals.clicked.connect(rename, *Pane, onRename, self, .{});
        _ = gtk.Button.signals.clicked.connect(delete, *Pane, onDelete, self, .{});
        _ = gtk.Button.signals.clicked.connect(context_new, *Pane, onContextNewFolder, self, .{});
        _ = gtk.Button.signals.clicked.connect(context_rename, *Pane, onContextRename, self, .{});
        _ = gtk.Button.signals.clicked.connect(context_copy, *Pane, onContextCopy, self, .{});
        _ = gtk.Button.signals.clicked.connect(context_delete, *Pane, onContextDelete, self, .{});
        _ = gtk.Button.signals.clicked.connect(copy, *Pane, onCopy, self, .{});
        _ = gtk.Entry.signals.activate.connect(path_entry, *Pane, onPathActivated, self, .{});
        _ = gtk.ColumnView.signals.activate.connect(list, *Pane, onRowActivated, self, .{});
        _ = gtk.SelectionModel.signals.selection_changed.connect(selection.as(gtk.SelectionModel), *Pane, onSelectionChanged, self, .{});
        _ = gtk.GestureClick.signals.pressed.connect(right_click, *Pane, onRightClick, self, .{});
        _ = gtk.EventControllerKey.signals.key_pressed.connect(keys, *Pane, onKeyPressed, self, .{});
        _ = gtk.EventControllerFocus.signals.enter.connect(focus, *Pane, onFocus, self, .{});
        _ = gtk.SearchEntry.signals.search_changed.connect(filter_entry, *Pane, onFilterChanged, self, .{});
        _ = gtk.CheckButton.signals.toggled.connect(hidden_toggle, *Pane, onFilterToggled, self, .{});
        _ = gtk.CheckButton.signals.toggled.connect(monospace, *Pane, onAppearanceChanged, self, .{});
        _ = gobject.Object.signals.notify.connect(density.as(gobject.Object), *Pane, onDensityNotify, self, .{ .detail = "selected" });
        _ = gtk.DragSource.signals.prepare.connect(drag_source, *Pane, onDragPrepare, self, .{});
        _ = gtk.DropTarget.signals.drop.connect(drop_target, *Pane, onDrop, self, .{});
        _ = gtk.DropTarget.signals.drop.connect(file_drop_target, *Pane, onFileDrop, self, .{});

        toolbar.append(filter_entry.as(gtk.Widget));
        toolbar.append(hidden_toggle.as(gtk.Widget));
        toolbar.append(density.as(gtk.Widget));
        toolbar.append(monospace.as(gtk.Widget));
    }

    fn addColumn(self: *Pane, title: [*:0]const u8, column: Column, expand: bool) void {
        const binding = &self.column_bindings[@intFromEnum(column)];
        const factory = gtk.SignalListItemFactory.new();
        _ = gtk.SignalListItemFactory.signals.setup.connect(factory, *ColumnBinding, setupCell, binding, .{});
        _ = gtk.SignalListItemFactory.signals.bind.connect(factory, *ColumnBinding, bindCell, binding, .{});
        const view_column = gtk.ColumnViewColumn.new(title, factory.as(gtk.ListItemFactory));
        defer view_column.unref();
        view_column.setExpand(@intFromBool(expand));
        view_column.setResizable(1);
        const sorter = gtk.CustomSorter.new(compareRows, binding, null);
        defer sorter.unref();
        view_column.setSorter(sorter.as(gtk.Sorter));
        self.list.appendColumn(view_column);
    }

    fn setupCell(_: *gtk.SignalListItemFactory, object: *gobject.Object, binding: *ColumnBinding) callconv(.c) void {
        const item: *gtk.ColumnViewCell = @ptrCast(@alignCast(object));
        const label = gtk.Label.new("");
        label.setXalign(if (binding.column == .size) 1 else 0);
        label.setEllipsize(.end);
        label.as(gtk.Widget).setHexpand(1);
        item.setChild(label.as(gtk.Widget));
    }

    fn bindCell(_: *gtk.SignalListItemFactory, object: *gobject.Object, binding: *ColumnBinding) callconv(.c) void {
        const item: *gtk.ColumnViewCell = @ptrCast(@alignCast(object));
        const child = item.getChild() orelse return;
        const label: *gtk.Label = @ptrCast(@alignCast(child));
        const entry_index = entryIndexFromObject(item.getItem() orelse return) orelse return;
        const snapshot = binding.pane.snapshot orelse return;
        if (entry_index >= snapshot.entries.len) return;
        const entry = snapshot.entries[entry_index];
        var buf: [1024]u8 = undefined;
        const text: [:0]const u8 = switch (binding.column) {
            .name => std.fmt.bufPrintZ(&buf, "{s} {s}", .{
                if (entry.kind == .dir) "📁" else if (entry.kind == .symlink) "↗" else "📄",
                entry.name,
            }) catch "",
            .size => if (entry.kind == .dir)
                "—"
            else if (entry.size) |bytes|
                std.fmt.bufPrintZ(&buf, "{d}", .{bytes}) catch ""
            else
                "—",
            .modified => blk: {
                const rendered = if (binding.pane.owner.prefs.date_format == .relative)
                    ui.format.mtimeRelative(
                        buf[0 .. buf.len - 1],
                        entry.mtime,
                        @intCast(@divFloor(
                            std.Io.Clock.real.now(binding.pane.owner.core.io).nanoseconds,
                            std.time.ns_per_s,
                        )),
                    )
                else
                    ui.format.mtimeIso(buf[0 .. buf.len - 1], entry.mtime);
                if (rendered.len == 0) break :blk "—";
                buf[rendered.len] = 0;
                break :blk buf[0..rendered.len :0];
            },
            .permissions => if (entry.mode) |mode|
                std.fmt.bufPrintZ(&buf, "{o:0>3}", .{mode & 0o777}) catch ""
            else
                "—",
        };
        label.setText(text);
        const margin: c_int = switch (binding.pane.density.getSelected()) {
            0 => 7,
            2 => 1,
            else => 4,
        };
        label.as(gtk.Widget).setMarginTop(margin);
        label.as(gtk.Widget).setMarginBottom(margin);
        label.as(gtk.Widget).setMarginStart(8);
        label.as(gtk.Widget).setMarginEnd(8);
        if (binding.pane.monospace.getActive() != 0) {
            label.as(gtk.Widget).addCssClass("monospace");
        } else {
            label.as(gtk.Widget).removeCssClass("monospace");
        }
        if (binding.pane.owner.entryDiffers(binding.pane, entry)) {
            label.as(gtk.Widget).addCssClass("warning");
        } else {
            label.as(gtk.Widget).removeCssClass("warning");
        }
    }

    fn entryIndexFromObject(object: *gobject.Object) ?usize {
        const string_object: *gtk.StringObject = @ptrCast(@alignCast(object));
        return std.fmt.parseInt(usize, std.mem.span(string_object.getString()), 10) catch null;
    }

    fn compareRows(a_raw: ?*const anyopaque, b_raw: ?*const anyopaque, data: ?*anyopaque) callconv(.c) c_int {
        const binding: *ColumnBinding = @ptrCast(@alignCast(data.?));
        const snapshot = binding.pane.snapshot orelse return 0;
        const a_object: *gobject.Object = @ptrCast(@alignCast(@constCast(a_raw.?)));
        const b_object: *gobject.Object = @ptrCast(@alignCast(@constCast(b_raw.?)));
        const a_index = entryIndexFromObject(a_object) orelse return 0;
        const b_index = entryIndexFromObject(b_object) orelse return 0;
        if (a_index >= snapshot.entries.len or b_index >= snapshot.entries.len) return 0;
        const a = snapshot.entries[a_index];
        const b = snapshot.entries[b_index];
        if ((a.kind == .dir) != (b.kind == .dir)) return if (a.kind == .dir) -1 else 1;
        return switch (binding.column) {
            .name => orderToInt(std.ascii.orderIgnoreCase(a.name, b.name)),
            .size => compareOptional(a.size, b.size),
            .modified => compareOptional(a.mtime, b.mtime),
            .permissions => compareOptional(a.mode, b.mode),
        };
    }

    fn orderToInt(order: std.math.Order) c_int {
        return switch (order) {
            .lt => -1,
            .eq => 0,
            .gt => 1,
        };
    }

    fn compareOptional(a: anytype, b: @TypeOf(a)) c_int {
        if (a == null and b == null) return 0;
        if (a == null) return -1;
        if (b == null) return 1;
        return if (a.? < b.?) -1 else if (a.? > b.?) 1 else 0;
    }

    fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
        if (needle.len == 0) return true;
        if (needle.len > haystack.len) return false;
        var i: usize = 0;
        while (i + needle.len <= haystack.len) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
        }
        return false;
    }

    fn filterEntry(object: *gobject.Object, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Pane = @ptrCast(@alignCast(raw.?));
        const entry_index = entryIndexFromObject(object) orelse return 0;
        const snapshot = self.snapshot orelse return 0;
        if (entry_index >= snapshot.entries.len) return 0;
        const entry = snapshot.entries[entry_index];
        if (self.hidden_toggle.getActive() == 0 and entry.name.len > 0 and entry.name[0] == '.') return 0;
        const query = std.mem.trim(u8, std.mem.span(self.filter_entry.as(gtk.Editable).getText()), " \t\r\n");
        return @intFromBool(containsAsciiIgnoreCase(entry.name, query));
    }

    fn deinit(self: *Pane) void {
        if (self.name_dialog) |dialog| dialog.destroy();
        if (self.delete_dialog) |dialog| dialog.destroy();
        self.context_menu.popdown();
        self.context_menu.as(gtk.Widget).unparent();
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        for (self.navigation.items) |path| self.owner.gpa.free(path);
        self.navigation.deinit(self.owner.gpa);
        self.releaseSnapshot();
    }

    fn currentPath(self: *const Pane) []const u8 {
        if (self.snapshot) |snapshot| return snapshot.path;
        return std.mem.span(self.path_entry.as(gtk.Editable).getText());
    }

    fn releaseSnapshot(self: *Pane) void {
        if (self.snapshot) |snapshot| snapshot.unref();
        self.snapshot = null;
        const count = self.model.as(gio.ListModel).getNItems();
        if (count > 0) self.model.splice(0, count, null);
    }

    fn navigate(self: *Pane, path: []const u8) !void {
        const old_path = try self.owner.gpa.dupe(u8, self.currentPath());
        defer self.owner.gpa.free(old_path);
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        self.pending_request = try self.owner.core.listPath(self.token, self.site_id, path);
        self.setPath(path);
        self.spinner.as(gtk.Widget).setVisible(1);
        self.spinner.start();
        self.setStatus("Loading…", .{});
        if (!self.navigating_history) {
            while (self.navigation.items.len > self.navigation_index + @intFromBool(self.navigation.items.len > 0)) {
                self.owner.gpa.free(self.navigation.pop().?);
            }
            if (self.navigation.items.len == 0 or !std.mem.eql(u8, self.navigation.items[self.navigation.items.len - 1], path)) {
                try self.navigation.append(self.owner.gpa, try self.owner.gpa.dupe(u8, path));
                self.navigation_index = self.navigation.items.len - 1;
            }
        }
        self.owner.mirrorNavigation(self, old_path, path);
    }

    fn bindSite(self: *Pane, site_id: u64, label: []const u8, path: []const u8) !void {
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        self.pending_request = null;
        self.releaseSnapshot();
        self.site_id = site_id;
        const site = self.owner.site_store.get(site_id);
        const label_z = if (site) |value|
            allocPrintZ(self.owner.gpa, "{s}{s}{s}{s}", .{
                switch (value.environment) {
                    .none => "",
                    .dev => "DEV · ",
                    .staging => "STAGING · ",
                    .prod => "PRODUCTION · ",
                },
                label,
                if (value.insecure_skip_verify) " · " else "",
                if (value.insecure_skip_verify) "INSECURE TLS" else "",
            }) catch null
        else
            allocPrintZ(self.owner.gpa, "{s}", .{label}) catch null;
        if (label_z) |text| {
            defer self.owner.gpa.free(text);
            self.site_label.setText(text);
        }
        if (site) |value| {
            if (value.environment == .prod) {
                self.root.as(gtk.Widget).addCssClass("relay-production");
            } else {
                self.root.as(gtk.Widget).removeCssClass("relay-production");
            }
            if (value.insecure_skip_verify) {
                self.site_label.as(gtk.Widget).addCssClass("relay-insecure");
            } else {
                self.site_label.as(gtk.Widget).removeCssClass("relay-insecure");
            }
        } else {
            self.root.as(gtk.Widget).removeCssClass("relay-production");
            self.site_label.as(gtk.Widget).removeCssClass("relay-insecure");
        }
        self.pending_request = if (site_id != local_site_id and path.len == 0)
            try self.owner.core.listDefaultPath(self.token, site_id)
        else
            try self.owner.core.listPath(self.token, site_id, path);
        self.setPath(if (path.len == 0) "…" else path);
        self.spinner.as(gtk.Widget).setVisible(1);
        self.spinner.start();
        self.setStatus("Connecting…", .{});
        for (self.navigation.items) |old_path| self.owner.gpa.free(old_path);
        self.navigation.clearRetainingCapacity();
        if (path.len > 0) {
            try self.navigation.append(self.owner.gpa, try self.owner.gpa.dupe(u8, path));
            self.navigation_index = 0;
        }
    }

    fn setPath(self: *Pane, path: []const u8) void {
        const path_z = allocPrintZ(self.owner.gpa, "{s}", .{path}) catch return;
        defer self.owner.gpa.free(path_z);
        self.path_entry.as(gtk.Editable).setText(path_z);
    }

    fn replaceSnapshot(self: *Pane, incoming: *DirSnapshot, incoming_sort: []const u32) !void {
        const retained = incoming.ref();
        errdefer retained.unref();

        self.releaseSnapshot();
        self.snapshot = retained;
        self.setPath(incoming.path);
        for (incoming_sort) |entry_index| {
            var index_buf: [32]u8 = undefined;
            const text = std.fmt.bufPrintZ(&index_buf, "{d}", .{entry_index}) catch continue;
            self.model.append(text);
        }
        self.filter.as(gtk.Filter).changed(.different);
        self.setStatus("{d} item{s}{s}{d}{s}", .{
            incoming.entries.len,
            if (incoming.entries.len == 1) "" else "s",
            if (self.last_latency_ms > 0 and self.site_id != local_site_id) " · " else "",
            if (self.last_latency_ms > 0 and self.site_id != local_site_id) self.last_latency_ms else 0,
            if (self.last_latency_ms > 0 and self.site_id != local_site_id) " ms" else "",
        });
    }

    fn setStatus(self: *Pane, comptime format: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const text = std.fmt.bufPrintZ(&buf, format, args) catch return;
        self.status.setText(text);
    }

    fn onBack(_: *gtk.Button, self: *Pane) callconv(.c) void {
        if (self.navigation.items.len == 0 or self.navigation_index == 0) return;
        self.navigation_index -= 1;
        self.navigating_history = true;
        defer self.navigating_history = false;
        self.navigate(self.navigation.items[self.navigation_index]) catch |err| {
            self.setStatus("Back failed: {s}", .{@errorName(err)});
        };
    }

    fn onForward(_: *gtk.Button, self: *Pane) callconv(.c) void {
        if (self.navigation_index + 1 >= self.navigation.items.len) return;
        self.navigation_index += 1;
        self.navigating_history = true;
        defer self.navigating_history = false;
        self.navigate(self.navigation.items[self.navigation_index]) catch |err| {
            self.setStatus("Forward failed: {s}", .{@errorName(err)});
        };
    }

    fn onUp(_: *gtk.Button, self: *Pane) callconv(.c) void {
        const path = self.currentPath();
        const parent = relay.vfs.path.parent(path) orelse return;
        self.navigate(parent) catch |err| self.setStatus("Cannot open parent: {s}", .{@errorName(err)});
    }

    fn onRefresh(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.navigate(self.currentPath()) catch |err| self.setStatus("Refresh failed: {s}", .{@errorName(err)});
    }

    fn onFilterChanged(_: *gtk.SearchEntry, self: *Pane) callconv(.c) void {
        self.filter.as(gtk.Filter).changed(.different);
        self.updateSelectionStatus();
    }

    fn onFilterToggled(_: *gtk.CheckButton, self: *Pane) callconv(.c) void {
        self.filter.as(gtk.Filter).changed(.different);
        self.updateSelectionStatus();
    }

    fn onAppearanceChanged(_: *gtk.CheckButton, self: *Pane) callconv(.c) void {
        self.rebuildModel();
    }

    fn onDensityNotify(_: *gobject.Object, _: *gobject.ParamSpec, self: *Pane) callconv(.c) void {
        self.rebuildModel();
    }

    fn rebuildModel(self: *Pane) void {
        const snapshot = self.snapshot orelse return;
        const count = self.model.as(gio.ListModel).getNItems();
        if (count > 0) self.model.splice(0, count, null);
        for (snapshot.entries, 0..) |_, entry_index| {
            var index_buf: [32]u8 = undefined;
            const text = std.fmt.bufPrintZ(&index_buf, "{d}", .{entry_index}) catch continue;
            self.model.append(text);
        }
        self.filter.as(gtk.Filter).changed(.different);
    }

    fn updateSelectionStatus(self: *Pane) void {
        const visible = self.sort_model.as(gio.ListModel).getNItems();
        const selected = self.selectionCount();
        if (selected > 0) {
            self.setStatus("{d} visible · {d} selected", .{ visible, selected });
        } else {
            self.setStatus("{d} visible", .{visible});
        }
    }

    fn selectionCount(self: *Pane) usize {
        return self.selectionInfo().count;
    }

    const SelectionInfo = struct {
        count: usize = 0,
        first: ?usize = null,
    };

    fn selectionInfo(self: *Pane) SelectionInfo {
        var info: SelectionInfo = .{};
        const model = self.selection.as(gtk.SelectionModel);
        const count = self.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < count) : (position += 1) {
            if (model.isSelected(position) == 0) continue;
            info.count += 1;
            if (info.first == null) info.first = position;
        }

        return info;
    }

    const SelectedPath = struct { path: []u8, is_dir: bool };

    fn selectedPath(self: *Pane) error{ NoSelection, InvalidPath, OutOfMemory }!SelectedPath {
        const snapshot = self.snapshot orelse return error.NoSelection;
        const selection = self.selectionInfo();
        if (selection.count != 1) return error.NoSelection;
        const entry_index = self.entryIndexAt(selection.first.?) orelse return error.NoSelection;
        if (entry_index >= snapshot.entries.len) return error.NoSelection;
        const entry = snapshot.entries[entry_index];
        return .{
            .path = try relay.vfs.path.join(self.owner.gpa, snapshot.path, entry.name),
            .is_dir = entry.kind == .dir,
        };
    }

    fn entryIndexAt(self: *Pane, position: usize) ?usize {
        const object_raw = self.sort_model.as(gio.ListModel).getItem(@intCast(position)) orelse return null;
        const object: *gobject.Object = @ptrCast(@alignCast(object_raw));
        defer object.unref();
        return entryIndexFromObject(object);
    }

    fn onSelectionChanged(_: *gtk.SelectionModel, _: c_uint, _: c_uint, self: *Pane) callconv(.c) void {
        const count = self.selectionCount();
        const can_rename = count == 1;
        const can_delete = count > 0;
        self.rename_button.as(gtk.Widget).setSensitive(@intFromBool(can_rename));
        self.delete_button.as(gtk.Widget).setSensitive(@intFromBool(can_delete));
        self.context_rename.as(gtk.Widget).setSensitive(@intFromBool(can_rename));
        self.context_copy.as(gtk.Widget).setSensitive(@intFromBool(can_delete));
        self.context_delete.as(gtk.Widget).setSensitive(@intFromBool(can_delete));
        self.updateSelectionStatus();
        if (self.owner.inspector_initialized) self.owner.inspector.update(self);
    }

    fn onNewFolder(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.beginNewFolder();
    }

    fn onRename(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.beginRename();
    }

    fn onDelete(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.beginDelete();
    }

    fn onContextNewFolder(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.context_menu.popdown();
        self.beginNewFolder();
    }

    fn onContextRename(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.context_menu.popdown();
        self.beginRename();
    }

    fn onContextDelete(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.context_menu.popdown();
        self.beginDelete();
    }

    fn onContextCopy(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.context_menu.popdown();
        self.copySelection();
    }

    fn onRightClick(_: *gtk.GestureClick, _: c_int, x: f64, y: f64, self: *Pane) callconv(.c) void {
        const point: gdk.Rectangle = .{
            .f_x = @intFromFloat(x),
            .f_y = @as(c_int, @intFromFloat(y)) + 52,
            .f_width = 1,
            .f_height = 1,
        };
        self.context_menu.setPointingTo(&point);
        self.context_menu.popup();
    }

    fn onKeyPressed(
        _: *gtk.EventControllerKey,
        keyval: c_uint,
        _: c_uint,
        state: gdk.ModifierType,
        self: *Pane,
    ) callconv(.c) c_int {
        if (self.owner.prefs.vim_mode and !state.alt_mask) {
            const is_ascii = keyval >= 0x20 and keyval <= 0x7e;
            const character: u8 = if (is_ascii) @intCast(std.ascii.toLower(@as(u8, @intCast(keyval)))) else 0;
            const action = self.vim_keymap.feed(.{
                .char = character,
                .shift = state.shift_mask,
                .control = state.control_mask,
                .enter = keyval == gdk.KEY_Return or keyval == gdk.KEY_KP_Enter,
                .escape = keyval == gdk.KEY_Escape,
            });
            if (action != .none) {
                self.handleVimAction(action);
                return 1;
            }
            if (is_ascii) return 1;
        }
        if (keyval == gdk.KEY_F2) {
            self.beginRename();
            return 1;
        }
        if (keyval == gdk.KEY_Delete) {
            self.beginDelete();
            return 1;
        }
        if (state.control_mask and state.shift_mask and (keyval == gdk.KEY_n or keyval == gdk.KEY_N)) {
            self.beginNewFolder();
            return 1;
        }
        if (state.control_mask and keyval == gdk.KEY_bracketleft) {
            onBack(undefined, self);
            return 1;
        }
        if (state.control_mask and keyval == gdk.KEY_bracketright) {
            onForward(undefined, self);
            return 1;
        }
        if (!state.control_mask and !state.alt_mask and keyval >= 0x20 and keyval <= 0x7e) {
            const needle: u8 = @intCast(keyval);
            const count = self.sort_model.as(gio.ListModel).getNItems();
            var position: c_uint = 0;
            while (position < count) : (position += 1) {
                const entry_index = self.entryIndexAt(position) orelse continue;
                const snapshot = self.snapshot orelse break;
                if (entry_index >= snapshot.entries.len or snapshot.entries[entry_index].name.len == 0) continue;
                if (std.ascii.toLower(snapshot.entries[entry_index].name[0]) != std.ascii.toLower(needle)) continue;
                _ = self.selection.as(gtk.SelectionModel).selectItem(position, 1);
                self.list.scrollTo(position, null, .{ .focus = true, .select = true }, null);
                return 1;
            }
        }
        return 0;
    }

    fn handleVimAction(self: *Pane, action: ui.vim.Action) void {
        const count = self.sort_model.as(gio.ListModel).getNItems();
        const current = self.firstSelectedPosition() orelse 0;
        switch (action) {
            .none, .consumed => {},
            .move_down, .next_match => self.selectPosition(@min(current + 1, if (count > 0) count - 1 else 0)),
            .move_up, .prev_match => self.selectPosition(if (current > 0) current - 1 else 0),
            .parent => onUp(undefined, self),
            .open => if (count > 0) onRowActivated(self.list, current, self),
            .top => self.selectPosition(0),
            .bottom => if (count > 0) self.selectPosition(count - 1),
            .half_page_down => self.selectPosition(@min(current + 10, if (count > 0) count - 1 else 0)),
            .half_page_up => self.selectPosition(if (current > 10) current - 10 else 0),
            .focus_filter => _ = self.filter_entry.as(gtk.Widget).grabFocus(),
            .toggle_select => {
                const model = self.selection.as(gtk.SelectionModel);
                if (model.isSelected(current) != 0) {
                    _ = model.unselectItem(current);
                } else {
                    _ = model.selectItem(current, 0);
                }
            },
            .range_anchor => {},
            .delete => self.beginDelete(),
            .rename => self.beginRename(),
            .yank => {
                const selected = self.selectedPath() catch return;
                defer self.owner.gpa.free(selected.path);
                self.owner.services.copyText(selected.path);
                self.setStatus("Copied path to the clipboard", .{});
            },
        }
    }

    fn firstSelectedPosition(self: *Pane) ?c_uint {
        const model = self.selection.as(gtk.SelectionModel);
        const count = self.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < count) : (position += 1) {
            if (model.isSelected(position) != 0) return position;
        }
        return null;
    }

    fn selectPosition(self: *Pane, position: c_uint) void {
        if (position >= self.sort_model.as(gio.ListModel).getNItems()) return;
        _ = self.selection.as(gtk.SelectionModel).selectItem(position, 1);
        self.list.scrollTo(position, null, .{ .focus = true, .select = true }, null);
    }

    fn onFocus(_: *gtk.EventControllerFocus, self: *Pane) callconv(.c) void {
        self.owner.setActivePane(self);
    }

    fn onDragPrepare(_: *gtk.DragSource, _: f64, _: f64, self: *Pane) callconv(.c) ?*gdk.ContentProvider {
        if (self.selectionCount() == 0 or self.snapshot == null) return null;
        var payload_buf: [64]u8 = undefined;
        const payload = std.fmt.bufPrintZ(&payload_buf, "relay-pane:{d}", .{self.token}) catch return null;
        var value: gobject.Value = std.mem.zeroes(gobject.Value);
        _ = value.init(gobject.typeFromName("gchararray"));
        defer value.unset();
        value.setString(payload);
        const internal = gdk.ContentProvider.newForValue(&value);
        if (self.site_id != local_site_id) return internal;
        const files = self.selectedLocalFiles() catch return internal;
        defer {
            for (files) |file| file.unref();
            self.owner.gpa.free(files);
        }
        if (files.len == 0) return internal;
        const file_list = gdk.FileList.newFromArray(files.ptr, files.len);
        var file_value: gobject.Value = std.mem.zeroes(gobject.Value);
        _ = file_value.init(gdk.FileList.getGObjectType());
        defer file_value.unset();
        g_value_take_boxed(&file_value, file_list);
        const external = gdk.ContentProvider.newForValue(&file_value);
        var providers = [_]*gdk.ContentProvider{ internal, external };
        const combined = gdk.ContentProvider.newUnion(&providers, providers.len);
        internal.unref();
        external.unref();
        return combined;
    }

    fn selectedLocalFiles(self: *Pane) ![]*gio.File {
        var files: std.ArrayList(*gio.File) = .empty;
        errdefer {
            for (files.items) |file| file.unref();
            files.deinit(self.owner.gpa);
        }
        const snapshot = self.snapshot orelse return files.toOwnedSlice(self.owner.gpa);
        const model = self.selection.as(gtk.SelectionModel);
        const count = self.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < count) : (position += 1) {
            if (model.isSelected(position) == 0) continue;
            const entry_index = self.entryIndexAt(position) orelse continue;
            if (entry_index >= snapshot.entries.len) continue;
            const path = relay.vfs.path.join(self.owner.gpa, snapshot.path, snapshot.entries[entry_index].name) catch continue;
            defer self.owner.gpa.free(path);
            const path_z = try self.owner.gpa.dupeZ(u8, path);
            defer self.owner.gpa.free(path_z);
            try files.append(self.owner.gpa, gio.File.newForPath(path_z));
        }
        return files.toOwnedSlice(self.owner.gpa);
    }

    fn onDrop(_: *gtk.DropTarget, value: *gobject.Value, _: f64, _: f64, self: *Pane) callconv(.c) c_int {
        const payload_z = value.getString() orelse return 0;
        const payload = std.mem.span(payload_z);
        const prefix = "relay-pane:";
        if (!std.mem.startsWith(u8, payload, prefix)) return 0;
        const token = std.fmt.parseInt(ui.bridge.PaneToken, payload[prefix.len..], 10) catch return 0;
        const source = self.owner.paneFor(token) orelse return 0;
        if (source == self) {
            self.setStatus("Cannot drop a selection onto the same pane", .{});
            return 0;
        }
        source.copySelection();
        return 1;
    }

    fn onFileDrop(_: *gtk.DropTarget, value: *gobject.Value, _: f64, _: f64, self: *Pane) callconv(.c) c_int {
        const raw = value.getBoxed() orelse return 0;
        const file_list: *gdk.FileList = @ptrCast(@alignCast(raw));
        const head = file_list.getFiles();
        defer g_slist_free(head);
        var node: ?*glib.SList = head;
        var enqueued: usize = 0;
        while (node) |current| : (node = current.f_next) {
            const file: *gio.File = @ptrCast(@alignCast(current.f_data orelse continue));
            const path_z = file.getPath() orelse continue;
            defer glib.free(path_z);
            const source_path = std.mem.span(path_z);
            if (!std.mem.startsWith(u8, source_path, "/")) continue;
            const normalized_source = relay.vfs.path.normalize(self.owner.gpa, source_path) catch continue;
            defer self.owner.gpa.free(normalized_source);
            const name = relay.vfs.path.basename(normalized_source);
            if (!relay.vfs.path.isSafeChildName(name)) continue;
            const source_type = file.queryFileType(.{ .nofollow_symlinks = true }, null);
            if (source_type == .symbolic_link) continue;
            const is_dir = source_type == .directory;
            const real_source = std.Io.Dir.realPathFileAbsoluteAlloc(
                self.owner.core.io,
                normalized_source,
                self.owner.gpa,
            ) catch continue;
            defer self.owner.gpa.free(real_source);

            const destination = relay.vfs.path.join(self.owner.gpa, self.currentPath(), name) catch continue;
            defer self.owner.gpa.free(destination);
            var canonical_destination: ?[:0]u8 = null;
            defer if (canonical_destination) |path| self.owner.gpa.free(path);
            if (self.site_id == local_site_id) {
                const real_parent = std.Io.Dir.realPathFileAbsoluteAlloc(
                    self.owner.core.io,
                    self.currentPath(),
                    self.owner.gpa,
                ) catch continue;
                defer self.owner.gpa.free(real_parent);
                const lexical_destination = relay.vfs.path.join(self.owner.gpa, real_parent, name) catch continue;
                defer self.owner.gpa.free(lexical_destination);

                const destination_z = self.owner.gpa.dupeZ(u8, destination) catch continue;
                defer self.owner.gpa.free(destination_z);
                const destination_file = gio.File.newForPath(destination_z);
                defer destination_file.unref();
                if (destination_file.queryFileType(.{ .nofollow_symlinks = true }, null) == .symbolic_link) continue;
                canonical_destination = std.Io.Dir.realPathFileAbsoluteAlloc(
                    self.owner.core.io,
                    destination,
                    self.owner.gpa,
                ) catch self.owner.gpa.dupeZ(u8, lexical_destination) catch continue;
                if (std.mem.eql(u8, real_source, canonical_destination.?) or
                    (is_dir and pathContains(real_source, canonical_destination.?))) continue;
            }
            _ = self.owner.core.enqueueTransfer(.{
                .direction = if (self.site_id == local_site_id) .download else .upload,
                .kind = if (is_dir) .folder else .file,
                .src = .{ .site_id = local_site_id, .path = real_source },
                .dst = .{
                    .site_id = self.site_id,
                    .path = if (canonical_destination) |path| path else destination,
                },
                .conflict = .ask,
            }) catch continue;
            enqueued += 1;
        }
        if (enqueued == 0) return 0;
        self.owner.transfers.root.setExpanded(1);
        self.owner.transfers.syncFromEngine();
        self.setStatus("Queued {d} dropped item{s}", .{ enqueued, if (enqueued == 1) "" else "s" });
        return 1;
    }

    fn beginNewFolder(self: *Pane) void {
        if (self.pending_request != null or self.snapshot == null) {
            self.setStatus("Wait for this folder to finish loading", .{});
            return;
        }
        if (self.name_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        NameDialog.create(self, .new_folder, null) catch {
            self.setStatus("Not enough memory to open New Folder", .{});
        };
    }

    fn beginRename(self: *Pane) void {
        if (self.pending_request != null or self.snapshot == null) {
            self.setStatus("Wait for this folder to finish loading", .{});
            return;
        }
        const selection = self.selectionInfo();
        if (selection.count != 1) {
            self.setStatus("Select exactly one item to rename", .{});
            return;
        }
        const snapshot = self.snapshot.?;
        const entry_index = self.entryIndexAt(selection.first orelse return) orelse return;
        if (entry_index >= snapshot.entries.len) return;
        if (self.name_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        NameDialog.create(self, .rename, snapshot.entries[entry_index].name) catch {
            self.setStatus("Not enough memory to open Rename", .{});
        };
    }

    fn beginDelete(self: *Pane) void {
        if (self.pending_request != null or self.snapshot == null) {
            self.setStatus("Wait for this folder to finish loading", .{});
            return;
        }
        if (self.selectionCount() == 0) {
            self.setStatus("Select one or more items to delete", .{});
            return;
        }
        if (self.delete_dialog) |dialog| {
            dialog.native.as(gtk.Window).present();
            return;
        }
        DeleteDialog.create(self) catch {
            self.setStatus("Not enough memory to confirm deletion", .{});
        };
    }

    fn handleOpDone(self: *Pane, event: ui.bridge.OpDone) void {
        if (self.pending_ops > 0) self.pending_ops -= 1;
        self.updatePendingStyle();
        if (!event.success) {
            const failure = if (event.failure) |value| value.message else "Unknown error";
            self.setStatus("{s} failed: {s}", .{ operationLabel(event.op), failure });
            self.presentOperationError(event.op, failure);
            return;
        }
        self.setStatus("{s} completed", .{operationLabel(event.op)});
        const snapshot = self.snapshot orelse return;
        const affected_dir = relay.vfs.path.parent(event.path) orelse "/";
        if (event.site_id != self.site_id or !std.mem.eql(u8, snapshot.path, affected_dir)) return;
        self.navigate(affected_dir) catch |err| {
            self.setStatus("Refresh after {s} failed: {s}", .{ operationLabel(event.op), @errorName(err) });
        };
    }

    fn presentOperationError(self: *Pane, op: ui.bridge.OpKind, detail: []const u8) void {
        const alert = gtk.AlertDialog.new("File operation failed");
        const title_z = allocPrintZ(self.owner.gpa, "{s} failed", .{operationLabel(op)}) catch null;
        if (title_z) |title| {
            defer self.owner.gpa.free(title);
            alert.setMessage(title);
        }

        const detail_z = allocPrintZ(self.owner.gpa, "{s}", .{detail}) catch null;
        if (detail_z) |message| {
            defer self.owner.gpa.free(message);
            alert.setDetail(message);
        }
        alert.show(self.owner.native.as(gtk.Window));
        alert.unref();
    }

    fn updatePendingStyle(self: *Pane) void {
        if (self.pending_ops > 0) {
            self.list.as(gtk.Widget).addCssClass("relay-pending");
        } else {
            self.list.as(gtk.Widget).removeCssClass("relay-pending");
        }
    }

    fn onCopy(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.copySelection();
    }

    fn copySelection(self: *Pane) void {
        const destination = if (self == &self.owner.panes[0])
            &self.owner.panes[1]
        else
            &self.owner.panes[0];
        if (self.pending_request != null or destination.pending_request != null or
            self.snapshot == null or destination.snapshot == null)
        {
            self.setStatus("Both panes must finish loading before copying", .{});
            return;
        }
        if (self.site_id == destination.site_id and
            std.mem.eql(u8, self.snapshot.?.path, destination.snapshot.?.path))
        {
            self.setStatus("Choose a different destination folder", .{});
            return;
        }
        var selection: CopySelection = .{ .source = self, .destination = destination };
        const model = self.selection.as(gtk.SelectionModel);
        const count = self.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < count) : (position += 1) {
            if (model.isSelected(position) == 0) continue;
            self.copySelectedPosition(position, &selection);
        }
        if (selection.selected == 0) {
            self.setStatus("Select one or more items to copy", .{});
            return;
        }
        if (selection.enqueued == 0) {
            self.setStatus("Could not queue selected items", .{});
            return;
        }
        self.setStatus("Queued {d} of {d} selected item{s}", .{
            selection.enqueued,
            selection.selected,
            if (selection.selected == 1) "" else "s",
        });
        self.owner.transfers.root.setExpanded(1);
        self.owner.transfers.syncFromEngine();
    }

    const CopySelection = struct {
        source: *Pane,
        destination: *Pane,
        selected: usize = 0,
        enqueued: usize = 0,
    };

    fn copySelectedPosition(source: *Pane, position: usize, selection: *CopySelection) void {
        selection.selected += 1;
        const source_snapshot = source.snapshot orelse return;
        const destination_snapshot = selection.destination.snapshot orelse return;
        const entry_index = source.entryIndexAt(position) orelse return;
        if (entry_index >= source_snapshot.entries.len) return;
        const entry = &source_snapshot.entries[entry_index];
        if (!relay.vfs.path.isSafeChildName(entry.name)) return;

        const src_path = relay.vfs.path.join(source.owner.gpa, source_snapshot.path, entry.name) catch return;
        defer source.owner.gpa.free(src_path);
        const dst_path = relay.vfs.path.join(source.owner.gpa, destination_snapshot.path, entry.name) catch return;
        defer source.owner.gpa.free(dst_path);
        if (source.site_id == selection.destination.site_id and
            (std.mem.eql(u8, src_path, dst_path) or
                (entry.kind == .dir and pathContains(src_path, dst_path)))) return;
        _ = source.owner.core.enqueueTransfer(.{
            .direction = if (selection.destination.site_id != local_site_id) .upload else .download,
            .kind = if (entry.kind == .dir) .folder else .file,
            .src = .{ .site_id = source.site_id, .path = src_path },
            .dst = .{ .site_id = selection.destination.site_id, .path = dst_path },
            .conflict = .ask,
            .bytes_total = entry.size orelse 0,
        }) catch return;
        selection.enqueued += 1;
    }

    fn pathContains(parent: []const u8, candidate: []const u8) bool {
        if (!std.mem.startsWith(u8, candidate, parent) or candidate.len <= parent.len) return false;
        return parent.len == 1 or candidate[parent.len] == '/';
    }

    fn onPathActivated(_: *gtk.Entry, self: *Pane) callconv(.c) void {
        const path = std.mem.span(self.path_entry.as(gtk.Editable).getText());
        self.navigate(path) catch |err| self.setStatus("Invalid path: {s}", .{@errorName(err)});
    }

    fn onRowActivated(_: *gtk.ColumnView, position: c_uint, self: *Pane) callconv(.c) void {
        const snapshot = self.snapshot orelse return;
        const entry_index = self.entryIndexAt(position) orelse return;
        if (entry_index >= snapshot.entries.len) return;
        const entry = &snapshot.entries[entry_index];
        if (entry.kind != .dir) {
            self.openFile(entry.*, .open);
            return;
        }
        const base = snapshot.path;
        const path = if (std.mem.eql(u8, base, "/"))
            std.fmt.allocPrint(self.owner.gpa, "/{s}", .{entry.name})
        else
            std.fmt.allocPrint(self.owner.gpa, "{s}/{s}", .{ base, entry.name });
        const next = path catch {
            self.setStatus("Not enough memory to open folder", .{});
            return;
        };
        defer self.owner.gpa.free(next);
        self.navigate(next) catch |err| self.setStatus("Cannot open folder: {s}", .{@errorName(err)});
    }

    fn openSelected(self: *Pane, kind: PendingFileKind) void {
        const selection = self.selectionInfo();
        if (selection.count != 1) {
            self.setStatus("Select exactly one file", .{});
            return;
        }
        const snapshot = self.snapshot orelse return;
        const entry_index = self.entryIndexAt(selection.first.?) orelse return;
        if (entry_index >= snapshot.entries.len or snapshot.entries[entry_index].kind == .dir) {
            self.setStatus("Select a file, not a folder", .{});
            return;
        }
        self.openFile(snapshot.entries[entry_index], kind);
    }

    fn openFile(self: *Pane, entry: Entry, kind: PendingFileKind) void {
        const snapshot = self.snapshot orelse return;
        if (!relay.vfs.path.isSafeChildName(entry.name)) {
            self.setStatus("Cannot open an unsafe remote file name", .{});
            return;
        }
        const source_path = relay.vfs.path.join(self.owner.gpa, snapshot.path, entry.name) catch return;
        defer self.owner.gpa.free(source_path);
        if (self.site_id == local_site_id) {
            switch (kind) {
                .open, .edit => self.owner.services.opener().openPath(source_path) catch |err| {
                    self.setStatus("Could not open file: {s}", .{@errorName(err)});
                },
                .preview => PreviewWindow.create(self.owner, source_path) catch |err| {
                    self.setStatus("Could not preview file: {s}", .{@errorName(err)});
                },
            }
            return;
        }

        const destination = if (kind == .open) blk: {
            const base = self.owner.downloadDirectory() catch {
                self.setStatus("Could not create the download directory", .{});
                return;
            };
            defer self.owner.gpa.free(base);
            break :blk relay.vfs.path.join(self.owner.gpa, base, entry.name) catch return;
        } else blk: {
            const id = self.owner.next_temp_id;
            self.owner.next_temp_id += 1;
            const child = std.fmt.allocPrint(
                self.owner.gpa,
                "{s}-{d}-{s}",
                .{ @tagName(kind), id, entry.name },
            ) catch return;
            defer self.owner.gpa.free(child);
            break :blk relay.vfs.path.join(self.owner.gpa, self.owner.temp_dir, child) catch return;
        };
        errdefer self.owner.gpa.free(destination);
        const item_id = self.owner.core.enqueueTransfer(.{
            .direction = .download,
            .kind = .file,
            .src = .{ .site_id = self.site_id, .path = source_path },
            .dst = .{ .site_id = local_site_id, .path = destination },
            .conflict = .overwrite,
            .bytes_total = entry.size orelse 0,
        }) catch |err| {
            self.owner.gpa.free(destination);
            self.setStatus("Could not queue download: {s}", .{@errorName(err)});
            return;
        };
        const remote_path = if (kind == .edit) self.owner.gpa.dupe(u8, source_path) catch {
            self.owner.gpa.free(destination);
            _ = self.owner.core.cancelTransfer(item_id);
            return;
        } else null;
        self.owner.pending_files.put(self.owner.gpa, item_id, .{
            .path = destination,
            .kind = kind,
            .site_id = self.site_id,
            .remote_path = remote_path,
            .remote_mtime = entry.mtime,
            .cleanup_temp = kind != .open,
        }) catch {
            self.owner.gpa.free(destination);
            if (remote_path) |path| self.owner.gpa.free(path);
            _ = self.owner.core.cancelTransfer(item_id);
            return;
        };
        self.owner.transfers.root.setExpanded(1);
        self.owner.transfers.syncFromEngine();
        self.setStatus("Downloading “{s}” to {s}…", .{ entry.name, @tagName(kind) });
    }
};

fn operationLabel(op: ui.bridge.OpKind) []const u8 {
    return switch (op) {
        .mkdir => "New folder",
        .rename => "Rename",
        .chmod => "Change permissions",
        .delete => "Delete",
        .stat => "Refresh metadata",
    };
}

const NameDialog = struct {
    owner: *Pane,
    native: *gtk.Dialog,
    entry: *gtk.Editable,
    error_label: *gtk.Label,
    mode: Mode,
    site_id: u64,
    base_path: []u8,
    old_name: ?[]u8,

    const Mode = enum { new_folder, rename };

    fn create(owner: *Pane, mode: Mode, old_name: ?[]const u8) !void {
        const snapshot = owner.snapshot orelse return error.NoSnapshot;
        const base_path = try owner.owner.gpa.dupe(u8, snapshot.path);
        errdefer owner.owner.gpa.free(base_path);
        const old_owned = if (old_name) |name| try owner.owner.gpa.dupe(u8, name) else null;
        errdefer if (old_owned) |name| owner.owner.gpa.free(name);
        const self = try owner.owner.gpa.create(NameDialog);
        errdefer owner.owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();

        const title = if (mode == .new_folder) "New Folder" else "Rename";
        dialog.as(gtk.Window).setTitle(title);
        dialog.as(gtk.Window).setTransientFor(owner.owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton(if (mode == .new_folder) "Create" else "Rename", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.accept));

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);
        const prompt = gtk.Label.new(if (mode == .new_folder) "Folder name" else "New name");
        prompt.setXalign(0);
        const entry = gtk.Entry.new();
        const initial_z = try allocPrintZ(owner.owner.gpa, "{s}", .{old_name orelse "untitled folder"});
        defer owner.owner.gpa.free(initial_z);
        entry.as(gtk.Editable).setText(initial_z);
        const error_label = gtk.Label.new("");
        error_label.setXalign(0);
        error_label.setWrap(1);
        error_label.as(gtk.Widget).addCssClass("error");
        content.append(prompt.as(gtk.Widget));
        content.append(entry.as(gtk.Widget));
        content.append(error_label.as(gtk.Widget));

        self.* = .{
            .owner = owner,
            .native = dialog,
            .entry = entry.as(gtk.Editable),
            .error_label = error_label,
            .mode = mode,
            .site_id = owner.site_id,
            .base_path = base_path,
            .old_name = old_owned,
        };
        owner.name_dialog = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *NameDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
        _ = entry.as(gtk.Widget).grabFocus();
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *NameDialog) callconv(.c) void {
        if (response != @intFromEnum(gtk.ResponseType.accept)) {
            self.finish();
            return;
        }
        const raw = std.mem.span(self.entry.getText());
        const name = std.mem.trim(u8, raw, " \t");
        if (!relay.vfs.path.isSafeChildName(name)) {
            self.error_label.setText("Use one non-empty name without ‘/’; the names ‘.’ and ‘..’ are reserved.");
            return;
        }
        const snapshot = self.owner.snapshot orelse {
            self.error_label.setText("The folder is no longer available.");
            return;
        };
        if (self.owner.site_id != self.site_id or !std.mem.eql(u8, snapshot.path, self.base_path)) {
            self.error_label.setText("The pane changed while this dialog was open. Try again.");
            return;
        }

        switch (self.mode) {
            .new_folder => self.startNewFolder(name),
            .rename => self.startRename(name),
        }
    }

    fn startNewFolder(self: *NameDialog, name: []const u8) void {
        const target = relay.vfs.path.join(self.owner.owner.gpa, self.base_path, name) catch {
            self.error_label.setText("Could not build the destination path.");
            return;
        };
        defer self.owner.owner.gpa.free(target);
        self.owner.owner.core.mkdirPath(self.owner.token, self.site_id, target) catch |err| {
            self.setStartError(err);
            return;
        };
        self.owner.pending_ops += 1;
        self.owner.updatePendingStyle();
        self.owner.setStatus("Creating “{s}”…", .{name});
        self.finish();
    }

    fn startRename(self: *NameDialog, name: []const u8) void {
        const old_name = self.old_name orelse return;
        if (std.mem.eql(u8, old_name, name)) {
            self.finish();
            return;
        }
        const from = relay.vfs.path.join(self.owner.owner.gpa, self.base_path, old_name) catch {
            self.error_label.setText("Could not build the source path.");
            return;
        };
        defer self.owner.owner.gpa.free(from);
        const to = relay.vfs.path.join(self.owner.owner.gpa, self.base_path, name) catch {
            self.error_label.setText("Could not build the destination path.");
            return;
        };
        defer self.owner.owner.gpa.free(to);
        self.owner.owner.core.renamePath(self.owner.token, self.site_id, from, to) catch |err| {
            self.setStartError(err);
            return;
        };
        self.owner.pending_ops += 1;
        self.owner.updatePendingStyle();
        self.owner.setStatus("Renaming “{s}” to “{s}”…", .{ old_name, name });
        self.finish();
    }

    fn setStartError(self: *NameDialog, err: anyerror) void {
        var buf: [160]u8 = undefined;
        const message = std.fmt.bufPrintZ(&buf, "Could not start operation: {s}", .{@errorName(err)}) catch "Could not start operation.";
        self.error_label.setText(message);
    }

    fn finish(self: *NameDialog) void {
        const pane = self.owner;
        pane.name_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.free();
    }

    fn destroy(self: *NameDialog) void {
        self.owner.name_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.free();
    }

    fn free(self: *NameDialog) void {
        const gpa = self.owner.owner.gpa;
        gpa.free(self.base_path);
        if (self.old_name) |name| gpa.free(name);
        gpa.destroy(self);
    }
};

const DeleteTarget = struct {
    path: []u8,
    recursive: bool,
};

const DeleteDialog = struct {
    owner: *Pane,
    native: *gtk.Dialog = undefined,
    targets: std.ArrayList(DeleteTarget) = .empty,
    collect_failed: bool = false,
    site_id: u64,
    confirmation_entry: ?*gtk.Entry = null,
    accept_button: ?*gtk.Widget = null,

    fn create(owner: *Pane) !void {
        const self = try owner.owner.gpa.create(DeleteDialog);
        self.* = .{ .owner = owner, .site_id = owner.site_id };
        errdefer {
            self.freeTargets();
            owner.owner.gpa.destroy(self);
        }
        const model = owner.selection.as(gtk.SelectionModel);
        const count = owner.sort_model.as(gio.ListModel).getNItems();
        var position: c_uint = 0;
        while (position < count) : (position += 1) {
            if (model.isSelected(position) == 0) continue;
            self.collectTarget(position);
        }
        if (self.collect_failed) return error.OutOfMemory;
        if (self.targets.items.len == 0) return error.NoSelection;
        const production = if (owner.owner.site_store.get(owner.site_id)) |site|
            site.environment == .prod
        else
            false;
        if (!owner.owner.prefs.confirm_delete and !production) {
            self.start();
            self.freeTargets();
            owner.owner.gpa.destroy(self);
            return;
        }

        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        self.native = dialog;
        dialog.as(gtk.Window).setTitle("Delete Items");
        dialog.as(gtk.Window).setTransientFor(owner.owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Cancel", @intFromEnum(gtk.ResponseType.cancel));
        _ = dialog.addButton("Delete", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.cancel));
        if (dialog.getWidgetForResponse(@intFromEnum(gtk.ResponseType.accept))) |button| {
            button.addCssClass("destructive-action");
            self.accept_button = button;
            if (production) button.setSensitive(0);
        }

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);
        var message_buf: [256]u8 = undefined;
        const message = if (self.targets.items.len == 1)
            std.fmt.bufPrintZ(&message_buf, "Permanently delete “{s}”?", .{relay.vfs.path.basename(self.targets.items[0].path)}) catch "Permanently delete this item?"
        else
            std.fmt.bufPrintZ(&message_buf, "Permanently delete {d} selected items?", .{self.targets.items.len}) catch "Permanently delete the selected items?";
        const label = gtk.Label.new(message);
        label.setWrap(1);
        label.setXalign(0);
        const warning = gtk.Label.new(if (production)
            "Production safeguard: type DELETE below. This cannot be undone."
        else
            "This cannot be undone. Folders are deleted recursively.");
        warning.setWrap(1);
        warning.setXalign(0);
        warning.as(gtk.Widget).addCssClass("dim-label");
        content.append(label.as(gtk.Widget));
        content.append(warning.as(gtk.Widget));
        if (production) {
            const confirmation = gtk.Entry.new();
            confirmation.setPlaceholderText("Type DELETE");
            content.append(confirmation.as(gtk.Widget));
            self.confirmation_entry = confirmation;
            _ = gtk.Editable.signals.changed.connect(
                confirmation.as(gtk.Editable),
                *DeleteDialog,
                onConfirmationChanged,
                self,
                .{},
            );
        }

        owner.delete_dialog = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *DeleteDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
    }

    fn collectTarget(self: *DeleteDialog, position: usize) void {
        if (self.collect_failed) return;
        const snapshot = self.owner.snapshot orelse return;
        const entry_index = self.owner.entryIndexAt(position) orelse return;
        if (entry_index >= snapshot.entries.len) return;
        const entry = &snapshot.entries[entry_index];
        if (!relay.vfs.path.isSafeChildName(entry.name)) return;
        const path = relay.vfs.path.join(self.owner.owner.gpa, snapshot.path, entry.name) catch {
            self.collect_failed = true;
            return;
        };
        self.targets.append(self.owner.owner.gpa, .{
            .path = path,
            .recursive = entry.kind == .dir,
        }) catch {
            self.owner.owner.gpa.free(path);
            self.collect_failed = true;
        };
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *DeleteDialog) callconv(.c) void {
        if (response != @intFromEnum(gtk.ResponseType.accept)) {
            self.finish();
            return;
        }
        self.start();
        self.finish();
    }

    fn onConfirmationChanged(_: *gtk.Editable, self: *DeleteDialog) callconv(.c) void {
        const entry = self.confirmation_entry orelse return;
        const button = self.accept_button orelse return;
        button.setSensitive(@intFromBool(std.mem.eql(
            u8,
            std.mem.trim(u8, std.mem.span(entry.as(gtk.Editable).getText()), " \t\r\n"),
            "DELETE",
        )));
    }

    fn start(self: *DeleteDialog) void {
        var started: usize = 0;
        var first_error: ?anyerror = null;
        for (self.targets.items) |target| {
            self.owner.owner.core.deletePath(
                self.owner.token,
                self.site_id,
                target.path,
                target.recursive,
            ) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            started += 1;
        }
        self.owner.pending_ops += started;
        self.owner.updatePendingStyle();
        if (started == self.targets.items.len) {
            self.owner.setStatus("Deleting {d} item{s}…", .{ started, if (started == 1) "" else "s" });
        } else {
            self.owner.setStatus("Started {d} of {d} deletions: {s}", .{
                started,
                self.targets.items.len,
                if (first_error) |err| @errorName(err) else "unknown error",
            });
        }
    }

    fn finish(self: *DeleteDialog) void {
        const pane = self.owner;
        pane.delete_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.free();
    }

    fn destroy(self: *DeleteDialog) void {
        self.owner.delete_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.free();
    }

    fn free(self: *DeleteDialog) void {
        const gpa = self.owner.owner.gpa;
        self.freeTargets();
        gpa.destroy(self);
    }

    fn freeTargets(self: *DeleteDialog) void {
        const gpa = self.owner.owner.gpa;
        for (self.targets.items) |target| gpa.free(target.path);
        self.targets.deinit(gpa);
    }
};

const TransferPanel = struct {
    owner: *Window,
    root: *gtk.Expander,
    list: *gtk.ListBox,
    failed_list: *gtk.ListBox,
    stack: *gtk.Stack,
    transcript_buffer: *gtk.TextBuffer,
    upload_limit: *gtk.SpinButton,
    download_limit: *gtk.SpinButton,
    summary: *gtk.Label,
    rows: std.ArrayList(TransferRow) = .empty,
    collapsed_groups: std.AutoHashMapUnmanaged(ui.bridge.ItemId, void) = .empty,
    conflict_dialog: ?*ConflictDialog = null,

    fn init(self: *TransferPanel, owner: *Window) void {
        const root = gtk.Expander.new("Transfers");
        root.setResizeToplevel(0);

        const body = gtk.Box.new(.vertical, 6);
        const body_widget = body.as(gtk.Widget);
        body_widget.setMarginTop(6);
        body_widget.setMarginBottom(8);
        body_widget.setMarginStart(8);
        body_widget.setMarginEnd(8);

        const controls = gtk.Box.new(.horizontal, 6);
        const summary = gtk.Label.new("No transfers");
        summary.setXalign(0);
        summary.as(gtk.Widget).setHexpand(1);
        summary.as(gtk.Widget).addCssClass("dim-label");
        const pause = gtk.Button.newWithLabel("Pause / Resume");
        const cancel = gtk.Button.newWithLabel("Cancel");
        const remove = gtk.Button.newWithLabel("Remove");
        const up = gtk.Button.newWithLabel("↑");
        const down = gtk.Button.newWithLabel("↓");
        const retry = gtk.Button.newWithLabel("Retry Failed");
        const clear = gtk.Button.newWithLabel("Clear Finished");
        controls.append(summary.as(gtk.Widget));
        controls.append(pause.as(gtk.Widget));
        controls.append(cancel.as(gtk.Widget));
        controls.append(remove.as(gtk.Widget));
        controls.append(up.as(gtk.Widget));
        controls.append(down.as(gtk.Widget));
        controls.append(retry.as(gtk.Widget));
        controls.append(clear.as(gtk.Widget));

        const bulk = gtk.Box.new(.horizontal, 6);
        const pause_all = gtk.Button.newWithLabel("Pause All");
        const resume_all = gtk.Button.newWithLabel("Resume All");
        const cancel_all = gtk.Button.newWithLabel("Cancel All");
        const restore = gtk.Button.newWithLabel("Restore Queue");
        const upload_label = gtk.Label.new("Upload KB/s");
        const upload_limit = gtk.SpinButton.newWithRange(0, 10_000_000, 100);
        upload_limit.setValue(@floatFromInt(owner.core.settings.rate_limit_up / 1024));
        const download_label = gtk.Label.new("Download KB/s");
        const download_limit = gtk.SpinButton.newWithRange(0, 10_000_000, 100);
        download_limit.setValue(@floatFromInt(owner.core.settings.rate_limit_down / 1024));
        bulk.append(pause_all.as(gtk.Widget));
        bulk.append(resume_all.as(gtk.Widget));
        bulk.append(cancel_all.as(gtk.Widget));
        bulk.append(restore.as(gtk.Widget));
        bulk.append(upload_label.as(gtk.Widget));
        bulk.append(upload_limit.as(gtk.Widget));
        bulk.append(download_label.as(gtk.Widget));
        bulk.append(download_limit.as(gtk.Widget));

        const list = gtk.ListBox.new();
        list.setSelectionMode(.single);
        list.setShowSeparators(1);
        const list_keys = gtk.EventControllerKey.new();
        list.as(gtk.Widget).addController(list_keys.as(gtk.EventController));
        const active_scroller = gtk.ScrolledWindow.new();
        active_scroller.as(gtk.Widget).setSizeRequest(-1, 190);
        active_scroller.setPolicy(.automatic, .automatic);
        active_scroller.setChild(list.as(gtk.Widget));

        const failed_list = gtk.ListBox.new();
        failed_list.setSelectionMode(.single);
        failed_list.setShowSeparators(1);
        const failed_keys = gtk.EventControllerKey.new();
        failed_list.as(gtk.Widget).addController(failed_keys.as(gtk.EventController));
        const failed_scroller = gtk.ScrolledWindow.new();
        failed_scroller.as(gtk.Widget).setSizeRequest(-1, 190);
        failed_scroller.setPolicy(.automatic, .automatic);
        failed_scroller.setChild(failed_list.as(gtk.Widget));

        const transcript_buffer = gtk.TextBuffer.new(null);
        const transcript = gtk.TextView.newWithBuffer(transcript_buffer);
        transcript.setEditable(0);
        transcript.setCursorVisible(0);
        transcript.setMonospace(1);
        const transcript_scroller = gtk.ScrolledWindow.new();
        transcript_scroller.as(gtk.Widget).setSizeRequest(-1, 190);
        transcript_scroller.setPolicy(.automatic, .automatic);
        transcript_scroller.setChild(transcript.as(gtk.Widget));

        const stack = gtk.Stack.new();
        stack.setTransitionType(.crossfade);
        _ = stack.addTitled(active_scroller.as(gtk.Widget), "active", "Active / Queued");
        _ = stack.addTitled(failed_scroller.as(gtk.Widget), "failed", "Failed");
        _ = stack.addTitled(transcript_scroller.as(gtk.Widget), "transcript", "Transcript");
        const switcher = gtk.StackSwitcher.new();
        switcher.setStack(stack);

        body.append(controls.as(gtk.Widget));
        body.append(bulk.as(gtk.Widget));
        body.append(switcher.as(gtk.Widget));
        body.append(stack.as(gtk.Widget));
        root.setChild(body.as(gtk.Widget));
        self.* = .{
            .owner = owner,
            .root = root,
            .list = list,
            .failed_list = failed_list,
            .stack = stack,
            .transcript_buffer = transcript_buffer,
            .upload_limit = upload_limit,
            .download_limit = download_limit,
            .summary = summary,
        };

        _ = gtk.Button.signals.clicked.connect(pause, *TransferPanel, onPauseResume, self, .{});
        _ = gtk.Button.signals.clicked.connect(cancel, *TransferPanel, onCancel, self, .{});
        _ = gtk.Button.signals.clicked.connect(remove, *TransferPanel, onRemove, self, .{});
        _ = gtk.Button.signals.clicked.connect(up, *TransferPanel, onMoveUp, self, .{});
        _ = gtk.Button.signals.clicked.connect(down, *TransferPanel, onMoveDown, self, .{});
        _ = gtk.Button.signals.clicked.connect(retry, *TransferPanel, onRetryFailed, self, .{});
        _ = gtk.Button.signals.clicked.connect(clear, *TransferPanel, onClearFinished, self, .{});
        _ = gtk.Button.signals.clicked.connect(pause_all, *TransferPanel, onPauseAll, self, .{});
        _ = gtk.Button.signals.clicked.connect(resume_all, *TransferPanel, onResumeAll, self, .{});
        _ = gtk.Button.signals.clicked.connect(cancel_all, *TransferPanel, onCancelAll, self, .{});
        _ = gtk.Button.signals.clicked.connect(restore, *TransferPanel, onRestore, self, .{});
        _ = gtk.EventControllerKey.signals.key_pressed.connect(list_keys, *TransferPanel, onQueueKey, self, .{});
        _ = gtk.EventControllerKey.signals.key_pressed.connect(failed_keys, *TransferPanel, onQueueKey, self, .{});
        _ = gtk.SpinButton.signals.value_changed.connect(upload_limit, *TransferPanel, onRateChanged, self, .{});
        _ = gtk.SpinButton.signals.value_changed.connect(download_limit, *TransferPanel, onRateChanged, self, .{});
    }

    fn deinit(self: *TransferPanel) void {
        if (self.conflict_dialog) |dialog| dialog.destroy();
        self.collapsed_groups.deinit(self.owner.gpa);
        self.rows.deinit(self.owner.gpa);
    }

    fn syncFromEngine(self: *TransferPanel) void {
        var arena: std.heap.ArenaAllocator = .init(self.owner.gpa);
        defer arena.deinit();
        const snapshots = self.owner.core.queueSnapshot(arena.allocator()) catch {
            self.summary.setText("Could not load transfer queue");
            return;
        };

        self.list.removeAll();
        self.failed_list.removeAll();
        self.rows.clearRetainingCapacity();
        var complete = true;
        for (snapshots, 0..) |snapshot, queue_index| {
            if (snapshot.parent != 0 and self.collapsed_groups.contains(snapshot.parent)) continue;
            self.appendSnapshot(snapshot, queue_index) catch {
                complete = false;
                break;
            };
        }
        self.updateSummary();
        if (!complete) self.summary.setText("Not enough memory to display every transfer");
        self.showNextConflict();
    }

    fn appendSnapshot(self: *TransferPanel, snapshot: relay.queue.engine.ItemSnapshot, queue_index: usize) !void {
        try self.rows.ensureUnusedCapacity(self.owner.gpa, 1);
        const content = gtk.Box.new(.vertical, 3);
        const top = gtk.Box.new(.horizontal, 8);
        const name = relay.vfs.path.basename(snapshot.dst.path);
        const name_z = try allocPrintZ(self.owner.gpa, "{s}{s}  {s}", .{
            if (snapshot.parent != 0) "  ↳ " else "",
            if (snapshot.direction == .upload) "↑" else "↓",
            name,
        });
        defer self.owner.gpa.free(name_z);
        const name_label = gtk.Label.new(name_z);
        name_label.setXalign(0);
        name_label.as(gtk.Widget).setHexpand(1);
        const state_label = gtk.Label.new("");
        state_label.setXalign(1);
        state_label.setMaxWidthChars(80);
        state_label.as(gtk.Widget).addCssClass("dim-label");
        var group_toggle: ?*gtk.CheckButton = null;
        if (snapshot.kind == .folder and snapshot.parent == 0) {
            const toggle = gtk.CheckButton.new();
            toggle.setActive(@intFromBool(!self.collapsed_groups.contains(snapshot.id)));
            toggle.as(gtk.Widget).setTooltipText("Show folder transfer children");
            top.append(toggle.as(gtk.Widget));
            group_toggle = toggle;
        }
        top.append(name_label.as(gtk.Widget));
        top.append(state_label.as(gtk.Widget));

        const progress = gtk.ProgressBar.new();
        progress.setShowText(0);
        content.as(gtk.Widget).setMarginTop(6);
        content.as(gtk.Widget).setMarginBottom(6);
        content.as(gtk.Widget).setMarginStart(8);
        content.as(gtk.Widget).setMarginEnd(8);
        content.append(top.as(gtk.Widget));
        content.append(progress.as(gtk.Widget));
        const target_list = if (snapshot.state == .failed) self.failed_list else self.list;
        target_list.append(content.as(gtk.Widget));

        self.rows.appendAssumeCapacity(.{
            .id = snapshot.id,
            .parent = snapshot.parent,
            .queue_index = queue_index,
            .state = snapshot.state.toEventState(),
            .bytes_done = snapshot.bytes_done,
            .bytes_total = snapshot.bytes_total,
            .rate = snapshot.rate_bps,
            .progress = progress,
            .state_label = state_label,
            .list = target_list,
            .group_toggle = group_toggle,
        });
        const row = &self.rows.items[self.rows.items.len - 1];
        row.name_len = @min(name.len, row.name_buf.len);
        @memcpy(row.name_buf[0..row.name_len], name[0..row.name_len]);
        row.failure_len = @min(snapshot.failure_message.len, row.failure_buf.len);
        @memcpy(row.failure_buf[0..row.failure_len], snapshot.failure_message[0..row.failure_len]);
        if (group_toggle) |toggle| {
            _ = gtk.CheckButton.signals.toggled.connect(toggle, *TransferPanel, onGroupToggled, self, .{});
        }
        self.updateRow(row);
    }

    fn onGroupToggled(toggle: *gtk.CheckButton, self: *TransferPanel) callconv(.c) void {
        var id: ?ui.bridge.ItemId = null;
        for (self.rows.items) |row| {
            if (row.group_toggle == toggle) {
                id = row.id;
                break;
            }
        }
        const group_id = id orelse return;
        if (toggle.getActive() != 0) {
            _ = self.collapsed_groups.remove(group_id);
        } else {
            self.collapsed_groups.put(self.owner.gpa, group_id, {}) catch return;
        }
        self.syncFromEngine();
    }

    fn applyState(self: *TransferPanel, event: relay.events.CoreEvent.TransferStateChange) void {
        if (event.state == .failed or event.state == .queued or event.state == .connecting) {
            self.syncFromEngine();
            if (event.state == .conflict) self.showConflict(event.item_id);
            return;
        }
        for (self.rows.items) |*row| {
            if (row.id != event.item_id) continue;
            row.state = event.state;
            if (event.failure) |failure| {
                row.failure_len = @min(failure.message.len, row.failure_buf.len);
                @memcpy(row.failure_buf[0..row.failure_len], failure.message[0..row.failure_len]);
            } else if (event.state != .failed and event.state != .canceled) {
                row.failure_len = 0;
            }
            self.updateRow(row);
            self.updateSummary();
            if (event.state == .conflict) self.showConflict(event.item_id);
            return;
        }
        self.syncFromEngine();
        if (event.state == .conflict) self.showConflict(event.item_id);
    }

    fn applyProgress(self: *TransferPanel, event: relay.events.CoreEvent.TransferProgress) void {
        for (self.rows.items) |*row| {
            if (row.id != event.item_id) continue;
            row.bytes_done = event.bytes_done;
            row.rate = event.rate;
            self.updateRow(row);
            self.updateSummary();
            return;
        }
        self.syncFromEngine();
    }

    fn updateRow(_: *TransferPanel, row: *TransferRow) void {
        if (row.state == .completed) {
            row.progress.setFraction(1.0);
        } else if (row.bytes_total > 0) {
            const done: f64 = @floatFromInt(row.bytes_done);
            const total: f64 = @floatFromInt(row.bytes_total);
            row.progress.setFraction(@min(1.0, done / total));
        } else {
            row.progress.setFraction(0.0);
            if (row.state == .transferring) row.progress.pulse();
        }

        var done_buf: [32]u8 = undefined;
        var total_buf: [32]u8 = undefined;
        var rate_value_buf: [32]u8 = undefined;
        var rate_buf: [32]u8 = undefined;
        const done = ui.format.humanBytes(&done_buf, row.bytes_done);
        const total = if (row.bytes_total > 0) ui.format.humanBytes(&total_buf, row.bytes_total) else "?";
        const rate = if (row.state == .transferring and row.rate > 0)
            std.fmt.bufPrint(&rate_buf, " · {s}/s", .{ui.format.humanBytes(&rate_value_buf, row.rate)}) catch ""
        else
            "";
        const failure = if (row.failure_len > 0) row.failure_buf[0..row.failure_len] else "";
        var label_buf: [512]u8 = undefined;
        const label = std.fmt.bufPrintZ(&label_buf, "{s} · {s} / {s}{s}{s}{s}", .{
            transferStateLabel(row.state),
            done,
            total,
            rate,
            if (failure.len > 0) " · " else "",
            failure,
        }) catch {
            row.state_label.setText("Transfer");
            return;
        };
        row.state_label.setText(label);
    }

    fn updateSummary(self: *TransferPanel) void {
        var active: usize = 0;
        var failed: usize = 0;
        var rate: u64 = 0;
        var bytes_done: u64 = 0;
        var bytes_total: u64 = 0;
        for (self.rows.items) |row| {
            switch (row.state) {
                .queued, .connecting, .transferring => active += 1,
                .failed => failed += 1,
                else => {},
            }
            if (row.state == .transferring) rate +|= row.rate;
            bytes_done +|= row.bytes_done;
            bytes_total +|= row.bytes_total;
        }
        var rate_buf: [32]u8 = undefined;
        var done_buf: [32]u8 = undefined;
        var total_buf: [32]u8 = undefined;
        var summary_buf: [256]u8 = undefined;
        const eta = if (rate > 0 and bytes_total > bytes_done) (bytes_total - bytes_done) / rate else 0;
        const text = if (self.rows.items.len == 0)
            "No transfers"
        else if (rate > 0)
            std.fmt.bufPrintZ(&summary_buf, "{d} items · {s} / {s} · {s}/s · ETA {d}s · {d} failed", .{
                self.rows.items.len,
                ui.format.humanBytes(&done_buf, bytes_done),
                ui.format.humanBytes(&total_buf, bytes_total),
                ui.format.humanBytes(&rate_buf, rate),
                eta,
                failed,
            }) catch "Transfers"
        else
            std.fmt.bufPrintZ(&summary_buf, "{d} total · {d} active · {d} failed", .{
                self.rows.items.len, active, failed,
            }) catch "Transfers";
        self.summary.setText(text);

        var title_buf: [64]u8 = undefined;
        const title = std.fmt.bufPrintZ(&title_buf, "Transfers ({d})", .{self.rows.items.len}) catch "Transfers";
        self.root.setLabel(title);
    }

    fn selected(self: *TransferPanel) ?*TransferRow {
        const selected_list, const selected_row = if (self.list.getSelectedRow()) |row|
            .{ self.list, row }
        else if (self.failed_list.getSelectedRow()) |row|
            .{ self.failed_list, row }
        else
            return null;
        const index = selected_row.getIndex();
        if (index < 0) return null;
        var list_index: usize = 0;
        for (self.rows.items) |*row| {
            if (row.list != selected_list) continue;
            if (list_index == @as(usize, @intCast(index))) return row;
            list_index += 1;
        }
        return null;
    }

    fn onPauseResume(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const row = self.selected() orelse return;
        if (row.state == .paused) {
            _ = self.owner.core.resumeTransfer(row.id) catch false;
        } else {
            _ = self.owner.core.pauseTransfer(row.id);
        }
    }

    fn onCancel(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const row = self.selected() orelse return;
        _ = self.owner.core.cancelTransfer(row.id);
    }

    fn onRemove(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const row = self.selected() orelse return;
        if (self.owner.core.removeTransferDetailed(row.id) == .removed) self.owner.abandonTransfer(row.id);
        self.syncFromEngine();
    }

    fn onMoveUp(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const row = self.selected() orelse return;
        if (row.queue_index == 0) return;
        _ = self.owner.core.reorderTransfer(row.id, row.queue_index - 1);
        self.syncFromEngine();
    }

    fn onMoveDown(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const row = self.selected() orelse return;
        _ = self.owner.core.reorderTransfer(row.id, row.queue_index + 1);
        self.syncFromEngine();
    }

    fn onRetryFailed(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        if (self.owner.core.requeueFailed() > 0) self.root.setExpanded(1);
        self.syncFromEngine();
    }

    fn onClearFinished(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        self.clearFinished();
    }

    fn clearFinished(self: *TransferPanel) void {
        var i = self.rows.items.len;
        while (i > 0) {
            i -= 1;
            const row = self.rows.items[i];
            switch (row.state) {
                .completed, .canceled => _ = self.owner.core.removeTransfer(row.id),
                else => {},
            }
        }
        self.syncFromEngine();
    }

    fn onPauseAll(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        self.owner.core.pauseAllTransfers();
        self.syncFromEngine();
    }

    fn onResumeAll(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        self.owner.core.resumeAllTransfers() catch {};
        self.syncFromEngine();
    }

    fn onCancelAll(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        self.owner.core.cancelAllTransfers();
        self.syncFromEngine();
    }

    fn onRestore(_: *gtk.Button, self: *TransferPanel) callconv(.c) void {
        const count = self.owner.core.restoreQueue();
        self.syncFromEngine();
        self.root.setExpanded(@intFromBool(count > 0));
    }

    fn onRateChanged(_: *gtk.SpinButton, self: *TransferPanel) callconv(.c) void {
        const upload_kb: u64 = @intCast(@max(0, self.upload_limit.getValueAsInt()));
        const download_kb: u64 = @intCast(@max(0, self.download_limit.getValueAsInt()));
        self.owner.core.setTransferRateLimits(upload_kb * 1024, download_kb * 1024);
        self.owner.core.saveSettings() catch {};
    }

    fn onQueueKey(
        _: *gtk.EventControllerKey,
        keyval: c_uint,
        _: c_uint,
        _: gdk.ModifierType,
        self: *TransferPanel,
    ) callconv(.c) c_int {
        if (keyval == gdk.KEY_space) {
            const row = self.selected() orelse return 0;
            if (row.state == .paused) {
                _ = self.owner.core.resumeTransfer(row.id) catch false;
            } else if (row.state == .failed) {
                _ = self.owner.core.requeueTransfer(row.id) catch false;
            } else {
                _ = self.owner.core.pauseTransfer(row.id);
            }
            return 1;
        }
        if (keyval == gdk.KEY_Delete) {
            onRemove(undefined, self);
            return 1;
        }
        return 0;
    }

    fn appendTranscript(self: *TransferPanel, event: relay.events.CoreEvent.TranscriptLine) void {
        if (event.verbose and !self.owner.core.settings.verbose_transcript) return;
        var clean_buf: [ui.transcript.max_line_bytes]u8 = undefined;
        const clean = ui.transcript.sanitizeUtf8(event.text[0..@min(event.text.len, clean_buf.len)], &clean_buf);
        const prefix = switch (event.dir) {
            .client => "> ",
            .server => "< ",
            .info => "• ",
        };
        const line = allocPrintZ(self.owner.gpa, "[{d}] {s}{s}\n", .{ event.connection_id, prefix, clean }) catch return;
        defer self.owner.gpa.free(line);
        var end: gtk.TextIter = undefined;
        self.transcript_buffer.getEndIter(&end);
        self.transcript_buffer.insert(&end, line, -1);
    }

    fn showNextConflict(self: *TransferPanel) void {
        if (self.conflict_dialog != null) return;
        for (self.rows.items) |row| {
            if (row.state == .conflict) {
                self.showConflict(row.id);
                return;
            }
        }
    }

    fn showConflict(self: *TransferPanel, id: ui.bridge.ItemId) void {
        if (self.conflict_dialog != null) return;
        var name: []const u8 = "destination";
        for (self.rows.items) |*row| {
            if (row.id == id) name = row.name_buf[0..row.name_len];
        }
        ConflictDialog.create(self, id, name) catch {
            std.log.err("could not open transfer conflict dialog", .{});
        };
    }
};

const TransferRow = struct {
    id: ui.bridge.ItemId,
    parent: ui.bridge.ItemId,
    queue_index: usize,
    state: relay.events.TransferState,
    bytes_done: u64,
    bytes_total: u64,
    rate: u64,
    progress: *gtk.ProgressBar,
    state_label: *gtk.Label,
    list: *gtk.ListBox,
    group_toggle: ?*gtk.CheckButton = null,
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    failure_buf: [256]u8 = undefined,
    failure_len: usize = 0,
};

fn transferStateLabel(state: relay.events.TransferState) []const u8 {
    return switch (state) {
        .queued => "Queued",
        .connecting => "Connecting",
        .transferring => "Transferring",
        .paused => "Paused",
        .completed => "Completed",
        .failed => "Failed",
        .canceled => "Canceled",
        .conflict => "Needs confirmation",
    };
}

const ConflictDialog = struct {
    owner: *TransferPanel,
    native: *gtk.Dialog,
    item_id: ui.bridge.ItemId,

    fn create(owner: *TransferPanel, item_id: ui.bridge.ItemId, name: []const u8) !void {
        const self = try owner.owner.gpa.create(ConflictDialog);
        errdefer owner.owner.gpa.destroy(self);
        const dialog = gtk.Dialog.new();
        errdefer dialog.as(gtk.Window).destroy();
        dialog.as(gtk.Window).setTitle("File Already Exists");
        dialog.as(gtk.Window).setTransientFor(owner.owner.native.as(gtk.Window));
        dialog.as(gtk.Window).setModal(1);
        dialog.as(gtk.Window).setDestroyWithParent(1);
        _ = dialog.addButton("Skip", @intFromEnum(gtk.ResponseType.reject));
        _ = dialog.addButton("Overwrite", @intFromEnum(gtk.ResponseType.accept));
        dialog.setDefaultResponse(@intFromEnum(gtk.ResponseType.reject));

        const content = dialog.getContentArea();
        content.setSpacing(8);
        const content_widget = content.as(gtk.Widget);
        content_widget.setMarginTop(16);
        content_widget.setMarginBottom(16);
        content_widget.setMarginStart(16);
        content_widget.setMarginEnd(16);
        var message_buf: [160]u8 = undefined;
        const message = std.fmt.bufPrintZ(&message_buf, "“{s}” already exists at the destination. Overwrite it?", .{name}) catch "The destination already exists. Overwrite it?";
        const label = gtk.Label.new(message);
        label.setWrap(1);
        label.setXalign(0);
        content.append(label.as(gtk.Widget));

        self.* = .{ .owner = owner, .native = dialog, .item_id = item_id };
        owner.conflict_dialog = self;
        _ = gtk.Dialog.signals.response.connect(dialog, *ConflictDialog, onResponse, self, .{});
        dialog.as(gtk.Window).present();
    }

    fn onResponse(_: *gtk.Dialog, response: c_int, self: *ConflictDialog) callconv(.c) void {
        const policy: ui.bridge.ConflictPolicy = if (response == @intFromEnum(gtk.ResponseType.accept)) .overwrite else .skip;
        _ = self.owner.owner.core.resolveConflict(self.item_id, policy) catch false;
        self.finish();
    }

    fn finish(self: *ConflictDialog) void {
        const panel = self.owner;
        panel.conflict_dialog = null;
        self.native.as(gtk.Window).destroy();
        panel.owner.gpa.destroy(self);
    }

    fn destroy(self: *ConflictDialog) void {
        self.owner.conflict_dialog = null;
        self.native.as(gtk.Window).destroy();
        self.owner.owner.gpa.destroy(self);
    }
};

test "copy target containment is component-aware" {
    try std.testing.expect(Pane.pathContains("/folder", "/folder/child"));
    try std.testing.expect(Pane.pathContains("/", "/folder"));
    try std.testing.expect(!Pane.pathContains("/folder", "/folder"));
    try std.testing.expect(!Pane.pathContains("/folder", "/folder-name"));
    try std.testing.expect(!Pane.pathContains("/folder", "/other/folder"));
}

test {
    std.testing.refAllDecls(@This());
}

//! GTK application/window assembly for the Linux frontend.
//!
//! The executable owns relay_ui's AppCore; this module owns every GTK object
//! and translates AppCore listing events into native widgets. Keeping that
//! boundary here means src/app_gtk never imports GTK directly.

const std = @import("std");
const gtk = @import("gtk");
const gio = @import("gio");
const glib = @import("glib");
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

fn allocPrintZ(gpa: Allocator, comptime format: []const u8, args: anytype) error{OutOfMemory}![:0]u8 {
    const text = try std.fmt.allocPrint(gpa, format, args);
    defer gpa.free(text);
    return gpa.dupeZ(u8, text);
}

/// Run the GTK frontend until the last application window closes.
pub fn run(gpa: Allocator, core: *AppCore, site_store: *SiteStore, init: std.process.Init.Minimal) !void {
    const gtk_app = gtk.Application.new(app_id, .{});
    defer gtk_app.unref();

    var app: Application = .{
        .gpa = gpa,
        .core = core,
        .site_store = site_store,
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
    native: *gtk.Application,
    window: ?*Window = null,
    smoke_mode: bool,
    smoke_timer: c_uint = 0,
    smoke_passed: bool = false,
    init_failed: bool = false,

    fn smokeSucceeded(self: *Application) void {
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
    application: *Application,
    native: *gtk.ApplicationWindow,
    panes: [2]Pane = undefined,
    panes_initialized: usize = 0,
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

    fn create(application: *Application, app: *gtk.Application) !*Window {
        const gpa = application.gpa;
        const core = application.core;
        const self = try gpa.create(Window);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .site_store = application.site_store,
            .application = application,
            .native = gtk.ApplicationWindow.new(app),
            .site_model = gtk.StringList.new(null),
            .site_picker = undefined,
            .connect_button = undefined,
            .disconnect_button = undefined,
            .subtitle = undefined,
            .ssh = .init(gpa),
        };
        errdefer self.cleanup();

        const window = self.native.as(gtk.Window);
        window.setTitle("Relay");
        window.setDefaultSize(1180, 760);

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
        disconnect_button.as(gtk.Widget).setSensitive(0);
        header.packStart(site_picker.as(gtk.Widget));
        header.packStart(connect_button.as(gtk.Widget));
        header.packEnd(disconnect_button.as(gtk.Widget));
        header.packEnd(quick_button.as(gtk.Widget));
        window.setTitlebar(header.as(gtk.Widget));

        self.site_picker = site_picker;
        self.connect_button = connect_button;
        self.disconnect_button = disconnect_button;
        self.subtitle = subtitle;
        const home = if (std.c.getenv("HOME")) |value| std.mem.span(value) else "/";
        self.ssh.refresh(core.io, home);
        try self.rebuildSitePicker();
        _ = gtk.Button.signals.clicked.connect(connect_button, *Window, onConnectSaved, self, .{});
        _ = gtk.Button.signals.clicked.connect(quick_button, *Window, onQuickConnect, self, .{});
        _ = gtk.Button.signals.clicked.connect(disconnect_button, *Window, onDisconnect, self, .{});

        const split = gtk.Paned.new(.horizontal);
        split.setWideHandle(1);
        split.setPosition(590);
        split.setResizeStartChild(1);
        split.setResizeEndChild(1);
        split.setShrinkStartChild(0);
        split.setShrinkEndChild(0);

        self.panes[0].init(self, 1);
        self.panes_initialized = 1;
        self.panes[1].init(self, 2);
        self.panes_initialized = 2;
        split.setStartChild(self.panes[0].root.as(gtk.Widget));
        split.setEndChild(self.panes[1].root.as(gtk.Widget));
        window.setChild(split.as(gtk.Widget));

        // Mark registration live before the first append so errdefer cleanup
        // also removes a partially registered listener set.
        self.listeners_registered = true;
        try core.registerListener(.listing_progress, self, onListingProgress);
        try core.registerListener(.listing_done, self, onListingDone);
        try core.registerListener(.site_status, self, onSiteStatus);
        try core.registerListener(.prompt_needed, self, onPromptNeeded);

        try self.panes[0].navigate("/");
        try self.panes[1].navigate("/");
        return self;
    }

    fn destroy(self: *Window) void {
        const gpa = self.gpa;
        self.cleanup();
        gpa.destroy(self);
    }

    fn cleanup(self: *Window) void {
        if (self.listeners_registered) {
            self.core.unregisterListeners(@ptrCast(self));
            self.listeners_registered = false;
        }
        if (self.quick_dialog) |dialog| dialog.destroy();
        while (self.prompt_dialogs.pop()) |dialog| dialog.destroy(false);
        self.clearTransients();
        self.transients.deinit(self.gpa);
        self.statuses.deinit(self.gpa);
        self.site_ids.deinit(self.gpa);
        self.ssh.deinit();
        self.site_model.unref();
        var i = self.panes_initialized;
        while (i > 0) {
            i -= 1;
            self.panes[i].deinit();
        }
        self.panes_initialized = 0;
    }

    fn paneFor(self: *Window, token: ui.bridge.PaneToken) ?*Pane {
        for (&self.panes) |*pane| if (pane.token == token) return pane;
        return null;
    }

    fn onListingProgress(self: *Window, event: ui.bridge.ListingProgress) void {
        const pane = self.paneFor(event.pane_token) orelse return;
        if (pane.pending_request != event.request_id) return;
        pane.setStatus("Loading {d} items…", .{event.entries_so_far});
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
        pane.replaceSnapshot(snapshot, event.sort_index) catch {
            pane.setStatus("Not enough memory to display this directory", .{});
            self.application.smokeFailed();
            return;
        };
        if (self.panes[0].snapshot != null and self.panes[0].pending_request == null and
            self.panes[1].snapshot != null and self.panes[1].pending_request == null)
            self.application.smokeSucceeded();
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
    }

    fn setHeaderStatus(self: *Window, text: []const u8) void {
        const text_z = allocPrintZ(self.gpa, "Linux · {s}", .{text}) catch return;
        defer self.gpa.free(text_z);
        self.subtitle.setText(text_z);
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
        self.disconnectRemotePane();
    }

    fn connectToSite(self: *Window, site_id: u64, path_override: ?[]const u8) void {
        const site = self.site_store.get(site_id) orelse return;
        const previous = self.pane_sites[remote_pane_index];
        self.core.connectSite(site_id) catch |err| {
            self.panes[remote_pane_index].setStatus("Could not start connection: {s}", .{@errorName(err)});
            return;
        };
        const path = path_override orelse site.initial_remote_path;
        self.panes[remote_pane_index].bindSite(site_id, ui.sites.siteLabel(site.*), path) catch |err| {
            self.core.disconnectSite(site_id);
            self.panes[remote_pane_index].setStatus("Could not list server: {s}", .{@errorName(err)});
            return;
        };
        if (previous) |old_site_id| {
            if (old_site_id != site_id) self.core.disconnectSite(old_site_id);
        }
        self.pane_sites[remote_pane_index] = site_id;
        self.disconnect_button.as(gtk.Widget).setSensitive(1);
        self.setHeaderStatus("connecting");
    }

    fn disconnectRemotePane(self: *Window) void {
        if (self.pane_sites[remote_pane_index]) |site_id| self.core.disconnectSite(site_id);
        self.pane_sites[remote_pane_index] = null;
        self.panes[remote_pane_index].bindSite(local_site_id, "Local", "/") catch |err| {
            self.panes[remote_pane_index].setStatus("Could not restore local pane: {s}", .{@errorName(err)});
        };
        self.disconnect_button.as(gtk.Widget).setSensitive(0);
        self.setHeaderStatus("local");
    }

    fn onSiteStatus(self: *Window, event: relay.events.CoreEvent.SiteStatusChange) void {
        self.statuses.put(self.gpa, event.site_id, event.status) catch {};
        self.resolveTransients(event.site_id, event.status);
        if (self.pane_sites[remote_pane_index] != event.site_id) return;

        const pane = &self.panes[remote_pane_index];
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

const Pane = struct {
    owner: *Window,
    token: ui.bridge.PaneToken,
    root: *gtk.Box,
    path_entry: *gtk.Entry,
    list: *gtk.ListBox,
    spinner: *gtk.Spinner,
    status: *gtk.Label,
    site_label: *gtk.Label,
    site_id: u64 = local_site_id,
    pending_request: ?ui.bridge.RequestId = null,
    snapshot: ?*DirSnapshot = null,
    sort_index: []u32 = &.{},

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
        const up = gtk.Button.newFromIconName("go-up-symbolic");
        const refresh = gtk.Button.newFromIconName("view-refresh-symbolic");
        const site_label = gtk.Label.new("Local");
        site_label.as(gtk.Widget).addCssClass("heading");
        const path_entry = gtk.Entry.new();
        path_entry.setPlaceholderText("Absolute path");
        path_entry.as(gtk.Widget).setHexpand(1);
        const spinner = gtk.Spinner.new();
        spinner.as(gtk.Widget).setVisible(0);
        toolbar.append(up.as(gtk.Widget));
        toolbar.append(refresh.as(gtk.Widget));
        toolbar.append(site_label.as(gtk.Widget));
        toolbar.append(path_entry.as(gtk.Widget));
        toolbar.append(spinner.as(gtk.Widget));

        const list = gtk.ListBox.new();
        list.setSelectionMode(.multiple);
        list.setShowSeparators(1);
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
            .list = list,
            .spinner = spinner,
            .status = status,
            .site_label = site_label,
        };

        _ = gtk.Button.signals.clicked.connect(up, *Pane, onUp, self, .{});
        _ = gtk.Button.signals.clicked.connect(refresh, *Pane, onRefresh, self, .{});
        _ = gtk.Entry.signals.activate.connect(path_entry, *Pane, onPathActivated, self, .{});
        _ = gtk.ListBox.signals.row_activated.connect(list, *Pane, onRowActivated, self, .{});
    }

    fn deinit(self: *Pane) void {
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        self.releaseSnapshot();
    }

    fn releaseSnapshot(self: *Pane) void {
        if (self.snapshot) |snapshot| snapshot.unref();
        self.snapshot = null;
        if (self.sort_index.len > 0) self.owner.gpa.free(self.sort_index);
        self.sort_index = &.{};
    }

    fn navigate(self: *Pane, path: []const u8) !void {
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        self.pending_request = try self.owner.core.listPath(self.token, self.site_id, path);
        self.setPath(path);
        self.spinner.as(gtk.Widget).setVisible(1);
        self.spinner.start();
        self.setStatus("Loading…", .{});
    }

    fn bindSite(self: *Pane, site_id: u64, label: []const u8, path: []const u8) !void {
        if (self.pending_request) |request| _ = self.owner.core.cancelListing(request);
        self.pending_request = null;
        self.releaseSnapshot();
        self.list.removeAll();
        self.site_id = site_id;
        const label_z = allocPrintZ(self.owner.gpa, "{s}", .{label}) catch null;
        if (label_z) |text| {
            defer self.owner.gpa.free(text);
            self.site_label.setText(text);
        }
        self.pending_request = if (site_id != local_site_id and path.len == 0)
            try self.owner.core.listDefaultPath(self.token, site_id)
        else
            try self.owner.core.listPath(self.token, site_id, path);
        self.setPath(if (path.len == 0) "…" else path);
        self.spinner.as(gtk.Widget).setVisible(1);
        self.spinner.start();
        self.setStatus("Connecting…", .{});
    }

    fn setPath(self: *Pane, path: []const u8) void {
        const path_z = allocPrintZ(self.owner.gpa, "{s}", .{path}) catch return;
        defer self.owner.gpa.free(path_z);
        self.path_entry.as(gtk.Editable).setText(path_z);
    }

    fn currentPath(self: *const Pane) []const u8 {
        if (self.snapshot) |snapshot| return snapshot.path;
        return std.mem.span(self.path_entry.as(gtk.Editable).getText());
    }

    fn replaceSnapshot(self: *Pane, incoming: *DirSnapshot, incoming_sort: []const u32) !void {
        const retained = incoming.ref();
        errdefer retained.unref();
        const order = try self.owner.gpa.dupe(u32, incoming_sort);
        errdefer self.owner.gpa.free(order);

        self.releaseSnapshot();
        self.snapshot = retained;
        self.sort_index = order;
        self.setPath(incoming.path);
        self.list.removeAll();

        const shown = @min(order.len, max_visible_rows);
        for (order[0..shown]) |entry_index| self.appendEntry(&incoming.entries[entry_index]);
        if (shown == incoming.entries.len) {
            self.setStatus("{d} item{s}", .{ shown, if (shown == 1) "" else "s" });
        } else {
            self.setStatus("Showing {d} of {d} items", .{ shown, incoming.entries.len });
        }
    }

    fn appendEntry(self: *Pane, entry: *const Entry) void {
        var size_buf: [32]u8 = undefined;
        const size = if (entry.kind == .dir)
            "Folder"
        else if (entry.size) |bytes|
            ui.inspector.formatBytes(bytes, &size_buf)
        else
            "—";
        const row_text = allocPrintZ(self.owner.gpa, "{s}\t{s}", .{ entry.name, size }) catch return;
        defer self.owner.gpa.free(row_text);
        const label = gtk.Label.new(row_text);
        label.setXalign(0);
        label.as(gtk.Widget).setHexpand(1);
        label.as(gtk.Widget).setMarginTop(7);
        label.as(gtk.Widget).setMarginBottom(7);
        label.as(gtk.Widget).setMarginStart(10);
        label.as(gtk.Widget).setMarginEnd(10);
        self.list.append(label.as(gtk.Widget));
    }

    fn setStatus(self: *Pane, comptime format: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const text = std.fmt.bufPrintZ(&buf, format, args) catch return;
        self.status.setText(text);
    }

    fn onUp(_: *gtk.Button, self: *Pane) callconv(.c) void {
        const path = self.currentPath();
        const parent = relay.vfs.path.parent(path) orelse return;
        self.navigate(parent) catch |err| self.setStatus("Cannot open parent: {s}", .{@errorName(err)});
    }

    fn onRefresh(_: *gtk.Button, self: *Pane) callconv(.c) void {
        self.navigate(self.currentPath()) catch |err| self.setStatus("Refresh failed: {s}", .{@errorName(err)});
    }

    fn onPathActivated(_: *gtk.Entry, self: *Pane) callconv(.c) void {
        const path = std.mem.span(self.path_entry.as(gtk.Editable).getText());
        self.navigate(path) catch |err| self.setStatus("Invalid path: {s}", .{@errorName(err)});
    }

    fn onRowActivated(_: *gtk.ListBox, row: *gtk.ListBoxRow, self: *Pane) callconv(.c) void {
        const snapshot = self.snapshot orelse return;
        const row_index = row.getIndex();
        if (row_index < 0 or @as(usize, @intCast(row_index)) >= self.sort_index.len) return;
        const entry = &snapshot.entries[self.sort_index[@intCast(row_index)]];
        if (entry.kind != .dir) return;
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
};

test {
    std.testing.refAllDecls(@This());
}

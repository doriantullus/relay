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

const app_id = "us.doriantull.relay";
const max_visible_rows = 2_000;

fn allocPrintZ(gpa: Allocator, comptime format: []const u8, args: anytype) error{OutOfMemory}![:0]u8 {
    const text = try std.fmt.allocPrint(gpa, format, args);
    defer gpa.free(text);
    return gpa.dupeZ(u8, text);
}

/// Run the GTK frontend until the last application window closes.
pub fn run(gpa: Allocator, core: *AppCore, init: std.process.Init.Minimal) !void {
    const gtk_app = gtk.Application.new(app_id, .{});
    defer gtk_app.unref();

    var app: Application = .{
        .gpa = gpa,
        .core = core,
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
    application: *Application,
    native: *gtk.ApplicationWindow,
    panes: [2]Pane = undefined,
    panes_initialized: usize = 0,
    listeners_registered: bool = false,

    fn create(application: *Application, app: *gtk.Application) !*Window {
        const gpa = application.gpa;
        const core = application.core;
        const self = try gpa.create(Window);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .application = application,
            .native = gtk.ApplicationWindow.new(app),
        };
        errdefer self.cleanup();

        const window = self.native.as(gtk.Window);
        window.setTitle("Relay");
        window.setDefaultSize(1180, 760);

        const header = gtk.HeaderBar.new();
        const title_box = gtk.Box.new(.vertical, 0);
        const title = gtk.Label.new("Relay");
        title.as(gtk.Widget).addCssClass("title");
        const site_status = try allocPrintZ(gpa, "Linux · {d} saved site{s}", .{
            core.site_list.sites.len,
            if (core.site_list.sites.len == 1) "" else "s",
        });
        defer gpa.free(site_status);
        const subtitle = gtk.Label.new(site_status);
        subtitle.as(gtk.Widget).addCssClass("dim-label");
        title_box.append(title.as(gtk.Widget));
        title_box.append(subtitle.as(gtk.Widget));
        header.setTitleWidget(title_box.as(gtk.Widget));
        window.setTitlebar(header.as(gtk.Widget));

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

        try core.registerListener(.listing_progress, self, onListingProgress);
        try core.registerListener(.listing_done, self, onListingDone);
        self.listeners_registered = true;

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
};

const Pane = struct {
    owner: *Window,
    token: ui.bridge.PaneToken,
    root: *gtk.Box,
    path_entry: *gtk.Entry,
    list: *gtk.ListBox,
    spinner: *gtk.Spinner,
    status: *gtk.Label,
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
        const path_entry = gtk.Entry.new();
        path_entry.setPlaceholderText("Absolute path");
        path_entry.as(gtk.Widget).setHexpand(1);
        const spinner = gtk.Spinner.new();
        spinner.as(gtk.Widget).setVisible(0);
        toolbar.append(up.as(gtk.Widget));
        toolbar.append(refresh.as(gtk.Widget));
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
        self.pending_request = try self.owner.core.listPath(self.token, relay.queue.item.local_site_id, path);
        self.setPath(path);
        self.spinner.as(gtk.Widget).setVisible(1);
        self.spinner.start();
        self.setStatus("Loading…", .{});
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

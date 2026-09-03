//! Linux implementations of Relay's opener, notification, watcher, and
//! terminal-launcher service seams.

const std = @import("std");
const gdk = @import("gdk");
const gio = @import("gio");
const glib = @import("glib");
const ui = @import("relay_ui");

const Allocator = std.mem.Allocator;
const interfaces = ui.platform.services;

pub const Services = struct {
    gpa: Allocator,
    application: *gio.Application,

    pub fn opener(self: *Services) interfaces.Opener {
        return .{ .context = self, .openPathFn = openPath, .openUriFn = openUri };
    }

    pub fn notifier(self: *Services) interfaces.Notifier {
        return .{ .context = self, .sendFn = notify };
    }

    pub fn terminal(self: *Services) interfaces.TerminalLauncher {
        return .{ .context = self, .launchFn = launchTerminal };
    }

    pub fn watcher(self: *Services) interfaces.Watcher {
        return .{ .context = self, .watchFn = watch };
    }

    pub fn copyText(_: *Services, text: []const u8) void {
        const display = gdk.Display.getDefault() orelse return;
        const clipboard = display.getClipboard();
        const text_z = std.heap.smp_allocator.dupeZ(u8, text) catch return;
        defer std.heap.smp_allocator.free(text_z);
        clipboard.setText(text_z);
    }

    pub fn launchNewInstance(_: *Services) interfaces.LaunchError!void {
        var argv = [_]?[*:0]const u8{ "/proc/self/exe", null };
        var glib_error: ?*glib.Error = null;
        const process = gio.Subprocess.newv(@ptrCast(&argv), .{}, &glib_error) orelse {
            if (glib_error) |value| value.free();
            return error.LaunchFailed;
        };
        process.unref();
    }

    fn openPath(raw: *anyopaque, path: []const u8) interfaces.OpenError!void {
        const self: *Services = @ptrCast(@alignCast(raw));
        const path_z = try self.gpa.dupeZ(u8, path);
        defer self.gpa.free(path_z);
        const file = gio.File.newForPath(path_z);
        defer file.unref();
        const uri = file.getUri();
        defer glib.free(uri);
        return openUri(self, std.mem.span(uri));
    }

    fn openUri(raw: *anyopaque, uri: []const u8) interfaces.OpenError!void {
        const self: *Services = @ptrCast(@alignCast(raw));
        if (uri.len == 0) return error.InvalidTarget;
        const uri_z = try self.gpa.dupeZ(u8, uri);
        defer self.gpa.free(uri_z);
        var glib_error: ?*glib.Error = null;
        if (gio.AppInfo.launchDefaultForUri(uri_z, null, &glib_error) == 0) {
            if (glib_error) |value| value.free();
            return error.LaunchFailed;
        }
    }

    fn notify(raw: *anyopaque, title: []const u8, body: []const u8) void {
        const self: *Services = @ptrCast(@alignCast(raw));
        const title_z = self.gpa.dupeZ(u8, title) catch return;
        defer self.gpa.free(title_z);
        const body_z = self.gpa.dupeZ(u8, body) catch return;
        defer self.gpa.free(body_z);
        const notification = gio.Notification.new(title_z);
        defer notification.unref();
        notification.setBody(body_z);
        notification.setCategory("transfer.complete");
        self.application.sendNotification(null, notification);
    }

    fn launchTerminal(raw: *anyopaque, command: []const []const u8) interfaces.LaunchError!void {
        const self: *Services = @ptrCast(@alignCast(raw));
        if (command.len == 0) return error.InvalidCommand;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var argv: std.ArrayList(?[*:0]const u8) = .empty;
        if (std.c.getenv("FLATPAK_ID") != null) {
            try argv.append(arena, (try arena.dupeZ(u8, "flatpak-spawn")).ptr);
            try argv.append(arena, (try arena.dupeZ(u8, "--host")).ptr);
        }
        const configured_terminal = terminalConfig();
        var words = std.mem.tokenizeAny(u8, configured_terminal, " \t");
        const executable = words.next() orelse return error.InvalidCommand;
        try argv.append(arena, (try arena.dupeZ(u8, executable)).ptr);
        while (words.next()) |word| try argv.append(arena, (try arena.dupeZ(u8, word)).ptr);
        const base = std.fs.path.basename(executable);
        if (std.mem.eql(u8, base, "gnome-terminal") or std.mem.eql(u8, base, "kgx") or
            std.mem.eql(u8, base, "wezterm"))
        {
            try argv.append(arena, (try arena.dupeZ(u8, "--")).ptr);
        } else {
            try argv.append(arena, (try arena.dupeZ(u8, "-e")).ptr);
        }
        for (command) |arg| try argv.append(arena, (try arena.dupeZ(u8, arg)).ptr);
        try argv.append(arena, null);

        var glib_error: ?*glib.Error = null;
        const process = gio.Subprocess.newv(@ptrCast(argv.items.ptr), .{}, &glib_error) orelse {
            if (glib_error) |value| value.free();
            return error.LaunchFailed;
        };
        process.unref();
    }

    fn terminalConfig() []const u8 {
        if (std.c.getenv("TERMINAL")) |value| {
            const configured = std.mem.trim(u8, std.mem.span(value), " \t\r\n");
            if (configured.len > 0) return configured;
        }
        return "x-terminal-emulator";
    }

    const Monitor = struct {
        gpa: Allocator,
        native: *gio.FileMonitor,
        callback: interfaces.WatchCallback,

        fn changed(
            _: *gio.FileMonitor,
            _: *gio.File,
            _: ?*gio.File,
            event: gio.FileMonitorEvent,
            self: *Monitor,
        ) callconv(.c) void {
            self.callback.notify(switch (event) {
                .created => .created,
                .deleted => .deleted,
                .renamed, .moved, .moved_in, .moved_out => .moved,
                else => .changed,
            });
        }

        fn destroy(raw: *anyopaque) void {
            const self: *Monitor = @ptrCast(@alignCast(raw));
            _ = self.native.cancel();
            self.native.unref();
            const gpa = self.gpa;
            gpa.destroy(self);
        }
    };

    fn watch(raw: *anyopaque, path: []const u8, callback: interfaces.WatchCallback) interfaces.WatchError!interfaces.WatchHandle {
        const self: *Services = @ptrCast(@alignCast(raw));
        const path_z = self.gpa.dupeZ(u8, path) catch return error.Unavailable;
        defer self.gpa.free(path_z);
        const file = gio.File.newForPath(path_z);
        defer file.unref();
        var glib_error: ?*glib.Error = null;
        const native = file.monitorFile(.{}, null, &glib_error) orelse {
            if (glib_error) |value| value.free();
            return error.Unavailable;
        };
        const monitor = self.gpa.create(Monitor) catch {
            native.unref();
            return error.Unavailable;
        };
        monitor.* = .{ .gpa = self.gpa, .native = native, .callback = callback };
        _ = gio.FileMonitor.signals.changed.connect(native, *Monitor, Monitor.changed, monitor, .{});
        return .{ .context = monitor, .destroyFn = Monitor.destroy };
    }
};

test {
    std.testing.refAllDecls(@This());
}

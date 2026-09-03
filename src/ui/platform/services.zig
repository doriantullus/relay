//! Small platform-service seams used by toolkit frontends.

pub const OpenError = error{ InvalidTarget, LaunchFailed, OutOfMemory };
pub const LaunchError = error{ InvalidCommand, LaunchFailed, OutOfMemory };
pub const WatchError = error{Unavailable};

pub const Opener = struct {
    context: *anyopaque,
    openPathFn: *const fn (*anyopaque, []const u8) OpenError!void,
    openUriFn: *const fn (*anyopaque, []const u8) OpenError!void,

    pub fn openPath(self: Opener, path: []const u8) OpenError!void {
        return self.openPathFn(self.context, path);
    }

    pub fn openUri(self: Opener, uri: []const u8) OpenError!void {
        return self.openUriFn(self.context, uri);
    }
};

pub const Notifier = struct {
    context: *anyopaque,
    sendFn: *const fn (*anyopaque, []const u8, []const u8) void,

    pub fn send(self: Notifier, title: []const u8, body: []const u8) void {
        self.sendFn(self.context, title, body);
    }
};

pub const TerminalLauncher = struct {
    context: *anyopaque,
    launchFn: *const fn (*anyopaque, []const []const u8) LaunchError!void,

    pub fn launch(self: TerminalLauncher, command: []const []const u8) LaunchError!void {
        return self.launchFn(self.context, command);
    }
};

pub const WatchEvent = enum { changed, created, deleted, moved };
pub const WatchCallback = struct {
    context: *anyopaque,
    notifyFn: *const fn (*anyopaque, WatchEvent) void,

    pub fn notify(self: WatchCallback, event: WatchEvent) void {
        self.notifyFn(self.context, event);
    }
};

pub const WatchHandle = struct {
    context: *anyopaque,
    destroyFn: *const fn (*anyopaque) void,

    pub fn destroy(self: WatchHandle) void {
        self.destroyFn(self.context);
    }
};

pub const Watcher = struct {
    context: *anyopaque,
    watchFn: *const fn (*anyopaque, []const u8, WatchCallback) WatchError!WatchHandle,

    pub fn watch(self: Watcher, path: []const u8, callback: WatchCallback) WatchError!WatchHandle {
        return self.watchFn(self.context, path, callback);
    }
};

test {
    @import("std").testing.refAllDecls(@This());
}

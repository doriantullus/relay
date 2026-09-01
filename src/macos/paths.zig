//! macOS implementation of relay_ui's application-path service.

const std = @import("std");
const ui = @import("relay_ui");

const Allocator = std.mem.Allocator;
const Paths = ui.platform.Paths;

pub const AppPaths = struct {
    app_id: []const u8,

    pub fn init(app_id: []const u8) AppPaths {
        return .{ .app_id = app_id };
    }

    pub fn service(self: *AppPaths) Paths {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    fn fromCtx(ctx: *anyopaque) *AppPaths {
        return @ptrCast(@alignCast(ctx));
    }

    fn home() Paths.Error![]const u8 {
        return if (std.c.getenv("HOME")) |value| std.mem.span(value) else error.NoHomeDirectory;
    }

    fn configDir(ctx: *anyopaque, gpa: Allocator) Paths.Error![]u8 {
        const self = fromCtx(ctx);
        return std.fmt.allocPrint(gpa, "{s}/Library/Application Support/{s}", .{
            try home(), self.app_id,
        }) catch error.OutOfMemory;
    }

    fn cacheDir(ctx: *anyopaque, gpa: Allocator, sub: []const u8) Paths.Error![]u8 {
        const self = fromCtx(ctx);
        return std.fmt.allocPrint(gpa, "{s}/Library/Caches/{s}/{s}", .{
            try home(), self.app_id, sub,
        }) catch error.OutOfMemory;
    }

    const vtable: Paths.VTable = .{
        .configDir = configDir,
        .cacheDir = cacheDir,
    };
};

test {
    std.testing.refAllDecls(AppPaths);
}

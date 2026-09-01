//! XDG implementation of relay_ui's application-path service.

const std = @import("std");
const ui = @import("relay_ui");

const Allocator = std.mem.Allocator;
const Paths = ui.platform.Paths;

pub const Environment = struct {
    xdg_config_home: ?[]const u8 = null,
    xdg_cache_home: ?[]const u8 = null,
    home: ?[]const u8 = null,
};

pub const AppPaths = struct {
    app_id: []const u8,
    environment: ?Environment = null,

    pub fn init(app_id: []const u8) AppPaths {
        return .{ .app_id = app_id };
    }

    pub fn initForTest(app_id: []const u8, environment: Environment) AppPaths {
        return .{ .app_id = app_id, .environment = environment };
    }

    pub fn service(self: *AppPaths) Paths {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    fn fromCtx(ctx: *anyopaque) *AppPaths {
        return @ptrCast(@alignCast(ctx));
    }

    fn envValue(self: *const AppPaths, comptime name: [:0]const u8) ?[]const u8 {
        if (self.environment) |environment| {
            if (comptime std.mem.eql(u8, name, "XDG_CONFIG_HOME"))
                return environment.xdg_config_home;
            if (comptime std.mem.eql(u8, name, "XDG_CACHE_HOME"))
                return environment.xdg_cache_home;
            if (comptime std.mem.eql(u8, name, "HOME")) return environment.home;
            @compileError("unsupported environment key");
        }
        const value = std.c.getenv(name) orelse return null;
        const slice = std.mem.span(value);
        return if (slice.len == 0) null else slice;
    }

    fn xdgBase(self: *const AppPaths, comptime name: [:0]const u8, fallback: []const u8) Paths.Error!struct {
        home: []const u8,
        suffix: []const u8,
    } {
        if (self.envValue(name)) |base| return .{ .home = base, .suffix = "" };
        return .{
            .home = self.envValue("HOME") orelse return error.NoHomeDirectory,
            .suffix = fallback,
        };
    }

    fn configDir(ctx: *anyopaque, gpa: Allocator) Paths.Error![]u8 {
        const self = fromCtx(ctx);
        const base = try self.xdgBase("XDG_CONFIG_HOME", "/.config");
        return std.fmt.allocPrint(gpa, "{s}{s}/{s}", .{ base.home, base.suffix, self.app_id }) catch
            error.OutOfMemory;
    }

    fn cacheDir(ctx: *anyopaque, gpa: Allocator, sub: []const u8) Paths.Error![]u8 {
        const self = fromCtx(ctx);
        const base = try self.xdgBase("XDG_CACHE_HOME", "/.cache");
        return std.fmt.allocPrint(gpa, "{s}{s}/{s}/{s}", .{
            base.home,
            base.suffix,
            self.app_id,
            sub,
        }) catch error.OutOfMemory;
    }

    const vtable: Paths.VTable = .{
        .configDir = configDir,
        .cacheDir = cacheDir,
    };
};

test "XDG values win; HOME fallbacks match the freedesktop defaults" {
    const gpa = std.testing.allocator;
    var xdg = AppPaths.initForTest("relay", .{
        .xdg_config_home = "/config",
        .xdg_cache_home = "/cache",
        .home = "/home/user",
    });
    const config = try xdg.service().configDir(gpa);
    defer gpa.free(config);
    try std.testing.expectEqualStrings("/config/relay", config);
    const cache = try xdg.service().cacheDir(gpa, "preview");
    defer gpa.free(cache);
    try std.testing.expectEqualStrings("/cache/relay/preview", cache);

    var fallback = AppPaths.initForTest("relay", .{ .home = "/home/user" });
    const fallback_config = try fallback.service().configDir(gpa);
    defer gpa.free(fallback_config);
    try std.testing.expectEqualStrings("/home/user/.config/relay", fallback_config);
    const fallback_cache = try fallback.service().cacheDir(gpa, "edit");
    defer gpa.free(fallback_cache);
    try std.testing.expectEqualStrings("/home/user/.cache/relay/edit", fallback_cache);
}

test {
    std.testing.refAllDecls(AppPaths);
}

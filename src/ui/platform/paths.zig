//! Platform-owned application paths. The shared UI layer asks for logical
//! locations and never encodes a toolkit or operating-system directory.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Paths = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const Error = error{ OutOfMemory, NoHomeDirectory, NameTooLong };

    pub const VTable = struct {
        /// Durable app data. Caller owns the returned path.
        /// macOS: ~/Library/Application Support/<bundle_id>
        /// Linux: $XDG_CONFIG_HOME/<app_id> (default ~/.config/<app_id>)
        configDir: *const fn (ctx: *anyopaque, gpa: Allocator) Error![]u8,

        /// Discardable data, with `sub` appended (for example "preview").
        /// macOS: ~/Library/Caches/<bundle_id>/<sub>
        /// Linux: $XDG_CACHE_HOME/<app_id>/<sub> (default ~/.cache/...)
        cacheDir: *const fn (ctx: *anyopaque, gpa: Allocator, sub: []const u8) Error![]u8,
    };

    pub fn configDir(self: Paths, gpa: Allocator) Error![]u8 {
        return self.vtable.configDir(self.ctx, gpa);
    }

    pub fn cacheDir(self: Paths, gpa: Allocator, sub: []const u8) Error![]u8 {
        return self.vtable.cacheDir(self.ctx, gpa, sub);
    }
};

test {
    std.testing.refAllDecls(Paths);
}

//! Toolkit-free edit-session path and conflict logic.

const std = @import("std");
const relay = @import("relay_core");
const Paths = @import("platform/paths.zig").Paths;

const Allocator = std.mem.Allocator;
const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;

pub const SaveDecision = enum { upload, conflict };

pub fn decideOnSave(recorded_mtime: ?i64, restat_mtime: ?i64) SaveDecision {
    const recorded = recorded_mtime orelse return .upload;
    const current = restat_mtime orelse return .upload;
    return if (recorded == current) .upload else .conflict;
}

pub fn entryMtime(entries: []const vfs_mod.Entry, name: []const u8) ?i64 {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.mtime;
    }
    return null;
}

pub fn defaultCacheBase(gpa: Allocator, paths: Paths) Paths.Error![]u8 {
    return paths.cacheDir(gpa, "edit");
}

pub fn sessionDir(gpa: Allocator, base: []const u8, session_id: u64) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{d}", .{ base, session_id });
}

pub fn duplicateName(gpa: Allocator, name: []const u8) error{OutOfMemory}![]u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.');
    if (dot == null or dot.? == 0) {
        return std.fmt.allocPrint(gpa, "{s} copy", .{name});
    }
    return std.fmt.allocPrint(gpa, "{s} copy{s}", .{ name[0..dot.?], name[dot.?..] });
}

pub fn relFromVfs(path: []const u8) []const u8 {
    std.debug.assert(path_mod.isNormalized(path));
    return if (path.len == 1) "." else path[1..];
}

test "conflict rule and entry mtime lookup" {
    try std.testing.expectEqual(SaveDecision.upload, decideOnSave(null, 1));
    try std.testing.expectEqual(SaveDecision.upload, decideOnSave(1, 1));
    try std.testing.expectEqual(SaveDecision.conflict, decideOnSave(1, 2));
    const entries = [_]vfs_mod.Entry{
        .{ .name = "a", .kind = .file, .mtime = 10 },
        .{ .name = "b", .kind = .file, .mtime = null },
    };
    try std.testing.expectEqual(@as(?i64, 10), entryMtime(&entries, "a"));
    try std.testing.expectEqual(@as(?i64, null), entryMtime(&entries, "b"));
}

test "session and duplicate paths" {
    const gpa = std.testing.allocator;
    const dir = try sessionDir(gpa, "/cache/edit", 7);
    defer gpa.free(dir);
    try std.testing.expectEqualStrings("/cache/edit/7", dir);
    try std.testing.expectEqualStrings("cache/edit/7", relFromVfs(dir));
    const duplicate = try duplicateName(gpa, "notes.txt");
    defer gpa.free(duplicate);
    try std.testing.expectEqualStrings("notes copy.txt", duplicate);
}

test {
    std.testing.refAllDecls(@This());
}

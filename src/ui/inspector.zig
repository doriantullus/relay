//! Toolkit-free selection and permission model for the inspector.

const std = @import("std");
const bridge = @import("bridge.zig");

pub const ItemKind = enum {
    file,
    dir,
    symlink,
    other,

    pub fn label(self: ItemKind) [:0]const u8 {
        return switch (self) {
            .file => "File",
            .dir => "Folder",
            .symlink => "Symlink",
            .other => "Item",
        };
    }
};

pub const SelectedItem = struct {
    name: []const u8,
    path: []const u8,
    kind: ItemKind = .file,
    size: ?u64 = null,
    mode: ?u16 = null,
};

pub const Selection = struct {
    pane_token: bridge.PaneToken = 0,
    site_id: u64 = 0,
    items: []const SelectedItem = &.{},
};

pub const ChmodStageHook = struct {
    ctx: ?*anyopaque = null,
    stage: ?*const fn (
        ctx: ?*anyopaque,
        pane_token: bridge.PaneToken,
        path: []const u8,
        mode: u16,
    ) void = null,
};

/// Checkbox order: owner r,w,x · group r,w,x · others r,w,x.
pub fn rwxFromMode(mode: u16) [9]bool {
    var flags: [9]bool = undefined;
    for (&flags, 0..) |*flag, i| {
        const bit: u4 = @intCast(8 - i);
        flag.* = (mode >> bit) & 1 == 1;
    }
    return flags;
}

pub fn modeFromRwx(flags: [9]bool) u16 {
    var mode: u16 = 0;
    for (flags, 0..) |flag, i| {
        if (flag) mode |= @as(u16, 1) << @intCast(8 - i);
    }
    return mode;
}

pub fn modeFromOctalText(text: []const u8) ?u16 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > 4) return null;
    var value: u32 = 0;
    for (trimmed) |ch| {
        if (ch < '0' or ch > '7') return null;
        value = value * 8 + (ch - '0');
    }
    if (value > 0o777) return null;
    return @intCast(value);
}

pub fn octalTextFromMode(mode: u16, buf: *[3]u8) []const u8 {
    buf[0] = '0' + @as(u8, @intCast((mode >> 6) & 7));
    buf[1] = '0' + @as(u8, @intCast((mode >> 3) & 7));
    buf[2] = '0' + @as(u8, @intCast(mode & 7));
    return buf[0..];
}

pub fn sizeSum(items: []const SelectedItem) u64 {
    var total: u64 = 0;
    for (items) |item| total +|= item.size orelse 0;
    return total;
}

pub fn formatBytes(bytes: u64, buf: []u8) []const u8 {
    if (bytes < 1024) return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "?";
    const units = [_][]const u8{ "KB", "MB", "GB", "TB" };
    var value: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    value /= 1024;
    while (value >= 1024 and unit < units.len - 1) : (unit += 1) value /= 1024;
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "?";
}

test "permission model round-trips every supported mode" {
    for (0..0o1000) |raw| {
        const mode: u16 = @intCast(raw);
        try std.testing.expectEqual(mode, modeFromRwx(rwxFromMode(mode)));
    }
}

test "octal parsing, size summing, and formatting" {
    try std.testing.expectEqual(@as(?u16, 0o644), modeFromOctalText(" 0644 "));
    try std.testing.expectEqual(@as(?u16, null), modeFromOctalText("1777"));
    var octal: [3]u8 = undefined;
    try std.testing.expectEqualStrings("755", octalTextFromMode(0o755, &octal));
    const items = [_]SelectedItem{ .{ .name = "a", .path = "/a", .size = 512 }, .{
        .name = "b",
        .path = "/b",
        .size = 1024,
    } };
    try std.testing.expectEqual(@as(u64, 1536), sizeSum(&items));
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.5 KB", formatBytes(1536, &buf));
}

test {
    std.testing.refAllDecls(@This());
}

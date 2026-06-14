//! Small, pure, headless-tested formatting helpers shared across the app's
//! controllers (no ObjC). Kept here so browser/transfers/etc. share one
//! implementation instead of each carrying a copy.

const std = @import("std");

/// "532 B", "1.5 KB", "2.4 MB" — one decimal below 10 units, whole above.
/// Writes into `buf`; returns the formatted slice (empty on buffer overflow).
pub fn humanBytes(buf: []u8, bytes: u64) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB", "PB" };
    if (bytes < 1024) return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "";
    var value: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    while (value >= 1024 and unit + 1 < units.len) : (unit += 1) value /= 1024;
    if (value < 10)
        return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "";
    return std.fmt.bufPrint(buf, "{d:.0} {s}", .{ value, units[unit] }) catch "";
}

test "humanBytes formatting" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("0 B", humanBytes(&buf, 0));
    try std.testing.expectEqualStrings("532 B", humanBytes(&buf, 532));
    try std.testing.expectEqualStrings("1023 B", humanBytes(&buf, 1023));
    try std.testing.expectEqualStrings("1.5 KB", humanBytes(&buf, 1536));
    try std.testing.expectEqualStrings("250 KB", humanBytes(&buf, 256_000));
    try std.testing.expectEqualStrings("1.0 MB", humanBytes(&buf, 1 << 20));
    try std.testing.expectEqualStrings("2.4 MB", humanBytes(&buf, 2_516_582));
    try std.testing.expectEqualStrings("5.0 MB", humanBytes(&buf, 5 * 1024 * 1024));
    try std.testing.expectEqualStrings("10 MB", humanBytes(&buf, 10 << 20));
    try std.testing.expectEqualStrings("3.0 GB", humanBytes(&buf, 3 * 1024 * 1024 * 1024));
}

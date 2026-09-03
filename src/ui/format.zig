//! Small, pure, headless-tested formatting helpers shared across both apps'
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

/// ISO 8601 UTC to the minute for file-list modified columns.
pub fn mtimeIso(buf: []u8, mtime: ?i64) []const u8 {
    const value = mtime orelse return "";
    if (value < 0) return "";
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(value) };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
    }) catch buf[0..0];
}

pub fn mtimeRelative(buf: []u8, mtime: ?i64, now: i64) []const u8 {
    const value = mtime orelse return "";
    const elapsed = @max(@as(i64, 0), now - value);
    if (elapsed < 60) return std.fmt.bufPrint(buf, "just now", .{}) catch "";
    if (elapsed < 3_600) return std.fmt.bufPrint(buf, "{d} min ago", .{elapsed / 60}) catch "";
    if (elapsed < 86_400) return std.fmt.bufPrint(buf, "{d} hr ago", .{elapsed / 3_600}) catch "";
    if (elapsed < 604_800) return std.fmt.bufPrint(buf, "{d} days ago", .{elapsed / 86_400}) catch "";
    return mtimeIso(buf, mtime);
}

test "mtimeIso formats UTC timestamps" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2024-01-01 00:00", mtimeIso(&buf, 1_704_067_200));
    try std.testing.expectEqualStrings("", mtimeIso(&buf, null));
}

test "mtimeRelative uses readable recent units" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("just now", mtimeRelative(&buf, 990, 1_000));
    try std.testing.expectEqualStrings("5 min ago", mtimeRelative(&buf, 700, 1_000));
    try std.testing.expectEqualStrings("2 hr ago", mtimeRelative(&buf, 1_000, 8_200));
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

//! settings — typed app configuration ↔ ZON on disk. Sites live in
//! sites.zig; secrets live only in cred/ (never in any config file).
//!
//! Persistence is crash-safe: `atomicWriteFile` writes a unique temp file
//! in the same directory, fsyncs, then renames over the target — a reader
//! sees either the old or the new file, never a torn one.
//!
//! These are local-disk config helpers, not protocol calls, so they take no
//! CancelToken/Diagnostics; errors stay typed Zig errors.

const std = @import("std");

pub const Settings = struct {
    /// Bump on incompatible layout changes; `parse` rejects unknown fields
    /// so older binaries fail loudly rather than silently dropping data.
    schema_version: u32 = 1,
    show_hidden_files: bool = false,
    verbose_transcript: bool = false,
    /// Concurrent connections per site (UI clamps to 1..8).
    connections_per_site: u8 = 3,
    connect_timeout_ms: u32 = 15_000,
    keepalive_interval_s: u32 = 60,
    /// Global transfer rate caps in bytes/second; 0 = unlimited.
    rate_limit_down: u64 = 0,
    rate_limit_up: u64 = 0,
};

pub const ParseError = error{ OutOfMemory, ParseZon };

/// `Settings` holds no pointers, so the result needs no freeing; `gpa` is
/// only used for the parser's temporaries.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) ParseError!Settings {
    // A Diagnostics must be passed and freed: with `null`, std.zon leaks
    // the rendered message on "unexpected field" errors (0.16).
    var zon_diag: std.zon.parse.Diagnostics = .{};
    defer zon_diag.deinit(gpa);
    return std.zon.parse.fromSlice(Settings, gpa, source, &zon_diag, .{});
}

pub fn serialize(settings: Settings, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try std.zon.stringify.serialize(settings, .{}, writer);
    try writer.writeByte('\n');
}

/// Config files bigger than this are corrupt by definition.
pub const max_file_bytes = 1 << 20;

pub fn load(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) !Settings {
    const source = try readFileZ(io, dir, sub_path, gpa);
    defer gpa.free(source);
    return parse(gpa, source);
}

pub fn save(
    settings: Settings,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // The Allocating writer only fails on OOM.
    serialize(settings, &out.writer) catch return error.OutOfMemory;
    try atomicWriteFile(io, dir, sub_path, out.written());
}

/// Reads `sub_path` (≤ `max_file_bytes`) into a NUL-terminated buffer for
/// the ZON parser. Shared with sites.zig.
pub fn readFileZ(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) ![:0]u8 {
    var file = try dir.openFile(io, sub_path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;
    if (size > max_file_bytes) return error.FileTooBig;
    const buf = try gpa.allocSentinel(u8, @intCast(size), 0);
    errdefer gpa.free(buf);
    var reader = file.reader(io, &.{});
    reader.interface.readSliceAll(buf) catch return error.InputOutput;
    return buf;
}

/// Crash-safe replace of `dir/sub_path` with `bytes`: write a uniquely
/// named temp file in the same directory (rename is only atomic within a
/// filesystem), fsync, rename over the target. The temp file is removed on
/// any failure.
pub fn atomicWriteFile(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    bytes: []const u8,
) !void {
    var name_buf: [1024]u8 = undefined;
    // Random suffix: a concurrent writer (or a leftover from a crash) must
    // never be overwritten mid-write; `exclusive` makes a collision an error
    // instead of a corruption.
    var suffix: [8]u8 = undefined;
    io.random(&suffix);
    const tmp_name = std.fmt.bufPrint(&name_buf, "{s}.tmp-{x}", .{
        sub_path, @as(u64, @bitCast(suffix)),
    }) catch return error.NameTooLong;

    var file = try dir.createFile(io, tmp_name, .{ .exclusive = true });
    var tmp_exists = true;
    defer if (tmp_exists) dir.deleteFile(io, tmp_name) catch {};
    {
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    try dir.rename(tmp_name, dir, sub_path, io);
    tmp_exists = false;
}

test "settings: zon round trip preserves every field" {
    const original: Settings = .{
        .show_hidden_files = true,
        .connections_per_site = 5,
        .connect_timeout_ms = 9_000,
        .rate_limit_up = 1_000_000,
    };
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(original, &out.writer);

    const source = try std.testing.allocator.dupeZ(u8, out.written());
    defer std.testing.allocator.free(source);
    const parsed = try parse(std.testing.allocator, source);
    try std.testing.expectEqualDeep(original, parsed);
}

test "settings: empty zon yields defaults" {
    const parsed = try parse(std.testing.allocator, ".{}");
    try std.testing.expectEqualDeep(Settings{}, parsed);
}

test "settings: corrupt input is a graceful error, never a crash" {
    const corrupt_inputs = [_][:0]const u8{
        "garbage{{{",
        ".{ .schema_version = \"not an int\" }",
        ".{ .unknown_field = 1 }",
        ".{ .connections_per_site = 99999 }", // u8 overflow
        "", // empty file
        ".{ .show_hidden_files = .blue }",
    };
    for (corrupt_inputs) |source| {
        try std.testing.expectError(error.ParseZon, parse(std.testing.allocator, source));
    }
}

fn parseCycle(gpa: std.mem.Allocator, source: [:0]const u8) !void {
    _ = try parse(gpa, source);
}

test "settings: parser survives allocation failure at every point" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseCycle, .{
        @as([:0]const u8, ".{ .schema_version = 1, .verbose_transcript = true }"),
    });
}

test "settings: save is atomic and load round-trips" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Pre-existing file gets replaced, not appended or torn.
    try tmp.dir.writeFile(io, .{ .sub_path = "settings.zon", .data = "not zon at all" });

    const settings: Settings = .{ .verbose_transcript = true, .keepalive_interval_s = 30 };
    try save(settings, io, tmp.dir, "settings.zon", std.testing.allocator);

    const loaded = try load(io, tmp.dir, "settings.zon", std.testing.allocator);
    try std.testing.expectEqualDeep(settings, loaded);

    // No temp files left behind.
    var it = tmp.dir.iterate();
    var file_count: usize = 0;
    while (try it.next(io)) |entry| {
        try std.testing.expectEqualStrings("settings.zon", entry.name);
        file_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), file_count);
}

test "settings: load of missing or corrupt file errors gracefully" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(
        error.FileNotFound,
        load(io, tmp.dir, "nope.zon", std.testing.allocator),
    );

    try tmp.dir.writeFile(io, .{ .sub_path = "bad.zon", .data = "}{ totally corrupt \x00\xff" });
    try std.testing.expectError(
        error.ParseZon,
        load(io, tmp.dir, "bad.zon", std.testing.allocator),
    );
}

test {
    std.testing.refAllDecls(@This());
}

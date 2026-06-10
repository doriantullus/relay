//! sites — the site list (bookmarks) ↔ ZON on disk.
//!
//! SECURITY INVARIANT: sites carry NO secrets. A site stores the account
//! *name* only; the password/passphrase lives in the CredStore keyed by
//! (protocol, host, port, account) — see ../cred/store.zig. Nothing in
//! `Site` may ever hold credential material, because this file is written
//! to disk in plaintext.

const std = @import("std");
const settings = @import("settings.zig");

pub const Protocol = enum { ftp, ftps, sftp };

pub fn defaultPort(protocol: Protocol) u16 {
    return switch (protocol) {
        .ftp => 21,
        .ftps => 990,
        .sftp => 22,
    };
}

pub const Site = struct {
    /// Stable id; referenced by queue persistence and UI state. Assigned
    /// once at creation, never reused.
    id: u64,
    name: []const u8 = "",
    protocol: Protocol = .ftp,
    host: []const u8,
    /// 0 = protocol default (see `defaultPort`).
    port: u16 = 0,
    /// Login name only — the credential key, never the credential.
    account: []const u8 = "",
    initial_remote_path: []const u8 = "",
    initial_local_path: []const u8 = "",
    /// Per-site TLS escape hatch; the UI makes this loud.
    insecure_skip_verify: bool = false,

    pub fn effectivePort(site: Site) u16 {
        return if (site.port != 0) site.port else defaultPort(site.protocol);
    }
};

pub const SiteList = struct {
    schema_version: u32 = 1,
    sites: []const Site = &.{},
};

/// Parse result; all `SiteList` slices are owned by one arena (frees as a
/// single `deinit`, per the arena-per-result rule).
pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    value: SiteList,

    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const ParseError = error{ OutOfMemory, ParseZon };

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) ParseError!Parsed {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    // free_on_error off: the arena reclaims partial results wholesale.
    const value = try std.zon.parse.fromSliceAlloc(SiteList, arena.allocator(), source, null, .{
        .free_on_error = false,
    });
    return .{ .arena = arena, .value = value };
}

pub fn serialize(list: SiteList, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try std.zon.stringify.serialize(list, .{}, writer);
    try writer.writeByte('\n');
}

pub fn load(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) !Parsed {
    const source = try settings.readFileZ(io, dir, sub_path, gpa);
    defer gpa.free(source);
    return parse(gpa, source);
}

/// Atomic (temp file + rename); see settings.atomicWriteFile.
pub fn save(
    list: SiteList,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // The Allocating writer only fails on OOM.
    serialize(list, &out.writer) catch return error.OutOfMemory;
    try settings.atomicWriteFile(io, dir, sub_path, out.written());
}

const test_list: SiteList = .{
    .sites = &.{
        .{
            .id = 1,
            .name = "prod web",
            .protocol = .sftp,
            .host = "web1.example.com",
            .port = 2222,
            .account = "deploy",
            .initial_remote_path = "/var/www",
        },
        .{
            .id = 2,
            .protocol = .ftps,
            .host = "ftp.example.org",
            .account = "anonymous",
        },
    },
};

test "sites: zon round trip preserves the list" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(test_list, &out.writer);

    const source = try std.testing.allocator.dupeZ(u8, out.written());
    defer std.testing.allocator.free(source);
    var parsed = try parse(std.testing.allocator, source);
    defer parsed.deinit();
    try std.testing.expectEqualDeep(test_list, parsed.value);
}

test "sites: effective port falls back to protocol default" {
    try std.testing.expectEqual(@as(u16, 2222), test_list.sites[0].effectivePort());
    try std.testing.expectEqual(@as(u16, 990), test_list.sites[1].effectivePort());
    try std.testing.expectEqual(@as(u16, 21), defaultPort(.ftp));
    try std.testing.expectEqual(@as(u16, 22), defaultPort(.sftp));
}

test "sites: corrupt input is a graceful error, never a crash" {
    const corrupt_inputs = [_][:0]const u8{
        "garbage{{{",
        ".{ .sites = 42 }",
        ".{ .sites = .{ .{ .id = 1 } } }", // missing required host
        ".{ .sites = .{ .{ .id = \"one\", .host = \"h\" } } }", // id type mismatch
        ".{ .sites = .{ .{ .id = 1, .host = \"h\", .protocol = .gopher } } }",
        ".{ .bogus = true }",
        "",
    };
    for (corrupt_inputs) |source| {
        try std.testing.expectError(error.ParseZon, parse(std.testing.allocator, source));
    }
}

fn parseCycle(gpa: std.mem.Allocator, source: [:0]const u8) !void {
    var parsed = try parse(gpa, source);
    defer parsed.deinit();
    if (parsed.value.sites.len != 2) return error.TestUnexpectedResult;
}

test "sites: parser survives allocation failure at every point" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(test_list, &out.writer);
    const source = try std.testing.allocator.dupeZ(u8, out.written());
    defer std.testing.allocator.free(source);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseCycle, .{
        @as([:0]const u8, source),
    });
}

test "sites: atomic save + load round-trips on disk" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "sites.zon", .data = "stale and corrupt" });
    try save(test_list, io, tmp.dir, "sites.zon", std.testing.allocator);

    var loaded = try load(io, tmp.dir, "sites.zon", std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expectEqualDeep(test_list, loaded.value);

    // The serialized form must never contain a secret-looking field: the
    // whole point of the cred split. Belt and braces for refactors.
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(test_list, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "password") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "secret") == null);

    var it = tmp.dir.iterate();
    var file_count: usize = 0;
    while (try it.next(io)) |entry| {
        try std.testing.expectEqualStrings("sites.zon", entry.name);
        file_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), file_count);
}

test {
    std.testing.refAllDecls(@This());
}

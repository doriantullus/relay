//! listing_mlsd — MLSD/MLST fact parser (RFC 3659) producing `vfs.Entry`.
//!
//! Entry lines are `[facts] SP pathname`; each fact is `name=value;`.
//! Fact names (and `type` values) are case-insensitive. Unknown facts are
//! skipped. `type=cdir`/`type=pdir` entries — and literal "." / ".."
//! pathnames — are filtered out (the VFS lists directory *contents*).
//!
//! `modify` is authoritative server UTC per RFC 3659 ("time-val =
//! 14DIGIT [ . 1*DIGIT ]"); fractional seconds are truncated. The civil
//! time <-> epoch conversion below is first-party (proleptic Gregorian,
//! Howard Hinnant's algorithms) — no libc, no timezone database.
//!
//! Callers feeding MLST control-channel replies must strip the mandated
//! leading space first; an MLSD line *starting* with a space is treated per
//! RFC as an entry with no facts.

const std = @import("std");
const CancelToken = @import("../../cancel.zig").CancelToken;
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const vfs = @import("../../vfs/vfs.zig");

pub const Error = error{
    Canceled,
    /// Data connection dropped (read failure mid-listing).
    ConnectionLost,
    /// A listing line exceeded the reader's buffer capacity (DoS guard).
    ProtocolViolation,
    OutOfMemory,
};

/// Parses one MLSD entry line (no trailing CR/LF required; one trailing CR
/// is tolerated). Returns null for empty/filtered/malformed lines —
/// listings keep streaming past junk. All slices in the result are arena
/// copies.
pub fn parseLine(arena: std.mem.Allocator, line_in: []const u8) error{OutOfMemory}!?vfs.Entry {
    var line = line_in;
    if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
    if (line.len == 0) return null;

    const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return null; // no pathname
    const facts = line[0..sp];
    const name = line[sp + 1 ..];
    if (name.len == 0) return null;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return null;

    var entry: vfs.Entry = .{ .name = undefined };
    var link_target: ?[]const u8 = null;
    var perm_fact: ?[]const u8 = null;
    // unix.ownername > unix.owner > unix.uid (and the group equivalents);
    // ProFTPD sends the numeric id in UNIX.owner and the name in
    // UNIX.ownername.
    var owner_prio: u8 = 0;
    var owner: ?[]const u8 = null;
    var group_prio: u8 = 0;
    var group: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, facts, ';');
    while (it.next()) |fact| {
        if (fact.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, fact, '=') orelse continue;
        const fname = fact[0..eq];
        const fval = fact[eq + 1 ..];
        if (eqlNoCase(fname, "type")) {
            if (eqlNoCase(fval, "file")) {
                entry.kind = .file;
            } else if (eqlNoCase(fval, "dir")) {
                entry.kind = .dir;
            } else if (eqlNoCase(fval, "cdir") or eqlNoCase(fval, "pdir")) {
                return null; // current/parent directory: filtered
            } else if (std.ascii.startsWithIgnoreCase(fval, "os.unix=slink:")) {
                entry.kind = .symlink;
                const target = fval["os.unix=slink:".len..];
                if (target.len != 0) link_target = target;
            } else if (std.ascii.startsWithIgnoreCase(fval, "os.unix=symlink")) {
                entry.kind = .symlink;
            } else {
                entry.kind = .unknown;
            }
        } else if (eqlNoCase(fname, "size")) {
            entry.size = std.fmt.parseInt(u64, fval, 10) catch null;
        } else if (eqlNoCase(fname, "modify")) {
            entry.mtime = parseTimeVal(fval);
        } else if (eqlNoCase(fname, "perm")) {
            perm_fact = fval;
        } else if (eqlNoCase(fname, "unix.mode")) {
            const mode = std.fmt.parseInt(u32, fval, 8) catch continue;
            entry.mode = @intCast(mode & 0o7777);
        } else if (eqlNoCase(fname, "unix.ownername")) {
            if (owner_prio < 3) {
                owner = fval;
                owner_prio = 3;
            }
        } else if (eqlNoCase(fname, "unix.owner")) {
            if (owner_prio < 2) {
                owner = fval;
                owner_prio = 2;
            }
        } else if (eqlNoCase(fname, "unix.uid")) {
            if (owner_prio < 1) {
                owner = fval;
                owner_prio = 1;
            }
        } else if (eqlNoCase(fname, "unix.groupname")) {
            if (group_prio < 3) {
                group = fval;
                group_prio = 3;
            }
        } else if (eqlNoCase(fname, "unix.group")) {
            if (group_prio < 2) {
                group = fval;
                group_prio = 2;
            }
        } else if (eqlNoCase(fname, "unix.gid")) {
            if (group_prio < 1) {
                group = fval;
                group_prio = 1;
            }
        } else if (eqlNoCase(fname, "unique")) {
            // Recognized but unused: would only matter for cycle detection.
        } else {
            // Unknown fact: tolerated per RFC 3659.
        }
    }

    if (entry.kind == .unknown) {
        if (perm_fact) |perm| entry.kind = kindFromPerm(perm);
    }

    entry.name = try arena.dupe(u8, name);
    if (owner) |o| entry.owner = try arena.dupe(u8, o);
    if (group) |g| entry.group = try arena.dupe(u8, g);
    if (link_target) |t| entry.link_target = try arena.dupe(u8, t);
    return entry;
}

/// Parses a whole MLSD stream. Lines that don't parse are skipped; only
/// transport-level failures error. The result slice and all entry strings
/// are arena-owned.
pub fn parseAll(
    arena: std.mem.Allocator,
    r: *std.Io.Reader,
    cancel: *CancelToken,
    diag: *Diagnostics,
) Error![]vfs.Entry {
    var entries: std.ArrayList(vfs.Entry) = .empty;
    while (true) {
        cancel.check() catch |err| {
            diag.set(.cancel, 0, "canceled while parsing listing", .{});
            return err;
        };
        const line = r.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => {
                diag.set(.transient, 0, "data connection lost mid-listing", .{});
                return error.ConnectionLost;
            },
            error.StreamTooLong => {
                diag.set(.permanent, 0, "listing line exceeds buffer capacity", .{});
                return error.ProtocolViolation;
            },
        };
        if (try parseLine(arena, line)) |entry| try entries.append(arena, entry);
        const buffered = r.buffered();
        if (buffered.len != 0 and buffered[0] == '\n') r.toss(1);
    }
    return entries.items;
}

/// RFC 3659 time-val: YYYYMMDDHHMMSS with optional ".frac" (truncated).
/// Returns null on any malformed or out-of-range field.
fn parseTimeVal(val: []const u8) ?i64 {
    const core = if (std.mem.indexOfScalar(u8, val, '.')) |dot| val[0..dot] else val;
    if (core.len != 14) return null;
    for (core) |c| if (!std.ascii.isDigit(c)) return null;
    const year = digits(i64, core[0..4]);
    const month: u8 = @intCast(digits(u16, core[4..6]));
    const day: u8 = @intCast(digits(u16, core[6..8]));
    const hour = digits(u32, core[8..10]);
    const minute = digits(u32, core[10..12]);
    const second = digits(u32, core[12..14]);
    if (month < 1 or month > 12) return null;
    if (day < 1 or day > daysInMonth(year, month)) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;
    return epochFromCivil(year, month, day, hour, minute, second);
}

fn digits(comptime T: type, s: []const u8) T {
    var v: T = 0;
    for (s) |c| v = v * 10 + (c - '0');
    return v;
}

fn eqlNoCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Fallback kind inference from the RFC 3659 `perm` fact when `type` is
/// absent: 'e' (CWD) / 'l' (LIST) only apply to directories; 'r' (RETR),
/// 'w' (STOR) and 'a' (APPE) only to files.
fn kindFromPerm(perm: []const u8) vfs.EntryKind {
    for (perm) |c| switch (std.ascii.toLower(c)) {
        'e', 'l' => return .dir,
        else => {},
    };
    for (perm) |c| switch (std.ascii.toLower(c)) {
        'r', 'w', 'a' => return .file,
        else => {},
    };
    return .unknown;
}

// ---------------------------------------------------------------------------
// Civil time <-> epoch (proleptic Gregorian, UTC, no libc).
// Algorithms: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".
// Shared with listing_list.zig (LIST date columns) and usable for MDTM.
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 of the given civil date. Total for month 1-12 and
/// day 1-31; out-of-range days simply overflow into the next month.
pub fn daysFromCivil(year: i64, month: u8, day: u8) i64 {
    const y: i64 = if (month <= 2) year - 1 else year;
    const era: i64 = @divFloor(y, 400);
    const yoe: u64 = @intCast(y - era * 400); // [0, 399]
    const mp: u64 = @mod(@as(u64, month) + 9, 12); // March-first month [0, 11]
    const doy: u64 = (153 * mp + 2) / 5 + day - 1;
    const doe: u64 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + @as(i64, @intCast(doe)) - 719468;
}

pub fn epochFromCivil(year: i64, month: u8, day: u8, hour: u32, minute: u32, second: u32) i64 {
    return daysFromCivil(year, month, day) * 86400 +
        @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

pub const Civil = struct { year: i64, month: u8, day: u8 };

pub fn civilFromEpoch(secs: i64) Civil {
    return civilFromDays(@divFloor(secs, 86400));
}

pub fn civilFromDays(days: i64) Civil {
    const z = days + 719468;
    const era: i64 = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097); // [0, 146096]
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp: u64 = (5 * doy + 2) / 153; // [0, 11]
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // [1, 31]
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9); // [1, 12]
    return .{ .year = if (m <= 2) y + 1 else y, .month = m, .day = d };
}

pub fn isLeapYear(year: i64) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

pub fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Walks up from the test cwd to the repo root (marked by build.zig.zon),
/// because `zig build` does not normalize the runner's cwd.
fn readFixture(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const io = testing.io;
    var prefix: [30]u8 = ("../" ** 10).*;
    var prefix_len: usize = 0;
    while (prefix_len <= prefix.len) : (prefix_len += 3) {
        var path_buf: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}test/fixtures/ftp/{s}", .{
            prefix[0..prefix_len], name,
        });
        return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err|
            switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
    }
    return error.FileNotFound;
}

const ExpectedEntry = struct {
    name: []const u8,
    kind: vfs.EntryKind = .unknown,
    size: ?u64 = null,
    mode: ?u16 = null,
    mtime: ?i64 = null,
    owner: ?[]const u8 = null,
    group: ?[]const u8 = null,
    link_target: ?[]const u8 = null,
};

fn expectEntry(expected: ExpectedEntry, actual: vfs.Entry) !void {
    try testing.expectEqualStrings(expected.name, actual.name);
    try testing.expectEqual(expected.kind, actual.kind);
    try testing.expectEqual(expected.size, actual.size);
    try testing.expectEqual(expected.mode, actual.mode);
    try testing.expectEqual(expected.mtime, actual.mtime);
    try expectOptStr(expected.owner, actual.owner);
    try expectOptStr(expected.group, actual.group);
    try expectOptStr(expected.link_target, actual.link_target);
}

fn expectOptStr(expected: ?[]const u8, actual: ?[]const u8) !void {
    if (expected) |e| {
        try testing.expect(actual != null);
        try testing.expectEqualStrings(e, actual.?);
    } else {
        try testing.expectEqual(@as(?[]const u8, null), actual);
    }
}

const FixtureCase = struct {
    fixture: []const u8,
    expected: []const ExpectedEntry,
};

// Reference values cross-checked against Python `calendar.timegm`.
const fixture_cases = [_]FixtureCase{
    .{
        .fixture = "mlsd_rfc3659.txt",
        .expected = &.{
            // cdir + pdir lines are filtered out.
            .{ .name = "tmp", .kind = .dir, .mtime = 910428735 },
            .{ .name = "file1.txt", .kind = .file, .size = 4096, .mtime = 871270740 },
            .{ .name = "file2.txt", .kind = .file, .size = 1024, .mtime = 871270740 },
        },
    },
    .{
        .fixture = "mlsd_filezilla.txt",
        .expected = &.{
            .{ .name = "My Documents", .kind = .dir, .mtime = 1725957928 },
            .{ .name = "report final.pdf", .kind = .file, .size = 512354, .mtime = 1725957928 },
            .{ .name = "UPPER case facts.txt", .kind = .file, .size = 0, .mtime = 1725957928 },
        },
    },
    .{
        .fixture = "mlsd_proftpd.txt",
        .expected = &.{
            .{
                .name = "src",
                .kind = .dir,
                .mode = 0o755,
                .mtime = 1781029845,
                .owner = "fredrik",
                .group = "relay",
            },
            .{
                .name = "build.zig",
                .kind = .file,
                .size = 1218,
                .mode = 0o644,
                .mtime = 1781029845,
                .owner = "501",
                .group = "1000",
            },
            .{
                .name = "data-link",
                .kind = .symlink,
                .size = 12,
                .mode = 0o777,
                .mtime = 1696507200,
                .link_target = "/srv/data",
            },
            .{ .name = "tolerate unknown.bin", .kind = .file, .size = 99, .mtime = 1767225600 },
        },
    },
};

test "MLSD corpus" {
    for (fixture_cases) |case| {
        const data = try readFixture(testing.allocator, case.fixture);
        defer testing.allocator.free(data);

        var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_inst.deinit();
        var reader: std.Io.Reader = .fixed(data);
        var cancel: CancelToken = .{};
        var diag: Diagnostics = .{};
        const entries = try parseAll(arena_inst.allocator(), &reader, &cancel, &diag);

        try testing.expectEqual(case.expected.len, entries.len);
        for (case.expected, entries) |expected, actual| try expectEntry(expected, actual);
    }
}

test "fact names and type values are case-insensitive" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const entry = (try parseLine(
        arena_inst.allocator(),
        "TYPE=DIR;MODIFY=20240910084528;UNIX.MODE=0700; photos",
    )).?;
    try expectEntry(.{
        .name = "photos",
        .kind = .dir,
        .mode = 0o700,
        .mtime = 1725957928,
    }, entry);
}

test "MLST-style line with no facts" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const entry = (try parseLine(arena_inst.allocator(), " just a name.txt")).?;
    try expectEntry(.{ .name = "just a name.txt", .kind = .unknown }, entry);
}

test "perm fact infers kind when type is absent" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const dir = (try parseLine(arena_inst.allocator(), "perm=el;modify=19990112030508; d")).?;
    try testing.expectEqual(vfs.EntryKind.dir, dir.kind);
    try testing.expectEqual(@as(?i64, 916110308), dir.mtime);
    const file = (try parseLine(arena_inst.allocator(), "perm=adfrw; f")).?;
    try testing.expectEqual(vfs.EntryKind.file, file.kind);
}

test "malformed and filtered lines yield null" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, ""));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "\r"));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "type=file;size=1;no-pathname"));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "type=cdir; /pub"));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "type=PDIR; .."));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "size=1; ."));
    try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, "type=file;size=1; "));
}

test "bad fact values are dropped, entry survives" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const entry = (try parseLine(
        arena_inst.allocator(),
        "size=12bad;modify=2024134199x999;unix.mode=99zz;type=file; odd.bin",
    )).?;
    try expectEntry(.{ .name = "odd.bin", .kind = .file }, entry);
}

test "modify rejects out-of-range fields and truncates fractions" {
    try testing.expectEqual(@as(?i64, 1725957928), parseTimeVal("20240910084528"));
    try testing.expectEqual(@as(?i64, 1725957928), parseTimeVal("20240910084528.997"));
    try testing.expectEqual(@as(?i64, 951782400), parseTimeVal("20000229000000"));
    try testing.expectEqual(@as(?i64, null), parseTimeVal("20230229000000")); // not a leap year
    try testing.expectEqual(@as(?i64, null), parseTimeVal("20241310000000")); // month 13
    try testing.expectEqual(@as(?i64, null), parseTimeVal("20240910246060"));
    try testing.expectEqual(@as(?i64, null), parseTimeVal("2024091008452")); // 13 digits
    try testing.expectEqual(@as(?i64, null), parseTimeVal(""));
}

test "civil time <-> epoch ground truth" {
    // Values cross-checked against Python calendar.timegm.
    try testing.expectEqual(@as(i64, 0), epochFromCivil(1970, 1, 1, 0, 0, 0));
    try testing.expectEqual(@as(i64, -1), epochFromCivil(1969, 12, 31, 23, 59, 59));
    try testing.expectEqual(@as(i64, 946684799), epochFromCivil(1999, 12, 31, 23, 59, 59));
    try testing.expectEqual(@as(i64, 951827696), epochFromCivil(2000, 2, 29, 12, 34, 56));
    try testing.expectEqual(@as(i64, 4107542400), epochFromCivil(2100, 3, 1, 0, 0, 0));
    try testing.expectEqual(@as(i64, 1781049600), epochFromCivil(2026, 6, 10, 0, 0, 0));

    try testing.expectEqual(Civil{ .year = 1970, .month = 1, .day = 1 }, civilFromEpoch(0));
    try testing.expectEqual(Civil{ .year = 1969, .month = 12, .day = 31 }, civilFromEpoch(-1));
    try testing.expectEqual(Civil{ .year = 2026, .month = 6, .day = 10 }, civilFromEpoch(1781049600));
}

test "civil time round-trips across eras" {
    var day: i64 = -200_000; // 1422-05-13
    while (day <= 200_000) : (day += 271) { // prime stride hits all month shapes
        const c = civilFromDays(day);
        try testing.expectEqual(day, daysFromCivil(c.year, c.month, c.day));
        try testing.expect(c.month >= 1 and c.month <= 12);
        try testing.expect(c.day >= 1 and c.day <= daysInMonth(c.year, c.month));
    }
}

test "canceled mid-stream" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed("type=file;size=1; a\r\n");
    var cancel: CancelToken = .{};
    cancel.cancel();
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.Canceled,
        parseAll(arena_inst.allocator(), &reader, &cancel, &diag),
    );
    try testing.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
}

test "line longer than reader buffer is ProtocolViolation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var buf: [16]u8 = undefined;
    var source: testing.Reader = .init(&buf, &.{
        .{ .buffer = "type=file;size=123456789; this line never fits\r\n" },
    });
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.ProtocolViolation,
        parseAll(arena_inst.allocator(), &source.interface, &cancel, &diag),
    );
    try testing.expectEqual(diag_mod.ErrorClass.permanent, diag.class);
}

fn testParseAllAllocs(gpa: std.mem.Allocator, input: []const u8) !void {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed(input);
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    _ = parseAll(arena_inst.allocator(), &reader, &cancel, &diag) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
}

test "parseAll survives all allocation failures" {
    try testing.checkAllAllocationFailures(testing.allocator, testParseAllAllocs, .{
        "type=dir;modify=20240910084528;unix.ownername=u;unix.groupname=g; a dir\r\n" ++
            "type=OS.unix=slink:/x;size=3; link\r\n" ++
            "type=cdir; .\r\n",
    });
}

fn fuzzMlsd(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];

    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed(input);
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    const entries = parseAll(arena_inst.allocator(), &reader, &cancel, &diag) catch |err|
        switch (err) {
            error.Canceled, error.ConnectionLost, error.ProtocolViolation => unreachable,
            error.OutOfMemory => return,
        };
    for (entries) |entry| {
        try testing.expect(entry.name.len != 0);
        try testing.expect(!std.mem.eql(u8, entry.name, "."));
        try testing.expect(!std.mem.eql(u8, entry.name, ".."));
    }
}

test "fuzz MLSD parser" {
    try testing.fuzz({}, fuzzMlsd, .{ .corpus = &.{
        "type=file;size=4096;modify=19970811033900;perm=r; file1.txt\r\n",
        "Type=dir;UNIX.mode=0755;UNIX.ownername=u; d\r\n",
        "type=OS.unix=slink:/srv/data;size=12; data-link\r\n",
        ";;;=;a=b; n\r\n",
    } });
}

test {
    std.testing.refAllDecls(@This());
}

//! listing_list — LIST fallback parser producing `vfs.Entry`, for servers
//! without MLSD. Three wire dialects, auto-detected per line:
//!
//! - Unix `ls -l` (vsftpd, ProFTPD, Pure-FTPd, wu-ftpd, busybox/musl):
//!   permission string incl. setuid/setgid/sticky/mandatory-lock chars,
//!   hard-link count, owner/group (group may be absent, or contain spaces),
//!   size or `major, minor` device numbers, `Mmm dd HH:MM` / `Mmm dd yyyy`
//!   dates, `name -> target` symlinks, `total N` header lines.
//! - DOS/IIS (`01-23-26  04:05PM  <DIR>  name`), 12- or 24-hour time,
//!   2- or 4-digit years.
//! - EPLF (https://cr.yp.to/ftp/list/eplf.html): `+facts\tname`.
//!
//! Timestamp convention (documented choice, see also listing_mlsd.zig):
//! LIST output carries no timezone, so all dates are interpreted as UTC —
//! guessing server-local offsets without evidence only moves the error
//! around. MLSD `modify` is the authoritative source when available.
//! The year-less Unix form (`Mmm dd HH:MM`) is printed by ls only for
//! mtimes within roughly the last six months, so it resolves to the most
//! recent year that does not place the file more than one day ahead of
//! `Options.now` (the slack absorbs server clock skew and the UTC
//! convention's offset error).
//!
//! Month names are matched in English only (FTP servers format listings in
//! the POSIX locale; localized listings are unparseable garbage to every
//! client and fall out as skipped lines).

const std = @import("std");
const CancelToken = @import("../../cancel.zig").CancelToken;
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const vfs = @import("../../vfs/vfs.zig");
const mlsd = @import("listing_mlsd.zig");

pub const Error = error{
    Canceled,
    /// Data connection dropped (read failure mid-listing).
    ConnectionLost,
    /// A listing line exceeded the reader's buffer capacity (DoS guard).
    ProtocolViolation,
    OutOfMemory,
};

pub const Format = enum { unix, dos, eplf };

pub const Options = struct {
    /// UTC reference instant used to resolve year-less Unix dates.
    now: i64,
};

/// Per-line format sniff. Cheap enough to run on every line; `null` means
/// the line is skippable chrome ("total 24", blanks) or garbage.
pub fn detectLine(line_in: []const u8) ?Format {
    const line = stripCr(line_in);
    if (line.len == 0) return null;
    if (line[0] == '+' and std.mem.indexOfScalar(u8, line, '\t') != null) return .eplf;
    var tok_buf: [3]Token = undefined;
    const toks = tokenize(line, &tok_buf);
    if (toks.len == 0) return null; // whitespace-only line
    if (toks.len >= 3 and
        parseDosDate(tokSlice(line, toks[0])) != null and
        parseDosTime(tokSlice(line, toks[1])) != null) return .dos;
    const perm = tokSlice(line, toks[0]);
    if (perm.len >= 10 and
        kindFromTypeChar(perm[0]) != null and
        modeFromPerm(perm[1..10]) != null) return .unix;
    return null;
}

/// Corpus-driven confidence over a listing sample: per-line votes; the
/// winner should be locked in for the whole listing (servers never mix
/// formats). `format == null` means nothing parseable was seen.
pub const Detection = struct {
    format: ?Format,
    /// Lines that voted for `format`.
    matched: usize,
    /// Non-empty lines inspected.
    total: usize,
};

pub fn detect(sample: []const u8) Detection {
    var votes = [_]usize{0} ** 3;
    var total: usize = 0;
    var it = std.mem.splitScalar(u8, sample, '\n');
    while (it.next()) |raw| {
        const line = stripCr(raw);
        if (line.len == 0) continue;
        total += 1;
        if (detectLine(line)) |format| votes[@intFromEnum(format)] += 1;
    }
    var best: Format = .unix;
    for (std.enums.values(Format)) |f| {
        if (votes[@intFromEnum(f)] > votes[@intFromEnum(best)]) best = f;
    }
    const matched = votes[@intFromEnum(best)];
    return .{
        .format = if (matched == 0) null else best,
        .matched = matched,
        .total = total,
    };
}

/// Parses one LIST line (one trailing CR tolerated). Returns null for
/// header/garbage lines and "." / ".." entries — LIST output is junk-prone
/// by nature, so listings keep streaming past anything unparseable.
/// All slices in the result are arena copies.
pub fn parseLine(
    arena: std.mem.Allocator,
    line_in: []const u8,
    opts: Options,
) error{OutOfMemory}!?vfs.Entry {
    const line = stripCr(line_in);
    return switch (detectLine(line) orelse return null) {
        .unix => parseUnix(arena, line, opts),
        .dos => parseDos(arena, line),
        .eplf => parseEplf(arena, line),
    };
}

/// Parses a whole LIST stream; same transport semantics as
/// `listing_mlsd.parseAll`. The result slice and entry strings are
/// arena-owned.
pub fn parseAll(
    arena: std.mem.Allocator,
    r: *std.Io.Reader,
    cancel: *CancelToken,
    diag: *Diagnostics,
    opts: Options,
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
        if (try parseLine(arena, line, opts)) |entry| try entries.append(arena, entry);
        const buffered = r.buffered();
        if (buffered.len != 0 and buffered[0] == '\n') r.toss(1);
    }
    return entries.items;
}

// ---------------------------------------------------------------------------
// Unix ls -l
// ---------------------------------------------------------------------------

fn parseUnix(arena: std.mem.Allocator, line: []const u8, opts: Options) error{OutOfMemory}!?vfs.Entry {
    var tok_buf: [24]Token = undefined;
    const toks = tokenize(line, &tok_buf);
    if (toks.len < 7) return null; // minimum: perm links size Mmm dd yyyy name

    const perm = tokSlice(line, toks[0]);
    var entry: vfs.Entry = .{
        .name = undefined,
        .kind = kindFromTypeChar(perm[0]) orelse return null,
        .mode = modeFromPerm(perm[1..10]) orelse return null,
    };
    if (!allDigits(tokSlice(line, toks[1]))) return null; // hard-link count

    const date = findDate(line, toks) orelse return null;
    const j = date.month_idx;

    if (!date.device) {
        const size_tok = tokSlice(line, toks[j - 1]);
        if (allDigits(size_tok)) entry.size = std.fmt.parseInt(u64, size_tok, 10) catch null;
    }
    entry.mtime = switch (date.tv) {
        .year => |y| mlsd.epochFromCivil(y, date.month, date.day, 0, 0, 0),
        .time => |t| resolveYearlessDate(opts.now, date.month, date.day, t.hour, t.minute),
    };

    // ls emits exactly one space between the date and the name; any further
    // spaces belong to the name (names with leading spaces survive).
    const after = toks[j + 2].end;
    if (after >= line.len or line[after] != ' ') return null;
    var name = line[after + 1 ..];
    if (name.len == 0) return null;
    var link_target: ?[]const u8 = null;
    if (entry.kind == .symlink) {
        // First occurrence: a target containing " -> " is likelier than a
        // link name containing it (both are unrecoverable ambiguities).
        if (std.mem.indexOf(u8, name, " -> ")) |arrow| {
            const target = name[arrow + 4 ..];
            if (target.len != 0) link_target = target;
            name = name[0..arrow];
        }
    }
    if (name.len == 0 or isDotOrDotDot(name)) return null;

    // Owner/group live between the link count and the size column. One
    // token: owner only. Three or more: the group contains spaces.
    const og_end = if (date.device) j - 2 else j - 1;
    if (og_end > 2) entry.owner = try arena.dupe(u8, tokSlice(line, toks[2]));
    if (og_end > 3) entry.group = try arena.dupe(u8, line[toks[3].start..toks[og_end - 1].end]);

    entry.name = try arena.dupe(u8, name);
    if (link_target) |t| entry.link_target = try arena.dupe(u8, t);
    return entry;
}

const TimeOrYear = union(enum) {
    time: struct { hour: u8, minute: u8 },
    year: i64,
};

const DateLoc = struct {
    /// Token index of the month name.
    month_idx: usize,
    month: u8,
    day: u8,
    tv: TimeOrYear,
    /// Size column is "major, minor" device numbers.
    device: bool,
};

/// Locates the `Mmm dd (HH:MM|yyyy)` column triple. Two passes: the first
/// requires the preceding token to be a plausible size column (all digits,
/// or device major/minor numbers) so owners or groups named like months
/// ("May") don't fool the scanner; the second pass drops that requirement
/// for exotic listings with non-numeric size columns.
fn findDate(line: []const u8, toks: []const Token) ?DateLoc {
    for ([2]bool{ true, false }) |strict| {
        // Index 3 is the earliest possible month position:
        // perm links size Mmm…
        var j: usize = 3;
        while (j + 2 < toks.len) : (j += 1) {
            const month = monthFromName(tokSlice(line, toks[j])) orelse continue;
            const day = parseDayNum(tokSlice(line, toks[j + 1])) orelse continue;
            const tv = parseTimeOrYear(tokSlice(line, toks[j + 2])) orelse continue;
            const size_tok = tokSlice(line, toks[j - 1]);
            const device = j >= 5 and allDigits(size_tok) and
                endsWithComma(tokSlice(line, toks[j - 2]));
            if (strict and !allDigits(size_tok)) continue;
            return .{ .month_idx = j, .month = month, .day = day, .tv = tv, .device = device };
        }
    }
    return null;
}

/// See the file doc comment for the year-resolution convention.
const future_slack: i64 = 86_400;

fn resolveYearlessDate(now: i64, month: u8, day: u8, hour: u8, minute: u8) i64 {
    const this_year = mlsd.civilFromEpoch(now).year;
    const candidate = mlsd.epochFromCivil(this_year, month, day, hour, minute, 0);
    if (candidate > now + future_slack)
        return mlsd.epochFromCivil(this_year - 1, month, day, hour, minute, 0);
    return candidate;
}

fn kindFromTypeChar(c: u8) ?vfs.EntryKind {
    return switch (c) {
        '-' => .file,
        'd' => .dir,
        'l' => .symlink,
        // block/char device, FIFO, socket, Solaris door
        'b', 'c', 'p', 's', 'D' => .special,
        else => null,
    };
}

/// POSIX mode bits from the 9 permission chars, incl. setuid ('s'/'S' in
/// user-x), setgid ('s'/'S' and mandatory-lock 'l'/'L' in group-x) and
/// sticky ('t'/'T' in other-x). Uppercase variants mean "special bit set,
/// execute clear". Null on any unrecognized character.
fn modeFromPerm(p: []const u8) ?u16 {
    std.debug.assert(p.len == 9);
    var mode: u16 = 0;
    for (0..3) |group| {
        const shift: u4 = @intCast((2 - group) * 3);
        const r = p[group * 3 + 0];
        const w = p[group * 3 + 1];
        const x = p[group * 3 + 2];
        if (r == 'r') mode |= @as(u16, 0b100) << shift else if (r != '-') return null;
        if (w == 'w') mode |= @as(u16, 0b010) << shift else if (w != '-') return null;
        switch (x) {
            'x' => mode |= @as(u16, 0b001) << shift,
            '-' => {},
            's', 'S' => {
                if (group == 2) return null;
                if (x == 's') mode |= @as(u16, 0b001) << shift;
                mode |= if (group == 0) @as(u16, 0o4000) else @as(u16, 0o2000);
            },
            'l', 'L' => {
                if (group != 1) return null;
                mode |= 0o2000;
            },
            't', 'T' => {
                if (group != 2) return null;
                if (x == 't') mode |= 0o001;
                mode |= 0o1000;
            },
            else => return null,
        }
    }
    return mode;
}

// ---------------------------------------------------------------------------
// DOS/IIS
// ---------------------------------------------------------------------------

fn parseDos(arena: std.mem.Allocator, line: []const u8) error{OutOfMemory}!?vfs.Entry {
    var tok_buf: [3]Token = undefined;
    const toks = tokenize(line, &tok_buf);
    if (toks.len < 3) return null;
    const date = parseDosDate(tokSlice(line, toks[0])) orelse return null;
    const time = parseDosTime(tokSlice(line, toks[1])) orelse return null;

    var entry: vfs.Entry = .{ .name = undefined };
    const size_tok = tokSlice(line, toks[2]);
    if (std.ascii.eqlIgnoreCase(size_tok, "<dir>")) {
        entry.kind = .dir;
    } else if (allDigits(size_tok)) {
        entry.kind = .file;
        entry.size = std.fmt.parseInt(u64, size_tok, 10) catch null;
    } else return null;
    entry.mtime = mlsd.epochFromCivil(date.year, date.month, date.day, time.hour, time.minute, 0);

    // IIS pads the name column for alignment: skip all spaces (names with
    // leading spaces are unrecoverable in this format).
    var i = toks[2].end;
    while (i < line.len and line[i] == ' ') i += 1;
    if (i >= line.len) return null;
    const name = line[i..];
    if (isDotOrDotDot(name)) return null;
    entry.name = try arena.dupe(u8, name);
    return entry;
}

const DosDate = struct { year: i64, month: u8, day: u8 };

/// MM-DD-YY or MM-DD-YYYY ('/' tolerated as separator). Two-digit years
/// pivot at 70: 70-99 -> 19xx, 00-69 -> 20xx (the convention FileZilla and
/// lftp use).
fn parseDosDate(s: []const u8) ?DosDate {
    var it = std.mem.splitAny(u8, s, "-/");
    const m_part = it.next() orelse return null;
    const d_part = it.next() orelse return null;
    const y_part = it.next() orelse return null;
    if (it.next() != null) return null;
    if (!allDigits(m_part) or !allDigits(d_part) or !allDigits(y_part)) return null;
    if (m_part.len > 2 or d_part.len > 2) return null;
    const month = parseDayLike(m_part, 12) orelse return null;
    const year: i64 = switch (y_part.len) {
        2 => blk: {
            const y = digits(u16, y_part);
            break :blk if (y >= 70) 1900 + @as(i64, y) else 2000 + @as(i64, y);
        },
        4 => digits(i64, y_part),
        else => return null,
    };
    const day = parseDayLike(d_part, mlsd.daysInMonth(year, month)) orelse return null;
    return .{ .year = year, .month = month, .day = day };
}

const DosTime = struct { hour: u8, minute: u8 };

/// HH:MM with optional AM/PM suffix (12-hour when present, 24-hour
/// otherwise).
fn parseDosTime(s: []const u8) ?DosTime {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0 or colon > 2) return null;
    const h_part = s[0..colon];
    if (s.len < colon + 3) return null;
    const m_part = s[colon + 1 ..][0..2];
    if (!allDigits(h_part) or !allDigits(m_part)) return null;
    var hour = digits(u8, h_part);
    const minute = digits(u8, m_part);
    if (minute > 59) return null;
    const suffix = s[colon + 3 ..];
    if (suffix.len == 0) {
        if (hour > 23) return null;
    } else {
        if (hour < 1 or hour > 12) return null;
        if (std.ascii.eqlIgnoreCase(suffix, "am")) {
            if (hour == 12) hour = 0;
        } else if (std.ascii.eqlIgnoreCase(suffix, "pm")) {
            if (hour != 12) hour += 12;
        } else return null;
    }
    return .{ .hour = hour, .minute = minute };
}

// ---------------------------------------------------------------------------
// EPLF
// ---------------------------------------------------------------------------

fn parseEplf(arena: std.mem.Allocator, line: []const u8) error{OutOfMemory}!?vfs.Entry {
    const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return null;
    const name = line[tab + 1 ..];
    if (name.len == 0 or isDotOrDotDot(name)) return null;

    var entry: vfs.Entry = .{ .name = undefined };
    var is_dir = false;
    var is_file = false;
    var it = std.mem.splitScalar(u8, line[1..tab], ',');
    while (it.next()) |fact| {
        if (fact.len == 0) continue;
        switch (fact[0]) {
            '/' => is_dir = fact.len == 1,
            'r' => is_file = fact.len == 1,
            's' => entry.size = std.fmt.parseInt(u64, fact[1..], 10) catch null,
            'm' => entry.mtime = std.fmt.parseInt(i64, fact[1..], 10) catch null,
            'i' => {}, // unique id — unused
            'u' => if (std.mem.startsWith(u8, fact, "up")) {
                const mode = std.fmt.parseInt(u32, fact[2..], 8) catch continue;
                entry.mode = @intCast(mode & 0o7777);
            },
            else => {}, // unknown facts are tolerated per the EPLF spec
        }
    }
    entry.kind = if (is_dir) .dir else if (is_file) .file else .unknown;
    entry.name = try arena.dupe(u8, name);
    return entry;
}

// ---------------------------------------------------------------------------
// Shared lexing helpers
// ---------------------------------------------------------------------------

const Token = struct { start: usize, end: usize };

/// Space-separated tokens with source offsets (offsets are what let name
/// parsing preserve runs of spaces inside file names). Stops at `buf.len`
/// tokens; everything later is name territory and accessed by offset.
fn tokenize(line: []const u8, buf: []Token) []Token {
    var n: usize = 0;
    var i: usize = 0;
    while (i < line.len and n < buf.len) {
        while (i < line.len and line[i] == ' ') i += 1;
        if (i >= line.len) break;
        const start = i;
        while (i < line.len and line[i] != ' ') i += 1;
        buf[n] = .{ .start = start, .end = i };
        n += 1;
    }
    return buf[0..n];
}

fn tokSlice(line: []const u8, t: Token) []const u8 {
    return line[t.start..t.end];
}

fn stripCr(line: []const u8) []const u8 {
    return if (line.len != 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;
}

fn isDotOrDotDot(name: []const u8) bool {
    return std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..");
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn endsWithComma(s: []const u8) bool {
    return s.len >= 2 and s[s.len - 1] == ',' and allDigits(s[0 .. s.len - 1]);
}

fn digits(comptime T: type, s: []const u8) T {
    var v: T = 0;
    for (s) |c| v = v * 10 + (c - '0');
    return v;
}

const month_names = [_][]const u8{
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
};

fn monthFromName(s: []const u8) ?u8 {
    if (s.len != 3) return null;
    for (month_names, 1..) |m, i| {
        if (std.ascii.eqlIgnoreCase(s, m)) return @intCast(i);
    }
    return null;
}

/// 1-2 digits in [1, max].
fn parseDayLike(s: []const u8, max: u8) ?u8 {
    if (s.len == 0 or s.len > 2 or !allDigits(s)) return null;
    const v = digits(u8, s);
    if (v < 1 or v > max) return null;
    return v;
}

fn parseDayNum(s: []const u8) ?u8 {
    return parseDayLike(s, 31);
}

/// `HH:MM` (optionally `:SS`, ignored) or a 4-digit year.
fn parseTimeOrYear(s: []const u8) ?TimeOrYear {
    if (std.mem.indexOfScalar(u8, s, ':')) |colon| {
        if (colon == 0 or colon > 2) return null;
        const h_part = s[0..colon];
        const rest = s[colon + 1 ..];
        const m_part = switch (rest.len) {
            2 => rest,
            5 => blk: {
                if (rest[2] != ':' or !allDigits(rest[3..5])) return null;
                break :blk rest[0..2];
            },
            else => return null,
        };
        if (!allDigits(h_part) or !allDigits(m_part)) return null;
        const hour = digits(u8, h_part);
        const minute = digits(u8, m_part);
        if (hour > 23 or minute > 59) return null;
        return .{ .time = .{ .hour = hour, .minute = minute } };
    }
    if (s.len == 4 and allDigits(s)) return .{ .year = digits(i64, s) };
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 2026-06-10 00:00:00 UTC — the reference instant all corpus expectations
/// are pinned to (see test/fixtures/ftp/README.md).
const test_now: i64 = 1781049600;

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
    format: Format,
    /// Lines that are not expected to vote for `format` (headers).
    chrome_lines: usize = 0,
    /// Lines that vote for `format` but parse to no entry ("." / "..").
    filtered_lines: usize = 0,
    expected: []const ExpectedEntry,
};

// Expected values cross-checked against Python `calendar.timegm` with
// `test_now` = 2026-06-10 00:00:00 UTC. Provenance of each fixture:
// test/fixtures/ftp/README.md.
const fixture_cases = [_]FixtureCase{
    .{
        .fixture = "unix_vsftpd.txt",
        .format = .unix,
        .expected = &.{
            .{ .name = "pub", .kind = .dir, .size = 4096, .mode = 0o755, .mtime = 1781004600, .owner = "0", .group = "0" },
            .{ .name = "big.iso", .kind = .file, .size = 1073741824, .mode = 0o644, .mtime = 1709337600, .owner = "1000", .group = "1000" },
            .{ .name = "welcome.msg", .kind = .file, .size = 3415, .mode = 0o644, .mtime = 1769184300, .owner = "14", .group = "50" },
            .{ .name = "latest", .kind = .symlink, .size = 7, .mode = 0o777, .mtime = 1781004600, .owner = "0", .group = "0", .link_target = "big.iso" },
        },
    },
    .{
        .fixture = "unix_proftpd.txt",
        .format = .unix,
        .expected = &.{
            .{ .name = "archive", .kind = .dir, .size = 4096, .mode = 0o755, .mtime = 1755388800, .owner = "ftp", .group = "ftp" },
            .{ .name = "RELEASE NOTES.txt", .kind = .file, .size = 524288, .mode = 0o644, .mtime = 1780956660, .owner = "relay", .group = "staff" },
            .{ .name = "setuid-tool", .kind = .file, .size = 77824, .mode = 0o4755, .mtime = 1735084800, .owner = "root", .group = "wheel" },
            .{ .name = "incoming", .kind = .dir, .size = 4096, .mode = 0o1777, .mtime = 1781049600, .owner = "ftp", .group = "ftp" },
            .{ .name = "current", .kind = .symlink, .size = 11, .mode = 0o777, .mtime = 1771059660, .owner = "ftp", .group = "ftp", .link_target = "./archive/9" },
        },
    },
    .{
        .fixture = "unix_pureftpd.txt",
        .format = .unix,
        .filtered_lines = 2, // "." and ".."
        .expected = &.{
            // "." and ".." are filtered.
            .{ .name = "-leading-dash.bin", .kind = .file, .size = 1024000, .mode = 0o644, .mtime = 1062806400, .owner = "1000", .group = "ftpgroup" },
            .{ .name = "čí šek.txt", .kind = .file, .size = 42, .mode = 0o444, .mtime = 1781049600, .owner = "1000", .group = "ftpgroup" },
        },
    },
    .{
        .fixture = "unix_busybox.txt",
        .format = .unix,
        .chrome_lines = 1, // "total 64"
        .expected = &.{
            .{ .name = "bin", .kind = .dir, .size = 12288, .mode = 0o755, .mtime = 1680652800, .owner = "root", .group = "root" },
            .{ .name = "null", .kind = .special, .mode = 0o666, .mtime = 1767225600, .owner = "root", .group = "root" },
            .{ .name = "sda", .kind = .special, .mode = 0o660, .mtime = 1767225600, .owner = "root", .group = "disk" },
            .{ .name = "fifo", .kind = .special, .size = 0, .mode = 0o644, .mtime = 804816000, .owner = "root", .group = "root" },
            .{ .name = "busybox", .kind = .file, .size = 452472, .mode = 0o2755, .mtime = 1680652800, .owner = "root", .group = "root" },
        },
    },
    .{
        .fixture = "unix_names_edge.txt",
        .format = .unix,
        .expected = &.{
            .{ .name = "simple.txt", .kind = .file, .size = 100, .mode = 0o644, .mtime = 1577836800, .owner = "user", .group = "users" },
            .{ .name = "two  spaces.txt", .kind = .file, .size = 200, .mode = 0o644, .mtime = 1577836800, .owner = "user", .group = "users" },
            .{ .name = "-rf", .kind = .file, .size = 300, .mode = 0o644, .mtime = 1577836800, .owner = "user", .group = "users" },
            .{ .name = "åäö 日本語.dat", .kind = .file, .size = 400, .mode = 0o644, .mtime = 1577836800, .owner = "user", .group = "users" },
            .{ .name = "weird", .kind = .symlink, .size = 20, .mode = 0o777, .mtime = 1577836800, .owner = "user", .group = "users", .link_target = "name -> target dir" },
            .{ .name = "owner-named-may", .kind = .file, .size = 1234, .mode = 0o644, .mtime = 1778591640, .owner = "May", .group = "12" },
            .{ .name = "from-last-year.log", .kind = .file, .size = 500, .mode = 0o644, .mtime = 1749633300, .owner = "user", .group = "users" },
        },
    },
    .{
        .fixture = "dos_iis.txt",
        .format = .dos,
        .expected = &.{
            .{ .name = "aspnet_client", .kind = .dir, .mtime = 1769184300 },
            .{ .name = "default.htm", .kind = .file, .size = 14336, .mtime = 1529932080 },
            .{ .name = "empty file.log", .kind = .file, .size = 0, .mtime = 1767139140 },
            .{ .name = "y2k leap.bin", .kind = .file, .size = 524288, .mtime = 951782400 },
            .{ .name = "Old Sites", .kind = .dir, .mtime = 804859200 },
        },
    },
    .{
        .fixture = "eplf.txt",
        .format = .eplf,
        .expected = &.{
            .{ .name = "djb.html", .kind = .file, .size = 280, .mtime = 825718503 },
            .{ .name = "514", .kind = .dir, .mtime = 824255907 },
            .{ .name = "514.html", .kind = .file, .size = 612, .mtime = 824253270 },
            .{ .name = "important notes", .kind = .dir, .mode = 0o153, .mtime = 824255902 },
        },
    },
};

test "LIST corpus: detection confidence and exact entries" {
    for (fixture_cases) |case| {
        const data = try readFixture(testing.allocator, case.fixture);
        defer testing.allocator.free(data);

        const detection = detect(data);
        try testing.expectEqual(@as(?Format, case.format), detection.format);
        // Every non-chrome line must vote for the winning format, and the
        // voters are exactly the expected entries plus filtered "."/"..".
        try testing.expectEqual(detection.total - case.chrome_lines, detection.matched);
        try testing.expectEqual(case.expected.len + case.filtered_lines, detection.matched);

        var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_inst.deinit();
        var reader: std.Io.Reader = .fixed(data);
        var cancel: CancelToken = .{};
        var diag: Diagnostics = .{};
        const entries = try parseAll(
            arena_inst.allocator(),
            &reader,
            &cancel,
            &diag,
            .{ .now = test_now },
        );
        try testing.expectEqual(case.expected.len, entries.len);
        for (case.expected, entries) |expected, actual| try expectEntry(expected, actual);
    }
}

test "unix: owner without group, and group containing spaces" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const opts: Options = .{ .now = test_now };

    const no_group = (try parseLine(arena, "drwxr-xr-x   2 ftp          4096 Jan  1  2020 files", opts)).?;
    try expectEntry(.{
        .name = "files",
        .kind = .dir,
        .size = 4096,
        .mode = 0o755,
        .mtime = 1577836800,
        .owner = "ftp",
    }, no_group);

    const spaced_group = (try parseLine(arena, "-rw-r--r--   1 svc domain users  100 Jan  1  2020 report.txt", opts)).?;
    try expectEntry(.{
        .name = "report.txt",
        .kind = .file,
        .size = 100,
        .mode = 0o644,
        .mtime = 1577836800,
        .owner = "svc",
        .group = "domain users",
    }, spaced_group);
}

test "unix: permission special bits" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const opts: Options = .{ .now = test_now };
    const cases = [_]struct { perm: []const u8, mode: u16 }{
        .{ .perm = "-rwsr-sr-t", .mode = 0o7755 },
        .{ .perm = "-rwSr--r--", .mode = 0o4644 },
        .{ .perm = "-rw-r-lr--", .mode = 0o2644 },
        .{ .perm = "drwxrwxrwT", .mode = 0o1776 },
    };
    for (cases) |case| {
        var buf: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "{s} 1 u g 1 Jan 1 2020 x", .{case.perm});
        const entry = (try parseLine(arena, line, opts)).?;
        try testing.expectEqual(@as(?u16, case.mode), entry.mode);
    }
}

test "unix: total header, garbage, and dot entries are skipped" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const opts: Options = .{ .now = test_now };
    for ([_][]const u8{
        "total 64",
        "",
        "\r",
        "drwxr-xr-x   2 a b 4096 Jan  1  2020 .",
        "drwxr-xr-x   2 a b 4096 Jan  1  2020 ..",
        "drwxr-xr-x   2 a b 4096 Foo  1  2020 x", // bad month
        "drwxr-xr-x   2 a b 4096 Jan 32  2020 x", // bad day
        "drwxr-xr-x   2 a b 4096 Jan  1 99999 x", // bad year
        "drwxr-xr-x   x b 4096 Jan  1 2020 x", // non-numeric link count
        "drwxr-xr-x   2 a b 4096 Jan  1  2020", // no name
        "qrwxr-xr-x   2 a b 4096 Jan  1  2020 x", // unknown type char
    }) |line| {
        try testing.expectEqual(@as(?vfs.Entry, null), try parseLine(arena, line, opts));
    }
}

test "unix: year-less dates resolve against Options.now" {
    // Pinned: now = 2026-06-10 00:00:00 UTC.
    // A date later in June resolves to 2025; one earlier resolves to 2026.
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const opts: Options = .{ .now = test_now };
    const past = (try parseLine(arena, "-rw-r--r-- 1 u g 1 Jun  9 11:30 a", opts)).?;
    try testing.expectEqual(@as(?i64, 1781004600), past.mtime);
    const future = (try parseLine(arena, "-rw-r--r-- 1 u g 1 Jun 11 09:15 b", opts)).?;
    try testing.expectEqual(@as(?i64, 1749633300), future.mtime);
    // Within the one-day slack: stays in the current year.
    const today = (try parseLine(arena, "-rw-r--r-- 1 u g 1 Jun 10 12:00 c", opts)).?;
    try testing.expectEqual(@as(?i64, 1781092800), today.mtime);
}

test "dos: 24-hour times, 4-digit years, slash separators" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const opts: Options = .{ .now = test_now };
    const entry = (try parseLine(arena, "01/23/2026  16:05          1234 report.txt", opts)).?;
    try expectEntry(.{
        .name = "report.txt",
        .kind = .file,
        .size = 1234,
        .mtime = 1769184300,
    }, entry);
    // Invalid 12-hour value with AM/PM suffix.
    try testing.expectEqual(
        @as(?vfs.Entry, null),
        try parseLine(arena, "01-23-26  13:05PM  1234 x", opts),
    );
}

test "detectLine representatives" {
    try testing.expectEqual(@as(?Format, .unix), detectLine("drwxr-xr-x 2 a b 4096 Jan 1 2020 x"));
    try testing.expectEqual(@as(?Format, .dos), detectLine("01-23-26  04:05PM       <DIR>          x"));
    try testing.expectEqual(@as(?Format, .eplf), detectLine("+i9,m5,r,s1,\tx"));
    try testing.expectEqual(@as(?Format, null), detectLine("total 24"));
    try testing.expectEqual(@as(?Format, null), detectLine("+no-tab-here"));
    try testing.expectEqual(@as(?Format, null), detectLine(""));
    try testing.expectEqual(@as(?Format, null), detectLine("   "));
    try testing.expectEqual(@as(?Format, null), detectLine(" \r"));
}

test "canceled mid-stream" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed("total 1\r\n");
    var cancel: CancelToken = .{};
    cancel.cancel();
    var diag: Diagnostics = .{};
    try testing.expectError(error.Canceled, parseAll(
        arena_inst.allocator(),
        &reader,
        &cancel,
        &diag,
        .{ .now = test_now },
    ));
    try testing.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
}

test "line longer than reader buffer is ProtocolViolation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var buf: [16]u8 = undefined;
    var source: testing.Reader = .init(&buf, &.{
        .{ .buffer = "-rw-r--r-- 1 user group 123456 Jan  1  2020 some name.txt\r\n" },
    });
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    try testing.expectError(error.ProtocolViolation, parseAll(
        arena_inst.allocator(),
        &source.interface,
        &cancel,
        &diag,
        .{ .now = test_now },
    ));
    try testing.expectEqual(diag_mod.ErrorClass.permanent, diag.class);
}

fn testParseAllAllocs(gpa: std.mem.Allocator, input: []const u8) !void {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed(input);
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    _ = parseAll(arena_inst.allocator(), &reader, &cancel, &diag, .{ .now = test_now }) catch |err|
        switch (err) {
            error.OutOfMemory => return err,
            else => return,
        };
}

test "parseAll survives all allocation failures" {
    try testing.checkAllAllocationFailures(testing.allocator, testParseAllAllocs, .{
        "lrwxrwxrwx 1 user domain users 7 Jun  9 11:30 latest -> big.iso\r\n" ++
            "01-23-26  04:05PM       <DIR>          aspnet_client\r\n" ++
            "+up153,m824255902,/,\timportant notes\r\n",
    });
}

fn fuzzList(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];

    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var reader: std.Io.Reader = .fixed(input);
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    const entries = parseAll(
        arena_inst.allocator(),
        &reader,
        &cancel,
        &diag,
        .{ .now = test_now },
    ) catch |err| switch (err) {
        error.Canceled, error.ConnectionLost, error.ProtocolViolation => unreachable,
        error.OutOfMemory => return,
    };
    for (entries) |entry| {
        try testing.expect(entry.name.len != 0);
        try testing.expect(!isDotOrDotDot(entry.name));
    }
    // Detection must never crash either, whatever the bytes.
    _ = detect(input);
}

test "fuzz LIST parser" {
    try testing.fuzz({}, fuzzList, .{ .corpus = &.{
        "drwxr-xr-x    2 0        0            4096 Jun 09 11:30 pub\r\n",
        "crw-rw-rw-    1 root     root        1,   3 Jan  1 00:00 null\n",
        "lrwxrwxrwx   1 ftp ftp 11 Feb 14 09:01 current -> ./archive/9\r\n",
        "01-23-26  04:05PM       <DIR>          aspnet_client\r\n",
        "+i8388621.48594,m825718503,r,s280,\tdjb.html\r\n",
        "total 64\n",
        "   \r\n",
    } });
}

test {
    std.testing.refAllDecls(@This());
}

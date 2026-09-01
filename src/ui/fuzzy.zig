//! fuzzy — relay_ui's headless palette ranking kit:
//!
//!  1. `Matcher` — subsequence fuzzy matcher with scoring: consecutive-run
//!     bonus, word/separator-boundary bonus, camelCase bonus, start-of-string
//!     bonus, gap penalties; case-smart (lowercase needle chars match either
//!     case, uppercase ones match exactly). Returns the score plus matched
//!     index ranges (for highlights) written into reusable scratch — no
//!     allocation per candidate.
//!  2. `TopList` — best-N selection over any candidate stream into a
//!     caller-provided buffer (again: zero allocation per candidate).
//!  3. `Frecency` — key → {count, last_used} persisted as ZON in the
//!     settings dir via settings.zig's crash-safe atomic writer. Missing or
//!     corrupt files degrade to empty (the settings.zon policy).
//!
//! Final rank = match score × frecency boost (see `rank`).

const std = @import("std");
const relay = @import("relay_core");

const settings_mod = relay.settings;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

/// Needles longer than this never match (palette queries are short; the
/// scratch buffers are sized by this bound).
pub const max_needle: usize = 64;

/// One matched span of haystack indexes, `[start .. start+len)`.
pub const Range = struct { start: u32, len: u32 };

pub const Match = struct {
    /// Always >= 1 for a successful match (so frecency multiplication
    /// keeps its sign).
    score: i32,
    /// Ascending, non-overlapping haystack ranges covering every matched
    /// needle char. Points into the Matcher's scratch: valid until the next
    /// `match` call on the same Matcher.
    ranges: []const Range,
};

// Scoring weights. Tuned relative to each other, not absolute: a boundary
// hit beats a mid-word run of two, an exact prefix beats everything.
pub const score_match: i32 = 4; // per matched char
pub const bonus_start: i32 = 16; // match begins at haystack[0]
pub const bonus_boundary: i32 = 12; // char follows a separator
pub const bonus_camel: i32 = 10; // lower→upper / nondigit→digit edge
pub const bonus_consecutive: i32 = 8; // adjacent to the previous match
pub const penalty_gap_start: i32 = 3; // first skipped char of a gap
pub const penalty_gap_extend: i32 = 1; // each further skipped char

fn isSeparator(ch: u8) bool {
    return switch (ch) {
        '/', '\\', '_', '-', '.', ' ', ':', ',' => true,
        else => false,
    };
}

fn isUpper(ch: u8) bool {
    return ch >= 'A' and ch <= 'Z';
}

fn isLower(ch: u8) bool {
    return ch >= 'a' and ch <= 'z';
}

fn isDigit(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

/// Positional bonus of matching haystack[i] (independent of the needle).
fn positionBonus(haystack: []const u8, i: usize) i32 {
    if (i == 0) return bonus_start;
    const prev = haystack[i - 1];
    if (isSeparator(prev)) return bonus_boundary;
    const cur = haystack[i];
    if (isLower(prev) and isUpper(cur)) return bonus_camel;
    if (!isDigit(prev) and isDigit(cur)) return bonus_camel;
    return 0;
}

/// Case-smart char compare: a lowercase needle char matches both cases;
/// anything else (uppercase, digits, punctuation, UTF-8 bytes) must match
/// exactly.
fn charMatches(needle_ch: u8, hay_ch: u8) bool {
    // std.ascii.toLower only maps A–Z (no arithmetic on arbitrary bytes).
    if (isLower(needle_ch)) return needle_ch == std.ascii.toLower(hay_ch);
    return needle_ch == hay_ch;
}

pub const Matcher = struct {
    /// Matched haystack index per needle char (scratch).
    positions: [max_needle]u32 = undefined,
    /// Merged ranges over `positions` (scratch; at most one per needle char).
    ranges_buf: [max_needle]Range = undefined,

    /// Subsequence match of `needle` in `haystack`. Returns null when the
    /// needle is not a (case-smart) subsequence, or longer than `max_needle`.
    /// An empty needle matches everything with score 1 and no ranges.
    ///
    /// Never crashes on arbitrary input; all returned ranges lie within
    /// `haystack` and cover exactly `needle.len` indexes in ascending order.
    pub fn match(self: *Matcher, needle: []const u8, haystack: []const u8) ?Match {
        if (needle.len == 0) return .{ .score = 1, .ranges = &.{} };
        if (needle.len > max_needle or needle.len > haystack.len) return null;

        // Forward pass: earliest end of a complete subsequence match.
        var ni: usize = 0;
        var end: usize = 0; // one past the last matched index
        for (haystack, 0..) |ch, hi| {
            if (charMatches(needle[ni], ch)) {
                ni += 1;
                if (ni == needle.len) {
                    end = hi + 1;
                    break;
                }
            }
        }
        if (ni != needle.len) return null;

        // Backward pass: latest start such that needle still fits before
        // `end` — the tightest window (fzf-v1 style; keeps "ab" matching
        // the "_ab" of "axx_ab", not the spread-out a…b).
        var start = end;
        var nj: usize = needle.len;
        while (nj > 0) {
            start -= 1;
            if (charMatches(needle[nj - 1], haystack[start])) nj -= 1;
        }

        // Greedy assignment inside the tight window + scoring.
        var score: i32 = 0;
        var matched: usize = 0;
        var last_pos: ?usize = null;
        var hi = start;
        while (matched < needle.len) : (hi += 1) {
            // The window is a verified match: hi never reaches `end`
            // before the needle completes.
            if (!charMatches(needle[matched], haystack[hi])) continue;
            score += score_match;
            score += positionBonus(haystack, hi);
            if (last_pos) |lp| {
                if (hi == lp + 1) {
                    score += bonus_consecutive;
                } else {
                    const gap: i32 = @intCast(hi - lp - 1);
                    score -= penalty_gap_start + penalty_gap_extend * (gap - 1);
                }
            }
            self.positions[matched] = @intCast(hi);
            last_pos = hi;
            matched += 1;
        }
        if (score < 1) score = 1;

        // Merge adjacent positions into ranges.
        var n_ranges: usize = 0;
        for (self.positions[0..needle.len]) |pos| {
            if (n_ranges > 0) {
                const last = &self.ranges_buf[n_ranges - 1];
                if (pos == last.start + last.len) {
                    last.len += 1;
                    continue;
                }
            }
            self.ranges_buf[n_ranges] = .{ .start = pos, .len = 1 };
            n_ranges += 1;
        }
        return .{ .score = score, .ranges = self.ranges_buf[0..n_ranges] };
    }
};

// ---------------------------------------------------------------------------
// Top-N selection (no allocation per candidate; the caller provides the
// result buffer once and streams candidates through `consider`).
// ---------------------------------------------------------------------------

pub const Ranked = struct {
    /// Caller-side candidate index (resolved back after selection).
    index: usize,
    score: f64,
};

pub const TopList = struct {
    buf: []Ranked,
    len: usize = 0,

    pub fn init(buf: []Ranked) TopList {
        return .{ .buf = buf };
    }

    pub fn clear(self: *TopList) void {
        self.len = 0;
    }

    /// Keep the best `buf.len` candidates by score (descending); ties keep
    /// the earlier-considered candidate first (stable for equal scores).
    pub fn consider(self: *TopList, candidate: Ranked) void {
        if (self.buf.len == 0) return;
        if (self.len == self.buf.len and
            candidate.score <= self.buf[self.len - 1].score) return;

        // Insertion position: after every entry with score >= candidate's.
        var pos = self.len;
        while (pos > 0 and self.buf[pos - 1].score < candidate.score) pos -= 1;

        if (self.len < self.buf.len) self.len += 1;
        var i = self.len - 1;
        while (i > pos) : (i -= 1) self.buf[i] = self.buf[i - 1];
        self.buf[pos] = candidate;
    }

    pub fn items(self: *const TopList) []const Ranked {
        return self.buf[0..self.len];
    }
};

// ---------------------------------------------------------------------------
// Frecency store — key → {count, last_used}, ZON on disk.
// ---------------------------------------------------------------------------

pub const FrecencyEntry = struct {
    count: u32 = 0,
    /// Wall-clock seconds since epoch of the most recent use.
    last_used: i64 = 0,
};

/// score × boost. `score` is clamped >= 1 by the matcher, so the product
/// orders correctly.
pub fn rank(score: i32, boost: f64) f64 {
    return @as(f64, @floatFromInt(score)) * boost;
}

/// 1.0 for unknown keys; grows with use count (log2-damped) weighted by
/// recency (hour > day > week > older).
pub fn boostFor(entry: ?FrecencyEntry, now: i64) f64 {
    const e = entry orelse return 1.0;
    if (e.count == 0) return 1.0;
    const age: i64 = @max(0, now -| e.last_used);
    const recency: f64 = if (age < std.time.s_per_hour)
        4.0
    else if (age < std.time.s_per_day)
        2.0
    else if (age < 7 * std.time.s_per_day)
        1.0
    else
        0.25;
    const freq = std.math.log2(1.0 + @as(f64, @floatFromInt(@min(e.count, 1024))));
    return 1.0 + recency * freq;
}

// ZON shape on disk. `parse` rejects unknown fields (settings.zon policy:
// older binaries fail loudly), corrupt files degrade to empty.
const FrecencyRec = struct {
    key: []const u8,
    count: u32 = 0,
    last_used: i64 = 0,
};

const FrecencyFile = struct {
    schema_version: u32 = 1,
    entries: []const FrecencyRec = &.{},
};

pub const Frecency = struct {
    gpa: Allocator,
    /// Keys are gpa-owned dupes. Array map: iteration order == insertion
    /// order, which keeps serialization deterministic for tests.
    map: std.StringArrayHashMapUnmanaged(FrecencyEntry) = .empty,

    /// Entry cap; the least-recently-used key is evicted past this.
    pub const max_entries: usize = 512;

    pub fn init(gpa: Allocator) Frecency {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Frecency) void {
        for (self.map.keys()) |key| self.gpa.free(key);
        self.map.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Frecency) usize {
        return self.map.count();
    }

    pub fn get(self: *const Frecency, key: []const u8) ?FrecencyEntry {
        return self.map.get(key);
    }

    pub fn boost(self: *const Frecency, key: []const u8, now: i64) f64 {
        return boostFor(self.get(key), now);
    }

    /// Record one use of `key` at wall-clock `now` (seconds).
    pub fn bump(self: *Frecency, key: []const u8, now: i64) error{OutOfMemory}!void {
        const gop = try self.map.getOrPut(self.gpa, key);
        if (!gop.found_existing) {
            errdefer _ = self.map.orderedRemove(key);
            gop.key_ptr.* = try self.gpa.dupe(u8, key);
            gop.value_ptr.* = .{};
        }
        gop.value_ptr.count +|= 1;
        gop.value_ptr.last_used = now;
        self.evictIfNeeded();
    }

    fn evictIfNeeded(self: *Frecency) void {
        while (self.map.count() > max_entries) {
            var oldest_i: usize = 0;
            var oldest: i64 = std.math.maxInt(i64);
            for (self.map.values(), 0..) |entry, i| {
                if (entry.last_used < oldest) {
                    oldest = entry.last_used;
                    oldest_i = i;
                }
            }
            const key = self.map.keys()[oldest_i];
            self.map.orderedRemoveAt(oldest_i);
            self.gpa.free(key);
        }
    }

    /// Load `dir/sub_path`; a missing or corrupt file leaves the store
    /// empty (the settings.zon degradation policy). Only OOM propagates.
    pub fn load(
        self: *Frecency,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) error{OutOfMemory}!void {
        const source = settings_mod.readFileZ(io, dir, sub_path, self.gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return,
        };
        defer self.gpa.free(source);

        var zon_diag: std.zon.parse.Diagnostics = .{};
        defer zon_diag.deinit(self.gpa);
        const parsed = std.zon.parse.fromSliceAlloc(
            FrecencyFile,
            self.gpa,
            source,
            &zon_diag,
            .{},
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseZon => return,
        };
        defer std.zon.parse.free(self.gpa, parsed);

        for (parsed.entries) |entry| {
            if (entry.key.len == 0) continue;
            const gop = try self.map.getOrPut(self.gpa, entry.key);
            if (!gop.found_existing) {
                errdefer _ = self.map.orderedRemove(entry.key);
                gop.key_ptr.* = try self.gpa.dupe(u8, entry.key);
            }
            gop.value_ptr.* = .{ .count = entry.count, .last_used = entry.last_used };
        }
        self.evictIfNeeded();
    }

    /// Persist as ZON via settings.zig's crash-safe atomic writer.
    pub fn save(self: *const Frecency, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !void {
        const gpa = self.gpa;
        const recs = try gpa.alloc(FrecencyRec, self.map.count());
        defer gpa.free(recs);
        for (self.map.keys(), self.map.values(), recs) |key, entry, *rec| {
            rec.* = .{ .key = key, .count = entry.count, .last_used = entry.last_used };
        }

        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const file: FrecencyFile = .{ .entries = recs };
        std.zon.stringify.serialize(file, .{}, &out.writer) catch return error.OutOfMemory;
        out.writer.writeByte('\n') catch return error.OutOfMemory;
        try settings_mod.atomicWriteFile(io, dir, sub_path, out.written());
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;

fn scoreOf(needle: []const u8, haystack: []const u8) ?i32 {
    var m: Matcher = .{};
    const result = m.match(needle, haystack) orelse return null;
    return result.score;
}

test "matcher: subsequence basics" {
    var m: Matcher = .{};

    // Exact and subsequence hits.
    try testing.expect(m.match("abc", "abc") != null);
    try testing.expect(m.match("abc", "a1b2c3") != null);
    try testing.expect(m.match("abc", "xxaxbxcxx") != null);

    // Misses: wrong order, missing char, needle longer than haystack.
    try testing.expect(m.match("abc", "cba") == null);
    try testing.expect(m.match("abc", "ab") == null);
    try testing.expect(m.match("abcd", "abc") == null);
    try testing.expect(m.match("x", "") == null);

    // Empty needle matches anything (score 1, no ranges).
    const empty = m.match("", "whatever").?;
    try testing.expectEqual(@as(i32, 1), empty.score);
    try testing.expectEqual(@as(usize, 0), empty.ranges.len);

    // Over-long needles never match (scratch bound).
    const long = "x" ** (max_needle + 1);
    try testing.expect(m.match(long, long ++ long) == null);
}

test "matcher: case-smart" {
    var m: Matcher = .{};
    // Lowercase needle matches both cases.
    try testing.expect(m.match("readme", "README.md") != null);
    try testing.expect(m.match("rm", "ReadMe") != null);
    // Uppercase needle chars require uppercase haystack.
    try testing.expect(m.match("RM", "ReadMe") != null);
    try testing.expect(m.match("RM", "readme") == null);
}

test "matcher: ranges cover the needle and merge runs" {
    var m: Matcher = .{};

    const exact = m.match("abc", "abc").?;
    try testing.expectEqual(@as(usize, 1), exact.ranges.len);
    try testing.expectEqual(Range{ .start = 0, .len = 3 }, exact.ranges[0]);

    const split = m.match("ac", "abc").?;
    try testing.expectEqual(@as(usize, 2), split.ranges.len);
    try testing.expectEqual(Range{ .start = 0, .len = 1 }, split.ranges[0]);
    try testing.expectEqual(Range{ .start = 2, .len = 1 }, split.ranges[1]);
}

test "matcher: scoring preferences" {
    // Consecutive run beats the same chars spread out.
    try testing.expect(scoreOf("abc", "abcxxx").? > scoreOf("abc", "axbxcx").?);

    // Start-of-string beats mid-string.
    try testing.expect(scoreOf("conf", "config.zon").? > scoreOf("conf", "my_config.zon").?);

    // Separator boundary beats mid-word.
    try testing.expect(scoreOf("zon", "settings.zon").? > scoreOf("zon", "amazonia").?);

    // camelCase boundary beats mid-word.
    try testing.expect(scoreOf("v", "fooView").? > scoreOf("v", "favor").?);

    // Longer gaps cost more.
    try testing.expect(scoreOf("ab", "axb").? > scoreOf("ab", "axxxxb").?);

    // Tight-window selection: prefer the boundary "ab" cluster at the end.
    var m: Matcher = .{};
    const tight = m.match("ab", "axx_ab").?;
    try testing.expectEqual(@as(usize, 1), tight.ranges.len);
    try testing.expectEqual(Range{ .start = 4, .len = 2 }, tight.ranges[0]);

    // Successful matches always score >= 1.
    var worst_hay: [max_needle * 8]u8 = undefined;
    @memset(&worst_hay, 'x');
    var i: usize = 0;
    while (i < 8) : (i += 1) worst_hay[i * 8] = 'a';
    try testing.expect(scoreOf("aaaaaaaa", &worst_hay).? >= 1);
}

fn checkMatchInvariants(needle: []const u8, haystack: []const u8) !void {
    var m: Matcher = .{};
    const result = m.match(needle, haystack) orelse {
        // Miss ⇒ no prefix-of-haystack claim to verify.
        return;
    };
    try testing.expect(result.score >= 1);

    // Ranges: in bounds, ascending, non-overlapping, covering needle.len.
    var covered: usize = 0;
    var prev_end: usize = 0;
    for (result.ranges, 0..) |range, i| {
        try testing.expect(range.len > 0);
        try testing.expect(range.start < haystack.len);
        try testing.expect(range.start + range.len <= haystack.len);
        if (i > 0) try testing.expect(range.start > prev_end); // gap ⇒ separate range
        prev_end = range.start + range.len;
        covered += range.len;
    }
    try testing.expectEqual(needle.len, covered);

    // Monotonic prefix property: every prefix of a matching needle matches
    // too (a prefix of a subsequence is a subsequence).
    var k: usize = 0;
    while (k <= needle.len) : (k += 1) {
        var pm: Matcher = .{};
        try testing.expect(pm.match(needle[0..k], haystack) != null);
    }
}

test "matcher: fuzz — never crashes, ranges in bounds, prefix-monotonic" {
    var prng = std.Random.DefaultPrng.init(0x5eed_f02d);
    const random = prng.random();

    const alphabet = "abcXYZ_/.-0立\xff\x00 ";
    var needle_buf: [max_needle + 8]u8 = undefined;
    var hay_buf: [256]u8 = undefined;

    var round: usize = 0;
    while (round < 2000) : (round += 1) {
        const nlen = random.uintAtMost(usize, needle_buf.len);
        const hlen = random.uintAtMost(usize, hay_buf.len);
        for (needle_buf[0..nlen]) |*ch| ch.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        for (hay_buf[0..hlen]) |*ch| ch.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        try checkMatchInvariants(needle_buf[0..nlen], hay_buf[0..hlen]);
    }

    // A guaranteed-hit round: haystack embeds the needle.
    round = 0;
    while (round < 500) : (round += 1) {
        const nlen = 1 + random.uintAtMost(usize, 12);
        for (needle_buf[0..nlen]) |*ch| ch.* = 'a' + @as(u8, random.uintLessThan(u8, 26));
        const prefix = random.uintAtMost(usize, 32);
        for (hay_buf[0..prefix]) |*ch| ch.* = '0'; // never matches a letter
        @memcpy(hay_buf[prefix..][0..nlen], needle_buf[0..nlen]);
        try checkMatchInvariants(needle_buf[0..nlen], hay_buf[0 .. prefix + nlen]);
        var m: Matcher = .{};
        try testing.expect(m.match(needle_buf[0..nlen], hay_buf[0 .. prefix + nlen]) != null);
    }
}

test "top list: keeps the best N, ordered, stable on ties" {
    var buf: [3]Ranked = undefined;
    var top = TopList.init(&buf);

    try testing.expectEqual(@as(usize, 0), top.items().len);
    top.consider(.{ .index = 0, .score = 5 });
    top.consider(.{ .index = 1, .score = 9 });
    top.consider(.{ .index = 2, .score = 1 });
    top.consider(.{ .index = 3, .score = 7 });
    top.consider(.{ .index = 4, .score = 7 }); // tie: stays after index 3
    top.consider(.{ .index = 5, .score = 0.5 }); // below the floor: dropped

    const items = top.items();
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqual(@as(usize, 1), items[0].index);
    try testing.expectEqual(@as(usize, 3), items[1].index);
    try testing.expectEqual(@as(usize, 4), items[2].index);

    // New maximum displaces the tail.
    top.consider(.{ .index = 6, .score = 100 });
    try testing.expectEqual(@as(usize, 6), top.items()[0].index);
    try testing.expectEqual(@as(usize, 3), top.items()[2].index);

    top.clear();
    try testing.expectEqual(@as(usize, 0), top.items().len);

    // Zero-capacity list swallows everything quietly.
    var none = TopList.init(&.{});
    none.consider(.{ .index = 0, .score = 1 });
    try testing.expectEqual(@as(usize, 0), none.items().len);
}

test "frecency: bump, boost ordering, eviction" {
    var store = Frecency.init(testing.allocator);
    defer store.deinit();

    const now: i64 = 1_750_000_000;
    try testing.expectEqual(@as(f64, 1.0), store.boost("unknown", now));

    try store.bump("a", now - 10);
    try store.bump("b", now - 10);
    try store.bump("b", now - 5);

    // More used ⇒ bigger boost; both beat unknown.
    try testing.expect(store.boost("b", now) > store.boost("a", now));
    try testing.expect(store.boost("a", now) > 1.0);

    // Recency tiers: the same count used a month ago boosts less.
    try store.bump("stale", now - 40 * std.time.s_per_day);
    try testing.expect(store.boost("a", now) > store.boost("stale", now));

    // rank multiplies (score clamped >= 1 keeps the order meaningful).
    try testing.expect(rank(10, store.boost("b", now)) > rank(10, 1.0));

    // Eviction: oldest last_used goes first.
    var key_buf: [16]u8 = undefined;
    var i: usize = 0;
    while (store.count() < Frecency.max_entries) : (i += 1) {
        const key = std.fmt.bufPrint(&key_buf, "fill{d}", .{i}) catch unreachable;
        try store.bump(key, now);
    }
    try testing.expectEqual(Frecency.max_entries, store.count());
    try testing.expect(store.get("stale") != null);
    try store.bump("one-more", now);
    try testing.expectEqual(Frecency.max_entries, store.count());
    try testing.expect(store.get("stale") == null); // oldest evicted
    try testing.expect(store.get("one-more") != null);
}

test "frecency: zon round-trip through the settings dir" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = Frecency.init(testing.allocator);
    defer store.deinit();
    try store.bump("cmd:Connect to Server…", 100);
    try store.bump("cmd:Connect to Server…", 200);
    try store.bump("path:7:/var/www", 150);
    try store.save(io, tmp.dir, "palette.zon");

    var loaded = Frecency.init(testing.allocator);
    defer loaded.deinit();
    try loaded.load(io, tmp.dir, "palette.zon");

    try testing.expectEqual(@as(usize, 2), loaded.count());
    try testing.expectEqual(
        FrecencyEntry{ .count = 2, .last_used = 200 },
        loaded.get("cmd:Connect to Server…").?,
    );
    try testing.expectEqual(
        FrecencyEntry{ .count = 1, .last_used = 150 },
        loaded.get("path:7:/var/www").?,
    );

    // Save over the existing file: replaced atomically, still loadable.
    try loaded.bump("path:7:/var/www", 300);
    try loaded.save(io, tmp.dir, "palette.zon");
    var again = Frecency.init(testing.allocator);
    defer again.deinit();
    try again.load(io, tmp.dir, "palette.zon");
    try testing.expectEqual(@as(u32, 2), again.get("path:7:/var/www").?.count);
}

test "frecency: missing and corrupt files degrade to empty" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = Frecency.init(testing.allocator);
    defer store.deinit();
    try store.load(io, tmp.dir, "nope.zon");
    try testing.expectEqual(@as(usize, 0), store.count());

    const corrupt_inputs = [_][]const u8{
        "}{ not zon \x00\xff",
        ".{ .schema_version = 1, .entries = .{ .{ .unknown_field = 1 } } }",
        ".{ .entries = 42 }",
        "",
    };
    for (corrupt_inputs, 0..) |data, i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "bad{d}.zon", .{i}) catch unreachable;
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
        try store.load(io, tmp.dir, name);
        try testing.expectEqual(@as(usize, 0), store.count());
    }
}

test {
    testing.refAllDecls(@This());
}

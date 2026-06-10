//! transcript — per-connection ring buffer of protocol lines for the UI's
//! transcript pane and "copy transcript" support. Fixed memory: all storage
//! is allocated once at init (default ~20k lines × 256 bytes ≈ 5 MiB per
//! connection); append never allocates and never fails.
//!
//! REDACTION HAPPENS HERE, at append time — it is the engine's job, not the
//! UI's: once a secret is in the ring, every consumer (snapshot, export,
//! crash report) would see it.

const std = @import("std");

pub const Direction = enum(u8) { client, server, info };

pub const Options = struct {
    /// Lines retained; the oldest line is evicted on wraparound.
    capacity: usize = 20_000,
    /// Stored bytes per line; longer lines are truncated. RFC 959 caps
    /// control lines at 512 bytes; real traffic stays far below 256.
    max_line_bytes: usize = 256,
};

/// One transcript line as seen by consumers.
pub const Line = struct {
    /// Monotonic per-connection sequence number (0-based, never reused), so
    /// the UI can detect eviction gaps between snapshots.
    seq: u64,
    dir: Direction,
    /// Verbose lines (keepalive NOOPs, low-level chatter) are stored but
    /// hidden by the UI unless verbose mode is on.
    verbose: bool,
    text: []const u8,
};

pub const Transcript = struct {
    gpa: std.mem.Allocator,
    metas: []Meta,
    /// `metas.len * max_line_bytes` slab; slot i owns
    /// `text[i*max_line_bytes..][0..max_line_bytes]`.
    text: []u8,
    max_line_bytes: usize,
    /// Total lines ever appended == next seq to assign.
    next_seq: u64 = 0,
    /// Appends come from the connection worker, snapshots from the main
    /// thread; see events.zig for why a spin on `std.atomic.Mutex` is the
    /// lock of choice in 0.16 (no io-free blocking mutex in std).
    mutex: std.atomic.Mutex = .unlocked,

    const Meta = struct {
        seq: u64,
        dir: Direction,
        verbose: bool,
        len: u16,
    };

    pub fn init(gpa: std.mem.Allocator, options: Options) error{OutOfMemory}!Transcript {
        std.debug.assert(options.capacity > 0);
        std.debug.assert(options.max_line_bytes > 0 and options.max_line_bytes <= std.math.maxInt(u16));
        const metas = try gpa.alloc(Meta, options.capacity);
        errdefer gpa.free(metas);
        const text = try gpa.alloc(u8, options.capacity * options.max_line_bytes);
        return .{
            .gpa = gpa,
            .metas = metas,
            .text = text,
            .max_line_bytes = options.max_line_bytes,
        };
    }

    pub fn deinit(self: *Transcript) void {
        self.gpa.free(self.metas);
        self.gpa.free(self.text);
        self.* = undefined;
    }

    /// Records one protocol line: strips trailing CR/LF, redacts secrets
    /// (see `redact`), truncates to `max_line_bytes`, evicts the oldest
    /// line when full. Never allocates, never fails. Thread-safe.
    pub fn append(self: *Transcript, dir: Direction, verbose: bool, line: []const u8) void {
        const trimmed = std.mem.trimEnd(u8, line, "\r\n");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const slot: usize = @intCast(self.next_seq % self.metas.len);
        const dst = self.text[slot * self.max_line_bytes ..][0..self.max_line_bytes];
        const stored = redact(dir, trimmed, dst);
        self.metas[slot] = .{
            .seq = self.next_seq,
            .dir = dir,
            .verbose = verbose,
            .len = @intCast(stored.len),
        };
        self.next_seq += 1;
    }

    /// Lines currently retained (≤ capacity).
    pub fn count(self: *Transcript) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return @intCast(@min(self.next_seq, self.metas.len));
    }

    pub const Snapshot = struct {
        /// Oldest → newest.
        lines: []const Line,
        slab: []u8,

        pub fn deinit(self: *Snapshot, gpa: std.mem.Allocator) void {
            gpa.free(self.lines);
            gpa.free(self.slab);
            self.* = undefined;
        }
    };

    /// Copies the retained lines (oldest → newest) for the UI. The result
    /// is independent of the ring; appends may continue concurrently.
    /// Allocates while holding the lock — snapshots are rare (transcript
    /// pane open/refresh) and producers spin for at most one alloc.
    pub fn snapshot(self: *Transcript, gpa: std.mem.Allocator) error{OutOfMemory}!Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const cap = self.metas.len;
        const n: usize = @intCast(@min(self.next_seq, cap));
        const start: usize = if (self.next_seq <= cap) 0 else @intCast(self.next_seq % cap);

        const lines = try gpa.alloc(Line, n);
        errdefer gpa.free(lines);
        var total: usize = 0;
        for (0..n) |i| total += self.metas[(start + i) % cap].len;
        const slab = try gpa.alloc(u8, total);

        var offset: usize = 0;
        for (0..n) |i| {
            const slot = (start + i) % cap;
            const meta = self.metas[slot];
            const src = self.text[slot * self.max_line_bytes ..][0..meta.len];
            @memcpy(slab[offset..][0..meta.len], src);
            lines[i] = .{
                .seq = meta.seq,
                .dir = meta.dir,
                .verbose = meta.verbose,
                .text = slab[offset..][0..meta.len],
            };
            offset += meta.len;
        }
        return .{ .lines = lines, .slab = slab };
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

/// Copies `line` into `dst` (truncating to `dst.len`), masking secret
/// material:
/// - client `PASS <arg>` / `ACCT <arg>` → `PASS ****` (FTP login secrets)
/// - any direction: text after a colon that follows "passphrase"
///   (case-insensitive) → `... passphrase: ****` (key decryption prompts)
/// Returns the stored slice (a prefix of `dst`).
pub fn redact(dir: Direction, line: []const u8, dst: []u8) []u8 {
    if (dir == .client) {
        if (secretCommandLen(line)) |cmd_len| {
            return maskAfter(dst, line[0..cmd_len]);
        }
    }
    if (std.ascii.indexOfIgnoreCase(line, "passphrase")) |idx| {
        if (std.mem.indexOfScalarPos(u8, line, idx, ':')) |colon| {
            if (colon + 1 < line.len) return maskAfter(dst, line[0 .. colon + 1]);
        }
    }
    const n = @min(line.len, dst.len);
    @memcpy(dst[0..n], line[0..n]);
    return dst[0..n];
}

/// FTP commands whose argument is a secret. Returns the command length when
/// `line` is that command with a non-empty argument.
fn secretCommandLen(line: []const u8) ?usize {
    const commands = [_][]const u8{ "PASS", "ACCT" };
    for (commands) |cmd| {
        if (line.len > cmd.len + 1 and
            std.ascii.startsWithIgnoreCase(line, cmd) and
            line[cmd.len] == ' ')
        {
            return cmd.len;
        }
    }
    return null;
}

fn maskAfter(dst: []u8, visible: []const u8) []u8 {
    const mask = " ****";
    const vis_n = @min(visible.len, dst.len);
    @memcpy(dst[0..vis_n], visible[0..vis_n]);
    const mask_n = @min(mask.len, dst.len - vis_n);
    @memcpy(dst[vis_n..][0..mask_n], mask[0..mask_n]);
    return dst[0 .. vis_n + mask_n];
}

test "transcript: append, seq, direction, verbose, CRLF strip" {
    var transcript: Transcript = try .init(std.testing.allocator, .{ .capacity = 8, .max_line_bytes = 64 });
    defer transcript.deinit();

    transcript.append(.client, false, "USER fred\r\n");
    transcript.append(.server, false, "331 Please specify the password.\r\n");
    transcript.append(.info, true, "keepalive NOOP");
    try std.testing.expectEqual(@as(usize, 3), transcript.count());

    var snap = try transcript.snapshot(std.testing.allocator);
    defer snap.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), snap.lines.len);
    try std.testing.expectEqual(@as(u64, 0), snap.lines[0].seq);
    try std.testing.expectEqual(Direction.client, snap.lines[0].dir);
    try std.testing.expectEqualStrings("USER fred", snap.lines[0].text);
    try std.testing.expectEqualStrings("331 Please specify the password.", snap.lines[1].text);
    try std.testing.expectEqual(@as(u64, 2), snap.lines[2].seq);
    try std.testing.expect(snap.lines[2].verbose);
    try std.testing.expect(!snap.lines[1].verbose);
}

test "transcript: wraparound evicts oldest, keeps seq monotonic" {
    var transcript: Transcript = try .init(std.testing.allocator, .{ .capacity = 4, .max_line_bytes = 32 });
    defer transcript.deinit();

    var buf: [16]u8 = undefined;
    for (0..6) |i| {
        transcript.append(.server, false, try std.fmt.bufPrint(&buf, "line {d}", .{i}));
    }
    try std.testing.expectEqual(@as(usize, 4), transcript.count());

    var snap = try transcript.snapshot(std.testing.allocator);
    defer snap.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), snap.lines.len);
    for (snap.lines, 2..) |line, expected_seq| {
        try std.testing.expectEqual(@as(u64, @intCast(expected_seq)), line.seq);
        const expected = try std.fmt.bufPrint(&buf, "line {d}", .{expected_seq});
        try std.testing.expectEqualStrings(expected, line.text);
    }
}

test "transcript: redaction of PASS/ACCT args and passphrases at append time" {
    var transcript: Transcript = try .init(std.testing.allocator, .{ .capacity = 8, .max_line_bytes = 64 });
    defer transcript.deinit();

    transcript.append(.client, false, "PASS hunter2\r\n");
    transcript.append(.client, false, "pass hunter2"); // case-insensitive
    transcript.append(.client, false, "ACCT hunter2");
    transcript.append(.client, false, "PASV"); // PASS-prefixed but not PASS
    transcript.append(.server, false, "331 Please specify the password."); // server lines untouched
    transcript.append(.info, false, "unlocking key, Passphrase: hunter2");

    var snap = try transcript.snapshot(std.testing.allocator);
    defer snap.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("PASS ****", snap.lines[0].text);
    try std.testing.expectEqualStrings("pass ****", snap.lines[1].text);
    try std.testing.expectEqualStrings("ACCT ****", snap.lines[2].text);
    try std.testing.expectEqualStrings("PASV", snap.lines[3].text);
    try std.testing.expectEqualStrings("331 Please specify the password.", snap.lines[4].text);
    try std.testing.expectEqualStrings("unlocking key, Passphrase: ****", snap.lines[5].text);

    // Defense in depth: the secret must not survive anywhere in the ring.
    try std.testing.expect(std.mem.indexOf(u8, transcript.text, "hunter2") == null);
}

test "transcript: long lines are truncated to max_line_bytes" {
    var transcript: Transcript = try .init(std.testing.allocator, .{ .capacity = 2, .max_line_bytes = 8 });
    defer transcript.deinit();

    transcript.append(.server, false, "0123456789abcdef");
    transcript.append(.client, false, "PASS averylongsecret"); // mask still fits within cap

    var snap = try transcript.snapshot(std.testing.allocator);
    defer snap.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("01234567", snap.lines[0].text);
    try std.testing.expectEqualStrings("PASS ***", snap.lines[1].text);
    try std.testing.expect(std.mem.indexOf(u8, transcript.text, "secret") == null);
}

fn transcriptCycle(gpa: std.mem.Allocator) !void {
    var transcript: Transcript = try .init(gpa, .{ .capacity = 4, .max_line_bytes = 32 });
    defer transcript.deinit();
    transcript.append(.client, false, "USER fred");
    transcript.append(.client, false, "PASS hunter2");
    var snap = try transcript.snapshot(gpa);
    defer snap.deinit(gpa);
    if (snap.lines.len != 2) return error.TestUnexpectedResult;
}

test "transcript: allocation failures neither leak nor corrupt" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, transcriptCycle, .{});
}

test {
    std.testing.refAllDecls(@This());
}

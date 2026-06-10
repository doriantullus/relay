//! reply — RFC 959 control-channel reply parser.
//!
//! Reads exactly one complete server reply (single- or multi-line) from a
//! `*std.Io.Reader`. Wire tolerance, all observed on real servers:
//!
//! - bare-LF line terminators (CR is optional, stripped when present);
//! - telnet IAC sequences embedded in reply text are stripped
//!   (`IAC IAC` unescapes to a literal 0xFF; `IAC WILL/WONT/DO/DONT opt`
//!   drops three bytes; any other `IAC x` drops two; subnegotiation
//!   `IAC SB … IAC SE` is not state-tracked — no FTP server emits it);
//! - a missing trailing newline before EOF still yields the final line;
//! - `"ddd"` with no text is accepted both as a one-line reply and as a
//!   multi-line terminator.
//!
//! Multi-line replies follow RFC 959 4.2: the reply ends at a line that
//! starts with the *same* three digits followed by a space; intermediate
//! lines may start with anything, including other digit sequences.
//!
//! The reply size is hard-capped (`Limits`) so a hostile server cannot make
//! the client buffer unbounded reply text: exceeding the cap is
//! `error.ProtocolViolation`.

const std = @import("std");
const CancelToken = @import("../../cancel.zig").CancelToken;
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const ErrorClass = diag_mod.ErrorClass;

pub const Error = error{
    Canceled,
    /// Control connection dropped (read failure or EOF mid-reply).
    ConnectionLost,
    /// Malformed reply syntax or a reply exceeding `Limits`.
    ProtocolViolation,
    OutOfMemory,
};

/// Memory DoS guard for one reply.
pub const Limits = struct {
    /// Cap on the summed wire length of all lines of one reply.
    max_total_bytes: usize = 16 * 1024,
    /// Cap on the number of lines of one multi-line reply.
    max_lines: usize = 64,
};

pub const Reply = struct {
    code: u16,
    /// Reply text, one slice per line, arena-owned. Terminators and telnet
    /// IAC sequences are removed; the `"ddd-"`/`"ddd "` prefix is stripped
    /// from lines that carry this reply's code (intermediate lines that
    /// don't are kept verbatim).
    lines: []const []const u8,

    /// 2xx — positive completion.
    pub fn isPositive(self: Reply) bool {
        return self.code / 100 == 2;
    }

    /// 3xx — positive intermediate (more commands expected, e.g. 331).
    pub fn isIntermediate(self: Reply) bool {
        return self.code / 100 == 3;
    }

    /// 4xx — transient negative completion.
    pub fn isTransientErr(self: Reply) bool {
        return self.code / 100 == 4;
    }

    /// 5xx — permanent negative completion.
    pub fn isPermanentErr(self: Reply) bool {
        return self.code / 100 == 5;
    }

    /// Retry/UI classification for this reply, null when it is not an
    /// error reply. See `errorClassOf`.
    pub fn errorClass(self: Reply) ?ErrorClass {
        return errorClassOf(self.code);
    }
};

/// Maps a negative reply code to the retry matrix in diag.zig:
/// 4xx auto-retry, 5xx never, except credential rejections (430/530/532)
/// which pause the site and raise one interactive prompt.
pub fn errorClassOf(code: u16) ?ErrorClass {
    return switch (code) {
        430, 530, 532 => .auth,
        else => switch (code / 100) {
            4 => .transient,
            5 => .permanent,
            else => null,
        },
    };
}

/// Reads one reply with default `Limits`. `arena` owns the result; the
/// caller resets it per command (arena-per-result, no individual frees).
pub fn read(
    arena: std.mem.Allocator,
    r: *std.Io.Reader,
    cancel: *CancelToken,
    diag: *Diagnostics,
) Error!Reply {
    return readLimited(arena, r, .{}, cancel, diag);
}

pub fn readLimited(
    arena: std.mem.Allocator,
    r: *std.Io.Reader,
    limits: Limits,
    cancel: *CancelToken,
    diag: *Diagnostics,
) Error!Reply {
    var total: usize = 0;
    var lines: std.ArrayList([]const u8) = .empty;

    try checkCancel(cancel, diag);
    const first = try nextLine(arena, r, limits, &total, diag);
    const code = parseCode(first) orelse return violation(diag, first);

    if (first.len == 3) {
        // Tolerated: code with no text and no separator.
        try lines.append(arena, first[3..]);
        return .{ .code = code, .lines = lines.items };
    }
    switch (first[3]) {
        ' ' => {
            try lines.append(arena, first[4..]);
            return .{ .code = code, .lines = lines.items };
        },
        '-' => {},
        else => return violation(diag, first),
    }

    try lines.append(arena, first[4..]);
    while (true) {
        try checkCancel(cancel, diag);
        if (lines.items.len >= limits.max_lines) {
            diag.set(.permanent, code, "reply exceeded {d} lines", .{limits.max_lines});
            return error.ProtocolViolation;
        }
        const line = try nextLine(arena, r, limits, &total, diag);
        if (line.len >= 3 and std.mem.eql(u8, line[0..3], first[0..3])) {
            if (line.len == 3) {
                // Tolerated: bare "ddd" terminator.
                try lines.append(arena, line[3..]);
                break;
            }
            if (line[3] == ' ') {
                try lines.append(arena, line[4..]);
                break;
            }
            if (line[3] == '-') {
                // Server prefixes every continuation line with "ddd-".
                try lines.append(arena, line[4..]);
                continue;
            }
        }
        try lines.append(arena, line);
    }
    return .{ .code = code, .lines = lines.items };
}

fn checkCancel(cancel: *CancelToken, diag: *Diagnostics) error{Canceled}!void {
    cancel.check() catch |err| {
        diag.set(.cancel, 0, "canceled while reading reply", .{});
        return err;
    };
}

fn violation(diag: *Diagnostics, line: []const u8) error{ProtocolViolation} {
    diag.set(.permanent, 0, "malformed reply line: \"{s}\"", .{line[0..@min(line.len, 100)]});
    return error.ProtocolViolation;
}

/// "ddd" with d0 in 1-5 (RFC 959 reply code space), else null.
fn parseCode(line: []const u8) ?u16 {
    if (line.len < 3) return null;
    if (line[0] < '1' or line[0] > '5') return null;
    if (!std.ascii.isDigit(line[1]) or !std.ascii.isDigit(line[2])) return null;
    return @as(u16, line[0] - '0') * 100 + @as(u16, line[1] - '0') * 10 + (line[2] - '0');
}

/// Takes one line off the wire and returns an arena copy with the trailing
/// CR and telnet IAC sequences removed.
fn nextLine(
    arena: std.mem.Allocator,
    r: *std.Io.Reader,
    limits: Limits,
    total: *usize,
    diag: *Diagnostics,
) Error![]u8 {
    const raw = r.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream, error.ReadFailed => {
            diag.set(.transient, 0, "control connection lost mid-reply", .{});
            return error.ConnectionLost;
        },
        // Line longer than the reader's buffer capacity.
        error.StreamTooLong => {
            diag.set(.permanent, 0, "reply line exceeds buffer capacity", .{});
            return error.ProtocolViolation;
        },
    };
    total.* += raw.len + 1;
    if (total.* > limits.max_total_bytes) {
        diag.set(.permanent, 0, "reply exceeded {d} bytes", .{limits.max_total_bytes});
        return error.ProtocolViolation;
    }
    const line = try stripLine(arena, raw);
    // takeDelimiterExclusive stops *at* the delimiter; consume it. At EOF
    // (line ended by stream end instead) there is nothing buffered to toss.
    const buffered = r.buffered();
    if (buffered.len != 0 and buffered[0] == '\n') r.toss(1);
    return line;
}

const iac = 0xff;

/// Arena copy of `raw` without trailing CR and with IAC sequences removed.
fn stripLine(arena: std.mem.Allocator, raw_in: []const u8) error{OutOfMemory}![]u8 {
    var raw = raw_in;
    if (raw.len != 0 and raw[raw.len - 1] == '\r') raw = raw[0 .. raw.len - 1];
    // Exact-size arena allocation: count first, then copy.
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] != iac) {
            n += 1;
            i += 1;
        } else if (i + 1 < raw.len and raw[i + 1] == iac) {
            n += 1;
            i += 2;
        } else {
            i += iacSkip(raw[i..]);
        }
    }
    const out = try arena.alloc(u8, n);
    var o: usize = 0;
    i = 0;
    while (i < raw.len) {
        if (raw[i] != iac) {
            out[o] = raw[i];
            o += 1;
            i += 1;
        } else if (i + 1 < raw.len and raw[i + 1] == iac) {
            out[o] = iac;
            o += 1;
            i += 2;
        } else {
            i += iacSkip(raw[i..]);
        }
    }
    return out;
}

/// Length of the IAC sequence at the start of `rest` (rest[0] == IAC,
/// not an escaped IAC IAC). Truncated sequences at end of line are dropped.
fn iacSkip(rest: []const u8) usize {
    if (rest.len < 2) return rest.len;
    return switch (rest[1]) {
        // WILL, WONT, DO, DONT carry an option byte.
        251...254 => @min(rest.len, 3),
        else => 2,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn readFromSlice(arena: std.mem.Allocator, input: []const u8, diag: *Diagnostics) Error!Reply {
    var reader: std.Io.Reader = .fixed(input);
    var cancel: CancelToken = .{};
    return read(arena, &reader, &cancel, diag);
}

test "single line reply, CRLF" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "226 Transfer complete.\r\n", &diag);
    try testing.expectEqual(@as(u16, 226), reply.code);
    try testing.expectEqual(@as(usize, 1), reply.lines.len);
    try testing.expectEqualStrings("Transfer complete.", reply.lines[0]);
    try testing.expect(reply.isPositive());
    try testing.expect(!reply.isIntermediate());
    try testing.expectEqual(@as(?ErrorClass, null), reply.errorClass());
}

test "single line reply, bare LF" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "220 ready\n", &diag);
    try testing.expectEqual(@as(u16, 220), reply.code);
    try testing.expectEqualStrings("ready", reply.lines[0]);
}

test "code-only reply" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "421\r\n", &diag);
    try testing.expectEqual(@as(u16, 421), reply.code);
    try testing.expectEqualStrings("", reply.lines[0]);
    try testing.expect(reply.isTransientErr());
    try testing.expectEqual(@as(?ErrorClass, .transient), reply.errorClass());
}

test "missing trailing newline at EOF still yields the reply" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "200 done", &diag);
    try testing.expectEqual(@as(u16, 200), reply.code);
    try testing.expectEqualStrings("done", reply.lines[0]);
}

test "multiline reply per RFC 959, digit-leading intermediate lines" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "123-First line\r\n" ++
        "Second line\r\n" ++
        "  234 A line beginning with numbers\r\n" ++
        "456 not a terminator either\r\n" ++
        "123 The last line\r\n", &diag);
    try testing.expectEqual(@as(u16, 123), reply.code);
    try testing.expectEqual(@as(usize, 5), reply.lines.len);
    try testing.expectEqualStrings("First line", reply.lines[0]);
    try testing.expectEqualStrings("Second line", reply.lines[1]);
    try testing.expectEqualStrings("  234 A line beginning with numbers", reply.lines[2]);
    try testing.expectEqualStrings("456 not a terminator either", reply.lines[3]);
    try testing.expectEqualStrings("The last line", reply.lines[4]);
}

test "multiline reply with ddd- prefix on every continuation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = try readFromSlice(arena_inst.allocator(), "226-Options: -a -l\r\n226-12 matches total\r\n226 Done\r\n", &diag);
    try testing.expectEqual(@as(u16, 226), reply.code);
    try testing.expectEqual(@as(usize, 3), reply.lines.len);
    try testing.expectEqualStrings("Options: -a -l", reply.lines[0]);
    try testing.expectEqualStrings("12 matches total", reply.lines[1]);
    try testing.expectEqualStrings("Done", reply.lines[2]);
}

test "multiline reply does not stop reading at a fixed-buffer boundary" {
    // Two replies back to back: only the first must be consumed.
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    var reader: std.Io.Reader = .fixed("230-Welcome\r\n230 Logged in\r\n200 NOOP ok\r\n");
    var cancel: CancelToken = .{};
    const reply = try read(arena_inst.allocator(), &reader, &cancel, &diag);
    try testing.expectEqual(@as(u16, 230), reply.code);
    try testing.expectEqual(@as(usize, 2), reply.lines.len);
    const next = try read(arena_inst.allocator(), &reader, &cancel, &diag);
    try testing.expectEqual(@as(u16, 200), next.code);
    try testing.expectEqualStrings("NOOP ok", next.lines[0]);
}

test "telnet IAC sequences are stripped" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    // IAC DO 6 mid-text, IAC IAC escape, IAC IP (two-byte), trailing lone IAC.
    const reply = try readFromSlice(arena_inst.allocator(), "200 ok\xff\xfd\x06done a\xff\xffb\xff\xf4tail\xff\r\n", &diag);
    try testing.expectEqual(@as(u16, 200), reply.code);
    try testing.expectEqualStrings("okdone a\xffbtail", reply.lines[0]);
}

test "EOF mid-reply is ConnectionLost, transient" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.ConnectionLost,
        readFromSlice(arena_inst.allocator(), "230-Welcome\r\n", &diag),
    );
    try testing.expectEqual(ErrorClass.transient, diag.class);
}

test "empty stream is ConnectionLost" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    try testing.expectError(error.ConnectionLost, readFromSlice(arena_inst.allocator(), "", &diag));
}

test "garbage first lines are ProtocolViolation, permanent" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    for ([_][]const u8{
        "garbage\r\n",
        "12x hello\r\n",
        "672 out of code space\r\n",
        "20\r\n",
        "200xtext\r\n",
        "\r\n",
    }) |input| {
        var diag: Diagnostics = .{};
        try testing.expectError(
            error.ProtocolViolation,
            readFromSlice(arena_inst.allocator(), input, &diag),
        );
        try testing.expectEqual(ErrorClass.permanent, diag.class);
    }
}

test "reply line longer than reader buffer is ProtocolViolation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    var cancel: CancelToken = .{};
    var buf: [16]u8 = undefined;
    var source: testing.Reader = .init(&buf, &.{
        .{ .buffer = "220 this line is much longer than sixteen bytes\r\n" },
    });
    try testing.expectError(
        error.ProtocolViolation,
        read(arena_inst.allocator(), &source.interface, &cancel, &diag),
    );
    try testing.expectEqual(ErrorClass.permanent, diag.class);
}

test "total reply size cap" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    var reader: std.Io.Reader = .fixed("220-0123456789abcdef\r\n0123456789abcdef\r\n220 ok\r\n");
    var cancel: CancelToken = .{};
    try testing.expectError(error.ProtocolViolation, readLimited(
        arena_inst.allocator(),
        &reader,
        .{ .max_total_bytes = 32 },
        &cancel,
        &diag,
    ));
}

test "line count cap" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    var reader: std.Io.Reader = .fixed("220-a\r\nb\r\nc\r\nd\r\n220 ok\r\n");
    var cancel: CancelToken = .{};
    try testing.expectError(error.ProtocolViolation, readLimited(
        arena_inst.allocator(),
        &reader,
        .{ .max_lines = 3 },
        &cancel,
        &diag,
    ));
}

test "pre-canceled token" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    var reader: std.Io.Reader = .fixed("226 Done\r\n");
    var cancel: CancelToken = .{};
    cancel.cancel();
    try testing.expectError(
        error.Canceled,
        read(arena_inst.allocator(), &reader, &cancel, &diag),
    );
    try testing.expectEqual(ErrorClass.cancel, diag.class);
}

test "errorClassOf retry matrix mapping" {
    try testing.expectEqual(@as(?ErrorClass, .transient), errorClassOf(421));
    try testing.expectEqual(@as(?ErrorClass, .transient), errorClassOf(450));
    try testing.expectEqual(@as(?ErrorClass, .permanent), errorClassOf(550));
    try testing.expectEqual(@as(?ErrorClass, .permanent), errorClassOf(502));
    try testing.expectEqual(@as(?ErrorClass, .auth), errorClassOf(530));
    try testing.expectEqual(@as(?ErrorClass, .auth), errorClassOf(430));
    try testing.expectEqual(@as(?ErrorClass, .auth), errorClassOf(532));
    try testing.expectEqual(@as(?ErrorClass, null), errorClassOf(226));
    try testing.expectEqual(@as(?ErrorClass, null), errorClassOf(331));
    try testing.expectEqual(@as(?ErrorClass, null), errorClassOf(150));
}

fn testReadAllocs(gpa: std.mem.Allocator, input: []const u8) !void {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = readFromSlice(arena_inst.allocator(), input, &diag) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    if (reply.lines.len == 0) return error.TestUnexpectedResult;
}

test "read survives all allocation failures" {
    try testing.checkAllAllocationFailures(
        testing.allocator,
        testReadAllocs,
        .{"230-Welcome to\r\nthe machine\r\n230 ok\r\n"},
    );
    try testing.checkAllAllocationFailures(
        testing.allocator,
        testReadAllocs,
        .{"226 Done\xff\xff now\r\n"},
    );
}

fn fuzzReply(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];

    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var diag: Diagnostics = .{};
    const reply = readFromSlice(arena_inst.allocator(), input, &diag) catch |err| switch (err) {
        error.Canceled => unreachable, // token is never canceled here
        error.ConnectionLost, error.ProtocolViolation, error.OutOfMemory => return,
    };
    // Parsed replies always satisfy the documented invariants.
    try testing.expect(reply.code >= 100 and reply.code <= 599);
    try testing.expect(reply.lines.len >= 1);
    for (reply.lines) |line| {
        try testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
        try testing.expect(std.mem.indexOfScalar(u8, line, '\r') == null);
    }
}

test "fuzz reply parser" {
    try testing.fuzz({}, fuzzReply, .{ .corpus = &.{
        "226 Transfer complete.\r\n",
        "230-Welcome\r\n 230 not done\r\n230 done\r\n",
        "421\n",
        "550 Failed\xff\xfb\x01\r\n",
    } });
}

test {
    std.testing.refAllDecls(@This());
}

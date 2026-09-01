//! Toolkit-free transcript model shared by native frontends.

const std = @import("std");
const relay = @import("relay_core");

const Allocator = std.mem.Allocator;

pub const ring_capacity: usize = 20_000;
pub const max_line_bytes: usize = 512;

pub const LineKind = enum(u2) { client, server, err, info };

pub fn classifyLine(dir: relay.transcript.Direction, text: []const u8) LineKind {
    switch (dir) {
        .client => return .client,
        .server => {
            if (text.len >= 3 and (text[0] == '4' or text[0] == '5') and
                std.ascii.isDigit(text[1]) and std.ascii.isDigit(text[2]))
                return .err;
            return .server;
        },
        .info => {
            if (std.ascii.startsWithIgnoreCase(text, "error")) return .err;
            return .info;
        },
    }
}

pub fn sanitizeUtf8(src: []const u8, dst: []u8) []const u8 {
    std.debug.assert(dst.len >= src.len);
    var i: usize = 0;
    var n: usize = 0;
    while (i < src.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(src[i]) catch {
            dst[n] = '?';
            n += 1;
            i += 1;
            continue;
        };
        if (i + seq_len > src.len or !std.unicode.utf8ValidateSlice(src[i..][0..seq_len])) {
            dst[n] = '?';
            n += 1;
            i += 1;
            continue;
        }
        @memcpy(dst[n..][0..seq_len], src[i..][0..seq_len]);
        n += seq_len;
        i += seq_len;
    }
    return dst[0..n];
}

pub fn isAtBottom(doc_height: f64, clip_origin_y: f64, clip_height: f64, slack: f64) bool {
    return doc_height - (clip_origin_y + clip_height) <= slack;
}

pub const Model = struct {
    pub const Line = struct {
        conn: u64,
        kind: LineKind,
        utf16_len: u32,
        text: []u8,
    };

    pub const Appended = struct {
        visible: bool,
        new_conn: bool,
        trimmed_lines: usize = 0,
        trimmed_visible_utf16: u64 = 0,
    };

    gpa: Allocator,
    capacity: usize,
    lines: std.ArrayList(Line) = .empty,
    head: usize = 0,
    compact_threshold: usize = 4096,
    conns: std.AutoArrayHashMapUnmanaged(u64, void) = .empty,

    pub fn init(gpa: Allocator, capacity: usize) Model {
        std.debug.assert(capacity > 0);
        return .{ .gpa = gpa, .capacity = capacity };
    }

    pub fn deinit(self: *Model) void {
        for (self.live()) |line| self.gpa.free(line.text);
        self.lines.deinit(self.gpa);
        self.conns.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Model) usize {
        return self.lines.items.len - self.head;
    }

    pub fn live(self: *const Model) []const Line {
        return self.lines.items[self.head..];
    }

    pub fn connCount(self: *const Model) usize {
        return self.conns.count();
    }

    pub fn connAt(self: *const Model, index: usize) u64 {
        return self.conns.keys()[index];
    }

    pub fn matchesFilter(line: Line, filter: ?u64) bool {
        const want = filter orelse return true;
        return line.conn == want;
    }

    pub fn append(
        self: *Model,
        conn: u64,
        kind: LineKind,
        raw: []const u8,
        filter: ?u64,
    ) error{OutOfMemory}!Appended {
        const trimmed_input = std.mem.trimEnd(u8, raw, "\r\n");
        const capped = trimmed_input[0..@min(trimmed_input.len, max_line_bytes)];
        var buf: [max_line_bytes]u8 = undefined;
        const clean = sanitizeUtf8(capped, &buf);
        const utf16_len = std.unicode.calcUtf16LeLen(clean) catch unreachable;

        const text = try self.gpa.dupe(u8, clean);
        errdefer self.gpa.free(text);
        const gop = try self.conns.getOrPut(self.gpa, conn);
        const line: Line = .{
            .conn = conn,
            .kind = kind,
            .utf16_len = @intCast(utf16_len),
            .text = text,
        };
        try self.lines.append(self.gpa, line);

        var result: Appended = .{
            .visible = matchesFilter(line, filter),
            .new_conn = !gop.found_existing,
        };
        while (self.count() > self.capacity) {
            const dropped = self.lines.items[self.head];
            if (matchesFilter(dropped, filter)) {
                result.trimmed_visible_utf16 += @as(u64, dropped.utf16_len) + 1;
            }
            result.trimmed_lines += 1;
            self.gpa.free(dropped.text);
            self.head += 1;
        }
        if (self.head >= self.compact_threshold) self.compact();
        return result;
    }

    fn compact(self: *Model) void {
        const n = self.count();
        std.mem.copyForwards(Line, self.lines.items[0..n], self.lines.items[self.head..]);
        self.lines.shrinkRetainingCapacity(n);
        self.head = 0;
    }

    pub fn visibleText(self: *const Model, gpa: Allocator, filter: ?u64) error{OutOfMemory}![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (self.live()) |line| {
            if (!matchesFilter(line, filter)) continue;
            try out.appendSlice(gpa, line.text);
            try out.append(gpa, '\n');
        }
        return out.toOwnedSlice(gpa);
    }
};

test "append trims the ring and preserves filter accounting" {
    var model = Model.init(std.testing.allocator, 2);
    defer model.deinit();
    _ = try model.append(1, .client, "one", 1);
    _ = try model.append(2, .server, "two", 1);
    const result = try model.append(1, .err, "three", 1);
    try std.testing.expectEqual(@as(usize, 2), model.count());
    try std.testing.expectEqual(@as(usize, 1), result.trimmed_lines);
    try std.testing.expectEqual(@as(u64, 4), result.trimmed_visible_utf16);
    const text = try model.visibleText(std.testing.allocator, 1);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("three\n", text);
}

test "UTF-8 sanitation, classification, and follow-tail geometry" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("a?b", sanitizeUtf8("a\xc3b", &buf));
    try std.testing.expectEqual(LineKind.err, classifyLine(.server, "550 missing"));
    try std.testing.expectEqual(LineKind.err, classifyLine(.info, "ERROR: failed"));
    try std.testing.expect(isAtBottom(1000, 799, 200, 2));
    try std.testing.expect(!isAtBottom(1000, 500, 200, 2));
}

test {
    std.testing.refAllDecls(@This());
}

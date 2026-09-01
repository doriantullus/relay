//! Toolkit-neutral palette candidate store and fuzzy ranking model.

const std = @import("std");
const fuzzy = @import("fuzzy.zig");

const Allocator = std.mem.Allocator;

/// Candidate is supplied by the frontend because command identifiers and
/// shortcut presentation belong to its command system. It must expose the
/// string fields `title`, `hint`, `key`, and `path`.
pub fn Model(comptime Candidate: type, comptime max_results: usize) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        arena: std.heap.ArenaAllocator,
        candidates: std.ArrayList(Candidate) = .empty,
        matcher: fuzzy.Matcher = .{},
        ranked_buf: [max_results]fuzzy.Ranked = undefined,
        results: [max_results]fuzzy.Ranked = undefined,
        result_len: usize = 0,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa, .arena = .init(gpa) };
        }

        pub fn deinit(self: *Self) void {
            self.candidates.deinit(self.gpa);
            self.arena.deinit();
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            _ = self.arena.reset(.retain_capacity);
            self.candidates.clearRetainingCapacity();
            self.result_len = 0;
        }

        pub fn add(self: *Self, candidate: Candidate) error{OutOfMemory}!void {
            const arena = self.arena.allocator();
            var copy = candidate;
            copy.title = try arena.dupe(u8, candidate.title);
            copy.hint = try arena.dupe(u8, candidate.hint);
            copy.key = try arena.dupe(u8, candidate.key);
            copy.path = try arena.dupe(u8, candidate.path);
            try self.candidates.append(self.gpa, copy);
        }

        pub fn hasKey(self: *const Self, key: []const u8) bool {
            for (self.candidates.items) |candidate| {
                if (std.mem.eql(u8, candidate.key, key)) return true;
            }
            return false;
        }

        pub fn filter(self: *Self, query: []const u8, frecency: *const fuzzy.Frecency, now: i64) void {
            var top = fuzzy.TopList.init(&self.ranked_buf);
            for (self.candidates.items, 0..) |candidate, i| {
                const match = self.matcher.match(query, candidate.title) orelse continue;
                const boost = if (candidate.key.len > 0) frecency.boost(candidate.key, now) else 1.0;
                top.consider(.{ .index = i, .score = fuzzy.rank(match.score, boost) });
            }
            const items = top.items();
            @memcpy(self.results[0..items.len], items);
            self.result_len = items.len;
        }

        pub fn resultCount(self: *const Self) usize {
            return self.result_len;
        }

        pub fn resultAt(self: *const Self, row: usize) ?*const Candidate {
            if (row >= self.result_len) return null;
            return &self.candidates.items[self.results[row].index];
        }
    };
}

test "model deep-copies, deduplicates, and ranks candidates" {
    const Candidate = struct {
        title: []const u8,
        hint: []const u8 = "",
        key: []const u8 = "",
        path: []const u8 = "",
    };
    const TestModel = Model(Candidate, 4);
    var model = TestModel.init(std.testing.allocator);
    defer model.deinit();
    var title = [_]u8{ 'O', 'p', 'e', 'n' };
    try model.add(.{ .title = &title, .key = "command:open" });
    title[0] = 'X';
    try model.add(.{ .title = "Close", .key = "command:close" });
    try std.testing.expect(model.hasKey("command:open"));

    var frecency = fuzzy.Frecency.init(std.testing.allocator);
    defer frecency.deinit();
    model.filter("op", &frecency, 0);
    try std.testing.expectEqual(@as(usize, 1), model.resultCount());
    try std.testing.expectEqualStrings("Open", model.resultAt(0).?.title);
}

test {
    std.testing.refAllDecls(@This());
}

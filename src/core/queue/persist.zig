//! persist — transfer queue state ↔ ZON on disk, plus the debounce gate the
//! engine's timer thread uses for autosaves.
//!
//! Only pending (queued/active-as-queued/paused) and failed items are
//! persisted; done and canceled items are history, not work. A corrupt or
//! missing file yields a clean empty queue — losing the queue is annoying,
//! crashing on startup is unacceptable.

const std = @import("std");
const settings = @import("../settings/settings.zig");
const item_mod = @import("item.zig");

pub const PersistedState = enum { queued, paused, failed };

pub const PersistedItem = struct {
    id: u64,
    direction: item_mod.Direction = .download,
    kind: item_mod.Kind = .file,
    src_site: u64 = item_mod.local_site_id,
    src_path: []const u8,
    dst_site: u64 = item_mod.local_site_id,
    dst_path: []const u8,
    conflict: item_mod.ConflictPolicy = .overwrite,
    /// Folder item that spawned this one; 0 = top-level.
    parent: u64 = 0,
    state: PersistedState = .queued,
    /// 0 = unknown.
    bytes_total: u64 = 0,
    attempts: u32 = 0,
};

pub const PersistedQueue = struct {
    /// Bump on incompatible layout changes; `parse` rejects unknown fields.
    schema_version: u32 = 1,
    items: []const PersistedItem = &.{},
};

/// Parse result; all slices owned by one arena (arena-per-result rule).
pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    value: PersistedQueue,

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
    const value = try std.zon.parse.fromSliceAlloc(PersistedQueue, arena.allocator(), source, null, .{
        .free_on_error = false,
    });
    return .{ .arena = arena, .value = value };
}

pub fn serialize(queue: PersistedQueue, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try std.zon.stringify.serialize(queue, .{}, writer);
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

/// Resume-on-start entry point: any failure (missing file, corruption,
/// truncation, OOM) degrades to an empty queue. Never errors, never crashes.
pub fn loadOrEmpty(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) Parsed {
    return load(io, dir, sub_path, gpa) catch .{ .arena = .init(gpa), .value = .{} };
}

/// Atomic (temp file + fsync + rename); see settings.atomicWriteFile.
pub fn save(
    queue: PersistedQueue,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    gpa: std.mem.Allocator,
) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // The Allocating writer only fails on OOM.
    serialize(queue, &out.writer) catch return error.OutOfMemory;
    try settings.atomicWriteFile(io, dir, sub_path, out.written());
}

/// Debounce gate for autosave: any number of `markDirty` calls collapse
/// into one save `interval_ns` after the first of the burst. `markDirty`
/// is callable from any thread; `poll` from exactly one (the timer).
pub const Debounce = struct {
    interval_ns: u64,
    dirty: std.atomic.Value(bool) = .init(false),
    // Poll-thread private.
    armed: bool = false,
    deadline_ns: i96 = 0,

    pub fn markDirty(self: *Debounce) void {
        self.dirty.store(true, .release);
    }

    /// Returns true when a save is due; consumes the dirty flag. A
    /// `markDirty` racing the consume simply re-arms on the next poll.
    pub fn poll(self: *Debounce, now_ns: i96) bool {
        if (!self.armed) {
            if (!self.dirty.load(.acquire)) return false;
            self.armed = true;
            self.deadline_ns = now_ns + self.interval_ns;
            return false;
        }
        if (now_ns < self.deadline_ns) return false;
        self.armed = false;
        return self.dirty.swap(false, .acq_rel);
    }
};

const test_queue: PersistedQueue = .{
    .items = &.{
        .{
            .id = 1,
            .direction = .download,
            .src_site = 4,
            .src_path = "/remote/report.pdf",
            .dst_path = "/Users/x/Downloads/report.pdf",
            .state = .queued,
            .bytes_total = 123_456,
        },
        .{
            .id = 2,
            .direction = .upload,
            .kind = .folder,
            .src_path = "/Users/x/site",
            .dst_site = 4,
            .dst_path = "/var/www",
            .conflict = .resume_existing,
            .state = .paused,
        },
        .{
            .id = 3,
            .direction = .upload,
            .src_path = "/Users/x/site/index.html",
            .dst_site = 4,
            .dst_path = "/var/www/index.html",
            .parent = 2,
            .state = .failed,
            .attempts = 3,
        },
    },
};

test "persist: zon round trip preserves every field" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(test_queue, &out.writer);

    const source = try std.testing.allocator.dupeZ(u8, out.written());
    defer std.testing.allocator.free(source);
    var parsed = try parse(std.testing.allocator, source);
    defer parsed.deinit();
    try std.testing.expectEqualDeep(test_queue, parsed.value);
}

test "persist: corrupt input is a graceful error, never a crash" {
    const corrupt_inputs = [_][:0]const u8{
        "garbage{{{",
        ".{ .items = 42 }",
        ".{ .items = .{ .{ .id = 1 } } }", // missing required paths
        ".{ .items = .{ .{ .id = \"x\", .src_path = \"a\", .dst_path = \"b\" } } }",
        ".{ .items = .{ .{ .id = 1, .src_path = \"a\", .dst_path = \"b\", .state = .exploded } } }",
        ".{ .bogus = true }",
        "",
        "\x00\xff\xfe binary junk",
    };
    for (corrupt_inputs) |source| {
        try std.testing.expectError(error.ParseZon, parse(std.testing.allocator, source));
    }
}

fn parseCycle(gpa: std.mem.Allocator, source: [:0]const u8) !void {
    var parsed = try parse(gpa, source);
    defer parsed.deinit();
    if (parsed.value.items.len != 3) return error.TestUnexpectedResult;
}

test "persist: parser survives allocation failure at every point" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serialize(test_queue, &out.writer);
    const source = try std.testing.allocator.dupeZ(u8, out.written());
    defer std.testing.allocator.free(source);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseCycle, .{
        @as([:0]const u8, source),
    });
}

test "persist: atomic save + load round-trips on disk" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "queue.zon", .data = "stale garbage" });
    try save(test_queue, io, tmp.dir, "queue.zon", std.testing.allocator);

    var loaded = try load(io, tmp.dir, "queue.zon", std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expectEqualDeep(test_queue, loaded.value);

    // No temp files left behind.
    var it = tmp.dir.iterate();
    var file_count: usize = 0;
    while (try it.next(io)) |entry| {
        try std.testing.expectEqualStrings("queue.zon", entry.name);
        file_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), file_count);
}

test "persist: loadOrEmpty degrades missing and corrupt files to empty" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var missing = loadOrEmpty(io, tmp.dir, "absent.zon", std.testing.allocator);
    defer missing.deinit();
    try std.testing.expectEqual(@as(usize, 0), missing.value.items.len);

    try tmp.dir.writeFile(io, .{ .sub_path = "bad.zon", .data = "}{ not zon \x00\xff" });
    var corrupt = loadOrEmpty(io, tmp.dir, "bad.zon", std.testing.allocator);
    defer corrupt.deinit();
    try std.testing.expectEqual(@as(usize, 0), corrupt.value.items.len);
}

test "debounce: bursts collapse into one save per interval" {
    var d: Debounce = .{ .interval_ns = 100 };

    // Clean: nothing due.
    try std.testing.expect(!d.poll(0));

    // First dirty arms; due only after the interval.
    d.markDirty();
    try std.testing.expect(!d.poll(10)); // arms, deadline = 110
    d.markDirty(); // burst: no new deadline
    d.markDirty();
    try std.testing.expect(!d.poll(109));
    try std.testing.expect(d.poll(110)); // one save for the whole burst
    try std.testing.expect(!d.poll(111)); // consumed

    // Re-arm after consumption.
    d.markDirty();
    try std.testing.expect(!d.poll(200));
    try std.testing.expect(!d.poll(250));
    try std.testing.expect(d.poll(300));
    try std.testing.expect(!d.poll(400)); // idle again
}

test {
    std.testing.refAllDecls(@This());
}

//! snapshot — DirSnapshot, the core listing data structure: one immutable,
//! refcounted directory listing whose entries and every string they
//! reference live in a single arena. The last `unref` destroys the arena —
//! a 100k-entry listing frees in O(1).
//!
//! Mutation never happens after `Builder.finish`: sorting and filtering
//! produce index permutation arrays over `entries`, never copies, so the
//! UI can hold several views of the same snapshot for free.

const std = @import("std");
const vfs = @import("vfs.zig");

const Allocator = std.mem.Allocator;

pub const DirSnapshot = struct {
    /// Owns `path`, `entries`, every Entry slice, and this struct itself.
    arena: std.heap.ArenaAllocator,
    /// Normalized absolute path this snapshot lists (see path.zig).
    path: []const u8,
    entries: []const vfs.Entry,
    /// Caller-assigned (listing request id); lets the UI discard stale
    /// snapshots that finish out of order.
    generation: u64,
    rc: std.atomic.Value(usize),

    pub fn ref(s: *DirSnapshot) *DirSnapshot {
        const prev = s.rc.fetchAdd(1, .monotonic);
        std.debug.assert(prev != 0); // resurrection
        return s;
    }

    /// Thread-safe; the final unref destroys the whole arena in O(1).
    pub fn unref(s: *DirSnapshot) void {
        if (s.rc.fetchSub(1, .release) != 1) return;
        _ = s.rc.load(.acquire);
        // The snapshot lives inside its own arena: move the arena out
        // before tearing the memory down beneath ourselves.
        var arena = s.arena;
        arena.deinit();
    }

    // ------------------------------------------------------------------ //
    // Index-permutation views (no entry is ever copied)

    pub const SortKey = enum { name, size, mtime };

    pub const SortOptions = struct {
        key: SortKey = .name,
        /// Directories group before non-directories regardless of order.
        dirs_first: bool = true,
        ascending: bool = true,
    };

    /// Permutation of entry indexes in display order; caller owns it.
    pub fn sortIndex(s: *const DirSnapshot, gpa: Allocator, opts: SortOptions) error{OutOfMemory}![]u32 {
        const index = try gpa.alloc(u32, s.entries.len);
        for (index, 0..) |*v, i| v.* = @intCast(i);
        s.sortIndexInPlace(index, opts);
        return index;
    }

    /// Re-sorts an existing permutation (column-header clicks reuse the
    /// allocation).
    pub fn sortIndexInPlace(s: *const DirSnapshot, index: []u32, opts: SortOptions) void {
        std.mem.sortUnstable(u32, index, SortContext{
            .entries = s.entries,
            .opts = opts,
        }, SortContext.lessThan);
    }

    const SortContext = struct {
        entries: []const vfs.Entry,
        opts: SortOptions,

        fn lessThan(c: SortContext, ai: u32, bi: u32) bool {
            const a = &c.entries[ai];
            const b = &c.entries[bi];
            if (c.opts.dirs_first) {
                const a_dir = a.kind == .dir;
                const b_dir = b.kind == .dir;
                if (a_dir != b_dir) return a_dir;
            }
            var order = switch (c.opts.key) {
                .name => naturalOrder(a.name, b.name),
                .size => orderNullsFirst(u64, a.size, b.size),
                .mtime => orderNullsFirst(i64, a.mtime, b.mtime),
            };
            if (order == .eq and c.opts.key != .name)
                order = naturalOrder(a.name, b.name);
            if (!c.opts.ascending) order = order.invert();
            // Original index as the final tie-break keeps the permutation
            // deterministic under sortUnstable.
            if (order == .eq) return ai < bi;
            return order == .lt;
        }
    };

    fn orderNullsFirst(comptime T: type, a: ?T, b: ?T) std.math.Order {
        if (a == null and b == null) return .eq;
        if (a == null) return .lt;
        if (b == null) return .gt;
        return std.math.order(a.?, b.?);
    }

    /// Indexes of the entries matching `pred`, in entry order; caller owns
    /// the slice. `context` is any value `pred` needs.
    pub fn filterIndex(
        s: *const DirSnapshot,
        gpa: Allocator,
        context: anytype,
        comptime pred: fn (@TypeOf(context), entry: *const vfs.Entry) bool,
    ) error{OutOfMemory}![]u32 {
        var out: std.ArrayList(u32) = .empty;
        errdefer out.deinit(gpa);
        for (s.entries, 0..) |*entry, i| {
            if (pred(context, entry)) try out.append(gpa, @intCast(i));
        }
        return out.toOwnedSlice(gpa);
    }

    /// Case-insensitive (ASCII) substring filter on names — the UI's
    /// quick-filter box.
    pub fn filterByName(s: *const DirSnapshot, gpa: Allocator, needle: []const u8) error{OutOfMemory}![]u32 {
        return s.filterIndex(gpa, needle, nameContains);
    }

    fn nameContains(needle: []const u8, entry: *const vfs.Entry) bool {
        return std.ascii.indexOfIgnoreCase(entry.name, needle) != null;
    }
};

/// Natural-order name comparison: ASCII-case-insensitive with digit runs
/// compared numerically ("file2" < "file10"). Multibyte UTF-8 falls back
/// to byte order, which matches codepoint order.
pub fn naturalOrder(a: []const u8, b: []const u8) std.math.Order {
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        if (std.ascii.isDigit(a[i]) and std.ascii.isDigit(b[j])) {
            var ie = i;
            while (ie < a.len and std.ascii.isDigit(a[ie])) ie += 1;
            var je = j;
            while (je < b.len and std.ascii.isDigit(b[je])) je += 1;
            const ra = std.mem.trimStart(u8, a[i..ie], "0");
            const rb = std.mem.trimStart(u8, b[j..je], "0");
            if (ra.len != rb.len) return std.math.order(ra.len, rb.len);
            switch (std.mem.order(u8, ra, rb)) {
                .eq => {},
                else => |o| return o,
            }
            // Equal values: fewer leading zeros sorts first ("1" < "01").
            if (ie - i != je - j) return std.math.order(ie - i, je - j);
            i = ie;
            j = je;
            continue;
        }
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[j]);
        if (ca != cb) return std.math.order(ca, cb);
        i += 1;
        j += 1;
    }
    return std.math.order(a.len - i, b.len - j);
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fills a DirSnapshot from a streaming listing: pass `builder.arena()` and
/// `builder.sink()` to `Vfs.list`, then call `finish` (or `abandon` on the
/// error path). Owner/group strings are deduped through an arena-backed
/// intern map — a 100k-entry listing typically carries a handful of unique
/// owners.
pub const Builder = struct {
    gpa: Allocator,
    arena_inst: std.heap.ArenaAllocator,
    /// gpa-backed while building (an arena-backed list would leak every
    /// growth step into the snapshot); copied into the arena once at finish.
    entries: std.ArrayList(vfs.Entry),
    /// Keys are the canonical arena-owned strings; values unused.
    intern_map: std.StringHashMapUnmanaged(void),
    path: []const u8,
    generation: u64,
    /// Set when a sink batch hits OOM (the sink callback cannot fail);
    /// `finish` turns it into error.OutOfMemory.
    failed: bool,

    pub fn init(gpa: Allocator, dir_path: []const u8, generation: u64) error{OutOfMemory}!Builder {
        var arena_inst: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena_inst.deinit();
        const path_copy = try arena_inst.allocator().dupe(u8, dir_path);
        return .{
            .gpa = gpa,
            .arena_inst = arena_inst,
            .entries = .empty,
            .intern_map = .empty,
            .path = path_copy,
            .generation = generation,
            .failed = false,
        };
    }

    /// The allocator every Entry slice streamed into the sink must come
    /// from (Vfs.list's `arena` argument).
    pub fn arena(b: *Builder) Allocator {
        return b.arena_inst.allocator();
    }

    pub fn sink(b: *Builder) vfs.ListingSink {
        return .{ .context = b, .batchFn = onBatch };
    }

    fn onBatch(ctx: *anyopaque, batch: []const vfs.Entry) void {
        const b: *Builder = @ptrCast(@alignCast(ctx));
        b.append(batch) catch {
            b.failed = true;
        };
    }

    /// Direct (fallible) form of the sink callback.
    pub fn append(b: *Builder, batch: []const vfs.Entry) error{OutOfMemory}!void {
        try b.entries.ensureUnusedCapacity(b.gpa, batch.len);
        for (batch) |entry| {
            var copy = entry;
            if (copy.owner) |owner| copy.owner = try b.intern(owner);
            if (copy.group) |group| copy.group = try b.intern(group);
            b.entries.appendAssumeCapacity(copy);
        }
    }

    /// Canonical arena-owned copy of `s`. The first occurrence's slice
    /// (already arena-owned per the sink contract) becomes the canonical
    /// one; later duplicates collapse onto it.
    pub fn intern(b: *Builder, s: []const u8) error{OutOfMemory}![]const u8 {
        const gop = try b.intern_map.getOrPut(b.arena(), s);
        return gop.key_ptr.*;
    }

    pub fn count(b: *const Builder) usize {
        return b.entries.items.len;
    }

    /// Seals the snapshot with rc = 1 and consumes the builder. On error
    /// (including a sink-recorded OOM) everything is freed.
    pub fn finish(b: *Builder) error{OutOfMemory}!*DirSnapshot {
        errdefer b.abandon();
        if (b.failed) return error.OutOfMemory;
        const a = b.arena_inst.allocator();
        const entries_copy = try a.dupe(vfs.Entry, b.entries.items);
        const snap = try a.create(DirSnapshot);
        snap.* = .{
            .arena = b.arena_inst,
            .path = b.path,
            .entries = entries_copy,
            .generation = b.generation,
            .rc = .init(1),
        };
        b.entries.deinit(b.gpa);
        b.* = undefined;
        return snap;
    }

    /// Error-path teardown; frees everything the build accumulated.
    pub fn abandon(b: *Builder) void {
        b.entries.deinit(b.gpa);
        b.arena_inst.deinit();
        b.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn buildSample(gpa: Allocator) !*DirSnapshot {
    var b = try Builder.init(gpa, "/pub", 7);
    var finishing = false;
    errdefer if (!finishing) b.abandon();
    const a = b.arena();
    const batch = [_]vfs.Entry{
        .{ .name = try a.dupe(u8, "file10.txt"), .kind = .file, .size = 100, .mtime = 30, .owner = try a.dupe(u8, "ftp"), .group = try a.dupe(u8, "users") },
        .{ .name = try a.dupe(u8, "file2.txt"), .kind = .file, .size = 5000, .mtime = 10, .owner = try a.dupe(u8, "ftp"), .group = try a.dupe(u8, "users") },
        .{ .name = try a.dupe(u8, "Alpha"), .kind = .dir, .mtime = 20, .owner = try a.dupe(u8, "root") },
        .{ .name = try a.dupe(u8, "zeta"), .kind = .dir },
        .{ .name = try a.dupe(u8, "no-size.log"), .kind = .file },
    };
    try b.append(&batch);
    finishing = true;
    return b.finish();
}

test "builder: arena ownership, generation, path, intern dedup" {
    const snap = try buildSample(testing.allocator);
    defer snap.unref();

    try testing.expectEqual(@as(u64, 7), snap.generation);
    try testing.expectEqualStrings("/pub", snap.path);
    try testing.expectEqual(@as(usize, 5), snap.entries.len);

    // Same owner content -> same canonical pointer (interned).
    try testing.expectEqualStrings("ftp", snap.entries[0].owner.?);
    try testing.expect(snap.entries[0].owner.?.ptr == snap.entries[1].owner.?.ptr);
    try testing.expect(snap.entries[0].group.?.ptr == snap.entries[1].group.?.ptr);
    try testing.expect(snap.entries[0].owner.?.ptr != snap.entries[2].owner.?.ptr);
}

test "sortIndex: natural order, dirs first, descending size, null-first mtime" {
    const snap = try buildSample(testing.allocator);
    defer snap.unref();

    const by_name = try snap.sortIndex(testing.allocator, .{});
    defer testing.allocator.free(by_name);
    // Dirs first (Alpha, zeta), then files in natural order: file2 < file10.
    try testing.expectEqualStrings("Alpha", snap.entries[by_name[0]].name);
    try testing.expectEqualStrings("zeta", snap.entries[by_name[1]].name);
    try testing.expectEqualStrings("file2.txt", snap.entries[by_name[2]].name);
    try testing.expectEqualStrings("file10.txt", snap.entries[by_name[3]].name);
    try testing.expectEqualStrings("no-size.log", snap.entries[by_name[4]].name);

    const by_size_desc = try snap.sortIndex(testing.allocator, .{
        .key = .size,
        .dirs_first = false,
        .ascending = false,
    });
    defer testing.allocator.free(by_size_desc);
    try testing.expectEqualStrings("file2.txt", snap.entries[by_size_desc[0]].name);
    try testing.expectEqualStrings("file10.txt", snap.entries[by_size_desc[1]].name);

    const by_mtime = try snap.sortIndex(testing.allocator, .{ .key = .mtime, .dirs_first = false });
    defer testing.allocator.free(by_mtime);
    // Null mtimes first, then ascending.
    try testing.expect(snap.entries[by_mtime[0]].mtime == null);
    try testing.expect(snap.entries[by_mtime[1]].mtime == null);
    try testing.expectEqual(@as(?i64, 10), snap.entries[by_mtime[2]].mtime);
    try testing.expectEqual(@as(?i64, 30), snap.entries[by_mtime[4]].mtime);

    // In-place re-sort reuses the allocation.
    snap.sortIndexInPlace(by_mtime, .{ .key = .name, .dirs_first = true });
    try testing.expectEqualStrings("Alpha", snap.entries[by_mtime[0]].name);
}

test "filterIndex and filterByName" {
    const snap = try buildSample(testing.allocator);
    defer snap.unref();

    const files = try snap.filterIndex(testing.allocator, {}, struct {
        fn pred(_: void, entry: *const vfs.Entry) bool {
            return entry.kind == .file;
        }
    }.pred);
    defer testing.allocator.free(files);
    try testing.expectEqual(@as(usize, 3), files.len);

    const matched = try snap.filterByName(testing.allocator, "FILE");
    defer testing.allocator.free(matched);
    try testing.expectEqual(@as(usize, 2), matched.len);
    try testing.expectEqualStrings("file10.txt", snap.entries[matched[0]].name);
}

test "naturalOrder table" {
    const lt = std.math.Order.lt;
    const eq = std.math.Order.eq;
    const cases = [_]struct { a: []const u8, b: []const u8, want: std.math.Order }{
        .{ .a = "file2", .b = "file10", .want = lt },
        .{ .a = "file2", .b = "FILE2", .want = eq },
        .{ .a = "a1b2", .b = "a1b10", .want = lt },
        .{ .a = "1", .b = "01", .want = lt },
        .{ .a = "abc", .b = "abcd", .want = lt },
        .{ .a = "", .b = "", .want = eq },
        .{ .a = "9", .b = "10", .want = lt },
        .{ .a = "x10y", .b = "x10z", .want = lt },
    };
    for (cases) |case| {
        try testing.expectEqual(case.want, naturalOrder(case.a, case.b));
        if (case.want == .lt) try testing.expectEqual(std.math.Order.gt, naturalOrder(case.b, case.a));
    }
}

test "rc lifecycle under threads frees exactly once" {
    const snap = try buildSample(testing.allocator);

    const Worker = struct {
        fn run(s: *DirSnapshot) void {
            for (0..5_000) |_| {
                const held = s.ref();
                std.mem.doNotOptimizeAway(held.entries.len);
                held.unref();
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{snap});
    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(usize, 1), snap.rc.load(.monotonic));
    snap.unref(); // testing.allocator reports a leak if this misses the free
}

test "sink path: batches stream in, OOM is deferred to finish" {
    var b = try Builder.init(testing.allocator, "/", 1);
    const s = b.sink();
    const a = b.arena();
    const one = [_]vfs.Entry{.{ .name = try a.dupe(u8, "x"), .kind = .file }};
    s.batch(&one);
    s.batch(&one);
    try testing.expectEqual(@as(usize, 2), b.count());
    const snap = try b.finish();
    defer snap.unref();
    try testing.expectEqual(@as(usize, 2), snap.entries.len);

    // A sink that hits OOM poisons the build; finish reports it.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var poisoned = Builder.init(failing.allocator(), "/p", 2) catch return; // init may be the failing alloc
    poisoned.sink().batch(&one);
    try testing.expect(poisoned.failed);
    try testing.expectError(error.OutOfMemory, poisoned.finish());
}

fn builderCycle(gpa: Allocator) !void {
    var b = try Builder.init(gpa, "/dir", 3);
    // finish() consumes the builder even on error; only abandon before it.
    var finishing = false;
    errdefer if (!finishing) b.abandon();
    const a = b.arena();
    const batch = [_]vfs.Entry{
        .{ .name = try a.dupe(u8, "a"), .owner = try a.dupe(u8, "u1"), .group = try a.dupe(u8, "g") },
        .{ .name = try a.dupe(u8, "b"), .owner = try a.dupe(u8, "u1"), .group = try a.dupe(u8, "g") },
    };
    try b.append(&batch);
    finishing = true;
    const snap = try b.finish();
    defer snap.unref();
    if (snap.entries.len != 2) return error.TestUnexpectedResult;
    const index = try snap.sortIndex(gpa, .{});
    defer gpa.free(index);
}

test "builder + sort survive allocation failure at every point" {
    try testing.checkAllAllocationFailures(testing.allocator, builderCycle, .{});
}

test "informational: 100k-entry build + sort timing" {
    const io = testing.io;
    const entry_count = 100_000;

    var b = try Builder.init(testing.allocator, "/big", 1);
    var finishing = false;
    errdefer if (!finishing) b.abandon();
    const a = b.arena();
    const owners = [_][]const u8{ "root", "ftp", "deploy", "www" };

    const t_build0 = std.Io.Clock.Timestamp.now(io, .awake);
    var batch: [256]vfs.Entry = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        batch[n] = .{
            .name = try std.fmt.allocPrint(a, "file-{d}.dat", .{(i * 7919) % entry_count}),
            .kind = if (i % 16 == 0) .dir else .file,
            .size = i,
            .mtime = @intCast(1_700_000_000 + (i % 100_000)),
            .owner = try a.dupe(u8, owners[i % owners.len]),
        };
        n += 1;
        if (n == batch.len) {
            try b.append(batch[0..n]);
            n = 0;
        }
    }
    try b.append(batch[0..n]);
    finishing = true;
    const snap = try b.finish();
    defer snap.unref();
    const t_build1 = std.Io.Clock.Timestamp.now(io, .awake);

    const index = try snap.sortIndex(testing.allocator, .{});
    defer testing.allocator.free(index);
    const t_sort1 = std.Io.Clock.Timestamp.now(io, .awake);

    // Spot-check the permutation is actually ordered.
    try testing.expectEqual(@as(usize, entry_count), index.len);
    var prev: ?u32 = null;
    for (index[0..100]) |idx| {
        if (prev) |p| {
            const e_prev = &snap.entries[p];
            const e_cur = &snap.entries[idx];
            if (e_prev.kind == e_cur.kind) {
                try testing.expect(naturalOrder(e_prev.name, e_cur.name) != .gt);
            }
        }
        prev = idx;
    }
    // Interning held: 4 unique owner strings across 100k entries.
    try testing.expect(snap.entries[0].owner.?.ptr == snap.entries[4].owner.?.ptr);

    // Timing print is opt-in: any stderr from a passing test makes Zig
    // 0.16's build runner append a misleading red "failed command:" footer
    // to a green `zig build test`.
    if (std.c.getenv("RELAY_PERF") != null) {
        std.debug.print(
            "\n[info] DirSnapshot 100k entries: build {d} ms, sort {d} ms\n",
            .{
                t_build0.durationTo(t_build1).raw.toMilliseconds(),
                t_build1.durationTo(t_sort1).raw.toMilliseconds(),
            },
        );
    }
}

test {
    std.testing.refAllDecls(@This());
}

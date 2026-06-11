//! temp_cache — content-addressed local store for remote preview files
//! (Quick Look, edit sessions, inline viewers).
//!
//! Identity is the full tuple (site_id, remote_path, size, mtime): any
//! change on the server produces a DIFFERENT key, so a stale local copy can
//! never be served for an updated remote file — old versions simply age out
//! through the LRU. The key is hashed (SHA-256) into the on-disk file name
//! under `<root>/…/preview/`, so the directory itself is the durable index:
//! a fresh process adopts files written by an earlier run on first `hit`.
//!
//! Memory/IO contract: single-threaded (main thread) like all UI-side
//! state; downloads land here only after the worker handed the bytes over.
//! Paths returned by `hit`/`put`/`stagePath` are cache-owned and valid only
//! until the next mutating call (put/evict/purge/deinit) — callers that
//! keep one (e.g. to build an NSURL) must copy it first.
//!
//! Eviction: LRU by byte budget (default 512 MiB). The entry touched by the
//! current `put` is never its own eviction victim, so a single oversized
//! preview still works (the cache just runs over budget until the next put).

const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const default_budget_bytes: u64 = 512 * 1024 * 1024;

/// Hex SHA-256 of the canonical key encoding == on-disk file name.
pub const name_len = Sha256.digest_length * 2;

/// Cache identity of one remote file version. `remote_path` is borrowed for
/// the call; the cache never keeps it.
pub const Key = struct {
    site_id: u64,
    remote_path: []const u8,
    /// Remote size in bytes (vfs.Entry.size).
    size: u64,
    /// Remote mtime, seconds since epoch (vfs.Entry.mtime); 0 when the
    /// server reported none.
    mtime: i64,

    /// Canonical fixed-width-prefix encoding (no separator ambiguity:
    /// the path is length-delimited by the buffer end).
    fn fileName(key: Key) [name_len]u8 {
        var hasher = Sha256.init(.{});
        var scalars: [24]u8 = undefined;
        std.mem.writeInt(u64, scalars[0..8], key.site_id, .little);
        std.mem.writeInt(u64, scalars[8..16], key.size, .little);
        std.mem.writeInt(i64, scalars[16..24], key.mtime, .little);
        hasher.update(&scalars);
        hasher.update(key.remote_path);
        var digest: [Sha256.digest_length]u8 = undefined;
        hasher.final(&digest);
        var name: [name_len]u8 = undefined;
        for (digest, 0..) |byte, i| {
            const hex = "0123456789abcdef";
            name[i * 2] = hex[byte >> 4];
            name[i * 2 + 1] = hex[byte & 0xf];
        }
        return name;
    }
};

pub const TempCache = struct {
    gpa: Allocator,
    io: std.Io,
    /// Opened (and owned) by initAt/openDefault; closed by deinit.
    dir: std.Io.Dir,
    /// Absolute path of `dir`; prefix of every returned entry path.
    root_path: []u8,
    budget_bytes: u64,
    /// file name (entry-owned, == abs_path tail) → entry.
    entries: std.StringHashMapUnmanaged(*Entry) = .empty,
    total_bytes: u64 = 0,
    /// LRU clock: bumped on every hit/put; smallest = coldest.
    tick: u64 = 0,
    evictions: u64 = 0,

    const Entry = struct {
        /// root_path ++ "/" ++ name; gpa-owned.
        abs_path: []u8,
        size: u64,
        last_used: u64,

        /// The file-name tail of abs_path (the map key).
        fn name(e: *const Entry) []const u8 {
            return e.abs_path[e.abs_path.len - name_len ..];
        }
    };

    pub const InitError = error{ OutOfMemory, Unexpected } || std.Io.Dir.CreateDirPathOpenError;

    /// Open (creating if needed) the production cache dir:
    /// ~/Library/Caches/<bundle_id>/preview/.
    pub fn openDefault(
        gpa: Allocator,
        io: std.Io,
        bundle_id: []const u8,
        budget_bytes: u64,
    ) (InitError || error{ NoHomeDirectory, NameTooLong })!TempCache {
        const home = std.c.getenv("HOME") orelse return error.NoHomeDirectory;
        var buf: [1024]u8 = undefined;
        const root = std.fmt.bufPrint(&buf, "{s}/Library/Caches/{s}/preview", .{
            std.mem.span(home), bundle_id,
        }) catch return error.NameTooLong;
        return initAt(gpa, io, std.Io.Dir.cwd(), root, budget_bytes);
    }

    /// Open (creating if needed) `root` relative to `base` and run the
    /// cache there. Returned entry paths are absolute
    /// (`realPath(base/root) ++ "/" ++ name`).
    pub fn initAt(
        gpa: Allocator,
        io: std.Io,
        base: std.Io.Dir,
        root: []const u8,
        budget_bytes: u64,
    ) InitError!TempCache {
        var dir = try base.createDirPathOpen(io, root, .{ .open_options = .{ .iterate = true } });
        errdefer dir.close(io);
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const n = dir.realPath(io, &path_buf) catch return error.Unexpected;
        const root_path = try gpa.dupe(u8, path_buf[0..n]);
        return .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .root_path = root_path,
            .budget_bytes = budget_bytes,
        };
    }

    /// Frees the index. On-disk files are kept (they are the durable
    /// index); call `purgeAll` first to drop them.
    pub fn deinit(self: *TempCache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| self.destroyEntry(entry.*);
        self.entries.deinit(self.gpa);
        self.dir.close(self.io);
        self.gpa.free(self.root_path);
        self.* = undefined;
    }

    // ------------------------------------------------------------------ //
    // Hit / miss

    /// Local path of the cached copy for `key`, or null (miss). Bumps the
    /// entry's LRU position. Adopts a file written by an earlier process
    /// (or a crashed-after-write run) when the index has no entry but the
    /// content-addressed file exists on disk.
    pub fn hit(self: *TempCache, key: Key) ?[]const u8 {
        const name = key.fileName();
        if (self.entries.get(&name)) |entry| {
            self.tick += 1;
            entry.last_used = self.tick;
            return entry.abs_path;
        }
        // Disk probe: the name encodes the full key, so existence == hit.
        const st = self.dir.statFile(self.io, &name, .{}) catch return null;
        const entry = self.insertEntry(&name, st.size) catch return null;
        return entry.abs_path;
    }

    /// Store `bytes` as the cached copy for `key` and return its local
    /// path. Write is atomic (temp file + rename), so a crash mid-put can
    /// never leave a half preview behind the content-addressed name.
    /// Re-putting an existing key just refreshes the bytes in place.
    pub fn put(self: *TempCache, key: Key, bytes: []const u8) ![]const u8 {
        const name = key.fileName();
        var tmp_name: [name_len + 4]u8 = undefined;
        @memcpy(tmp_name[0..name_len], &name);
        @memcpy(tmp_name[name_len..], ".tmp");
        try self.dir.writeFile(self.io, .{ .sub_path = &tmp_name, .data = bytes });
        errdefer self.dir.deleteFile(self.io, &tmp_name) catch {};
        try self.dir.rename(&tmp_name, self.dir, &name, self.io);
        return self.indexFile(&name, bytes.len);
    }

    /// Where a downloader should write the bytes for `key` (same name
    /// `put` would use). The path is NOT indexed yet — call `commit(key)`
    /// after the write finishes.
    pub fn stagePath(self: *TempCache, key: Key, buf: []u8) error{NoSpaceLeft}![]const u8 {
        const name = key.fileName();
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.root_path, &name });
    }

    /// Index a file previously written to `stagePath(key)`. Stats the file
    /// for its real size; fails (clean miss) when nothing was written.
    pub fn commit(self: *TempCache, key: Key) ![]const u8 {
        const name = key.fileName();
        const st = try self.dir.statFile(self.io, &name, .{});
        return self.indexFile(&name, st.size);
    }

    /// Delete every cached file (indexed or adopted-later leftovers) and
    /// reset the accounting.
    pub fn purgeAll(self: *TempCache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| self.destroyEntry(entry.*);
        self.entries.clearRetainingCapacity();
        self.total_bytes = 0;
        // Sweep stragglers (previous runs, staged-but-never-committed).
        var dir_it = self.dir.iterate();
        while (dir_it.next(self.io) catch null) |dirent| {
            if (dirent.kind != .file) continue;
            self.dir.deleteFile(self.io, dirent.name) catch {};
        }
    }

    pub fn entryCount(self: *const TempCache) usize {
        return self.entries.count();
    }

    pub fn totalBytes(self: *const TempCache) u64 {
        return self.total_bytes;
    }

    // ------------------------------------------------------------------ //
    // Internals

    fn indexFile(self: *TempCache, name: []const u8, size: u64) ![]const u8 {
        if (self.entries.get(name)) |existing| {
            // Same key re-put: swap the accounted size, bump LRU.
            self.total_bytes -= existing.size;
            self.total_bytes += size;
            existing.size = size;
            self.tick += 1;
            existing.last_used = self.tick;
            self.evictOver(existing);
            return existing.abs_path;
        }
        const entry = try self.insertEntry(name, size);
        self.evictOver(entry);
        return entry.abs_path;
    }

    fn insertEntry(self: *TempCache, name: []const u8, size: u64) error{OutOfMemory}!*Entry {
        const entry = try self.gpa.create(Entry);
        errdefer self.gpa.destroy(entry);
        entry.abs_path = try std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ self.root_path, name });
        errdefer self.gpa.free(entry.abs_path);
        entry.size = size;
        try self.entries.put(self.gpa, entry.name(), entry);
        self.tick += 1;
        entry.last_used = self.tick;
        self.total_bytes += size;
        return entry;
    }

    /// Evict coldest-first until within budget. `keep` (the entry the
    /// caller is actively producing/consuming) is never the victim.
    fn evictOver(self: *TempCache, keep: *const Entry) void {
        while (self.total_bytes > self.budget_bytes) {
            var coldest: ?*Entry = null;
            var it = self.entries.valueIterator();
            while (it.next()) |candidate| {
                const e = candidate.*;
                if (e == keep) continue;
                if (coldest == null or e.last_used < coldest.?.last_used) coldest = e;
            }
            const victim = coldest orelse return; // only `keep` left
            self.dir.deleteFile(self.io, victim.name()) catch {};
            self.total_bytes -= victim.size;
            _ = self.entries.remove(victim.name());
            self.destroyEntry(victim);
            self.evictions += 1;
        }
    }

    fn destroyEntry(self: *TempCache, entry: *Entry) void {
        self.gpa.free(entry.abs_path);
        self.gpa.destroy(entry);
    }
};

// ---------------------------------------------------------------------------
// Tests (headless; std.testing.allocator + tmp dirs)
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestCache = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
    tmp: std.testing.TmpDir,
    cache: TempCache,

    fn start(t: *TestCache, budget: u64) !void {
        t.threaded = .init(testing.allocator, .{});
        t.io = t.threaded.io();
        t.tmp = std.testing.tmpDir(.{ .iterate = true });
        t.cache = try TempCache.initAt(testing.allocator, t.io, t.tmp.dir, "preview", budget);
    }

    fn stop(t: *TestCache) void {
        t.cache.deinit();
        t.tmp.cleanup();
        t.threaded.deinit();
    }
};

fn keyOf(site: u64, path: []const u8, size: u64, mtime: i64) Key {
    return .{ .site_id = site, .remote_path = path, .size = size, .mtime = mtime };
}

test "put then hit round-trips path and bytes; unknown key misses" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const key = keyOf(1, "/srv/readme.txt", 5, 1_700_000_000);
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(key));

    const path = try t.cache.put(key, "hello");
    try testing.expect(std.fs.path.isAbsolute(path));
    try testing.expectStringEndsWith(path, &key.fileName());

    const hit_path = t.cache.hit(key) orelse return error.TestExpectedHit;
    try testing.expectEqualStrings(path, hit_path);

    const back = try std.Io.Dir.cwd().readFileAlloc(t.io, hit_path, testing.allocator, .unlimited);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("hello", back);

    try testing.expectEqual(@as(usize, 1), t.cache.entryCount());
    try testing.expectEqual(@as(u64, 5), t.cache.totalBytes());
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(keyOf(2, "/srv/readme.txt", 5, 1_700_000_000)));
}

test "key identity: size/mtime/site changes are misses, versions coexist" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const v1 = keyOf(1, "/a/file.bin", 3, 100);
    const v2 = keyOf(1, "/a/file.bin", 3, 200); // server touched the file
    const v3 = keyOf(1, "/a/file.bin", 4, 200); // and changed the size

    _ = try t.cache.put(v1, "old");
    // A newer remote version must NEVER read the stale copy.
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(v2));
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(v3));

    const p2 = try t.cache.put(v2, "new");
    const p1 = t.cache.hit(v1) orelse return error.TestExpectedHit;
    try testing.expect(!std.mem.eql(u8, p1, p2)); // distinct content addresses
    try testing.expectEqual(@as(usize, 2), t.cache.entryCount());

    const back = try std.Io.Dir.cwd().readFileAlloc(t.io, p1, testing.allocator, .unlimited);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("old", back);
}

test "LRU eviction: coldest entry goes first, hits refresh recency" {
    var t: TestCache = undefined;
    try t.start(10); // tiny byte budget
    defer t.stop();

    const ka = keyOf(1, "/a", 4, 1);
    const kb = keyOf(1, "/b", 4, 1);
    const kc = keyOf(1, "/c", 4, 1);

    _ = try t.cache.put(ka, "aaaa");
    _ = try t.cache.put(kb, "bbbb");
    try testing.expectEqual(@as(u64, 8), t.cache.totalBytes());

    // Touch a so b becomes the coldest, then overflow with c.
    _ = t.cache.hit(ka) orelse return error.TestExpectedHit;
    _ = try t.cache.put(kc, "cccc");

    try testing.expectEqual(@as(u64, 1), t.cache.evictions);
    try testing.expectEqual(@as(usize, 2), t.cache.entryCount());
    try testing.expectEqual(@as(u64, 8), t.cache.totalBytes());
    try testing.expect(t.cache.hit(ka) != null);
    try testing.expect(t.cache.hit(kc) != null);
    // b is gone from the index AND from disk (no zombie file to re-adopt).
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(kb));
    try testing.expectError(error.FileNotFound, t.cache.dir.statFile(t.io, &kb.fileName(), .{}));
}

test "eviction order is strict LRU across several rounds" {
    var t: TestCache = undefined;
    try t.start(12);
    defer t.stop();

    const keys = [_]Key{
        keyOf(1, "/0", 4, 0),
        keyOf(1, "/1", 4, 0),
        keyOf(1, "/2", 4, 0),
    };
    for (keys) |k| _ = try t.cache.put(k, "xxxx");
    // Recency now 0 < 1 < 2. Re-touch in reverse: 2 < 1 < 0.
    _ = t.cache.hit(keys[2]).?;
    _ = t.cache.hit(keys[1]).?;
    _ = t.cache.hit(keys[0]).?;

    _ = try t.cache.put(keyOf(1, "/3", 4, 0), "xxxx"); // evicts /2
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(keys[2]));

    // Touch /1 then /0; /3 is now the coldest of {/0, /1, /3}.
    _ = t.cache.hit(keys[1]).?;
    _ = t.cache.hit(keys[0]).?;
    _ = try t.cache.put(keyOf(1, "/4", 4, 0), "xxxx"); // evicts /3
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(keyOf(1, "/3", 4, 0)));
    try testing.expect(t.cache.hit(keys[0]) != null);
    try testing.expect(t.cache.hit(keys[1]) != null);
}

test "an oversized put is kept (never its own victim) and flushes the rest" {
    var t: TestCache = undefined;
    try t.start(8);
    defer t.stop();

    _ = try t.cache.put(keyOf(1, "/small", 4, 0), "xxxx");
    const big = keyOf(1, "/big", 16, 0);
    _ = try t.cache.put(big, "xxxxxxxxxxxxxxxx");

    try testing.expectEqual(@as(usize, 1), t.cache.entryCount());
    try testing.expect(t.cache.hit(big) != null);
    try testing.expectEqual(@as(u64, 16), t.cache.totalBytes()); // over budget, tolerated
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(keyOf(1, "/small", 4, 0)));
}

test "re-putting the same key replaces bytes without double accounting" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const key = keyOf(7, "/f", 9, 9);
    _ = try t.cache.put(key, "first");
    const path = try t.cache.put(key, "second!!");
    try testing.expectEqual(@as(usize, 1), t.cache.entryCount());
    try testing.expectEqual(@as(u64, 8), t.cache.totalBytes());

    const back = try std.Io.Dir.cwd().readFileAlloc(t.io, path, testing.allocator, .unlimited);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("second!!", back);
}

test "stagePath + commit indexes a worker-written file; bare commit misses" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const key = keyOf(3, "/staged.bin", 6, 42);
    try testing.expectError(error.FileNotFound, t.cache.commit(key));

    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const stage = try t.cache.stagePath(key, &buf);
    var data: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    try std.Io.Dir.cwd().writeFile(t.io, .{ .sub_path = stage, .data = &data });

    const path = try t.cache.commit(key);
    try testing.expectEqualStrings(stage, path);
    try testing.expectEqual(@as(u64, 6), t.cache.totalBytes());
    try testing.expect(t.cache.hit(key) != null);
}

test "purgeAll empties index, disk, and accounting" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const ka = keyOf(1, "/a", 1, 0);
    _ = try t.cache.put(ka, "a");
    _ = try t.cache.put(keyOf(1, "/b", 1, 0), "b");
    t.cache.purgeAll();

    try testing.expectEqual(@as(usize, 0), t.cache.entryCount());
    try testing.expectEqual(@as(u64, 0), t.cache.totalBytes());
    try testing.expectEqual(@as(?[]const u8, null), t.cache.hit(ka));

    var it = t.cache.dir.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(t.io));
}

test "a second cache over the same root adopts files from the first" {
    var t: TestCache = undefined;
    try t.start(default_budget_bytes);
    defer t.stop();

    const key = keyOf(9, "/persisted", 4, 4);
    _ = try t.cache.put(key, "data");

    var second = try TempCache.initAt(testing.allocator, t.io, t.tmp.dir, "preview", default_budget_bytes);
    defer second.deinit();
    const path = second.hit(key) orelse return error.TestExpectedHit;
    const back = try std.Io.Dir.cwd().readFileAlloc(t.io, path, testing.allocator, .unlimited);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("data", back);
    try testing.expectEqual(@as(u64, 4), second.totalBytes()); // adopted size counted
}

test "file names are stable, hex, and free of separator aliasing" {
    const a = keyOf(1, "/x", 2, 3).fileName();
    const b = keyOf(1, "/x", 2, 3).fileName();
    try testing.expectEqualStrings(&a, &b);
    for (a) |ch| try testing.expect(std.ascii.isHex(ch));
    const c = keyOf(1, "/x/2", 3, 3).fileName();
    try testing.expect(!std.mem.eql(u8, &a, &c));
}

test {
    testing.refAllDecls(@This());
}

//! path — RemotePath helpers: normalized absolute UTF-8 paths, the one
//! currency every Vfs backend speaks. Normal form: starts with '/',
//! '/'-separated, no empty/"."/".." components, no trailing slash (except
//! the root "/" itself), valid UTF-8, no NUL bytes.
//!
//! Lookup helpers (`parent`, `basename`, `extension`, `components`) are
//! slice/iterator based and never allocate; `normalize` and `join` build
//! new paths and take an allocator.

const std = @import("std");

pub const Error = error{ InvalidPath, OutOfMemory };

/// Why a path failed `validate`; carried by diagnostics at higher layers.
fn validate(raw: []const u8) error{InvalidPath}!void {
    if (std.mem.indexOfScalar(u8, raw, 0) != null) return error.InvalidPath;
    if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidPath;
}

/// Builds the normalized absolute form of `raw`: collapses repeated
/// separators, resolves "." and "..", absolutizes relative input against
/// the root. Rejects ".." escaping above the root, invalid UTF-8, and
/// embedded NUL bytes (C-API / protocol smuggling guard).
/// Caller owns the returned slice.
pub fn normalize(gpa: std.mem.Allocator, raw: []const u8) Error![]u8 {
    try validate(raw);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var it = std.mem.tokenizeScalar(u8, raw, '/');
    while (it.next()) |comp| {
        if (std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..")) {
            if (out.items.len == 0) return error.InvalidPath;
            // Components are stored as "/name" runs, so a '/' always exists.
            const cut = std.mem.lastIndexOfScalar(u8, out.items, '/').?;
            out.shrinkRetainingCapacity(cut);
            continue;
        }
        try out.append(gpa, '/');
        try out.appendSlice(gpa, comp);
    }
    if (out.items.len == 0) try out.append(gpa, '/');
    return out.toOwnedSlice(gpa);
}

/// Joins `rel` (one component or a relative path; "." and ".." resolved,
/// never above the root) onto normalized `base`. Caller owns the result.
pub fn join(gpa: std.mem.Allocator, base: []const u8, rel: []const u8) Error![]u8 {
    std.debug.assert(isNormalized(base));
    const raw = try std.mem.concat(gpa, u8, &.{ base, "/", rel });
    defer gpa.free(raw);
    return normalize(gpa, raw);
}

/// True when `p` is already in normal form (see module doc).
pub fn isNormalized(p: []const u8) bool {
    if (p.len == 0 or p[0] != '/') return false;
    validate(p) catch return false;
    if (p.len == 1) return true;
    if (p[p.len - 1] == '/') return false;
    var it = std.mem.splitScalar(u8, p[1..], '/');
    while (it.next()) |comp| {
        if (comp.len == 0) return false; // "//"
        if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return false;
    }
    return true;
}

/// Parent directory as a slice of `p`; null for the root.
pub fn parent(p: []const u8) ?[]const u8 {
    std.debug.assert(isNormalized(p));
    if (p.len == 1) return null;
    const cut = std.mem.lastIndexOfScalar(u8, p, '/').?;
    return if (cut == 0) p[0..1] else p[0..cut];
}

/// Final component as a slice of `p`; "" for the root.
pub fn basename(p: []const u8) []const u8 {
    std.debug.assert(isNormalized(p));
    if (p.len == 1) return p[1..];
    const cut = std.mem.lastIndexOfScalar(u8, p, '/').?;
    return p[cut + 1 ..];
}

/// Extension including the dot (".gz" for "/a/b.tar.gz"); "" when the
/// basename has none. Dotfiles (".bashrc") have no extension.
pub fn extension(p: []const u8) []const u8 {
    const base = basename(p);
    const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return base[base.len..];
    if (dot == 0) return base[base.len..];
    return base[dot..];
}

/// Whether an UNTRUSTED listing entry name is exactly one normal path
/// component. Anything else ("..", "x/y", NUL bytes, invalid UTF-8) would
/// escape its parent when joined — for a download that is an arbitrary
/// local write; for a recursive remove it deletes outside the chosen
/// subtree. Every consumer of server-supplied names must check this before
/// building a child path (join alone only rejects escapes above root).
pub fn isSafeChildName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    if (std.mem.indexOfAny(u8, name, "/\x00") != null) return false;
    return std.unicode.utf8ValidateSlice(name);
}

test "isSafeChildName rejects traversal and accepts normal names" {
    try std.testing.expect(isSafeChildName("notes.txt"));
    try std.testing.expect(isSafeChildName("häst med blanksteg.md"));
    try std.testing.expect(!isSafeChildName(""));
    try std.testing.expect(!isSafeChildName("."));
    try std.testing.expect(!isSafeChildName(".."));
    try std.testing.expect(!isSafeChildName("../sibling"));
    try std.testing.expect(!isSafeChildName("evil/nested"));
    try std.testing.expect(!isSafeChildName("nul\x00byte"));
    try std.testing.expect(!isSafeChildName("bad\xff utf8"));
}

/// Allocation-free component iterator over a normalized path. The root
/// yields no components.
pub fn components(p: []const u8) std.mem.TokenIterator(u8, .scalar) {
    std.debug.assert(isNormalized(p));
    return std.mem.tokenizeScalar(u8, p, '/');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectNormalized(expected: []const u8, raw: []const u8) !void {
    const got = try normalize(testing.allocator, raw);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
    try testing.expect(isNormalized(got));
}

test "normalize: collapse, dot, dotdot, absolutize" {
    try expectNormalized("/", "/");
    try expectNormalized("/", "");
    try expectNormalized("/", "///");
    try expectNormalized("/a/b", "/a/b");
    try expectNormalized("/a/b", "a//b/");
    try expectNormalized("/a/b", "/a/./b/.");
    try expectNormalized("/b", "/a/../b");
    try expectNormalized("/", "/a/..");
    try expectNormalized("/a", "/a/b/c/../..");
    try expectNormalized("/a b/c.d", "/a b/c.d");
}

test "normalize: rejects escape above root, NUL, invalid UTF-8" {
    try testing.expectError(error.InvalidPath, normalize(testing.allocator, "/.."));
    try testing.expectError(error.InvalidPath, normalize(testing.allocator, "/a/../.."));
    try testing.expectError(error.InvalidPath, normalize(testing.allocator, "../etc/passwd"));
    try testing.expectError(error.InvalidPath, normalize(testing.allocator, "/a\x00b"));
    try testing.expectError(error.InvalidPath, normalize(testing.allocator, "/a/\xff\xfe"));
}

test "normalize: UTF-8 multibyte names survive intact" {
    try expectNormalized("/påse/смех/日本語", "//påse/./смех//日本語/");
    try expectNormalized("/naïve", "/x/../naïve");
}

test "join resolves relative segments against the base" {
    const cases = [_]struct { base: []const u8, rel: []const u8, want: []const u8 }{
        .{ .base = "/", .rel = "a", .want = "/a" },
        .{ .base = "/a/b", .rel = "c.txt", .want = "/a/b/c.txt" },
        .{ .base = "/a/b", .rel = "../c", .want = "/a/c" },
        .{ .base = "/a", .rel = "./d/", .want = "/a/d" },
        .{ .base = "/a", .rel = "", .want = "/a" },
    };
    for (cases) |case| {
        const got = try join(testing.allocator, case.base, case.rel);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(case.want, got);
    }
    try testing.expectError(error.InvalidPath, join(testing.allocator, "/a", "../../x"));
}

test "parent, basename, extension, components" {
    try testing.expectEqual(@as(?[]const u8, null), parent("/"));
    try testing.expectEqualStrings("/", parent("/a").?);
    try testing.expectEqualStrings("/a/b", parent("/a/b/c").?);

    try testing.expectEqualStrings("", basename("/"));
    try testing.expectEqualStrings("c.txt", basename("/a/b/c.txt"));
    try testing.expectEqualStrings("ärlig", basename("/x/ärlig"));

    try testing.expectEqualStrings(".gz", extension("/a/b.tar.gz"));
    try testing.expectEqualStrings("", extension("/a/Makefile"));
    try testing.expectEqualStrings("", extension("/home/.bashrc"));
    try testing.expectEqualStrings("", extension("/"));

    var it = components("/a/b b/ç");
    try testing.expectEqualStrings("a", it.next().?);
    try testing.expectEqualStrings("b b", it.next().?);
    try testing.expectEqualStrings("ç", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());

    var root_it = components("/");
    try testing.expectEqual(@as(?[]const u8, null), root_it.next());
}

fn normalizeCycle(gpa: std.mem.Allocator) !void {
    const a = try normalize(gpa, "//a/./b/../c/påse");
    defer gpa.free(a);
    const b = try join(gpa, a, "../x");
    defer gpa.free(b);
    if (!std.mem.eql(u8, b, "/a/c/x")) return error.TestUnexpectedResult;
}

test "normalize/join survive allocation failure at every point" {
    try testing.checkAllAllocationFailures(testing.allocator, normalizeCycle, .{});
}

fn fuzzNormalize(_: void, smith: *std.testing.Smith) !void {
    var in_buf: [256]u8 = undefined;
    const input = in_buf[0..smith.slice(&in_buf)];
    const out = normalize(testing.allocator, input) catch |err| switch (err) {
        error.InvalidPath => return,
        error.OutOfMemory => return err,
    };
    defer testing.allocator.free(out);
    // Whatever comes out must be in normal form and idempotent.
    try testing.expect(isNormalized(out));
    const again = try normalize(testing.allocator, out);
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(out, again);
}

test "fuzz normalize" {
    try testing.fuzz({}, fuzzNormalize, .{ .corpus = &.{
        "/a//b/../c/./d",
        "../..",
        "/påse/смех",
        "////",
    } });
}

test {
    std.testing.refAllDecls(@This());
}

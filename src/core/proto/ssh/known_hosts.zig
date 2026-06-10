//! OpenSSH known_hosts parsing, host matching and verification, pure Zig.
//! Supports plain hostnames, `[host]:port`, comma-separated pattern lists
//! with `*`/`?` wildcards and `!` negation, hashed `|1|salt|digest` entries
//! (HMAC-SHA1), and the `@cert-authority` / `@revoked` markers.
//!
//! Parsing borrows from the input text — zero allocation. `verify` makes a
//! single allocation (the candidate key re-encoded as base64) so entry blobs
//! never need decoding.

const std = @import("std");
const keys = @import("keys.zig");

const Allocator = std.mem.Allocator;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub const Marker = enum { none, cert_authority, revoked };

/// One syntactically valid known_hosts line; all slices borrow the input.
pub const Entry = struct {
    marker: Marker,
    /// Raw hosts field: comma-separated patterns or one `|1|...` hash.
    hosts: []const u8,
    /// Key algorithm name, e.g. "ssh-ed25519".
    key_type: []const u8,
    /// Key blob, still base64 (decode lazily; comparison happens in base64).
    key_b64: []const u8,
    comment: []const u8,
    line_number: usize,

    pub fn matchesHost(e: *const Entry, host: []const u8, port: u16) bool {
        var canon_buf: [hostname_max + 8]u8 = undefined;
        const canon = canonicalHost(&canon_buf, host, port) orelse return false;
        if (std.mem.startsWith(u8, e.hosts, "|")) return matchesHashed(e.hosts, canon);
        return matchPatternList(e.hosts, canon, ',');
    }
};

/// The three security-distinct outcomes plus the attack signal. A mismatch
/// (host known, key changed) must never be presented as a first-contact
/// "unknown host" prompt.
pub const Verification = union(enum) {
    /// Exact key found for this host.
    known: MatchInfo,
    /// No entry mentions this host at all (first contact).
    unknown,
    /// Host is known with a different key of the same type — MITM signal.
    mismatch: MatchInfo,
    /// This exact key is marked @revoked for this host.
    revoked: MatchInfo,
};

pub const MatchInfo = struct {
    line_number: usize,
    key_type: []const u8,
};

const hostname_max = 255;

/// Scans the whole known_hosts text for `host:port` presenting `key_blob`
/// (SSH wire format). Precedence: revoked > known > mismatch > unknown.
/// `@cert-authority` entries cannot vouch for a plain host key and are
/// skipped (M1 has no certificate support).
pub fn verify(
    gpa: Allocator,
    text: []const u8,
    host: []const u8,
    port: u16,
    key_blob: []const u8,
) Allocator.Error!Verification {
    const type_name = keys.blobTypeName(key_blob) orelse return .unknown;

    const enc = std.base64.standard.Encoder;
    const key_b64 = try gpa.alloc(u8, enc.calcSize(key_blob.len));
    defer gpa.free(key_b64);
    _ = enc.encode(key_b64, key_blob);

    var result: Verification = .unknown;
    var it: LineIterator = .{ .text = text };
    while (it.next()) |entry| {
        if (entry.marker == .cert_authority) continue;
        if (!entry.matchesHost(host, port)) continue;
        if (!std.mem.eql(u8, entry.key_type, type_name)) continue;
        const info: MatchInfo = .{ .line_number = entry.line_number, .key_type = entry.key_type };
        if (std.mem.eql(u8, entry.key_b64, key_b64)) {
            if (entry.marker == .revoked) return .{ .revoked = info };
            result = .{ .known = info };
        } else if (entry.marker != .revoked and result != .known) {
            // A later line may still hold the right key (multiple keys per
            // host are legitimate), so keep scanning.
            result = .{ .mismatch = info };
        }
    }
    return result;
}

/// Iterates syntactically valid entries, silently skipping blanks, comments
/// and malformed lines (matching OpenSSH, which warns and moves on).
pub const LineIterator = struct {
    text: []const u8,
    pos: usize = 0,
    line_number: usize = 0,

    pub fn next(it: *LineIterator) ?Entry {
        while (it.pos < it.text.len) {
            const nl = std.mem.indexOfScalarPos(u8, it.text, it.pos, '\n') orelse it.text.len;
            const line = it.text[it.pos..nl];
            it.pos = @min(nl + 1, it.text.len);
            it.line_number += 1;
            if (parseLine(line, it.line_number) catch null) |entry| return entry;
        }
        return null;
    }
};

pub const ParseError = error{MalformedLine};

/// Parses one line; null for blanks and comments, error for malformed input.
pub fn parseLine(line: []const u8, line_number: usize) ParseError!?Entry {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0 or trimmed[0] == '#') return null;

    var rest = trimmed;
    var first = nextField(&rest) orelse return error.MalformedLine;
    var marker: Marker = .none;
    if (first.len > 0 and first[0] == '@') {
        if (std.mem.eql(u8, first, "@cert-authority")) {
            marker = .cert_authority;
        } else if (std.mem.eql(u8, first, "@revoked")) {
            marker = .revoked;
        } else {
            return error.MalformedLine; // unknown markers are rejected, like OpenSSH
        }
        first = nextField(&rest) orelse return error.MalformedLine;
    }
    const hosts = first;
    if (hosts.len > hostname_max + 8) return error.MalformedLine;
    const key_type = nextField(&rest) orelse return error.MalformedLine;
    if (keys.KeyType.fromName(key_type) == null and !isPlausibleAlgoName(key_type))
        return error.MalformedLine;
    const key_b64 = nextField(&rest) orelse return error.MalformedLine;
    if (!isPlausibleBase64(key_b64)) return error.MalformedLine;

    return .{
        .marker = marker,
        .hosts = hosts,
        .key_type = key_type,
        .key_b64 = key_b64,
        .comment = std.mem.trim(u8, rest, " \t"),
        .line_number = line_number,
    };
}

fn nextField(rest: *[]const u8) ?[]const u8 {
    const s = std.mem.trimStart(u8, rest.*, " \t");
    if (s.len == 0) {
        rest.* = s;
        return null;
    }
    const end = std.mem.indexOfAny(u8, s, " \t") orelse s.len;
    rest.* = s[end..];
    return s[0..end];
}

/// Accept unsupported-but-real algorithm names (sk-*, *-cert-v01@openssh.com)
/// so their lines parse instead of being treated as garbage.
fn isPlausibleAlgoName(s: []const u8) bool {
    if (s.len < 3 or s.len > 64) return false;
    for (s) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '@', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn isPlausibleBase64(s: []const u8) bool {
    if (s.len < 4) return false;
    for (s) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/', '=' => {},
            else => return false,
        }
    }
    return true;
}

/// OpenSSH lookup key: bare hostname for port 22, `[host]:port` otherwise.
/// Lowercases (host matching is case-insensitive). Null if oversized.
fn canonicalHost(buf: *[hostname_max + 8]u8, host: []const u8, port: u16) ?[]const u8 {
    if (host.len == 0 or host.len > hostname_max) return null;
    var w: std.Io.Writer = .fixed(buf);
    if (port == 22) {
        w.writeAll(host) catch return null;
    } else {
        w.print("[{s}]:{d}", .{ host, port }) catch return null;
    }
    const out = buf[0..w.end];
    for (out) |*c| c.* = std.ascii.toLower(c.*);
    return out;
}

// ---------------------------------------------------------------------------
// Pattern matching (OpenSSH match.c semantics)
// ---------------------------------------------------------------------------

/// Case-insensitive glob with `*` and `?`. Shared with ssh_config.zig
/// (Host patterns use identical semantics, split on whitespace not comma).
pub fn matchPattern(pattern: []const u8, name: []const u8) bool {
    // Iterative glob with single-star backtracking.
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and (pattern[p] == '?' or
            std.ascii.toLower(pattern[p]) == std.ascii.toLower(name[n])))
        {
            p += 1;
            n += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star_p = p;
            star_n = n;
            p += 1;
        } else if (star_p) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
        } else {
            return false;
        }
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Negation-aware list match: a negated hit vetoes the whole list.
pub fn matchPatternList(list: []const u8, name: []const u8, separator: u8) bool {
    var got_positive = false;
    var pats = std.mem.splitScalar(u8, list, separator);
    while (pats.next()) |raw| {
        var pat = std.mem.trim(u8, raw, " \t");
        if (pat.len == 0) continue;
        const negated = pat[0] == '!';
        if (negated) pat = pat[1..];
        if (matchPattern(pat, name)) {
            if (negated) return false;
            got_positive = true;
        }
    }
    return got_positive;
}

// ---------------------------------------------------------------------------
// Hashed entries
// ---------------------------------------------------------------------------

const hash_magic = "|1|";

fn matchesHashed(hosts: []const u8, canonical_host: []const u8) bool {
    if (!std.mem.startsWith(u8, hosts, hash_magic)) return false;
    const body = hosts[hash_magic.len..];
    const sep = std.mem.indexOfScalar(u8, body, '|') orelse return false;
    const salt_b64 = body[0..sep];
    const digest_b64 = body[sep + 1 ..];

    const decoder = std.base64.standard.Decoder;
    var salt: [HmacSha1.mac_length]u8 = undefined;
    var digest: [HmacSha1.mac_length]u8 = undefined;
    const salt_len = decoder.calcSizeForSlice(salt_b64) catch return false;
    const digest_len = decoder.calcSizeForSlice(digest_b64) catch return false;
    // ssh-keygen -H always emits 20-byte salt and HMAC-SHA1 digest.
    if (salt_len != salt.len or digest_len != digest.len) return false;
    decoder.decode(&salt, salt_b64) catch return false;
    decoder.decode(&digest, digest_b64) catch return false;

    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, canonical_host, &salt);
    return std.crypto.timing_safe.eql([HmacSha1.mac_length]u8, mac, digest);
}

// ---------------------------------------------------------------------------
// Writing entries
// ---------------------------------------------------------------------------

pub const WriteOptions = struct {
    /// Provide a (random) salt to write a hashed entry; null writes plain.
    hash_salt: ?[HmacSha1.mac_length]u8 = null,
};

/// Appends one entry in OpenSSH format (with trailing newline). The caller
/// owns transactionality (write to a temp file + rename for the real file).
pub fn writeEntry(
    w: *std.Io.Writer,
    host: []const u8,
    port: u16,
    key_blob: []const u8,
    options: WriteOptions,
) std.Io.Writer.Error!void {
    var canon_buf: [hostname_max + 8]u8 = undefined;
    // Oversized hostnames cannot be encoded; treat as a write failure.
    const canon = canonicalHost(&canon_buf, host, port) orelse return error.WriteFailed;
    const type_name = keys.blobTypeName(key_blob) orelse return error.WriteFailed;

    if (options.hash_salt) |salt| {
        var mac: [HmacSha1.mac_length]u8 = undefined;
        HmacSha1.create(&mac, canon, &salt);
        try w.writeAll(hash_magic);
        try w.printBase64(&salt);
        try w.writeByte('|');
        try w.printBase64(&mac);
    } else {
        try w.writeAll(canon);
    }
    try w.writeByte(' ');
    try w.writeAll(type_name);
    try w.writeByte(' ');
    try w.printBase64(key_blob);
    try w.writeByte('\n');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

fn expectUnknown(v: Verification) !void {
    switch (v) {
        .unknown => {},
        else => {
            std.debug.print("expected .unknown, got {t}\n", .{v});
            return error.TestUnexpectedVerification;
        },
    }
}

const Fixture = struct {
    text: []u8,
    key_a: keys.PublicKey,
    key_b: keys.PublicKey,
    key_rsa: keys.PublicKey,

    fn load() !Fixture {
        const text = try keys.fixtures.load(t.allocator, "known_hosts");
        errdefer t.allocator.free(text);
        var key_a = try loadPub("hostkey_a.pub");
        errdefer key_a.deinit();
        var key_b = try loadPub("hostkey_b.pub");
        errdefer key_b.deinit();
        var key_rsa = try loadPub("hostkey_rsa.pub");
        errdefer key_rsa.deinit();
        return .{ .text = text, .key_a = key_a, .key_b = key_b, .key_rsa = key_rsa };
    }

    fn loadPub(name: []const u8) !keys.PublicKey {
        const line = try keys.fixtures.load(t.allocator, name);
        defer t.allocator.free(line);
        return keys.parsePublicLine(t.allocator, line);
    }

    fn deinit(f: *Fixture) void {
        t.allocator.free(f.text);
        f.key_a.deinit();
        f.key_b.deinit();
        f.key_rsa.deinit();
    }
};

test "verify against ssh-keygen generated known_hosts" {
    var f = try Fixture.load();
    defer f.deinit();

    // Plain entry, exact key.
    {
        const v = try verify(t.allocator, f.text, "plain.example.com", 22, f.key_a.blob);
        try t.expectEqual(@as(usize, 1), v.known.line_number);
    }
    // Same host, different key of the same type: THE attack signal.
    {
        const v = try verify(t.allocator, f.text, "files.example.com", 22, f.key_b.blob);
        try t.expectEqual(@as(usize, 7), v.mismatch.line_number);
    }
    // Comma list and wildcard patterns.
    {
        const v = try verify(t.allocator, f.text, "beta.example.com", 22, f.key_rsa.blob);
        try t.expectEqual(@as(usize, 2), v.known.line_number);
        const w = try verify(t.allocator, f.text, "deep.wild.example.com", 22, f.key_rsa.blob);
        try t.expectEqual(@as(usize, 2), w.known.line_number);
    }
    // Non-default port entries only match their port.
    {
        const v = try verify(t.allocator, f.text, "port.example.com", 2222, f.key_a.blob);
        try t.expectEqual(@as(usize, 3), v.known.line_number);
        try expectUnknown(try verify(t.allocator, f.text, "port.example.com", 22, f.key_a.blob));
    }
    // Hashed entry (ssh-keygen -H ground truth for our HMAC-SHA1 path).
    {
        const v = try verify(t.allocator, f.text, "hashed.example.com", 22, f.key_a.blob);
        try t.expectEqual(@as(usize, 4), v.known.line_number);
        // Hashed entries must not match other hosts.
        try expectUnknown(try verify(t.allocator, f.text, "other.example.org", 22, f.key_a.blob));
    }
    // Revoked key is flagged, not just "known".
    {
        const v = try verify(t.allocator, f.text, "revoked.example.com", 22, f.key_b.blob);
        try t.expectEqual(@as(usize, 5), v.revoked.line_number);
    }
    // @cert-authority lines never vouch for plain keys.
    {
        const ca_line = try keys.fixtures.load(t.allocator, "ca_key.pub");
        defer t.allocator.free(ca_line);
        var ca = try keys.parsePublicLine(t.allocator, ca_line);
        defer ca.deinit();
        try expectUnknown(try verify(t.allocator, f.text, "x.corp.example.com", 22, ca.blob));
    }
    // Hostname matching is case-insensitive.
    {
        const v = try verify(t.allocator, f.text, "PLAIN.example.COM", 22, f.key_a.blob);
        try t.expectEqual(@as(usize, 1), v.known.line_number);
    }
}

test "known beats earlier mismatch; revoked beats known" {
    var f = try Fixture.load();
    defer f.deinit();
    var buf: [4096]u8 = undefined;

    // Line 1 = host with key B (wrong), line 2 = host with key A (right).
    var w: std.Io.Writer = .fixed(&buf);
    try writeEntry(&w, "h.example.com", 22, f.key_b.blob, .{});
    try writeEntry(&w, "h.example.com", 22, f.key_a.blob, .{});
    const v = try verify(t.allocator, buf[0..w.end], "h.example.com", 22, f.key_a.blob);
    try t.expectEqual(@as(usize, 2), v.known.line_number);

    // Same key both plain and @revoked: revocation wins.
    w = .fixed(&buf);
    try writeEntry(&w, "h.example.com", 22, f.key_a.blob, .{});
    try w.writeAll("@revoked ");
    try writeEntry(&w, "h.example.com", 22, f.key_a.blob, .{});
    const r = try verify(t.allocator, buf[0..w.end], "h.example.com", 22, f.key_a.blob);
    try t.expectEqual(@as(usize, 2), r.revoked.line_number);
}

test "negation vetoes a matching list" {
    try t.expect(matchPatternList("*.example.com,!evil.example.com", "good.example.com", ','));
    try t.expect(!matchPatternList("*.example.com,!evil.example.com", "evil.example.com", ','));
    try t.expect(!matchPatternList("!*", "anything", ','));
    try t.expect(matchPattern("?ost.example.*", "host.example.org"));
    try t.expect(!matchPattern("?ost", "oost.example.org"));
    try t.expect(matchPattern("*", "x"));
    try t.expect(!matchPattern("", "x"));
    try t.expect(matchPattern("", ""));
}

test "writeEntry plain and hashed round-trip" {
    var f = try Fixture.load();
    defer f.deinit();

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeEntry(&w, "New.Example.Com", 22, f.key_a.blob, .{});
    try writeEntry(&w, "new.example.com", 2200, f.key_a.blob, .{ .hash_salt = [_]u8{7} ** 20 });
    const written = buf[0..w.end];

    // Plain line is canonical OpenSSH format (lowercased host).
    try t.expect(std.mem.startsWith(u8, written, "new.example.com ssh-ed25519 "));
    // And both round-trip through our own verifier.
    const v1 = try verify(t.allocator, written, "new.example.com", 22, f.key_a.blob);
    try t.expectEqual(@as(usize, 1), v1.known.line_number);
    const v2 = try verify(t.allocator, written, "NEW.example.com", 2200, f.key_a.blob);
    try t.expectEqual(@as(usize, 2), v2.known.line_number);
    try expectUnknown(try verify(t.allocator, written, "new.example.com", 2201, f.key_a.blob));
}

test "hashed writer reproduces ssh-keygen -H output for the same salt" {
    var f = try Fixture.load();
    defer f.deinit();
    // Line 4 is `ssh-keygen -H` output for hashed.example.com. Reuse its salt;
    // our HMAC + encoding must reproduce the hosts token byte for byte.
    var it: LineIterator = .{ .text = f.text };
    var line4: ?Entry = null;
    while (it.next()) |e| {
        if (e.line_number == 4) line4 = e;
    }
    const entry = line4.?;
    const body = entry.hosts[hash_magic.len..];
    const sep = std.mem.indexOfScalar(u8, body, '|').?;
    var salt: [20]u8 = undefined;
    try std.base64.standard.Decoder.decode(&salt, body[0..sep]);

    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeEntry(&w, "hashed.example.com", 22, f.key_a.blob, .{ .hash_salt = salt });
    const our_hosts = buf[0..std.mem.indexOfScalar(u8, buf[0..w.end], ' ').?];
    try t.expectEqualStrings(entry.hosts, our_hosts);
}

test "parseLine rejects malformed input" {
    try t.expectEqual(null, try parseLine("", 1));
    try t.expectEqual(null, try parseLine("# comment", 1));
    try t.expectError(error.MalformedLine, parseLine("host", 1));
    try t.expectError(error.MalformedLine, parseLine("host ssh-ed25519", 1));
    try t.expectError(error.MalformedLine, parseLine("@bogus host ssh-ed25519 AAAA", 1));
    try t.expectError(error.MalformedLine, parseLine("host ssh-ed25519 not&base64", 1));
    try t.expectError(error.MalformedLine, parseLine("host bad!algo AAAA", 1));
    // Unsupported but plausible algorithm still parses.
    const e = (try parseLine("host sk-ssh-ed25519@openssh.com AAAAdGVzdA== c", 1)).?;
    try t.expectEqualStrings("sk-ssh-ed25519@openssh.com", e.key_type);
}

test "verify survives allocation failure" {
    var f = try Fixture.load();
    defer f.deinit();
    const Check = struct {
        fn run(gpa: Allocator, text: []const u8, blob: []const u8) !void {
            _ = verify(gpa, text, "plain.example.com", 22, blob) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{ f.text, f.key_a.blob });
}

test "fuzz known_hosts line parser and verifier" {
    try t.fuzz({}, fuzzKnownHosts, .{});
}

fn fuzzKnownHosts(_: void, smith: *t.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len = smith.slice(&buf);
    const text = buf[0..len];
    _ = parseLine(text, 1) catch null;
    var blob_buf: [64]u8 = undefined;
    const blob_len = smith.slice(&blob_buf);
    _ = try verify(t.allocator, text, "host.example.com", 22, blob_buf[0..blob_len]);
    _ = try verify(t.allocator, text, "host.example.com", 2222, blob_buf[0..blob_len]);
}

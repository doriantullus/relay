//! openssh-key-v1 private key container + authorized_keys public line
//! parsing, pure Zig. Covers ssh-ed25519, ssh-rsa and ecdsa-sha2-nistp256,
//! unencrypted or encrypted with bcrypt KDF (`std.crypto.bcrypt.opensshKdf`)
//! + aes256-ctr / aes256-gcm@openssh.com — exactly what `ssh-keygen` has
//! emitted by default since OpenSSH 7.8.
//!
//! All parse results are arena-per-result: one `deinit` frees everything and
//! securely zeroes private material. Decrypted plaintext scratch is zeroed
//! before being freed, so secrets never linger in freed heap memory.

const std = @import("std");
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

pub const Error = error{
    OutOfMemory,
    /// Structurally not a valid key (bad armor, bad base64, bad framing).
    InvalidKey,
    UnsupportedCipher,
    UnsupportedKdf,
    UnsupportedKeyType,
    /// Encrypted key and no (or empty) passphrase supplied.
    PassphraseRequired,
    /// Decryption succeeded structurally but the checkint pair (or the
    /// AES-GCM tag) did not validate.
    WrongPassphrase,
};

pub const KeyType = enum {
    ssh_ed25519,
    ssh_rsa,
    ecdsa_sha2_nistp256,

    pub fn fromName(n: []const u8) ?KeyType {
        if (std.mem.eql(u8, n, "ssh-ed25519")) return .ssh_ed25519;
        if (std.mem.eql(u8, n, "ssh-rsa")) return .ssh_rsa;
        if (std.mem.eql(u8, n, "ecdsa-sha2-nistp256")) return .ecdsa_sha2_nistp256;
        return null;
    }

    pub fn name(kt: KeyType) []const u8 {
        return switch (kt) {
            .ssh_ed25519 => "ssh-ed25519",
            .ssh_rsa => "ssh-rsa",
            .ecdsa_sha2_nistp256 => "ecdsa-sha2-nistp256",
        };
    }
};

pub const Cipher = enum {
    none,
    aes256_ctr,
    aes256_gcm,

    fn fromName(n: []const u8) ?Cipher {
        if (std.mem.eql(u8, n, "none")) return .none;
        if (std.mem.eql(u8, n, "aes256-ctr")) return .aes256_ctr;
        if (std.mem.eql(u8, n, "aes256-gcm@openssh.com")) return .aes256_gcm;
        return null;
    }
};

/// Type-specific private material. Slices are arena-owned; secret-bearing
/// fields are securely zeroed by `PrivateKey.deinit`.
pub const Material = union(KeyType) {
    ssh_ed25519: struct {
        public: [32]u8,
        /// OpenSSH layout: 32-byte seed ++ 32-byte public.
        secret: [64]u8,
    },
    ssh_rsa: struct {
        // SSH mpint encodings, minimal form, no sign bytes needed (positive).
        n: []u8,
        e: []u8,
        d: []u8,
        iqmp: []u8,
        p: []u8,
        q: []u8,
    },
    ecdsa_sha2_nistp256: struct {
        /// SEC1 uncompressed point (0x04 || X || Y), 65 bytes for P-256.
        point: []u8,
        scalar: []u8,
    },
};

pub const PrivateKey = struct {
    arena: ArenaAllocator,
    key_type: KeyType,
    /// How the on-disk file was protected (UI: lock badge).
    cipher: Cipher,
    /// SSH wire-format public key blob — the currency for agent matching,
    /// known_hosts comparison and fingerprints.
    public_blob: []u8,
    comment: []u8,
    material: Material,

    pub fn fingerprint(k: *const PrivateKey) [fingerprint_len]u8 {
        return fingerprintSha256(k.public_blob);
    }

    pub fn deinit(k: *PrivateKey) void {
        switch (k.material) {
            .ssh_ed25519 => |*m| std.crypto.secureZero(u8, &m.secret),
            .ssh_rsa => |m| for ([_][]u8{ m.d, m.iqmp, m.p, m.q }) |s| {
                std.crypto.secureZero(u8, s);
            },
            .ecdsa_sha2_nistp256 => |m| std.crypto.secureZero(u8, m.scalar),
        }
        k.arena.deinit();
        k.* = undefined;
    }
};

pub const PublicKey = struct {
    arena: ArenaAllocator,
    key_type: KeyType,
    blob: []u8,
    comment: []u8,

    pub fn fingerprint(k: *const PublicKey) [fingerprint_len]u8 {
        return fingerprintSha256(k.blob);
    }

    pub fn deinit(k: *PublicKey) void {
        k.arena.deinit();
        k.* = undefined;
    }
};

/// "SHA256:" ++ 43 chars of unpadded base64 — same output as ssh-keygen -lf.
pub const fingerprint_len = "SHA256:".len + 43;

pub fn fingerprintSha256(public_blob: []const u8) [fingerprint_len]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(public_blob, &digest, .{});
    var out: [fingerprint_len]u8 = undefined;
    out[0.."SHA256:".len].* = "SHA256:".*;
    _ = std.base64.standard_no_pad.Encoder.encode(out["SHA256:".len..], &digest);
    return out;
}

/// First wire string of a public key blob, i.e. its algorithm name.
/// Null if the blob is too mangled to contain one.
pub fn blobTypeName(blob: []const u8) ?[]const u8 {
    var r: WireReader = .{ .buf = blob };
    const n = r.takeString() catch return null;
    if (n.len == 0 or n.len > 64) return null;
    return n;
}

// ---------------------------------------------------------------------------
// authorized_keys / *.pub line parsing
// ---------------------------------------------------------------------------

/// Parses one authorized_keys-format line: `[options] type base64 [comment]`.
/// A leading options field (quote-aware) is tolerated and skipped.
pub fn parsePublicLine(gpa: Allocator, line: []const u8) Error!PublicKey {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] == '#') return error.InvalidKey;

    var rest = trimmed;
    var type_tok = takeToken(&rest) orelse return error.InvalidKey;
    if (KeyType.fromName(type_tok) == null) {
        // Not a key type: must be the options field; skip it (it may contain
        // quoted whitespace, e.g. command="...").
        rest = trimmed[skipOptions(trimmed)..];
        rest = std.mem.trimStart(u8, rest, " \t");
        type_tok = takeToken(&rest) orelse return error.InvalidKey;
    }
    const key_type = KeyType.fromName(type_tok) orelse return error.UnsupportedKeyType;
    const b64 = takeToken(&rest) orelse return error.InvalidKey;
    const comment = std.mem.trim(u8, rest, " \t");

    var arena: ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const blob = decodeBase64Alloc(a, b64) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidKey,
    };
    const inner = blobTypeName(blob) orelse return error.InvalidKey;
    if (!std.mem.eql(u8, inner, type_tok)) return error.InvalidKey;

    // All arena allocation must precede the struct literal: `.arena = arena`
    // copies the arena state, and later allocations would not survive deinit.
    const comment_copy = try a.dupe(u8, comment);
    return .{
        .arena = arena,
        .key_type = key_type,
        .blob = blob,
        .comment = comment_copy,
    };
}

fn takeToken(rest: *[]const u8) ?[]const u8 {
    const s = std.mem.trimStart(u8, rest.*, " \t");
    if (s.len == 0) {
        rest.* = s;
        return null;
    }
    const end = std.mem.indexOfAny(u8, s, " \t") orelse s.len;
    rest.* = s[end..];
    return s[0..end];
}

/// Length of the leading options field: scans to the first unquoted
/// whitespace, honoring double quotes and backslash escapes (sshd(8)).
fn skipOptions(s: []const u8) usize {
    var i: usize = 0;
    var quoted = false;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '\\' and i + 1 < s.len) {
            i += 1;
        } else if (c == '"') {
            quoted = !quoted;
        } else if (!quoted and (c == ' ' or c == '\t')) {
            return i;
        }
    }
    return s.len;
}

// ---------------------------------------------------------------------------
// openssh-key-v1 private key container
// ---------------------------------------------------------------------------

const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
const pem_end = "-----END OPENSSH PRIVATE KEY-----";
const auth_magic = "openssh-key-v1\x00";
/// Defense against absurd KDF work factors in hostile files; ssh-keygen's
/// default is 16 and even paranoid real-world keys stay well under this.
const max_kdf_rounds = 1024;
/// Container cap: largest legit private key files (RSA-4096) are ~3.4 KiB.
const max_container_len = 1 << 20;

/// True if the PEM holds an encrypted container (passphrase prompt needed).
/// Cheap: decodes the armor and reads only the cipher name.
pub fn privateKeyIsEncrypted(gpa: Allocator, pem_text: []const u8) Error!bool {
    const bin = try decodeArmor(gpa, pem_text);
    defer {
        std.crypto.secureZero(u8, bin);
        gpa.free(bin);
    }
    var r: WireReader = .{ .buf = bin };
    try expectMagic(&r);
    const cipher_name = r.takeString() catch return error.InvalidKey;
    const cipher = Cipher.fromName(cipher_name) orelse return error.UnsupportedCipher;
    return cipher != .none;
}

/// Parses (and if needed decrypts) an OpenSSH private key file.
/// Errors are classified into `diag`: wrong/missing passphrase -> .auth
/// (drives the interactive prompt), everything else -> .permanent.
pub fn parsePrivateKey(
    gpa: Allocator,
    pem_text: []const u8,
    passphrase: ?[]const u8,
    diag: *Diagnostics,
) Error!PrivateKey {
    return parsePrivateKeyInner(gpa, pem_text, passphrase) catch |err| {
        switch (err) {
            error.PassphraseRequired => diag.set(.auth, 0, "private key is encrypted: passphrase required", .{}),
            error.WrongPassphrase => diag.set(.auth, 0, "wrong passphrase for private key", .{}),
            error.InvalidKey => diag.set(.permanent, 0, "malformed OpenSSH private key", .{}),
            error.UnsupportedCipher => diag.set(.permanent, 0, "unsupported private key cipher", .{}),
            error.UnsupportedKdf => diag.set(.permanent, 0, "unsupported private key KDF", .{}),
            error.UnsupportedKeyType => diag.set(.permanent, 0, "unsupported key type", .{}),
            error.OutOfMemory => {},
        }
        return err;
    };
}

fn parsePrivateKeyInner(
    gpa: Allocator,
    pem_text: []const u8,
    passphrase: ?[]const u8,
) Error!PrivateKey {
    const bin = try decodeArmor(gpa, pem_text);
    defer {
        std.crypto.secureZero(u8, bin);
        gpa.free(bin);
    }

    var r: WireReader = .{ .buf = bin };
    try expectMagic(&r);
    const cipher_name = try r.takeString();
    const cipher = Cipher.fromName(cipher_name) orelse return error.UnsupportedCipher;
    const kdf_name = try r.takeString();
    const kdf_options = try r.takeString();

    const encrypted = cipher != .none;
    if (std.mem.eql(u8, kdf_name, "none")) {
        // "none" KDF with a real cipher (or stray KDF options) is malformed.
        if (encrypted or kdf_options.len != 0) return error.InvalidKey;
    } else if (std.mem.eql(u8, kdf_name, "bcrypt")) {
        if (!encrypted) return error.InvalidKey;
    } else {
        return error.UnsupportedKdf;
    }

    const n_keys = try r.takeU32();
    // OpenSSH has only ever written exactly one key per container.
    if (n_keys != 1) return error.InvalidKey;

    const public_blob = try r.takeString();
    const pub_type_name = blobTypeName(public_blob) orelse return error.InvalidKey;
    const key_type = KeyType.fromName(pub_type_name) orelse return error.UnsupportedKeyType;

    const enc_section = try r.takeString();
    const tag: ?*const [16]u8 = if (cipher == .aes256_gcm) (try r.takeBytes(16))[0..16] else null;
    try r.expectEnd();

    // Both supported AES variants pad the plaintext to 16-byte blocks; the
    // "none" cipher pads to 8.
    const block: usize = if (encrypted) 16 else 8;
    if (enc_section.len == 0 or enc_section.len % block != 0) return error.InvalidKey;

    const section = try gpa.dupe(u8, enc_section);
    defer {
        std.crypto.secureZero(u8, section);
        gpa.free(section);
    }

    if (encrypted) {
        const pass = passphrase orelse return error.PassphraseRequired;
        if (pass.len == 0) return error.PassphraseRequired;

        var kdf_r: WireReader = .{ .buf = kdf_options };
        const salt = try kdf_r.takeString();
        const rounds = try kdf_r.takeU32();
        try kdf_r.expectEnd();
        if (salt.len == 0 or salt.len > 64) return error.InvalidKey;
        if (rounds == 0) return error.InvalidKey;
        if (rounds > max_kdf_rounds) return error.UnsupportedKdf;

        // 32-byte AES-256 key ++ IV (16 for CTR, 12-byte nonce for GCM).
        var derived: [48]u8 = undefined;
        defer std.crypto.secureZero(u8, &derived);
        const iv_len: usize = if (cipher == .aes256_gcm) 12 else 16;
        std.crypto.pwhash.bcrypt.opensshKdf(pass, salt, derived[0 .. 32 + iv_len], rounds) catch
            return error.InvalidKey;

        switch (cipher) {
            .none => unreachable,
            .aes256_ctr => {
                const ctx = std.crypto.core.aes.Aes256.initEnc(derived[0..32].*);
                std.crypto.core.modes.ctr(@TypeOf(ctx), ctx, section, section, derived[32..48].*, .big);
            },
            .aes256_gcm => {
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                    section,
                    section,
                    tag.?.*,
                    "",
                    derived[32..44].*,
                    derived[0..32].*,
                ) catch return error.WrongPassphrase;
            },
        }
    }

    var s: WireReader = .{ .buf = section };
    const check1 = try s.takeU32();
    const check2 = try s.takeU32();
    if (check1 != check2) {
        // For an encrypted key this is the wrong-passphrase signal (CTR has
        // no authentication tag); for a plaintext key it is just corruption.
        return if (encrypted) error.WrongPassphrase else error.InvalidKey;
    }

    const inner_type_name = try s.takeString();
    if (!std.mem.eql(u8, inner_type_name, pub_type_name)) return error.InvalidKey;

    var arena: ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const material: Material = switch (key_type) {
        .ssh_ed25519 => blk: {
            const pub_part = try s.takeString();
            const sec_part = try s.takeString();
            if (pub_part.len != 32 or sec_part.len != 64) return error.InvalidKey;
            // The secret's trailing half repeats the public key; all three
            // copies (incl. the outer blob) must agree.
            if (!std.mem.eql(u8, sec_part[32..], pub_part)) return error.InvalidKey;
            var pub_r: WireReader = .{ .buf = public_blob };
            _ = try pub_r.takeString();
            const blob_pub = try pub_r.takeString();
            try pub_r.expectEnd();
            if (!std.mem.eql(u8, blob_pub, pub_part)) return error.InvalidKey;
            break :blk .{ .ssh_ed25519 = .{
                .public = pub_part[0..32].*,
                .secret = sec_part[0..64].*,
            } };
        },
        .ssh_rsa => blk: {
            const n = try s.takeMpint();
            const e = try s.takeMpint();
            const d = try s.takeMpint();
            const iqmp = try s.takeMpint();
            const p = try s.takeMpint();
            const q = try s.takeMpint();
            var pub_r: WireReader = .{ .buf = public_blob };
            _ = try pub_r.takeString();
            const blob_e = try pub_r.takeMpint();
            const blob_n = try pub_r.takeMpint();
            try pub_r.expectEnd();
            if (!std.mem.eql(u8, blob_n, n) or !std.mem.eql(u8, blob_e, e)) return error.InvalidKey;
            break :blk .{ .ssh_rsa = .{
                .n = try a.dupe(u8, n),
                .e = try a.dupe(u8, e),
                .d = try a.dupe(u8, d),
                .iqmp = try a.dupe(u8, iqmp),
                .p = try a.dupe(u8, p),
                .q = try a.dupe(u8, q),
            } };
        },
        .ecdsa_sha2_nistp256 => blk: {
            const curve = try s.takeString();
            if (!std.mem.eql(u8, curve, "nistp256")) return error.InvalidKey;
            const point = try s.takeString();
            const scalar = try s.takeMpint();
            // SEC1 uncompressed point for P-256.
            if (point.len != 65 or point[0] != 0x04) return error.InvalidKey;
            var pub_r: WireReader = .{ .buf = public_blob };
            _ = try pub_r.takeString();
            const blob_curve = try pub_r.takeString();
            const blob_point = try pub_r.takeString();
            try pub_r.expectEnd();
            if (!std.mem.eql(u8, blob_curve, curve) or !std.mem.eql(u8, blob_point, point))
                return error.InvalidKey;
            break :blk .{ .ecdsa_sha2_nistp256 = .{
                .point = try a.dupe(u8, point),
                .scalar = try a.dupe(u8, scalar),
            } };
        },
    };

    const comment = try s.takeString();

    // Deterministic padding: 1, 2, 3, ... up to the cipher block size.
    const padding = s.remaining();
    if (padding.len >= block) return error.InvalidKey;
    for (padding, 1..) |b, i| {
        if (b != i) return error.InvalidKey;
    }

    // All arena allocation must precede the struct literal: `.arena = arena`
    // copies the arena state, and later allocations would not survive deinit.
    const public_blob_copy = try a.dupe(u8, public_blob);
    const comment_copy = try a.dupe(u8, comment);
    return .{
        .arena = arena,
        .key_type = key_type,
        .cipher = cipher,
        .public_blob = public_blob_copy,
        .comment = comment_copy,
        .material = material,
    };
}

fn expectMagic(r: *WireReader) Error!void {
    const m = r.takeBytes(auth_magic.len) catch return error.InvalidKey;
    if (!std.mem.eql(u8, m, auth_magic)) return error.InvalidKey;
}

/// PEM armor -> decoded binary container, caller owns (and zeroes) result.
fn decodeArmor(gpa: Allocator, pem_text: []const u8) Error![]u8 {
    const begin = std.mem.indexOf(u8, pem_text, pem_begin) orelse return error.InvalidKey;
    const body_start = begin + pem_begin.len;
    const end = std.mem.indexOfPos(u8, pem_text, body_start, pem_end) orelse return error.InvalidKey;
    const body = pem_text[body_start..end];
    if (body.len > max_container_len) return error.InvalidKey;

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const scratch = try gpa.alloc(u8, decoder.calcSizeUpperBound(body.len));
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }
    const n = decoder.decode(scratch, body) catch return error.InvalidKey;
    return gpa.dupe(u8, scratch[0..n]);
}

fn decodeBase64Alloc(a: Allocator, b64: []const u8) (Allocator.Error || std.base64.Error)![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(b64);
    const buf = try a.alloc(u8, size);
    try decoder.decode(buf, b64);
    return buf;
}

/// SSH wire-format reader over a byte slice. All failures collapse to
/// error.InvalidKey: a parse error in hostile input is not interesting
/// beyond "reject".
const WireReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn takeU32(r: *WireReader) Error!u32 {
        const b = try r.takeBytes(4);
        return std.mem.readInt(u32, b[0..4], .big);
    }

    fn takeString(r: *WireReader) Error![]const u8 {
        const len = try r.takeU32();
        if (len > r.buf.len - r.pos) return error.InvalidKey;
        return r.takeBytes(len);
    }

    /// String holding a non-negative mpint in minimal encoding.
    fn takeMpint(r: *WireReader) Error![]const u8 {
        const s = try r.takeString();
        if (s.len > 0 and s[0] == 0x00) {
            // Leading zero is only valid to clear a would-be sign bit.
            if (s.len == 1 or s[1] < 0x80) return error.InvalidKey;
        }
        return s;
    }

    fn takeBytes(r: *WireReader, n: usize) Error![]const u8 {
        if (n > r.buf.len - r.pos) return error.InvalidKey;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    fn remaining(r: *const WireReader) []const u8 {
        return r.buf[r.pos..];
    }

    fn expectEnd(r: *const WireReader) Error!void {
        if (r.pos != r.buf.len) return error.InvalidKey;
    }
};

// ---------------------------------------------------------------------------
// Test support: fixture loading (shared by the other proto/ssh module tests).
// ---------------------------------------------------------------------------

pub const fixtures = struct {
    const dir_path = "test/fixtures/ssh";

    /// Reads a fixture relative to the repo root, searching upward from the
    /// test runner's cwd so `zig build test` works from subdirectories too.
    pub fn load(gpa: Allocator, name: []const u8) ![]u8 {
        const io = std.testing.io;
        var path_buf: [256]u8 = undefined;
        var prefix_buf: [24]u8 = undefined; // up to 8 "../" levels
        var prefix_len: usize = 0;
        while (prefix_len <= prefix_buf.len - 3) : (prefix_len += 3) {
            const path = try std.fmt.bufPrint(&path_buf, "{s}{s}/{s}", .{
                prefix_buf[0..prefix_len], dir_path, name,
            });
            return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
                error.FileNotFound => {
                    prefix_buf[prefix_len..][0..3].* = "../".*;
                    continue;
                },
                else => err,
            };
        }
        std.debug.print("ssh fixture not found from cwd: {s}/{s}\n", .{ dir_path, name });
        return error.FileNotFound;
    }

    /// Looks up `<name> <SHA256:...>` in fingerprints.txt (ssh-keygen -lf
    /// ground truth, baked at fixture generation time).
    pub fn expectedFingerprint(gpa: Allocator, name: []const u8) ![]u8 {
        const text = try load(gpa, "fingerprints.txt");
        defer gpa.free(text);
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.tokenizeScalar(u8, line, ' ');
            const file = fields.next() orelse continue;
            const fp = fields.next() orelse continue;
            if (std.mem.eql(u8, file, name)) return gpa.dupe(u8, fp);
        }
        return error.FixtureMissingFingerprint;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

fn expectFixtureFingerprint(comptime priv_name: []const u8, expect_type: KeyType, pass: ?[]const u8) !void {
    const pem = try fixtures.load(t.allocator, priv_name);
    defer t.allocator.free(pem);
    const want_fp = try fixtures.expectedFingerprint(t.allocator, priv_name);
    defer t.allocator.free(want_fp);

    var d: Diagnostics = .{};
    var key = try parsePrivateKey(t.allocator, pem, pass, &d);
    defer key.deinit();
    try t.expectEqual(expect_type, key.key_type);
    const fp = key.fingerprint();
    try t.expectEqualStrings(want_fp, &fp);
    try t.expectEqualStrings("relay-test", key.comment);

    // The .pub sidecar must agree on blob and fingerprint.
    const pub_line = try fixtures.load(t.allocator, priv_name ++ ".pub");
    defer t.allocator.free(pub_line);
    var pk = try parsePublicLine(t.allocator, pub_line);
    defer pk.deinit();
    try t.expectEqualSlices(u8, key.public_blob, pk.blob);
    const pub_fp = pk.fingerprint();
    try t.expectEqualStrings(want_fp, &pub_fp);
}

test "ed25519 unencrypted matches ssh-keygen fingerprint" {
    try expectFixtureFingerprint("id_ed25519", .ssh_ed25519, null);
}

test "rsa-3072 unencrypted matches ssh-keygen fingerprint" {
    try expectFixtureFingerprint("id_rsa_3072", .ssh_rsa, null);
}

test "ecdsa-p256 unencrypted matches ssh-keygen fingerprint" {
    try expectFixtureFingerprint("id_ecdsa_p256", .ecdsa_sha2_nistp256, null);
}

test "ed25519 aes256-ctr decrypts with correct passphrase" {
    try expectFixtureFingerprint("id_ed25519_pw", .ssh_ed25519, "relay-test");
}

test "ed25519 aes256-gcm decrypts with correct passphrase" {
    try expectFixtureFingerprint("id_ed25519_gcm", .ssh_ed25519, "relay-test");
}

test "ed25519 material is internally consistent" {
    const pem = try fixtures.load(t.allocator, "id_ed25519");
    defer t.allocator.free(pem);
    var d: Diagnostics = .{};
    var key = try parsePrivateKey(t.allocator, pem, null, &d);
    defer key.deinit();
    const m = key.material.ssh_ed25519;
    try t.expectEqualSlices(u8, &m.public, m.secret[32..]);
    try t.expectEqual(Cipher.none, key.cipher);
}

test "wrong passphrase on aes256-ctr key is a clean auth error" {
    const pem = try fixtures.load(t.allocator, "id_ed25519_pw");
    defer t.allocator.free(pem);
    var d: Diagnostics = .{};
    try t.expectError(error.WrongPassphrase, parsePrivateKey(t.allocator, pem, "nope", &d));
    try t.expectEqual(diag_mod.ErrorClass.auth, d.class);
}

test "wrong passphrase on aes256-gcm key is a clean auth error" {
    const pem = try fixtures.load(t.allocator, "id_ed25519_gcm");
    defer t.allocator.free(pem);
    var d: Diagnostics = .{};
    try t.expectError(error.WrongPassphrase, parsePrivateKey(t.allocator, pem, "nope", &d));
    try t.expectEqual(diag_mod.ErrorClass.auth, d.class);
}

test "encrypted key without passphrase reports PassphraseRequired" {
    const pem = try fixtures.load(t.allocator, "id_ed25519_pw");
    defer t.allocator.free(pem);
    var d: Diagnostics = .{};
    try t.expectError(error.PassphraseRequired, parsePrivateKey(t.allocator, pem, null, &d));
    try t.expectEqual(diag_mod.ErrorClass.auth, d.class);
    d.clear();
    try t.expectError(error.PassphraseRequired, parsePrivateKey(t.allocator, pem, "", &d));
}

test "privateKeyIsEncrypted" {
    const plain = try fixtures.load(t.allocator, "id_ed25519");
    defer t.allocator.free(plain);
    const enc = try fixtures.load(t.allocator, "id_ed25519_pw");
    defer t.allocator.free(enc);
    try t.expect(!try privateKeyIsEncrypted(t.allocator, plain));
    try t.expect(try privateKeyIsEncrypted(t.allocator, enc));
}

test "public line with options field and missing comment" {
    const pub_line = try fixtures.load(t.allocator, "id_ed25519.pub");
    defer t.allocator.free(pub_line);
    var it = std.mem.tokenizeAny(u8, pub_line, " \n");
    const type_tok = it.next().?;
    const b64 = it.next().?;

    const line = try std.fmt.allocPrint(
        t.allocator,
        "command=\"echo a b\",no-pty {s} {s}",
        .{ type_tok, b64 },
    );
    defer t.allocator.free(line);
    var pk = try parsePublicLine(t.allocator, line);
    defer pk.deinit();
    try t.expectEqual(KeyType.ssh_ed25519, pk.key_type);
    try t.expectEqualStrings("", pk.comment);
}

test "public line rejects garbage" {
    try t.expectError(error.InvalidKey, parsePublicLine(t.allocator, ""));
    try t.expectError(error.InvalidKey, parsePublicLine(t.allocator, "# comment"));
    try t.expectError(error.UnsupportedKeyType, parsePublicLine(t.allocator, "opt ssh-dss AAAA x"));
    try t.expectError(error.InvalidKey, parsePublicLine(t.allocator, "ssh-ed25519 !!! c"));
    // Valid base64 but inner type does not match the outer name.
    try t.expectError(error.InvalidKey, parsePublicLine(t.allocator, "ssh-ed25519 AAAABHNzaA== c"));
}

test "container rejects truncation at every length" {
    const pem = try fixtures.load(t.allocator, "id_ed25519");
    defer t.allocator.free(pem);
    var d: Diagnostics = .{};
    var key = try parsePrivateKey(t.allocator, pem, null, &d);
    key.deinit();
    // Re-armor truncated binary containers: every prefix must be rejected.
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const body = pem[std.mem.indexOf(u8, pem, pem_begin).? + pem_begin.len .. std.mem.indexOf(u8, pem, pem_end).?];
    const bin = try t.allocator.alloc(u8, decoder.calcSizeUpperBound(body.len));
    defer t.allocator.free(bin);
    const bin_len = try decoder.decode(bin, body);
    var b64_buf: [8192]u8 = undefined;
    var pem_buf: [8192 + 128]u8 = undefined;
    var len: usize = 0;
    while (len < bin_len) : (len += 7) {
        const b64 = std.base64.standard.Encoder.encode(&b64_buf, bin[0..len]);
        const txt = try std.fmt.bufPrint(&pem_buf, "{s}\n{s}\n{s}\n", .{ pem_begin, b64, pem_end });
        try t.expectError(error.InvalidKey, parsePrivateKey(t.allocator, txt, null, &d));
    }
}

test "parsers survive allocation failure" {
    const Check = struct {
        fn parsePriv(gpa: Allocator, pem: []const u8, pass: ?[]const u8) !void {
            var d: Diagnostics = .{};
            var key = parsePrivateKey(gpa, pem, pass, &d) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            key.deinit();
        }
        fn parsePub(gpa: Allocator, line: []const u8) !void {
            var pk = parsePublicLine(gpa, line) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            pk.deinit();
        }
    };
    inline for (.{ "id_ed25519", "id_rsa_3072", "id_ecdsa_p256" }) |name| {
        const pem = try fixtures.load(t.allocator, name);
        defer t.allocator.free(pem);
        try t.checkAllAllocationFailures(t.allocator, Check.parsePriv, .{ pem, null });
    }
    // Encrypted path (gcm fixture uses 8 KDF rounds, keeps this fast-ish).
    const enc = try fixtures.load(t.allocator, "id_ed25519_gcm");
    defer t.allocator.free(enc);
    try t.checkAllAllocationFailures(t.allocator, Check.parsePriv, .{ enc, "relay-test" });

    const pub_line = try fixtures.load(t.allocator, "id_rsa_3072.pub");
    defer t.allocator.free(pub_line);
    try t.checkAllAllocationFailures(t.allocator, Check.parsePub, .{pub_line});
}

test "fuzz openssh-key-v1 container parser" {
    try t.fuzz({}, fuzzContainer, .{});
}

fn fuzzContainer(_: void, smith: *t.Smith) !void {
    var raw: [2048]u8 = undefined;
    const raw_len = smith.slice(&raw);

    var text_buf: [3200]u8 = undefined;
    var input: []const u8 = raw[0..raw_len];
    if (smith.value(bool)) {
        // Re-armor so fuzzing reaches past the base64 layer: valid PEM
        // wrapper, attacker-controlled binary container (magic stitched on
        // half the time to reach the framing code).
        var bin_buf: [1024]u8 = undefined;
        var bin_len: usize = 0;
        if (smith.value(bool)) {
            @memcpy(bin_buf[0..auth_magic.len], auth_magic);
            bin_len = auth_magic.len;
        }
        const extra = @min(raw_len, bin_buf.len - bin_len);
        @memcpy(bin_buf[bin_len..][0..extra], raw[0..extra]);
        bin_len += extra;
        var b64_buf: [1400]u8 = undefined;
        const b64 = std.base64.standard.Encoder.encode(&b64_buf, bin_buf[0..bin_len]);
        input = std.fmt.bufPrint(&text_buf, "{s}\n{s}\n{s}\n", .{ pem_begin, b64, pem_end }) catch unreachable;
    }

    var d: Diagnostics = .{};
    // Never a passphrase here: hostile KDF params must be rejected before any
    // KDF work, and rejection paths are what we want covered.
    var key = parsePrivateKey(t.allocator, input, null, &d) catch return;
    key.deinit();
}

test "fuzz public line parser" {
    try t.fuzz({}, fuzzPublicLine, .{});
}

fn fuzzPublicLine(_: void, smith: *t.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    var pk = parsePublicLine(t.allocator, buf[0..len]) catch return;
    pk.deinit();
}

//! verify_sectrust — peer certificate verification for the LibreSSL
//! TlsProvider (libressl.zig installs this on every SSL_CTX).
//!
//! macOS: LibreSSL's built-in X.509 path building is replaced wholesale via
//! `SSL_CTX_set_cert_verify_callback`. The peer chain is re-encoded to DER,
//! lifted into SecCertificateRefs, and evaluated by Security.framework
//! (SecTrustEvaluateWithError with an SSL policy), so user- and
//! enterprise-installed CAs and trust settings are honored — the vendored
//! LibreSSL has no CA bundle of its own.
//!
//! Linux: the standard chain verify against the distro CA paths
//! (`SSL_CTX_set_default_verify_paths`), so dtcore integration tests work.
//! Hostname checking there comes from `SSL_set1_host` (set by libressl.zig).
//!
//! TESTING POLICY: unit tests never call SecTrustEvaluateWithError — it
//! reads the system/user trust stores. Only the pure plumbing (ex_data
//! attach, DER → SecCertificateRef conversion) is unit-tested.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");

const is_macos = builtin.os.tag == .macos;

/// SSL ex_data slot used for the per-connection `VerifyState` pointer.
/// Index 0 is the libcrypto "app data" slot; Relay is the application.
pub const ex_data_index: c_int = 0;

/// Per-connection verification input/output, owned by the stream object in
/// libressl.zig (must outlive the SSL). The callback reads `host` and
/// `skip_verify`, and reports failure detail back through the rest.
pub const VerifyState = struct {
    /// NUL-terminated server name the certificate must be valid for.
    host: [:0]const u8,
    skip_verify: bool,
    failure: Failure = .none,
    detail_buf: [detail_capacity]u8 = undefined,
    detail_len: usize = 0,

    pub const detail_capacity = 192;
    pub const Failure = enum { none, untrusted, hostname_mismatch };

    /// Human-readable failure detail (CFError description on macOS).
    pub fn detail(s: *const VerifyState) []const u8 {
        return s.detail_buf[0..s.detail_len];
    }

    fn setDetail(s: *VerifyState, text: []const u8) void {
        const n = @min(text.len, s.detail_buf.len);
        @memcpy(s.detail_buf[0..n], text[0..n]);
        s.detail_len = n;
    }
};

/// Installs chain verification on a freshly created client SSL_CTX.
pub fn install(ctx: *c.SSL_CTX) void {
    if (is_macos) {
        c.SSL_CTX_set_cert_verify_callback(ctx, mac.verifyCallback, null);
    } else {
        // Failure here only means the CA bundle is missing; the handshake
        // then fails with UNABLE_TO_GET_ISSUER_CERT_LOCALLY, which is the
        // right diagnostic anyway.
        _ = c.SSL_CTX_set_default_verify_paths(ctx);
    }
}

/// Attaches the per-connection state the macOS callback needs. No-op on
/// other platforms (the built-in verifier is configured per-SSL by
/// libressl.zig instead).
pub fn attach(ssl: *c.SSL, state: *VerifyState) void {
    if (is_macos) {
        _ = c.SSL_set_ex_data(ssl, ex_data_index, state);
    }
}

/// macOS-only machinery, comptime-fenced so the Security.framework externs
/// are never analyzed (or linked) elsewhere.
const mac = if (is_macos) struct {
    /// Longest peer chain accepted; longer chains are hostile or broken.
    const max_chain_len = 16;

    fn verifyCallback(store_ctx: ?*c.X509_STORE_CTX, arg: ?*anyopaque) callconv(.c) c_int {
        _ = arg;
        const ctx = store_ctx orelse return 0;
        const idx = c.SSL_get_ex_data_X509_STORE_CTX_idx();
        const ssl: ?*c.SSL = @ptrCast(@alignCast(c.X509_STORE_CTX_get_ex_data(ctx, idx)));
        const state_ptr = c.SSL_get_ex_data(ssl, ex_data_index) orelse {
            // No VerifyState attached: refuse rather than silently trust.
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        };
        const state: *VerifyState = @ptrCast(@alignCast(state_ptr));
        if (state.skip_verify) return 1;
        return evaluate(ctx, state);
    }

    fn evaluate(ctx: *c.X509_STORE_CTX, state: *VerifyState) c_int {
        var certs: [max_chain_len]cf.TypeRef = undefined;
        const n = collectChain(ctx, &certs) catch {
            state.failure = .untrusted;
            state.setDetail("could not re-encode the peer certificate chain");
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        };
        defer for (certs[0..n]) |cert| cf.CFRelease(cert.?);

        const chain = cf.CFArrayCreate(null, &certs, @intCast(n), &cf.kCFTypeArrayCallBacks) orelse {
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_OUT_OF_MEM);
            return 0;
        };
        defer cf.CFRelease(chain);

        const host_cf = cf.CFStringCreateWithBytes(
            null,
            state.host.ptr,
            @intCast(state.host.len),
            cf.kCFStringEncodingUTF8,
            0,
        ) orelse {
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_OUT_OF_MEM);
            return 0;
        };
        defer cf.CFRelease(host_cf);

        const ssl_policy = cf.SecPolicyCreateSSL(1, host_cf) orelse {
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_OUT_OF_MEM);
            return 0;
        };
        defer cf.CFRelease(ssl_policy);
        if (evalTrust(chain, ssl_policy, state)) return 1;

        // Failed under the SSL policy. If the same chain passes the basic
        // X.509 policy (no hostname), the problem is the name — that
        // distinction drives a different error and UI.
        const name_only = if (cf.SecPolicyCreateBasicX509()) |basic| blk: {
            defer cf.CFRelease(basic);
            break :blk evalTrust(chain, basic, null);
        } else false;
        if (name_only) {
            state.failure = .hostname_mismatch;
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_HOSTNAME_MISMATCH);
        } else {
            state.failure = .untrusted;
            c.X509_STORE_CTX_set_error(ctx, c.X509_V_ERR_CERT_UNTRUSTED);
        }
        return 0;
    }

    /// Re-encodes the chain the peer presented (leaf first) into
    /// SecCertificateRefs. Returns how many were stored in `out`.
    fn collectChain(ctx: *c.X509_STORE_CTX, out: *[max_chain_len]cf.TypeRef) error{BadChain}!usize {
        var n: usize = 0;
        errdefer for (out[0..n]) |cert| cf.CFRelease(cert.?);

        const untrusted = c.X509_STORE_CTX_get0_untrusted(ctx);
        const count: usize = if (untrusted != null)
            @intCast(@max(0, c.sk_num(@ptrCast(untrusted))))
        else
            0;
        if (count > max_chain_len) return error.BadChain;
        if (count == 0) {
            // No untrusted stack: fall back to the bare leaf.
            const leaf = c.X509_STORE_CTX_get0_cert(ctx) orelse return error.BadChain;
            out[0] = certFromX509(leaf) orelse return error.BadChain;
            return 1;
        }
        for (0..count) |i| {
            const x: ?*c.X509 = @ptrCast(@alignCast(c.sk_value(@ptrCast(untrusted), @intCast(i))));
            out[n] = certFromX509(x orelse return error.BadChain) orelse return error.BadChain;
            n += 1;
        }
        return n;
    }

    /// Real-world certificates stay well under this; anything larger is
    /// rejected rather than heap-allocated mid-handshake.
    const der_cert_max = 16 * 1024;

    /// X509 → DER (i2d) → SecCertificateRef. Caller releases the result.
    fn certFromX509(x: *c.X509) cf.TypeRef {
        const len = c.i2d_X509(x, null);
        if (len <= 0 or len > der_cert_max) return null;
        var buf: [der_cert_max]u8 = undefined;
        var p: [*c]u8 = &buf;
        if (c.i2d_X509(x, &p) != len) return null;
        const data = cf.CFDataCreate(null, &buf, @intCast(len)) orelse return null;
        defer cf.CFRelease(data);
        return cf.SecCertificateCreateWithData(null, data);
    }

    fn evalTrust(chain: *const anyopaque, policy: cf.TypeRef, state: ?*VerifyState) bool {
        var trust: cf.SecTrustRef = null;
        if (cf.SecTrustCreateWithCertificates(chain, policy, &trust) != 0) return false;
        const t = trust orelse return false;
        defer cf.CFRelease(t);
        var cf_err: cf.ErrorRef = null;
        const ok = cf.SecTrustEvaluateWithError(t, &cf_err);
        if (cf_err) |e| {
            if (!ok) {
                if (state) |s| captureError(e, s);
            }
            cf.CFRelease(e);
        }
        return ok;
    }

    fn captureError(err: *const anyopaque, state: *VerifyState) void {
        const desc = cf.CFErrorCopyDescription(err) orelse return;
        defer cf.CFRelease(desc);
        var buf: [VerifyState.detail_capacity + 1]u8 = undefined;
        if (cf.CFStringGetCString(desc, &buf, @intCast(buf.len), cf.kCFStringEncodingUTF8) != 0) {
            state.setDetail(std.mem.sliceTo(&buf, 0));
        }
    }

    /// CoreFoundation/Security externs (core links both frameworks on
    /// macOS); style mirrors cred/keychain.zig.
    const cf = struct {
        const Index = isize;
        const TypeRef = ?*const anyopaque;
        const ErrorRef = ?*const anyopaque;
        const SecTrustRef = ?*const anyopaque;
        const OSStatus = i32;
        const StringEncoding = u32;
        const kCFStringEncodingUTF8: StringEncoding = 0x0800_0100;

        const ArrayCallBacks = extern struct {
            version: Index,
            retain: ?*const anyopaque,
            release: ?*const anyopaque,
            copyDescription: ?*const anyopaque,
            equal: ?*const anyopaque,
        };
        extern const kCFTypeArrayCallBacks: ArrayCallBacks;

        extern fn CFRelease(cf_obj: *const anyopaque) void;
        extern fn CFDataCreate(alloc: ?*const anyopaque, bytes: [*]const u8, length: Index) TypeRef;
        extern fn CFStringCreateWithBytes(
            alloc: ?*const anyopaque,
            bytes: [*]const u8,
            num_bytes: Index,
            encoding: StringEncoding,
            is_external_representation: u8,
        ) TypeRef;
        extern fn CFStringGetCString(string: *const anyopaque, buffer: [*]u8, buffer_size: Index, encoding: StringEncoding) u8;
        extern fn CFArrayCreate(
            alloc: ?*const anyopaque,
            values: *const [max_chain_len]TypeRef,
            num_values: Index,
            callbacks: *const ArrayCallBacks,
        ) TypeRef;
        extern fn CFErrorCopyDescription(err: *const anyopaque) TypeRef;

        extern fn SecCertificateCreateWithData(alloc: ?*const anyopaque, data: TypeRef) TypeRef;
        extern fn SecPolicyCreateSSL(server: u8, hostname: TypeRef) TypeRef;
        extern fn SecPolicyCreateBasicX509() TypeRef;
        extern fn SecTrustCreateWithCertificates(certificates: *const anyopaque, policies: TypeRef, trust: *SecTrustRef) OSStatus;
        extern fn SecTrustEvaluateWithError(trust: *const anyopaque, err: ?*ErrorRef) bool;
    };
} else struct {};

// ---------------------------------------------------------------------------
// Tests (offline: no network, no trust-store evaluation)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "attach stores per-connection state in the app-data ex_data slot" {
    if (!is_macos) return error.SkipZigTest;
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OutOfMemory;
    defer c.SSL_CTX_free(ctx);
    const ssl = c.SSL_new(ctx) orelse return error.OutOfMemory;
    defer c.SSL_free(ssl);

    var state: VerifyState = .{ .host = "example.com", .skip_verify = false };
    attach(ssl, &state);
    const got: ?*anyopaque = c.SSL_get_ex_data(ssl, ex_data_index);
    try testing.expectEqual(@as(?*anyopaque, &state), got);
}

test "install on a fresh client SSL_CTX" {
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OutOfMemory;
    defer c.SSL_CTX_free(ctx);
    install(ctx);
}

/// Self-signed RSA-2048 test certificate (CN=relay-test.invalid), DER,
/// base64. Fixture only — never trusted by anything.
const fixture_cert_b64 =
    "MIICtjCCAZ4CCQDcT78ZKuEZIDANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJyZWxheS10ZXN0" ++
    "LmludmFsaWQwHhcNMjYwNjEwMjAxNjMzWhcNMzYwNjA3MjAxNjMzWjAdMRswGQYDVQQDDBJyZWxh" ++
    "eS10ZXN0LmludmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDuSMy+abvfM8Cb" ++
    "/smrbF1+qw/rA2SuhLudAXvoUIWcefJSGA5+f7G7MJC9Mk89JjVysSuk1PeG9dfOfswIkU4Y2gY8" ++
    "BFTMFRYa8qDc3DZeUR65Joo3dyQbCty/hh6oDuKlx/LLjJnY6N1aF5AVVsnWpz8okbXf9mIjCcWM" ++
    "ZhuEKLN/GRxu6qw8szp2PRsEwlf2TmMBIwTE2kM53yL9Ubyu6eNy76qbBPTw/Ajc34iblBlHeCBW" ++
    "kULb5b3ehoHr++bQHYl+yrNxoRv2s06vZ1Uuv5ctLaxmTXLOzzRkRxqqjnLcfUMELynRbc9C9UhN" ++
    "ksUDu+j32gwsgHzFwfstBim5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHGSaVwk6uJimxTz1Z9k" ++
    "I9nnUCuudJRbc4k1razWfNau1R8BWJ9+WPXceqmC1Lw59ctkc2NeAGMIjkAUZxYlA8Fhs+K759wP" ++
    "aSAFmhPiNWHlP3r5bhA25Jx7EzF0P+eYOWdeLi9HCqVFoA4AaMIxTTG8Zxzzk7BkuuMz6MEx5P73" ++
    "8n7a/LnkdFJh9V2CQJqrVQDApj2gPiw8foqqr2c/2/l585BKaYAXRKUc43oHIp8fH6x22mOsNog2" ++
    "hM8EnPPTFloSr0VVHAGC+2UKNS0cAYXC/g8ug7lG9F90YOo/8T2Jz1YW28tTsQwN+gp2CANunUE8" ++
    "erv6Jt2w2GVr3VEf1Z4=";

test "DER round trip: X509 -> SecCertificateRef (no trust evaluation)" {
    if (!is_macos) return error.SkipZigTest;
    var der: [800]u8 = undefined;
    const der_len = try std.base64.standard.Decoder.calcSizeForSlice(fixture_cert_b64);
    try std.base64.standard.Decoder.decode(der[0..der_len], fixture_cert_b64);

    var in: [*c]const u8 = &der;
    const x = c.d2i_X509(null, &in, @intCast(der_len)) orelse return error.TestUnexpectedResult;
    defer c.X509_free(x);

    const cert = mac.certFromX509(x) orelse return error.TestUnexpectedResult;
    mac.cf.CFRelease(cert);
}

test "verify state detail capture truncates" {
    var state: VerifyState = .{ .host = "h", .skip_verify = false };
    try testing.expectEqualStrings("", state.detail());
    state.setDetail("short");
    try testing.expectEqualStrings("short", state.detail());
    const long = "x" ** 500;
    state.setDetail(long);
    try testing.expectEqual(state.detail_buf.len, state.detail().len);
}

test {
    std.testing.refAllDecls(@This());
}

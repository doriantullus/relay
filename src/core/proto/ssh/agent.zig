//! ssh-agent client (draft-ietf-sshm-ssh-agent): uint32 length-prefixed
//! messages over the SSH_AUTH_SOCK unix-domain socket. Implements exactly
//! the two operations Relay needs — REQUEST_IDENTITIES and SIGN_REQUEST —
//! coded against `*std.Io.Reader`/`*std.Io.Writer` so the protocol logic
//! unit-tests against in-memory streams and a fake agent.
//!
//! The socket dial uses `std.Io.net.UnixAddress.connect` (first-class in
//! std 0.16; `Io.Threaded` implements `netConnectUnix` on POSIX), so no
//! raw-`std.posix` fallback is needed.

const std = @import("std");
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const cancel_mod = @import("../../cancel.zig");
const CancelToken = cancel_mod.CancelToken;
const keys = @import("keys.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

/// Reply cap, matching OpenSSH's MAX_AGENT_REPLY_LEN: anything larger is a
/// framing error from a hostile or broken peer, rejected before allocation.
pub const max_message_len = 256 * 1024;
/// Matches OpenSSH's MAX_AGENT_IDENTITIES.
pub const max_identities = 2048;

pub const MessageType = enum(u8) {
    /// Generic refusal: key absent, user declined, agent locked.
    failure = 5,
    success = 6,
    request_identities = 11,
    identities_answer = 12,
    sign_request = 13,
    sign_response = 14,
    _,
};

/// SIGN_REQUEST flags word. For ssh-rsa keys exactly one of the rsa_sha2
/// bits selects the signature algorithm; other key types use 0.
pub const SignFlags = packed struct(u32) {
    /// Bit 0 (value 1): SSH1 legacy (SSH_AGENT_OLD_SIGNATURE), never set.
    old_signature: bool = false,
    /// SSH_AGENT_RSA_SHA2_256 = 2
    rsa_sha2_256: bool = false,
    /// SSH_AGENT_RSA_SHA2_512 = 4
    rsa_sha2_512: bool = false,
    _reserved: u29 = 0,

    pub fn toWire(f: SignFlags) u32 {
        return @bitCast(f);
    }
};

/// Errors produced by reply decoding (no transport involved).
pub const ParseError = error{
    OutOfMemory,
    /// Agent replied SSH_AGENT_FAILURE: key not present, user declined,
    /// agent locked. Classified .auth — the caller should try other keys
    /// or prompt.
    AgentRefused,
    /// Reply violates the wire protocol (bad type, framing, oversize).
    ProtocolError,
};

pub const Error = ParseError || error{
    Canceled,
    ReadFailed,
    WriteFailed,
    /// Agent hung up mid-reply.
    EndOfStream,
};

pub const Identity = struct {
    /// SSH wire-format public key blob (same currency as keys.zig and
    /// known_hosts.zig).
    key_blob: []const u8,
    comment: []const u8,

    pub fn fingerprint(id: *const Identity) [keys.fingerprint_len]u8 {
        return keys.fingerprintSha256(id.key_blob);
    }
};

pub const IdentityList = struct {
    arena: ArenaAllocator,
    identities: []const Identity,

    pub fn deinit(l: *IdentityList) void {
        l.arena.deinit();
        l.* = undefined;
    }
};

/// Protocol endpoint over caller-supplied streams. Holds no other state, so
/// tests drive it with fixed buffers and a Connection drives it with the
/// real socket streams.
pub const Client = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,

    pub fn listIdentities(
        c: Client,
        gpa: Allocator,
        cancel: *const CancelToken,
        diag: *Diagnostics,
    ) Error!IdentityList {
        try checkCancel(cancel, diag);
        sendRequestIdentities(c.writer) catch return failWrite(diag);
        const message = try c.readMessage(gpa, diag);
        defer gpa.free(message);
        try checkCancel(cancel, diag);
        return parseIdentitiesAnswer(gpa, message) catch |err| classifyParse(err, diag);
    }

    /// Asks the agent to sign `data` with the key identified by `key_blob`
    /// (as obtained from listIdentities). Returns the signature blob
    /// (wire format: string algorithm, string signature), caller frees.
    pub fn sign(
        c: Client,
        gpa: Allocator,
        key_blob: []const u8,
        data: []const u8,
        flags: SignFlags,
        cancel: *const CancelToken,
        diag: *Diagnostics,
    ) Error![]u8 {
        try checkCancel(cancel, diag);
        const payload_len = 1 + 4 + key_blob.len + 4 + data.len + 4;
        if (payload_len > max_message_len) {
            diag.set(.permanent, 0, "ssh-agent sign request too large ({d} bytes)", .{payload_len});
            return error.ProtocolError;
        }
        sendSignRequest(c.writer, key_blob, data, flags, @intCast(payload_len)) catch
            return failWrite(diag);
        const message = try c.readMessage(gpa, diag);
        defer gpa.free(message);
        try checkCancel(cancel, diag);
        return parseSignResponse(gpa, message) catch |err| classifyParse(err, diag);
    }

    /// One length-prefixed reply, length-capped before allocation.
    /// Caller frees.
    fn readMessage(c: Client, gpa: Allocator, diag: *Diagnostics) Error![]u8 {
        const len = c.reader.takeInt(u32, .big) catch |err| return failRead(err, diag);
        if (len == 0 or len > max_message_len) {
            diag.set(.permanent, 0, "ssh-agent framing violation: reply length {d}", .{len});
            return error.ProtocolError;
        }
        const buf = try gpa.alloc(u8, len);
        errdefer gpa.free(buf);
        c.reader.readSliceAll(buf) catch |err| return failRead(err, diag);
        return buf;
    }
};

fn sendRequestIdentities(w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeInt(u32, 1, .big);
    try w.writeByte(@intFromEnum(MessageType.request_identities));
    try w.flush();
}

fn sendSignRequest(
    w: *std.Io.Writer,
    key_blob: []const u8,
    data: []const u8,
    flags: SignFlags,
    payload_len: u32,
) std.Io.Writer.Error!void {
    try w.writeInt(u32, payload_len, .big);
    try w.writeByte(@intFromEnum(MessageType.sign_request));
    try writeBlob(w, key_blob);
    try writeBlob(w, data);
    try w.writeInt(u32, flags.toWire(), .big);
    try w.flush();
}

/// SSH wire string: uint32 length + bytes. Callers guarantee len fits u32.
fn writeBlob(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    try w.writeInt(u32, @intCast(bytes.len), .big);
    try w.writeAll(bytes);
}

// ---------------------------------------------------------------------------
// Reply decoding (pure; fuzzed directly)
// ---------------------------------------------------------------------------

/// Decodes an IDENTITIES_ANSWER message (type byte included).
pub fn parseIdentitiesAnswer(gpa: Allocator, message: []const u8) ParseError!IdentityList {
    var r: WireReader = .{ .buf = message };
    try expectReplyType(&r, .identities_answer);
    const count = try r.takeU32();
    if (count > max_identities) return error.ProtocolError;
    // Each identity costs at least 8 bytes of framing; a count the payload
    // cannot hold is a lie (and a memory-exhaustion vector).
    if (count > (message.len - r.pos) / 8) return error.ProtocolError;

    var arena: ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const identities = try a.alloc(Identity, count);
    for (identities) |*id| {
        const blob = try r.takeString();
        if (blob.len == 0) return error.ProtocolError;
        const comment = try r.takeString();
        id.* = .{
            .key_blob = try a.dupe(u8, blob),
            .comment = try a.dupe(u8, comment),
        };
    }
    try r.expectEnd();
    return .{ .arena = arena, .identities = identities };
}

/// Decodes a SIGN_RESPONSE message; returns the signature blob, caller frees.
pub fn parseSignResponse(gpa: Allocator, message: []const u8) ParseError![]u8 {
    var r: WireReader = .{ .buf = message };
    try expectReplyType(&r, .sign_response);
    const sig = try r.takeString();
    if (sig.len == 0) return error.ProtocolError;
    try r.expectEnd();
    return gpa.dupe(u8, sig);
}

fn expectReplyType(r: *WireReader, want: MessageType) ParseError!void {
    const byte = try r.takeByte();
    if (byte == @intFromEnum(MessageType.failure)) return error.AgentRefused;
    if (byte != @intFromEnum(want)) return error.ProtocolError;
}

/// SSH wire-format reader over one received message. All shape failures
/// collapse to ProtocolError: framing already delivered the full message,
/// so truncation inside it is a peer bug, not a stream condition.
const WireReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn takeByte(r: *WireReader) ParseError!u8 {
        if (r.pos >= r.buf.len) return error.ProtocolError;
        defer r.pos += 1;
        return r.buf[r.pos];
    }

    fn takeU32(r: *WireReader) ParseError!u32 {
        if (4 > r.buf.len - r.pos) return error.ProtocolError;
        defer r.pos += 4;
        return std.mem.readInt(u32, r.buf[r.pos..][0..4], .big);
    }

    fn takeString(r: *WireReader) ParseError![]const u8 {
        const len = try r.takeU32();
        if (len > r.buf.len - r.pos) return error.ProtocolError;
        defer r.pos += len;
        return r.buf[r.pos..][0..len];
    }

    fn expectEnd(r: *const WireReader) ParseError!void {
        if (r.pos != r.buf.len) return error.ProtocolError;
    }
};

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn checkCancel(cancel: *const CancelToken, diag: *Diagnostics) error{Canceled}!void {
    cancel.check() catch |err| {
        diag.set(.cancel, 0, "canceled", .{});
        return err;
    };
}

fn failWrite(diag: *Diagnostics) Error {
    // Transient: the agent may have restarted; reconnect and retry.
    diag.set(.transient, 0, "ssh-agent write failed", .{});
    return error.WriteFailed;
}

fn failRead(err: std.Io.Reader.Error, diag: *Diagnostics) Error {
    switch (err) {
        error.EndOfStream => diag.set(.transient, 0, "ssh-agent closed the connection mid-reply", .{}),
        error.ReadFailed => diag.set(.transient, 0, "ssh-agent read failed", .{}),
    }
    return err;
}

fn classifyParse(err: ParseError, diag: *Diagnostics) Error {
    switch (err) {
        error.AgentRefused => diag.set(.auth, 0, "ssh-agent refused the request", .{}),
        error.ProtocolError => diag.set(.permanent, 0, "malformed ssh-agent reply", .{}),
        error.OutOfMemory => {},
    }
    return err;
}

// ---------------------------------------------------------------------------
// Socket connection (integration-only; unit tests use in-memory streams)
// ---------------------------------------------------------------------------

/// Stream buffer per direction. Agent messages are small (reply bodies are
/// heap-read anyway), so the control-channel size is plenty.
pub const buffer_len = 4096;

pub const Connection = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    stream_reader: std.Io.net.Stream.Reader,
    stream_writer: std.Io.net.Stream.Writer,
    read_buf: [buffer_len]u8,
    write_buf: [buffer_len]u8,

    pub const ConnectError = std.Io.net.UnixAddress.InitError ||
        std.Io.net.UnixAddress.ConnectError;

    /// Dials the agent socket (callers pass $SSH_AUTH_SOCK or the resolved
    /// ssh_config IdentityAgent). In-place init: the stream interfaces
    /// borrow the interior buffers, so a Connection must not be moved or
    /// copied after this call.
    pub fn connect(conn: *Connection, io: std.Io, path: []const u8) ConnectError!void {
        const addr = try std.Io.net.UnixAddress.init(path);
        const stream = try addr.connect(io);
        conn.io = io;
        conn.stream = stream;
        conn.stream_reader = stream.reader(io, &conn.read_buf);
        conn.stream_writer = stream.writer(io, &conn.write_buf);
    }

    pub fn client(conn: *Connection) Client {
        return .{
            .reader = &conn.stream_reader.interface,
            .writer = &conn.stream_writer.interface,
        };
    }

    pub fn close(conn: *Connection) void {
        conn.stream.close(conn.io);
        conn.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;
const duplex = @import("../../testutil/duplex.zig");

/// Minimal structurally-valid ed25519 public key blob for tests.
fn testBlob(comptime seed: u8) [4 + 11 + 4 + 32]u8 {
    var out: [4 + 11 + 4 + 32]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], 11, .big);
    out[4..15].* = "ssh-ed25519".*;
    std.mem.writeInt(u32, out[15..19], 32, .big);
    for (out[19..], 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return out;
}

const blob_a = testBlob(0xa0);
const blob_b = testBlob(0xb0);

fn fixedClient(r: *std.Io.Reader, w: *std.Io.Writer) Client {
    return .{ .reader = r, .writer = w };
}

test "sign flags have the draft wire values" {
    try t.expectEqual(@as(u32, 0), (SignFlags{}).toWire());
    try t.expectEqual(@as(u32, 2), (SignFlags{ .rsa_sha2_256 = true }).toWire());
    try t.expectEqual(@as(u32, 4), (SignFlags{ .rsa_sha2_512 = true }).toWire());
}

test "listIdentities: canonical request bytes + reply parsing" {
    // Fake agent reply: 12, nkeys=2, (blob_a, "key-a"), (blob_b, "").
    var resp_buf: [512]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&resp_buf);
    {
        var payload_buf: [256]u8 = undefined;
        var pw: std.Io.Writer = .fixed(&payload_buf);
        try pw.writeByte(@intFromEnum(MessageType.identities_answer));
        try pw.writeInt(u32, 2, .big);
        try writeBlob(&pw, &blob_a);
        try writeBlob(&pw, "key-a");
        try writeBlob(&pw, &blob_b);
        try writeBlob(&pw, "");
        try writeBlob(&rw, pw.buffered());
    }

    var req_buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var r: std.Io.Reader = .fixed(rw.buffered());
    var token: CancelToken = .{};
    var d: Diagnostics = .{};

    var list = try fixedClient(&r, &w).listIdentities(t.allocator, &token, &d);
    defer list.deinit();

    // Request on the wire: uint32 len=1, byte 11.
    try t.expectEqualSlices(u8, &.{ 0, 0, 0, 1, 11 }, w.buffered());

    try t.expectEqual(@as(usize, 2), list.identities.len);
    try t.expectEqualSlices(u8, &blob_a, list.identities[0].key_blob);
    try t.expectEqualStrings("key-a", list.identities[0].comment);
    try t.expectEqualSlices(u8, &blob_b, list.identities[1].key_blob);
    try t.expectEqualStrings("", list.identities[1].comment);
    // Fingerprint helper agrees with keys.zig on the same blob.
    const fp = list.identities[0].fingerprint();
    try t.expectEqualStrings(&keys.fingerprintSha256(&blob_a), &fp);
}

test "sign: request encodes key, data and flags; response decodes" {
    var resp_buf: [128]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&resp_buf);
    {
        var payload_buf: [64]u8 = undefined;
        var pw: std.Io.Writer = .fixed(&payload_buf);
        try pw.writeByte(@intFromEnum(MessageType.sign_response));
        try writeBlob(&pw, "FAKESIG");
        try writeBlob(&rw, pw.buffered());
    }

    var req_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var r: std.Io.Reader = .fixed(rw.buffered());
    var token: CancelToken = .{};
    var d: Diagnostics = .{};

    const sig = try fixedClient(&r, &w).sign(
        t.allocator,
        &blob_a,
        "data-to-sign",
        .{ .rsa_sha2_256 = true },
        &token,
        &d,
    );
    defer t.allocator.free(sig);
    try t.expectEqualStrings("FAKESIG", sig);

    // Decode our own request and verify every field, flags included.
    const req = w.buffered();
    const payload_len = std.mem.readInt(u32, req[0..4], .big);
    try t.expectEqual(req.len - 4, payload_len);
    var wr: WireReader = .{ .buf = req[4..] };
    try t.expectEqual(@intFromEnum(MessageType.sign_request), try wr.takeByte());
    try t.expectEqualSlices(u8, &blob_a, try wr.takeString());
    try t.expectEqualStrings("data-to-sign", try wr.takeString());
    try t.expectEqual(@as(u32, 2), try wr.takeU32()); // SSH_AGENT_RSA_SHA2_256
    try wr.expectEnd();
}

test "agent failure reply is AgentRefused, classified .auth" {
    const failure_msg = [_]u8{ 0, 0, 0, 1, @intFromEnum(MessageType.failure) };
    var req_buf: [256]u8 = undefined;
    var token: CancelToken = .{};

    var w: std.Io.Writer = .fixed(&req_buf);
    var r: std.Io.Reader = .fixed(&failure_msg);
    var d: Diagnostics = .{};
    try t.expectError(
        error.AgentRefused,
        fixedClient(&r, &w).sign(t.allocator, &blob_a, "x", .{}, &token, &d),
    );
    try t.expectEqual(diag_mod.ErrorClass.auth, d.class);

    w = .fixed(&req_buf);
    r = .fixed(&failure_msg);
    d.clear();
    try t.expectError(
        error.AgentRefused,
        fixedClient(&r, &w).listIdentities(t.allocator, &token, &d),
    );
    try t.expectEqual(diag_mod.ErrorClass.auth, d.class);
}

test "length sanity: zero and oversized replies rejected before allocation" {
    var req_buf: [64]u8 = undefined;
    var token: CancelToken = .{};

    inline for (.{ @as(u32, 0), @as(u32, max_message_len + 1) }) |bad_len| {
        var header: [4]u8 = undefined;
        std.mem.writeInt(u32, &header, bad_len, .big);
        var w: std.Io.Writer = .fixed(&req_buf);
        var r: std.Io.Reader = .fixed(&header);
        var d: Diagnostics = .{};
        // failing_allocator proves rejection happens before any allocation.
        try t.expectError(
            error.ProtocolError,
            fixedClient(&r, &w).listIdentities(t.failing_allocator, &token, &d),
        );
        try t.expectEqual(diag_mod.ErrorClass.permanent, d.class);
    }
}

test "truncated replies are EndOfStream, classified .transient" {
    var req_buf: [64]u8 = undefined;
    var token: CancelToken = .{};

    // Header truncated mid-uint32, then body shorter than declared.
    const cases = [_][]const u8{
        &.{ 0, 0 },
        &.{ 0, 0, 0, 10, 12, 0, 0 },
    };
    for (cases) |resp| {
        var w: std.Io.Writer = .fixed(&req_buf);
        var r: std.Io.Reader = .fixed(resp);
        var d: Diagnostics = .{};
        try t.expectError(
            error.EndOfStream,
            fixedClient(&r, &w).listIdentities(t.allocator, &token, &d),
        );
        try t.expectEqual(diag_mod.ErrorClass.transient, d.class);
    }
}

test "decoder rejects malformed identity answers" {
    var msg_buf: [256]u8 = undefined;

    // Wrong reply type entirely.
    try t.expectError(error.ProtocolError, parseIdentitiesAnswer(t.allocator, &.{6}));
    // Empty message.
    try t.expectError(error.ProtocolError, parseIdentitiesAnswer(t.allocator, &.{}));

    // Count says 2 but payload holds 1 identity.
    var w: std.Io.Writer = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.identities_answer));
    try w.writeInt(u32, 2, .big);
    try writeBlob(&w, &blob_a);
    try writeBlob(&w, "only-one");
    try t.expectError(error.ProtocolError, parseIdentitiesAnswer(t.allocator, w.buffered()));

    // Absurd count (memory-exhaustion probe) dies before allocation.
    w = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.identities_answer));
    try w.writeInt(u32, 0xffff_ffff, .big);
    try t.expectError(
        error.ProtocolError,
        parseIdentitiesAnswer(t.failing_allocator, w.buffered()),
    );

    // Empty key blob is meaningless and rejected.
    w = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.identities_answer));
    try w.writeInt(u32, 1, .big);
    try writeBlob(&w, "");
    try writeBlob(&w, "comment");
    try t.expectError(error.ProtocolError, parseIdentitiesAnswer(t.allocator, w.buffered()));

    // Trailing garbage after a valid answer.
    w = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.identities_answer));
    try w.writeInt(u32, 1, .big);
    try writeBlob(&w, &blob_a);
    try writeBlob(&w, "c");
    try w.writeByte(0);
    try t.expectError(error.ProtocolError, parseIdentitiesAnswer(t.allocator, w.buffered()));

    // Empty list is valid (agent with no keys loaded).
    w = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.identities_answer));
    try w.writeInt(u32, 0, .big);
    var empty = try parseIdentitiesAnswer(t.allocator, w.buffered());
    defer empty.deinit();
    try t.expectEqual(@as(usize, 0), empty.identities.len);
}

test "decoder rejects malformed sign responses" {
    try t.expectError(error.ProtocolError, parseSignResponse(t.allocator, &.{}));
    try t.expectError(error.ProtocolError, parseSignResponse(t.allocator, &.{12}));
    var msg_buf: [64]u8 = undefined;
    // Empty signature.
    var w: std.Io.Writer = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.sign_response));
    try writeBlob(&w, "");
    try t.expectError(error.ProtocolError, parseSignResponse(t.allocator, w.buffered()));
    // Signature string overruns the message.
    w = .fixed(&msg_buf);
    try w.writeByte(@intFromEnum(MessageType.sign_response));
    try w.writeInt(u32, 100, .big);
    try w.writeByte('x');
    try t.expectError(error.ProtocolError, parseSignResponse(t.allocator, w.buffered()));
}

test "canceled token aborts before any bytes are written" {
    var req_buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var r: std.Io.Reader = .fixed(&.{});
    var token: CancelToken = .{};
    token.cancel();
    var d: Diagnostics = .{};
    try t.expectError(
        error.Canceled,
        fixedClient(&r, &w).listIdentities(t.allocator, &token, &d),
    );
    try t.expectEqual(diag_mod.ErrorClass.cancel, d.class);
    try t.expectEqual(@as(usize, 0), w.buffered().len);
}

test "client survives allocation failure" {
    const Check = struct {
        fn list(gpa: Allocator, resp: []const u8) !void {
            var req_buf: [64]u8 = undefined;
            var w: std.Io.Writer = .fixed(&req_buf);
            var r: std.Io.Reader = .fixed(resp);
            var token: CancelToken = .{};
            var d: Diagnostics = .{};
            var l = fixedClient(&r, &w).listIdentities(gpa, &token, &d) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            l.deinit();
        }
        fn signOnce(gpa: Allocator, resp: []const u8) !void {
            var req_buf: [256]u8 = undefined;
            var w: std.Io.Writer = .fixed(&req_buf);
            var r: std.Io.Reader = .fixed(resp);
            var token: CancelToken = .{};
            var d: Diagnostics = .{};
            const sig = fixedClient(&r, &w).sign(gpa, &blob_a, "data", .{}, &token, &d) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            gpa.free(sig);
        }
    };

    var resp_buf: [256]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&resp_buf);
    var pw_buf: [128]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&pw_buf);
    try pw.writeByte(@intFromEnum(MessageType.identities_answer));
    try pw.writeInt(u32, 1, .big);
    try writeBlob(&pw, &blob_a);
    try writeBlob(&pw, "c");
    try writeBlob(&rw, pw.buffered());
    try t.checkAllAllocationFailures(t.allocator, Check.list, .{rw.buffered()});

    rw = .fixed(&resp_buf);
    pw = .fixed(&pw_buf);
    try pw.writeByte(@intFromEnum(MessageType.sign_response));
    try writeBlob(&pw, "SIG");
    try writeBlob(&rw, pw.buffered());
    try t.checkAllAllocationFailures(t.allocator, Check.signOnce, .{rw.buffered()});
}

// Fake agent served over real OS pipes: exercises the client against
// streaming reads/writes (partial fills, flush boundaries), not just
// pre-baked fixed buffers.
const FakeAgent = struct {
    fn run(ep: *duplex.Endpoint, err_out: *?anyerror) void {
        serve(ep) catch |err| {
            err_out.* = err;
        };
        ep.close();
    }

    fn serve(ep: *duplex.Endpoint) !void {
        const r = ep.reader();
        const w = ep.writer();
        while (true) {
            const len = r.takeInt(u32, .big) catch |err| switch (err) {
                error.EndOfStream => return, // client hung up
                else => return err,
            };
            if (len == 0 or len > 4096) return error.FakeAgentBadRequest;
            var msg_buf: [4096]u8 = undefined;
            const msg = msg_buf[0..len];
            try r.readSliceAll(msg);

            var payload_buf: [512]u8 = undefined;
            var pw: std.Io.Writer = .fixed(&payload_buf);
            switch (msg[0]) {
                @intFromEnum(MessageType.request_identities) => {
                    if (msg.len != 1) return error.FakeAgentBadRequest;
                    try pw.writeByte(@intFromEnum(MessageType.identities_answer));
                    try pw.writeInt(u32, 2, .big);
                    try writeBlob(&pw, &blob_a);
                    try writeBlob(&pw, "alpha@relay");
                    try writeBlob(&pw, &blob_b);
                    try writeBlob(&pw, "beta@relay");
                },
                @intFromEnum(MessageType.sign_request) => {
                    var wr: WireReader = .{ .buf = msg[1..] };
                    const blob = try wr.takeString();
                    const data = try wr.takeString();
                    const flags = try wr.takeU32();
                    try wr.expectEnd();
                    if (std.mem.eql(u8, blob, &blob_a)) {
                        // Echo data and flags into the "signature" so the
                        // test can prove flag passing end to end.
                        try pw.writeByte(@intFromEnum(MessageType.sign_response));
                        var sig_buf: [128]u8 = undefined;
                        var sw: std.Io.Writer = .fixed(&sig_buf);
                        try sw.print("signed({s},flags={d})", .{ data, flags });
                        try writeBlob(&pw, sw.buffered());
                    } else {
                        try pw.writeByte(@intFromEnum(MessageType.failure));
                    }
                },
                else => try pw.writeByte(@intFromEnum(MessageType.failure)),
            }
            try writeBlob(w, pw.buffered());
            try w.flush();
        }
    }
};

test "fake agent over in-memory duplex: list, sign, flags, refusal" {
    const io = std.testing.io;
    var d: duplex.Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    var agent_err: ?anyerror = null;
    {
        const thread = try std.Thread.spawn(.{}, FakeAgent.run, .{ &d.b, &agent_err });
        defer thread.join();
        defer d.a.close(); // before join (LIFO): unblocks the agent thread

        const c = fixedClient(d.a.reader(), d.a.writer());
        var token: CancelToken = .{};
        var dg: Diagnostics = .{};

        var list = try c.listIdentities(t.allocator, &token, &dg);
        defer list.deinit();
        try t.expectEqual(@as(usize, 2), list.identities.len);
        try t.expectEqualStrings("alpha@relay", list.identities[0].comment);
        try t.expectEqualSlices(u8, &blob_b, list.identities[1].key_blob);

        // Sign with the known key: flags travel to the agent and back.
        const sig = try c.sign(
            t.allocator,
            list.identities[0].key_blob,
            "exchange-hash",
            .{ .rsa_sha2_512 = true },
            &token,
            &dg,
        );
        defer t.allocator.free(sig);
        try t.expectEqualStrings("signed(exchange-hash,flags=4)", sig);

        // Unknown key: agent refuses, connection stays usable after.
        try t.expectError(
            error.AgentRefused,
            c.sign(t.allocator, &blob_b, "x", .{}, &token, &dg),
        );
        try t.expectEqual(diag_mod.ErrorClass.auth, dg.class);

        var again = try c.listIdentities(t.allocator, &token, &dg);
        again.deinit();
    }
    try t.expectEqual(@as(?anyerror, null), agent_err);
}

test "fuzz agent message decoder" {
    try t.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *t.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len = smith.slice(&buf);
    // Bias toward valid reply types so the body decoders get coverage.
    if (len > 0 and smith.value(bool)) {
        buf[0] = if (smith.value(bool))
            @intFromEnum(MessageType.identities_answer)
        else
            @intFromEnum(MessageType.sign_response);
    }
    const msg = buf[0..len];

    var list: ?IdentityList = parseIdentitiesAnswer(t.allocator, msg) catch null;
    if (list) |*l| l.deinit();
    const sig: ?[]u8 = parseSignResponse(t.allocator, msg) catch null;
    if (sig) |s| t.allocator.free(s);

    // Framed path: same bytes through the client read loop and length caps.
    var framed_buf: [1028]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&framed_buf);
    fw.writeInt(u32, @intCast(len), .big) catch unreachable;
    fw.writeAll(msg) catch unreachable;
    var r: std.Io.Reader = .fixed(fw.buffered());
    var req_buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var token: CancelToken = .{};
    var dg: Diagnostics = .{};
    var l2: ?IdentityList = fixedClient(&r, &w).listIdentities(t.allocator, &token, &dg) catch null;
    if (l2) |*l| l.deinit();
}

test {
    std.testing.refAllDecls(@This());
}

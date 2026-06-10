//! data_conn — FTP data-connection plumbing for the engine in client.zig:
//! EPSV/PASV reply parsing, EPRT/PORT command formatting, the active-mode
//! listener (std.Io.net), and `Link` — an established data connection with
//! TLS optionally stacked on top.
//!
//! The engine never dials. Passive connections come from a
//! `DataConnFactory` (seam defined in ../../testutil/ftp_script.zig:
//! production wires a real TCP dialer, tests use `ScriptedServer.factory()`).
//! Active connections come from `ActiveListener.accept`.
//!
//! Security note: PASV replies advertise an arbitrary IP — a hostile or
//! confused server can redirect the data connection (FTP bounce). The
//! engine validates the advertised address against the control connection's
//! peer (see client.zig); this file only parses.

const std = @import("std");
const ftp_script = @import("../../testutil/ftp_script.zig");
const tls_provider = @import("../../tls/provider.zig");
const CancelToken = @import("../../cancel.zig").CancelToken;
const Diagnostics = @import("../../diag.zig").Diagnostics;

pub const DataConn = ftp_script.DataConn;
pub const DataConnFactory = ftp_script.DataConnFactory;
pub const DialError = ftp_script.DialError;

pub const Ip4 = [4]u8;

pub const PasvTarget = struct {
    ip: Ip4,
    port: u16,
};

/// Parses the text of a 229 reply (RFC 2428): "(<d><d><d><tcp-port><d>)"
/// where <d> is one arbitrary delimiter character. Tolerates leading prose
/// ("Entering Extended Passive Mode ..."). Null on any malformed shape or a
/// zero port.
pub fn parseEpsvReply(text: []const u8) ?u16 {
    const open = std.mem.indexOfScalar(u8, text, '(') orelse return null;
    const rest = text[open + 1 ..];
    if (rest.len < 6) return null; // shortest: d d d digit d )
    const d = rest[0];
    if (d == ')' or std.ascii.isDigit(d)) return null;
    if (rest[1] != d or rest[2] != d) return null;
    var i: usize = 3;
    var port: u32 = 0;
    var digits: usize = 0;
    while (i < rest.len and std.ascii.isDigit(rest[i])) : (i += 1) {
        port = port * 10 + (rest[i] - '0');
        if (port > std.math.maxInt(u16)) return null;
        digits += 1;
    }
    if (digits == 0) return null;
    if (i + 1 >= rest.len or rest[i] != d or rest[i + 1] != ')') return null;
    if (port == 0) return null;
    return @intCast(port);
}

/// Parses the text of a 227 reply: six comma-separated byte values
/// "h1,h2,h3,h4,p1,p2". RFC 959 puts them in parentheses but real servers
/// also emit them bare or with other framing, so this scans for the first
/// digit run that starts a valid six-tuple. Null when none is found or the
/// port is zero.
pub fn parsePasvReply(text: []const u8) ?PasvTarget {
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (!std.ascii.isDigit(text[i])) continue;
        if (parseSixTuple(text[i..])) |target| return target;
        // Skip the rest of this digit run; a tuple cannot start inside it.
        while (i + 1 < text.len and std.ascii.isDigit(text[i + 1])) i += 1;
    }
    return null;
}

fn parseSixTuple(s: []const u8) ?PasvTarget {
    var nums: [6]u8 = undefined;
    var i: usize = 0;
    for (&nums, 0..) |*out, n| {
        if (n != 0) {
            if (i >= s.len or s[i] != ',') return null;
            i += 1;
        }
        var v: u32 = 0;
        var digits: usize = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
            v = v * 10 + (s[i] - '0');
            if (v > 255) return null;
            digits += 1;
        }
        if (digits == 0) return null;
        out.* = @intCast(v);
    }
    const port = @as(u16, nums[4]) * 256 + nums[5];
    if (port == 0) return null;
    return .{ .ip = nums[0..4].*, .port = port };
}

/// Dotted-quad text of `ip`; `buf` must hold at least 15 bytes.
pub fn formatIp4(buf: []u8, ip: Ip4) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch
        unreachable; // 15 bytes always suffice
}

pub const eprt_cmd_max_len = "EPRT |1|255.255.255.255|65535|".len;

/// RFC 2428 EPRT command line (IPv4). `buf` must hold `eprt_cmd_max_len`.
pub fn formatEprt(buf: []u8, ip: Ip4, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "EPRT |1|{d}.{d}.{d}.{d}|{d}|", .{
        ip[0], ip[1], ip[2], ip[3], port,
    }) catch unreachable;
}

pub const port_cmd_max_len = "PORT 255,255,255,255,255,255".len;

/// RFC 959 PORT command line. `buf` must hold `port_cmd_max_len`.
pub fn formatPort(buf: []u8, ip: Ip4, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "PORT {d},{d},{d},{d},{d},{d}", .{
        ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xff,
    }) catch unreachable;
}

/// An established data connection: the plaintext `DataConn` plus the TLS
/// stream stacked on it for FTPS. All engine I/O goes through `reader`/
/// `writer` so the transfer code cannot tell TLS from plaintext.
pub const Link = struct {
    conn: DataConn,
    tls: ?*tls_provider.Stream = null,

    pub fn reader(l: *const Link) *std.Io.Reader {
        return if (l.tls) |s| s.reader else l.conn.reader;
    }

    pub fn writer(l: *const Link) *std.Io.Writer {
        return if (l.tls) |s| s.writer else l.conn.writer;
    }

    /// Ends an upload: flush, TLS close_notify (end-of-data for FTPS), then
    /// half-close the socket (end-of-data for plaintext).
    pub fn finishWrite(l: *Link) std.Io.Writer.Error!void {
        try l.writer().flush();
        if (l.tls) |s| {
            s.close();
            l.tls = null;
        }
        try l.conn.closeWrite();
    }

    /// Hard close, both layers. Idempotent.
    pub fn close(l: *Link) void {
        if (l.tls) |s| {
            s.close();
            l.tls = null;
        }
        l.conn.close();
    }
};

/// Stacks TLS onto an established data connection. FTPS interop rule #1:
/// `opts.session` must carry the control connection's exported session
/// unless the per-site `disable_session_reuse` escape hatch is on.
/// On error the plaintext connection is NOT closed; the caller owns it.
pub fn wrapTls(
    conn: DataConn,
    provider: tls_provider.TlsProvider,
    gpa: std.mem.Allocator,
    cancel: *CancelToken,
    diag: *Diagnostics,
    opts: tls_provider.HandshakeOptions,
) tls_provider.Error!Link {
    const stream = try provider.handshake(gpa, cancel, diag, conn.fd, opts);
    return .{ .conn = conn, .tls = stream };
}

// ---------------------------------------------------------------------------
// Active mode (EPRT/PORT): we listen, the server dials.
// ---------------------------------------------------------------------------

/// One-shot listener for an active-mode transfer. Production-only path
/// (binds a real socket); unit tests cover passive mode through the
/// factory seam, active mode is exercised by integration tests.
pub const ActiveListener = struct {
    server: std.Io.net.Server,

    pub const OpenError = std.Io.net.IpAddress.ListenError;

    /// Binds an ephemeral port on the wildcard address. The address to
    /// advertise in EPRT/PORT is the control connection's local IP, which
    /// the caller knows and this listener does not.
    pub fn open(io: std.Io) OpenError!ActiveListener {
        const addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
        return .{ .server = try addr.listen(io, .{ .kernel_backlog = 1 }) };
    }

    /// The kernel-assigned port to advertise.
    pub fn port(l: *const ActiveListener) u16 {
        return l.server.socket.address.getPort();
    }

    /// Waits for the server's inbound connection and wraps it as a
    /// `DataConn` (heap-allocated; freed by its `close`).
    pub fn accept(
        l: *ActiveListener,
        io: std.Io,
        gpa: std.mem.Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
    ) DialError!DataConn {
        cancel.check() catch |err| {
            diag.set(.cancel, 0, "canceled before active data accept", .{});
            return err;
        };
        const stream = l.server.accept(io) catch |err| switch (err) {
            error.Canceled => {
                diag.set(.cancel, 0, "canceled during active data accept", .{});
                return error.Canceled;
            },
            else => {
                diag.set(.transient, 0, "active-mode data accept failed: {t}", .{err});
                return error.ConnectionLost;
            },
        };
        const ac = gpa.create(ActiveConn) catch {
            stream.close(io);
            diag.set(.transient, 0, "out of memory accepting data connection", .{});
            return error.Unexpected;
        };
        ac.attach(gpa, io, stream);
        return .{
            .reader = &ac.reader.interface,
            .writer = &ac.writer.interface,
            .context = ac,
            .vtable = &active_conn_vtable,
            .fd = stream.socket.handle,
        };
    }

    pub fn close(l: *ActiveListener, io: std.Io) void {
        l.server.deinit(io);
    }
};

const ActiveConn = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    write_closed: bool,
    read_buf: [buffer_len]u8,
    write_buf: [buffer_len]u8,

    const buffer_len = 8192;

    /// In-place init: reader/writer buffers are interior slices, so an
    /// `ActiveConn` is pinned once attached (hence the heap allocation).
    fn attach(ac: *ActiveConn, gpa: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) void {
        ac.gpa = gpa;
        ac.io = io;
        ac.stream = stream;
        ac.write_closed = false;
        ac.reader = stream.reader(io, &ac.read_buf);
        ac.writer = stream.writer(io, &ac.write_buf);
    }
};

const active_conn_vtable: DataConn.VTable = .{
    .closeWrite = activeCloseWrite,
    .close = activeClose,
};

fn activeCloseWrite(ctx: *anyopaque) std.Io.Writer.Error!void {
    const ac: *ActiveConn = @ptrCast(@alignCast(ctx));
    if (ac.write_closed) return;
    try ac.writer.interface.flush();
    ac.write_closed = true;
    ac.stream.shutdown(ac.io, .send) catch return error.WriteFailed;
}

fn activeClose(ctx: *anyopaque) void {
    const ac: *ActiveConn = @ptrCast(@alignCast(ctx));
    ac.writer.interface.flush() catch {};
    ac.stream.close(ac.io);
    const gpa = ac.gpa;
    ac.* = undefined;
    gpa.destroy(ac);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const duplex = @import("../../testutil/duplex.zig");

test "EPSV reply parsing" {
    try testing.expectEqual(@as(?u16, 20021), parseEpsvReply("Entering Extended Passive Mode (|||20021|)"));
    try testing.expectEqual(@as(?u16, 1), parseEpsvReply("(|||1|)"));
    try testing.expectEqual(@as(?u16, 65535), parseEpsvReply("ok (|||65535|)"));
    // Any delimiter character is legal per RFC 2428.
    try testing.expectEqual(@as(?u16, 4242), parseEpsvReply("(===4242=)"));

    try testing.expectEqual(@as(?u16, null), parseEpsvReply(""));
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("no parens |||21|"));
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(|||0|)")); // zero port
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(|||65536|)")); // overflow
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(||21|)")); // two delimiters
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(|x|21|)")); // mixed delimiters
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(|||21x)")); // bad terminator
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(|||21|")); // missing ')'
    try testing.expectEqual(@as(?u16, null), parseEpsvReply("(123421|)")); // digit delimiter
}

test "PASV reply parsing" {
    const t1 = parsePasvReply("Entering Passive Mode (127,0,0,1,78,53)").?;
    try testing.expectEqual(Ip4{ 127, 0, 0, 1 }, t1.ip);
    try testing.expectEqual(@as(u16, 78 * 256 + 53), t1.port);

    // No parentheses (real-world tolerance).
    const t2 = parsePasvReply("=203,0,113,5,195,80").?;
    try testing.expectEqual(Ip4{ 203, 0, 113, 5 }, t2.ip);
    try testing.expectEqual(@as(u16, 195 * 256 + 80), t2.port);

    // Leading digits that are not part of the tuple are skipped over.
    const t3 = parsePasvReply("v2 ready 10,20,30,40,1,2 end").?;
    try testing.expectEqual(Ip4{ 10, 20, 30, 40 }, t3.ip);
    try testing.expectEqual(@as(u16, 258), t3.port);

    try testing.expectEqual(@as(?PasvTarget, null), parsePasvReply(""));
    try testing.expectEqual(@as(?PasvTarget, null), parsePasvReply("Passive mode disabled"));
    try testing.expectEqual(@as(?PasvTarget, null), parsePasvReply("(256,0,0,1,1,1)")); // byte overflow
    try testing.expectEqual(@as(?PasvTarget, null), parsePasvReply("(127,0,0,1,0,0)")); // zero port
    try testing.expectEqual(@as(?PasvTarget, null), parsePasvReply("(127,0,0,1,78)")); // five fields
}

test "EPRT/PORT/dotted-quad formatting" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("192.0.2.7", formatIp4(&buf, .{ 192, 0, 2, 7 }));
    try testing.expectEqualStrings(
        "EPRT |1|192.0.2.7|49152|",
        formatEprt(&buf, .{ 192, 0, 2, 7 }, 49152),
    );
    try testing.expectEqualStrings(
        "PORT 192,0,2,7,192,0",
        formatPort(&buf, .{ 192, 0, 2, 7 }, 49152),
    );
    // Max-width values fit the documented buffer lengths exactly.
    var max_buf: [eprt_cmd_max_len]u8 = undefined;
    try testing.expectEqualStrings(
        "EPRT |1|255.255.255.255|65535|",
        formatEprt(&max_buf, .{ 255, 255, 255, 255 }, 65535),
    );
    var port_buf: [port_cmd_max_len]u8 = undefined;
    try testing.expectEqualStrings(
        "PORT 255,255,255,255,255,255",
        formatPort(&port_buf, .{ 255, 255, 255, 255 }, 65535),
    );
}

// Test-only DataConn over one duplex endpoint (mirrors ScriptedServer's).
const test_endpoint_vtable: DataConn.VTable = .{
    .closeWrite = testEndpointCloseWrite,
    .close = testEndpointClose,
};

fn testEndpointCloseWrite(ctx: *anyopaque) std.Io.Writer.Error!void {
    const ep: *duplex.Endpoint = @ptrCast(@alignCast(ctx));
    return ep.closeWrite();
}

fn testEndpointClose(ctx: *anyopaque) void {
    const ep: *duplex.Endpoint = @ptrCast(@alignCast(ctx));
    ep.close();
}

fn testConn(ep: *duplex.Endpoint) DataConn {
    return .{
        .reader = ep.reader(),
        .writer = ep.writer(),
        .context = ep,
        .vtable = &test_endpoint_vtable,
    };
}

test "Link plaintext passthrough, finishWrite half-close, idempotent close" {
    const io = testing.io;
    var d: duplex.Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    var link: Link = .{ .conn = testConn(&d.a) };
    try testing.expectEqual(@as(std.posix.fd_t, -1), link.conn.fd);

    try link.writer().writeAll("upload bytes");
    try link.finishWrite(); // flush + half-close: peer sees data then EOF

    var buf: [12]u8 = undefined;
    try d.b.reader().readSliceAll(&buf);
    try testing.expectEqualStrings("upload bytes", &buf);
    try testing.expectError(error.EndOfStream, d.b.reader().takeByte());

    // Reverse direction still works post-half-close.
    try d.b.writer().writeAll("reply\n");
    try d.b.writer().flush();
    try testing.expectEqualStrings("reply", try link.reader().takeSentinel('\n'));

    link.close();
    link.close(); // idempotent
}

fn fuzzPassiveParsers(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    if (parseEpsvReply(input)) |port| {
        try testing.expect(port != 0);
    }
    if (parsePasvReply(input)) |target| {
        try testing.expect(target.port != 0);
        // The tuple must literally appear in the input.
        var quad: [port_cmd_max_len]u8 = undefined;
        const tuple = std.fmt.bufPrint(&quad, "{d},{d},{d},{d},{d},{d}", .{
            target.ip[0],     target.ip[1],       target.ip[2], target.ip[3],
            target.port >> 8, target.port & 0xff,
        }) catch unreachable;
        try testing.expect(std.mem.indexOf(u8, input, tuple) != null);
    }
}

test "fuzz EPSV/PASV reply parsers" {
    try testing.fuzz({}, fuzzPassiveParsers, .{ .corpus = &.{
        "229 Entering Extended Passive Mode (|||20021|)",
        "227 Entering Passive Mode (127,0,0,1,78,53)",
        "227 =203,0,113,5,195,80",
        "(|||0|)(1,2,3,4,5,6)",
    } });
}

test {
    std.testing.refAllDecls(@This());
}

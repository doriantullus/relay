//! ftp_script — ScriptedServer, the offline FTP protocol-test harness.
//!
//! A test declares the server side of an FTP conversation as a `Step` slice;
//! `ScriptedServer` plays it on its own `std.Thread` over an in-memory
//! duplex pipe (../testutil/duplex.zig). The engine under test talks to
//! `clientReader()`/`clientWriter()` exactly as it would to a socket. The
//! full conversation is recorded for assertions (`transcript()`), and any
//! deviation — wrong command, premature close — is reported as a readable
//! expected-vs-got diff via `check()`.
//!
//! ## The DataConnFactory seam
//!
//! FTP transfers open a second (data) connection: the engine parses the
//! PASV/EPSV reply and dials host:port. In production that dial is a real
//! TCP connect (+ TLS for FTPS); in tests it must resolve to an in-memory
//! pipe. `DataConnFactory` is that seam: phase 2's engine takes one by
//! value and calls `factory.dial(io, cancel, diag, host, port)` instead of
//! touching the network.
//!
//! Scripted wiring: a `.open_data = port_token` step provisions a fresh
//! duplex pair keyed by the port token *before* the script sends the PASV
//! reply that advertises it, so the registration happens-before the engine
//! can dial. `ScriptedServer.factory()` returns a factory whose `dial`
//! hands out the client endpoint of the matching pair (each pair satisfies
//! exactly one dial; an unmatched dial fails with `error.ConnectionRefused`
//! and a diagnostic). The server side of the pair is driven by
//! `.data_send` / `.data_expect` / `.close_data` steps.

const std = @import("std");
const duplex = @import("duplex.zig");
const CancelToken = @import("../cancel.zig").CancelToken;
const Diagnostics = @import("../diag.zig").Diagnostics;

/// Most `.open_data` steps a single script may contain.
pub const max_data_conns = 8;

/// One step of the server's side of the conversation, executed in order.
pub const Step = union(enum) {
    /// Read one CRLF-terminated command; it must match exactly.
    expect: []const u8,
    /// Read one command; it must start with this prefix (e.g. "PASS").
    expect_prefix: []const u8,
    /// Send one reply line; CRLF is appended.
    reply: []const u8,
    /// Send several lines, CRLF appended to each. The script author writes
    /// RFC 959 multiline framing: `&.{ "211-Features:", " MLST", "211 End" }`.
    reply_multiline: []const []const u8,
    /// Provision a fresh in-memory data connection that the factory will
    /// hand to the engine when it dials this port token. Place before the
    /// PASV/EPSV reply advertising the token.
    open_data: u16,
    /// Write bytes to the current data connection and flush (RETR payload).
    data_send: []const u8,
    /// Read exactly this many bytes from the current data connection and
    /// compare (STOR payload).
    data_expect: []const u8,
    /// Close the server side of the current data connection (EOF marks
    /// end-of-transfer for the engine).
    close_data,
    /// Fault injection: slam the control connection shut. Remaining steps
    /// are skipped; this is not recorded as a failure.
    drop_connection,
    /// Sleep before the next step (timeout-path testing; keep tiny).
    delay_ms: u64,
};

pub const DialError = error{
    Canceled,
    ConnectionRefused,
    ConnectionLost,
    Timeout,
    Unexpected,
};

/// An established data connection. Concrete stream interfaces plus the two
/// lifecycle calls FTP needs: `closeWrite` (a STOR upload ends by data-
/// connection half-close) and `close`.
pub const DataConn = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    context: *anyopaque,
    vtable: *const VTable,
    /// Underlying socket when the factory dialed a real TCP connection; -1
    /// for in-memory test pairs. FTPS needs it: `TlsProvider.handshake`
    /// operates directly on the fd, so production factories must set it.
    fd: std.posix.fd_t = -1,

    pub const VTable = struct {
        /// Flush + half-close the write side; must be idempotent.
        closeWrite: *const fn (ctx: *anyopaque) std.Io.Writer.Error!void,
        /// Full close; must be idempotent.
        close: *const fn (ctx: *anyopaque) void,
    };

    pub fn closeWrite(c: DataConn) std.Io.Writer.Error!void {
        return c.vtable.closeWrite(c.context);
    }
    pub fn close(c: DataConn) void {
        c.vtable.close(c.context);
    }
};

/// How the FTP engine obtains data connections (the PASV/EPSV dial seam).
/// Production: TCP connect. Tests: `ScriptedServer.factory()`.
pub const DataConnFactory = struct {
    context: *anyopaque,
    dialFn: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) DialError!DataConn,

    pub fn dial(
        f: DataConnFactory,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) DialError!DataConn {
        return f.dialFn(f.context, io, cancel, diag, host, port);
    }
};

pub const ScriptedServer = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    script: []const Step,
    control: duplex.Duplex,
    thread: ?std.Thread,

    /// Guards `slots`/`slot_count`/`client_gone` (shared with `dial` and
    /// `shutdownClient`). Everything below it is server-thread-only until
    /// the thread is joined.
    mutex: std.Io.Mutex,
    slots: [max_data_conns]DataSlot,
    slot_count: usize,
    client_gone: bool,

    /// Server side of the most recent `.open_data` pair.
    cur_data: ?*duplex.Duplex,
    step_index: usize,
    transcript_list: std.ArrayList(u8),
    failure_buf: [1024]u8,
    failure_len: usize,

    const DataSlot = struct {
        pair: *duplex.Duplex,
        port: u16,
        dialed: bool,
    };

    const ScriptFailed = error{ScriptFailed};

    /// In-place init (pinned memory: stream buffers and the factory context
    /// point into `s`). Spawns the server thread immediately.
    pub fn init(
        s: *ScriptedServer,
        gpa: std.mem.Allocator,
        io: std.Io,
        script: []const Step,
    ) (duplex.Duplex.InitError || std.Thread.SpawnError)!void {
        s.* = .{
            .gpa = gpa,
            .io = io,
            .script = script,
            .control = undefined,
            .thread = null,
            .mutex = .init,
            .slots = undefined,
            .slot_count = 0,
            .client_gone = false,
            .cur_data = null,
            .step_index = 0,
            .transcript_list = .empty,
            .failure_buf = undefined,
            .failure_len = 0,
        };
        try s.control.init(io);
        errdefer s.control.deinit();
        s.thread = try std.Thread.spawn(.{}, serverMain, .{s});
    }

    /// Unblocks the server (it fails any remaining expectations), joins it,
    /// and frees everything. Safe after `check()`.
    pub fn deinit(s: *ScriptedServer) void {
        s.shutdownClient();
        s.join();
        for (s.slots[0..s.slot_count]) |slot| {
            slot.pair.deinit();
            s.gpa.destroy(slot.pair);
        }
        s.transcript_list.deinit(s.gpa);
        s.control.deinit();
        s.* = undefined;
    }

    /// Control-connection streams for the engine under test.
    pub fn clientReader(s: *ScriptedServer) *std.Io.Reader {
        return s.control.a.reader();
    }
    pub fn clientWriter(s: *ScriptedServer) *std.Io.Writer {
        return s.control.a.writer();
    }

    pub fn factory(s: *ScriptedServer) DataConnFactory {
        return .{ .context = s, .dialFn = dialData };
    }

    /// Call when the client side of the conversation is done: closes the
    /// client streams (so a server stuck on an unmet expectation fails
    /// instead of deadlocking), joins, and reports any script failure with
    /// the recorded transcript.
    pub fn check(s: *ScriptedServer) ScriptFailed!void {
        s.shutdownClient();
        s.join();
        if (s.failure_len != 0) {
            std.debug.print(
                "--- scripted FTP server failure ---\n{s}\n--- transcript ---\n{s}---\n",
                .{ s.failureMessage(), s.transcript() },
            );
            return error.ScriptFailed;
        }
    }

    /// Like `check` but silent: joins and returns the failure message (empty
    /// if the script completed). For tests asserting ON harness failures.
    pub fn joinQuiet(s: *ScriptedServer) []const u8 {
        s.shutdownClient();
        s.join();
        return s.failureMessage();
    }

    /// Full conversation, one event per line ("C: USER alice\n",
    /// "S: 331 ...\n", "S: <open-data 20021>\n"). Only valid after the
    /// server thread is joined (`check`/`joinQuiet`/`deinit`).
    pub fn transcript(s: *const ScriptedServer) []const u8 {
        return s.transcript_list.items;
    }

    pub fn failureMessage(s: *const ScriptedServer) []const u8 {
        return s.failure_buf[0..s.failure_len];
    }

    fn join(s: *ScriptedServer) void {
        if (s.thread) |t| {
            t.join();
            s.thread = null;
        }
    }

    /// Close the client end of the control connection and of every data
    /// pair, and refuse future `.open_data` registrations. Any blocked
    /// server step wakes with EOF / broken pipe. Idempotent.
    fn shutdownClient(s: *ScriptedServer) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (s.client_gone) return;
        s.client_gone = true;
        s.control.a.close();
        for (s.slots[0..s.slot_count]) |slot| slot.pair.a.close();
    }

    // ---------------------------------------------------------------- //
    // Engine-facing factory (called from the engine's thread)

    fn dialData(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) DialError!DataConn {
        const s: *ScriptedServer = @ptrCast(@alignCast(ctx));
        _ = host; // the port token alone identifies the scripted pair
        cancel.check() catch |err| {
            diag.set(.cancel, 0, "data dial canceled", .{});
            return err;
        };
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        for (s.slots[0..s.slot_count]) |*slot| {
            if (!slot.dialed and slot.port == port) {
                slot.dialed = true;
                const ep = &slot.pair.a;
                return .{
                    .reader = ep.reader(),
                    .writer = ep.writer(),
                    .context = ep,
                    .vtable = &endpoint_data_vtable,
                };
            }
        }
        diag.set(.transient, 0, "scripted server: no pending data connection for port {d}", .{port});
        return error.ConnectionRefused;
    }

    const endpoint_data_vtable: DataConn.VTable = .{
        .closeWrite = endpointCloseWrite,
        .close = endpointClose,
    };

    fn endpointCloseWrite(ctx: *anyopaque) std.Io.Writer.Error!void {
        const ep: *duplex.Endpoint = @ptrCast(@alignCast(ctx));
        return ep.closeWrite();
    }

    fn endpointClose(ctx: *anyopaque) void {
        const ep: *duplex.Endpoint = @ptrCast(@alignCast(ctx));
        ep.close();
    }

    // ---------------------------------------------------------------- //
    // Server thread

    fn serverMain(s: *ScriptedServer) void {
        s.run() catch {}; // failure already recorded by fail()
        s.control.b.close();
        if (s.cur_data) |pair| pair.b.close();
    }

    fn run(s: *ScriptedServer) ScriptFailed!void {
        for (s.script, 0..) |step, i| {
            s.step_index = i;
            switch (step) {
                .expect => |want| try s.expectLine(want, .exact),
                .expect_prefix => |want| try s.expectLine(want, .prefix),
                .reply => |line| try s.sendLine(line),
                .reply_multiline => |lines| for (lines) |line| try s.sendLine(line),
                .open_data => |port| try s.openData(port),
                .data_send => |bytes| try s.dataSend(bytes),
                .data_expect => |bytes| try s.dataExpect(bytes),
                .close_data => try s.closeData(),
                .drop_connection => {
                    try s.record("S: ", "<drop-connection>");
                    return;
                },
                .delay_ms => |ms| s.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {},
            }
        }
    }

    const MatchKind = enum { exact, prefix };

    fn expectLine(s: *ScriptedServer, want: []const u8, kind: MatchKind) ScriptFailed!void {
        const r = s.control.b.reader();
        const raw = r.takeSentinel('\n') catch |err| switch (err) {
            error.EndOfStream => return s.fail(
                \\step {d}: expected command but the client closed the control connection
                \\  expected ({t}): "{s}"
            , .{ s.step_index, kind, want }),
            error.ReadFailed, error.StreamTooLong => |e| return s.fail(
                "step {d}: control read failed: {t}",
                .{ s.step_index, e },
            ),
        };
        const line = std.mem.trimEnd(u8, raw, "\r");
        try s.record("C: ", line);
        const ok = switch (kind) {
            .exact => std.mem.eql(u8, line, want),
            .prefix => std.mem.startsWith(u8, line, want),
        };
        if (!ok) return s.fail(
            \\step {d}: control command mismatch
            \\  expected ({t}): "{s}"
            \\  got           : "{s}"
        , .{ s.step_index, kind, want, line });
    }

    fn sendLine(s: *ScriptedServer, line: []const u8) ScriptFailed!void {
        const w = s.control.b.writer();
        blk: {
            w.writeAll(line) catch break :blk;
            w.writeAll("\r\n") catch break :blk;
            w.flush() catch break :blk;
            return s.record("S: ", line);
        }
        return s.fail(
            "step {d}: control write of \"{s}\" failed (client closed the connection?)",
            .{ s.step_index, line },
        );
    }

    fn openData(s: *ScriptedServer, port: u16) ScriptFailed!void {
        const pair = s.gpa.create(duplex.Duplex) catch
            return s.fail("step {d}: out of memory creating data pair", .{s.step_index});
        pair.init(s.io) catch |err| {
            s.gpa.destroy(pair);
            return s.fail("step {d}: data pipe creation failed: {t}", .{ s.step_index, err });
        };
        s.mutex.lockUncancelable(s.io);
        if (s.client_gone or s.slot_count == max_data_conns) {
            const gone = s.client_gone;
            s.mutex.unlock(s.io);
            pair.deinit();
            s.gpa.destroy(pair);
            if (gone) return s.fail("step {d}: open_data after client shutdown", .{s.step_index});
            return s.fail("step {d}: more than {d} open_data steps", .{ s.step_index, max_data_conns });
        }
        s.slots[s.slot_count] = .{ .pair = pair, .port = port, .dialed = false };
        s.slot_count += 1;
        s.mutex.unlock(s.io);
        s.cur_data = pair;
        var buf: [32]u8 = undefined;
        const note = std.fmt.bufPrint(&buf, "<open-data {d}>", .{port}) catch unreachable;
        try s.record("S: ", note);
    }

    fn dataSend(s: *ScriptedServer, bytes: []const u8) ScriptFailed!void {
        const pair = s.cur_data orelse
            return s.fail("step {d}: data_send without open_data", .{s.step_index});
        blk: {
            pair.b.writer().writeAll(bytes) catch break :blk;
            pair.b.writer().flush() catch break :blk;
            var buf: [48]u8 = undefined;
            const note = std.fmt.bufPrint(&buf, "<data-send {d} bytes>", .{bytes.len}) catch unreachable;
            return s.record("S: ", note);
        }
        return s.fail(
            "step {d}: data_send of {d} bytes failed (engine closed the data connection?)",
            .{ s.step_index, bytes.len },
        );
    }

    fn dataExpect(s: *ScriptedServer, want: []const u8) ScriptFailed!void {
        const pair = s.cur_data orelse
            return s.fail("step {d}: data_expect without open_data", .{s.step_index});
        const r = pair.b.reader();
        var buf: [duplex.buffer_len]u8 = undefined;
        var off: usize = 0;
        while (off < want.len) {
            const n = @min(buf.len, want.len - off);
            r.readSliceAll(buf[0..n]) catch |err| return s.fail(
                "step {d}: data_expect wanted {d} bytes, got {d} then {t}",
                .{ s.step_index, want.len, off, err },
            );
            if (std.mem.indexOfDiff(u8, buf[0..n], want[off .. off + n])) |bad| {
                return s.fail(
                    \\step {d}: data_expect mismatch at byte {d}
                    \\  expected: 0x{x:0>2}
                    \\  got     : 0x{x:0>2}
                , .{ s.step_index, off + bad, want[off + bad], buf[bad] });
            }
            off += n;
        }
        var note_buf: [48]u8 = undefined;
        const note = std.fmt.bufPrint(&note_buf, "<data-recv {d} bytes>", .{want.len}) catch unreachable;
        try s.record("S: ", note);
    }

    fn closeData(s: *ScriptedServer) ScriptFailed!void {
        const pair = s.cur_data orelse
            return s.fail("step {d}: close_data without open_data", .{s.step_index});
        pair.b.close();
        s.cur_data = null;
        try s.record("S: ", "<close-data>");
    }

    fn record(s: *ScriptedServer, prefix: []const u8, line: []const u8) ScriptFailed!void {
        const list = &s.transcript_list;
        list.ensureUnusedCapacity(s.gpa, prefix.len + line.len + 1) catch
            return s.fail("step {d}: out of memory recording transcript", .{s.step_index});
        list.appendSliceAssumeCapacity(prefix);
        list.appendSliceAssumeCapacity(line);
        list.appendAssumeCapacity('\n');
    }

    /// Records the first failure (fixed buffer; no allocation) and aborts
    /// the script. Read back via `failureMessage` after join.
    fn fail(s: *ScriptedServer, comptime fmt: []const u8, args: anytype) ScriptFailed {
        if (s.failure_len == 0) {
            var w: std.Io.Writer = .fixed(&s.failure_buf);
            w.print(fmt, args) catch {}; // truncation acceptable
            s.failure_len = w.end;
        }
        return error.ScriptFailed;
    }
};

// -------------------------------------------------------------------- //
// Self-tests: this file is the client ("engine") side of each script.

/// Test helper: read one CRLF-terminated reply line.
fn readLine(r: *std.Io.Reader) ![]const u8 {
    return std.mem.trimEnd(u8, try r.takeSentinel('\n'), "\r");
}

fn sendCmd(w: *std.Io.Writer, cmd: []const u8) !void {
    try w.writeAll(cmd);
    try w.writeAll("\r\n");
    try w.flush();
}

test "scripted USER/PASS/PASV/RETR happy path" {
    const io = std.testing.io;
    const payload = "hello, relay!\nthis came over the data channel.\n";

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .reply = "220 relay-test FTP ready" },
        .{ .expect = "USER alice" },
        .{ .reply = "331 Need password" },
        .{ .expect_prefix = "PASS" },
        .{ .reply = "230 Logged in" },
        .{ .expect = "FEAT" },
        .{ .reply_multiline = &.{ "211-Features:", " MLST", "211 End" } },
        .{ .expect = "PASV" },
        .{ .open_data = 20021 },
        .{ .reply = "227 Entering Passive Mode (127,0,0,1,78,53)" },
        .{ .expect = "RETR hello.txt" },
        .{ .reply = "150 Opening data connection" },
        .{ .data_send = payload },
        .close_data,
        .{ .reply = "226 Transfer complete" },
        .{ .expect = "QUIT" },
        .{ .reply = "221 Bye" },
    });
    defer server.deinit();

    const r = server.clientReader();
    const w = server.clientWriter();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try std.testing.expectEqualStrings("220 relay-test FTP ready", try readLine(r));
    try sendCmd(w, "USER alice");
    try std.testing.expectEqualStrings("331 Need password", try readLine(r));
    try sendCmd(w, "PASS hunter2");
    try std.testing.expectEqualStrings("230 Logged in", try readLine(r));

    try sendCmd(w, "FEAT");
    try std.testing.expectEqualStrings("211-Features:", try readLine(r));
    try std.testing.expectEqualStrings(" MLST", try readLine(r));
    try std.testing.expectEqualStrings("211 End", try readLine(r));

    try sendCmd(w, "PASV");
    const pasv = try readLine(r);
    try std.testing.expect(std.mem.startsWith(u8, pasv, "227 "));
    // 78,53 in the reply: 78 * 256 + 53.
    const data = try server.factory().dial(io, &cancel, &diag, "127.0.0.1", 20021);
    defer data.close();

    try sendCmd(w, "RETR hello.txt");
    try std.testing.expectEqualStrings("150 Opening data connection", try readLine(r));
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(std.testing.allocator);
    try data.reader.appendRemaining(std.testing.allocator, &got, .limited(4 * payload.len));
    try std.testing.expectEqualStrings(payload, got.items);
    try std.testing.expectEqualStrings("226 Transfer complete", try readLine(r));

    try sendCmd(w, "QUIT");
    try std.testing.expectEqualStrings("221 Bye", try readLine(r));

    try server.check();
    try std.testing.expectEqualStrings(
        \\S: 220 relay-test FTP ready
        \\C: USER alice
        \\S: 331 Need password
        \\C: PASS hunter2
        \\S: 230 Logged in
        \\C: FEAT
        \\S: 211-Features:
        \\S:  MLST
        \\S: 211 End
        \\C: PASV
        \\S: <open-data 20021>
        \\S: 227 Entering Passive Mode (127,0,0,1,78,53)
        \\C: RETR hello.txt
        \\S: 150 Opening data connection
        \\S: <data-send 47 bytes>
        \\S: <close-data>
        \\S: 226 Transfer complete
        \\C: QUIT
        \\S: 221 Bye
        \\
    , server.transcript());
}

test "scripted STOR upload via data_expect and client half-close" {
    const io = std.testing.io;
    const payload = "uploaded bytes \x00\x01\x02 (binary-safe)";

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .expect = "PASV" },
        .{ .open_data = 30000 },
        .{ .reply = "227 ok" },
        .{ .expect = "STOR up.bin" },
        .{ .reply = "150 ok, send it" },
        .{ .data_expect = payload },
        .close_data,
        .{ .reply = "226 Stored" },
    });
    defer server.deinit();

    const r = server.clientReader();
    const w = server.clientWriter();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try sendCmd(w, "PASV");
    _ = try readLine(r);
    const data = try server.factory().dial(io, &cancel, &diag, "127.0.0.1", 30000);
    defer data.close();

    try sendCmd(w, "STOR up.bin");
    _ = try readLine(r);
    try data.writer.writeAll(payload);
    try data.closeWrite(); // end-of-upload signal
    try std.testing.expectEqualStrings("226 Stored", try readLine(r));

    try server.check();
}

test "unexpected command fails with a readable diff" {
    const io = std.testing.io;

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .expect = "USER alice" },
        .{ .reply = "331 never sent" },
    });
    defer server.deinit();

    try sendCmd(server.clientWriter(), "USER bob");
    const msg = server.joinQuiet();
    try std.testing.expect(std.mem.indexOf(u8, msg, "mismatch") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "\"USER alice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "\"USER bob\"") != null);
    try std.testing.expectEqualStrings("C: USER bob\n", server.transcript());
}

test "client never speaks: check() reports instead of deadlocking" {
    const io = std.testing.io;

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .expect = "USER alice" },
    });
    defer server.deinit();

    const msg = server.joinQuiet();
    try std.testing.expect(std.mem.indexOf(u8, msg, "closed the control connection") != null);
}

test "drop_connection and delay_ms fault injection" {
    const io = std.testing.io;

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .reply = "220 here, then gone" },
        .{ .delay_ms = 2 },
        .drop_connection,
    });
    defer server.deinit();

    const r = server.clientReader();
    try std.testing.expectEqualStrings("220 here, then gone", try readLine(r));
    try std.testing.expectError(error.EndOfStream, r.takeByte());
    try server.check(); // an executed drop is success, not failure
    try std.testing.expect(std.mem.indexOf(u8, server.transcript(), "<drop-connection>") != null);
}

test "dial without pending open_data is refused with diagnostics" {
    const io = std.testing.io;

    var server: ScriptedServer = undefined;
    try server.init(std.testing.allocator, io, &.{
        .{ .reply = "220 ready" },
    });
    defer server.deinit();

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};
    try std.testing.expectError(
        error.ConnectionRefused,
        server.factory().dial(io, &cancel, &diag, "127.0.0.1", 12345),
    );
    try std.testing.expectEqual(.transient, diag.class);
    try std.testing.expect(std.mem.indexOf(u8, diag.message, "12345") != null);

    cancel.cancel();
    try std.testing.expectError(
        error.Canceled,
        server.factory().dial(io, &cancel, &diag, "127.0.0.1", 12345),
    );
    try std.testing.expectEqual(.cancel, diag.class);

    _ = try readLine(server.clientReader());
    try server.check();
}

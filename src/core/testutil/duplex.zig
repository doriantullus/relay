//! duplex — in-memory full-duplex byte pipe for offline protocol tests.
//!
//! Two endpoints, `a` and `b`; bytes written to one endpoint's writer come
//! out of the other endpoint's reader. Built on a pair of real OS pipes
//! wrapped in `std.Io.File.Reader`/`.Writer` in streaming mode, so blocking,
//! EOF, and broken-pipe semantics under `std.Io.Threaded` are the kernel's,
//! not a reimplementation (and `Io.Threaded` already installs the no-op
//! SIGPIPE handler that turns writes-after-close into clean errors).
//!
//! Semantics the protocol tests rely on:
//! - The two directions are independent: half-close one (`closeWrite`) and
//!   the peer's reader sees EOF while the reverse direction keeps flowing.
//! - Close is idempotent, so harness cleanup can close endpoints that a
//!   test (or an engine under test) already closed.
//! - Closing an endpoint widows the underlying pipes: a peer blocked in
//!   read wakes with EOF, a peer blocked in write fails immediately —
//!   teardown cannot deadlock as long as you close before joining threads.
//!
//! An endpoint is NOT thread-safe; use each endpoint from one thread at a
//! time (the normal shape: test thread owns `a`, server thread owns `b`).

const std = @import("std");

/// Stream buffer for each direction's reader/writer interface. Deliberately
/// small so multi-megabyte test transfers exercise many refill/drain cycles.
pub const buffer_len = 4096;

pub const Duplex = struct {
    a: Endpoint,
    b: Endpoint,

    pub const InitError = std.Io.Threaded.PipeError;

    /// In-place init: the endpoints' stream buffers are interior slices, so
    /// a `Duplex` must never be moved or copied after this call.
    pub fn init(d: *Duplex, io: std.Io) InitError!void {
        const a_to_b = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
        errdefer for (a_to_b) |fd| closeFd(io, fd);
        const b_to_a = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
        d.a.attach(io, b_to_a[0], a_to_b[1]);
        d.b.attach(io, a_to_b[0], b_to_a[1]);
    }

    /// Closes both endpoints (idempotent per fd). Join any thread using an
    /// endpoint before deinit, or close that endpoint's peer first so the
    /// thread unblocks.
    pub fn deinit(d: *Duplex) void {
        d.a.close();
        d.b.close();
        d.* = undefined;
    }
};

pub const Endpoint = struct {
    io: std.Io,
    file_reader: std.Io.File.Reader,
    file_writer: std.Io.File.Writer,
    read_open: bool,
    write_open: bool,
    read_buf: [buffer_len]u8,
    write_buf: [buffer_len]u8,

    fn attach(e: *Endpoint, io: std.Io, read_fd: std.posix.fd_t, write_fd: std.posix.fd_t) void {
        e.io = io;
        e.read_open = true;
        e.write_open = true;
        // Streaming mode: pipes have no size and cannot seek.
        e.file_reader = .initStreaming(fileFromFd(read_fd), io, &e.read_buf);
        e.file_writer = .initStreaming(fileFromFd(write_fd), io, &e.write_buf);
    }

    pub fn reader(e: *Endpoint) *std.Io.Reader {
        return &e.file_reader.interface;
    }

    pub fn writer(e: *Endpoint) *std.Io.Writer {
        return &e.file_writer.interface;
    }

    /// Flush buffered bytes, then half-close: the peer's reader sees EOF
    /// after draining. The reverse direction is unaffected.
    pub fn closeWrite(e: *Endpoint) std.Io.Writer.Error!void {
        if (!e.write_open) return;
        defer {
            e.file_writer.file.close(e.io);
            e.write_open = false;
        }
        try e.file_writer.interface.flush();
    }

    /// Close the receiving side; a peer blocked writing fails immediately
    /// (widowed pipe) instead of deadlocking.
    pub fn closeRead(e: *Endpoint) void {
        if (!e.read_open) return;
        e.file_reader.file.close(e.io);
        e.read_open = false;
    }

    /// Full close, ignoring final-flush errors (the peer may already be
    /// gone); cleanup-path variant of `closeWrite` + `closeRead`.
    pub fn close(e: *Endpoint) void {
        e.closeWrite() catch {};
        e.closeRead();
    }
};

fn fileFromFd(fd: std.posix.fd_t) std.Io.File {
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}

fn closeFd(io: std.Io, fd: std.posix.fd_t) void {
    fileFromFd(fd).close(io);
}

fn expectedByte(index: usize) u8 {
    return @truncate(index *% 131 +% 7);
}

test "echo across two threads" {
    const io = std.testing.io;
    var d: Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    const Echo = struct {
        fn run(ep: *Endpoint, err_out: *?anyerror) void {
            loop(ep) catch |err| {
                err_out.* = err;
            };
            ep.close();
        }
        fn loop(ep: *Endpoint) !void {
            while (true) {
                const line = ep.reader().takeDelimiterInclusive('\n') catch |err| switch (err) {
                    error.EndOfStream => return,
                    else => return err,
                };
                try ep.writer().writeAll(line);
                try ep.writer().flush();
            }
        }
    };

    var thread_err: ?anyerror = null;
    {
        const thread = try std.Thread.spawn(.{}, Echo.run, .{ &d.b, &thread_err });
        defer thread.join();
        // Runs before join (LIFO): unblocks the echo thread on error paths.
        defer d.a.close();

        const w = d.a.writer();
        const r = d.a.reader();

        try w.writeAll("hello over the pipe\n");
        try w.flush();
        try std.testing.expectEqualStrings("hello over the pipe", try r.takeSentinel('\n'));

        try w.writeAll("second line\n");
        try w.flush();
        try std.testing.expectEqualStrings("second line", try r.takeSentinel('\n'));

        // Half-close our write side: echo drains, sees EOF, closes its end.
        try d.a.closeWrite();
        try std.testing.expectError(error.EndOfStream, r.takeByte());
    }
    try std.testing.expectEqual(@as(?anyerror, null), thread_err);
}

test "half-close: EOF propagates, reverse direction stays open" {
    const io = std.testing.io;
    var d: Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    // closeWrite must flush buffered bytes before EOF.
    try d.a.writer().writeAll("residual");
    try d.a.closeWrite();

    var buf: [8]u8 = undefined;
    try d.b.reader().readSliceAll(&buf);
    try std.testing.expectEqualStrings("residual", &buf);
    try std.testing.expectError(error.EndOfStream, d.b.reader().takeByte());

    // b -> a still flows after a -> b is closed.
    try d.b.writer().writeAll("still up\n");
    try d.b.writer().flush();
    try std.testing.expectEqualStrings("still up", try d.a.reader().takeSentinel('\n'));

    // Idempotent close: safe to close again before deinit closes everything.
    try d.a.closeWrite();
    d.b.close();
    d.b.close();
}

test "interleaved writes keep per-direction byte order" {
    const io = std.testing.io;
    var d: Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    // Alternate directions with multiple unflushed writes per turn; the
    // pipe buffers make this safe single-threaded at these sizes.
    var turn: usize = 0;
    while (turn < 50) : (turn += 1) {
        try d.a.writer().writeAll("alpha-");
        try d.a.writer().writeAll("beta\n");
        try d.a.writer().flush();
        try d.b.writer().writeAll("gamma-");
        try d.b.writer().writeAll("delta\n");
        try d.b.writer().flush();
        try std.testing.expectEqualStrings("alpha-beta", try d.b.reader().takeSentinel('\n'));
        try std.testing.expectEqualStrings("gamma-delta", try d.a.reader().takeSentinel('\n'));
    }
}

test "large transfer through small stream buffers" {
    const io = std.testing.io;
    const total: usize = (1 << 20) + 12_345; // > 1 MiB, non-power-of-two tail

    var d: Duplex = undefined;
    try d.init(io);
    defer d.deinit();

    const Producer = struct {
        fn run(ep: *Endpoint, err_out: *?anyerror) void {
            produce(ep) catch |err| {
                err_out.* = err;
            };
            ep.close();
        }
        fn produce(ep: *Endpoint) !void {
            var chunk: [1000]u8 = undefined; // not a divisor of buffer_len
            var off: usize = 0;
            while (off < total) {
                const n = @min(chunk.len, total - off);
                for (chunk[0..n], 0..) |*byte, i| byte.* = expectedByte(off + i);
                try ep.writer().writeAll(chunk[0..n]);
                off += n;
            }
            try ep.closeWrite();
        }
    };

    var thread_err: ?anyerror = null;
    {
        const thread = try std.Thread.spawn(.{}, Producer.run, .{ &d.b, &thread_err });
        defer thread.join();
        defer d.a.close();

        const r = d.a.reader();
        var buf: [8192]u8 = undefined;
        var got: usize = 0;
        while (true) {
            const n = try r.readSliceShort(&buf);
            if (n == 0) break;
            for (buf[0..n], 0..) |byte, i| {
                if (byte != expectedByte(got + i)) {
                    std.debug.print("corrupt byte at offset {d}\n", .{got + i});
                    return error.TestUnexpectedResult;
                }
            }
            got += n;
        }
        try std.testing.expectEqual(total, got);
    }
    try std.testing.expectEqual(@as(?anyerror, null), thread_err);
}

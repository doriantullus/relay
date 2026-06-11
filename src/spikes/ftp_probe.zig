//! Headless FTP/FTPS probe: drives relay_core's FtpClient against a real
//! server and prints every step + the transcript, to locate the bug the
//! user hit (FTP/FTPS connect/list failing in the GUI).
//!
//!   zig build ftp-probe -- ftp.scene.org 21 ftp test@mail.org
//!   zig build ftp-probe -- demo.wftpserver.com 21 demo demo ftps
const std = @import("std");
const relay = @import("relay_core");
const ftp = relay.ftp.client;
const data_conn = relay.ftp.data_conn;
const transcript_mod = relay.transcript;
const vfs = relay.vfs.iface;
const CancelToken = relay.cancel.CancelToken;
const Diagnostics = relay.diag.Diagnostics;

const DataState = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    rbuf: [16 * 1024]u8 = undefined,
    wbuf: [16 * 1024]u8 = undefined,
    write_closed: bool = false,
};

fn dialAny(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {
        const name = try std.Io.net.HostName.init(host);
        return name.connect(io, port, .{ .mode = .stream });
    }
}

fn dataDial(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, host: []const u8, port: u16) data_conn.DialError!data_conn.DataConn {
    _ = ctx;
    cancel.check() catch return error.Canceled;
    std.debug.print("  [data] dialing {s}:{d} ...\n", .{ host, port });
    const stream = dialAny(io, host, port) catch {
        diag.set(.transient, 0, "data connect failed", .{});
        return error.ConnectionRefused;
    };
    const d = std.heap.c_allocator.create(DataState) catch return error.Unexpected;
    d.* = .{ .gpa = std.heap.c_allocator, .io = io, .stream = stream, .reader = undefined, .writer = undefined };
    d.reader = .init(stream, io, &d.rbuf);
    d.writer = .init(stream, io, &d.wbuf);
    return .{ .reader = &d.reader.interface, .writer = &d.writer.interface, .context = @ptrCast(d), .vtable = &data_vtable, .fd = stream.socket.handle };
}
const data_vtable: data_conn.DataConn.VTable = .{ .closeWrite = dataCloseWrite, .close = dataClose };
fn dataCloseWrite(ctx: *anyopaque) std.Io.Writer.Error!void {
    const d: *DataState = @ptrCast(@alignCast(ctx));
    if (d.write_closed) return;
    d.write_closed = true;
    d.writer.interface.flush() catch {};
}
fn dataClose(ctx: *anyopaque) void {
    const d: *DataState = @ptrCast(@alignCast(ctx));
    d.stream.close(d.io);
}

fn sink(_: *anyopaque, entries: []const vfs.Entry) void {
    for (entries) |e| std.debug.print("  [entry] {s}  kind={t} size={?d}\n", .{ e.name, e.kind, e.size });
}

pub fn main(init: std.process.Init.Minimal) !void {
    var threaded: std.Io.Threaded = .init(std.heap.c_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = std.heap.c_allocator;

    var args = init.args.iterate();
    _ = args.next();
    const host = args.next() orelse "ftp.scene.org";
    const port = try std.fmt.parseInt(u16, args.next() orelse "21", 10);
    const user = args.next() orelse "ftp";
    const pass = args.next() orelse "test@mail.org";
    const is_ftps = if (args.next()) |m| std.mem.eql(u8, m, "ftps") else false;

    std.debug.print("connecting {s}:{d} user={s} ftps={}\n", .{ host, port, user, is_ftps });

    var tr = try transcript_mod.Transcript.init(gpa, .{ .capacity = 4096, .max_line_bytes = 512 });
    defer tr.deinit();

    const stream = dialAny(io, host, port) catch |e| {
        std.debug.print("connect failed: {t}\n", .{e});
        return e;
    };
    defer stream.close(io);
    std.debug.print("control connected, fd={d}\n", .{stream.socket.handle});

    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [4 * 1024]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var writer = stream.writer(io, &wbuf);

    var tls_opt: ?relay.tls.provider.TlsProvider = null;
    if (is_ftps) {
        const p = try relay.tls.libressl.LibresslProvider.init(gpa, .{});
        tls_opt = p.provider();
    }

    var client = ftp.FtpClient.init(gpa, &reader.interface, &writer.interface, .{ .context = undefined, .dialFn = dataDial }, &tr, .{
        .host = host,
        .tls = tls_opt,
        .tls_mode = if (is_ftps) (if (port == 990) .implicit else .explicit) else .none,
        .control_fd = stream.socket.handle,
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    std.debug.print("--- connect ---\n", .{});
    client.connect(io, &cancel, &diag, .{ .user = user, .pass = pass }) catch |e| {
        std.debug.print("CONNECT FAILED: {t}  diag.class={t} code={d} msg={s}\n", .{ e, diag.class, diag.protocol_code, diag.message });
        dumpTranscript(&tr, gpa);
        return e;
    };
    std.debug.print("connect OK. caps: {any}\n", .{client.caps});

    std.debug.print("--- list / ---\n", .{});
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    client.list(io, &cancel, &diag, "", arena.allocator(), .{ .context = undefined, .batchFn = sink }) catch |e| {
        std.debug.print("LIST FAILED: {t}  diag.class={t} code={d} msg={s}\n", .{ e, diag.class, diag.protocol_code, diag.message });
        dumpTranscript(&tr, gpa);
        return e;
    };
    std.debug.print("LIST OK\n", .{});
    dumpTranscript(&tr, gpa);
}

fn dumpTranscript(tr: *transcript_mod.Transcript, gpa: std.mem.Allocator) void {
    std.debug.print("\n--- transcript ---\n", .{});
    var snap = tr.snapshot(gpa) catch return;
    defer snap.deinit(gpa);
    for (snap.lines) |ln| {
        const tag = switch (ln.dir) {
            .client => ">>",
            .server => "<<",
            .info => "--",
        };
        std.debug.print("{s} {s}\n", .{ tag, ln.text });
    }
}

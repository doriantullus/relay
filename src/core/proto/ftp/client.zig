//! client — the FTP/FTPS control-connection engine, the first-party core of
//! Relay. Codes strictly against `*std.Io.Reader`/`*std.Io.Writer` handed in
//! at init: it NEVER dials (the pool owns sockets) and cannot tell TLS from
//! plaintext from an in-memory test pipe.
//!
//! Composition seams:
//! - `TlsProvider` (../../tls/provider.zig) for explicit (AUTH TLS) or
//!   implicit FTPS. Data connections resume the control connection's
//!   exported TLS session — the #1 FTPS interop requirement — unless the
//!   per-site `disable_session_reuse` escape hatch is set.
//! - `DataConnFactory` (../../testutil/ftp_script.zig) for passive data
//!   connections; `data_conn.ActiveListener` for EPRT/PORT mode.
//! - Every control line, sent and received, goes to the `Transcript`
//!   (which redacts PASS/ACCT arguments at append time).
//!
//! Conventions: every fallible op takes `(io, cancel, diag)`; errors are
//! classified per ../../diag.zig with the server's verbatim reply text.
//! Parse output is arena-per-result; the per-command arena is reset with
//! `.retain_capacity` so steady-state operation does not allocate.
//!
//! An `FtpClient` must not be moved while a transfer stream is open (the
//! stream's interfaces point into the embedded transfer state).

const std = @import("std");
const CancelToken = @import("../../cancel.zig").CancelToken;
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const vfs = @import("../../vfs/vfs.zig");
const reply_mod = @import("reply.zig");
const mlsd = @import("listing_mlsd.zig");
const listing_list = @import("listing_list.zig");
const data_conn = @import("data_conn.zig");
const tls_provider = @import("../../tls/provider.zig");
const transcript_mod = @import("../../log/transcript.zig");

pub const Error = vfs.Error;

/// Server capabilities discovered via FEAT (RFC 2389), driving command
/// selection (MLSD vs LIST, EPSV vs PASV, REST resume, ...).
pub const Caps = packed struct {
    mlsd: bool = false,
    mlst: bool = false,
    utf8: bool = false,
    epsv: bool = false,
    rest: bool = false,
    size: bool = false,
    mdtm: bool = false,
    tvfs: bool = false,
    pret: bool = false,
};

pub const TlsMode = enum {
    none,
    /// Plain connection upgraded via AUTH TLS (FTPES).
    explicit,
    /// TLS from the first byte, before the greeting (legacy port 990).
    implicit,
};

pub const DataMode = enum { passive, active };

pub const Credentials = struct {
    user: []const u8,
    pass: []const u8 = "",
    /// RFC 959 ACCT; sent only when the server answers PASS with 332.
    acct: ?[]const u8 = null,
};

pub const Options = struct {
    /// Server name: TLS SNI/verification, and the EPSV dial target when the
    /// control peer IP is unknown.
    host: []const u8 = "",
    /// The control connection's peer IPv4, when the pool knows it. PASV
    /// replies advertising a different address are rejected (FTP bounce
    /// hijack guard) unless `allow_foreign_data_ip` is set.
    control_peer_ip: ?data_conn.Ip4 = null,
    tls: ?tls_provider.TlsProvider = null,
    tls_mode: TlsMode = .none,
    /// Control socket fd for the TLS handshake (the pool owns the socket
    /// and must pass it whenever `tls != null`); fakes may ignore it.
    control_fd: std.posix.fd_t = -1,
    insecure_skip_verify: bool = false,
    /// Per-site escape hatch: some servers mishandle TLS session resumption
    /// on data connections.
    disable_session_reuse: bool = false,
    /// Per-site escape hatch for NAT'd servers whose PASV reply advertises
    /// a private/foreign address.
    allow_foreign_data_ip: bool = false,
    data_mode: DataMode = .passive,
    /// Local IPv4 advertised in EPRT/PORT (the control connection's local
    /// address, which the pool knows).
    active_advertise_ip: data_conn.Ip4 = .{ 127, 0, 0, 1 },
    /// Entries accumulated before each ListingSink batch.
    list_batch_max: usize = 64,
    /// Fixed "now" for year-less LIST dates; null = the io real clock.
    list_now: ?i64 = null,
};

/// Buffer for the transfer stream interfaces handed to consumers. The bulk
/// data moves through the data connection's own buffers; this one only
/// serves consumers that use the `take*`/`peek*` Reader APIs.
pub const transfer_buffer_len = 4096;

pub const FtpClient = struct {
    gpa: std.mem.Allocator,
    control_r: *std.Io.Reader,
    control_w: *std.Io.Writer,
    factory: data_conn.DataConnFactory,
    transcript: *transcript_mod.Transcript,
    opts: Options,
    caps: Caps,
    /// Per-command arena: reply text lives here until the next command.
    arena_inst: std.heap.ArenaAllocator,
    tls_stream: ?*tls_provider.Stream,
    tls_session: ?*tls_provider.Session,
    /// At most one transfer per control connection (FTP cannot multiplex).
    transfer: Transfer,
    transfer_active: bool,

    pub fn init(
        gpa: std.mem.Allocator,
        control_reader: *std.Io.Reader,
        control_writer: *std.Io.Writer,
        factory: data_conn.DataConnFactory,
        transcript: *transcript_mod.Transcript,
        opts: Options,
    ) FtpClient {
        return .{
            .gpa = gpa,
            .control_r = control_reader,
            .control_w = control_writer,
            .factory = factory,
            .transcript = transcript,
            .opts = opts,
            .caps = .{},
            .arena_inst = std.heap.ArenaAllocator.init(gpa),
            .tls_stream = null,
            .tls_session = null,
            .transfer = undefined,
            .transfer_active = false,
        };
    }

    /// Releases TLS state and the command arena. Does not close the control
    /// socket (the pool owns it). Any open transfer stream is hard-closed
    /// without protocol courtesy.
    pub fn deinit(self: *FtpClient) void {
        if (self.transfer_active) {
            if (!self.transfer.link_closed) self.transfer.link.close();
            self.transfer_active = false;
        }
        if (self.tls_session) |session| self.opts.tls.?.releaseSession(session);
        if (self.tls_stream) |stream| stream.close();
        self.arena_inst.deinit();
        self.* = undefined;
    }

    // ------------------------------------------------------------------ //
    // Connect sequence

    pub fn connect(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        creds: Credentials,
    ) Error!void {
        if (self.opts.tls_mode == .implicit) try self.upgradeTls(cancel, diag);

        // Greeting: optional 120 preamble(s), then 220.
        var greeting = try self.readReply(io, cancel, diag);
        while (greeting.code == 120) greeting = try self.readReply(io, cancel, diag);
        if (greeting.code != 220) return self.replyError(diag, greeting);

        if (self.opts.tls_mode == .explicit) {
            try self.sendCmd(io, cancel, diag, "AUTH TLS", .{});
            const auth = try self.readReply(io, cancel, diag);
            if (auth.code != 234) return self.replyError(diag, auth);
            try self.upgradeTls(cancel, diag);
        }
        if (self.tls_stream != null) {
            // RFC 4217: buffer size 0 for TLS, then protect data channels.
            _ = try self.cmdExpectPositive(io, cancel, diag, "PBSZ 0", .{});
            _ = try self.cmdExpectPositive(io, cancel, diag, "PROT P", .{});
        }

        try self.sendCmd(io, cancel, diag, "USER {s}", .{creds.user});
        var login = try self.readReply(io, cancel, diag);
        if (login.code == 331) {
            try self.sendCmd(io, cancel, diag, "PASS {s}", .{creds.pass});
            login = try self.readReply(io, cancel, diag);
        }
        if (login.code == 332) {
            const acct = creds.acct orelse {
                diag.set(.auth, 332, "server requires an ACCT and none is configured", .{});
                return error.AuthRequired;
            };
            try self.sendCmd(io, cancel, diag, "ACCT {s}", .{acct});
            login = try self.readReply(io, cancel, diag);
        }
        if (!login.isPositive()) return self.replyError(diag, login);

        // FEAT: pre-RFC 2389 servers answer 500/502; that just means no caps.
        try self.sendCmd(io, cancel, diag, "FEAT", .{});
        const feat = try self.readReply(io, cancel, diag);
        if (feat.isPositive()) self.parseFeat(feat);

        if (self.caps.utf8) {
            // Advisory (RFC 2640 servers are always-on); failure tolerated.
            try self.sendCmd(io, cancel, diag, "OPTS UTF8 ON", .{});
            _ = try self.readReply(io, cancel, diag);
        }
        _ = try self.cmdExpectPositive(io, cancel, diag, "TYPE I", .{});
    }

    /// FEAT reply: first and last lines are framing; each line between is
    /// one feature label (single leading space mandated by RFC 2389),
    /// optionally followed by parameters.
    fn parseFeat(self: *FtpClient, feat: reply_mod.Reply) void {
        if (feat.lines.len < 3) return;
        for (feat.lines[1 .. feat.lines.len - 1]) |raw| {
            const line = std.mem.trim(u8, raw, " \t");
            var it = std.mem.tokenizeAny(u8, line, " \t");
            const label = it.next() orelse continue;
            if (std.ascii.eqlIgnoreCase(label, "MLSD")) self.caps.mlsd = true;
            if (std.ascii.eqlIgnoreCase(label, "MLST")) {
                self.caps.mlst = true;
                // MLST advertised without MLSD still implies MLSD support
                // on every known server, but we stay literal: MLSD only
                // when announced.
            }
            if (std.ascii.eqlIgnoreCase(label, "UTF8")) self.caps.utf8 = true;
            if (std.ascii.eqlIgnoreCase(label, "EPSV")) self.caps.epsv = true;
            if (std.ascii.eqlIgnoreCase(label, "REST")) {
                const arg = it.next() orelse "";
                if (std.ascii.eqlIgnoreCase(arg, "STREAM")) self.caps.rest = true;
            }
            if (std.ascii.eqlIgnoreCase(label, "SIZE")) self.caps.size = true;
            if (std.ascii.eqlIgnoreCase(label, "MDTM")) self.caps.mdtm = true;
            if (std.ascii.eqlIgnoreCase(label, "TVFS")) self.caps.tvfs = true;
            if (std.ascii.eqlIgnoreCase(label, "PRET")) self.caps.pret = true;
        }
    }

    fn upgradeTls(self: *FtpClient, cancel: *CancelToken, diag: *Diagnostics) Error!void {
        const provider = self.opts.tls orelse {
            diag.set(.permanent, 0, "FTPS requested but no TLS provider configured", .{});
            return error.NotSupported;
        };
        const stream = provider.handshake(self.gpa, cancel, diag, self.opts.control_fd, .{
            .host = self.opts.host,
            .insecure_skip_verify = self.opts.insecure_skip_verify,
        }) catch |err| return tlsError(err);
        self.tls_stream = stream;
        self.control_r = stream.reader;
        self.control_w = stream.writer;
        if (!self.opts.disable_session_reuse) self.tls_session = stream.exportSession();
        self.transcript.append(.info, false, "TLS handshake complete (control connection)");
    }

    // ------------------------------------------------------------------ //
    // Simple ops

    /// Current working directory, copied into `out` (the 257 reply's quoted
    /// path with `""` unescaping).
    pub fn pwd(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        out: []u8,
    ) Error![]u8 {
        try self.sendCmd(io, cancel, diag, "PWD", .{});
        const r = try self.readReply(io, cancel, diag);
        if (r.code != 257) return self.replyError(diag, r);
        return parse257Path(r.lines[0], out) orelse {
            diag.set(.permanent, 257, "unparseable PWD reply: \"{s}\"", .{r.lines[0]});
            return error.ProtocolViolation;
        };
    }

    pub fn cwd(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "CWD {s}", .{path});
    }

    pub fn cdup(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "CDUP", .{});
    }

    pub fn dele(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "DELE {s}", .{path});
    }

    pub fn rmd(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "RMD {s}", .{path});
    }

    pub fn mkd(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "MKD {s}", .{path});
    }

    pub fn rename(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        from: []const u8,
        to: []const u8,
    ) Error!void {
        try self.sendCmd(io, cancel, diag, "RNFR {s}", .{from});
        const rnfr = try self.readReply(io, cancel, diag);
        if (rnfr.code != 350) return self.replyError(diag, rnfr);
        _ = try self.cmdExpectPositive(io, cancel, diag, "RNTO {s}", .{to});
    }

    pub fn chmod(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        mode: u16,
    ) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "SITE CHMOD {o:0>3} {s}", .{ mode & 0o7777, path });
    }

    pub fn noop(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "NOOP", .{});
    }

    pub fn quit(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) Error!void {
        _ = try self.cmdExpectPositive(io, cancel, diag, "QUIT", .{});
    }

    pub fn size(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!u64 {
        try self.sendCmd(io, cancel, diag, "SIZE {s}", .{path});
        const r = try self.readReply(io, cancel, diag);
        if (r.code != 213) return self.replyError(diag, r);
        const text = std.mem.trim(u8, r.lines[0], " \t");
        return std.fmt.parseInt(u64, text, 10) catch {
            diag.set(.permanent, 213, "unparseable SIZE reply: \"{s}\"", .{r.lines[0]});
            return error.ProtocolViolation;
        };
    }

    /// Modification time as seconds since epoch (server UTC per RFC 3659).
    pub fn mdtm(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) Error!i64 {
        try self.sendCmd(io, cancel, diag, "MDTM {s}", .{path});
        const r = try self.readReply(io, cancel, diag);
        if (r.code != 213) return self.replyError(diag, r);
        const text = std.mem.trim(u8, r.lines[0], " \t");
        return mlsd.parseTimeVal(text) orelse {
            diag.set(.permanent, 213, "unparseable MDTM reply: \"{s}\"", .{r.lines[0]});
            return error.ProtocolViolation;
        };
    }

    // ------------------------------------------------------------------ //
    // Listings

    /// Streams the listing of `path` ("" = current directory) into `sink`,
    /// batching entries AS THEY PARSE so a 100k-entry directory renders
    /// immediately. MLSD when the server supports it, LIST with per-line
    /// format auto-detection otherwise. Entries are owned by `arena`.
    pub fn list(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        arena: std.mem.Allocator,
        sink: vfs.ListingSink,
    ) Error!void {
        std.debug.assert(!self.transfer_active);
        const use_mlsd = self.caps.mlsd;

        var pending = try self.prepareData(io, cancel, diag);
        var pending_owned = true;
        errdefer if (pending_owned) discardPending(io, &pending);

        const verb: []const u8 = if (use_mlsd) "MLSD" else "LIST";
        if (path.len == 0) {
            try self.sendCmd(io, cancel, diag, "{s}", .{verb});
        } else {
            try self.sendCmd(io, cancel, diag, "{s} {s}", .{ verb, path });
        }
        const opening = try self.readReply(io, cancel, diag);
        if (opening.code / 100 != 1) return self.replyError(diag, opening);

        pending_owned = false;
        var link = try self.establishData(io, cancel, diag, &pending);
        var link_open = true;
        // On a mid-listing failure the control connection is left with an
        // unread completion reply; the pool sees the diagnostic and retires
        // the connection rather than resynchronizing.
        errdefer if (link_open) link.close();

        const now: i64 = self.opts.list_now orelse nowFromClock(io);
        var entries: std.ArrayList(vfs.Entry) = .empty;
        var flushed: usize = 0;
        const r = link.reader();
        while (true) {
            cancel.check() catch |err| {
                diag.set(.cancel, 0, "canceled while listing", .{});
                return err;
            };
            const line = r.takeDelimiterExclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => {
                    diag.set(.transient, 0, "data connection lost mid-listing", .{});
                    return error.ConnectionLost;
                },
                error.StreamTooLong => {
                    diag.set(.permanent, 0, "listing line exceeds buffer capacity", .{});
                    return error.ProtocolViolation;
                },
            };
            const parsed = if (use_mlsd)
                try mlsd.parseLine(arena, line)
            else
                try listing_list.parseLine(arena, line, .{ .now = now });
            if (parsed) |entry| try entries.append(arena, entry);
            const buffered = r.buffered();
            if (buffered.len != 0 and buffered[0] == '\n') r.toss(1);
            if (entries.items.len - flushed >= self.opts.list_batch_max) {
                sink.batch(entries.items[flushed..]);
                flushed = entries.items.len;
            }
        }
        link.close();
        link_open = false;
        if (entries.items.len > flushed) sink.batch(entries.items[flushed..]);

        const final = try self.readReply(io, cancel, diag);
        if (!final.isPositive()) return self.replyError(diag, final);
    }

    // ------------------------------------------------------------------ //
    // Transfers

    /// Starts a download (REST `offset` first when nonzero). The returned
    /// stream reports `EndOfStream` only after the server's final reply
    /// confirms a complete transfer; a missing/negative reply surfaces as
    /// `ReadFailed` with `diag` filled. `cancel` and `diag` must outlive
    /// the stream. Close on the happy path is silent; close before
    /// EndOfStream sends ABOR, drains the 426/226 pair, then hard-closes
    /// the data connection.
    pub fn retr(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        offset: u64,
    ) Error!vfs.ReadStream {
        std.debug.assert(!self.transfer_active);
        var pending = try self.prepareData(io, cancel, diag);
        var pending_owned = true;
        errdefer if (pending_owned) discardPending(io, &pending);

        if (offset != 0) {
            try self.sendCmd(io, cancel, diag, "REST {d}", .{offset});
            const rest = try self.readReply(io, cancel, diag);
            if (rest.code != 350) return self.replyError(diag, rest);
        }
        try self.sendCmd(io, cancel, diag, "RETR {s}", .{path});
        const opening = try self.readReply(io, cancel, diag);
        if (opening.code / 100 != 1) return self.replyError(diag, opening);

        pending_owned = false;
        const link = try self.establishData(io, cancel, diag, &pending);
        self.beginTransfer(io, cancel, diag, link);
        self.transfer.reader = .{
            .vtable = &transfer_reader_vtable,
            .buffer = &self.transfer.buf,
            .seek = 0,
            .end = 0,
        };
        return .{
            .reader = &self.transfer.reader,
            .context = self,
            .closeFn = readStreamClose,
        };
    }

    pub const StorMode = enum { store, append };

    /// Starts an upload: STOR (REST `offset` first when nonzero) or APPE.
    /// `close` flushes, half-closes the data connection, and waits for the
    /// final reply — only a successful close means the server stored the
    /// file. `cancel` and `diag` must outlive the stream.
    pub fn stor(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        offset: u64,
        mode: StorMode,
    ) Error!vfs.WriteStream {
        std.debug.assert(!self.transfer_active);
        var pending = try self.prepareData(io, cancel, diag);
        var pending_owned = true;
        errdefer if (pending_owned) discardPending(io, &pending);

        if (offset != 0 and mode == .store) {
            try self.sendCmd(io, cancel, diag, "REST {d}", .{offset});
            const rest = try self.readReply(io, cancel, diag);
            if (rest.code != 350) return self.replyError(diag, rest);
        }
        switch (mode) {
            .store => try self.sendCmd(io, cancel, diag, "STOR {s}", .{path}),
            .append => try self.sendCmd(io, cancel, diag, "APPE {s}", .{path}),
        }
        const opening = try self.readReply(io, cancel, diag);
        if (opening.code / 100 != 1) return self.replyError(diag, opening);

        pending_owned = false;
        const link = try self.establishData(io, cancel, diag, &pending);
        self.beginTransfer(io, cancel, diag, link);
        self.transfer.writer = .{
            .vtable = &transfer_writer_vtable,
            .buffer = &self.transfer.buf,
            .end = 0,
        };
        return .{
            .writer = &self.transfer.writer,
            .context = self,
            .closeFn = writeStreamClose,
        };
    }

    const Transfer = struct {
        client: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        link: data_conn.Link,
        /// The data link was already closed on the happy path (downloads
        /// close it before the final reply; see transferStream).
        link_closed: bool,
        /// Protocol completed: data EOF seen and the final reply was 2xx.
        done: bool,
        /// Canceled or data failure: close must ABOR instead of confirming.
        failed: bool,
        reader: std.Io.Reader,
        writer: std.Io.Writer,
        buf: [transfer_buffer_len]u8,
    };

    fn beginTransfer(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        link: data_conn.Link,
    ) void {
        const t = &self.transfer;
        t.client = self;
        t.io = io;
        t.cancel = cancel;
        t.diag = diag;
        t.link = link;
        t.link_closed = false;
        t.done = false;
        t.failed = false;
        self.transfer_active = true;
    }

    const transfer_reader_vtable: std.Io.Reader.VTable = .{ .stream = transferStream };

    fn transferStream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const t: *Transfer = @alignCast(@fieldParentPtr("reader", r));
        if (t.failed) return error.ReadFailed;
        if (t.done) return error.EndOfStream;
        if (t.cancel.isCanceled()) {
            t.diag.set(.cancel, 0, "transfer canceled", .{});
            t.failed = true;
            return error.ReadFailed;
        }
        const n = t.link.reader().stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => {
                // Close the data connection BEFORE waiting for the final
                // reply: vsftpd with TLS data connections sends 226 only
                // after the client's close_notify/FIN (holding the link
                // open deadlocks until the server's data timeout). The
                // listing path has always closed in this order.
                t.link.close();
                t.link_closed = true;
                // End of data is not success: the final reply decides.
                t.client.finishRead() catch {
                    t.failed = true;
                    return error.ReadFailed;
                };
                t.done = true;
                return error.EndOfStream;
            },
            error.ReadFailed => {
                t.diag.set(.transient, 0, "data connection lost mid-transfer", .{});
                t.failed = true;
                return error.ReadFailed;
            },
            error.WriteFailed => return error.WriteFailed,
        };
        return n;
    }

    fn finishRead(self: *FtpClient) error{TransferFailed}!void {
        const t = &self.transfer;
        const final = self.readReply(t.io, t.cancel, t.diag) catch return error.TransferFailed;
        if (!final.isPositive()) {
            self.setReplyDiag(t.diag, final);
            return error.TransferFailed;
        }
    }

    fn readStreamClose(ctx: *anyopaque, io: std.Io) void {
        const self: *FtpClient = @ptrCast(@alignCast(ctx));
        if (!self.transfer_active) return;
        const t = &self.transfer;
        // Close the data link BEFORE the ABOR exchange: a server blocked
        // writing data (we stopped reading) never processes control input
        // — vsftpd over TLS deadlocks until its data timeout otherwise.
        // The failed write also prompts the server's own 426.
        if (!t.link_closed) {
            t.link.close();
            t.link_closed = true;
        }
        if (!t.done) self.abortTransfer(io);
        self.transfer_active = false;
    }

    /// Protocol courtesy on a canceled/failed transfer: tell the server,
    /// then drain its 426/226 pair so the control connection stays usable.
    /// Uses a fresh token — the transfer's token is the one that fired.
    fn abortTransfer(self: *FtpClient, io: std.Io) void {
        var fresh: CancelToken = .{};
        var scratch: Diagnostics = .{};
        self.sendCmd(io, &fresh, &scratch, "ABOR", .{}) catch return;
        var drained: usize = 0;
        while (drained < 2) : (drained += 1) {
            const r = self.readReply(io, &fresh, &scratch) catch return;
            // 426 announces the aborted transfer; the ABOR completion
            // reply (226/225) follows it.
            if (r.code != 426) break;
        }
    }

    const transfer_writer_vtable: std.Io.Writer.VTable = .{
        .drain = transferDrain,
        .flush = transferFlush,
    };

    fn transferDrain(
        w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const t: *Transfer = @alignCast(@fieldParentPtr("writer", w));
        if (t.failed) return error.WriteFailed;
        if (t.cancel.isCanceled()) {
            t.diag.set(.cancel, 0, "transfer canceled", .{});
            t.failed = true;
            return error.WriteFailed;
        }
        const inner = t.link.writer();
        const buffered = w.buffered();
        if (buffered.len != 0) inner.writeAll(buffered) catch return uploadFailed(t);
        var consumed: usize = 0;
        if (data.len != 0) {
            for (data[0 .. data.len - 1]) |slice| {
                inner.writeAll(slice) catch return uploadFailed(t);
                consumed += slice.len;
            }
            const pattern = data[data.len - 1];
            for (0..splat) |_| {
                inner.writeAll(pattern) catch return uploadFailed(t);
                consumed += pattern.len;
            }
        }
        w.end = 0;
        return consumed;
    }

    fn transferFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const t: *Transfer = @alignCast(@fieldParentPtr("writer", w));
        while (w.end != 0) _ = try transferDrain(w, &.{""}, 1);
        t.link.writer().flush() catch return uploadFailed(t);
    }

    fn uploadFailed(t: *Transfer) std.Io.Writer.Error {
        t.diag.set(.transient, 0, "data connection lost mid-upload", .{});
        t.failed = true;
        return error.WriteFailed;
    }

    fn writeStreamClose(ctx: *anyopaque, io: std.Io) vfs.Error!void {
        const self: *FtpClient = @ptrCast(@alignCast(ctx));
        if (!self.transfer_active) return;
        const t = &self.transfer;
        defer {
            t.link.close();
            self.transfer_active = false;
        }
        if (!t.failed and t.cancel.isCanceled()) {
            t.diag.set(.cancel, 0, "transfer canceled", .{});
            t.failed = true;
        }
        if (t.failed) {
            self.abortTransfer(io);
            return if (t.diag.class == .cancel) error.Canceled else error.ConnectionLost;
        }
        t.writer.flush() catch {
            self.abortTransfer(io);
            return error.ConnectionLost;
        };
        t.link.finishWrite() catch {
            t.diag.set(.transient, 0, "data connection lost finishing upload", .{});
            self.abortTransfer(io);
            return error.ConnectionLost;
        };
        const final = try self.readReply(io, t.cancel, t.diag);
        if (!final.isPositive()) return self.replyError(t.diag, final);
    }

    // ------------------------------------------------------------------ //
    // Data connection establishment

    const PendingData = union(enum) {
        dialed: data_conn.DataConn,
        listener: data_conn.ActiveListener,
    };

    fn discardPending(io: std.Io, pending: *PendingData) void {
        switch (pending.*) {
            .dialed => |conn| conn.close(),
            .listener => |*l| l.close(io),
        }
    }

    /// Phase one of a transfer: negotiate where the data connection comes
    /// from. Passive: EPSV first (when advertised), PASV fallback, dial via
    /// the factory. Active: bind a listener and advertise it (EPRT first,
    /// PORT fallback). For FTPS, TLS is stacked later in `establishData` —
    /// servers handshake the data connection only after the transfer
    /// command is accepted.
    fn prepareData(self: *FtpClient, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) Error!PendingData {
        switch (self.opts.data_mode) {
            .active => {
                var listener = data_conn.ActiveListener.open(io) catch |err| switch (err) {
                    error.Canceled => {
                        diag.set(.cancel, 0, "canceled opening active-mode listener", .{});
                        return error.Canceled;
                    },
                    else => {
                        diag.set(.transient, 0, "cannot open active-mode listener: {t}", .{err});
                        return error.Unexpected;
                    },
                };
                errdefer listener.close(io);
                const ip = self.opts.active_advertise_ip;
                var cmd_buf: [data_conn.eprt_cmd_max_len]u8 = undefined;
                try self.sendCmd(io, cancel, diag, "{s}", .{
                    data_conn.formatEprt(&cmd_buf, ip, listener.port()),
                });
                var r = try self.readReply(io, cancel, diag);
                if (r.code == 500 or r.code == 502) {
                    // Pre-RFC 2428 server: fall back to PORT.
                    try self.sendCmd(io, cancel, diag, "{s}", .{
                        data_conn.formatPort(&cmd_buf, ip, listener.port()),
                    });
                    r = try self.readReply(io, cancel, diag);
                }
                if (!r.isPositive()) return self.replyError(diag, r);
                return .{ .listener = listener };
            },
            .passive => {
                if (self.caps.epsv) epsv: {
                    try self.sendCmd(io, cancel, diag, "EPSV", .{});
                    const r = try self.readReply(io, cancel, diag);
                    if (r.isPermanentErr()) {
                        // Advertised but refused: remember and fall back.
                        self.caps.epsv = false;
                        break :epsv;
                    }
                    if (r.code != 229) return self.replyError(diag, r);
                    const port = data_conn.parseEpsvReply(r.lines[0]) orelse {
                        diag.set(.permanent, 229, "unparseable EPSV reply: \"{s}\"", .{r.lines[0]});
                        return error.ProtocolViolation;
                    };
                    // EPSV never carries an address: always the control peer.
                    var host_buf: [15]u8 = undefined;
                    const host = if (self.opts.control_peer_ip) |ip|
                        data_conn.formatIp4(&host_buf, ip)
                    else
                        self.opts.host;
                    return .{ .dialed = try self.dialData(io, cancel, diag, host, port) };
                }
                try self.sendCmd(io, cancel, diag, "PASV", .{});
                const r = try self.readReply(io, cancel, diag);
                if (r.code != 227) return self.replyError(diag, r);
                const target = data_conn.parsePasvReply(r.lines[0]) orelse {
                    diag.set(.permanent, 227, "unparseable PASV reply: \"{s}\"", .{r.lines[0]});
                    return error.ProtocolViolation;
                };
                if (self.opts.control_peer_ip) |peer| {
                    if (!std.mem.eql(u8, &peer, &target.ip) and !self.opts.allow_foreign_data_ip) {
                        diag.set(
                            .permanent,
                            227,
                            "PASV advertised {d}.{d}.{d}.{d}, not the control peer {d}.{d}.{d}.{d} (FTP bounce guard)",
                            .{
                                target.ip[0], target.ip[1], target.ip[2], target.ip[3],
                                peer[0],      peer[1],      peer[2],      peer[3],
                            },
                        );
                        return error.ProtocolViolation;
                    }
                }
                var host_buf: [15]u8 = undefined;
                const host = data_conn.formatIp4(&host_buf, target.ip);
                return .{ .dialed = try self.dialData(io, cancel, diag, host, target.port) };
            },
        }
    }

    /// Phase two, after the transfer command's 1xx reply: produce the live
    /// `Link`, accepting the inbound connection (active mode) and stacking
    /// TLS with the control connection's session (FTPS).
    fn establishData(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        pending: *PendingData,
    ) Error!data_conn.Link {
        switch (pending.*) {
            .dialed => |conn| return self.maybeWrapTls(cancel, diag, conn),
            .listener => |*l| {
                defer l.close(io);
                const conn = l.accept(io, self.gpa, cancel, diag) catch |err|
                    return dialError(err);
                return self.maybeWrapTls(cancel, diag, conn);
            },
        }
    }

    fn maybeWrapTls(
        self: *FtpClient,
        cancel: *CancelToken,
        diag: *Diagnostics,
        conn: data_conn.DataConn,
    ) Error!data_conn.Link {
        const provider = self.opts.tls orelse return .{ .conn = conn };
        if (self.tls_stream == null) return .{ .conn = conn };
        return data_conn.wrapTls(conn, provider, self.gpa, cancel, diag, .{
            .host = self.opts.host,
            .session = if (self.opts.disable_session_reuse) null else self.tls_session,
            .insecure_skip_verify = self.opts.insecure_skip_verify,
        }) catch |err| {
            conn.close();
            return tlsError(err);
        };
    }

    fn dialData(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) Error!data_conn.DataConn {
        return self.factory.dial(io, cancel, diag, host, port) catch |err| dialError(err);
    }

    fn dialError(err: data_conn.DialError) Error {
        return switch (err) {
            error.Canceled => error.Canceled,
            error.Timeout => error.Timeout,
            error.ConnectionRefused, error.ConnectionLost => error.ConnectionLost,
            error.Unexpected => error.Unexpected,
        };
    }

    // ------------------------------------------------------------------ //
    // Control-channel machinery

    fn sendCmd(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        comptime fmt: []const u8,
        args: anytype,
    ) Error!void {
        _ = io;
        cancel.check() catch |err| {
            diag.set(.cancel, 0, "canceled before command", .{});
            return err;
        };
        var buf: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, fmt, args) catch {
            diag.set(.permanent, 0, "command line too long", .{});
            return error.Unexpected;
        };
        self.control_w.writeAll(line) catch return self.controlLost(diag);
        self.control_w.writeAll("\r\n") catch return self.controlLost(diag);
        self.control_w.flush() catch return self.controlLost(diag);
        const verbose = std.mem.eql(u8, line, "NOOP");
        self.transcript.append(.client, verbose, line);
    }

    fn controlLost(self: *FtpClient, diag: *Diagnostics) Error {
        _ = self;
        diag.set(.transient, 0, "control connection lost", .{});
        return error.ConnectionLost;
    }

    fn readReply(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
    ) Error!reply_mod.Reply {
        _ = io;
        _ = self.arena_inst.reset(.retain_capacity);
        const r = reply_mod.read(self.arena_inst.allocator(), self.control_r, cancel, diag) catch |err|
            return switch (err) {
                error.Canceled => error.Canceled,
                error.ConnectionLost => error.ConnectionLost,
                error.ProtocolViolation => error.ProtocolViolation,
                error.OutOfMemory => error.OutOfMemory,
            };
        self.logReply(r);
        return r;
    }

    /// Sends `fmt` and requires a 2xx reply.
    fn cmdExpectPositive(
        self: *FtpClient,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        comptime fmt: []const u8,
        args: anytype,
    ) Error!reply_mod.Reply {
        try self.sendCmd(io, cancel, diag, fmt, args);
        const r = try self.readReply(io, cancel, diag);
        if (!r.isPositive()) return self.replyError(diag, r);
        return r;
    }

    fn setReplyDiag(self: *FtpClient, diag: *Diagnostics, r: reply_mod.Reply) void {
        _ = self;
        const class = reply_mod.errorClassOf(r.code) orelse .permanent;
        const text = if (r.lines.len != 0) r.lines[0] else "";
        diag.set(class, r.code, "{d} {s}", .{ r.code, text });
    }

    /// Classifies a negative (or unexpected) reply into diag and maps it to
    /// a Zig error. The class in diag drives retry/UI; the error value is a
    /// coarse hint.
    fn replyError(self: *FtpClient, diag: *Diagnostics, r: reply_mod.Reply) Error {
        self.setReplyDiag(diag, r);
        return switch (r.code) {
            421 => error.ConnectionLost,
            430, 530, 532 => error.AuthRequired,
            450, 550 => error.NotFound,
            500, 501, 502, 504 => error.NotSupported,
            553 => error.PermissionDenied,
            else => error.Unexpected,
        };
    }

    /// Transcript copy with the wire framing reconstructed (reply.zig
    /// strips it during parsing); the text content is verbatim.
    fn logReply(self: *FtpClient, r: reply_mod.Reply) void {
        var buf: [512]u8 = undefined;
        const n = r.lines.len;
        for (r.lines, 0..) |line, i| {
            const text = if (i == n - 1)
                std.fmt.bufPrint(&buf, "{d} {s}", .{ r.code, line }) catch line
            else if (i == 0)
                std.fmt.bufPrint(&buf, "{d}-{s}", .{ r.code, line }) catch line
            else
                line;
            self.transcript.append(.server, false, text);
        }
    }
};

fn tlsError(err: tls_provider.Error) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        error.ConnectionLost => error.ConnectionLost,
        error.ProtocolViolation => error.ProtocolViolation,
        error.HandshakeFailed,
        error.CertificateUntrusted,
        error.HostnameMismatch,
        error.Unexpected,
        => error.Unexpected,
    };
}

fn nowFromClock(io: std.Io) i64 {
    const ts = std.Io.Clock.real.now(io);
    return @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
}

/// RFC 959 257 reply: `"<path>" <commentary>` where embedded quotes are
/// doubled. Returns the unescaped path copied into `out`, or null when the
/// reply is malformed or `out` is too small.
fn parse257Path(text: []const u8, out: []u8) ?[]u8 {
    if (text.len < 2 or text[0] != '"') return null;
    var n: usize = 0;
    var i: usize = 1;
    while (i < text.len) {
        if (text[i] == '"') {
            if (i + 1 < text.len and text[i + 1] == '"') {
                if (n == out.len) return null;
                out[n] = '"';
                n += 1;
                i += 2;
                continue;
            }
            return out[0..n];
        }
        if (n == out.len) return null;
        out[n] = text[i];
        n += 1;
        i += 1;
    }
    return null; // unterminated quote
}

// ---------------------------------------------------------------------------
// Tests (ScriptedServer, fully offline)
// ---------------------------------------------------------------------------

const testing = std.testing;
const ftp_script = @import("../../testutil/ftp_script.zig");
const ScriptedServer = ftp_script.ScriptedServer;
const Step = ftp_script.Step;

const TestRig = struct {
    server: ScriptedServer,
    transcript: transcript_mod.Transcript,
    client: FtpClient,
    cancel: CancelToken,
    diag: Diagnostics,

    /// In-place init; `rig` must be pinned (the client points at the
    /// server's streams and at itself during transfers).
    fn init(rig: *TestRig, script: []const Step, opts: Options) !void {
        rig.cancel = .{};
        rig.diag = .{};
        rig.transcript = try transcript_mod.Transcript.init(
            testing.allocator,
            .{ .capacity = 128, .max_line_bytes = 128 },
        );
        errdefer rig.transcript.deinit();
        try rig.server.init(testing.allocator, testing.io, script);
        rig.client = FtpClient.init(
            testing.allocator,
            rig.server.clientReader(),
            rig.server.clientWriter(),
            rig.server.factory(),
            &rig.transcript,
            opts,
        );
    }

    fn deinit(rig: *TestRig) void {
        rig.client.deinit();
        rig.server.deinit();
        rig.transcript.deinit();
    }

    fn connect(rig: *TestRig, creds: Credentials) Error!void {
        return rig.client.connect(testing.io, &rig.cancel, &rig.diag, creds);
    }
};

/// Plain-FTP login conversation used by several tests; FEAT advertises the
/// full capability set (multiline reply).
const login_steps = [_]Step{
    .{ .reply = "220 relay-test FTP ready" },
    .{ .expect = "USER alice" },
    .{ .reply = "331 Password required" },
    .{ .expect = "PASS hunter2" },
    .{ .reply = "230 Logged in" },
    .{ .expect = "FEAT" },
    .{ .reply_multiline = &.{
        "211-Features:",
        " MLST type*;size*;modify*;UNIX.mode*;",
        " MLSD",
        " UTF8",
        " EPSV",
        " REST STREAM",
        " SIZE",
        " MDTM",
        " TVFS",
        "211 End",
    } },
    .{ .expect = "OPTS UTF8 ON" },
    .{ .reply = "200 Always in UTF8 mode." },
    .{ .expect = "TYPE I" },
    .{ .reply = "200 Switching to Binary mode." },
};

const test_creds: Credentials = .{ .user = "alice", .pass = "hunter2" };

test "connect: full login, multiline FEAT caps, PASS redacted in transcript" {
    var rig: TestRig = undefined;
    try rig.init(&login_steps, .{ .host = "test.example" });
    defer rig.deinit();

    try rig.connect(test_creds);
    try rig.server.check();

    try testing.expect(rig.client.caps.mlsd);
    try testing.expect(rig.client.caps.mlst);
    try testing.expect(rig.client.caps.utf8);
    try testing.expect(rig.client.caps.epsv);
    try testing.expect(rig.client.caps.rest);
    try testing.expect(rig.client.caps.size);
    try testing.expect(rig.client.caps.mdtm);
    try testing.expect(rig.client.caps.tvfs);
    try testing.expect(!rig.client.caps.pret);

    // The server saw the real password but the transcript never stores it.
    try testing.expect(std.mem.indexOf(u8, rig.server.transcript(), "PASS hunter2") != null);
    var snap = try rig.transcript.snapshot(testing.allocator);
    defer snap.deinit(testing.allocator);
    var saw_redacted = false;
    for (snap.lines) |line| {
        try testing.expect(std.mem.indexOf(u8, line.text, "hunter2") == null);
        if (std.mem.eql(u8, line.text, "PASS ****")) saw_redacted = true;
    }
    try testing.expect(saw_redacted);
}

test "connect: 120 preamble, FEAT refused, no-PASS login" {
    var rig: TestRig = undefined;
    try rig.init(&.{
        .{ .reply = "120 Service ready in a moment" },
        .{ .reply_multiline = &.{ "220-Welcome", "220 ready" } },
        .{ .expect = "USER anonymous" },
        .{ .reply = "230 Guest login ok" },
        .{ .expect = "FEAT" },
        .{ .reply = "502 Command not implemented" },
        .{ .expect = "TYPE I" },
        .{ .reply = "200 ok" },
    }, .{});
    defer rig.deinit();

    try rig.connect(.{ .user = "anonymous" });
    try rig.server.check();
    try testing.expectEqual(Caps{}, rig.client.caps);
}

test "connect: 530 PASS rejection is .auth" {
    var rig: TestRig = undefined;
    try rig.init(&.{
        .{ .reply = "220 ready" },
        .{ .expect = "USER alice" },
        .{ .reply = "331 Password required" },
        .{ .expect = "PASS hunter2" },
        .{ .reply = "530 Login incorrect." },
    }, .{});
    defer rig.deinit();

    try testing.expectError(error.AuthRequired, rig.connect(test_creds));
    try testing.expectEqual(diag_mod.ErrorClass.auth, rig.diag.class);
    try testing.expectEqual(@as(u32, 530), rig.diag.protocol_code);
    try testing.expect(std.mem.indexOf(u8, rig.diag.message, "Login incorrect.") != null);
    try rig.server.check();
}

test "421 reply is .transient ConnectionLost; 550 is .permanent" {
    var rig: TestRig = undefined;
    try rig.init(&.{
        .{ .expect = "CWD /ok" },
        .{ .reply = "250 ok" },
        .{ .expect = "CWD /missing" },
        .{ .reply = "550 /missing: No such file or directory" },
        .{ .expect = "NOOP" },
        .{ .reply = "421 Too many connections, closing" },
    }, .{});
    defer rig.deinit();

    const io = testing.io;
    try rig.client.cwd(io, &rig.cancel, &rig.diag, "/ok");

    try testing.expectError(
        error.NotFound,
        rig.client.cwd(io, &rig.cancel, &rig.diag, "/missing"),
    );
    try testing.expectEqual(diag_mod.ErrorClass.permanent, rig.diag.class);
    try testing.expectEqual(@as(u32, 550), rig.diag.protocol_code);
    try testing.expect(std.mem.indexOf(u8, rig.diag.message, "No such file or directory") != null);

    try testing.expectError(
        error.ConnectionLost,
        rig.client.noop(io, &rig.cancel, &rig.diag),
    );
    try testing.expectEqual(diag_mod.ErrorClass.transient, rig.diag.class);
    try testing.expectEqual(@as(u32, 421), rig.diag.protocol_code);
    try rig.server.check();
}

test "dropped control connection mid-command is .transient" {
    var rig: TestRig = undefined;
    try rig.init(&.{
        .{ .expect = "NOOP" },
        .drop_connection,
    }, .{});
    defer rig.deinit();

    try testing.expectError(
        error.ConnectionLost,
        rig.client.noop(testing.io, &rig.cancel, &rig.diag),
    );
    try testing.expectEqual(diag_mod.ErrorClass.transient, rig.diag.class);
    try rig.server.check();
}

test "pwd, size, mdtm, rename, mkd, dele, chmod, cdup, quit" {
    var rig: TestRig = undefined;
    try rig.init(&.{
        .{ .expect = "PWD" },
        .{ .reply = "257 \"/home/al\"\"ice\" is the current directory" },
        .{ .expect = "SIZE big.iso" },
        .{ .reply = "213 1073741824" },
        .{ .expect = "MDTM big.iso" },
        .{ .reply = "213 20240910084528" },
        .{ .expect = "RNFR old name.txt" },
        .{ .reply = "350 Ready for RNTO" },
        .{ .expect = "RNTO new name.txt" },
        .{ .reply = "250 Rename successful" },
        .{ .expect = "MKD photos" },
        .{ .reply = "257 \"/home/photos\" created" },
        .{ .expect = "DELE junk.tmp" },
        .{ .reply = "250 Deleted" },
        .{ .expect = "SITE CHMOD 644 file.txt" },
        .{ .reply = "200 SITE CHMOD ok" },
        .{ .expect = "CDUP" },
        .{ .reply = "250 ok" },
        .{ .expect = "QUIT" },
        .{ .reply = "221 Goodbye" },
    }, .{});
    defer rig.deinit();

    const io = testing.io;
    var path_buf: [128]u8 = undefined;
    const path = try rig.client.pwd(io, &rig.cancel, &rig.diag, &path_buf);
    try testing.expectEqualStrings("/home/al\"ice", path);
    try testing.expectEqual(
        @as(u64, 1073741824),
        try rig.client.size(io, &rig.cancel, &rig.diag, "big.iso"),
    );
    try testing.expectEqual(
        @as(i64, 1725957928),
        try rig.client.mdtm(io, &rig.cancel, &rig.diag, "big.iso"),
    );
    try rig.client.rename(io, &rig.cancel, &rig.diag, "old name.txt", "new name.txt");
    try rig.client.mkd(io, &rig.cancel, &rig.diag, "photos");
    try rig.client.dele(io, &rig.cancel, &rig.diag, "junk.tmp");
    try rig.client.chmod(io, &rig.cancel, &rig.diag, "file.txt", 0o644);
    try rig.client.cdup(io, &rig.cancel, &rig.diag);
    try rig.client.quit(io, &rig.cancel, &rig.diag);
    try rig.server.check();
}

test "parse257Path quoting" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/plain", parse257Path("\"/plain\" created", &buf).?);
    try testing.expectEqualStrings("/a\"b", parse257Path("\"/a\"\"b\"", &buf).?);
    try testing.expectEqualStrings("", parse257Path("\"\" empty", &buf).?);
    try testing.expectEqual(@as(?[]u8, null), parse257Path("no quotes", &buf));
    try testing.expectEqual(@as(?[]u8, null), parse257Path("\"unterminated", &buf));
    var tiny: [2]u8 = undefined;
    try testing.expectEqual(@as(?[]u8, null), parse257Path("\"/too-long\"", &tiny));
}

fn fuzzParse257(_: void, smith: *std.testing.Smith) !void {
    var in_buf: [128]u8 = undefined;
    const input = in_buf[0..smith.slice(&in_buf)];
    var out_buf: [128]u8 = undefined;
    if (parse257Path(input, &out_buf)) |path| {
        // Anything returned came from inside one balanced quote pair.
        try testing.expect(input.len >= path.len + 2);
    }
}

test "fuzz parse257Path" {
    try testing.fuzz({}, fuzzParse257, .{ .corpus = &.{
        "\"/home/alice\" is current",
        "\"/a\"\"b\"",
        "\"",
    } });
}

// -------------------------------------------------------------------- //
// Listings

const SinkRecorder = struct {
    /// Batch sizes in arrival order.
    batch_sizes: [16]usize = undefined,
    batch_count: usize = 0,
    names: [64][]const u8 = undefined,
    name_count: usize = 0,
    /// When set, the first batch writes NOOP to the control connection so
    /// a script `.expect = "NOOP"` step can prove streaming-before-226.
    gate_writer: ?*std.Io.Writer = null,

    fn sink(self: *SinkRecorder) vfs.ListingSink {
        return .{ .context = self, .batchFn = onBatch };
    }

    fn onBatch(ctx: *anyopaque, entries: []const vfs.Entry) void {
        const self: *SinkRecorder = @ptrCast(@alignCast(ctx));
        if (self.batch_count == 0) {
            if (self.gate_writer) |w| {
                w.writeAll("NOOP\r\n") catch {};
                w.flush() catch {};
            }
        }
        self.batch_sizes[self.batch_count] = entries.len;
        self.batch_count += 1;
        for (entries) |entry| {
            self.names[self.name_count] = entry.name;
            self.name_count += 1;
        }
    }
};

test "MLSD listing streams batches before the final 226" {
    var rig: TestRig = undefined;
    const script = login_steps ++ [_]Step{
        .{ .expect = "EPSV" },
        .{ .open_data = 3010 },
        .{ .reply = "229 Entering Extended Passive Mode (|||3010|)" },
        .{ .expect = "MLSD /pub" },
        .{ .reply = "150 Opening data connection for MLSD" },
        .{ .data_send = "type=file;size=1; a.txt\r\ntype=file;size=2; b.txt\r\n" },
        // The sink writes NOOP on its first batch: reaching this step
        // proves entries were delivered while the listing was still
        // streaming — strictly before the final data and the 226 below.
        .{ .expect = "NOOP" },
        .{ .data_send = "type=dir;modify=20240910084528; sub\r\ntype=cdir; .\r\n" },
        .close_data,
        .{ .reply = "226 Transfer complete" },
    };
    try rig.init(&script, .{ .host = "test.example", .list_batch_max = 2 });
    defer rig.deinit();

    try rig.connect(test_creds);

    var recorder: SinkRecorder = .{ .gate_writer = rig.server.clientWriter() };
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    try rig.client.list(
        testing.io,
        &rig.cancel,
        &rig.diag,
        "/pub",
        arena_inst.allocator(),
        recorder.sink(),
    );
    try rig.server.check();

    try testing.expectEqual(@as(usize, 2), recorder.batch_count);
    try testing.expectEqual(@as(usize, 2), recorder.batch_sizes[0]);
    try testing.expectEqual(@as(usize, 1), recorder.batch_sizes[1]); // cdir filtered
    try testing.expectEqualStrings("a.txt", recorder.names[0]);
    try testing.expectEqualStrings("b.txt", recorder.names[1]);
    try testing.expectEqualStrings("sub", recorder.names[2]);
}

test "LIST fallback with auto-detected unix format" {
    var rig: TestRig = undefined;
    // No FEAT caps: MLSD unknown, EPSV unknown -> LIST over PASV.
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 20030 },
        .{ .reply = "227 Entering Passive Mode (127,0,0,1,78,62)" }, // 78*256+62 = 20030
        .{ .expect = "LIST" },
        .{ .reply = "150 Here comes the directory listing" },
        .{ .data_send = "total 16\r\n" ++
            "drwxr-xr-x    2 ftp      ftp          4096 Jan 15  2020 pub\r\n" ++
            "-rw-r--r--    1 ftp      ftp          1234 Jan 15  2020 notes.txt\r\n" },
        .close_data,
        .{ .reply = "226 Directory send OK" },
    };
    try rig.init(&script, .{
        .control_peer_ip = .{ 127, 0, 0, 1 },
        .list_now = 1781049600, // 2026-06-10, fixed for determinism
    });
    defer rig.deinit();

    var recorder: SinkRecorder = .{};
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    try rig.client.list(
        testing.io,
        &rig.cancel,
        &rig.diag,
        "",
        arena_inst.allocator(),
        recorder.sink(),
    );
    try rig.server.check();

    try testing.expectEqual(@as(usize, 1), recorder.batch_count);
    try testing.expectEqual(@as(usize, 2), recorder.name_count); // "total 16" skipped
    try testing.expectEqualStrings("pub", recorder.names[0]);
    try testing.expectEqualStrings("notes.txt", recorder.names[1]);
}

// -------------------------------------------------------------------- //
// Transfers

test "RETR with REST offset: content equality and final-reply gating" {
    var rig: TestRig = undefined;
    const payload = "fghijklmnopqrstuvwxyz";
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 21000 },
        .{ .reply = "227 Entering Passive Mode (127,0,0,1,82,8)" }, // 82*256+8 = 21000
        .{ .expect = "REST 5" },
        .{ .reply = "350 Restarting at 5. Send RETR to initiate transfer" },
        .{ .expect = "RETR alphabet.txt" },
        .{ .reply = "150 Opening BINARY mode data connection" },
        .{ .data_send = payload },
        .close_data,
        .{ .reply = "226 Transfer complete" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    const io = testing.io;
    const stream = try rig.client.retr(io, &rig.cancel, &rig.diag, "alphabet.txt", 5);
    const got = try stream.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(payload, got);
    stream.close(io);
    try rig.server.check();
    try testing.expect(!rig.client.transfer_active);
}

test "RETR failure reply after EOF surfaces as ReadFailed with diag" {
    var rig: TestRig = undefined;
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 21001 },
        .{ .reply = "227 ok (127,0,0,1,82,9)" },
        .{ .expect = "RETR truncated.bin" },
        .{ .reply = "150 sending" },
        .{ .data_send = "partial" },
        .close_data,
        .{ .reply = "451 Transfer aborted: disk error" },
        // The engine still ABORs on close because the transfer failed.
        .{ .expect = "ABOR" },
        .{ .reply = "226 ABOR ok" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    const io = testing.io;
    const stream = try rig.client.retr(io, &rig.cancel, &rig.diag, "truncated.bin", 0);
    try testing.expectError(
        error.ReadFailed,
        stream.reader.allocRemaining(testing.allocator, .unlimited),
    );
    try testing.expectEqual(diag_mod.ErrorClass.transient, rig.diag.class);
    try testing.expectEqual(@as(u32, 451), rig.diag.protocol_code);
    stream.close(io);
    try rig.server.check();
}

test "RETR refused with 550 before any data" {
    var rig: TestRig = undefined;
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 21002 },
        .{ .reply = "227 ok (127,0,0,1,82,10)" },
        .{ .expect = "RETR missing.bin" },
        .{ .reply = "550 missing.bin: No such file" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    try testing.expectError(
        error.NotFound,
        rig.client.retr(testing.io, &rig.cancel, &rig.diag, "missing.bin", 0),
    );
    try testing.expectEqual(diag_mod.ErrorClass.permanent, rig.diag.class);
    try testing.expect(!rig.client.transfer_active);
    try rig.server.check();
}

test "STOR upload: payload, half-close, 226 on close" {
    var rig: TestRig = undefined;
    const payload = "uploaded \x00\x01\x02 binary-safe payload";
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 21010 },
        .{ .reply = "227 ok (127,0,0,1,82,18)" },
        .{ .expect = "STOR up.bin" },
        .{ .reply = "150 Ok to send data" },
        .{ .data_expect = payload },
        .{ .reply = "226 Transfer complete" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    const io = testing.io;
    const stream = try rig.client.stor(io, &rig.cancel, &rig.diag, "up.bin", 0, .store);
    try stream.writer.writeAll(payload);
    try stream.close(io);
    try rig.server.check();
    try testing.expect(!rig.client.transfer_active);
}

test "cancel mid-RETR: ABOR sent, 426/226 drained, data conn closed" {
    var rig: TestRig = undefined;
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 21020 },
        .{ .reply = "227 ok (127,0,0,1,82,28)" },
        .{ .expect = "RETR big.bin" },
        .{ .reply = "150 sending" },
        .{ .data_send = "0123456789" },
        .{ .expect = "ABOR" },
        .{ .reply = "426 Transfer aborted" },
        .{ .reply = "226 ABOR command successful" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    const io = testing.io;
    const stream = try rig.client.retr(io, &rig.cancel, &rig.diag, "big.bin", 0);
    var first: [10]u8 = undefined;
    try stream.reader.readSliceAll(&first);
    try testing.expectEqualStrings("0123456789", &first);

    rig.cancel.cancel();
    try testing.expectError(error.ReadFailed, stream.reader.takeByte());
    try testing.expectEqual(diag_mod.ErrorClass.cancel, rig.diag.class);

    stream.close(io); // sends ABOR with a fresh token, drains 426+226
    try rig.server.check();
    try testing.expect(std.mem.indexOf(u8, rig.server.transcript(), "C: ABOR") != null);
    try testing.expect(!rig.client.transfer_active);
}

test "PASV advertising a foreign address is rejected (bounce guard)" {
    var rig: TestRig = undefined;
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .reply = "227 Entering Passive Mode (10,9,8,7,4,1)" },
    };
    try rig.init(&script, .{ .control_peer_ip = .{ 127, 0, 0, 1 } });
    defer rig.deinit();

    try testing.expectError(
        error.ProtocolViolation,
        rig.client.retr(testing.io, &rig.cancel, &rig.diag, "x", 0),
    );
    try testing.expectEqual(diag_mod.ErrorClass.permanent, rig.diag.class);
    try testing.expect(std.mem.indexOf(u8, rig.diag.message, "10.9.8.7") != null);
    try testing.expect(std.mem.indexOf(u8, rig.diag.message, "bounce") != null);
    try rig.server.check();
}

test "PASV foreign address allowed with allow_foreign_data_ip" {
    var rig: TestRig = undefined;
    const script = [_]Step{
        .{ .expect = "PASV" },
        .{ .open_data = 1025 },
        .{ .reply = "227 Entering Passive Mode (10,9,8,7,4,1)" }, // 4*256+1 = 1025
        .{ .expect = "RETR x" },
        .{ .reply = "150 ok" },
        .{ .data_send = "y" },
        .close_data,
        .{ .reply = "226 done" },
    };
    try rig.init(&script, .{
        .control_peer_ip = .{ 127, 0, 0, 1 },
        .allow_foreign_data_ip = true,
    });
    defer rig.deinit();

    const io = testing.io;
    const stream = try rig.client.retr(io, &rig.cancel, &rig.diag, "x", 0);
    const got = try stream.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("y", got);
    stream.close(io);
    try rig.server.check();
}

test "EPSV refused at transfer time falls back to PASV" {
    var rig: TestRig = undefined;
    const script = login_steps ++ [_]Step{
        .{ .expect = "EPSV" },
        .{ .reply = "500 EPSV not understood after all" },
        .{ .expect = "PASV" },
        .{ .open_data = 20040 },
        .{ .reply = "227 ok (127,0,0,1,78,72)" }, // 78*256+72 = 20040
        .{ .expect = "RETR f" },
        .{ .reply = "150 ok" },
        .{ .data_send = "data" },
        .close_data,
        .{ .reply = "226 done" },
        // Second transfer goes straight to PASV: the cap was cleared.
        .{ .expect = "PASV" },
        .{ .open_data = 20041 },
        .{ .reply = "227 ok (127,0,0,1,78,73)" },
        .{ .expect = "RETR g" },
        .{ .reply = "150 ok" },
        .{ .data_send = "more" },
        .close_data,
        .{ .reply = "226 done" },
    };
    try rig.init(&script, .{
        .host = "test.example",
        .control_peer_ip = .{ 127, 0, 0, 1 },
    });
    defer rig.deinit();

    const io = testing.io;
    try rig.connect(test_creds);

    const s1 = try rig.client.retr(io, &rig.cancel, &rig.diag, "f", 0);
    const got1 = try s1.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got1);
    try testing.expectEqualStrings("data", got1);
    s1.close(io);
    try testing.expect(!rig.client.caps.epsv);

    const s2 = try rig.client.retr(io, &rig.cancel, &rig.diag, "g", 0);
    const got2 = try s2.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got2);
    try testing.expectEqualStrings("more", got2);
    s2.close(io);
    try rig.server.check();
}

// -------------------------------------------------------------------- //
// FTPS

/// Test double for the pinned TlsProvider contract. "Handshakes" are
/// pass-throughs over pre-registered plaintext stream pairs (the control
/// duplex, then each data connection as the recording factory dials it),
/// recording every session handle passed in so tests can assert that data
/// connections resume the control connection's session.
const FakeTls = struct {
    streams: [4]StreamState = undefined,
    stream_count: usize = 0,
    sessions_passed: [4]?*tls_provider.Session = @splat(null),
    pending: [4]Pair = undefined,
    pending_count: usize = 0,
    pending_taken: usize = 0,
    export_count: usize = 0,
    release_count: usize = 0,
    /// Unique non-null token handed out as the exported "session".
    session_token: u32 = 0,

    const Pair = struct { r: *std.Io.Reader, w: *std.Io.Writer };
    const StreamState = struct { stream: tls_provider.Stream, fake: *FakeTls };

    fn push(self: *FakeTls, r: *std.Io.Reader, w: *std.Io.Writer) void {
        self.pending[self.pending_count] = .{ .r = r, .w = w };
        self.pending_count += 1;
    }

    fn provider(self: *FakeTls) tls_provider.TlsProvider {
        return .{ .vtable = &provider_vtable, .ctx = self };
    }

    fn controlSession(self: *FakeTls) *tls_provider.Session {
        return @ptrCast(&self.session_token);
    }

    const provider_vtable: tls_provider.VTable = .{
        .handshake = handshake,
        .releaseSession = releaseSession,
        .deinit = providerDeinit,
    };

    const stream_vtable: tls_provider.StreamVTable = .{
        .exportSession = exportSession,
        .close = streamClose,
    };

    fn handshake(
        ctx: *anyopaque,
        gpa: std.mem.Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        fd: std.posix.fd_t,
        opts: tls_provider.HandshakeOptions,
    ) tls_provider.Error!*tls_provider.Stream {
        _ = gpa;
        _ = diag;
        _ = fd; // in-memory pairs have no usable fd; a real provider needs it
        try cancel.check();
        const self: *FakeTls = @ptrCast(@alignCast(ctx));
        self.sessions_passed[self.stream_count] = opts.session;
        const pair = self.pending[self.pending_taken];
        self.pending_taken += 1;
        const slot = &self.streams[self.stream_count];
        self.stream_count += 1;
        slot.* = .{
            .stream = .{
                .reader = pair.r,
                .writer = pair.w,
                .context = slot,
                .vtable = &stream_vtable,
            },
            .fake = self,
        };
        return &slot.stream;
    }

    fn exportSession(ctx: *anyopaque) ?*tls_provider.Session {
        const slot: *StreamState = @ptrCast(@alignCast(ctx));
        slot.fake.export_count += 1;
        return slot.fake.controlSession();
    }

    fn releaseSession(ctx: *anyopaque, session: *tls_provider.Session) void {
        const self: *FakeTls = @ptrCast(@alignCast(ctx));
        _ = session;
        self.release_count += 1;
    }

    fn streamClose(ctx: *anyopaque) void {
        _ = ctx;
    }

    fn providerDeinit(ctx: *anyopaque) void {
        _ = ctx;
    }
};

/// Wraps the scripted factory, registering each dialed data connection's
/// plaintext streams with the FakeTls so the next "handshake" wraps them.
const RecordingFactory = struct {
    inner: data_conn.DataConnFactory,
    fake: *FakeTls,

    fn factory(self: *RecordingFactory) data_conn.DataConnFactory {
        return .{ .context = self, .dialFn = dial };
    }

    fn dial(
        ctx: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        host: []const u8,
        port: u16,
    ) data_conn.DialError!data_conn.DataConn {
        const self: *RecordingFactory = @ptrCast(@alignCast(ctx));
        const conn = try self.inner.dial(io, cancel, diag, host, port);
        self.fake.push(conn.reader, conn.writer);
        return conn;
    }
};

test "explicit FTPS: AUTH TLS, PBSZ/PROT, data conns resume the control session" {
    const io = testing.io;
    const payload = "secret bytes over protected channel";

    var server: ScriptedServer = undefined;
    try server.init(testing.allocator, io, &([_]Step{
        .{ .reply = "220 secure server ready" },
        .{ .expect = "AUTH TLS" },
        .{ .reply = "234 Proceed with negotiation" },
        .{ .expect = "PBSZ 0" },
        .{ .reply = "200 PBSZ=0" },
        .{ .expect = "PROT P" },
        .{ .reply = "200 Protection set to Private" },
        .{ .expect = "USER alice" },
        .{ .reply = "331 Password required" },
        .{ .expect = "PASS hunter2" },
        .{ .reply = "230 Logged in" },
        .{ .expect = "FEAT" },
        .{ .reply_multiline = &.{ "211-Features:", " EPSV", "211 End" } },
        .{ .expect = "TYPE I" },
        .{ .reply = "200 ok" },
        .{ .expect = "EPSV" },
        .{ .open_data = 2121 },
        .{ .reply = "229 Entering Extended Passive Mode (|||2121|)" },
        .{ .expect = "RETR secret.bin" },
        .{ .reply = "150 Opening data connection" },
        .{ .data_send = payload },
        .close_data,
        .{ .reply = "226 Transfer complete" },
    } ++ [_]Step{
        // Second data connection must also resume the session.
        .{ .expect = "EPSV" },
        .{ .open_data = 2122 },
        .{ .reply = "229 ok (|||2122|)" },
        .{ .expect = "STOR out.bin" },
        .{ .reply = "150 send it" },
        .{ .data_expect = "tiny" },
        .{ .reply = "226 Stored" },
    }));
    defer server.deinit();

    var transcript = try transcript_mod.Transcript.init(
        testing.allocator,
        .{ .capacity = 128, .max_line_bytes = 128 },
    );
    defer transcript.deinit();

    var fake: FakeTls = .{};
    fake.push(server.clientReader(), server.clientWriter()); // control pair first
    var recording: RecordingFactory = .{ .inner = server.factory(), .fake = &fake };

    var client = FtpClient.init(
        testing.allocator,
        server.clientReader(),
        server.clientWriter(),
        recording.factory(),
        &transcript,
        .{ .host = "secure.example", .tls = fake.provider(), .tls_mode = .explicit },
    );
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try client.connect(io, &cancel, &diag, test_creds);
    try testing.expectEqual(@as(usize, 1), fake.stream_count);
    try testing.expectEqual(@as(?*tls_provider.Session, null), fake.sessions_passed[0]);
    try testing.expectEqual(@as(usize, 1), fake.export_count);

    const stream = try client.retr(io, &cancel, &diag, "secret.bin", 0);
    const got = try stream.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(payload, got);
    stream.close(io);

    const up = try client.stor(io, &cancel, &diag, "out.bin", 0, .store);
    try up.writer.writeAll("tiny");
    try up.close(io);

    try server.check();

    // The interop requirement: both data handshakes carried the control
    // connection's exported session.
    try testing.expectEqual(@as(usize, 3), fake.stream_count);
    try testing.expectEqual(@as(?*tls_provider.Session, fake.controlSession()), fake.sessions_passed[1]);
    try testing.expectEqual(@as(?*tls_provider.Session, fake.controlSession()), fake.sessions_passed[2]);

    client.deinit();
    try testing.expectEqual(@as(usize, 1), fake.release_count);
}

test "explicit FTPS with disable_session_reuse passes null sessions" {
    const io = testing.io;

    var server: ScriptedServer = undefined;
    try server.init(testing.allocator, io, &.{
        .{ .reply = "220 ready" },
        .{ .expect = "AUTH TLS" },
        .{ .reply = "234 go" },
        .{ .expect = "PBSZ 0" },
        .{ .reply = "200 ok" },
        .{ .expect = "PROT P" },
        .{ .reply = "200 ok" },
        .{ .expect = "USER alice" },
        .{ .reply = "230 ok" },
        .{ .expect = "FEAT" },
        .{ .reply = "211 bare" },
        .{ .expect = "TYPE I" },
        .{ .reply = "200 ok" },
        .{ .expect = "PASV" },
        .{ .open_data = 2200 },
        .{ .reply = "227 ok (127,0,0,1,8,152)" }, // 8*256+152 = 2200
        .{ .expect = "RETR f" },
        .{ .reply = "150 ok" },
        .{ .data_send = "z" },
        .close_data,
        .{ .reply = "226 done" },
    });
    defer server.deinit();

    var transcript = try transcript_mod.Transcript.init(
        testing.allocator,
        .{ .capacity = 64, .max_line_bytes = 128 },
    );
    defer transcript.deinit();

    var fake: FakeTls = .{};
    fake.push(server.clientReader(), server.clientWriter());
    var recording: RecordingFactory = .{ .inner = server.factory(), .fake = &fake };

    var client = FtpClient.init(
        testing.allocator,
        server.clientReader(),
        server.clientWriter(),
        recording.factory(),
        &transcript,
        .{
            .host = "secure.example",
            .tls = fake.provider(),
            .tls_mode = .explicit,
            .disable_session_reuse = true,
            .control_peer_ip = .{ 127, 0, 0, 1 },
        },
    );
    defer client.deinit();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try client.connect(io, &cancel, &diag, .{ .user = "alice" });
    const stream = try client.retr(io, &cancel, &diag, "f", 0);
    const got = try stream.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("z", got);
    stream.close(io);
    try server.check();

    try testing.expectEqual(@as(usize, 0), fake.export_count);
    try testing.expectEqual(@as(?*tls_provider.Session, null), fake.sessions_passed[0]);
    try testing.expectEqual(@as(?*tls_provider.Session, null), fake.sessions_passed[1]);
}

test "implicit FTPS handshakes before the greeting" {
    const io = testing.io;

    var server: ScriptedServer = undefined;
    try server.init(testing.allocator, io, &.{
        .{ .reply = "220 implicit-TLS server" },
        .{ .expect = "PBSZ 0" },
        .{ .reply = "200 ok" },
        .{ .expect = "PROT P" },
        .{ .reply = "200 ok" },
        .{ .expect = "USER alice" },
        .{ .reply = "230 ok" },
        .{ .expect = "FEAT" },
        .{ .reply = "211 none" },
        .{ .expect = "TYPE I" },
        .{ .reply = "200 ok" },
    });
    defer server.deinit();

    var transcript = try transcript_mod.Transcript.init(
        testing.allocator,
        .{ .capacity = 64, .max_line_bytes = 128 },
    );
    defer transcript.deinit();

    var fake: FakeTls = .{};
    fake.push(server.clientReader(), server.clientWriter());

    var client = FtpClient.init(
        testing.allocator,
        server.clientReader(),
        server.clientWriter(),
        server.factory(),
        &transcript,
        .{ .host = "secure.example", .tls = fake.provider(), .tls_mode = .implicit },
    );
    defer client.deinit();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    try client.connect(io, &cancel, &diag, .{ .user = "alice" });
    try server.check();
    // Exactly one handshake (control), no AUTH TLS on the wire.
    try testing.expectEqual(@as(usize, 1), fake.stream_count);
    try testing.expect(std.mem.indexOf(u8, server.transcript(), "AUTH TLS") == null);
}

// -------------------------------------------------------------------- //
// Allocation-failure coverage

fn connectAndListAllocs(gpa: std.mem.Allocator) !void {
    const io = testing.io;
    var server: ScriptedServer = undefined;
    // The server runs on std.testing.allocator: only client-side
    // allocations see injected failures, keeping counts deterministic.
    try server.init(testing.allocator, io, &(login_steps ++ [_]Step{
        .{ .expect = "EPSV" },
        .{ .open_data = 3300 },
        .{ .reply = "229 ok (|||3300|)" },
        .{ .expect = "MLSD" },
        .{ .reply = "150 listing" },
        .{ .data_send = "type=file;size=1; a.txt\r\ntype=dir;modify=20240910084528; sub\r\n" },
        .close_data,
        .{ .reply = "226 done" },
    }));
    defer server.deinit();

    var transcript = try transcript_mod.Transcript.init(
        testing.allocator,
        .{ .capacity = 64, .max_line_bytes = 128 },
    );
    defer transcript.deinit();

    var client = FtpClient.init(
        gpa,
        server.clientReader(),
        server.clientWriter(),
        server.factory(),
        &transcript,
        .{ .host = "test.example" },
    );
    defer client.deinit();
    var cancel: CancelToken = .{};
    var diag: Diagnostics = .{};

    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    var recorder: SinkRecorder = .{};

    client.connect(io, &cancel, &diag, test_creds) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.TestUnexpectedResult,
    };
    client.list(io, &cancel, &diag, "", arena_inst.allocator(), recorder.sink()) catch |err|
        switch (err) {
            error.OutOfMemory => return err,
            else => return error.TestUnexpectedResult,
        };
    if (recorder.name_count != 2) return error.TestUnexpectedResult;
}

test "connect + MLSD list survive all allocation failures" {
    try testing.checkAllAllocationFailures(testing.allocator, connectAndListAllocs, .{});
}

test {
    std.testing.refAllDecls(@This());
}

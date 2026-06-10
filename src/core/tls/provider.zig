//! TlsProvider — the TLS abstraction the FTP/FTPS engine composes on.
//! This file is the contract; the LibreSSL implementation lives in
//! libressl.zig. Why not std.crypto.tls: it ignores session tickets and
//! lacks client certs, and real FTPS servers REQUIRE the data connection to
//! resume the control connection's TLS session.
//!
//! Lifetime rules:
//! - One provider per site (wraps one SSL_CTX); thread-compatible, not
//!   thread-safe — each connection uses it from one worker at a time.
//! - `Session` is an opaque refcounted handle (SSL_SESSION underneath);
//!   `exportSession` after the control handshake, pass it to `handshake`
//!   for every data connection.

const std = @import("std");
const CancelToken = @import("../cancel.zig").CancelToken;
const Diagnostics = @import("../diag.zig").Diagnostics;

pub const Error = error{
    Canceled,
    HandshakeFailed,
    CertificateUntrusted,
    HostnameMismatch,
    ConnectionLost,
    ProtocolViolation,
    OutOfMemory,
    Unexpected,
};

pub const Version = enum { tls12, tls13 };

pub const HandshakeOptions = struct {
    /// Server name for SNI + hostname verification.
    host: []const u8,
    /// Resume this session (FTPS data connections MUST pass the control
    /// connection's exported session here).
    session: ?*Session = null,
    /// Skip chain/hostname verification (per-site escape hatch; the UI
    /// makes this loud).
    insecure_skip_verify: bool = false,
    min_version: Version = .tls12,
    /// FTPS defaults to tls12 max: LibreSSL lacks TLS 1.3 session
    /// resumption and 1.3 tickets arrive post-handshake (curl #4654).
    max_version: Version = .tls12,
};

/// Opaque refcounted session handle (SSL_SESSION underneath).
pub const Session = opaque {};

/// An established TLS stream over a connected socket fd. Exposes concrete
/// `std.Io.Reader`/`std.Io.Writer` interfaces so the FTP engine cannot tell
/// TLS from plaintext from an in-memory test stream.
pub const Stream = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    context: *anyopaque,
    vtable: *const StreamVTable,

    pub fn exportSession(self: *Stream) ?*Session {
        return self.vtable.exportSession(self.context);
    }
    /// Sends close_notify best-effort, frees the SSL object. Does not close
    /// the underlying fd (the connection owns it).
    pub fn close(self: *Stream) void {
        self.vtable.close(self.context);
    }
};

pub const StreamVTable = struct {
    exportSession: *const fn (ctx: *anyopaque) ?*Session,
    close: *const fn (ctx: *anyopaque) void,
};

pub const VTable = struct {
    /// Client handshake over an already-connected socket. The fd must be in
    /// non-blocking mode on return regardless of entry state; the
    /// implementation polls internally with ≤100 ms wakeups, checking
    /// `cancel` on each.
    handshake: *const fn (
        ctx: *anyopaque,
        gpa: std.mem.Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        fd: std.posix.fd_t,
        opts: HandshakeOptions,
    ) Error!*Stream,
    releaseSession: *const fn (ctx: *anyopaque, session: *Session) void,
    deinit: *const fn (ctx: *anyopaque) void,
};

pub const TlsProvider = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub fn handshake(
        self: TlsProvider,
        gpa: std.mem.Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        fd: std.posix.fd_t,
        opts: HandshakeOptions,
    ) Error!*Stream {
        return self.vtable.handshake(self.ctx, gpa, cancel, diag, fd, opts);
    }
    pub fn releaseSession(self: TlsProvider, session: *Session) void {
        self.vtable.releaseSession(self.ctx, session);
    }
    pub fn deinit(self: TlsProvider) void {
        self.vtable.deinit(self.ctx);
    }
};

test {
    std.testing.refAllDecls(@This());
}

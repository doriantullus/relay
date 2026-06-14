//! session — one SSH connection: libssh2 handshake, host-key verification
//! hook, and the userauth chain (agent → explicit key → default ~/.ssh keys
//! → password → keyboard-interactive), all driven non-blocking through
//! poll.zig so cancellation resolves within ~100 ms.
//!
//! The engine is generic over a thin libssh2 boundary (`Engine(Lib)`); the
//! production `LibSsh2` routes every call through `poll.pump`, while the
//! unit tests inject a stub Lib to exercise chain ordering and error
//! classification without a server. `SshSession` is the production alias.
//!
//! Host key policy lives ABOVE this layer (known_hosts + UI prompt wired in
//! by the VFS backend); the engine only computes the fingerprint and relays
//! the callback's decision.

const std = @import("std");
const poll = @import("poll.zig");
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const CancelToken = @import("../../cancel.zig").CancelToken;
const agent_mod = @import("../ssh/agent.zig");
const keys = @import("../ssh/keys.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    Canceled,
    ConnectionLost,
    Timeout,
    ProtocolViolation,
    /// Host key actively rejected (known_hosts mismatch — MITM signal).
    HostKeyRejected,
    /// First contact: the verification hook could not vouch for the key.
    HostKeyUnknown,
    /// Every available auth method failed; see the auth trail.
    AuthFailed,
    OutOfMemory,
    Unexpected,
};

pub const HostKeyDecision = enum { accept, reject, unknown };

pub const HostKeyInfo = struct {
    host: []const u8,
    port: u16,
    /// Algorithm name from the key blob, e.g. "ssh-ed25519".
    key_type: []const u8,
    /// SSH wire-format public key blob (keys.zig/known_hosts.zig currency).
    key_blob: []const u8,
    /// OpenSSH-style "SHA256:..." fingerprint.
    sha256_fp: [keys.fingerprint_len]u8,
};

/// One keyboard-interactive sub-prompt (mirrors events.KiPrompt).
pub const KiPrompt = struct {
    text: []const u8,
    /// False means the answer must be masked (password-like secret).
    echo: bool,
};

pub const Callbacks = struct {
    context: *anyopaque,
    /// Called once after the handshake with the server's host key. The
    /// engine maps reject -> error.HostKeyRejected (.permanent) and
    /// unknown -> error.HostKeyUnknown (.auth, drives the trust prompt).
    verifyHostKey: *const fn (context: *anyopaque, info: *const HostKeyInfo) HostKeyDecision,
    /// keyboard-interactive prompt relay. Answer slices are allocated from
    /// `arena` (valid until the callback returns to the engine); return
    /// null when the user dismissed the prompt. Engine skips the method
    /// entirely when this is null.
    promptUser: ?*const fn (
        context: *anyopaque,
        arena: Allocator,
        name: []const u8,
        instruction: []const u8,
        prompts: []const KiPrompt,
    ) ?[]const []const u8 = null,
};

pub const ExplicitKey = struct {
    /// Verbatim key file bytes (openssh-key-v1 or PEM armor). Validated /
    /// decrypted via keys.zig first for precise diagnostics, then the
    /// original text is handed to libssh2_userauth_publickey_frommemory,
    /// which parses both formats itself.
    file_bytes: []const u8,
    passphrase: ?[]const u8 = null,
    /// Shown in the auth trail (typically the file path).
    label: []const u8 = "explicit key",
};

pub const AuthOptions = struct {
    username: []const u8,
    /// (1) ssh-agent. Socket path defaults to $SSH_AUTH_SOCK; the method
    /// is skipped silently when neither yields a reachable agent.
    try_agent: bool = true,
    agent_socket_path: ?[]const u8 = null,
    /// (2) explicit private key.
    key: ?ExplicitKey = null,
    /// (3) default keys: absolute path of the .ssh directory to probe for
    /// id_ed25519 / id_ecdsa / id_rsa. null skips the method.
    ssh_dir: ?[]const u8 = null,
    /// (4) password (also reused for default-key passphrases? no — default
    /// keys are tried without a passphrase; encrypted ones are recorded in
    /// the trail and skipped).
    password: ?[]const u8 = null,
    // (5) keyboard-interactive runs when callbacks.promptUser is set.
};

pub const default_key_names = [_][]const u8{ "id_ed25519", "id_ecdsa", "id_rsa" };

pub const max_username_len = 255;

// ---------------------------------------------------------------------------
// Auth trail: per-method failure log surfaced to the UI next to the final
// Diagnostics. Fixed storage — recording can never fail or allocate.
// ---------------------------------------------------------------------------

pub const AuthMethod = enum {
    agent_key,
    explicit_key,
    default_key,
    password,
    keyboard_interactive,

    pub fn label(m: AuthMethod) []const u8 {
        return switch (m) {
            .agent_key => "ssh-agent key",
            .explicit_key => "explicit key",
            .default_key => "default key",
            .password => "password",
            .keyboard_interactive => "keyboard-interactive",
        };
    }
};

pub const attempt_detail_len = 96;

pub const Attempt = struct {
    method: AuthMethod,
    class: diag_mod.ErrorClass,
    /// libssh2 rc (negative) or 0 when the failure was local.
    rc: i32,
    detail_buf: [attempt_detail_len]u8,
    detail_len: u8,

    pub fn detail(a: *const Attempt) []const u8 {
        return a.detail_buf[0..a.detail_len];
    }
};

pub const max_trail_entries = 16;

pub const Trail = struct {
    entries: [max_trail_entries]Attempt = undefined,
    len: usize = 0,
    /// Attempts that no longer fit (e.g. an agent with dozens of keys).
    dropped: usize = 0,

    pub fn add(
        tr: *Trail,
        method: AuthMethod,
        class: diag_mod.ErrorClass,
        rc: i32,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (tr.len == tr.entries.len) {
            tr.dropped += 1;
            return;
        }
        const a = &tr.entries[tr.len];
        a.method = method;
        a.class = class;
        a.rc = rc;
        var w: std.Io.Writer = .fixed(&a.detail_buf);
        w.print(fmt, args) catch {}; // truncation keeps the prefix
        a.detail_len = @intCast(w.buffered().len);
        tr.len += 1;
    }

    pub fn slice(tr: *const Trail) []const Attempt {
        return tr.entries[0..tr.len];
    }

    fn last(tr: *const Trail) ?*const Attempt {
        return if (tr.len == 0) null else &tr.entries[tr.len - 1];
    }
};

// ---------------------------------------------------------------------------
// libssh2 rc classification (pure; unit-tested)
// ---------------------------------------------------------------------------

/// Relevant LIBSSH2_ERROR_* values (mirrored so classification and its
/// tests don't depend on translate-c; asserted against the header below).
pub const lib_rc = struct {
    pub const socket_send: i32 = -7;
    pub const timeout: i32 = -9;
    pub const socket_disconnect: i32 = -13;
    pub const proto: i32 = -14;
    pub const password_expired: i32 = -15;
    pub const authentication_failed: i32 = -18;
    pub const publickey_unverified: i32 = -19;
    pub const socket_timeout: i32 = -30;
    pub const eagain: i32 = -37;
    pub const bad_socket: i32 = -45;
    pub const keyfile_auth_failed: i32 = -48;
    pub const alloc: i32 = -6;
    pub const socket_recv: i32 = -43;
    pub const kex_failure: i32 = -5;
    pub const key_exchange_failure: i32 = -8;
};

pub const RcClass = struct {
    class: diag_mod.ErrorClass,
    /// Set when the failure poisons the whole connection or chain; the
    /// auth loop aborts instead of trying the next method.
    fatal: ?Error,
};

/// Classifies a non-zero libssh2 rc for the auth chain: credential-shaped
/// failures continue to the next method (.auth), transport failures abort
/// (transient → reconnect+retry policy), local/method failures continue.
pub fn classifyLibRc(rc: i32) RcClass {
    return switch (rc) {
        lib_rc.authentication_failed,
        lib_rc.publickey_unverified,
        lib_rc.keyfile_auth_failed,
        lib_rc.password_expired,
        => .{ .class = .auth, .fatal = null },
        lib_rc.socket_send,
        lib_rc.socket_recv,
        lib_rc.socket_disconnect,
        lib_rc.bad_socket,
        => .{ .class = .transient, .fatal = error.ConnectionLost },
        lib_rc.timeout,
        lib_rc.socket_timeout,
        => .{ .class = .transient, .fatal = error.Timeout },
        lib_rc.kex_failure,
        lib_rc.key_exchange_failure,
        lib_rc.proto,
        => .{ .class = .permanent, .fatal = error.ProtocolViolation },
        lib_rc.alloc => .{ .class = .permanent, .fatal = error.OutOfMemory },
        else => .{ .class = .permanent, .fatal = null },
    };
}

// ---------------------------------------------------------------------------
// The engine, generic over the libssh2 boundary
// ---------------------------------------------------------------------------

/// `Lib` provides the libssh2 surface (see `LibSsh2` for the contract and
/// the production implementation). Everything above it — chain ordering,
/// host-key relay, trail, error classification — is shared and unit-tested
/// against a stub.
pub fn Engine(comptime Lib: type) type {
    return struct {
        pub const Session = struct {
            gpa: Allocator,
            io: std.Io,
            fd: std.posix.fd_t,
            handle: Lib.Handle,
            callbacks: Callbacks,
            port: u16,
            host_len: u8,
            host_buf: [255]u8,
            trail: Trail = .{},

            pub fn host(s: *const Session) []const u8 {
                return s.host_buf[0..s.host_len];
            }

            /// Performs the SSH handshake on an already-connected socket
            /// and relays host-key verification. The fd stays owned by the
            /// caller (close it after deinit).
            pub fn init(
                gpa: Allocator,
                io: std.Io,
                fd: std.posix.fd_t,
                host_name: []const u8,
                port: u16,
                cancel: *CancelToken,
                diag: *Diagnostics,
                callbacks: Callbacks,
            ) Error!Session {
                // libssh2's non-blocking session mode still issues blocking
                // recv()/send() when the fd itself is blocking (std.Io.Threaded
                // creates blocking sockets) — sftp_init deadlocks on a live
                // server without this, and cancellation latency dies with it.
                Lib.setNonBlocking(fd) catch {
                    diag.set(.permanent, 0, "could not set O_NONBLOCK on the session socket", .{});
                    return error.Unexpected;
                };

                const handle = Lib.sessionInit() orelse {
                    diag.set(.permanent, 0, "libssh2 session allocation failed", .{});
                    return error.Unexpected;
                };
                errdefer Lib.sessionFree(handle);

                var s: Session = .{
                    .gpa = gpa,
                    .io = io,
                    .fd = fd,
                    .handle = handle,
                    .callbacks = callbacks,
                    .port = port,
                    .host_len = @intCast(@min(host_name.len, 255)),
                    .host_buf = undefined,
                };
                @memcpy(s.host_buf[0..s.host_len], host_name[0..s.host_len]);

                const rc = Lib.handshake(handle, fd, cancel) catch |err|
                    return transportError(err, diag, "SSH handshake");
                if (rc != 0) {
                    var msg_buf: [256]u8 = undefined;
                    const cls = classifyLibRc(rc);
                    diag.set(cls.class, 0, "SSH handshake failed (rc {d}): {s}", .{
                        rc, Lib.lastErrorMessage(handle, &msg_buf),
                    });
                    return cls.fatal orelse error.ProtocolViolation;
                }

                const blob = Lib.hostKeyBlob(handle) orelse {
                    diag.set(.permanent, 0, "server presented no host key", .{});
                    return error.ProtocolViolation;
                };
                const info: HostKeyInfo = .{
                    .host = s.host(),
                    .port = port,
                    .key_type = keys.blobTypeName(blob) orelse "unknown",
                    .key_blob = blob,
                    .sha256_fp = keys.fingerprintSha256(blob),
                };
                switch (callbacks.verifyHostKey(callbacks.context, &info)) {
                    .accept => {},
                    .reject => {
                        diag.set(.permanent, 0, "host key for {s}:{d} rejected ({s} {s})", .{
                            info.host, port, info.key_type, info.sha256_fp,
                        });
                        return error.HostKeyRejected;
                    },
                    .unknown => {
                        diag.set(.auth, 0, "unknown host key for {s}:{d} ({s} {s})", .{
                            info.host, port, info.key_type, info.sha256_fp,
                        });
                        return error.HostKeyUnknown;
                    },
                }
                return s;
            }

            /// Runs the auth chain, stopping at the first success. On
            /// AuthFailed the per-method trail (`s.trail`) explains every
            /// attempt; `diag` summarizes the last one.
            pub fn authenticate(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                opts: AuthOptions,
            ) Error!void {
                s.trail = .{};
                try checkCancel(cancel, diag);

                if (opts.username.len > max_username_len) {
                    diag.set(.permanent, 0, "username too long ({d} bytes)", .{opts.username.len});
                    return error.Unexpected;
                }
                var user_buf: [max_username_len:0]u8 = undefined;
                @memcpy(user_buf[0..opts.username.len], opts.username);
                user_buf[opts.username.len] = 0;
                const user: [:0]const u8 = user_buf[0..opts.username.len :0];

                var list_buf: [512]u8 = undefined;
                const methods = Lib.userauthList(s.handle, s.fd, cancel, user, &list_buf) catch |err|
                    return transportError(err, diag, "userauth negotiation");
                if (methods == null and Lib.isAuthenticated(s.handle)) return; // "none" auth
                const allow = MethodMask.parse(methods);

                if (allow.publickey) {
                    if (opts.try_agent)
                        if (try s.tryAgent(cancel, diag, opts.agent_socket_path, user)) return;
                    if (opts.key) |k|
                        if (try s.tryKeyBytes(cancel, diag, user, .explicit_key, k.label, k.file_bytes, k.passphrase)) return;
                    if (opts.ssh_dir) |dir|
                        if (try s.tryDefaultKeys(cancel, diag, user, dir)) return;
                }
                if (allow.password) {
                    if (opts.password) |pw|
                        if (try s.tryPassword(cancel, diag, user, pw)) return;
                }
                if (allow.keyboard_interactive) {
                    if (s.callbacks.promptUser != null)
                        if (try s.tryKbdInt(cancel, diag, user)) return;
                }

                if (s.trail.last()) |a| {
                    diag.set(.auth, 0, "authentication failed for {s} ({d} attempts; last: {s}: {s})", .{
                        opts.username, s.trail.len + s.trail.dropped, a.method.label(), a.detail(),
                    });
                } else {
                    diag.set(.auth, 0, "no usable authentication method for {s} (server offers: {s})", .{
                        opts.username, methods orelse "unknown",
                    });
                }
                return error.AuthFailed;
            }

            fn tryAgent(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                socket_path: ?[]const u8,
                user: [:0]const u8,
            ) Error!bool {
                const conn = Lib.agentOpen(s.gpa, s.io, socket_path, cancel) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Canceled => return canceled(diag),
                } orelse return false; // no agent: skip silently, not a failure
                defer Lib.agentClose(s.gpa, conn);

                for (Lib.agentIdentities(conn)) |*id| {
                    try checkCancel(cancel, diag);
                    const rc = Lib.agentAuth(s.handle, s.fd, s.gpa, cancel, conn, user, id) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => |e| return transportError(e, diag, "agent auth"),
                    };
                    if (rc == 0) return true;
                    try s.recordRc(diag, .agent_key, rc, "agent key {s}", .{id.comment});
                }
                return false;
            }

            /// Shared by explicit and default keys: validate/decrypt via
            /// keys.zig first (precise local diagnostics, no wire round
            /// trip for unreadable keys), then hand the original file
            /// bytes to libssh2.
            fn tryKeyBytes(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                user: [:0]const u8,
                method: AuthMethod,
                label: []const u8,
                file_bytes: []const u8,
                passphrase: ?[]const u8,
            ) Error!bool {
                try checkCancel(cancel, diag);
                {
                    var parse_diag: Diagnostics = .{};
                    var pk = keys.parsePrivateKey(s.gpa, file_bytes, passphrase, &parse_diag) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {
                            s.trail.add(method, parse_diag.class, 0, "{s}: {s}", .{ label, parse_diag.message });
                            return false;
                        },
                    };
                    pk.deinit(); // validation only; libssh2 re-parses the file bytes
                }
                const rc = Lib.keyAuth(s.handle, s.fd, s.gpa, cancel, user, file_bytes, passphrase, label) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| return transportError(e, diag, "publickey auth"),
                };
                if (rc == 0) return true;
                try s.recordRc(diag, method, rc, "{s}", .{label});
                return false;
            }

            fn tryDefaultKeys(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                user: [:0]const u8,
                ssh_dir: []const u8,
            ) Error!bool {
                for (default_key_names) |name| {
                    try checkCancel(cancel, diag);
                    var path_buf: [1024]u8 = undefined;
                    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ ssh_dir, name }) catch continue;
                    const bytes = (try Lib.readKeyFile(s.gpa, s.io, path)) orelse continue;
                    defer {
                        std.crypto.secureZero(u8, bytes);
                        s.gpa.free(bytes);
                    }
                    if (try s.tryKeyBytes(cancel, diag, user, .default_key, name, bytes, null)) return true;
                }
                return false;
            }

            fn tryPassword(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                user: [:0]const u8,
                password: []const u8,
            ) Error!bool {
                const rc = Lib.passwordAuth(s.handle, s.fd, cancel, user, password) catch |err|
                    return transportError(err, diag, "password auth");
                if (rc == 0) return true;
                try s.recordRc(diag, .password, rc, "password", .{});
                return false;
            }

            fn tryKbdInt(
                s: *Session,
                cancel: *CancelToken,
                diag: *Diagnostics,
                user: [:0]const u8,
            ) Error!bool {
                const rc = Lib.kbdintAuth(s.handle, s.fd, s.gpa, cancel, user, &s.callbacks) catch |err| switch (err) {
                    // User dismissed the prompt: terminal and silent.
                    error.Canceled => return canceled(diag),
                    else => |e| return transportError(e, diag, "keyboard-interactive auth"),
                };
                if (rc == 0) return true;
                try s.recordRc(diag, .keyboard_interactive, rc, "keyboard-interactive", .{});
                return false;
            }

            /// Records a failed attempt; aborts the chain (and fills diag)
            /// when the rc poisons the connection.
            fn recordRc(
                s: *Session,
                diag: *Diagnostics,
                method: AuthMethod,
                rc: c_int,
                comptime fmt: []const u8,
                args: anytype,
            ) Error!void {
                var msg_buf: [256]u8 = undefined;
                const msg = Lib.lastErrorMessage(s.handle, &msg_buf);
                const cls = classifyLibRc(rc);
                s.trail.add(method, cls.class, rc, fmt ++ ": {s} (rc {d})", args ++ .{ msg, rc });
                if (cls.fatal) |err| {
                    diag.set(cls.class, 0, "{s} failed fatally: {s} (rc {d})", .{ method.label(), msg, rc });
                    return err;
                }
            }

            /// Configures transport keepalive (want_reply makes the server
            /// answer, proving liveness). interval 0 disables.
            pub fn keepalive(s: *Session, interval_s: u32) void {
                Lib.keepaliveConfig(s.handle, true, interval_s);
            }

            /// Sends a keepalive if one is due; returns seconds until the
            /// next one should be sent.
            pub fn keepaliveSend(s: *Session, cancel: *CancelToken, diag: *Diagnostics) Error!u32 {
                return Lib.keepaliveSend(s.handle, s.fd, cancel) catch |err|
                    transportError(err, diag, "keepalive");
            }

            /// Best-effort disconnect + free; never blocks longer than ~1s
            /// (bounded polls inside Lib.disconnect).
            pub fn deinit(s: *Session) void {
                Lib.disconnect(s.handle, s.fd);
                s.* = undefined;
            }
        };

        fn transportError(err: poll.Error, diag: *Diagnostics, what: []const u8) Error {
            switch (err) {
                error.Canceled => return canceled(diag),
                error.ConnectionLost => {
                    diag.set(.transient, 0, "{s}: connection lost", .{what});
                    return error.ConnectionLost;
                },
            }
        }

        fn canceled(diag: *Diagnostics) Error {
            diag.set(.cancel, 0, "canceled", .{});
            return error.Canceled;
        }

        fn checkCancel(cancel: *const CancelToken, diag: *Diagnostics) Error!void {
            cancel.check() catch return canceled(diag);
        }
    };
}

const MethodMask = struct {
    publickey: bool,
    password: bool,
    keyboard_interactive: bool,

    /// null (no list from the server) defensively allows everything.
    fn parse(list: ?[]const u8) MethodMask {
        const text = list orelse return .{
            .publickey = true,
            .password = true,
            .keyboard_interactive = true,
        };
        return .{
            .publickey = hasMethod(text, "publickey"),
            .password = hasMethod(text, "password"),
            .keyboard_interactive = hasMethod(text, "keyboard-interactive"),
        };
    }

    fn hasMethod(list: []const u8, name: []const u8) bool {
        var it = std.mem.splitScalar(u8, list, ',');
        while (it.next()) |m| {
            if (std.mem.eql(u8, std.mem.trim(u8, m, " "), name)) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Production libssh2 boundary
// ---------------------------------------------------------------------------

const c = @import("c");

pub const LibSsh2 = struct {
    pub const Handle = *c.LIBSSH2_SESSION;

    /// Open agent connection + its identity list. Heap-allocated because
    /// agent_mod.Connection pins interior stream buffers.
    pub const AgentConn = struct {
        conn: agent_mod.Connection,
        list: agent_mod.IdentityList,
    };

    /// Both halves of the non-blocking contract: the fd must be O_NONBLOCK
    /// (this fn) AND the session in non-blocking mode (sessionInit), or
    /// libssh2 blocks inside the kernel and poll.zig never gets to run.
    pub fn setNonBlocking(fd: std.posix.fd_t) error{Unexpected}!void {
        const flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
        if (flags < 0) return error.Unexpected;
        const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.Unexpected;
    }

    pub fn sessionInit() ?Handle {
        const h = c.libssh2_session_init_ex(null, null, null, null) orelse return null;
        c.libssh2_session_set_blocking(h, 0);
        return h;
    }

    pub fn sessionFree(h: Handle) void {
        _ = c.libssh2_session_free(h);
    }

    pub fn handshake(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken) poll.Error!c_int {
        const Op = struct {
            h: Handle,
            fd: std.posix.fd_t,

            pub fn call(op: @This()) c_int {
                return c.libssh2_session_handshake(op.h, op.fd);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        return poll.pump(fd, cancel, Op{ .h = h, .fd = fd });
    }

    pub fn hostKeyBlob(h: Handle) ?[]const u8 {
        var len: usize = 0;
        var key_type: c_int = 0;
        const ptr = c.libssh2_session_hostkey(h, &len, &key_type) orelse return null;
        if (len == 0) return null;
        return ptr[0..len];
    }

    pub fn lastErrorMessage(h: Handle, buf: []u8) []const u8 {
        var msg: [*c]u8 = null;
        var msg_len: c_int = 0;
        _ = c.libssh2_session_last_error(h, &msg, &msg_len, 0);
        if (msg == null or msg_len <= 0) return "";
        const text = msg[0..@intCast(msg_len)];
        const n = @min(text.len, buf.len);
        @memcpy(buf[0..n], text[0..n]);
        return buf[0..n];
    }

    pub fn isAuthenticated(h: Handle) bool {
        return c.libssh2_userauth_authenticated(h) != 0;
    }

    pub fn userauthList(
        h: Handle,
        fd: std.posix.fd_t,
        cancel: *CancelToken,
        user: [:0]const u8,
        buf: []u8,
    ) poll.Error!?[]const u8 {
        const Op = struct {
            h: Handle,
            user: [:0]const u8,

            pub fn call(op: @This()) ?[*:0]u8 {
                return c.libssh2_userauth_list(op.h, op.user.ptr, @intCast(op.user.len));
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
            pub fn lastErrno(op: @This()) c_int {
                return c.libssh2_session_last_errno(op.h);
            }
        };
        const ptr = try poll.pumpHandle(fd, cancel, Op{ .h = h, .user = user }) orelse return null;
        const list = std.mem.span(ptr);
        const n = @min(list.len, buf.len);
        @memcpy(buf[0..n], list[0..n]);
        return buf[0..n];
    }

    pub fn agentOpen(
        gpa: Allocator,
        io: std.Io,
        socket_path: ?[]const u8,
        cancel: *CancelToken,
    ) error{ OutOfMemory, Canceled }!?*AgentConn {
        const path = socket_path orelse blk: {
            const env = std.c.getenv("SSH_AUTH_SOCK") orelse return null;
            break :blk std.mem.span(env);
        };
        if (path.len == 0) return null;

        const ac = try gpa.create(AgentConn);
        errdefer gpa.destroy(ac);
        ac.conn.connect(io, path) catch return null;
        errdefer ac.conn.close();

        var list_diag: Diagnostics = .{};
        ac.list = ac.conn.client().listIdentities(gpa, cancel, &list_diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => {
                ac.conn.close();
                gpa.destroy(ac);
                return null;
            },
        };
        return ac;
    }

    pub fn agentIdentities(ac: *AgentConn) []const agent_mod.Identity {
        return ac.list.identities;
    }

    pub fn agentClose(gpa: Allocator, ac: *AgentConn) void {
        ac.list.deinit();
        ac.conn.close();
        gpa.destroy(ac);
    }

    /// State shared with the C sign callback through libssh2's abstract
    /// pointer (passed per-call to libssh2_userauth_publickey).
    const SignCtx = struct {
        gpa: Allocator,
        client: agent_mod.Client,
        key_blob: []const u8,
        cancel: *CancelToken,
        canceled: bool = false,
    };

    pub fn agentAuth(
        h: Handle,
        fd: std.posix.fd_t,
        gpa: Allocator,
        cancel: *CancelToken,
        ac: *AgentConn,
        user: [:0]const u8,
        id: *const agent_mod.Identity,
    ) (poll.Error || error{OutOfMemory})!c_int {
        var ctx: SignCtx = .{
            .gpa = gpa,
            .client = ac.conn.client(),
            .key_blob = id.key_blob,
            .cancel = cancel,
        };
        var abstract: ?*anyopaque = &ctx;
        const Op = struct {
            h: Handle,
            user: [:0]const u8,
            blob: []const u8,
            abstract: *?*anyopaque,

            pub fn call(op: @This()) c_int {
                return c.libssh2_userauth_publickey(
                    op.h,
                    op.user.ptr,
                    op.blob.ptr,
                    op.blob.len,
                    agentSignCallback,
                    @ptrCast(op.abstract),
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        const rc = try poll.pump(fd, cancel, Op{
            .h = h,
            .user = user,
            .blob = id.key_blob,
            .abstract = &abstract,
        });
        if (ctx.canceled) return error.Canceled;
        return rc;
    }

    /// LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC: must return the RAW signature
    /// bytes — libssh2 wraps them in `string method ++ string sig` itself
    /// (src/userauth.c sent1 state) — allocated with the session allocator
    /// (default = malloc; libssh2 frees with free()).
    fn agentSignCallback(
        session: ?*c.LIBSSH2_SESSION,
        sig: [*c][*c]u8,
        sig_len: [*c]usize,
        data: [*c]const u8,
        data_len: usize,
        abstract: [*c]?*anyopaque,
    ) callconv(.c) c_int {
        _ = session;
        const ctx: *SignCtx = @ptrCast(@alignCast(abstract.*.?));
        const signed_data = data[0..data_len];
        var sign_diag: Diagnostics = .{};
        const blob = ctx.client.sign(
            ctx.gpa,
            ctx.key_blob,
            signed_data,
            signFlagsForData(signed_data),
            ctx.cancel,
            &sign_diag,
        ) catch |err| {
            if (err == error.Canceled) ctx.canceled = true;
            return -1;
        };
        defer ctx.gpa.free(blob);
        const raw = rawSignature(blob) orelse return -1;
        const out: [*]u8 = @ptrCast(std.c.malloc(raw.len) orelse return -1);
        @memcpy(out[0..raw.len], raw);
        sig.* = out;
        sig_len.* = raw.len;
        return 0;
    }

    pub fn keyAuth(
        h: Handle,
        fd: std.posix.fd_t,
        gpa: Allocator,
        cancel: *CancelToken,
        user: [:0]const u8,
        file_bytes: []const u8,
        passphrase: ?[]const u8,
        label: []const u8,
    ) (poll.Error || error{OutOfMemory})!c_int {
        _ = label;
        // libssh2 wants a NUL-terminated passphrase; copy + zero after.
        const ppz: ?[:0]u8 = if (passphrase) |p| try gpa.dupeZ(u8, p) else null;
        defer if (ppz) |p| {
            std.crypto.secureZero(u8, p);
            gpa.free(p);
        };
        const Op = struct {
            h: Handle,
            user: [:0]const u8,
            pem: []const u8,
            pp: ?[*:0]const u8,

            pub fn call(op: @This()) c_int {
                // null public key: libssh2 derives it from the private key.
                return c.libssh2_userauth_publickey_frommemory(
                    op.h,
                    op.user.ptr,
                    op.user.len,
                    null,
                    0,
                    op.pem.ptr,
                    op.pem.len,
                    op.pp orelse null,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        return poll.pump(fd, cancel, Op{
            .h = h,
            .user = user,
            .pem = file_bytes,
            .pp = if (ppz) |p| p.ptr else null,
        });
    }

    /// Missing/unreadable files are a silent skip (null); only OOM is an
    /// error so the auth chain stays allocation-failure-correct.
    pub fn readKeyFile(gpa: Allocator, io: std.Io, path: []const u8) error{OutOfMemory}!?[]u8 {
        return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }

    pub fn passwordAuth(
        h: Handle,
        fd: std.posix.fd_t,
        cancel: *CancelToken,
        user: [:0]const u8,
        password: []const u8,
    ) poll.Error!c_int {
        const Op = struct {
            h: Handle,
            user: [:0]const u8,
            password: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_userauth_password_ex(
                    op.h,
                    op.user.ptr,
                    @intCast(op.user.len),
                    op.password.ptr,
                    @intCast(op.password.len),
                    null,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        return poll.pump(fd, cancel, Op{ .h = h, .user = user, .password = password });
    }

    /// State shared with the keyboard-interactive C callback through the
    /// session abstract slot (libssh2 offers no per-call abstract here).
    const KbdCtx = struct {
        gpa: Allocator,
        callbacks: *const Callbacks,
        canceled: bool = false,
        failed: bool = false,
    };

    pub fn kbdintAuth(
        h: Handle,
        fd: std.posix.fd_t,
        gpa: Allocator,
        cancel: *CancelToken,
        user: [:0]const u8,
        callbacks: *const Callbacks,
    ) poll.Error!c_int {
        var ctx: KbdCtx = .{ .gpa = gpa, .callbacks = callbacks };
        const slot = c.libssh2_session_abstract(h);
        slot.* = &ctx;
        defer slot.* = null;

        const Op = struct {
            h: Handle,
            user: [:0]const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_userauth_keyboard_interactive_ex(
                    op.h,
                    op.user.ptr,
                    @intCast(op.user.len),
                    kbdintCallback,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        const rc = try poll.pump(fd, cancel, Op{ .h = h, .user = user });
        if (ctx.canceled) return error.Canceled;
        return rc;
    }

    fn kbdintCallback(
        name: [*c]const u8,
        name_len: c_int,
        instruction: [*c]const u8,
        instruction_len: c_int,
        num_prompts: c_int,
        prompts: [*c]const c.LIBSSH2_USERAUTH_KBDINT_PROMPT,
        responses: [*c]c.LIBSSH2_USERAUTH_KBDINT_RESPONSE,
        abstract: [*c]?*anyopaque,
    ) callconv(.c) void {
        const ctx: *KbdCtx = @ptrCast(@alignCast(abstract.*.?));
        var arena: std.heap.ArenaAllocator = .init(ctx.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        const n: usize = @intCast(@max(num_prompts, 0));
        const ki = a.alloc(KiPrompt, n) catch {
            ctx.failed = true;
            return;
        };
        for (ki, 0..) |*p, i| {
            p.* = .{
                .text = if (prompts[i].text) |txt| txt[0..prompts[i].length] else "",
                .echo = prompts[i].echo != 0,
            };
        }
        const answers = ctx.callbacks.promptUser.?(
            ctx.callbacks.context,
            a,
            if (name) |p| p[0..@intCast(@max(name_len, 0))] else "",
            if (instruction) |p| p[0..@intCast(@max(instruction_len, 0))] else "",
            ki,
        ) orelse {
            // Dismissed: leave responses empty; the engine reports Canceled.
            ctx.canceled = true;
            return;
        };
        if (answers.len != n) {
            ctx.failed = true;
            return;
        }
        for (answers, 0..) |answer, i| {
            // libssh2 frees response text with the session allocator
            // (default free()), so it must come from malloc.
            const out: ?[*]u8 = @ptrCast(std.c.malloc(answer.len +| 1));
            const p = out orelse {
                ctx.failed = true;
                return;
            };
            @memcpy(p[0..answer.len], answer);
            responses[i].text = @ptrCast(p);
            responses[i].length = @intCast(answer.len);
        }
    }

    pub fn keepaliveConfig(h: Handle, want_reply: bool, interval_s: u32) void {
        c.libssh2_keepalive_config(h, @intFromBool(want_reply), @intCast(interval_s));
    }

    pub fn keepaliveSend(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken) poll.Error!u32 {
        var next: c_int = 0;
        const Op = struct {
            h: Handle,
            next: *c_int,

            pub fn call(op: @This()) c_int {
                return c.libssh2_keepalive_send(op.h, op.next);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        _ = try poll.pump(fd, cancel, Op{ .h = h, .next = &next });
        return @intCast(@max(next, 0));
    }

    /// Opens a direct-tcpip channel (the ProxyJump forward). null = the
    /// server refused; read last_errno for the reason.
    pub fn channelDirectTcpip(
        h: Handle,
        fd: std.posix.fd_t,
        cancel: *CancelToken,
        host: [:0]const u8,
        port: u16,
    ) poll.Error!?*c.LIBSSH2_CHANNEL {
        const Op = struct {
            h: Handle,
            host: [:0]const u8,
            port: u16,

            pub fn call(op: @This()) ?*c.LIBSSH2_CHANNEL {
                return c.libssh2_channel_direct_tcpip_ex(
                    op.h,
                    op.host.ptr,
                    @intCast(op.port),
                    "127.0.0.1",
                    0,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
            pub fn lastErrno(op: @This()) c_int {
                return c.libssh2_session_last_errno(op.h);
            }
        };
        return poll.pumpHandle(fd, cancel, Op{ .h = h, .host = host, .port = port });
    }

    /// Best-effort bounded channel close + free (mirrors `disconnect`).
    pub fn channelFree(ch: *c.LIBSSH2_CHANNEL, h: Handle, fd: std.posix.fd_t) void {
        var token: CancelToken = .{};
        const Close = struct {
            ch: *c.LIBSSH2_CHANNEL,
            h: Handle,

            pub fn call(op: @This()) c_int {
                return c.libssh2_channel_close(op.ch);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        _ = poll.pumpBounded(fd, &token, Close{ .ch = ch, .h = h }, 3) catch {};
        const Free = struct {
            ch: *c.LIBSSH2_CHANNEL,
            h: Handle,

            pub fn call(op: @This()) c_int {
                return c.libssh2_channel_free(op.ch);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        _ = poll.pumpBounded(fd, &token, Free{ .ch = ch, .h = h }, 3) catch {};
    }

    /// Best-effort teardown, bounded to ~1s total: ≤5 polls for the
    /// disconnect message, ≤5 for the session free. If libssh2 still
    /// reports EAGAIN after that we abandon the handle (leak, never hang).
    pub fn disconnect(h: Handle, fd: std.posix.fd_t) void {
        var token: CancelToken = .{};
        const Disc = struct {
            h: Handle,

            pub fn call(op: @This()) c_int {
                return c.libssh2_session_disconnect_ex(
                    op.h,
                    c.SSH_DISCONNECT_BY_APPLICATION,
                    "closing",
                    "",
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        _ = poll.pumpBounded(fd, &token, Disc{ .h = h }, 5) catch {};
        const Free = struct {
            h: Handle,

            pub fn call(op: @This()) c_int {
                return c.libssh2_session_free(op.h);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.h);
            }
        };
        _ = poll.pumpBounded(fd, &token, Free{ .h = h }, 5) catch {};
    }
};

/// The production session type the SFTP layer builds on.
pub const SshSession = Engine(LibSsh2).Session;

// ---------------------------------------------------------------------------
// Proxy transports — ProxyJump / ProxyCommand
//
// libssh2 wants ONE socket fd per session, so anything that is not a plain
// TCP connection (a direct-tcpip channel through a jump host, a spawned
// ProxyCommand's stdio) is bridged to a socketpair: the target session gets
// one end as its "socket", a pump thread shuttles bytes between the other
// end and the real transport. The pump is poll-driven with ≤100 ms wakeups
// so teardown (and cancellation above it) resolves promptly.
// ---------------------------------------------------------------------------

pub const pump_buf_len = 32 * 1024;

/// Result of one non-blocking read/write on the channel side of a pump.
pub const ChanResult = union(enum) {
    bytes: usize,
    /// Would block; progress needs the next poll wakeup.
    again,
    /// Orderly end of stream (reads only).
    eof,
    /// The transport is broken; the pump tears down.
    fail,
};

/// One pump thread bridging `Chan` (the transport) to a socketpair end.
/// `Chan` is duck-typed:
///
///   fn chanRead(ch, buf: []u8) ChanResult
///   fn chanWrite(ch, data: []const u8) ChanResult
///   fn chanSendEof(ch) void              — half-close toward the transport
///   fn readFd(ch) / writeFd(ch) fd_t     — fds to poll for progress
///   fn readPollEvents(ch) / writePollEvents(ch) i16
///
/// The pump owns no fds; the enclosing transport closes them after
/// `shutdown` joins the thread. `sock` must stay open until then.
pub fn Pump(comptime Chan: type) type {
    return struct {
        chan: *Chan,
        /// Pump-side socketpair end; `start` makes it O_NONBLOCK.
        sock: std.posix.fd_t,
        stop_flag: std.atomic.Value(bool) = .init(false),
        thread: ?std.Thread = null,

        to_sock_buf: [pump_buf_len]u8 = undefined,
        to_sock_start: usize = 0,
        to_sock_len: usize = 0,
        to_chan_buf: [pump_buf_len]u8 = undefined,
        to_chan_start: usize = 0,
        to_chan_len: usize = 0,
        chan_eof: bool = false,
        sock_eof: bool = false,
        sock_shut: bool = false,
        chan_eof_sent: bool = false,

        const Self = @This();

        /// Spawn the pump thread. The Self must not move afterwards (the
        /// thread holds the pointer) — transports heap-allocate themselves.
        pub fn start(self: *Self) error{Unexpected}!void {
            try LibSsh2.setNonBlocking(self.sock);
            self.thread = std.Thread.spawn(.{}, run, .{self}) catch return error.Unexpected;
        }

        /// Stops the loop and joins the thread (≤ ~one poll interval).
        /// Idempotent; safe when `start` was never called.
        pub fn shutdown(self: *Self) void {
            self.stop_flag.store(true, .release);
            if (self.thread) |th| th.join();
            self.thread = null;
        }

        fn run(self: *Self) void {
            while (self.step()) {}
            // Unblock a session still attached to the far socketpair end:
            // it sees EOF / write failure and classifies ConnectionLost.
            fdShutdown(self.sock, .both);
        }

        /// One poll + transfer round; false = the pump is done. Pure
        /// fd/Chan logic — unit-tested over socketpairs without SSH.
        fn step(self: *Self) bool {
            if (self.stop_flag.load(.acquire)) return false;
            if (self.done()) return false;

            var fds: [3]std.posix.pollfd = undefined;
            var n: usize = 0;
            {
                var ev: i16 = 0;
                if (self.to_chan_len == 0 and !self.sock_eof) ev |= std.posix.POLL.IN;
                if (self.to_sock_len != 0) ev |= std.posix.POLL.OUT;
                if (ev != 0) {
                    fds[n] = .{ .fd = self.sock, .events = ev, .revents = 0 };
                    n += 1;
                }
            }
            if (self.to_sock_len == 0 and !self.chan_eof) {
                fds[n] = .{
                    .fd = self.chan.readFd(),
                    .events = self.chan.readPollEvents(),
                    .revents = 0,
                };
                n += 1;
            }
            if (self.to_chan_len != 0) {
                fds[n] = .{
                    .fd = self.chan.writeFd(),
                    .events = self.chan.writePollEvents(),
                    .revents = 0,
                };
                n += 1;
            }
            _ = std.posix.poll(fds[0..n], poll.poll_interval_ms) catch return false;
            if (self.stop_flag.load(.acquire)) return false;

            // chan -> sock: flush pending, then refill from the channel.
            if (self.to_sock_len != 0) {
                const pending = self.to_sock_buf[self.to_sock_start..][0..self.to_sock_len];
                if (fdWrite(self.sock, pending)) |wrote| {
                    self.to_sock_start += wrote;
                    self.to_sock_len -= wrote;
                } else |err| switch (err) {
                    error.WouldBlock => {},
                    else => return false,
                }
            }
            if (self.to_sock_len == 0 and !self.chan_eof) {
                switch (self.chan.chanRead(&self.to_sock_buf)) {
                    .bytes => |got| {
                        self.to_sock_start = 0;
                        self.to_sock_len = got;
                    },
                    .again => {},
                    .eof => self.chan_eof = true,
                    .fail => return false,
                }
            }
            if (self.chan_eof and self.to_sock_len == 0 and !self.sock_shut) {
                self.sock_shut = true;
                fdShutdown(self.sock, .send);
            }

            // sock -> chan: flush pending, then refill from the socket.
            if (self.to_chan_len != 0) {
                const pending = self.to_chan_buf[self.to_chan_start..][0..self.to_chan_len];
                switch (self.chan.chanWrite(pending)) {
                    .bytes => |wrote| {
                        self.to_chan_start += wrote;
                        self.to_chan_len -= wrote;
                    },
                    .again => {},
                    .eof, .fail => return false,
                }
            }
            if (self.to_chan_len == 0 and !self.sock_eof) {
                if (std.posix.read(self.sock, &self.to_chan_buf)) |got| {
                    if (got == 0) {
                        self.sock_eof = true;
                    } else {
                        self.to_chan_start = 0;
                        self.to_chan_len = got;
                    }
                } else |err| switch (err) {
                    error.WouldBlock => {},
                    else => return false,
                }
            }
            if (self.sock_eof and self.to_chan_len == 0 and !self.chan_eof_sent) {
                self.chan_eof_sent = true;
                self.chan.chanSendEof();
            }
            return !self.done();
        }

        fn done(self: *const Self) bool {
            return self.chan_eof and self.sock_eof and
                self.to_sock_len == 0 and self.to_chan_len == 0;
        }
    };
}

/// Channel over a plain fd pair: a ProxyCommand child's stdout (read) and
/// stdin (write) — also the unit-test fake (both fds = one socketpair end).
/// Both fds must be O_NONBLOCK.
pub const FdChan = struct {
    read_fd: std.posix.fd_t,
    write_fd: std.posix.fd_t,
    eof_mode: EofMode,
    write_closed: bool = false,

    pub const EofMode = enum {
        /// Socket: shutdown(SHUT_WR), fd stays open (tests).
        shutdown_send,
        /// Pipe: close the write fd (a child's stdin EOF); the owner must
        /// then skip its own close (`write_closed`).
        close_fd,
    };

    pub fn chanRead(ch: *FdChan, buf: []u8) ChanResult {
        const got = std.posix.read(ch.read_fd, buf) catch |err| switch (err) {
            error.WouldBlock => return .again,
            else => return .fail,
        };
        return if (got == 0) .eof else .{ .bytes = got };
    }

    pub fn chanWrite(ch: *FdChan, data: []const u8) ChanResult {
        if (ch.write_closed) return .fail;
        const wrote = fdWrite(ch.write_fd, data) catch |err| switch (err) {
            error.WouldBlock => return .again,
            else => return .fail,
        };
        return .{ .bytes = wrote };
    }

    pub fn chanSendEof(ch: *FdChan) void {
        switch (ch.eof_mode) {
            .shutdown_send => fdShutdown(ch.write_fd, .send),
            .close_fd => {
                if (!ch.write_closed) fdClose(ch.write_fd);
                ch.write_closed = true;
            },
        }
    }

    pub fn readFd(ch: *const FdChan) std.posix.fd_t {
        return ch.read_fd;
    }
    pub fn writeFd(ch: *const FdChan) std.posix.fd_t {
        return ch.write_fd;
    }
    pub fn readPollEvents(_: *const FdChan) i16 {
        return std.posix.POLL.IN;
    }
    pub fn writePollEvents(_: *const FdChan) i16 {
        return std.posix.POLL.OUT;
    }
};

/// Channel over a libssh2 direct-tcpip channel of an (authenticated) jump
/// session. Only the pump thread touches the jump session after start —
/// libssh2 sessions are not thread-safe.
pub const ChannelChan = struct {
    session: LibSsh2.Handle,
    channel: *c.LIBSSH2_CHANNEL,
    /// The jump session's socket; polled for channel progress.
    fd: std.posix.fd_t,

    pub fn chanRead(ch: *ChannelChan, buf: []u8) ChanResult {
        const rc = c.libssh2_channel_read_ex(ch.channel, 0, buf.ptr, buf.len);
        if (rc > 0) return .{ .bytes = @intCast(rc) };
        if (rc == 0) return if (c.libssh2_channel_eof(ch.channel) != 0) .eof else .again;
        if (rc == poll.eagain) return .again;
        return .fail;
    }

    pub fn chanWrite(ch: *ChannelChan, data: []const u8) ChanResult {
        const rc = c.libssh2_channel_write_ex(ch.channel, 0, data.ptr, data.len);
        if (rc > 0) return .{ .bytes = @intCast(rc) };
        if (rc == poll.eagain or rc == 0) return .again;
        return .fail;
    }

    pub fn chanSendEof(ch: *ChannelChan) void {
        var token: CancelToken = .{};
        const Op = struct {
            ch: *ChannelChan,

            pub fn call(op: @This()) c_int {
                return c.libssh2_channel_send_eof(op.ch.channel);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.ch.session);
            }
        };
        _ = poll.pumpBounded(ch.fd, &token, Op{ .ch = ch }, 3) catch {};
    }

    pub fn readFd(ch: *const ChannelChan) std.posix.fd_t {
        return ch.fd;
    }
    pub fn writeFd(ch: *const ChannelChan) std.posix.fd_t {
        return ch.fd;
    }
    pub fn readPollEvents(ch: *const ChannelChan) i16 {
        return poll.directionsToPollEvents(c.libssh2_session_block_directions(ch.session));
    }
    pub fn writePollEvents(ch: *const ChannelChan) i16 {
        return poll.directionsToPollEvents(c.libssh2_session_block_directions(ch.session));
    }
};

// std.posix (0.16) keeps read/poll but dropped write/close/shutdown;
// route those through libc directly.
fn fdClose(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

const Shut = enum(c_int) {
    send = std.c.SHUT.WR,
    both = std.c.SHUT.RDWR,
};

fn fdShutdown(fd: std.posix.fd_t, how: Shut) void {
    _ = std.c.shutdown(fd, @intFromEnum(how));
}

fn fdWrite(fd: std.posix.fd_t, data: []const u8) error{ WouldBlock, Unexpected }!usize {
    while (true) {
        const rc = std.c.write(fd, data.ptr, data.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.Unexpected,
        }
    }
}

/// CLOEXEC AF_UNIX stream socketpair (proxy transports spawn children; the
/// pair must not leak into them).
fn socketPair(diag: *Diagnostics) error{Unexpected}![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        diag.set(.transient, 0, "socketpair failed for the proxy transport", .{});
        return error.Unexpected;
    }
    for (fds) |fd| _ = std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
    return fds;
}

/// One ProxyJump hop: an authenticated SSH session to the jump host plus a
/// direct-tcpip channel to the next hop / final target, bridged to
/// `target_fd` for the session running over it. Multi-hop chains stack
/// transports (each next session's "socket" is the previous `target_fd`).
///
/// Teardown contract: deinit the session running over `target_fd` FIRST
/// (its disconnect flows through the still-live pump), then `deinit` here;
/// the fd under the jump session stays owned by the caller (SshSession
/// convention).
pub const JumpTransport = struct {
    gpa: Allocator,
    session: SshSession,
    channel: *c.LIBSSH2_CHANNEL,
    chan: ChannelChan,
    pump: Pump(ChannelChan),
    /// The next session's socket; owned here, valid until deinit.
    target_fd: std.posix.fd_t,
    pump_fd: std.posix.fd_t,

    /// Opens the direct-tcpip channel to `host:port` through `session`
    /// (already authenticated) and starts the pump. Ownership of the
    /// session transfers unconditionally — on error it is deinitialized
    /// before returning.
    pub fn open(
        gpa: Allocator,
        session: SshSession,
        host: []const u8,
        port: u16,
        cancel: *CancelToken,
        diag: *Diagnostics,
    ) Error!*JumpTransport {
        var sess = session;
        errdefer sess.deinit();

        if (host.len > max_username_len) {
            diag.set(.permanent, 0, "jump target host name too long ({d} bytes)", .{host.len});
            return error.Unexpected;
        }
        var host_z: [max_username_len:0]u8 = undefined;
        @memcpy(host_z[0..host.len], host);
        host_z[host.len] = 0;

        const channel = (LibSsh2.channelDirectTcpip(
            sess.handle,
            sess.fd,
            cancel,
            host_z[0..host.len :0],
            port,
        ) catch |err| switch (err) {
            error.Canceled => {
                diag.set(.cancel, 0, "canceled", .{});
                return error.Canceled;
            },
            error.ConnectionLost => {
                diag.set(.transient, 0, "direct-tcpip to {s}:{d}: connection lost", .{ host, port });
                return error.ConnectionLost;
            },
        }) orelse {
            const rc = c.libssh2_session_last_errno(sess.handle);
            var msg_buf: [256]u8 = undefined;
            const cls = classifyLibRc(rc);
            diag.set(cls.class, 0, "direct-tcpip to {s}:{d} via {s} failed (rc {d}): {s}", .{
                host, port, sess.host(), rc, LibSsh2.lastErrorMessage(sess.handle, &msg_buf),
            });
            return cls.fatal orelse error.ConnectionLost;
        };
        errdefer LibSsh2.channelFree(channel, sess.handle, sess.fd);

        const pair = try socketPair(diag);
        errdefer for (pair) |fd| fdClose(fd);

        const jt = gpa.create(JumpTransport) catch return error.OutOfMemory;
        errdefer gpa.destroy(jt);
        jt.* = .{
            .gpa = gpa,
            .session = sess,
            .channel = channel,
            .chan = .{ .session = sess.handle, .channel = channel, .fd = sess.fd },
            .pump = .{ .chan = &jt.chan, .sock = pair[0] },
            .target_fd = pair[1],
            .pump_fd = pair[0],
        };
        jt.pump.start() catch {
            diag.set(.transient, 0, "could not start the ProxyJump pump thread", .{});
            return error.Unexpected;
        };
        return jt;
    }

    pub fn deinit(jt: *JumpTransport) void {
        jt.pump.shutdown();
        LibSsh2.channelFree(jt.channel, jt.session.handle, jt.session.fd);
        jt.session.deinit();
        fdClose(jt.pump_fd);
        fdClose(jt.target_fd);
        const gpa = jt.gpa;
        jt.* = undefined;
        gpa.destroy(jt);
    }
};

/// ProxyCommand: a spawned `/bin/sh -c <command>` whose stdin/stdout are
/// the SSH transport, bridged to `target_fd`. Same teardown contract as
/// JumpTransport (target session first); deinit kills the child.
pub const CommandTransport = struct {
    gpa: Allocator,
    io: std.Io,
    child: std.process.Child,
    chan: FdChan,
    pump: Pump(FdChan),
    target_fd: std.posix.fd_t,
    pump_fd: std.posix.fd_t,

    /// `command` is the verbatim ProxyCommand; %h/%p/%% are expanded here.
    pub fn spawn(
        gpa: Allocator,
        io: std.Io,
        command: []const u8,
        host: []const u8,
        port: u16,
        diag: *Diagnostics,
    ) Error!*CommandTransport {
        const expanded = try expandProxyCommand(gpa, command, host, port);
        defer gpa.free(expanded);

        var child = std.process.spawn(io, .{
            .argv = &.{ "/bin/sh", "-c", expanded },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch {
            diag.set(.permanent, 0, "proxy command failed to start: {s}", .{expanded});
            return error.Unexpected;
        };
        errdefer child.kill(io);

        // Take the pipe fds: kill() must not double-close them.
        const write_fd = child.stdin.?.handle;
        const read_fd = child.stdout.?.handle;
        child.stdin = null;
        child.stdout = null;
        errdefer fdClose(write_fd);
        errdefer fdClose(read_fd);
        LibSsh2.setNonBlocking(write_fd) catch {
            diag.set(.permanent, 0, "could not set O_NONBLOCK on the proxy command pipes", .{});
            return error.Unexpected;
        };
        LibSsh2.setNonBlocking(read_fd) catch {
            diag.set(.permanent, 0, "could not set O_NONBLOCK on the proxy command pipes", .{});
            return error.Unexpected;
        };

        const pair = try socketPair(diag);
        errdefer for (pair) |fd| fdClose(fd);

        const ct = gpa.create(CommandTransport) catch return error.OutOfMemory;
        errdefer gpa.destroy(ct);
        ct.* = .{
            .gpa = gpa,
            .io = io,
            .child = child,
            .chan = .{ .read_fd = read_fd, .write_fd = write_fd, .eof_mode = .close_fd },
            .pump = .{ .chan = &ct.chan, .sock = pair[0] },
            .target_fd = pair[1],
            .pump_fd = pair[0],
        };
        ct.pump.start() catch {
            diag.set(.transient, 0, "could not start the ProxyCommand pump thread", .{});
            return error.Unexpected;
        };
        return ct;
    }

    pub fn deinit(ct: *CommandTransport) void {
        ct.pump.shutdown();
        ct.child.kill(ct.io);
        if (!ct.chan.write_closed) fdClose(ct.chan.write_fd);
        fdClose(ct.chan.read_fd);
        fdClose(ct.pump_fd);
        fdClose(ct.target_fd);
        const gpa = ct.gpa;
        ct.* = undefined;
        gpa.destroy(ct);
    }
};

/// ssh_config(5) TOKENS for ProxyCommand: %h (host), %p (port), %%.
/// Unknown tokens stay verbatim (same lenience as ssh_config.zig).
pub fn expandProxyCommand(
    gpa: Allocator,
    command: []const u8,
    host: []const u8,
    port: u16,
) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var i: usize = 0;
    while (i < command.len) : (i += 1) {
        if (command[i] != '%' or i + 1 == command.len) {
            try out.append(gpa, command[i]);
            continue;
        }
        i += 1;
        switch (command[i]) {
            '%' => try out.append(gpa, '%'),
            'h' => try out.appendSlice(gpa, host),
            'p' => {
                var buf: [5]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{port}) catch unreachable;
                try out.appendSlice(gpa, s);
            },
            else => {
                try out.append(gpa, '%');
                try out.append(gpa, command[i]);
            },
        }
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// SSH wire helpers for the sign callback (pure; unit-tested + fuzzed)
// ---------------------------------------------------------------------------

/// Picks the agent sign flags by reading the publickey method name out of
/// the to-be-signed userauth blob: `string session_id` followed by the
/// SSH_MSG_USERAUTH_REQUEST packet (byte 50, string user, string service,
/// string "publickey", bool, string method, string key blob). libssh2 may
/// have upgraded an ssh-rsa key's method to rsa-sha2-256/512 via
/// server-sig-algs, and the agent must sign with the same algorithm.
pub fn signFlagsForData(data: []const u8) agent_mod.SignFlags {
    var r: WireCursor = .{ .buf = data };
    _ = r.string() orelse return .{}; // session id
    const msg_type = r.byte() orelse return .{};
    if (msg_type != 50) return .{}; // SSH_MSG_USERAUTH_REQUEST
    _ = r.string() orelse return .{}; // username
    _ = r.string() orelse return .{}; // service
    const method_kw = r.string() orelse return .{};
    if (!std.mem.eql(u8, method_kw, "publickey")) return .{};
    _ = r.byte() orelse return .{}; // TRUE
    const algo = r.string() orelse return .{};
    if (std.mem.eql(u8, algo, "rsa-sha2-256")) return .{ .rsa_sha2_256 = true };
    if (std.mem.eql(u8, algo, "rsa-sha2-512")) return .{ .rsa_sha2_512 = true };
    return .{};
}

/// Unwraps an SSH signature blob (`string algorithm ++ string signature`)
/// to the raw signature bytes libssh2's sign callback must produce.
pub fn rawSignature(sig_blob: []const u8) ?[]const u8 {
    var r: WireCursor = .{ .buf = sig_blob };
    const algo = r.string() orelse return null;
    if (algo.len == 0) return null;
    const raw = r.string() orelse return null;
    if (raw.len == 0 or r.pos != sig_blob.len) return null;
    return raw;
}

const WireCursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(r: *WireCursor) ?u8 {
        if (r.pos >= r.buf.len) return null;
        defer r.pos += 1;
        return r.buf[r.pos];
    }

    fn string(r: *WireCursor) ?[]const u8 {
        if (4 > r.buf.len - r.pos) return null;
        const len = std.mem.readInt(u32, r.buf[r.pos..][0..4], .big);
        r.pos += 4;
        if (len > r.buf.len - r.pos) return null;
        defer r.pos += len;
        return r.buf[r.pos..][0..len];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

fn wireString(w: *std.Io.Writer, bytes: []const u8) void {
    w.writeInt(u32, @intCast(bytes.len), .big) catch unreachable;
    w.writeAll(bytes) catch unreachable;
}

test "classifyLibRc table" {
    // auth-shaped: chain continues
    for ([_]i32{ -18, -19, -48, -15 }) |rc| {
        const cls = classifyLibRc(rc);
        try t.expectEqual(diag_mod.ErrorClass.auth, cls.class);
        try t.expectEqual(@as(?Error, null), cls.fatal);
    }
    // transport: chain aborts, transient (retry policy reconnects)
    for ([_]i32{ -7, -43, -13, -45 }) |rc| {
        const cls = classifyLibRc(rc);
        try t.expectEqual(diag_mod.ErrorClass.transient, cls.class);
        try t.expectEqual(@as(?Error, error.ConnectionLost), cls.fatal);
    }
    for ([_]i32{ -9, -30 }) |rc| {
        try t.expectEqual(@as(?Error, error.Timeout), classifyLibRc(rc).fatal);
    }
    // protocol-fatal
    for ([_]i32{ -5, -8, -14 }) |rc| {
        const cls = classifyLibRc(rc);
        try t.expectEqual(diag_mod.ErrorClass.permanent, cls.class);
        try t.expectEqual(@as(?Error, error.ProtocolViolation), cls.fatal);
    }
    try t.expectEqual(@as(?Error, error.OutOfMemory), classifyLibRc(-6).fatal);
    // unknown rcs: permanent but the chain may continue
    const other = classifyLibRc(-33);
    try t.expectEqual(diag_mod.ErrorClass.permanent, other.class);
    try t.expectEqual(@as(?Error, null), other.fatal);
}

comptime {
    std.debug.assert(c.LIBSSH2_ERROR_AUTHENTICATION_FAILED == lib_rc.authentication_failed);
    std.debug.assert(c.LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED == lib_rc.publickey_unverified);
    std.debug.assert(c.LIBSSH2_ERROR_SOCKET_SEND == lib_rc.socket_send);
    std.debug.assert(c.LIBSSH2_ERROR_SOCKET_RECV == lib_rc.socket_recv);
    std.debug.assert(c.LIBSSH2_ERROR_SOCKET_DISCONNECT == lib_rc.socket_disconnect);
    std.debug.assert(c.LIBSSH2_ERROR_TIMEOUT == lib_rc.timeout);
    std.debug.assert(c.LIBSSH2_ERROR_SOCKET_TIMEOUT == lib_rc.socket_timeout);
    std.debug.assert(c.LIBSSH2_ERROR_KEYFILE_AUTH_FAILED == lib_rc.keyfile_auth_failed);
    std.debug.assert(c.LIBSSH2_ERROR_PASSWORD_EXPIRED == lib_rc.password_expired);
    std.debug.assert(c.LIBSSH2_ERROR_ALLOC == lib_rc.alloc);
    std.debug.assert(c.LIBSSH2_ERROR_PROTO == lib_rc.proto);
    std.debug.assert(c.LIBSSH2_ERROR_KEX_FAILURE == lib_rc.kex_failure);
    std.debug.assert(c.LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE == lib_rc.key_exchange_failure);
    std.debug.assert(c.LIBSSH2_ERROR_BAD_SOCKET == lib_rc.bad_socket);
}

test "signFlagsForData reads the method out of the signed blob" {
    var buf: [256]u8 = undefined;

    const cases = [_]struct { algo: []const u8, expect: u32 }{
        .{ .algo = "rsa-sha2-256", .expect = 2 },
        .{ .algo = "rsa-sha2-512", .expect = 4 },
        .{ .algo = "ssh-rsa", .expect = 0 },
        .{ .algo = "ssh-ed25519", .expect = 0 },
    };
    for (cases) |case| {
        var w: std.Io.Writer = .fixed(&buf);
        wireString(&w, "0123456789abcdef0123456789abcdef"); // session id
        w.writeByte(50) catch unreachable;
        wireString(&w, "user");
        wireString(&w, "ssh-connection");
        wireString(&w, "publickey");
        w.writeByte(1) catch unreachable;
        wireString(&w, case.algo);
        wireString(&w, "\x00\x00\x00\x07ssh-rsa...");
        try t.expectEqual(case.expect, signFlagsForData(w.buffered()).toWire());
    }

    // Anything malformed degrades to no flags, never a crash.
    try t.expectEqual(@as(u32, 0), signFlagsForData("").toWire());
    try t.expectEqual(@as(u32, 0), signFlagsForData("\x00\x00\x00\x02xy").toWire());
}

test "rawSignature unwraps the agent's signature blob" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    wireString(&w, "ssh-ed25519");
    wireString(&w, "RAWSIGBYTES");
    try t.expectEqualStrings("RAWSIGBYTES", rawSignature(w.buffered()).?);

    try t.expectEqual(@as(?[]const u8, null), rawSignature(""));
    try t.expectEqual(@as(?[]const u8, null), rawSignature("\x00\x00\x00\x01x"));
    // trailing garbage rejected
    w = .fixed(&buf);
    wireString(&w, "ssh-ed25519");
    wireString(&w, "SIG");
    w.writeByte(0) catch unreachable;
    try t.expectEqual(@as(?[]const u8, null), rawSignature(w.buffered()));
}

test "fuzz sign-callback wire helpers" {
    try t.fuzz({}, fuzzWireHelpers, .{});
}

fn fuzzWireHelpers(_: void, smith: *t.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    _ = signFlagsForData(buf[0..len]);
    _ = rawSignature(buf[0..len]);
}

// ---------------------------------------------------------------------------
// Stubbed-Lib engine tests (auth chain ordering + classification)
// ---------------------------------------------------------------------------

/// Minimal structurally-valid ed25519 public key blob.
fn testKeyBlob(comptime seed: u8) [4 + 11 + 4 + 32]u8 {
    var out: [4 + 11 + 4 + 32]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], 11, .big);
    out[4..15].* = "ssh-ed25519".*;
    std.mem.writeInt(u32, out[15..19], 32, .big);
    for (out[19..], 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return out;
}

/// Builds an unencrypted openssh-key-v1 ed25519 private key file that
/// keys.zig accepts — exercises the real local validation step.
fn makeTestKeyPem(buf: []u8) []const u8 {
    const seed = [_]u8{0x42} ** 32;
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const pub_bytes = kp.public_key.toBytes();
    const secret = kp.secret_key.toBytes(); // 64 bytes: seed ++ public

    var bin_buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&bin_buf);
    w.writeAll("openssh-key-v1\x00") catch unreachable;
    wireString(&w, "none"); // cipher
    wireString(&w, "none"); // kdf
    wireString(&w, ""); // kdf options
    w.writeInt(u32, 1, .big) catch unreachable;

    var blob_buf: [128]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&blob_buf);
    wireString(&bw, "ssh-ed25519");
    wireString(&bw, &pub_bytes);
    wireString(&w, bw.buffered());

    var sec_buf: [256]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sec_buf);
    sw.writeInt(u32, 0xdeadbeef, .big) catch unreachable; // checkint x2
    sw.writeInt(u32, 0xdeadbeef, .big) catch unreachable;
    wireString(&sw, "ssh-ed25519");
    wireString(&sw, &pub_bytes);
    wireString(&sw, &secret);
    wireString(&sw, "relay-test");
    var pad: u8 = 1;
    while (sw.buffered().len % 8 != 0) : (pad += 1) {
        sw.writeByte(pad) catch unreachable;
    }
    wireString(&w, sw.buffered());

    var b64_buf: [1024]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, w.buffered());
    var out: std.Io.Writer = .fixed(buf);
    out.writeAll("-----BEGIN OPENSSH PRIVATE KEY-----\n") catch unreachable;
    var rest = b64;
    while (rest.len > 70) {
        out.writeAll(rest[0..70]) catch unreachable;
        out.writeByte('\n') catch unreachable;
        rest = rest[70..];
    }
    out.writeAll(rest) catch unreachable;
    out.writeAll("\n-----END OPENSSH PRIVATE KEY-----\n") catch unreachable;
    return out.buffered();
}

const stub_blob_a = testKeyBlob(0xa0);
const stub_blob_b = testKeyBlob(0xb0);

const StubLib = struct {
    var state: *State = undefined;

    const State = struct {
        handshake_rc: c_int = 0,
        hostkey: ?[]const u8 = &stub_blob_a,
        /// null = libssh2 returned NULL from userauth_list.
        method_list: ?[]const u8 = "publickey,password,keyboard-interactive",
        authenticated: bool = false,
        /// null = no agent reachable.
        agent_identities: ?[]const agent_mod.Identity = null,
        agent_rcs: []const c_int = &.{},
        agent_auth_calls: usize = 0,
        key_rc: c_int = lib_rc.authentication_failed,
        password_rc: c_int = lib_rc.authentication_failed,
        kbd_rc: c_int = lib_rc.authentication_failed,
        kbd_prompts: []const KiPrompt = &.{.{ .text = "Password: ", .echo = false }},
        /// Call log for ordering assertions.
        log_buf: [24][64]u8 = undefined,
        log_lens: [24]u8 = @splat(0),
        log_len: usize = 0,
        files: []const struct { name: []const u8, bytes: []const u8 } = &.{},

        fn logCall(st: *State, comptime fmt: []const u8, args: anytype) void {
            if (st.log_len == st.log_buf.len) return;
            var w: std.Io.Writer = .fixed(&st.log_buf[st.log_len]);
            w.print(fmt, args) catch {};
            st.log_lens[st.log_len] = @intCast(w.buffered().len);
            st.log_len += 1;
        }

        fn logged(st: *const State, i: usize) []const u8 {
            return st.log_buf[i][0..st.log_lens[i]];
        }
    };

    const Handle = *State;
    const AgentConn = State;

    fn setNonBlocking(fd: std.posix.fd_t) error{Unexpected}!void {
        _ = fd; // stub sessions have no real socket
    }
    fn sessionInit() ?Handle {
        return state;
    }
    fn sessionFree(h: Handle) void {
        _ = h;
    }
    fn handshake(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken) poll.Error!c_int {
        _ = fd;
        try cancel.check();
        return h.handshake_rc;
    }
    fn hostKeyBlob(h: Handle) ?[]const u8 {
        return h.hostkey;
    }
    fn lastErrorMessage(h: Handle, buf: []u8) []const u8 {
        _ = h;
        const msg = "stub failure";
        @memcpy(buf[0..msg.len], msg);
        return buf[0..msg.len];
    }
    fn isAuthenticated(h: Handle) bool {
        return h.authenticated;
    }
    fn userauthList(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken, user: [:0]const u8, buf: []u8) poll.Error!?[]const u8 {
        _ = fd;
        _ = user;
        try cancel.check();
        const list = h.method_list orelse return null;
        @memcpy(buf[0..list.len], list);
        return buf[0..list.len];
    }
    fn agentOpen(gpa: Allocator, io: std.Io, path: ?[]const u8, cancel: *CancelToken) error{ OutOfMemory, Canceled }!?*AgentConn {
        _ = gpa;
        _ = io;
        _ = path;
        try cancel.check();
        if (state.agent_identities == null) return null;
        return state;
    }
    fn agentIdentities(ac: *AgentConn) []const agent_mod.Identity {
        return ac.agent_identities.?;
    }
    fn agentClose(gpa: Allocator, ac: *AgentConn) void {
        _ = gpa;
        _ = ac;
    }
    fn agentAuth(h: Handle, fd: std.posix.fd_t, gpa: Allocator, cancel: *CancelToken, ac: *AgentConn, user: [:0]const u8, id: *const agent_mod.Identity) (poll.Error || error{OutOfMemory})!c_int {
        _ = fd;
        _ = gpa;
        _ = ac;
        _ = user;
        try cancel.check();
        h.logCall("agent:{s}", .{id.comment});
        const i = @min(h.agent_auth_calls, h.agent_rcs.len -| 1);
        h.agent_auth_calls += 1;
        return if (h.agent_rcs.len == 0) lib_rc.authentication_failed else h.agent_rcs[i];
    }
    fn keyAuth(h: Handle, fd: std.posix.fd_t, gpa: Allocator, cancel: *CancelToken, user: [:0]const u8, file_bytes: []const u8, passphrase: ?[]const u8, label: []const u8) (poll.Error || error{OutOfMemory})!c_int {
        _ = fd;
        _ = gpa;
        _ = user;
        _ = file_bytes;
        _ = passphrase;
        try cancel.check();
        h.logCall("key:{s}", .{label});
        return h.key_rc;
    }
    fn readKeyFile(gpa: Allocator, io: std.Io, path: []const u8) error{OutOfMemory}!?[]u8 {
        _ = io;
        for (state.files) |f| {
            if (std.mem.endsWith(u8, path, f.name)) return try gpa.dupe(u8, f.bytes);
        }
        return null;
    }
    fn passwordAuth(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken, user: [:0]const u8, password: []const u8) poll.Error!c_int {
        _ = fd;
        _ = user;
        _ = password;
        try cancel.check();
        h.logCall("password", .{});
        return h.password_rc;
    }
    fn kbdintAuth(h: Handle, fd: std.posix.fd_t, gpa: Allocator, cancel: *CancelToken, user: [:0]const u8, callbacks: *const Callbacks) poll.Error!c_int {
        _ = fd;
        _ = user;
        try cancel.check();
        h.logCall("kbdint", .{});
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const answers = callbacks.promptUser.?(
            callbacks.context,
            arena.allocator(),
            "stub",
            "answer me",
            h.kbd_prompts,
        ) orelse return error.Canceled;
        if (answers.len != h.kbd_prompts.len) return lib_rc.authentication_failed;
        return h.kbd_rc;
    }
    fn keepaliveConfig(h: Handle, want_reply: bool, interval_s: u32) void {
        _ = h;
        _ = want_reply;
        _ = interval_s;
    }
    fn keepaliveSend(h: Handle, fd: std.posix.fd_t, cancel: *CancelToken) poll.Error!u32 {
        _ = h;
        _ = fd;
        _ = cancel;
        return 5;
    }
    fn disconnect(h: Handle, fd: std.posix.fd_t) void {
        _ = fd;
        h.logCall("disconnect", .{});
    }
};

const StubEngine = Engine(StubLib);

const TestCallbacks = struct {
    decision: HostKeyDecision = .accept,
    seen_fp: ?[keys.fingerprint_len]u8 = null,
    seen_key_type: [32]u8 = undefined,
    seen_key_type_len: usize = 0,
    prompt_answers: ?[]const []const u8 = &.{"hunter2"},
    prompts_seen: usize = 0,
    /// The Callbacks ABI cannot return OOM; remember it for the
    /// allocation-failure test to re-raise.
    prompt_oom: bool = false,

    fn verify(ctx: *anyopaque, info: *const HostKeyInfo) HostKeyDecision {
        const self: *TestCallbacks = @ptrCast(@alignCast(ctx));
        self.seen_fp = info.sha256_fp;
        self.seen_key_type_len = @min(info.key_type.len, self.seen_key_type.len);
        @memcpy(self.seen_key_type[0..self.seen_key_type_len], info.key_type[0..self.seen_key_type_len]);
        return self.decision;
    }

    fn prompt(
        ctx: *anyopaque,
        arena: Allocator,
        name: []const u8,
        instruction: []const u8,
        prompts: []const KiPrompt,
    ) ?[]const []const u8 {
        _ = name;
        _ = instruction;
        const self: *TestCallbacks = @ptrCast(@alignCast(ctx));
        self.prompts_seen += prompts.len;
        const answers = self.prompt_answers orelse return null;
        const out = arena.alloc([]const u8, answers.len) catch {
            self.prompt_oom = true;
            return null;
        };
        for (out, answers) |*o, src| o.* = arena.dupe(u8, src) catch {
            self.prompt_oom = true;
            return null;
        };
        return out;
    }

    fn callbacks(self: *TestCallbacks) Callbacks {
        return .{
            .context = self,
            .verifyHostKey = verify,
            .promptUser = prompt,
        };
    }
};

fn stubSession(st: *StubLib.State, cb: *TestCallbacks, diag: *Diagnostics) !StubEngine.Session {
    StubLib.state = st;
    var cancel: CancelToken = .{};
    return StubEngine.Session.init(
        t.allocator,
        t.io,
        -1,
        "test.example",
        2222,
        &cancel,
        diag,
        cb.callbacks(),
    );
}

test "init: host key fingerprint relayed; decisions map to errors" {
    var diag: Diagnostics = .{};

    // accept
    var st: StubLib.State = .{};
    var cb: TestCallbacks = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();
    try t.expectEqualStrings("ssh-ed25519", cb.seen_key_type[0..cb.seen_key_type_len]);
    try t.expectEqualStrings(&keys.fingerprintSha256(&stub_blob_a), &cb.seen_fp.?);

    // reject -> permanent
    var st2: StubLib.State = .{};
    var cb2: TestCallbacks = .{ .decision = .reject };
    diag.clear();
    try t.expectError(error.HostKeyRejected, stubSession(&st2, &cb2, &diag));
    try t.expectEqual(diag_mod.ErrorClass.permanent, diag.class);
    try t.expect(std.mem.indexOf(u8, diag.message, "test.example:2222") != null);

    // unknown -> auth (first-contact prompt)
    var st3: StubLib.State = .{};
    var cb3: TestCallbacks = .{ .decision = .unknown };
    diag.clear();
    try t.expectError(error.HostKeyUnknown, stubSession(&st3, &cb3, &diag));
    try t.expectEqual(diag_mod.ErrorClass.auth, diag.class);

    // handshake transport failure
    var st4: StubLib.State = .{ .handshake_rc = lib_rc.socket_recv };
    var cb4: TestCallbacks = .{};
    diag.clear();
    try t.expectError(error.ConnectionLost, stubSession(&st4, &cb4, &diag));
    try t.expectEqual(diag_mod.ErrorClass.transient, diag.class);

    // missing host key
    var st5: StubLib.State = .{ .hostkey = null };
    var cb5: TestCallbacks = .{};
    diag.clear();
    try t.expectError(error.ProtocolViolation, stubSession(&st5, &cb5, &diag));
}

test "auth chain: full method order, trail recorded, final diag .auth" {
    var pem_buf: [1024]u8 = undefined;
    const pem = makeTestKeyPem(&pem_buf);

    const ids = [_]agent_mod.Identity{
        .{ .key_blob = &stub_blob_a, .comment = "alpha" },
        .{ .key_blob = &stub_blob_b, .comment = "beta" },
    };
    var st: StubLib.State = .{
        .agent_identities = &ids,
        .agent_rcs = &.{ lib_rc.authentication_failed, lib_rc.publickey_unverified },
        .files = &.{.{ .name = "id_ed25519", .bytes = pem }},
    };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try t.expectError(error.AuthFailed, s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .key = .{ .file_bytes = pem, .label = "/tmp/explicit" },
        .ssh_dir = "/home/relay/.ssh",
        .password = "secret",
    }));

    // Exact order: both agent identities, explicit key, the one default
    // key the stub "filesystem" has, password, then keyboard-interactive.
    try t.expectEqual(@as(usize, 6), st.log_len);
    try t.expectEqualStrings("agent:alpha", st.logged(0));
    try t.expectEqualStrings("agent:beta", st.logged(1));
    try t.expectEqualStrings("key:/tmp/explicit", st.logged(2));
    try t.expectEqualStrings("key:id_ed25519", st.logged(3));
    try t.expectEqualStrings("password", st.logged(4));
    try t.expectEqualStrings("kbdint", st.logged(5));

    // Trail mirrors the failures with classes.
    try t.expectEqual(@as(usize, 6), s.trail.len);
    try t.expectEqual(AuthMethod.agent_key, s.trail.slice()[0].method);
    try t.expectEqual(diag_mod.ErrorClass.auth, s.trail.slice()[0].class);
    try t.expectEqual(@as(i32, lib_rc.publickey_unverified), s.trail.slice()[1].rc);
    try t.expectEqual(AuthMethod.explicit_key, s.trail.slice()[2].method);
    try t.expectEqual(AuthMethod.default_key, s.trail.slice()[3].method);
    try t.expectEqual(AuthMethod.password, s.trail.slice()[4].method);
    try t.expectEqual(AuthMethod.keyboard_interactive, s.trail.slice()[5].method);

    try t.expectEqual(diag_mod.ErrorClass.auth, diag.class);
    try t.expect(cb.prompts_seen == 1);
}

test "auth chain stops at first success" {
    const ids = [_]agent_mod.Identity{
        .{ .key_blob = &stub_blob_a, .comment = "alpha" },
        .{ .key_blob = &stub_blob_b, .comment = "beta" },
    };
    var st: StubLib.State = .{
        .agent_identities = &ids,
        .agent_rcs = &.{ lib_rc.authentication_failed, 0 },
    };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .password = "never-used",
    });
    try t.expectEqual(@as(usize, 2), st.log_len);
    try t.expectEqualStrings("agent:beta", st.logged(1));
    // only the failed first identity is in the trail
    try t.expectEqual(@as(usize, 1), s.trail.len);
}

test "userauth_list gates methods: password-only server skips publickey" {
    const ids = [_]agent_mod.Identity{
        .{ .key_blob = &stub_blob_a, .comment = "alpha" },
    };
    var st: StubLib.State = .{
        .method_list = "password",
        .agent_identities = &ids,
        .password_rc = 0,
    };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try s.authenticate(&cancel, &diag, .{ .username = "relay", .password = "pw" });
    try t.expectEqual(@as(usize, 1), st.log_len);
    try t.expectEqualStrings("password", st.logged(0));
}

test "none auth: null method list + authenticated session succeeds" {
    var st: StubLib.State = .{ .method_list = null, .authenticated = true };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try s.authenticate(&cancel, &diag, .{ .username = "relay" });
    try t.expectEqual(@as(usize, 0), st.log_len);
}

test "transport failure mid-chain aborts instead of trying next method" {
    var st: StubLib.State = .{ .password_rc = lib_rc.socket_recv };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try t.expectError(error.ConnectionLost, s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .password = "pw",
    }));
    try t.expectEqual(diag_mod.ErrorClass.transient, diag.class);
    // keyboard-interactive must NOT have been attempted after the abort
    try t.expectEqual(@as(usize, 1), st.log_len);
    try t.expectEqualStrings("password", st.logged(0));
}

test "malformed explicit key is recorded locally and chain continues" {
    var st: StubLib.State = .{ .password_rc = 0 };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .key = .{ .file_bytes = "not a key at all", .label = "bogus.pem" },
        .password = "pw",
    });
    // keyAuth never reached the (stub) wire — keys.zig rejected locally.
    try t.expectEqual(@as(usize, 1), st.log_len);
    try t.expectEqualStrings("password", st.logged(0));
    try t.expectEqual(@as(usize, 1), s.trail.len);
    try t.expectEqual(AuthMethod.explicit_key, s.trail.slice()[0].method);
    try t.expectEqual(diag_mod.ErrorClass.permanent, s.trail.slice()[0].class);
    try t.expect(std.mem.indexOf(u8, s.trail.slice()[0].detail(), "bogus.pem") != null);
}

test "user dismissing keyboard-interactive cancels silently" {
    var st: StubLib.State = .{};
    var cb: TestCallbacks = .{ .prompt_answers = null };
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try t.expectError(error.Canceled, s.authenticate(&cancel, &diag, .{
        .username = "relay",
    }));
    try t.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
}

test "pre-canceled token aborts authenticate before any method" {
    var st: StubLib.State = .{};
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    cancel.cancel();
    try t.expectError(error.Canceled, s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .password = "pw",
    }));
    try t.expectEqual(diag_mod.ErrorClass.cancel, diag.class);
    try t.expectEqual(@as(usize, 0), st.log_len);
}

test "no credentials at all yields AuthFailed with an explanatory diag" {
    var st: StubLib.State = .{ .method_list = "hostbased" };
    var cb: TestCallbacks = .{};
    var diag: Diagnostics = .{};
    var s = try stubSession(&st, &cb, &diag);
    defer s.deinit();

    var cancel: CancelToken = .{};
    try t.expectError(error.AuthFailed, s.authenticate(&cancel, &diag, .{
        .username = "relay",
        .password = "pw",
    }));
    try t.expectEqual(diag_mod.ErrorClass.auth, diag.class);
    try t.expect(std.mem.indexOf(u8, diag.message, "hostbased") != null);
}

test "authenticate survives allocation failure" {
    var pem_buf: [1024]u8 = undefined;
    const pem = makeTestKeyPem(&pem_buf);

    const Check = struct {
        fn run(gpa: Allocator, pem_text: []const u8) !void {
            const ids = [_]agent_mod.Identity{
                .{ .key_blob = &stub_blob_a, .comment = "alpha" },
            };
            var st: StubLib.State = .{
                .agent_identities = &ids,
                .files = &.{.{ .name = "id_rsa", .bytes = pem_text }},
            };
            StubLib.state = &st;
            var cb: TestCallbacks = .{};
            var diag: Diagnostics = .{};
            var cancel: CancelToken = .{};
            var s = StubEngine.Session.init(
                gpa,
                t.io,
                -1,
                "test.example",
                22,
                &cancel,
                &diag,
                cb.callbacks(),
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            defer s.deinit();
            s.authenticate(&cancel, &diag, .{
                .username = "relay",
                .key = .{ .file_bytes = pem_text },
                .ssh_dir = "/x/.ssh",
                .password = "pw",
            }) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            };
            if (cb.prompt_oom) return error.OutOfMemory;
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{pem});
}

// ---------------------------------------------------------------------------
// Pump / transport tests — socketpairs and a fake byte protocol; no SSH.
// ---------------------------------------------------------------------------

const TestPair = struct {
    fds: [2]std.posix.fd_t,

    fn init() !TestPair {
        var diag: Diagnostics = .{};
        return .{ .fds = try socketPair(&diag) };
    }

    fn deinit(p: *TestPair) void {
        for (p.fds) |fd| fdClose(fd);
    }
};

/// Blocking-side read with a poll deadline so a broken pump fails the test
/// instead of hanging it.
fn readDeadline(fd: std.posix.fd_t, buf: []u8) ![]u8 {
    var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, 5000) catch return error.PollFailed;
    if (n == 0) return error.DeadlineExceeded;
    const got = try std.posix.read(fd, buf);
    return buf[0..got];
}

fn readExactDeadline(fd: std.posix.fd_t, buf: []u8) ![]u8 {
    var off: usize = 0;
    while (off < buf.len) {
        const got = try readDeadline(fd, buf[off..]);
        if (got.len == 0) return error.UnexpectedEof;
        off += got.len;
    }
    return buf;
}

test "pump bridges a fake byte protocol both ways over socketpairs" {
    var a = try TestPair.init(); // [0] pump side, [1] "target session" side
    defer a.deinit();
    var b = try TestPair.init(); // [0] chan side, [1] "remote server" side
    defer b.deinit();

    try LibSsh2.setNonBlocking(b.fds[0]);
    var chan: FdChan = .{ .read_fd = b.fds[0], .write_fd = b.fds[0], .eof_mode = .shutdown_send };
    var pump: Pump(FdChan) = .{ .chan = &chan, .sock = a.fds[0] };
    try pump.start();
    defer pump.shutdown();

    // Fake protocol: target sends a request, remote answers, twice.
    var buf: [64]u8 = undefined;
    _ = try fdWrite(a.fds[1], "PING relay");
    try t.expectEqualStrings("PING relay", try readDeadline(b.fds[1], &buf));
    _ = try fdWrite(b.fds[1], "PONG relay");
    try t.expectEqualStrings("PONG relay", try readDeadline(a.fds[1], &buf));
    _ = try fdWrite(a.fds[1], "QUIT");
    try t.expectEqualStrings("QUIT", try readDeadline(b.fds[1], &buf));
}

test "pump moves bulk data exceeding every buffer in the path" {
    var a = try TestPair.init();
    defer a.deinit();
    var b = try TestPair.init();
    defer b.deinit();

    try LibSsh2.setNonBlocking(b.fds[0]);
    var chan: FdChan = .{ .read_fd = b.fds[0], .write_fd = b.fds[0], .eof_mode = .shutdown_send };
    var pump: Pump(FdChan) = .{ .chan = &chan, .sock = a.fds[0] };
    try pump.start();
    defer pump.shutdown();

    const total: usize = 3 * pump_buf_len; // > any single buffer, with margin for multiple refills
    const Writer = struct {
        fn run(fd: std.posix.fd_t, n: usize) void {
            var chunk: [4096]u8 = undefined;
            var off: usize = 0;
            while (off < n) {
                const len = @min(chunk.len, n - off);
                for (chunk[0..len], 0..) |*p, i| p.* = @truncate((off + i) *% 31);
                var done: usize = 0;
                while (done < len) {
                    done += fdWrite(fd, chunk[done..len]) catch return;
                }
                off += len;
            }
        }
    };

    // target -> remote
    const th = try std.Thread.spawn(.{}, Writer.run, .{ a.fds[1], total });
    var got: usize = 0;
    var buf: [4096]u8 = undefined;
    while (got < total) {
        const chunk = try readDeadline(b.fds[1], &buf);
        if (chunk.len == 0) break;
        for (chunk, 0..) |byte, i| {
            try t.expectEqual(@as(u8, @truncate((got + i) *% 31)), byte);
        }
        got += chunk.len;
    }
    th.join();
    try t.expectEqual(total, got);

    // remote -> target
    const th2 = try std.Thread.spawn(.{}, Writer.run, .{ b.fds[1], total });
    got = 0;
    while (got < total) {
        const chunk = try readDeadline(a.fds[1], &buf);
        if (chunk.len == 0) break;
        for (chunk, 0..) |byte, i| {
            try t.expectEqual(@as(u8, @truncate((got + i) *% 31)), byte);
        }
        got += chunk.len;
    }
    th2.join();
    try t.expectEqual(total, got);
}

test "pump propagates EOF both ways and finishes on its own" {
    var a = try TestPair.init();
    defer a.deinit();
    var b = try TestPair.init();
    defer b.deinit();

    try LibSsh2.setNonBlocking(b.fds[0]);
    var chan: FdChan = .{ .read_fd = b.fds[0], .write_fd = b.fds[0], .eof_mode = .shutdown_send };
    var pump: Pump(FdChan) = .{ .chan = &chan, .sock = a.fds[0] };
    try pump.start();

    // Remote half-closes; the target side must observe EOF...
    _ = try fdWrite(b.fds[1], "tail");
    fdShutdown(b.fds[1], .send);
    var buf: [16]u8 = undefined;
    try t.expectEqualStrings("tail", try readDeadline(a.fds[1], &buf));
    try t.expectEqual(@as(usize, 0), (try readDeadline(a.fds[1], &buf)).len);

    // ...then the target closes; the pump completes without shutdown().
    fdShutdown(a.fds[1], .send);
    try t.expectEqual(@as(usize, 0), (try readDeadline(b.fds[1], &buf)).len);
    pump.shutdown(); // joins a thread that already exited naturally
    try t.expect(pump.chan_eof);
    try t.expect(pump.sock_eof);
}

test "pump teardown under cancel: shutdown joins within the poll budget" {
    const io = t.io;
    var a = try TestPair.init();
    defer a.deinit();
    var b = try TestPair.init();
    defer b.deinit();

    try LibSsh2.setNonBlocking(b.fds[0]);
    var chan: FdChan = .{ .read_fd = b.fds[0], .write_fd = b.fds[0], .eof_mode = .shutdown_send };
    var pump: Pump(FdChan) = .{ .chan = &chan, .sock = a.fds[0] };
    try pump.start();

    // Mid-flight traffic, then an idle pump parked in poll().
    _ = try fdWrite(a.fds[1], "in flight");
    var buf: [16]u8 = undefined;
    _ = try readDeadline(b.fds[1], &buf);

    const t0: std.Io.Clock.Timestamp = .now(io, .awake);
    pump.shutdown();
    const elapsed_ms = @divTrunc(
        t0.durationTo(.now(io, .awake)).raw.nanoseconds,
        std.time.ns_per_ms,
    );
    try t.expect(elapsed_ms < 500); // one ~100 ms poll wakeup + join slack
    // After the join the far end is unblocked (shutdown .both in run()).
    try t.expectEqual(@as(usize, 0), (try readDeadline(a.fds[1], &buf)).len);
}

test "CommandTransport: child stdio is the transport; deinit kills the child" {
    var diag: Diagnostics = .{};
    // `cat` echoes: bytes written to target_fd come back through the
    // child's stdin->stdout — the full ProxyCommand data path, no SSH.
    const ct = try CommandTransport.spawn(t.allocator, t.io, "exec cat", "h.example", 22, &diag);
    var torn_down = false;
    defer if (!torn_down) ct.deinit();

    _ = try fdWrite(ct.target_fd, "through the proxy");
    var buf: [32]u8 = undefined;
    try t.expectEqualStrings(
        "through the proxy",
        try readExactDeadline(ct.target_fd, buf[0.."through the proxy".len]),
    );

    const pid = ct.child.id.?;
    torn_down = true;
    ct.deinit();
    // deinit's kill() reaped the child: waitpid on the pid must report
    // "no such child" rather than find a live or zombie process.
    var status: c_int = 0;
    const rc = std.c.waitpid(pid, &status, 0);
    const err = std.posix.errno(rc);
    try t.expectEqual(@as(std.c.pid_t, -1), rc);
    try t.expectEqual(std.c.E.CHILD, err);
}

test "CommandTransport: spawn failure is classified, nothing leaks" {
    var diag: Diagnostics = .{};
    // /bin/sh starts fine but the command dies instantly; the transport
    // still constructs (OpenSSH parity) and the session above would see
    // EOF. Use a command that exits immediately to exercise child-exit.
    const ct = try CommandTransport.spawn(t.allocator, t.io, "exec true", "h", 22, &diag);
    defer ct.deinit();
    var buf: [8]u8 = undefined;
    // Child exited: target side observes EOF once the pump notices.
    try t.expectEqual(@as(usize, 0), (try readDeadline(ct.target_fd, &buf)).len);
}

test "expandProxyCommand: %h/%p/%% tokens" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "ssh -W %h:%p jump", .out = "ssh -W files.example.com:2222 jump" },
        .{ .in = "nc %h %p", .out = "nc files.example.com 2222" },
        .{ .in = "echo 100%% %h", .out = "echo 100% files.example.com" },
        .{ .in = "no tokens", .out = "no tokens" },
        .{ .in = "trailing %", .out = "trailing %" },
        .{ .in = "unknown %x stays", .out = "unknown %x stays" },
    };
    for (cases) |case| {
        const out = try expandProxyCommand(t.allocator, case.in, "files.example.com", 2222);
        defer t.allocator.free(out);
        try t.expectEqualStrings(case.out, out);
    }
}

test "expandProxyCommand survives allocation failure" {
    const Check = struct {
        fn run(gpa: Allocator) !void {
            const out = try expandProxyCommand(gpa, "ssh -W %h:%p j %% %z", "host.example", 22);
            gpa.free(out);
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{});
}

// ---------------------------------------------------------------------------
// Live proxy matrix — opt-in like live_test.zig (RELAY_SFTP_LIVE=1): two
// dockerized sshds. The jump host (linuxserver/openssh-server, password
// auth; AllowTcpForwarding flipped on in its /config/sshd/sshd_config) and
// an atmoz/sftp target reachable (a) through the jump via the docker
// network's DNS name — the ProxyJump leg — and (b) on a published localhost
// port for the ProxyCommand (`nc %h %p`) leg.
// ---------------------------------------------------------------------------

const live_jump_image = "linuxserver/openssh-server:latest";
const live_target_image = "atmoz/sftp:alpine";

fn liveDocker(gpa: Allocator, io: std.Io, argv: []const []const u8) error{ DockerFailed, OutOfMemory }![]u8 {
    const res = std.process.run(gpa, io, .{ .argv = argv }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DockerFailed,
    };
    defer gpa.free(res.stderr);
    switch (res.term) {
        .exited => |code| if (code == 0) return res.stdout,
        else => {},
    }
    gpa.free(res.stdout);
    return error.DockerFailed;
}

fn liveDockerOk(gpa: Allocator, io: std.Io, argv: []const []const u8) bool {
    const out = liveDocker(gpa, io, argv) catch return false;
    gpa.free(out);
    return true;
}

/// Waits (≤ ~60 s; the jump image may run under emulation) for an SSH
/// banner on the port. Docker's proxy accepts TCP before sshd listens.
fn liveWaitBanner(io: std.Io, port: u16) bool {
    for (0..300) |_| {
        if (liveBannerVisible(io, port)) return true;
        std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch return false;
    }
    return false;
}

fn liveBannerVisible(io: std.Io, port: u16) bool {
    const addr = std.Io.net.IpAddress.resolve(io, "127.0.0.1", port) catch return false;
    const stream = addr.connect(io, .{ .mode = .stream }) catch return false;
    defer stream.close(io);
    var fds = [1]std.posix.pollfd{.{
        .fd = stream.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, 2000) catch return false;
    if (n == 0) return false;
    var buf: [8]u8 = undefined;
    const got = std.posix.read(stream.socket.handle, &buf) catch return false;
    return got >= 4 and std.mem.eql(u8, buf[0..4], "SSH-");
}

const AcceptAllHostKey = struct {
    seen: usize = 0,

    fn verify(ctx: *anyopaque, info: *const HostKeyInfo) HostKeyDecision {
        const cb: *AcceptAllHostKey = @ptrCast(@alignCast(ctx));
        cb.seen += 1;
        _ = info;
        return .accept;
    }

    fn callbacks(cb: *AcceptAllHostKey) Callbacks {
        return .{ .context = cb, .verifyHostKey = verify };
    }
};

test "live: ProxyJump + ProxyCommand transports (set RELAY_SFTP_LIVE=1 to run)" {
    const gate = std.c.getenv("RELAY_SFTP_LIVE") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(gate), "1")) return error.SkipZigTest;

    const gpa = t.allocator;
    const io = t.io;

    if (!liveDockerOk(gpa, io, &.{ "docker", "version", "--format", "{{.Server.Version}}" }))
        return error.SkipZigTest;
    for ([_][]const u8{ live_jump_image, live_target_image }) |image| {
        if (!liveDockerOk(gpa, io, &.{ "docker", "image", "inspect", image })) {
            if (!liveDockerOk(gpa, io, &.{ "docker", "pull", image })) return error.SkipZigTest;
        }
    }

    // Clock-seeded ports/names (collision avoidance, not security).
    const now: std.Io.Clock.Timestamp = .now(io, .awake);
    const mix = @as(u64, @truncate(@as(u96, @bitCast(now.raw.nanoseconds)))) *% 0x9e3779b97f4a7c15;
    const jump_port: u16 = 20000 + @as(u16, @intCast((mix >> 32) % 19000));
    const target_port: u16 = jump_port + 1;
    var name_buf: [3][64]u8 = undefined;
    const net = std.fmt.bufPrint(&name_buf[0], "relay-pj-net-{d}", .{jump_port}) catch unreachable;
    const jump_name = std.fmt.bufPrint(&name_buf[1], "relay-pj-jump-{d}", .{jump_port}) catch unreachable;
    const target_name = std.fmt.bufPrint(&name_buf[2], "relay-pj-target-{d}", .{jump_port}) catch unreachable;

    if (!liveDockerOk(gpa, io, &.{ "docker", "network", "create", net })) return error.SkipZigTest;
    defer _ = liveDockerOk(gpa, io, &.{ "docker", "network", "rm", net });

    var port_buf: [2][32]u8 = undefined;
    const target_map = std.fmt.bufPrint(&port_buf[0], "127.0.0.1:{d}:22", .{target_port}) catch unreachable;
    const jump_map = std.fmt.bufPrint(&port_buf[1], "127.0.0.1:{d}:2222", .{jump_port}) catch unreachable;

    // Target: docker-DNS reachable from the jump AND published for the
    // ProxyCommand leg. TTL self-destruct mirrors live_test.zig.
    if (!liveDockerOk(gpa, io, &.{
        "docker", "run",      "-d",              "--rm",                          "--name", target_name, "--network", net,
        "-p",     target_map, live_target_image, "relay:relaypw:1001:100:upload",
    })) return error.SkipZigTest;
    defer _ = liveDockerOk(gpa, io, &.{ "docker", "rm", "-f", target_name });
    _ = liveDockerOk(gpa, io, &.{
        "docker", "exec", "-d", target_name, "sh", "-c", "sleep 600; kill 1",
    });

    // Jump host: password auth; no --rm (docker restart below races
    // autoremove), removed in the defer.
    if (!liveDockerOk(gpa, io, &.{
        "docker",               "run",           "-d", "--name",               jump_name, "--network",      net,
        "-p",                   jump_map,        "-e", "PASSWORD_ACCESS=true", "-e",      "USER_NAME=jump", "-e",
        "USER_PASSWORD=jumppw", live_jump_image,
    })) return error.SkipZigTest;
    defer _ = liveDockerOk(gpa, io, &.{ "docker", "rm", "-f", jump_name });

    if (!liveWaitBanner(io, jump_port)) return error.SkipZigTest;
    // The image ships AllowTcpForwarding no; flip it and restart sshd.
    if (!liveDockerOk(gpa, io, &.{
        "docker",                                           "exec",                     jump_name, "sed", "-i",
        "s/^AllowTcpForwarding no/AllowTcpForwarding yes/", "/config/sshd/sshd_config",
    })) return error.SkipZigTest;
    if (!liveDockerOk(gpa, io, &.{ "docker", "restart", jump_name })) return error.SkipZigTest;
    if (!liveWaitBanner(io, jump_port)) return error.SkipZigTest;
    if (!liveWaitBanner(io, target_port)) return error.SkipZigTest;

    // ---- ProxyJump leg: jump session -> direct-tcpip -> target session --
    {
        var cancel: CancelToken = .{};
        var diag: Diagnostics = .{};
        var hk: AcceptAllHostKey = .{};

        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", jump_port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);

        var jump_session = try SshSession.init(
            gpa,
            io,
            stream.socket.handle,
            "127.0.0.1",
            jump_port,
            &cancel,
            &diag,
            hk.callbacks(),
        );
        var jump_owned = true;
        defer if (jump_owned) jump_session.deinit();
        try jump_session.authenticate(&cancel, &diag, .{
            .username = "jump",
            .try_agent = false,
            .password = "jumppw",
        });

        jump_owned = false; // JumpTransport.open takes the session
        const jt = try JumpTransport.open(gpa, jump_session, target_name, 22, &cancel, &diag);
        var jt_owned = true;
        defer if (jt_owned) jt.deinit();

        // Full SSH handshake + host key + auth of the TARGET over the
        // pumped channel — the transport proof. Host keys verified per
        // hop: the callback fired once for the jump, once for the target.
        var target_session = try SshSession.init(
            gpa,
            io,
            jt.target_fd,
            target_name,
            22,
            &cancel,
            &diag,
            hk.callbacks(),
        );
        var target_owned = true;
        defer if (target_owned) target_session.deinit();
        try target_session.authenticate(&cancel, &diag, .{
            .username = "relay",
            .try_agent = false,
            .password = "relaypw",
        });
        try t.expectEqual(@as(usize, 2), hk.seen);
        target_session.keepalive(5);
        _ = try target_session.keepaliveSend(&cancel, &diag);

        // Teardown contract: target session first, then the transport.
        target_owned = false;
        target_session.deinit();
        jt_owned = false;
        jt.deinit();
        std.debug.print("RELAY-PROXY-LIVE jump leg PASS (2 host keys verified)\n", .{});
    }

    // ---- ProxyCommand leg: nc %h %p as the transport ---------------------
    {
        var cancel: CancelToken = .{};
        var diag: Diagnostics = .{};
        var hk: AcceptAllHostKey = .{};

        const ct = try CommandTransport.spawn(gpa, io, "nc %h %p", "127.0.0.1", target_port, &diag);
        var ct_owned = true;
        defer if (ct_owned) ct.deinit();

        var session = try SshSession.init(
            gpa,
            io,
            ct.target_fd,
            "127.0.0.1",
            target_port,
            &cancel,
            &diag,
            hk.callbacks(),
        );
        var session_owned = true;
        defer if (session_owned) session.deinit();
        try session.authenticate(&cancel, &diag, .{
            .username = "relay",
            .try_agent = false,
            .password = "relaypw",
        });

        session_owned = false;
        session.deinit();
        ct_owned = false;
        ct.deinit();
        std.debug.print("RELAY-PROXY-LIVE command leg PASS\n", .{});
    }
}

test {
    std.testing.refAllDecls(@This());
}

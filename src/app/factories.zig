//! factories — the production FTP/FTPS/SFTP connect factories injected
//! into the bridge for normal runs (`AppCore.setFactoryProvider`); the
//! resolution of the bridge's TODO(m2-factory).
//!
//! One `Factories` per process owns one `SiteState` per site id (created
//! by `make` on the main thread under the bridge's sites_mutex, kept for
//! the app lifetime so workers of retired pools never dangle). A state
//! carries the per-site knobs a connect needs off-main: the auth-metadata
//! snapshot (method + key file, refreshed on every `make` from the sites
//! controller via `meta_lookup`), the TLS escape hatch, and the lazily
//! created LibreSSL provider (one SSL_CTX per site, shared by control and
//! data connections for session reuse).
//!
//! Connect sequences:
//!  - SFTP: dial → SshSession handshake with known_hosts verification
//!    (user ~/.ssh/known_hosts read-only + the app's own Application
//!    Support known_hosts; unknown keys raise the host-key sheet through
//!    `AppCore.askPrompt`, accepted keys append to the app file) → auth
//!    chain per the site's method (agent + default keys / explicit key
//!    file / password) → SFTP subsystem.
//!  - FTP/FTPS: dial → FtpClient.connect (implicit TLS on 990, AUTH TLS
//!    otherwise, SecTrust verification via tls/verify_sectrust) with a
//!    real TCP DataConnFactory for PASV/EPSV.
//!
//! Credentials come from the bridge's CredProvider (Keychain). A missing
//! secret raises the password sheet with the real user/host and the fetch
//! is retried after the sheet stores it (TODO(m2-prompts) resolution); a
//! REFUSED secret is invalidated (`invalidateSiteSecret`) and re-prompted
//! once. Prompting is serialized per site so concurrent browse/transfer
//! connects cannot stack sheets.

const std = @import("std");
const relay = @import("relay_core");
const bridge = @import("bridge.zig");

const sites_mod = relay.sites;
const site_pool_mod = relay.pool.site_pool;
const vfs_mod = relay.vfs.iface;
const diag_mod = relay.diag;
const settings_mod = relay.settings;
const session_mod = relay.sftp.session;
const sftp_client_mod = relay.sftp.client;
const ftp_client_mod = relay.ftp.client;
const data_conn_mod = relay.ftp.data_conn;
const tls_provider_mod = relay.tls.provider;
const libressl_mod = relay.tls.libressl;
const known_hosts = relay.ssh.known_hosts;
const ssh_config_mod = relay.ssh.ssh_config;

const Allocator = std.mem.Allocator;
const CancelToken = relay.cancel.CancelToken;
const Diagnostics = diag_mod.Diagnostics;

/// Accepted host keys live here (Application Support), never in the
/// user's ~/.ssh/known_hosts — Relay reads that file but does not write it.
pub const known_hosts_file = "known_hosts";

pub const key_path_max = 1024;
pub const proxy_jump_max = 512;
pub const proxy_command_max = 1024;

pub const AuthMethod = enum { agent, key_file, password };

/// Per-site auth metadata (mirrors the sites controller's AuthMetaStore
/// entry without importing the controller).
pub const AuthChoice = struct {
    method: AuthMethod = .agent,
    key_path: []const u8 = "",
    /// Explicit per-site ProxyJump in ssh_config syntax ("[user@]host[:port]"
    /// hops, comma-separated; "none" disables). Empty = consult ~/.ssh/config.
    proxy_jump: []const u8 = "",
    /// Explicit per-site ProxyCommand (%h/%p tokens). Empty = consult
    /// ~/.ssh/config. The explicit ProxyJump wins when both are set.
    proxy_command: []const u8 = "",
};

/// Main-thread-only hook into the sites controller's AuthMetaStore;
/// consulted by `make` (which runs on the main thread per the bridge's
/// connectSite contract). The returned slices are borrowed for the call.
pub const MetaLookup = struct {
    ctx: ?*anyopaque = null,
    get: ?*const fn (ctx: ?*anyopaque, site_id: u64) ?AuthChoice = null,
};

/// RFC 1635 anonymous FTP convention; used when the site has no account.
const anonymous_creds: site_pool_mod.Credentials = .{
    .user = "anonymous",
    .secret = "anonymous@relay.app",
};

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

pub const Factories = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    /// Wired by main.zig once the sites controller exists.
    meta_lookup: MetaLookup = .{},
    /// Serializes appends to the app known_hosts file.
    kh_mutex: std.Io.Mutex = .init,
    /// Grow-only (main-thread appends in `make`); states live for the app.
    states: std.ArrayList(*SiteState) = .empty,

    pub fn create(gpa: Allocator, core: *bridge.AppCore) error{OutOfMemory}!*Factories {
        const self = try gpa.create(Factories);
        self.* = .{ .gpa = gpa, .core = core };
        return self;
    }

    /// Tests only — the app keeps the factories for the process lifetime.
    /// Call after AppCore.shutdown (no worker may still hold a state).
    pub fn destroy(self: *Factories) void {
        for (self.states.items) |state| {
            if (state.tls) |tls| tls.deinit();
            self.gpa.destroy(state);
        }
        self.states.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    pub fn provider(self: *Factories) bridge.FactoryProvider {
        return .{ .ctx = @ptrCast(self), .makeFn = make };
    }

    /// bridge.FactoryProvider entry point (main thread, under sites_mutex).
    fn make(ctx: *anyopaque, site: *const sites_mod.Site) site_pool_mod.ConnFactory {
        const self: *Factories = @ptrCast(@alignCast(ctx));
        const state = self.stateFor(site) catch
            return .{ .ctx = @ptrCast(&oom_factory_ctx), .connectFn = oomConnect };
        return .{ .ctx = @ptrCast(state), .connectFn = factoryConnect };
    }

    fn stateFor(self: *Factories, site: *const sites_mod.Site) error{OutOfMemory}!*SiteState {
        for (self.states.items) |state| {
            if (state.site_id == site.id) {
                state.refresh(self, site);
                return state;
            }
        }
        const state = try self.gpa.create(SiteState);
        state.* = .{ .owner = self, .site_id = site.id };
        state.refresh(self, site);
        self.states.append(self.gpa, state) catch {
            self.gpa.destroy(state);
            return error.OutOfMemory;
        };
        return state;
    }

    /// Appends one accepted host key to the app's known_hosts (read +
    /// rewrite atomically; the file is small).
    fn appendKnownHost(self: *Factories, io: std.Io, info: *const session_mod.HostKeyInfo) !void {
        self.kh_mutex.lockUncancelable(io);
        defer self.kh_mutex.unlock(io);
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const existing: ?[]u8 =
            self.core.config_dir.readFileAlloc(io, known_hosts_file, self.gpa, .unlimited) catch null;
        defer if (existing) |text| self.gpa.free(text);
        if (existing) |text| out.writer.writeAll(text) catch return error.OutOfMemory;
        known_hosts.writeEntry(&out.writer, info.host, info.port, info.key_blob, .{}) catch
            return error.OutOfMemory;
        try settings_mod.atomicWriteFile(io, self.core.config_dir, known_hosts_file, out.written());
    }
};

var oom_factory_ctx: u8 = 0;

fn oomConnect(
    _: *anyopaque,
    _: std.Io,
    _: *CancelToken,
    diag: *Diagnostics,
    _: *const site_pool_mod.SiteConfig,
    _: site_pool_mod.Role,
) vfs_mod.Error!site_pool_mod.Conn {
    diag.set(.transient, 0, "out of memory creating the site's connect factory", .{});
    return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// SiteState
// ---------------------------------------------------------------------------

const SiteState = struct {
    owner: *Factories,
    site_id: u64,

    /// Guards the auth-meta snapshot (written by `make` on main, read by
    /// connect workers) — copies only, nanosecond hold times.
    meta_mutex: std.atomic.Mutex = .unlocked,
    method: AuthMethod = .agent,
    key_path_buf: [key_path_max]u8 = undefined,
    key_path_len: usize = 0,
    proxy_jump_buf: [proxy_jump_max]u8 = undefined,
    proxy_jump_len: usize = 0,
    proxy_command_buf: [proxy_command_max]u8 = undefined,
    proxy_command_len: usize = 0,
    insecure_skip_verify: bool = false,

    /// Serializes the prompt+refetch path so concurrent browse/transfer
    /// connects raise at most one password sheet.
    prompt_serial: std.Io.Mutex = .init,

    /// Lazily created, then shared by every connection of the site.
    tls_mutex: std.atomic.Mutex = .unlocked,
    tls: ?*libressl_mod.LibresslProvider = null,

    fn refresh(state: *SiteState, owner: *Factories, site: *const sites_mod.Site) void {
        var choice: AuthChoice = .{
            .method = if (site.protocol == .sftp) .agent else .password,
        };
        if (owner.meta_lookup.get) |get| {
            if (get(owner.meta_lookup.ctx, site.id)) |c| choice = c;
        }
        lockSpin(&state.meta_mutex);
        defer state.meta_mutex.unlock();
        state.insecure_skip_verify = site.insecure_skip_verify;
        state.method = choice.method;
        state.key_path_len = copyClamped(&state.key_path_buf, choice.key_path);
        state.proxy_jump_len = copyClamped(&state.proxy_jump_buf, choice.proxy_jump);
        state.proxy_command_len = copyClamped(&state.proxy_command_buf, choice.proxy_command);
    }

    const AuthSnapshot = struct {
        method: AuthMethod,
        key_path: []const u8,
        proxy_jump: []const u8,
        proxy_command: []const u8,
    };

    const SnapshotBufs = struct {
        key_path: [key_path_max]u8 = undefined,
        proxy_jump: [proxy_jump_max]u8 = undefined,
        proxy_command: [proxy_command_max]u8 = undefined,
    };

    fn authSnapshot(state: *SiteState, bufs: *SnapshotBufs) AuthSnapshot {
        lockSpin(&state.meta_mutex);
        defer state.meta_mutex.unlock();
        @memcpy(bufs.key_path[0..state.key_path_len], state.key_path_buf[0..state.key_path_len]);
        @memcpy(bufs.proxy_jump[0..state.proxy_jump_len], state.proxy_jump_buf[0..state.proxy_jump_len]);
        @memcpy(
            bufs.proxy_command[0..state.proxy_command_len],
            state.proxy_command_buf[0..state.proxy_command_len],
        );
        return .{
            .method = state.method,
            .key_path = bufs.key_path[0..state.key_path_len],
            .proxy_jump = bufs.proxy_jump[0..state.proxy_jump_len],
            .proxy_command = bufs.proxy_command[0..state.proxy_command_len],
        };
    }

    fn insecureSkipVerify(state: *SiteState) bool {
        lockSpin(&state.meta_mutex);
        defer state.meta_mutex.unlock();
        return state.insecure_skip_verify;
    }

    fn tlsFor(state: *SiteState, diag: *Diagnostics) vfs_mod.Error!tls_provider_mod.TlsProvider {
        lockSpin(&state.tls_mutex);
        defer state.tls_mutex.unlock();
        if (state.tls == null) {
            state.tls = libressl_mod.LibresslProvider.init(state.owner.gpa, .{}) catch |err| {
                diag.set(.permanent, 0, "TLS provider initialization failed: {t}", .{err});
                return error.Unexpected;
            };
        }
        return state.tls.?.provider();
    }

    /// Password sheet + store re-fetch, serialized per site. `recheck`
    /// re-reads the store first (a parallel connect may have prompted
    /// already); pass false after `invalidateSiteSecret` — the store still
    /// holds the refused secret until the user answers. null = declined.
    fn promptForSecret(
        state: *SiteState,
        io: std.Io,
        cancel: *CancelToken,
        diag: *Diagnostics,
        site: *const site_pool_mod.SiteConfig,
        recheck: bool,
    ) vfs_mod.Error!?site_pool_mod.Credentials {
        const core = state.owner.core;
        state.prompt_serial.lockUncancelable(io);
        defer state.prompt_serial.unlock(io);
        if (recheck) {
            if (try storedCreds(site, diag)) |creds| return creds;
        }
        const retry = core.promptPassword(site.site_id, cancel) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (!retry) return null;
        return try storedCreds(site, diag);
    }
};

/// The stored credential, or null when the store has nothing yet (the
/// caller decides whether that warrants a prompt). Other failures pass.
fn storedCreds(
    site: *const site_pool_mod.SiteConfig,
    diag: *Diagnostics,
) vfs_mod.Error!?site_pool_mod.Credentials {
    const provider = site.creds orelse return null;
    return provider.fetch(diag) catch |err| switch (err) {
        error.AuthRequired => null,
        else => |e| e,
    };
}

fn factoryConnect(
    ctx: *anyopaque,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
    role: site_pool_mod.Role,
) vfs_mod.Error!site_pool_mod.Conn {
    _ = role; // browse and transfer connections are protocol-identical
    const state: *SiteState = @ptrCast(@alignCast(ctx));
    return switch (site.protocol) {
        .sftp => connectSftp(state, io, cancel, diag, site),
        .ftp, .ftps => connectFtp(state, io, cancel, diag, site),
    };
}

// ---------------------------------------------------------------------------
// Host-key policy (SFTP)
// ---------------------------------------------------------------------------

pub const HostKeyOutcome = enum { accept, reject, prompt };

/// Pure policy over both files' verdicts: a revoked key always rejects; a
/// known key accepts; a MISMATCH rejects without a prompt (a changed key
/// is a MITM signal and must never look like first contact); only a host
/// neither file has seen prompts.
pub fn hostKeyOutcome(user_v: known_hosts.Verification, app_v: known_hosts.Verification) HostKeyOutcome {
    if (user_v == .revoked or app_v == .revoked) return .reject;
    if (user_v == .known or app_v == .known) return .accept;
    if (user_v == .mismatch or app_v == .mismatch) return .reject;
    return .prompt;
}

const HostKeyCtx = struct {
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
};

fn verifyHostKeyCb(context: *anyopaque, info: *const session_mod.HostKeyInfo) session_mod.HostKeyDecision {
    const hk: *HostKeyCtx = @ptrCast(@alignCast(context));
    return hostKeyDecision(hk.state, hk.io, hk.cancel, info) catch .unknown;
}

fn hostKeyDecision(
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
    info: *const session_mod.HostKeyInfo,
) error{ OutOfMemory, Canceled }!session_mod.HostKeyDecision {
    const factories = state.owner;
    const gpa = factories.gpa;
    const core = factories.core;

    const user_text: ?[]u8 = readUserKnownHosts(gpa, io);
    defer if (user_text) |text| gpa.free(text);
    const app_text: ?[]u8 =
        core.config_dir.readFileAlloc(io, known_hosts_file, gpa, .unlimited) catch null;
    defer if (app_text) |text| gpa.free(text);

    const user_v = try known_hosts.verify(gpa, user_text orelse "", info.host, info.port, info.key_blob);
    const app_v = try known_hosts.verify(gpa, app_text orelse "", info.host, info.port, info.key_blob);
    switch (hostKeyOutcome(user_v, app_v)) {
        .accept => return .accept,
        .reject => return .reject,
        .prompt => {},
    }

    const accepted = core.askPrompt(state.site_id, .{ .host_key = .{
        .fingerprint = info.sha256_fp[0..],
        .host = info.host,
    } }, cancel) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (!accepted) return .unknown; // engine classifies .auth (trust prompt declined)
    // Persist; a write failure degrades to accept-once.
    factories.appendKnownHost(io, info) catch {};
    return .accept;
}

fn readUserKnownHosts(gpa: Allocator, io: std.Io) ?[]u8 {
    const home = std.c.getenv("HOME") orelse return null;
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/known_hosts", .{std.mem.span(home)}) catch
        return null;
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch null;
}

// ---------------------------------------------------------------------------
// Proxy plan (SFTP): per-site override or ~/.ssh/config ProxyJump /
// ProxyCommand, executed via session.zig's Jump/Command transports.
// ---------------------------------------------------------------------------

/// Hard cap on chained jump hops (cycle/typo guard; OpenSSH has no fixed
/// limit but each hop costs a session + pump thread).
pub const max_jump_hops = 4;

pub const ProxyPlan = struct {
    arena: std.heap.ArenaAllocator,
    /// Set = spawn this ProxyCommand; hops is empty then.
    command: ?[]const u8,
    /// ProxyJump chain in connection order; empty = direct.
    hops: []const ssh_config_mod.Hop,

    pub fn active(p: *const ProxyPlan) bool {
        return p.command != null or p.hops.len > 0;
    }

    pub fn deinit(p: *ProxyPlan) void {
        p.arena.deinit();
        p.* = undefined;
    }
};

/// Pure plan derivation (headless-tested): the explicit per-site fields
/// win — ProxyJump over ProxyCommand, "none" disables everything — and
/// only when both are unset is `config_text` (the user's ~/.ssh/config)
/// consulted for `host`, hops first (mirroring the per-site precedence).
pub fn buildProxyPlan(
    gpa: Allocator,
    explicit_jump: []const u8,
    explicit_command: []const u8,
    config_text: ?[]const u8,
    host: []const u8,
    home: []const u8,
) error{OutOfMemory}!ProxyPlan {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    if (explicit_jump.len > 0) {
        // Reuse ssh_config's hop grammar via a one-directive config; the
        // synthetic directive precedes any Host block so it matches all.
        var text_buf: [proxy_jump_max + 16]u8 = undefined;
        const text = std.fmt.bufPrint(&text_buf, "ProxyJump {s}", .{explicit_jump}) catch
            unreachable; // proxy_jump_max bounds the snapshot
        const hops = try resolveHops(gpa, a, text, host, home);
        return .{ .arena = arena, .command = null, .hops = hops };
    }
    if (explicit_command.len > 0) {
        const cmd = try a.dupe(u8, explicit_command);
        return .{ .arena = arena, .command = cmd, .hops = &.{} };
    }

    const text = config_text orelse
        return .{ .arena = arena, .command = null, .hops = &.{} };
    var cfg = try ssh_config_mod.parse(gpa, text, .none);
    defer cfg.deinit();
    var eff = try cfg.resolve(gpa, host, .{ .home = home });
    defer eff.deinit();
    if (eff.proxy_jump.len > 0) {
        const hops = try dupeHops(a, eff.proxy_jump);
        return .{ .arena = arena, .command = null, .hops = hops };
    }
    if (eff.proxy_command) |cmd| {
        // Allocation must precede the literal: `.arena = arena` copies the
        // arena state (same rule as ssh_config.resolve).
        const cmd_copy = try a.dupe(u8, cmd);
        return .{ .arena = arena, .command = cmd_copy, .hops = &.{} };
    }
    return .{ .arena = arena, .command = null, .hops = &.{} };
}

fn resolveHops(
    gpa: Allocator,
    a: Allocator,
    config_text: []const u8,
    host: []const u8,
    home: []const u8,
) error{OutOfMemory}![]const ssh_config_mod.Hop {
    var cfg = try ssh_config_mod.parse(gpa, config_text, .none);
    defer cfg.deinit();
    var eff = try cfg.resolve(gpa, host, .{ .home = home });
    defer eff.deinit();
    return dupeHops(a, eff.proxy_jump);
}

fn dupeHops(a: Allocator, hops: []const ssh_config_mod.Hop) error{OutOfMemory}![]const ssh_config_mod.Hop {
    const out = try a.alloc(ssh_config_mod.Hop, hops.len);
    for (hops, out) |src, *dst| {
        dst.* = .{
            .user = if (src.user) |u| try a.dupe(u8, u) else null,
            .host = try a.dupe(u8, src.host),
            .port = src.port,
        };
    }
    return out;
}

fn homeDir() []const u8 {
    const home = std.c.getenv("HOME") orelse return "";
    return std.mem.span(home);
}

fn userSshConfigText(gpa: Allocator, io: std.Io) ?[]u8 {
    const home = homeDir();
    if (home.len == 0) return null;
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/config", .{home}) catch return null;
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch null;
}

/// Everything a proxied SFTP connection owns underneath its SshSession.
/// Teardown (reverse of construction): jump transports target-first, then
/// the ProxyCommand child, then the base TCP stream.
const ProxyChainState = struct {
    base_stream: ?std.Io.net.Stream = null,
    command: ?*session_mod.CommandTransport = null,
    jumps: [max_jump_hops]*session_mod.JumpTransport = undefined,
    jump_len: usize = 0,

    fn deinit(chain: *ProxyChainState, io: std.Io) void {
        var i = chain.jump_len;
        while (i > 0) {
            i -= 1;
            chain.jumps[i].deinit();
        }
        chain.jump_len = 0;
        if (chain.command) |ct| {
            ct.deinit();
            chain.command = null;
        }
        if (chain.base_stream) |stream| {
            stream.close(io);
            chain.base_stream = null;
        }
    }
};

// ---------------------------------------------------------------------------
// SFTP connect
// ---------------------------------------------------------------------------

fn mapSessionError(err: session_mod.Error) vfs_mod.Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.ConnectionLost => error.ConnectionLost,
        error.Timeout => error.Timeout,
        error.ProtocolViolation => error.ProtocolViolation,
        error.HostKeyRejected, error.HostKeyUnknown, error.AuthFailed => error.AuthRequired,
        error.OutOfMemory => error.OutOfMemory,
        error.Unexpected => error.Unexpected,
    };
}

const SftpConnState = struct {
    gpa: Allocator,
    chain: ProxyChainState,
    session: session_mod.SshSession,
    client: sftp_client_mod.SftpClient,
};

/// Connect a TCP stream to host:port. `host` may be an IP literal OR a DNS
/// name — IpAddress.resolve parses literals only (it does NOT do DNS), so a
/// hostname must go through HostName.connect (which does the lookup +
/// happy-eyeballs). This is the single dial seam for every protocol.
fn dialTcp(
    io: std.Io,
    diag: *Diagnostics,
    host: []const u8,
    port: u16,
) vfs_mod.Error!std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream }) catch {
            diag.set(.transient, 0, "could not connect to {s}:{d}", .{ host, port });
            return error.ConnectionLost;
        };
    } else |_| {
        const name = std.Io.net.HostName.init(host) catch {
            diag.set(.transient, 0, "invalid host name {s}", .{host});
            return error.Unexpected;
        };
        return name.connect(io, port, .{ .mode = .stream }) catch {
            diag.set(.transient, 0, "could not resolve/connect {s}:{d}", .{ host, port });
            return error.ConnectionLost;
        };
    }
}

/// Builds the transport chain per the plan and returns the fd the target
/// session runs over. On error every partial resource is already in
/// `chain` for the caller's cleanup.
fn establishProxyChain(
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
    plan: *const ProxyPlan,
    login_user: []const u8,
    chain: *ProxyChainState,
    callbacks: session_mod.Callbacks,
) vfs_mod.Error!std.posix.fd_t {
    const gpa = state.owner.gpa;

    if (plan.command) |cmd| {
        const ct = session_mod.CommandTransport.spawn(gpa, io, cmd, site.host, site.port, diag) catch |err|
            return mapSessionError(err);
        chain.command = ct;
        return ct.target_fd;
    }
    if (plan.hops.len == 0) {
        const stream = try dialTcp(io, diag, site.host, site.port);
        chain.base_stream = stream;
        return stream.socket.handle;
    }
    if (plan.hops.len > max_jump_hops) {
        diag.set(.permanent, 0, "ProxyJump chain too long ({d} hops; limit {d})", .{
            plan.hops.len, max_jump_hops,
        });
        return error.Unexpected;
    }

    var fd: std.posix.fd_t = undefined;
    for (plan.hops, 0..) |hop, i| {
        const hop_port = hop.port orelse 22;
        if (i == 0) {
            const stream = try dialTcp(io, diag, hop.host, hop_port);
            chain.base_stream = stream;
            fd = stream.socket.handle;
        }
        // Host key verification runs per hop (the info carries the hop's
        // host:port, so known_hosts lookups and trust prompts are per hop).
        var hop_session = session_mod.SshSession.init(
            gpa,
            io,
            fd,
            hop.host,
            hop_port,
            cancel,
            diag,
            callbacks,
        ) catch |err| return mapSessionError(err);
        // Jump hosts authenticate via the non-interactive chain: agent +
        // default ~/.ssh keys (password rescue stays target-only for now).
        var ssh_dir_buf: [1024]u8 = undefined;
        hop_session.authenticate(cancel, diag, .{
            .username = hop.user orelse login_user,
            .try_agent = true,
            .ssh_dir = sshDir(&ssh_dir_buf),
        }) catch |err| {
            hop_session.deinit();
            return mapSessionError(err);
        };
        const next_host = if (i + 1 < plan.hops.len) plan.hops[i + 1].host else site.host;
        const next_port = if (i + 1 < plan.hops.len) plan.hops[i + 1].port orelse 22 else site.port;
        const jt = session_mod.JumpTransport.open(
            gpa,
            hop_session,
            next_host,
            next_port,
            cancel,
            diag,
        ) catch |err| return mapSessionError(err);
        chain.jumps[chain.jump_len] = jt;
        chain.jump_len += 1;
        fd = jt.target_fd;
    }
    return fd;
}

fn connectSftp(
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
) vfs_mod.Error!site_pool_mod.Conn {
    const factories = state.owner;
    const gpa = factories.gpa;
    const core = factories.core;

    var user_buf: [256]u8 = undefined;
    var host_buf: [256]u8 = undefined;
    const login = core.copySiteLogin(site.site_id, &user_buf, &host_buf) orelse {
        diag.set(.permanent, 0, "site {d} is not in the site list", .{site.site_id});
        return error.Unexpected;
    };

    var meta_bufs: SiteState.SnapshotBufs = undefined;
    const meta = state.authSnapshot(&meta_bufs);

    var stored = try storedCreds(site, diag);
    if (stored == null and meta.method == .password) {
        // Password sites prompt before dialing (no point handshaking
        // without a secret); agent/key sites try their chain first.
        stored = try state.promptForSecret(io, cancel, diag, site, true);
        if (stored == null) {
            diag.set(.auth, 0, "no credential for {s}@{s} (prompt declined)", .{ login.user, login.host });
            return error.AuthRequired;
        }
    }

    var plan = blk: {
        const config_text = userSshConfigText(gpa, io);
        defer if (config_text) |text| gpa.free(text);
        break :blk try buildProxyPlan(
            gpa,
            meta.proxy_jump,
            meta.proxy_command,
            config_text,
            site.host,
            homeDir(),
        );
    };
    defer plan.deinit();

    const conn = gpa.create(SftpConnState) catch return error.OutOfMemory;
    errdefer gpa.destroy(conn);
    conn.gpa = gpa;
    conn.chain = .{};
    var chain_owned = true;
    defer if (chain_owned) conn.chain.deinit(io);

    var hk_ctx: HostKeyCtx = .{ .state = state, .io = io, .cancel = cancel };
    const callbacks: session_mod.Callbacks = .{
        .context = @ptrCast(&hk_ctx),
        .verifyHostKey = verifyHostKeyCb,
    };

    const target_fd = try establishProxyChain(
        state,
        io,
        cancel,
        diag,
        site,
        &plan,
        login.user,
        &conn.chain,
        callbacks,
    );

    conn.session = session_mod.SshSession.init(
        gpa,
        io,
        target_fd,
        site.host,
        site.port,
        cancel,
        diag,
        callbacks,
    ) catch |err| return mapSessionError(err);
    errdefer conn.session.deinit();

    var ssh_dir_buf: [1024]u8 = undefined;
    const ssh_dir: ?[]const u8 = if (meta.method == .agent) sshDir(&ssh_dir_buf) else null;

    var key_bytes: ?[]u8 = null;
    defer if (key_bytes) |bytes| {
        std.crypto.secureZero(u8, bytes);
        gpa.free(bytes);
    };
    if (meta.method == .key_file and meta.key_path.len > 0) {
        key_bytes = std.Io.Dir.cwd().readFileAlloc(io, meta.key_path, gpa, .unlimited) catch null;
        if (key_bytes == null)
            diag.set(.auth, 0, "could not read the key file {s}", .{meta.key_path});
    }

    conn.session.authenticate(cancel, diag, .{
        .username = if (stored) |creds| creds.user else login.user,
        .try_agent = meta.method == .agent,
        .key = if (key_bytes) |bytes| .{
            .file_bytes = bytes,
            .passphrase = if (stored) |creds| creds.secret else null,
            .label = meta.key_path,
        } else null,
        .ssh_dir = ssh_dir,
        .password = if (stored) |creds| creds.secret else null,
    }) catch |err| switch (err) {
        error.AuthFailed => {
            // Password rescue: a missing or refused secret raises the
            // sheet and retries once on the same session.
            if (stored != null) core.invalidateSiteSecret(site.site_id);
            const fresh = (try state.promptForSecret(io, cancel, diag, site, stored == null)) orelse
                return mapSessionError(err);
            conn.session.authenticate(cancel, diag, .{
                .username = fresh.user,
                .try_agent = false,
                .password = fresh.secret,
            }) catch |retry_err| return mapSessionError(retry_err);
        },
        else => return mapSessionError(err),
    };

    conn.client = try sftp_client_mod.SftpClient.init(&conn.session, cancel, diag);

    chain_owned = false; // the Conn owns everything from here
    return .{
        .engine = .{ .sftp = &conn.client },
        .ctx = @ptrCast(conn),
        .vtable = &sftp_conn_vtable,
    };
}

fn sshDir(buf: *[1024]u8) ?[]const u8 {
    const home = std.c.getenv("HOME") orelse return null;
    return std.fmt.bufPrint(buf, "{s}/.ssh", .{std.mem.span(home)}) catch null;
}

const sftp_conn_vtable: site_pool_mod.Conn.VTable = .{
    .noop = sftpNoop,
    .alive = sftpAlive,
    .close = sftpClose,
};

fn sftpStateOf(ctx: *anyopaque) *SftpConnState {
    return @ptrCast(@alignCast(ctx));
}

fn sftpNoop(ctx: *anyopaque, _: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs_mod.Error!void {
    var buf: [1024]u8 = undefined;
    _ = try sftpStateOf(ctx).client.realpath(cancel, diag, ".", &buf);
}

fn sftpAlive(_: *anyopaque) bool {
    return true; // keepalive NOOPs discover drops
}

fn sftpClose(ctx: *anyopaque, io: std.Io) void {
    const conn = sftpStateOf(ctx);
    conn.client.deinit();
    // Target session first: its disconnect flows through the still-live
    // proxy pumps; then the chain (jumps target-first, command, stream).
    conn.session.deinit();
    conn.chain.deinit(io);
    conn.gpa.destroy(conn);
}

// ---------------------------------------------------------------------------
// FTP / FTPS connect
// ---------------------------------------------------------------------------

/// Port 990 is TLS-from-the-first-byte (legacy implicit FTPS); everything
/// else upgrades via AUTH TLS (FTPES, RFC 4217).
pub fn ftpsTlsMode(port: u16) ftp_client_mod.TlsMode {
    return if (port == 990) .implicit else .explicit;
}

const FtpConnState = struct {
    gpa: Allocator,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    rbuf: [8 * 1024]u8,
    wbuf: [1024]u8,
    client: ftp_client_mod.FtpClient,
};

fn connectFtp(
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
) vfs_mod.Error!site_pool_mod.Conn {
    const core = state.owner.core;

    var creds = (try storedCreds(site, diag)) orelse blk: {
        var user_buf: [256]u8 = undefined;
        var host_buf: [256]u8 = undefined;
        const login = core.copySiteLogin(site.site_id, &user_buf, &host_buf);
        const account = if (login) |l| l.user else "";
        if (account.len == 0 or std.mem.eql(u8, account, "anonymous")) break :blk anonymous_creds;
        break :blk (try state.promptForSecret(io, cancel, diag, site, true)) orelse {
            diag.set(.auth, 0, "no credential for {s}@{s} (prompt declined)", .{ account, site.host });
            return error.AuthRequired;
        };
    };

    var prompted = false;
    while (true) {
        if (dialFtp(state, io, cancel, diag, site, creds)) |conn| {
            return conn;
        } else |err| switch (err) {
            error.AuthRequired => {
                // The server refused the login: one sheet, one retry.
                if (prompted) return err;
                prompted = true;
                core.invalidateSiteSecret(site.site_id);
                creds = (try state.promptForSecret(io, cancel, diag, site, false)) orelse return err;
            },
            else => |other| return other,
        }
    }
}

fn dialFtp(
    state: *SiteState,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    site: *const site_pool_mod.SiteConfig,
    creds: site_pool_mod.Credentials,
) vfs_mod.Error!site_pool_mod.Conn {
    const factories = state.owner;
    const gpa = factories.gpa;

    cancel.check() catch {
        diag.set(.cancel, 0, "connect canceled", .{});
        return error.Canceled;
    };
    const tls: ?tls_provider_mod.TlsProvider =
        if (site.protocol == .ftps) try state.tlsFor(diag) else null;

    const stream = try dialTcp(io, diag, site.host, site.port);
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);

    const conn = gpa.create(FtpConnState) catch return error.OutOfMemory;
    errdefer gpa.destroy(conn);
    conn.gpa = gpa;
    conn.stream = stream;
    conn.reader = .init(stream, io, &conn.rbuf);
    conn.writer = .init(stream, io, &conn.wbuf);
    conn.client = ftp_client_mod.FtpClient.init(
        gpa,
        &conn.reader.interface,
        &conn.writer.interface,
        .{ .context = @ptrCast(factories), .dialFn = dataDial },
        &factories.core.transcript,
        .{
            .host = site.host,
            .tls = tls,
            .tls_mode = if (site.protocol == .ftps) ftpsTlsMode(site.port) else .none,
            .control_fd = stream.socket.handle,
            .insecure_skip_verify = state.insecureSkipVerify(),
        },
    );
    errdefer conn.client.deinit();

    try conn.client.connect(io, cancel, diag, .{ .user = creds.user, .pass = creds.secret });

    stream_owned = false; // the Conn owns everything from here
    return .{
        .engine = .{ .ftp = &conn.client },
        .ctx = @ptrCast(conn),
        .vtable = &ftp_conn_vtable,
    };
}

const ftp_conn_vtable: site_pool_mod.Conn.VTable = .{
    .noop = ftpNoop,
    .alive = ftpAlive,
    .close = ftpClose,
};

fn ftpStateOf(ctx: *anyopaque) *FtpConnState {
    return @ptrCast(@alignCast(ctx));
}

fn ftpNoop(ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *Diagnostics) vfs_mod.Error!void {
    return ftpStateOf(ctx).client.noop(io, cancel, diag);
}

fn ftpAlive(_: *anyopaque) bool {
    return true; // keepalive NOOPs discover drops
}

fn ftpClose(ctx: *anyopaque, io: std.Io) void {
    const conn = ftpStateOf(ctx);
    // No QUIT courtesy: close must be safe (and fast) on dead connections.
    conn.client.deinit();
    conn.stream.close(io);
    conn.gpa.destroy(conn);
}

// --- PASV/EPSV data connections (real TCP dialer behind the seam) ----------

const DataState = struct {
    gpa: Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    write_closed: bool,
    rbuf: [32 * 1024]u8,
    wbuf: [8 * 1024]u8,
};

fn dataDial(
    ctx: *anyopaque,
    io: std.Io,
    cancel: *CancelToken,
    diag: *Diagnostics,
    host: []const u8,
    port: u16,
) data_conn_mod.DialError!data_conn_mod.DataConn {
    const factories: *Factories = @ptrCast(@alignCast(ctx));
    cancel.check() catch {
        diag.set(.cancel, 0, "data connection dial canceled", .{});
        return error.Canceled;
    };
    // host is usually a PASV IP literal, but EPSV dials the control host,
    // which may be a DNS name — handle both (IpAddress.resolve is literal-only).
    const stream = blk: {
        if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
            break :blk addr.connect(io, .{ .mode = .stream }) catch {
                diag.set(.transient, 0, "could not open the data connection to {s}:{d}", .{ host, port });
                return error.ConnectionRefused;
            };
        } else |_| {
            const name = std.Io.net.HostName.init(host) catch {
                diag.set(.transient, 0, "invalid data host {s}", .{host});
                return error.ConnectionRefused;
            };
            break :blk name.connect(io, port, .{ .mode = .stream }) catch {
                diag.set(.transient, 0, "could not open the data connection to {s}:{d}", .{ host, port });
                return error.ConnectionRefused;
            };
        }
    };
    const data = factories.gpa.create(DataState) catch {
        stream.close(io);
        return error.Unexpected;
    };
    data.gpa = factories.gpa;
    data.io = io;
    data.stream = stream;
    data.write_closed = false;
    data.reader = .init(stream, io, &data.rbuf);
    data.writer = .init(stream, io, &data.wbuf);
    return .{
        .reader = &data.reader.interface,
        .writer = &data.writer.interface,
        .context = @ptrCast(data),
        .vtable = &data_vtable,
        .fd = stream.socket.handle, // FTPS: the TLS handshake needs it
    };
}

const data_vtable: data_conn_mod.DataConn.VTable = .{
    .closeWrite = dataCloseWrite,
    .close = dataClose,
};

fn dataStateOf(ctx: *anyopaque) *DataState {
    return @ptrCast(@alignCast(ctx));
}

fn dataCloseWrite(ctx: *anyopaque) std.Io.Writer.Error!void {
    const data = dataStateOf(ctx);
    if (data.write_closed) return;
    data.write_closed = true;
    data.writer.interface.flush() catch return error.WriteFailed;
    data.stream.shutdown(data.io, .send) catch {}; // half-close marks EOF
}

fn dataClose(ctx: *anyopaque) void {
    const data = dataStateOf(ctx);
    data.stream.close(data.io);
    data.gpa.destroy(data);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// See events.zig for the 0.16 lock-choice rationale.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn copyClamped(buf: []u8, src: []const u8) usize {
    const n = @min(src.len, buf.len);
    @memcpy(buf[0..n], src[0..n]);
    return n;
}

// ---------------------------------------------------------------------------
// Tests — headless: pure policy + per-site state plumbing. The live
// connect sequences are covered by `zig build run -- --smoke-sftp`
// (dockerized OpenSSH) and real-server runs.
// ---------------------------------------------------------------------------

const testing = std.testing;
const FakeStore = relay.cred.fake.FakeStore;

test "ftpsTlsMode: implicit only on 990" {
    try testing.expectEqual(ftp_client_mod.TlsMode.implicit, ftpsTlsMode(990));
    try testing.expectEqual(ftp_client_mod.TlsMode.explicit, ftpsTlsMode(21));
    try testing.expectEqual(ftp_client_mod.TlsMode.explicit, ftpsTlsMode(2121));
}

test "hostKeyOutcome: revoked > known > mismatch > unknown, across both files" {
    const info: known_hosts.MatchInfo = .{ .line_number = 1, .key_type = "ssh-ed25519" };
    const known: known_hosts.Verification = .{ .known = info };
    const mismatch: known_hosts.Verification = .{ .mismatch = info };
    const revoked: known_hosts.Verification = .{ .revoked = info };
    const unknown: known_hosts.Verification = .unknown;

    try testing.expectEqual(HostKeyOutcome.prompt, hostKeyOutcome(unknown, unknown));
    try testing.expectEqual(HostKeyOutcome.accept, hostKeyOutcome(known, unknown));
    try testing.expectEqual(HostKeyOutcome.accept, hostKeyOutcome(unknown, known));
    // The app file may know a host the user file has never seen — and a
    // key the USER file calls changed while the app file vouches for it
    // still accepts (multiple known_hosts files, OpenSSH semantics).
    try testing.expectEqual(HostKeyOutcome.accept, hostKeyOutcome(mismatch, known));
    try testing.expectEqual(HostKeyOutcome.reject, hostKeyOutcome(mismatch, unknown));
    try testing.expectEqual(HostKeyOutcome.reject, hostKeyOutcome(unknown, mismatch));
    // Revocation vetoes everything.
    try testing.expectEqual(HostKeyOutcome.reject, hostKeyOutcome(revoked, known));
    try testing.expectEqual(HostKeyOutcome.reject, hostKeyOutcome(known, revoked));
}

test "Factories: one state per site id, refreshed auth meta via meta_lookup" {
    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(testing.allocator);
    defer fake.deinit();
    const core = try bridge.AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });
    defer core.shutdown();

    const factories = try Factories.create(testing.allocator, core);
    defer factories.destroy();

    const Meta = struct {
        var choice: ?AuthChoice = null;
        fn get(_: ?*anyopaque, site_id: u64) ?AuthChoice {
            return if (site_id == 7) choice else null;
        }
    };
    factories.meta_lookup = .{ .ctx = null, .get = Meta.get };

    const site: sites_mod.Site = .{ .id = 7, .protocol = .sftp, .host = "h.example" };

    Meta.choice = null;
    const f1 = factories.provider().makeFn(@ptrCast(factories), &site);
    const state: *SiteState = @ptrCast(@alignCast(f1.ctx));
    try testing.expectEqual(@as(usize, 1), factories.states.items.len);
    try testing.expectEqual(AuthMethod.agent, state.method); // sftp default

    // Same site id reuses the state; the meta snapshot refreshes.
    Meta.choice = .{
        .method = .key_file,
        .key_path = "/keys/deploy_ed25519",
        .proxy_jump = "alice@bastion:2222",
        .proxy_command = "nc %h %p",
    };
    const f2 = factories.provider().makeFn(@ptrCast(factories), &site);
    try testing.expectEqual(f1.ctx, f2.ctx);
    try testing.expectEqual(@as(usize, 1), factories.states.items.len);
    var snap_bufs: SiteState.SnapshotBufs = undefined;
    const snap = state.authSnapshot(&snap_bufs);
    try testing.expectEqual(AuthMethod.key_file, snap.method);
    try testing.expectEqualStrings("/keys/deploy_ed25519", snap.key_path);
    try testing.expectEqualStrings("alice@bastion:2222", snap.proxy_jump);
    try testing.expectEqualStrings("nc %h %p", snap.proxy_command);

    // FTP sites default to password auth; a second id gets its own state.
    const ftp_site: sites_mod.Site = .{ .id = 8, .protocol = .ftp, .host = "f.example" };
    const f3 = factories.provider().makeFn(@ptrCast(factories), &ftp_site);
    try testing.expect(f3.ctx != f1.ctx);
    try testing.expectEqual(@as(usize, 2), factories.states.items.len);
    const ftp_state: *SiteState = @ptrCast(@alignCast(f3.ctx));
    try testing.expectEqual(AuthMethod.password, ftp_state.method);
}

test "buildProxyPlan: explicit per-site fields win; 'none' disables" {
    const gpa = testing.allocator;
    const cfg = "Host *\n  ProxyJump config-bastion\n";

    // Explicit multi-hop jump beats both the config and the explicit command.
    var jump = try buildProxyPlan(gpa, "alice@b1:2222,b2", "nc %h %p", cfg, "h.example", "/h");
    defer jump.deinit();
    try testing.expect(jump.active());
    try testing.expectEqual(@as(?[]const u8, null), jump.command);
    try testing.expectEqual(@as(usize, 2), jump.hops.len);
    try testing.expectEqualStrings("alice", jump.hops[0].user.?);
    try testing.expectEqualStrings("b1", jump.hops[0].host);
    try testing.expectEqual(@as(?u16, 2222), jump.hops[0].port);
    try testing.expectEqualStrings("b2", jump.hops[1].host);
    try testing.expectEqual(@as(?u16, null), jump.hops[1].port);

    // Explicit command (no explicit jump) beats the config.
    var cmd = try buildProxyPlan(gpa, "", "ssh -W %h:%p gw", cfg, "h.example", "/h");
    defer cmd.deinit();
    try testing.expect(cmd.active());
    try testing.expectEqualStrings("ssh -W %h:%p gw", cmd.command.?);
    try testing.expectEqual(@as(usize, 0), cmd.hops.len);

    // Explicit "none" disables proxying entirely, config notwithstanding.
    var none = try buildProxyPlan(gpa, "none", "", cfg, "h.example", "/h");
    defer none.deinit();
    try testing.expect(!none.active());
}

test "buildProxyPlan: ~/.ssh/config fallback, host-scoped" {
    const gpa = testing.allocator;
    const cfg =
        \\Host jumped.example.com
        \\  ProxyJump alice@bastion.example.com:2222
        \\Host commanded.example.com
        \\  ProxyCommand nc -x proxy:1080 %h %p
        \\Host direct.example.com
        \\  Port 2022
    ;

    var jump = try buildProxyPlan(gpa, "", "", cfg, "jumped.example.com", "/h");
    defer jump.deinit();
    try testing.expectEqual(@as(usize, 1), jump.hops.len);
    try testing.expectEqualStrings("bastion.example.com", jump.hops[0].host);
    try testing.expectEqual(@as(?u16, 2222), jump.hops[0].port);
    try testing.expectEqualStrings("alice", jump.hops[0].user.?);

    var cmd = try buildProxyPlan(gpa, "", "", cfg, "commanded.example.com", "/h");
    defer cmd.deinit();
    try testing.expectEqualStrings("nc -x proxy:1080 %h %p", cmd.command.?);

    var direct = try buildProxyPlan(gpa, "", "", cfg, "direct.example.com", "/h");
    defer direct.deinit();
    try testing.expect(!direct.active());

    var no_cfg = try buildProxyPlan(gpa, "", "", null, "jumped.example.com", "/h");
    defer no_cfg.deinit();
    try testing.expect(!no_cfg.active());
}

test "buildProxyPlan survives allocation failure" {
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var plan = try buildProxyPlan(
                gpa,
                "alice@b1:2222,b2",
                "",
                "Host *\n  ProxyJump cfg\n",
                "h.example",
                "/h",
            );
            plan.deinit();
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Check.run, .{});
}

test "appendKnownHost: accepted keys land in the app file and verify as known" {
    var tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_conf.cleanup();
    var tmp_root = std.testing.tmpDir(.{ .iterate = true });
    defer tmp_root.cleanup();
    var fake = FakeStore.init(testing.allocator);
    defer fake.deinit();
    const core = try bridge.AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = tmp_conf.dir,
        .local_root = tmp_root.dir,
        .cred_store = fake.credStore(),
    });
    defer core.shutdown();
    const factories = try Factories.create(testing.allocator, core);
    defer factories.destroy();
    const io = core.io;

    // Minimal ssh-ed25519 wire blob: len+name, len+32-byte key.
    var blob_buf: [4 + 11 + 4 + 32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&blob_buf);
    try w.writeInt(u32, 11, .big);
    try w.writeAll("ssh-ed25519");
    try w.writeInt(u32, 32, .big);
    try w.splatByteAll(0xab, 32);
    const blob = w.buffered();

    const info: session_mod.HostKeyInfo = .{
        .host = "kh.example",
        .port = 2222,
        .key_type = "ssh-ed25519",
        .key_blob = blob,
        .sha256_fp = undefined,
    };
    try factories.appendKnownHost(io, &info);
    try factories.appendKnownHost(io, &info); // appends, never clobbers

    const text = try core.config_dir.readFileAlloc(io, known_hosts_file, testing.allocator, .unlimited);
    defer testing.allocator.free(text);
    const v = try known_hosts.verify(testing.allocator, text, "kh.example", 2222, blob);
    try testing.expect(v == .known);
    // Same host, different port: unknown (the [host]:port canonical form).
    const v22 = try known_hosts.verify(testing.allocator, text, "kh.example", 22, blob);
    try testing.expect(v22 == .unknown);
}

test {
    testing.refAllDecls(@This());
}

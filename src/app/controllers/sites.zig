//! sites — sidebar + sites + connect flows (M2).
//!
//! Owns the source-list sidebar (outline_view wrapper) with three sections:
//!
//!  - **Servers** — saved sites (sites.zon CRUD through settings/sites.zig;
//!    add/edit/delete via the context menu — the spec's "+" footer button
//!    needs a button wrapper relay_mac does not expose yet, so Add Site…
//!    additionally lives in the background context menu, the Server menu
//!    items, and the public `addSite()` API for phase 3 to bind).
//!  - **SSH Config** — read-only smart group parsed from ~/.ssh/config via
//!    proto/ssh/ssh_config.zig (concrete Host aliases only; wildcard and
//!    negated patterns are skipped). Section headers are group rows and not
//!    selectable in the wrapper, so the refresh rides on the context menu
//!    ("Refresh SSH Config"), `refreshSshConfig()`, and controller startup
//!    instead of header selection. Connecting a row materializes an
//!    ephemeral site (protocol sftp, fields from the resolved config);
//!    "Save as Site…" opens the editor prefilled.
//!  - **History** — recent (site, path) pairs, newest first, persisted next
//!    to the settings as history.zon in the Application Support dir.
//!
//! Connect flow: Return/double-click connects in the ACTIVE pane
//! (bridge.connectSite + listPath of the initial dir); `site_status` events
//! are tracked per site (sidebar status dot; the path-bar chip reads
//! `siteStatus()`); `prompt_needed` events present host-key / password /
//! keyboard-interactive sheets and reply through bridge.respondPrompt —
//! host-key acceptance persists via the core callback reply (known_hosts
//! append happens core-side once the M2 factories land). Quick Connect
//! (Cmd+K via `serverMenuItems`) accepts sftp:// | ftps:// | ftp:// URLs
//! and bare ssh-config aliases, with a save-as-site choice. Disconnect is
//! Cmd+Shift+K (`disconnectActivePane`), the sidebar context menu's
//! Disconnect on connected rows, and File ▸ Disconnect All
//! (`disconnectAll`).
//!
//! Secrets: passwords go ONLY to the cred store (Keychain) — never to
//! sites.zon. "Save in Keychain: No" stores the secret transiently (the
//! bridge's CredProvider can only fetch from the store) and deletes it as
//! soon as the connect attempt resolves (connected/offline). The site
//! editor's auth metadata (method + key file path) has no slot in the M1
//! Site schema, so it persists in this controller's own sites_meta.zon.
//!
//! Laws honored: zero raw msgSends (only relay_mac wrappers), UI state
//! mutates on the main thread only (all entry points are main-thread:
//! outline callbacks, sheet completions, bridge listener dispatch).

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");

const objc = mac.objc;
const c = mac.runtime.c;

const Allocator = std.mem.Allocator;
const Window = mac.appkit.window.Window;
const panels = mac.appkit.panels;
const menu_mod = mac.appkit.menu;
const outline_mod = mac.appkit.outline_view;

const sites_mod = relay.sites;
const settings_mod = relay.settings;
const events_mod = relay.events;
const cred_store_mod = relay.cred.store;
const ssh_config_mod = relay.ssh.ssh_config;
const Diagnostics = relay.diag.Diagnostics;

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

pub const section_servers: usize = 0;
pub const section_ssh: usize = 1;
pub const section_history: usize = 2;
pub const section_count: usize = 3;

pub const history_file = "history.zon";
pub const meta_file = "sites_meta.zon";

/// Standalone fallback (no PaneHost wired — headless tests): an opaque
/// routing key for pane_sites/listPath. No browser pane exists in that
/// configuration, so it never has to match a real (allocated) pane token.
pub const default_pane_token: bridge.PaneToken = 1;

/// Injected by phase 3's window assembly so connects land in the ACTIVE
/// pane (docs/UX.md). Defaults keep the controller usable standalone.
pub const PaneHost = struct {
    ctx: ?*anyopaque = null,
    /// Which pane receives the connect + initial listing.
    active_token: ?*const fn (ctx: ?*anyopaque) bridge.PaneToken = null,
    /// Fired before connectSite so the pane can bind its status chip.
    connecting: ?*const fn (ctx: ?*anyopaque, pane: bridge.PaneToken, site_id: u64) void = null,
    /// Drive the pane's own navigation to (site_id, path) so the listing is
    /// pane-owned (pending_request tracked, history recorded). When null,
    /// connectAndList falls back to a direct core.listPath on the token.
    navigate: ?*const fn (ctx: ?*anyopaque, pane: bridge.PaneToken, site_id: u64, path: []const u8) void = null,

    pub fn activeToken(self: PaneHost) bridge.PaneToken {
        const f = self.active_token orelse return default_pane_token;
        return f(self.ctx);
    }

    fn notifyConnecting(self: PaneHost, pane: bridge.PaneToken, site_id: u64) void {
        if (self.connecting) |f| f(self.ctx, pane, site_id);
    }
};

/// Editable site fields (everything but the stable id). Slices are borrowed
/// for the duration of the call; stores dupe what they keep.
pub const SiteFields = struct {
    name: []const u8 = "",
    protocol: sites_mod.Protocol = .sftp,
    host: []const u8,
    port: u16 = 0,
    account: []const u8 = "",
    initial_remote_path: []const u8 = "",
    initial_local_path: []const u8 = "",
    insecure_skip_verify: bool = false,
    /// Visual accent + deployment tag (phase 2; consumed by browser.zig —
    /// see its accentUiColor hook). The editor sheet preserves these like
    /// insecure_skip_verify until it grows controls for them.
    accent: sites_mod.Accent = .none,
    environment: sites_mod.Environment = .none,
};

pub const AuthMethod = enum { agent, key_file, password };

// ---------------------------------------------------------------------------
// Quick Connect target parsing (pure; headless-tested)
// ---------------------------------------------------------------------------

pub const UrlParts = struct {
    protocol: sites_mod.Protocol,
    user: []const u8 = "",
    host: []const u8,
    /// 0 = protocol default.
    port: u16 = 0,
    /// Includes the leading '/'; empty = none given.
    path: []const u8 = "",
};

pub const Target = union(enum) {
    url: UrlParts,
    alias: []const u8,
};

pub const ParseTargetError = error{
    EmptyInput,
    UnknownScheme,
    MissingHost,
    BadHost,
    BadPort,
    BadAlias,
};

/// Parses `sftp://user@host:port/path` (also ftps://, ftp://; IPv6 hosts in
/// brackets) or a bare ssh-config alias. Returned slices point into `raw`.
pub fn parseTarget(raw: []const u8) ParseTargetError!Target {
    const input = std.mem.trim(u8, raw, " \t\r\n");
    if (input.len == 0) return error.EmptyInput;

    const scheme_end = std.mem.indexOf(u8, input, "://") orelse {
        // Bare ssh-config alias: one word, no path separators.
        if (std.mem.indexOfAny(u8, input, " \t/") != null) return error.BadAlias;
        return .{ .alias = input };
    };

    const scheme = input[0..scheme_end];
    const protocol: sites_mod.Protocol = if (std.ascii.eqlIgnoreCase(scheme, "sftp"))
        .sftp
    else if (std.ascii.eqlIgnoreCase(scheme, "ftps"))
        .ftps
    else if (std.ascii.eqlIgnoreCase(scheme, "ftp"))
        .ftp
    else
        return error.UnknownScheme;

    var rest = input[scheme_end + 3 ..];
    var path: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        path = rest[slash..];
        rest = rest[0..slash];
    }

    var user: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
        user = rest[0..at];
        rest = rest[at + 1 ..];
    }

    var host: []const u8 = rest;
    var port: u16 = 0;
    if (rest.len > 0 and rest[0] == '[') {
        // IPv6 literal: [::1] or [::1]:2222
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return error.BadHost;
        host = rest[1..close];
        const after = rest[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return error.BadHost;
            port = portFromText(after[1..]) orelse return error.BadPort;
            if (port == 0) return error.BadPort;
        }
    } else if (std.mem.lastIndexOfScalar(u8, rest, ':')) |colon| {
        // Multiple colons without brackets = bare IPv6 (require brackets).
        if (std.mem.indexOfScalar(u8, rest, ':') != colon) return error.BadHost;
        host = rest[0..colon];
        port = portFromText(rest[colon + 1 ..]) orelse return error.BadPort;
        if (port == 0) return error.BadPort;
    }

    if (host.len == 0) return error.MissingHost;
    if (!hostValid(host)) return error.BadHost;
    return .{ .url = .{
        .protocol = protocol,
        .user = user,
        .host = host,
        .port = port,
        .path = path,
    } };
}

pub fn parseErrorMessage(err: ParseTargetError) []const u8 {
    return switch (err) {
        error.EmptyInput => "Enter a server URL or an ssh-config alias.",
        error.UnknownScheme => "Only sftp://, ftps:// and ftp:// URLs are supported.",
        error.MissingHost => "The URL is missing a host.",
        error.BadHost => "The host is malformed (bracket IPv6 literals: [::1]).",
        error.BadPort => "Port must be a number between 1 and 65535.",
        error.BadAlias => "An alias must be a single word without slashes.",
    };
}

/// Editor/Quick-Connect inline validation (host field).
pub fn hostValid(host: []const u8) bool {
    if (host.len == 0) return false;
    return std.mem.indexOfAny(u8, host, " \t/") == null;
}

/// "" = 0 (protocol default); otherwise 1..65535 or null (invalid).
pub fn portFromText(text: []const u8) ?u16 {
    if (text.len == 0) return 0;
    const v = std.fmt.parseInt(u16, text, 10) catch return null;
    if (v == 0) return null;
    return v;
}

pub fn siteLabel(site: sites_mod.Site) []const u8 {
    return if (site.name.len > 0) site.name else site.host;
}

fn credProtocol(p: sites_mod.Protocol) cred_store_mod.Protocol {
    return switch (p) {
        .ftp => .ftp,
        .ftps => .ftps,
        .sftp => .sftp,
    };
}

const protocol_titles = [_][]const u8{ "SFTP", "FTPS", "FTP" };
const auth_titles = [_][]const u8{ "SSH Agent", "Key File…", "Password" };

fn protocolTitle(p: sites_mod.Protocol) []const u8 {
    return switch (p) {
        .sftp => protocol_titles[0],
        .ftps => protocol_titles[1],
        .ftp => protocol_titles[2],
    };
}

fn protocolFromTitle(title: []const u8) sites_mod.Protocol {
    if (std.mem.eql(u8, title, protocol_titles[1])) return .ftps;
    if (std.mem.eql(u8, title, protocol_titles[2])) return .ftp;
    return .sftp;
}

fn authTitle(m: AuthMethod) []const u8 {
    return switch (m) {
        .agent => auth_titles[0],
        .key_file => auth_titles[1],
        .password => auth_titles[2],
    };
}

fn authFromTitle(title: []const u8) AuthMethod {
    if (std.mem.eql(u8, title, auth_titles[1])) return .key_file;
    if (std.mem.eql(u8, title, auth_titles[2])) return .password;
    return .agent;
}

// ---------------------------------------------------------------------------
// SiteStore — the mutable site list behind AppCore.site_list
// ---------------------------------------------------------------------------

/// Owns every site the app knows about: persisted sites (sites.zon) plus
/// ephemeral ones materialized from ssh-config rows / Quick Connect.
///
/// String storage is a GROW-ONLY arena: site pools borrow `site.host` for
/// their whole life (see bridge.createRuntimeLocked) and workers read
/// `AppCore.site_list` without a lock, so no site string and no published
/// `coreSlice` generation is ever freed before the store dies (well after
/// AppCore.shutdown). Edits allocate fresh strings; old ones just stay.
pub const SiteStore = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    entries: std.ArrayList(Entry) = .empty,
    next_id: u64 = 1,

    pub const Entry = struct {
        site: sites_mod.Site,
        /// false = ephemeral (ssh-config / unsaved quick connect): visible
        /// to the core for connects, excluded from sites.zon + sidebar.
        persisted: bool,
    };

    pub fn init(gpa: Allocator) SiteStore {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    pub fn deinit(self: *SiteStore) void {
        self.entries.deinit(self.gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Copies an existing list (AppCore's parse of sites.zon) into the
    /// store; ids are preserved and `next_id` continues after the max.
    pub fn loadFrom(self: *SiteStore, list: sites_mod.SiteList) error{OutOfMemory}!void {
        for (list.sites) |site| {
            const owned = try self.dupeSite(site.id, .{
                .name = site.name,
                .protocol = site.protocol,
                .host = site.host,
                .port = site.port,
                .account = site.account,
                .initial_remote_path = site.initial_remote_path,
                .initial_local_path = site.initial_local_path,
                .insecure_skip_verify = site.insecure_skip_verify,
                .accent = site.accent,
                .environment = site.environment,
            });
            try self.entries.append(self.gpa, .{ .site = owned, .persisted = true });
            if (site.id >= self.next_id) self.next_id = site.id + 1;
        }
    }

    fn dupeSite(self: *SiteStore, id: u64, fields: SiteFields) error{OutOfMemory}!sites_mod.Site {
        const a = self.arena.allocator();
        return .{
            .id = id,
            .name = try a.dupe(u8, fields.name),
            .protocol = fields.protocol,
            .host = try a.dupe(u8, fields.host),
            .port = fields.port,
            .account = try a.dupe(u8, fields.account),
            .initial_remote_path = try a.dupe(u8, fields.initial_remote_path),
            .initial_local_path = try a.dupe(u8, fields.initial_local_path),
            .insecure_skip_verify = fields.insecure_skip_verify,
            .accent = fields.accent,
            .environment = fields.environment,
        };
    }

    /// Returns the new site's stable id (assigned once, never reused).
    pub fn add(self: *SiteStore, fields: SiteFields, persisted: bool) error{OutOfMemory}!u64 {
        const id = self.next_id;
        const site = try self.dupeSite(id, fields);
        try self.entries.append(self.gpa, .{ .site = site, .persisted = persisted });
        self.next_id += 1;
        return id;
    }

    pub fn update(self: *SiteStore, id: u64, fields: SiteFields) error{OutOfMemory}!bool {
        const idx = self.indexOf(id) orelse return false;
        self.entries.items[idx].site = try self.dupeSite(id, fields);
        return true;
    }

    pub fn remove(self: *SiteStore, id: u64) bool {
        const idx = self.indexOf(id) orelse return false;
        _ = self.entries.orderedRemove(idx);
        return true;
    }

    pub fn get(self: *const SiteStore, id: u64) ?*const sites_mod.Site {
        const idx = self.indexOf(id) orelse return null;
        return &self.entries.items[idx].site;
    }

    fn indexOf(self: *const SiteStore, id: u64) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (entry.site.id == id) return i;
        }
        return null;
    }

    pub fn persistedCount(self: *const SiteStore) usize {
        var n: usize = 0;
        for (self.entries.items) |entry| n += @intFromBool(entry.persisted);
        return n;
    }

    /// row-th persisted entry (the sidebar's Servers section ordering).
    pub fn persistedAt(self: *const SiteStore, row: usize) ?*const Entry {
        var n: usize = 0;
        for (self.entries.items) |*entry| {
            if (!entry.persisted) continue;
            if (n == row) return entry;
            n += 1;
        }
        return null;
    }

    /// Any site (persisted or ephemeral) with the same connection identity.
    pub fn findMatching(self: *const SiteStore, fields: SiteFields) ?u64 {
        const port = if (fields.port != 0) fields.port else sites_mod.defaultPort(fields.protocol);
        for (self.entries.items) |entry| {
            const s = entry.site;
            if (s.protocol == fields.protocol and
                s.effectivePort() == port and
                std.mem.eql(u8, s.host, fields.host) and
                std.mem.eql(u8, s.account, fields.account)) return s.id;
        }
        return null;
    }

    /// Fresh arena-owned generation for AppCore.site_list (never freed
    /// before the store dies — see the struct doc).
    pub fn coreSlice(self: *SiteStore) error{OutOfMemory}![]const sites_mod.Site {
        const a = self.arena.allocator();
        const out = try a.alloc(sites_mod.Site, self.entries.items.len);
        for (self.entries.items, out) |entry, *dst| dst.* = entry.site;
        return out;
    }

    /// Persisted sites only, gpa-owned (caller frees) — the sites.zon view.
    pub fn persistedSlice(self: *const SiteStore, gpa: Allocator) error{OutOfMemory}![]sites_mod.Site {
        const out = try gpa.alloc(sites_mod.Site, self.persistedCount());
        var n: usize = 0;
        for (self.entries.items) |entry| {
            if (!entry.persisted) continue;
            out[n] = entry.site;
            n += 1;
        }
        return out;
    }

    /// Atomic write of the persisted sites to `dir/sub_path`.
    pub fn saveTo(self: *const SiteStore, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, gpa: Allocator) !void {
        const slice = try self.persistedSlice(gpa);
        defer gpa.free(slice);
        try sites_mod.save(.{ .sites = slice }, io, dir, sub_path, gpa);
    }
};

// ---------------------------------------------------------------------------
// History — recent (site, path) pairs, ring of `history_cap`, newest first
// ---------------------------------------------------------------------------

pub const history_cap: usize = 20;

pub const History = struct {
    gpa: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        site_id: u64 = 0,
        /// Site label at push time (survives site deletion).
        label: []const u8 = "",
        path: []const u8 = "",
    };

    const File = struct {
        schema_version: u32 = 1,
        entries: []const Entry = &.{},
    };

    pub fn init(gpa: Allocator) History {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *History) void {
        self.clear();
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn clear(self: *History) void {
        for (self.entries.items) |entry| self.freeEntry(entry);
        self.entries.clearRetainingCapacity();
    }

    fn freeEntry(self: *History, entry: Entry) void {
        self.gpa.free(entry.label);
        self.gpa.free(entry.path);
    }

    /// Move-to-front with (site_id, path) dedupe; trims to `history_cap`.
    pub fn push(self: *History, site_id: u64, label: []const u8, path: []const u8) error{OutOfMemory}!void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = self.entries.items[i];
            if (e.site_id == site_id and std.mem.eql(u8, e.path, path)) {
                self.freeEntry(self.entries.orderedRemove(i));
                continue;
            }
            i += 1;
        }
        const owned_label = try self.gpa.dupe(u8, label);
        errdefer self.gpa.free(owned_label);
        const owned_path = try self.gpa.dupe(u8, path);
        errdefer self.gpa.free(owned_path);
        try self.entries.insert(self.gpa, 0, .{
            .site_id = site_id,
            .label = owned_label,
            .path = owned_path,
        });
        while (self.entries.items.len > history_cap) {
            self.freeEntry(self.entries.pop().?);
        }
    }

    pub fn removeAt(self: *History, index: usize) void {
        if (index >= self.entries.items.len) return;
        self.freeEntry(self.entries.orderedRemove(index));
    }

    /// Missing or corrupt file degrades to empty (config must never block).
    pub fn load(self: *History, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) void {
        self.clear();
        const source = settings_mod.readFileZ(io, dir, sub_path, self.gpa) catch return;
        defer self.gpa.free(source);
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena.deinit();
        const file = std.zon.parse.fromSliceAlloc(File, arena.allocator(), source, null, .{
            .free_on_error = false,
        }) catch return;
        for (file.entries) |entry| {
            if (self.entries.items.len >= history_cap) break;
            const owned_label = self.gpa.dupe(u8, entry.label) catch return;
            const owned_path = self.gpa.dupe(u8, entry.path) catch {
                self.gpa.free(owned_label);
                return;
            };
            self.entries.append(self.gpa, .{
                .site_id = entry.site_id,
                .label = owned_label,
                .path = owned_path,
            }) catch {
                self.gpa.free(owned_label);
                self.gpa.free(owned_path);
                return;
            };
        }
    }

    pub fn save(self: *const History, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !void {
        const file: File = .{ .entries = self.entries.items };
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        std.zon.stringify.serialize(file, .{}, &out.writer) catch return error.OutOfMemory;
        out.writer.writeByte('\n') catch return error.OutOfMemory;
        try settings_mod.atomicWriteFile(io, dir, sub_path, out.written());
    }
};

// ---------------------------------------------------------------------------
// AuthMetaStore — per-site auth method + key file path (sites_meta.zon).
// The M1 Site schema has no auth slot and secrets NEVER ride sites.zon, so
// the editor's auth metadata persists here (consumed by the M2+ factories).
// ---------------------------------------------------------------------------

pub const AuthMetaStore = struct {
    gpa: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        site_id: u64 = 0,
        method: AuthMethod = .agent,
        key_path: []const u8 = "",
    };

    const File = struct {
        schema_version: u32 = 1,
        entries: []const Entry = &.{},
    };

    pub fn init(gpa: Allocator) AuthMetaStore {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *AuthMetaStore) void {
        self.clear();
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn clear(self: *AuthMetaStore) void {
        for (self.entries.items) |entry| self.gpa.free(entry.key_path);
        self.entries.clearRetainingCapacity();
    }

    pub fn get(self: *const AuthMetaStore, site_id: u64) ?Entry {
        for (self.entries.items) |entry| {
            if (entry.site_id == site_id) return entry;
        }
        return null;
    }

    pub fn set(self: *AuthMetaStore, site_id: u64, method: AuthMethod, key_path: []const u8) error{OutOfMemory}!void {
        const owned = try self.gpa.dupe(u8, key_path);
        for (self.entries.items) |*entry| {
            if (entry.site_id == site_id) {
                self.gpa.free(entry.key_path);
                entry.method = method;
                entry.key_path = owned;
                return;
            }
        }
        self.entries.append(self.gpa, .{
            .site_id = site_id,
            .method = method,
            .key_path = owned,
        }) catch |err| {
            self.gpa.free(owned);
            return err;
        };
    }

    pub fn remove(self: *AuthMetaStore, site_id: u64) bool {
        for (self.entries.items, 0..) |entry, i| {
            if (entry.site_id == site_id) {
                self.gpa.free(entry.key_path);
                _ = self.entries.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn load(self: *AuthMetaStore, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) void {
        self.clear();
        const source = settings_mod.readFileZ(io, dir, sub_path, self.gpa) catch return;
        defer self.gpa.free(source);
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena.deinit();
        const file = std.zon.parse.fromSliceAlloc(File, arena.allocator(), source, null, .{
            .free_on_error = false,
        }) catch return;
        for (file.entries) |entry| {
            self.set(entry.site_id, entry.method, entry.key_path) catch return;
        }
    }

    pub fn save(self: *const AuthMetaStore, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !void {
        const file: File = .{ .entries = self.entries.items };
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        std.zon.stringify.serialize(file, .{}, &out.writer) catch return error.OutOfMemory;
        out.writer.writeByte('\n') catch return error.OutOfMemory;
        try settings_mod.atomicWriteFile(io, dir, sub_path, out.written());
    }
};

// ---------------------------------------------------------------------------
// SshGroup — the read-only ~/.ssh/config smart group
// ---------------------------------------------------------------------------

pub const SshGroup = struct {
    gpa: Allocator,
    config: ?ssh_config_mod.Config = null,
    /// Concrete Host aliases in config order (gpa-owned, deduped).
    aliases: std.ArrayList([]u8) = .empty,

    pub fn init(gpa: Allocator) SshGroup {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *SshGroup) void {
        self.clear();
        self.aliases.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn clear(self: *SshGroup) void {
        for (self.aliases.items) |alias| self.gpa.free(alias);
        self.aliases.clearRetainingCapacity();
        if (self.config) |*cfg| {
            cfg.deinit();
            self.config = null;
        }
    }

    /// Wildcard ('*', '?') and negated ('!') patterns never become rows.
    pub fn isConcreteAlias(pattern: []const u8) bool {
        if (pattern.len == 0) return false;
        if (pattern[0] == '!') return false;
        return std.mem.indexOfAny(u8, pattern, "*?") == null;
    }

    fn containsAlias(self: *const SshGroup, alias: []const u8) bool {
        for (self.aliases.items) |existing| {
            if (std.mem.eql(u8, existing, alias)) return true;
        }
        return false;
    }

    /// Parse config text and collect the concrete aliases. Keeps the parsed
    /// Config for later `materialize` resolution.
    pub fn setFromText(self: *SshGroup, text: []const u8) error{OutOfMemory}!void {
        self.clear();
        var cfg = try ssh_config_mod.parse(self.gpa, text, .none);
        errdefer cfg.deinit();
        for (cfg.directives) |directive| switch (directive) {
            .host => |patterns| for (patterns) |pattern| {
                if (!isConcreteAlias(pattern)) continue;
                if (self.containsAlias(pattern)) continue;
                const owned = try self.gpa.dupe(u8, pattern);
                self.aliases.append(self.gpa, owned) catch |err| {
                    self.gpa.free(owned);
                    return err;
                };
            },
            .set => {},
        };
        self.config = cfg;
    }

    /// Re-read {home}/.ssh/config; missing or unreadable file = empty group
    /// (zero-setup smart group, never an error surface).
    pub fn refresh(self: *SshGroup, io: std.Io, home: []const u8) void {
        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/config", .{home}) catch {
            self.clear();
            return;
        };
        const text = readWholeFile(self.gpa, io, path) catch {
            self.clear();
            return;
        };
        defer self.gpa.free(text);
        self.setFromText(text) catch self.clear();
    }

    pub const Materialized = struct {
        arena: std.heap.ArenaAllocator,
        name: []const u8,
        host: []const u8,
        port: u16,
        account: []const u8,

        pub fn deinit(m: *Materialized) void {
            m.arena.deinit();
            m.* = undefined;
        }

        /// The ephemeral-site recipe: protocol sftp, fields from the
        /// resolved config.
        pub fn fields(m: *const Materialized) SiteFields {
            return .{
                .name = m.name,
                .protocol = .sftp,
                .host = m.host,
                .port = m.port,
                .account = m.account,
            };
        }
    };

    /// Resolve `alias` through the parsed config (first-obtained-wins
    /// semantics live in ssh_config.zig). Without a config the alias is
    /// the host and everything else defaults.
    pub fn materialize(self: *const SshGroup, gpa: Allocator, alias: []const u8, home: []const u8) error{OutOfMemory}!Materialized {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        var host: []const u8 = undefined;
        var port: u16 = 0;
        var account: []const u8 = "";
        if (self.config) |*cfg| {
            var eff = try cfg.resolve(gpa, alias, .{ .home = home });
            defer eff.deinit();
            host = try a.dupe(u8, eff.host_name);
            port = if (eff.port == 22) 0 else eff.port;
            if (eff.user) |user| account = try a.dupe(u8, user);
        } else {
            host = try a.dupe(u8, alias);
        }
        const name = try a.dupe(u8, alias);
        // All arena allocation precedes the literal: `.arena = arena`
        // copies the arena state (same rule as ssh_config.resolve).
        return .{ .arena = arena, .name = name, .host = host, .port = port, .account = account };
    }
};

fn readWholeFile(gpa: Allocator, io: std.Io, abs_path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, abs_path, .{});
    defer file.close(io);
    const file_size = (try file.stat(io)).size;
    if (file_size > settings_mod.max_file_bytes) return error.FileTooBig;
    const buf = try gpa.alloc(u8, @intCast(file_size));
    errdefer gpa.free(buf);
    var reader = file.reader(io, &.{});
    reader.interface.readSliceAll(buf) catch return error.InputOutput;
    return buf;
}

// ---------------------------------------------------------------------------
// Importers (File ▸ Import): FileZilla sitemanager.xml + Cyberduck .duck
// bookmarks. Parsing is pure (hand-rolled minimal XML / plist-subset scans,
// headless-tested against test/fixtures/importers/); the controller glue
// below adds the non-duplicate sites as persisted entries and — with
// explicit consent — FileZilla's base64 passwords into the Keychain.
// Duplicate detection: SiteStore.findMatching, i.e. the connection identity
// (protocol, host, effective port, user). SECURITY: decoded passwords live
// only inside the ImportResult arena and the cred store — never sites.zon.
// ---------------------------------------------------------------------------

/// One parsed bookmark: site fields plus (FileZilla only) the decoded
/// password. All slices are owned by the enclosing ImportResult's arena.
pub const ImportedSite = struct {
    fields: SiteFields,
    password: ?[]const u8 = null,
};

/// Arena-per-result (one deinit frees everything, passwords included).
pub const ImportResult = struct {
    arena: std.heap.ArenaAllocator,
    sites: []const ImportedSite = &.{},
    /// Entries the parser had to skip (unsupported protocol, missing host).
    skipped: usize = 0,

    pub fn deinit(self: *ImportResult) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn passwordCount(self: *const ImportResult) usize {
        var n: usize = 0;
        for (self.sites) |site| {
            if (site.password) |pw| n += @intFromBool(pw.len > 0);
        }
        return n;
    }
};

/// What an import did (sheet summary + tests).
pub const ImportStats = struct {
    imported: usize = 0,
    duplicates: usize = 0,
    skipped: usize = 0,
    passwords_stored: usize = 0,
};

// --- minimal XML helpers (shared by both importers) --------------------------

const XmlTag = struct {
    /// Raw attribute text of the open tag (between the name and '>').
    attrs: []const u8,
    /// Raw inner text (undecoded); empty for self-closing tags.
    text: []const u8,
};

/// First `<tag …>text</tag>` inside `block`. Minimal by design: no nesting
/// of the SAME tag inside itself (true for every field FileZilla/Cyberduck
/// write), attributes are returned raw for the caller to scan.
fn xmlTag(block: []const u8, comptime tag: []const u8) ?XmlTag {
    const open = "<" ++ tag;
    const close = "</" ++ tag ++ ">";
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, block, search, open)) |start| {
        const after = start + open.len;
        if (after >= block.len) return null;
        // "<Pass" must not match "<Password>": the name must end here.
        const ch = block[after];
        if (ch != '>' and ch != ' ' and ch != '\t' and ch != '/' and ch != '\n' and ch != '\r') {
            search = after;
            continue;
        }
        const open_end = std.mem.indexOfScalarPos(u8, block, after, '>') orelse return null;
        if (open_end > 0 and block[open_end - 1] == '/') {
            return .{ .attrs = block[after .. open_end - 1], .text = "" };
        }
        const text_start = open_end + 1;
        const text_end = std.mem.indexOfPos(u8, block, text_start, close) orelse return null;
        return .{ .attrs = block[after..open_end], .text = block[text_start..text_end] };
    }
    return null;
}

fn xmlTagText(block: []const u8, comptime tag: []const u8) ?[]const u8 {
    const found = xmlTag(block, tag) orelse return null;
    return found.text;
}

/// Decode the five named XML entities plus decimal/hex character
/// references (ASCII range only — enough for FileZilla/Cyberduck output);
/// malformed references are copied verbatim.
fn xmlDecode(a: Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '&') == null) return a.dupe(u8, raw);
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] != '&') {
            try out.append(a, raw[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse {
            try out.append(a, raw[i]);
            i += 1;
            continue;
        };
        const name = raw[i + 1 .. semi];
        const decoded: ?u8 = blk: {
            if (std.mem.eql(u8, name, "amp")) break :blk '&';
            if (std.mem.eql(u8, name, "lt")) break :blk '<';
            if (std.mem.eql(u8, name, "gt")) break :blk '>';
            if (std.mem.eql(u8, name, "quot")) break :blk '"';
            if (std.mem.eql(u8, name, "apos")) break :blk '\'';
            if (name.len > 1 and name[0] == '#') {
                const v = if (name[1] == 'x' or name[1] == 'X')
                    std.fmt.parseInt(u8, name[2..], 16) catch break :blk null
                else
                    std.fmt.parseInt(u8, name[1..], 10) catch break :blk null;
                break :blk v;
            }
            break :blk null;
        };
        if (decoded) |ch| {
            try out.append(a, ch);
            i = semi + 1;
        } else {
            try out.append(a, raw[i]);
            i += 1;
        }
    }
    return out.items;
}

// --- FileZilla sitemanager.xml ------------------------------------------------

/// FileZilla's ServerProtocol values we can represent. 0 = FTP,
/// 1 = SFTP, 3 = FTPS (implicit TLS), 4 = FTPES (explicit TLS),
/// 6 = "insecure FTP". Everything else (HTTP, S3, Storj, …) is skipped.
fn fzProtocol(value: i32) ?sites_mod.Protocol {
    return switch (value) {
        0, 6 => .ftp,
        1 => .sftp,
        3, 4 => .ftps,
        else => null,
    };
}

/// Scan every `<Server>…</Server>` block (folders nest them; nesting depth
/// is irrelevant to a linear scan). Passwords: `<Pass encoding="base64">`
/// is decoded; legacy plaintext `<Pass>` is taken verbatim; passwords are
/// only kept for Logontype 1 (normal) and 4 (account). Logontype 0
/// (anonymous) maps to user "anonymous" without a password; ask (2),
/// interactive (3) and key (5) keep the user and drop any stored secret.
/// RemoteDir is skipped (FileZilla's segment encoding, not a plain path);
/// LocalDir is a plain path and maps to initial_local_path.
pub fn parseFileZilla(gpa: Allocator, xml: []const u8) error{OutOfMemory}!ImportResult {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var sites: std.ArrayList(ImportedSite) = .empty;
    var skipped: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, xml, pos, "<Server")) |start| {
        const after = start + "<Server".len;
        if (after >= xml.len) break;
        const ch = xml[after];
        if (ch != '>' and ch != ' ' and ch != '\t') {
            pos = after; // "<Servers>" wrapper, keep scanning inside it
            continue;
        }
        const open_end = std.mem.indexOfScalarPos(u8, xml, after, '>') orelse break;
        const body_end = std.mem.indexOfPos(u8, xml, open_end + 1, "</Server>") orelse break;
        const block = xml[open_end + 1 .. body_end];
        pos = body_end + "</Server>".len;

        if (try parseFzServer(a, block)) |site| {
            try sites.append(a, site);
        } else {
            skipped += 1;
        }
    }
    return .{ .arena = arena, .sites = sites.items, .skipped = skipped };
}

/// An imported host/account is safe iff it carries no ASCII control bytes
/// (incl. NUL/CR/LF) and no leading dash — the latter would be parsed as an
/// option by ssh/scp/rsync (see terminal.destinationSafe). Empty is allowed
/// (anonymous/identity-only logins).
fn importedFieldSafe(field: []const u8) bool {
    if (field.len == 0) return true;
    if (field[0] == '-') return false;
    for (field) |ch| {
        if (ch < 0x20 or ch == 0x7f) return false;
    }
    return true;
}

test "importedFieldSafe rejects control bytes and leading dash" {
    try std.testing.expect(importedFieldSafe("example.com"));
    try std.testing.expect(importedFieldSafe("")); // anonymous
    try std.testing.expect(importedFieldSafe("2001:db8::1"));
    try std.testing.expect(!importedFieldSafe("-oProxyCommand=touch /tmp/x"));
    try std.testing.expect(!importedFieldSafe("evil\x00host"));
    try std.testing.expect(!importedFieldSafe("two\nlines"));
}

fn parseFzServer(a: Allocator, block: []const u8) error{OutOfMemory}!?ImportedSite {
    const host_raw = xmlTagText(block, "Host") orelse return null;
    const host = try xmlDecode(a, std.mem.trim(u8, host_raw, " \t\r\n"));
    if (host.len == 0) return null;

    const proto_text = std.mem.trim(u8, xmlTagText(block, "Protocol") orelse "0", " \t\r\n");
    const proto_num = std.fmt.parseInt(i32, proto_text, 10) catch return null;
    const protocol = fzProtocol(proto_num) orelse return null;

    const port_text = std.mem.trim(u8, xmlTagText(block, "Port") orelse "", " \t\r\n");
    var port = std.fmt.parseInt(u16, port_text, 10) catch 0;
    if (port == sites_mod.defaultPort(protocol)) port = 0; // store "default" canonically

    const logontype_text = std.mem.trim(u8, xmlTagText(block, "Logontype") orelse "1", " \t\r\n");
    const logontype = std.fmt.parseInt(u8, logontype_text, 10) catch 1;

    var user: []const u8 = try xmlDecode(a, xmlTagText(block, "User") orelse "");
    var password: ?[]const u8 = null;
    switch (logontype) {
        0 => user = "anonymous", // FileZilla's anonymous login identity
        1, 4 => {
            if (xmlTag(block, "Pass")) |pass| {
                password = try decodeFzPass(a, pass);
            }
        },
        else => {}, // ask / interactive / key: identity only, no secret
    }

    const name = try xmlDecode(a, xmlTagText(block, "Name") orelse "");
    const local_dir = try xmlDecode(a, xmlTagText(block, "LocalDir") orelse "");

    return .{
        .fields = .{
            .name = name,
            .protocol = protocol,
            .host = host,
            .port = port,
            .account = user,
            .initial_local_path = local_dir,
        },
        .password = password,
    };
}

/// `<Pass encoding="base64">…</Pass>` → decoded; legacy plaintext is taken
/// verbatim; a corrupt base64 payload yields null (site still imports).
fn decodeFzPass(a: Allocator, pass: XmlTag) error{OutOfMemory}!?[]const u8 {
    const text = std.mem.trim(u8, pass.text, " \t\r\n");
    if (text.len == 0) return null;
    if (std.mem.indexOf(u8, pass.attrs, "base64") == null) return try xmlDecode(a, text);
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return null;
    const buf = try a.alloc(u8, size);
    decoder.decode(buf, text) catch return null;
    return buf;
}

// --- Cyberduck .duck bookmarks --------------------------------------------------

/// Cyberduck protocol identifiers we can represent; everything else
/// (s3, dav(s), azure, …) is skipped. Cyberduck stores secrets in its own
/// keychain items, so .duck imports never carry passwords.
fn duckProtocol(value: []const u8) ?sites_mod.Protocol {
    if (std.mem.eql(u8, value, "sftp")) return .sftp;
    if (std.mem.eql(u8, value, "ftps")) return .ftps;
    if (std.mem.eql(u8, value, "ftp")) return .ftp;
    return null;
}

/// `<key>K</key>` followed by `<string>…</string>` (or `<integer>`), the
/// XML-plist subset .duck files use. Returns the raw (undecoded) value.
fn plistValue(text: []const u8, comptime key: []const u8) ?[]const u8 {
    const needle = "<key>" ++ key ++ "</key>";
    const key_at = std.mem.indexOf(u8, text, needle) orelse return null;
    var i = key_at + needle.len;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t' or text[i] == '\n' or text[i] == '\r')) i += 1;
    const rest = text[i..];
    inline for (.{ "string", "integer" }) |value_tag| {
        const open = "<" ++ value_tag ++ ">";
        const close = "</" ++ value_tag ++ ">";
        if (std.mem.startsWith(u8, rest, open)) {
            const end = std.mem.indexOf(u8, rest, close) orelse return null;
            return rest[open.len..end];
        }
    }
    return null;
}

/// Parse a batch of .duck file contents (one bookmark per file). Files
/// with unsupported protocols or no hostname count as `skipped`.
pub fn parseCyberduck(gpa: Allocator, files: []const []const u8) error{OutOfMemory}!ImportResult {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var sites: std.ArrayList(ImportedSite) = .empty;
    var skipped: usize = 0;
    for (files) |text| {
        if (try parseDuck(a, text)) |site| {
            try sites.append(a, site);
        } else {
            skipped += 1;
        }
    }
    return .{ .arena = arena, .sites = sites.items, .skipped = skipped };
}

fn parseDuck(a: Allocator, text: []const u8) error{OutOfMemory}!?ImportedSite {
    const proto_raw = plistValue(text, "Protocol") orelse return null;
    const protocol = duckProtocol(std.mem.trim(u8, proto_raw, " \t\r\n")) orelse return null;

    const host_raw = plistValue(text, "Hostname") orelse return null;
    const host = try xmlDecode(a, std.mem.trim(u8, host_raw, " \t\r\n"));
    if (host.len == 0) return null;

    const port_text = std.mem.trim(u8, plistValue(text, "Port") orelse "", " \t\r\n");
    var port = std.fmt.parseInt(u16, port_text, 10) catch 0;
    if (port == sites_mod.defaultPort(protocol)) port = 0;

    return .{ .fields = .{
        .name = try xmlDecode(a, plistValue(text, "Nickname") orelse ""),
        .protocol = protocol,
        .host = host,
        .port = port,
        .account = try xmlDecode(a, plistValue(text, "Username") orelse ""),
        .initial_remote_path = try xmlDecode(a, plistValue(text, "Path") orelse ""),
    } };
}

// ---------------------------------------------------------------------------
// SitesController
// ---------------------------------------------------------------------------

const MenuKind = enum(usize) { servers, servers_connected, ssh, history, background };
const menu_kind_count = @typeInfo(MenuKind).@"enum".fields.len;

const TransientCred = struct {
    site_id: u64,
    protocol: cred_store_mod.Protocol,
    host: []u8,
    port: u16,
    account: []u8,
};

pub const SitesController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    win: ?Window,
    pane_host: PaneHost,
    /// $HOME (or the test override); gpa-owned.
    home: []u8,

    store: SiteStore,
    history: History,
    meta: AuthMetaStore,
    ssh: SshGroup,
    /// mtime of {home}/.ssh/config at the last (re)parse; 0 = no file.
    /// Gates the cheap re-parse on app activation.
    ssh_config_mtime_ns: i96 = 0,

    /// Last site_status per site id (sidebar suffix + `siteStatus()`).
    statuses: std.AutoHashMapUnmanaged(u64, events_mod.SiteStatus) = .empty,
    /// Site ids with an in-flight USER-initiated connect (set by
    /// connectAndList, cleared by the first terminal site_status). Gates the
    /// connect-failure sheet so background reconnect/breaker churn never
    /// sheet-spams: only a pending attempt's first .offline-with-error_class
    /// pops the popup, and the flag is gone before the next status arrives.
    pending_connects: std.AutoHashMapUnmanaged(u64, void) = .empty,
    /// pane token -> site id of the last connect issued there (Cmd+Shift+K).
    pane_sites: std.AutoHashMapUnmanaged(bridge.PaneToken, u64) = .empty,
    /// "Save in Keychain: No" secrets — deleted once the connect resolves.
    transients: std.ArrayList(TransientCred) = .empty,

    sidebar: ?*outline_mod.OutlineView = null,
    menu_reg: ?*menu_mod.Registry = null,
    /// Static context menus (built once; NSMenus intentionally live for the
    /// controller lifetime — relay_mac exposes no release wrapper and
    /// controllers are app-lifetime).
    menus: [menu_kind_count]?objc.Object = @splat(null),
    /// Row under the last right-click (read by the menu callbacks).
    clicked: ?outline_mod.SectionRow = null,

    pub const Options = struct {
        /// Sheet parent. null (headless tests): prompts auto-deny, editor /
        /// quick-connect entry points become no-ops.
        window: ?Window = null,
        pane_host: PaneHost = .{},
        /// Test override for ~; null = $HOME.
        home: ?[]const u8 = null,
        /// false skips all AppKit view construction (pure-logic tests).
        build_sidebar: bool = true,
        sidebar_autosave: ?[:0]const u8 = "RelaySidebar",
    };

    pub fn create(gpa: Allocator, core: *bridge.AppCore, options: Options) !*SitesController {
        const self = try gpa.create(SitesController);
        errdefer gpa.destroy(self);

        const home_src: []const u8 = options.home orelse blk: {
            const env = std.c.getenv("HOME") orelse break :blk "/";
            break :blk std.mem.span(env);
        };
        const home = try gpa.dupe(u8, home_src);
        errdefer gpa.free(home);

        self.* = .{
            .gpa = gpa,
            .core = core,
            .win = options.window,
            .pane_host = options.pane_host,
            .home = home,
            .store = .init(gpa),
            .history = .init(gpa),
            .meta = .init(gpa),
            .ssh = .init(gpa),
        };
        errdefer {
            self.store.deinit();
            self.history.deinit();
            self.meta.deinit();
            self.ssh.deinit();
        }

        try self.store.loadFrom(core.site_list);
        self.history.load(core.io, core.config_dir, history_file);
        self.meta.load(core.io, core.config_dir, meta_file);
        self.ssh.refresh(core.io, self.home);
        self.ssh_config_mtime_ns = self.sshConfigMtimeNs();

        if (options.build_sidebar) {
            self.menu_reg = try menu_mod.Registry.create(gpa);
            errdefer {
                self.menu_reg.?.destroy();
                self.menu_reg = null;
            }
            try self.buildMenus();
            self.sidebar = try outline_mod.OutlineView.init(gpa, .{
                .data_source = self.dataSource(),
                .autosave_name = options.sidebar_autosave,
            });
            errdefer {
                self.sidebar.?.deinit();
                self.sidebar = null;
            }
            // Listener registration is last: there is no unregister, so a
            // partially-built controller must never be reachable from the
            // bridge (registered ctx pointers live for the app lifetime).
            try self.registerListeners();
        } else {
            try self.registerListeners();
        }
        return self;
    }

    fn registerListeners(self: *SitesController) error{OutOfMemory}!void {
        try self.core.registerListener(.site_status, self, onSiteStatus);
        try self.core.registerListener(.prompt_needed, self, onPromptNeeded);
    }

    /// Tests only (after AppCore.shutdown). In the app the controller lives
    /// for the process — bridge listeners cannot be unregistered.
    pub fn destroy(self: *SitesController) void {
        if (self.sidebar) |sb| sb.deinit();
        if (self.menu_reg) |reg| reg.destroy();
        self.store.deinit();
        self.history.deinit();
        self.meta.deinit();
        self.ssh.deinit();
        self.statuses.deinit(self.gpa);
        self.pending_connects.deinit(self.gpa);
        self.pane_sites.deinit(self.gpa);
        self.clearTransients();
        self.transients.deinit(self.gpa);
        self.gpa.free(self.home);
        self.gpa.destroy(self);
    }

    /// The NSScrollView wrapping the sidebar (split-view embedding).
    pub fn sidebarView(self: *SitesController) ?c.id {
        const sb = self.sidebar orelse return null;
        return sb.view();
    }

    pub fn siteStatus(self: *const SitesController, site_id: u64) ?events_mod.SiteStatus {
        return self.statuses.get(site_id);
    }

    /// Server menu (phase 3 hands this to menu.installMainMenu):
    /// Cmd+K Quick Connect, Cmd+Shift+K disconnect, Add Site….
    pub fn serverMenuItems(self: *SitesController) [4]menu_mod.Item {
        return .{
            menu_mod.Item.call("Connect to Server…", .{ .ctx = self, .f = menuQuickConnect }, "k", .{}),
            menu_mod.Item.call("Disconnect", .{ .ctx = self, .f = menuDisconnect }, "k", .{ .shift = true }),
            .separator,
            menu_mod.Item.call("Add Site…", .{ .ctx = self, .f = cmAddSite }, "", .{}),
        };
    }

    // ------------------------------------------------------------------ //
    // Sidebar data source

    fn dataSource(self: *SitesController) outline_mod.DataSource {
        return .{
            .ctx = @ptrCast(self),
            .sectionCount = dsSectionCount,
            .sectionTitle = dsSectionTitle,
            .rowCount = dsRowCount,
            .rowItem = dsRowItem,
            .doubleAction = dsActivate,
            .returnAction = dsActivate,
            .contextMenu = dsContextMenu,
        };
    }

    fn fromCtx(ctx: *anyopaque) *SitesController {
        return @ptrCast(@alignCast(ctx));
    }

    fn dsSectionCount(_: *anyopaque) usize {
        return section_count;
    }

    fn dsSectionTitle(_: *anyopaque, section: usize, buf: []u8) []const u8 {
        _ = buf;
        return switch (section) {
            section_servers => "Servers",
            section_ssh => "SSH Config",
            section_history => "History",
            else => "",
        };
    }

    fn dsRowCount(ctx: *anyopaque, section: usize) usize {
        const self = fromCtx(ctx);
        return switch (section) {
            section_servers => self.store.persistedCount(),
            section_ssh => self.ssh.aliases.items.len,
            section_history => self.history.entries.items.len,
            else => 0,
        };
    }

    /// Sidebar connection-status dot for a site (green/orange in the cell;
    /// offline and never-seen sites draw nothing).
    fn statusDot(self: *const SitesController, site_id: u64) outline_mod.StatusDot {
        const status = self.statuses.get(site_id) orelse return .none;
        return switch (status) {
            .connected => .connected,
            .reconnecting => .reconnecting,
            .offline => .none,
        };
    }

    fn dsRowItem(ctx: *anyopaque, section: usize, row: usize, buf: []u8) outline_mod.Item {
        const self = fromCtx(ctx);
        switch (section) {
            section_servers => {
                const entry = self.store.persistedAt(row) orelse return .{ .title = "" };
                return .{
                    .title = siteLabel(entry.site),
                    .symbol = "server.rack",
                    .status = self.statusDot(entry.site.id),
                };
            },
            section_ssh => {
                if (row >= self.ssh.aliases.items.len) return .{ .title = "" };
                return .{ .title = self.ssh.aliases.items[row], .symbol = "terminal" };
            },
            section_history => {
                if (row >= self.history.entries.items.len) return .{ .title = "" };
                const entry = self.history.entries.items[row];
                // Empty path = "the server's default directory" (no
                // configured remote path): show just the site label.
                const title = if (entry.path.len == 0)
                    entry.label
                else
                    std.fmt.bufPrint(buf, "{s} · {s}", .{
                        entry.label, entry.path,
                    }) catch entry.label;
                return .{
                    .title = title,
                    .symbol = "clock",
                    .status = self.statusDot(entry.site_id),
                };
            },
            else => return .{ .title = "" },
        }
    }

    fn dsActivate(ctx: *anyopaque, item: outline_mod.SectionRow) void {
        fromCtx(ctx).activateRow(item);
    }

    fn dsContextMenu(ctx: *anyopaque, item: ?outline_mod.SectionRow) ?c.id {
        const self = fromCtx(ctx);
        self.clicked = item;
        const kind: MenuKind = if (item) |sr| switch (sr.section) {
            section_servers => self.serversMenuKind(sr.row),
            section_ssh => .ssh,
            section_history => .history,
            else => MenuKind.background,
        } else .background;
        const m = self.menus[@intFromEnum(kind)] orelse return null;
        return m.value;
    }

    /// The Disconnect-bearing variant only when the row's site is actually
    /// connected (or trying to be); offline rows keep the plain menu.
    fn serversMenuKind(self: *const SitesController, row: usize) MenuKind {
        const entry = self.store.persistedAt(row) orelse return .servers;
        const status = self.statuses.get(entry.site.id) orelse return .servers;
        return switch (status) {
            .connected, .reconnecting => .servers_connected,
            .offline => .servers,
        };
    }

    // ------------------------------------------------------------------ //
    // Context menus

    fn buildMenus(self: *SitesController) error{OutOfMemory}!void {
        const reg = self.menu_reg.?;
        const servers_items = [_]menu_mod.Item{
            menu_mod.Item.call("Connect", .{ .ctx = self, .f = cmConnect }, "", .{}),
            .separator,
            menu_mod.Item.call("Edit Site…", .{ .ctx = self, .f = cmEdit }, "", .{}),
            menu_mod.Item.call("Delete Site…", .{ .ctx = self, .f = cmDelete }, "", .{}),
            .separator,
            menu_mod.Item.call("Add Site…", .{ .ctx = self, .f = cmAddSite }, "", .{}),
        };
        self.menus[@intFromEnum(MenuKind.servers)] = try menu_mod.buildContextMenu(reg, &servers_items);

        // Connected/reconnecting rows get the same menu plus Disconnect.
        const servers_connected_items = [_]menu_mod.Item{
            menu_mod.Item.call("Connect", .{ .ctx = self, .f = cmConnect }, "", .{}),
            menu_mod.Item.call("Disconnect", .{ .ctx = self, .f = cmDisconnect }, "", .{}),
            .separator,
            menu_mod.Item.call("Edit Site…", .{ .ctx = self, .f = cmEdit }, "", .{}),
            menu_mod.Item.call("Delete Site…", .{ .ctx = self, .f = cmDelete }, "", .{}),
            .separator,
            menu_mod.Item.call("Add Site…", .{ .ctx = self, .f = cmAddSite }, "", .{}),
        };
        self.menus[@intFromEnum(MenuKind.servers_connected)] =
            try menu_mod.buildContextMenu(reg, &servers_connected_items);

        const ssh_items = [_]menu_mod.Item{
            menu_mod.Item.call("Connect", .{ .ctx = self, .f = cmConnect }, "", .{}),
            menu_mod.Item.call("Save as Site…", .{ .ctx = self, .f = cmSaveSshAsSite }, "", .{}),
            .separator,
            menu_mod.Item.call("Refresh SSH Config", .{ .ctx = self, .f = cmRefreshSsh }, "", .{}),
        };
        self.menus[@intFromEnum(MenuKind.ssh)] = try menu_mod.buildContextMenu(reg, &ssh_items);

        const history_items = [_]menu_mod.Item{
            menu_mod.Item.call("Connect", .{ .ctx = self, .f = cmConnect }, "", .{}),
            .separator,
            menu_mod.Item.call("Remove from History", .{ .ctx = self, .f = cmRemoveHistory }, "", .{}),
            menu_mod.Item.call("Clear History", .{ .ctx = self, .f = cmClearHistory }, "", .{}),
        };
        self.menus[@intFromEnum(MenuKind.history)] = try menu_mod.buildContextMenu(reg, &history_items);

        const background_items = [_]menu_mod.Item{
            menu_mod.Item.call("Add Site…", .{ .ctx = self, .f = cmAddSite }, "", .{}),
            menu_mod.Item.call("Refresh SSH Config", .{ .ctx = self, .f = cmRefreshSsh }, "", .{}),
        };
        self.menus[@intFromEnum(MenuKind.background)] = try menu_mod.buildContextMenu(reg, &background_items);
    }

    fn fromMenuCtx(ctx: ?*anyopaque) *SitesController {
        return @ptrCast(@alignCast(ctx.?));
    }

    fn cmConnect(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        if (self.clicked) |sr| self.activateRow(sr);
    }

    fn cmDisconnect(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        const sr = self.clicked orelse return;
        if (sr.section != section_servers) return;
        const entry = self.store.persistedAt(sr.row) orelse return;
        self.disconnectSite(entry.site.id);
    }

    fn cmEdit(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        const sr = self.clicked orelse return;
        if (sr.section != section_servers) return;
        const entry = self.store.persistedAt(sr.row) orelse return;
        self.presentEditor(entry.site.id, null);
    }

    fn cmDelete(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        const sr = self.clicked orelse return;
        if (sr.section != section_servers) return;
        const entry = self.store.persistedAt(sr.row) orelse return;
        const site_id = entry.site.id;
        const win = self.win orelse {
            self.deleteSite(site_id);
            return;
        };
        const session = self.gpa.create(DeleteSession) catch return;
        session.* = .{ .c = self, .site_id = site_id };
        var msg_buf: [320]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Delete \"{s}\"?", .{siteLabel(entry.site)}) catch "Delete this site?";
        panels.confirmSheet(
            win,
            msg,
            "Its Keychain credential is removed too. This cannot be undone.",
            "Delete",
            true,
            session,
            DeleteSession.onConfirm,
        );
    }

    fn cmAddSite(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).addSite();
    }

    fn cmSaveSshAsSite(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        const sr = self.clicked orelse return;
        if (sr.section != section_ssh) return;
        if (sr.row >= self.ssh.aliases.items.len) return;
        const alias = self.ssh.aliases.items[sr.row];
        var mat = self.ssh.materialize(self.gpa, alias, self.home) catch return;
        defer mat.deinit();
        const draft = draftFromFields(self.gpa, mat.fields(), .agent);
        self.presentEditor(null, draft);
    }

    fn cmRefreshSsh(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).refreshSshConfig();
    }

    fn cmRemoveHistory(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        const sr = self.clicked orelse return;
        if (sr.section != section_history) return;
        self.history.removeAt(sr.row);
        self.history.save(self.core.io, self.core.config_dir, history_file) catch {};
        if (self.sidebar) |sb| sb.reloadSection(section_history);
    }

    fn cmClearHistory(ctx: ?*anyopaque) void {
        const self = fromMenuCtx(ctx);
        self.history.clear();
        self.history.save(self.core.io, self.core.config_dir, history_file) catch {};
        if (self.sidebar) |sb| sb.reloadSection(section_history);
    }

    fn menuQuickConnect(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).quickConnect();
    }

    fn menuDisconnect(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).disconnectActivePane();
    }

    const DeleteSession = struct {
        c: *SitesController,
        site_id: u64,

        fn onConfirm(s: *DeleteSession, confirmed: bool) void {
            const self = s.c;
            defer self.gpa.destroy(s);
            if (confirmed) self.deleteSite(s.site_id);
        }
    };

    // ------------------------------------------------------------------ //
    // Connect flow

    fn activateRow(self: *SitesController, sr: outline_mod.SectionRow) void {
        switch (sr.section) {
            section_servers => {
                const entry = self.store.persistedAt(sr.row) orelse return;
                self.connectAndList(entry.site.id, null);
            },
            section_ssh => self.connectSshAlias(sr.row),
            section_history => {
                if (sr.row >= self.history.entries.items.len) return;
                const entry = self.history.entries.items[sr.row];
                if (self.store.get(entry.site_id) == null) {
                    self.showError("This site no longer exists", entry.label);
                    return;
                }
                // connectAndList re-pushes history, which frees this entry —
                // the path must not be borrowed across that.
                const path = self.gpa.dupe(u8, entry.path) catch return;
                defer self.gpa.free(path);
                self.connectAndList(entry.site_id, path);
            },
            else => {},
        }
    }

    /// connectSite + listPath of the initial dir in the active pane, then
    /// the history push. Status feedback arrives via site_status events.
    pub fn connectAndList(self: *SitesController, site_id: u64, path_override: ?[]const u8) void {
        const site = (self.store.get(site_id) orelse return).*;
        const pane = self.pane_host.activeToken();
        self.pane_host.notifyConnecting(pane, site_id);
        self.core.connectSite(site_id) catch |err| {
            self.showError("Could not start the connection", @errorName(err));
            return;
        };
        // Arm the connect-failure sheet for THIS attempt only. The async
        // result lands later as a site_status; until then a failure is
        // "the user just clicked Connect and it went offline" and earns a
        // popup. put() (not getOrPut) refreshes a stale flag from an earlier
        // attempt that never produced a terminal status. OOM = no sheet, the
        // inline banner/chip still surface the reason.
        self.pending_connects.put(self.gpa, site_id, {}) catch {};
        // Empty = no configured path: the listing resolves the server's
        // default directory (FTP login dir, SFTP home) instead of "/".
        const initial: []const u8 = blk: {
            if (path_override) |p| {
                if (p.len > 0) break :blk p;
            }
            break :blk site.initial_remote_path;
        };
        if (self.pane_host.navigate) |nav| {
            nav(self.pane_host.ctx, pane, site_id, initial);
        } else if (initial.len > 0) {
            _ = self.core.listPath(pane, site_id, initial) catch |err| {
                self.showError("Could not list the initial directory", @errorName(err));
            };
        } else {
            _ = self.core.listDefaultPath(pane, site_id) catch |err| {
                self.showError("Could not list the initial directory", @errorName(err));
            };
        }
        self.pane_sites.put(self.gpa, pane, site_id) catch {};
        self.history.push(site_id, siteLabel(site), initial) catch {};
        self.history.save(self.core.io, self.core.config_dir, history_file) catch {};
        if (self.sidebar) |sb| sb.reloadSection(section_history);
    }

    /// Cmd+Shift+K: disconnect whatever was last connected in the active pane.
    pub fn disconnectActivePane(self: *SitesController) void {
        const pane = self.pane_host.activeToken();
        const kv = self.pane_sites.fetchRemove(pane) orelse return;
        self.core.disconnectSite(kv.value);
    }

    /// Sidebar Disconnect: disconnect one site and drop every pane binding
    /// pointing at it (a stale binding would make Cmd+Shift+K re-disconnect
    /// a dead site).
    fn disconnectSite(self: *SitesController, site_id: u64) void {
        self.core.disconnectSite(site_id);
        // Collect-then-remove: removal invalidates a live map iterator.
        var stale: [8]bridge.PaneToken = undefined; // bounded: one per pane
        var n: usize = 0;
        var it = self.pane_sites.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* == site_id and n < stale.len) {
                stale[n] = e.key_ptr.*;
                n += 1;
            }
        }
        for (stale[0..n]) |pane| _ = self.pane_sites.remove(pane);
    }

    /// File ▸ Disconnect All: disconnect every site whose last status was
    /// connected or reconnecting, then drop all pane bindings (every one is
    /// stale after a global disconnect).
    pub fn disconnectAll(self: *SitesController) void {
        var it = self.statuses.iterator();
        while (it.next()) |e| switch (e.value_ptr.*) {
            .connected, .reconnecting => self.core.disconnectSite(e.key_ptr.*),
            .offline => {},
        };
        self.pane_sites.clearRetainingCapacity();
    }

    fn connectSshAlias(self: *SitesController, row: usize) void {
        if (row >= self.ssh.aliases.items.len) return;
        const alias = self.ssh.aliases.items[row];
        var mat = self.ssh.materialize(self.gpa, alias, self.home) catch return;
        defer mat.deinit();
        const site_id = self.ensureSite(mat.fields(), false) orelse return;
        self.connectAndList(site_id, null);
    }

    /// Reuse a matching site or add one (ephemeral or persisted), keeping
    /// disk + core in sync.
    fn ensureSite(self: *SitesController, fields: SiteFields, persist: bool) ?u64 {
        if (!persist) {
            if (self.store.findMatching(fields)) |existing| return existing;
        }
        const site_id = self.store.add(fields, persist) catch return null;
        if (persist) {
            self.persistSites();
            if (self.sidebar) |sb| sb.reload();
        }
        self.syncCore();
        return site_id;
    }

    pub fn refreshSshConfig(self: *SitesController) void {
        self.ssh_config_mtime_ns = self.sshConfigMtimeNs();
        self.ssh.refresh(self.core.io, self.home);
        if (self.sidebar) |sb| sb.reloadSection(section_ssh);
    }

    /// applicationDidBecomeActive hook (main.zig): cheap mtime stat first;
    /// the smart group re-parses only when ~/.ssh/config really changed.
    /// (The proper FSEvents watcher arrives with M3's edit-in-editor.)
    pub fn refreshSshConfigIfChanged(self: *SitesController) void {
        if (self.sshConfigMtimeNs() == self.ssh_config_mtime_ns) return;
        self.refreshSshConfig();
    }

    /// mtime of {home}/.ssh/config in ns; 0 when missing/unstatable (a
    /// file appearing or vanishing both read as a change).
    fn sshConfigMtimeNs(self: *const SitesController) i96 {
        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/config", .{self.home}) catch return 0;
        const st = std.Io.Dir.cwd().statFile(self.core.io, path, .{}) catch return 0;
        return st.mtime.nanoseconds;
    }

    // ------------------------------------------------------------------ //
    // Persistence + core sync

    fn persistSites(self: *SitesController) void {
        self.store.saveTo(self.core.io, self.core.config_dir, bridge.sites_file, self.gpa) catch |err| {
            self.showError("Could not save sites.zon", @errorName(err));
        };
    }

    /// Publish the store's current site set to AppCore.site_list. The swap
    /// rides the bridge's sites_mutex; the outgoing generation stays alive
    /// in the store's grow-only arena, so worker-held slices never dangle.
    fn syncCore(self: *SitesController) void {
        const slice = self.store.coreSlice() catch return;
        self.core.sites_mutex.lockUncancelable(self.core.io);
        self.core.site_list = .{ .sites = slice };
        self.core.sites_mutex.unlock(self.core.io);
    }

    // ------------------------------------------------------------------ //
    // Bridge listeners (main thread, run-to-completion)

    fn onSiteStatus(self: *SitesController, e: events_mod.CoreEvent.SiteStatusChange) void {
        self.statuses.put(self.gpa, e.site_id, e.status) catch {};
        if (self.connectFailureSheetEligible(e)) {
            self.showConnectFailure(e.site_id, e.reason);
        }
        self.resolveTransients(e.site_id, e.status);
        // Every transition (incl. reconnecting→connected) redraws the
        // status dots; History rows carry them too.
        if (self.sidebar) |sb| {
            sb.reloadSection(section_servers);
            sb.reloadSection(section_history);
        }
    }

    /// Pure pending-connect lifecycle (headless-tested): a site_status for a
    /// site with a PENDING user-initiated connect is terminal unless it is
    /// .reconnecting (the attempt is still in flight). On the first terminal
    /// status the flag clears; the function returns true ONLY when that
    /// terminal status is a real failure (.offline with error_class != null),
    /// i.e. exactly one popup per user click. Background reconnect/breaker
    /// offline churn never reaches here because the flag is already gone, so
    /// a second offline cannot re-trigger.
    fn connectFailureSheetEligible(self: *SitesController, e: events_mod.CoreEvent.SiteStatusChange) bool {
        if (e.status == .reconnecting) return false; // not yet terminal
        if (!self.pending_connects.remove(e.site_id)) return false; // not a user attempt
        // Terminal: .connected (silent) or .offline. Sheet only a classified
        // failure; a clean offline (error_class == null) clears silently.
        return e.status == .offline and e.error_class != null;
    }

    /// Present the connect-failure popup for a user-initiated attempt.
    /// Title uses the friendly site label (nickname, else host); the reason
    /// is the diagnostic message. Headless (no window) just logs.
    fn showConnectFailure(self: *SitesController, site_id: u64, reason: []const u8) void {
        var label_buf: [256]u8 = undefined;
        const label = self.core.siteLabel(site_id, &label_buf);
        var title_buf: [320]u8 = undefined;
        const title = std.fmt.bufPrint(
            &title_buf,
            "Couldn't connect to {s}",
            .{if (label.len > 0) label else "the server"},
        ) catch "Couldn't connect to the server";
        const detail = if (reason.len > 0) reason else "The connection failed.";
        self.showError(title, detail);
    }

    fn onPromptNeeded(self: *SitesController, e: events_mod.CoreEvent.PromptNeeded) void {
        const token: bridge.PromptToken = .{ .site_id = e.site_id, .prompt_id = e.prompt_id };
        const win = self.win orelse {
            // Headless: a prompt nobody can answer is a refusal, not a hang.
            self.core.respondPrompt(token, switch (e.prompt) {
                .host_key => .{ .host_key = false },
                else => .{ .auth = false },
            });
            return;
        };
        // Payload slices are event-arena-owned and only valid during this
        // dispatch; every sheet builder below copies them into ObjC strings
        // synchronously (makeAlert / buildForm), so nothing is kept.
        switch (e.prompt) {
            .host_key => |hk| {
                const session = self.gpa.create(HostKeySession) catch return;
                session.* = .{ .c = self, .token = token };
                var msg_buf: [320]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Verify the host key for {s}", .{hk.host}) catch
                    "Verify the host key";
                var info_buf: [640]u8 = undefined;
                const info = std.fmt.bufPrint(
                    &info_buf,
                    "Fingerprint:\n{s}\n\nAccept connects and remembers this key (known_hosts).",
                    .{hk.fingerprint},
                ) catch hk.fingerprint;
                panels.beginAlertSheet(win, .{
                    .style = .warning,
                    .message = msg,
                    .informative = info,
                    .buttons = &.{ "Accept", "Cancel" },
                }, session, HostKeySession.onAnswer);
            },
            .password => |p| {
                const session = self.gpa.create(AuthSession) catch return;
                session.* = .{ .c = self, .token = token, .secret_index = 0, .save_index = 1 };
                var title_buf: [320]u8 = undefined;
                const title = std.fmt.bufPrint(&title_buf, "Password for {s}@{s}", .{
                    p.user, p.host,
                }) catch "Password required";
                const fields = [_]panels.FormField{
                    .{ .label = "Password", .kind = .secure },
                    .{ .label = "Save in Keychain", .kind = .popup, .options = &.{ "Yes", "No" }, .initial = "Yes" },
                };
                _ = panels.beginFormSheet(win, title, "Connect", &fields, session, AuthSession.onAnswer);
            },
            .keyboard_interactive => |ki| {
                if (ki.prompts.len == 0) {
                    self.core.respondPrompt(token, .{ .auth = true });
                    return;
                }
                const max_prompts = 8;
                const n = @min(ki.prompts.len, max_prompts);
                var fields_buf: [max_prompts]panels.FormField = undefined;
                var secret_index: usize = 0;
                var have_secret = false;
                for (ki.prompts[0..n], 0..) |prompt, i| {
                    fields_buf[i] = .{
                        .label = prompt.text,
                        .kind = if (prompt.echo) .text else .secure,
                    };
                    if (!prompt.echo and !have_secret) {
                        secret_index = i;
                        have_secret = true;
                    }
                }
                const session = self.gpa.create(AuthSession) catch return;
                // KI answers are often one-time codes: stored transiently
                // (the bridge retry path can only fetch from the store) and
                // deleted once the connect resolves.
                session.* = .{
                    .c = self,
                    .token = token,
                    .secret_index = secret_index,
                    .save_index = null,
                    .store_secret = have_secret,
                };
                const title: []const u8 = if (ki.instruction.len > 0)
                    ki.instruction
                else
                    "Additional authentication required";
                _ = panels.beginFormSheet(win, title, "Continue", fields_buf[0..n], session, AuthSession.onAnswer);
            },
        }
    }

    const HostKeySession = struct {
        c: *SitesController,
        token: bridge.PromptToken,

        fn onAnswer(s: *HostKeySession, result: panels.AlertResult) void {
            const self = s.c;
            defer self.gpa.destroy(s);
            // Accept persists through the core callback reply (known_hosts
            // append happens in the factory once it consumes the answer).
            self.core.respondPrompt(s.token, .{ .host_key = result.button == 0 });
        }
    };

    const AuthSession = struct {
        c: *SitesController,
        token: bridge.PromptToken,
        secret_index: usize,
        /// Index of the "Save in Keychain" popup; null = always transient.
        save_index: ?usize,
        store_secret: bool = true,

        fn onAnswer(s: *AuthSession, result: ?panels.FormResult) void {
            const self = s.c;
            defer self.gpa.destroy(s);
            const r = result orelse {
                self.core.respondPrompt(s.token, .{ .auth = false });
                return;
            };
            const secret = if (s.secret_index < r.values.len) r.values[s.secret_index] else "";
            if (s.store_secret and secret.len > 0) {
                const save = if (s.save_index) |i|
                    i < r.values.len and std.mem.eql(u8, r.values[i], "Yes")
                else
                    false;
                self.storeSecret(s.token.site_id, secret, save);
            }
            self.core.respondPrompt(s.token, .{ .auth = secret.len > 0 });
        }
    };

    // ------------------------------------------------------------------ //
    // Secrets (cred store only — NEVER sites.zon)

    /// Synchronous Keychain write from the main thread: cred/store.zig
    /// prefers workers, but the sheet flows are rare, short generic-password
    /// writes; M2 accepts the trade for a race-free UX.
    fn storeSecret(self: *SitesController, site_id: u64, secret: []const u8, keep: bool) void {
        _ = self.storeSecretChecked(site_id, secret, keep);
    }

    /// True exactly when the credential landed in the store (importers
    /// count successes; the sheet flows ignore the result).
    fn storeSecretChecked(self: *SitesController, site_id: u64, secret: []const u8, keep: bool) bool {
        const site = self.store.get(site_id) orelse return false;
        if (site.account.len == 0) return false; // no account name = no cred key
        const key: cred_store_mod.Key = .{
            .protocol = credProtocol(site.protocol),
            .host = site.host,
            .port = site.effectivePort(),
            .account = site.account,
        };
        var diag: Diagnostics = .{};
        self.core.cred_store.set(&diag, key, secret) catch {
            self.showError("Could not store the credential", diag.message);
            return false;
        };
        if (!keep) self.rememberTransient(site_id, key);
        return true;
    }

    fn rememberTransient(self: *SitesController, site_id: u64, key: cred_store_mod.Key) void {
        const host = self.gpa.dupe(u8, key.host) catch return;
        const account = self.gpa.dupe(u8, key.account) catch {
            self.gpa.free(host);
            return;
        };
        self.transients.append(self.gpa, .{
            .site_id = site_id,
            .protocol = key.protocol,
            .host = host,
            .port = key.port,
            .account = account,
        }) catch {
            self.gpa.free(host);
            self.gpa.free(account);
        };
    }

    /// "Save in Keychain: No" cleanup: once the connect attempt resolves
    /// (connected — the pool cached the secret — or offline), the transient
    /// Keychain item is deleted.
    fn resolveTransients(self: *SitesController, site_id: u64, status: events_mod.SiteStatus) void {
        if (status == .reconnecting) return;
        var i: usize = 0;
        while (i < self.transients.items.len) {
            const t = self.transients.items[i];
            if (t.site_id != site_id) {
                i += 1;
                continue;
            }
            var diag: Diagnostics = .{};
            self.core.cred_store.delete(&diag, .{
                .protocol = t.protocol,
                .host = t.host,
                .port = t.port,
                .account = t.account,
            }) catch {};
            const removed = self.transients.orderedRemove(i);
            self.gpa.free(removed.host);
            self.gpa.free(removed.account);
        }
    }

    fn clearTransients(self: *SitesController) void {
        for (self.transients.items) |t| {
            self.gpa.free(t.host);
            self.gpa.free(t.account);
        }
        self.transients.clearRetainingCapacity();
    }

    // ------------------------------------------------------------------ //
    // Site editor sheet

    pub fn addSite(self: *SitesController) void {
        self.presentEditor(null, null);
    }

    pub fn deleteSite(self: *SitesController, site_id: u64) void {
        const site = (self.store.get(site_id) orelse return).*;
        var diag: Diagnostics = .{};
        self.core.cred_store.delete(&diag, .{
            .protocol = credProtocol(site.protocol),
            .host = site.host,
            .port = site.effectivePort(),
            .account = site.account,
        }) catch {};
        _ = self.store.remove(site_id);
        _ = self.meta.remove(site_id);
        self.meta.save(self.core.io, self.core.config_dir, meta_file) catch {};
        _ = self.statuses.remove(site_id);
        self.persistSites();
        self.syncCore();
        if (self.sidebar) |sb| sb.reload();
    }

    const editor_field_count = 10;
    const editor_host_index = 2;
    const editor_port_index = 3;
    const editor_password_index = 7;

    /// Takes ownership of `draft_in` (the re-present-after-validation path).
    fn presentEditor(self: *SitesController, site_id: ?u64, draft_in: ?*EditorDraft) void {
        const win = self.win orelse {
            if (draft_in) |d| d.destroy(self.gpa);
            return;
        };

        var port_buf: [8]u8 = undefined;
        var name: []const u8 = "";
        var protocol: []const u8 = protocol_titles[0];
        var host: []const u8 = "";
        var port: []const u8 = "";
        var user: []const u8 = "";
        var auth: []const u8 = auth_titles[0];
        var key_path: []const u8 = "";
        var password: []const u8 = "";
        var remote: []const u8 = "";
        var local: []const u8 = "";

        if (draft_in) |d| {
            name = d.vals[0];
            protocol = d.vals[1];
            host = d.vals[2];
            port = d.vals[3];
            user = d.vals[4];
            auth = d.vals[5];
            key_path = d.vals[6];
            password = d.vals[7];
            remote = d.vals[8];
            local = d.vals[9];
        } else if (site_id) |id| {
            if (self.store.get(id)) |site| {
                name = site.name;
                protocol = protocolTitle(site.protocol);
                host = site.host;
                if (site.port != 0) {
                    port = std.fmt.bufPrint(&port_buf, "{d}", .{site.port}) catch "";
                }
                user = site.account;
                remote = site.initial_remote_path;
                local = site.initial_local_path;
                if (self.meta.get(id)) |m| {
                    auth = authTitle(m.method);
                    key_path = m.key_path;
                }
            }
        }

        const fields = [_]panels.FormField{
            .{ .label = "Nickname", .initial = name, .placeholder = "optional" },
            .{ .label = "Protocol", .kind = .popup, .options = &protocol_titles, .initial = protocol },
            .{ .label = "Host", .initial = host, .placeholder = "host or IP (required)" },
            .{ .label = "Port", .initial = port, .placeholder = "default: 22 / 990 / 21" },
            .{ .label = "User", .initial = user },
            .{ .label = "Auth", .kind = .popup, .options = &auth_titles, .initial = auth },
            .{ .label = "Key File", .initial = key_path, .placeholder = "empty = choose via panel" },
            .{ .label = "Password", .kind = .secure, .initial = password, .placeholder = "saved to Keychain only" },
            .{ .label = "Remote Path", .initial = remote, .placeholder = "Server default" },
            .{ .label = "Local Path", .initial = local },
        };
        const session = self.gpa.create(EditorSession) catch {
            if (draft_in) |d| d.destroy(self.gpa);
            return;
        };
        session.* = .{ .c = self, .site_id = site_id, .draft = draft_in };
        _ = panels.beginFormSheet(
            win,
            if (site_id == null) "Add Site" else "Edit Site",
            "Save",
            &fields,
            session,
            EditorSession.onComplete,
        );
    }

    const EditorSession = struct {
        c: *SitesController,
        site_id: ?u64,
        draft: ?*EditorDraft,

        fn onComplete(s: *EditorSession, result: ?panels.FormResult) void {
            const self = s.c;
            const gpa = self.gpa;
            // The presented draft is consumed either way.
            if (s.draft) |d| {
                d.destroy(gpa);
                s.draft = null;
            }
            const r = result orelse {
                gpa.destroy(s);
                return;
            };

            // Inline validation (host/port): refuse the save, explain, and
            // re-present the sheet with everything the user typed intact.
            const host = std.mem.trim(u8, r.values[editor_host_index], " \t");
            const port_text = std.mem.trim(u8, r.values[editor_port_index], " \t");
            const host_ok = hostValid(host);
            const port_val = portFromText(port_text);
            if (!host_ok or port_val == null) {
                const msg: []const u8 = if (!host_ok)
                    "Host is required and must not contain spaces or slashes."
                else
                    "Port must be 1–65535 (leave empty for the protocol default).";
                s.draft = EditorDraft.create(gpa, r.values);
                if (self.win) |w| {
                    panels.beginAlertSheet(w, .{
                        .message = "Invalid site",
                        .informative = msg,
                    }, s, EditorSession.onInvalidAck);
                    return; // session lives until the alert acks
                }
                if (s.draft) |d| d.destroy(gpa);
                gpa.destroy(s);
                return;
            }

            const fields: SiteFields = .{
                .name = std.mem.trim(u8, r.values[0], " \t"),
                .protocol = protocolFromTitle(r.values[1]),
                .host = host,
                .port = port_val.?,
                .account = std.mem.trim(u8, r.values[4], " \t"),
                .initial_remote_path = std.mem.trim(u8, r.values[8], " \t"),
                .initial_local_path = std.mem.trim(u8, r.values[9], " \t"),
                .insecure_skip_verify = if (s.site_id) |id| blk: {
                    const old = self.store.get(id) orelse break :blk false;
                    break :blk old.insecure_skip_verify;
                } else false,
                // No editor controls yet (phase 2): preserve like
                // insecure_skip_verify so hand-edited sites.zon survives.
                .accent = if (s.site_id) |id| blk: {
                    const old = self.store.get(id) orelse break :blk .none;
                    break :blk old.accent;
                } else .none,
                .environment = if (s.site_id) |id| blk: {
                    const old = self.store.get(id) orelse break :blk .none;
                    break :blk old.environment;
                } else .none,
            };
            var site_id: u64 = undefined;
            if (s.site_id) |id| {
                const ok = self.store.update(id, fields) catch false;
                if (!ok) {
                    gpa.destroy(s);
                    return;
                }
                site_id = id;
            } else {
                site_id = self.store.add(fields, true) catch {
                    gpa.destroy(s);
                    return;
                };
            }
            self.persistSites();
            self.syncCore();
            if (self.sidebar) |sb| sb.reload();

            const method = authFromTitle(r.values[5]);
            const key_path = std.mem.trim(u8, r.values[6], " \t");
            self.meta.set(site_id, method, key_path) catch {};
            self.meta.save(self.core.io, self.core.config_dir, meta_file) catch {};

            const password = r.values[editor_password_index];
            if (method == .password and password.len > 0) {
                self.storeSecret(site_id, password, true);
            }
            if (method == .key_file and key_path.len == 0) {
                self.chooseKeyFile(site_id);
            }
            gpa.destroy(s);
        }

        fn onInvalidAck(s: *EditorSession, _: panels.AlertResult) void {
            const self = s.c;
            const site_id = s.site_id;
            const draft = s.draft;
            s.draft = null;
            self.gpa.destroy(s);
            self.presentEditor(site_id, draft);
        }
    };

    fn chooseKeyFile(self: *SitesController, site_id: u64) void {
        const session = self.gpa.create(KeySession) catch return;
        session.* = .{ .c = self, .site_id = site_id };
        _ = panels.beginOpenPanel(self.win, .{
            .choose_files = true,
            .message = "Choose the private key file for this site",
            .prompt = "Choose Key",
        }, session, KeySession.onChosen);
    }

    const KeySession = struct {
        c: *SitesController,
        site_id: u64,

        fn onChosen(s: *KeySession, paths: []const []const u8) void {
            const self = s.c;
            defer self.gpa.destroy(s);
            if (paths.len == 0) return;
            self.meta.set(s.site_id, .key_file, paths[0]) catch return;
            self.meta.save(self.core.io, self.core.config_dir, meta_file) catch {};
        }
    };

    // ------------------------------------------------------------------ //
    // Quick Connect (Cmd+K)

    pub fn quickConnect(self: *SitesController) void {
        self.presentQuickConnect(null);
    }

    /// Takes ownership of `draft` (re-present-after-parse-error path).
    fn presentQuickConnect(self: *SitesController, draft: ?[]u8) void {
        const win = self.win orelse {
            if (draft) |d| self.gpa.free(d);
            return;
        };
        const session = self.gpa.create(QcSession) catch {
            if (draft) |d| self.gpa.free(d);
            return;
        };
        session.* = .{ .c = self, .draft = draft };
        const fields = [_]panels.FormField{
            .{
                .label = "Server",
                .initial = if (draft) |d| d else "",
                .placeholder = "sftp://user@host:port/path — or an ssh-config alias",
            },
            .{ .label = "Save as Site", .kind = .popup, .options = &.{ "No", "Yes" }, .initial = "No" },
        };
        _ = panels.beginFormSheet(win, "Connect to Server", "Connect", &fields, session, QcSession.onComplete);
    }

    const QcSession = struct {
        c: *SitesController,
        draft: ?[]u8 = null,

        fn onComplete(s: *QcSession, result: ?panels.FormResult) void {
            const self = s.c;
            const r = result orelse {
                s.finish();
                return;
            };
            const input = r.values[0];
            const save = r.values.len > 1 and std.mem.eql(u8, r.values[1], "Yes");
            const target = parseTarget(input) catch |err| {
                // Keep the input, explain, re-present.
                const new_draft = self.gpa.dupe(u8, input) catch null;
                if (s.draft) |d| self.gpa.free(d);
                s.draft = new_draft;
                if (self.win) |w| {
                    panels.beginAlertSheet(w, .{
                        .message = "Could not parse the address",
                        .informative = parseErrorMessage(err),
                    }, s, QcSession.onErrAck);
                    return; // session lives until the alert acks
                }
                s.finish();
                return;
            };
            self.connectTarget(target, save);
            s.finish();
        }

        fn onErrAck(s: *QcSession, _: panels.AlertResult) void {
            const self = s.c;
            const draft = s.draft;
            s.draft = null;
            self.gpa.destroy(s);
            self.presentQuickConnect(draft);
        }

        fn finish(s: *QcSession) void {
            if (s.draft) |d| s.c.gpa.free(d);
            s.c.gpa.destroy(s);
        }
    };

    fn connectTarget(self: *SitesController, target: Target, save: bool) void {
        switch (target) {
            .alias => |alias| {
                var mat = self.ssh.materialize(self.gpa, alias, self.home) catch return;
                defer mat.deinit();
                const site_id = self.ensureSite(mat.fields(), save) orelse return;
                self.connectAndList(site_id, null);
            },
            .url => |u| {
                const fields: SiteFields = .{
                    .protocol = u.protocol,
                    .host = u.host,
                    .port = u.port,
                    .account = u.user,
                    .initial_remote_path = u.path,
                };
                const site_id = self.ensureSite(fields, save) orelse return;
                self.connectAndList(site_id, if (u.path.len > 0) u.path else null);
            },
        }
    }

    // ------------------------------------------------------------------ //
    // Import (File ▸ Import ▸ FileZilla… / Cyberduck…)
    //
    // TODO(m3-integrate): the menu tree (controllers/prefs.zig, not this
    // task's file) has no File ▸ Import submenu yet; phase 3 installs
    // `importMenuItems()` there (the items are plain menu_mod.Item values,
    // same contract as serverMenuItems()).

    pub fn importMenuItems(self: *SitesController) [2]menu_mod.Item {
        return .{
            menu_mod.Item.call("From FileZilla…", .{ .ctx = self, .f = cmImportFileZilla }, "", .{}),
            menu_mod.Item.call("From Cyberduck…", .{ .ctx = self, .f = cmImportCyberduck }, "", .{}),
        };
    }

    fn cmImportFileZilla(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).importFileZilla();
    }

    fn cmImportCyberduck(ctx: ?*anyopaque) void {
        fromMenuCtx(ctx).importCyberduck();
    }

    /// Add every non-duplicate parsed site as a persisted entry; with
    /// `import_passwords` the FileZilla secrets go to the Keychain (the UI
    /// flow asks for consent first; headless callers decide directly).
    pub fn applyImport(self: *SitesController, result: *const ImportResult, import_passwords: bool) ImportStats {
        var stats: ImportStats = .{ .skipped = result.skipped };
        for (result.sites) |site| {
            // Imported host/account come from an untrusted file. Control
            // bytes (XML entity refs can decode to NUL/newline) would flow
            // into cred keys, known_hosts lines, and ssh argv — reject them
            // here, the single commit chokepoint for both importers.
            if (!importedFieldSafe(site.fields.host) or !importedFieldSafe(site.fields.account)) {
                stats.skipped += 1;
                continue;
            }
            if (self.store.findMatching(site.fields) != null) {
                stats.duplicates += 1;
                continue;
            }
            const site_id = self.store.add(site.fields, true) catch {
                stats.skipped += 1;
                continue;
            };
            stats.imported += 1;
            if (import_passwords) {
                if (site.password) |pw| {
                    if (pw.len > 0 and self.storeSecretChecked(site_id, pw, true)) {
                        stats.passwords_stored += 1;
                    }
                }
            }
        }
        if (stats.imported > 0) {
            self.persistSites();
            self.syncCore();
            if (self.sidebar) |sb| sb.reload();
        }
        return stats;
    }

    pub fn importFileZilla(self: *SitesController) void {
        const session = self.gpa.create(ImportPickSession) catch return;
        session.* = .{ .c = self, .kind = .filezilla };
        _ = panels.beginOpenPanel(self.win, .{
            .choose_files = true,
            .message = "Choose FileZilla's sitemanager.xml (File ▸ Export… in FileZilla)",
            .prompt = "Import",
        }, session, ImportPickSession.onChosen);
    }

    pub fn importCyberduck(self: *SitesController) void {
        const session = self.gpa.create(ImportPickSession) catch return;
        session.* = .{ .c = self, .kind = .cyberduck };
        _ = panels.beginOpenPanel(self.win, .{
            .choose_files = true,
            .choose_directories = true,
            .allows_multiple = true,
            .message = "Choose Cyberduck .duck bookmarks (or the whole Bookmarks folder)",
            .prompt = "Import",
        }, session, ImportPickSession.onChosen);
    }

    const ImportKind = enum { filezilla, cyberduck };

    const ImportPickSession = struct {
        c: *SitesController,
        kind: ImportKind,

        fn onChosen(s: *ImportPickSession, paths: []const []const u8) void {
            const self = s.c;
            defer self.gpa.destroy(s);
            if (paths.len == 0) return;
            switch (s.kind) {
                .filezilla => self.finishFileZillaImport(paths[0]),
                .cyberduck => self.finishCyberduckImport(paths),
            }
        }
    };

    fn finishFileZillaImport(self: *SitesController, path: []const u8) void {
        const xml = readWholeFile(self.gpa, self.core.io, path) catch |err| {
            self.showError("Could not read the FileZilla export", @errorName(err));
            return;
        };
        defer self.gpa.free(xml);
        var result = parseFileZilla(self.gpa, xml) catch return;

        if (result.sites.len == 0) {
            result.deinit();
            self.showError("Nothing to import", "The file contains no supported FTP/FTPS/SFTP entries.");
            return;
        }

        // Consent before any secret leaves the export: the alert names the
        // exact count; "Sites Only" imports without touching the Keychain.
        const win = self.win orelse {
            // Headless: no consent surface = no secrets (askPrompt precedent).
            const stats = self.applyImport(&result, false);
            result.deinit();
            std.log.info("relay sites: imported {d} FileZilla site(s) ({d} duplicates)", .{
                stats.imported, stats.duplicates,
            });
            return;
        };
        const pw_count = result.passwordCount();
        if (pw_count == 0) {
            const stats = self.applyImport(&result, false);
            result.deinit();
            self.presentImportSummary(stats);
            return;
        }
        const session = self.gpa.create(ImportConsentSession) catch {
            result.deinit();
            return;
        };
        session.* = .{ .c = self, .result = result };
        var msg_buf: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Import {d} saved password{s} to the Keychain?", .{
            pw_count, if (pw_count == 1) "" else "s",
        }) catch "Import saved passwords to the Keychain?";
        panels.beginAlertSheet(win, .{
            .message = msg,
            .informative = "FileZilla stores passwords base64-encoded in the export. " ++
                "Relay keeps credentials only in the macOS Keychain — never in its config files.",
            .buttons = &.{ "Import with Passwords", "Sites Only", "Cancel" },
        }, session, ImportConsentSession.onAnswer);
    }

    const ImportConsentSession = struct {
        c: *SitesController,
        result: ImportResult,

        fn onAnswer(s: *ImportConsentSession, alert: panels.AlertResult) void {
            const self = s.c;
            defer {
                s.result.deinit();
                self.gpa.destroy(s);
            }
            switch (alert.button) {
                0, 1 => {
                    const stats = self.applyImport(&s.result, alert.button == 0);
                    self.presentImportSummary(stats);
                },
                else => {}, // Cancel: nothing imported
            }
        }
    };

    fn finishCyberduckImport(self: *SitesController, paths: []const []const u8) void {
        const gpa = self.gpa;
        const io = self.core.io;

        var files: std.ArrayList([]u8) = .empty;
        defer {
            for (files.items) |file| gpa.free(file);
            files.deinit(gpa);
        }
        var unreadable: usize = 0;
        for (paths) |path| {
            if (std.mem.endsWith(u8, path, ".duck")) {
                appendOwnedFile(gpa, io, &files, path) catch {
                    unreadable += 1;
                };
                continue;
            }
            // A folder selection: scan it (flat — Cyberduck's bookmark dir).
            var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch {
                unreadable += 1;
                continue;
            };
            defer dir.close(io);
            var it = dir.iterate();
            var name_buf: [2048]u8 = undefined;
            while (it.next(io) catch null) |entry| {
                if (entry.kind != .file) continue;
                if (!std.mem.endsWith(u8, entry.name, ".duck")) continue;
                const full = std.fmt.bufPrint(&name_buf, "{s}/{s}", .{ path, entry.name }) catch continue;
                appendOwnedFile(gpa, io, &files, full) catch {
                    unreadable += 1;
                };
            }
        }

        if (files.items.len == 0) {
            self.showError("Nothing to import", "No readable .duck bookmarks in the selection.");
            return;
        }
        var result = parseCyberduck(gpa, contentsSlice(files.items)) catch return;
        defer result.deinit();
        var stats = self.applyImport(&result, false); // .duck files carry no secrets
        stats.skipped += unreadable;
        if (self.win != null) {
            self.presentImportSummary(stats);
        } else {
            std.log.info("relay sites: imported {d} Cyberduck bookmark(s) ({d} duplicates)", .{
                stats.imported, stats.duplicates,
            });
        }
    }

    fn appendOwnedFile(gpa: Allocator, io: std.Io, files: *std.ArrayList([]u8), path: []const u8) !void {
        const data = try readWholeFile(gpa, io, path);
        errdefer gpa.free(data);
        try files.append(gpa, data);
    }

    fn contentsSlice(files: []const []u8) []const []const u8 {
        return @ptrCast(files);
    }

    fn presentImportSummary(self: *SitesController, stats: ImportStats) void {
        const win = self.win orelse return;
        var msg_buf: [96]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Imported {d} site{s}", .{
            stats.imported, if (stats.imported == 1) "" else "s",
        }) catch "Import complete";
        var info_buf: [192]u8 = undefined;
        const info = std.fmt.bufPrint(
            &info_buf,
            "{d} duplicate{s} skipped · {d} unsupported entr{s} skipped · {d} password{s} stored",
            .{
                stats.duplicates,       if (stats.duplicates == 1) "" else "s",
                stats.skipped,          if (stats.skipped == 1) "y" else "ies",
                stats.passwords_stored, if (stats.passwords_stored == 1) "" else "s",
            },
        ) catch "";
        const session = self.gpa.create(ImportAckSession) catch return;
        session.* = .{ .c = self };
        panels.beginAlertSheet(win, .{
            .message = msg,
            .informative = info,
        }, session, ImportAckSession.onAck);
    }

    const ImportAckSession = struct {
        c: *SitesController,

        fn onAck(s: *ImportAckSession, _: panels.AlertResult) void {
            s.c.gpa.destroy(s);
        }
    };

    // ------------------------------------------------------------------ //
    // Errors

    fn showError(self: *SitesController, message: []const u8, detail: []const u8) void {
        const win = self.win orelse {
            std.log.warn("relay sites: {s}: {s}", .{ message, detail });
            return;
        };
        panels.presentErrorSheet(win, message, detail);
    }
};

/// Form-sheet draft: the user's typed values, preserved across the
/// validation-error round trip. The password slot is zeroed before free.
const EditorDraft = struct {
    vals: [SitesController.editor_field_count][]u8,

    fn create(gpa: Allocator, values: []const []const u8) ?*EditorDraft {
        if (values.len != SitesController.editor_field_count) return null;
        const d = gpa.create(EditorDraft) catch return null;
        for (values, 0..) |v, i| {
            d.vals[i] = gpa.dupe(u8, v) catch {
                for (d.vals[0..i]) |owned| gpa.free(owned);
                gpa.destroy(d);
                return null;
            };
        }
        return d;
    }

    fn destroy(d: *EditorDraft, gpa: Allocator) void {
        std.crypto.secureZero(u8, d.vals[SitesController.editor_password_index]);
        for (d.vals) |v| gpa.free(v);
        gpa.destroy(d);
    }
};

fn draftFromFields(gpa: Allocator, fields: SiteFields, auth: AuthMethod) ?*EditorDraft {
    var port_buf: [8]u8 = undefined;
    const port_text: []const u8 = if (fields.port != 0)
        std.fmt.bufPrint(&port_buf, "{d}", .{fields.port}) catch ""
    else
        "";
    const vals = [SitesController.editor_field_count][]const u8{
        fields.name,
        protocolTitle(fields.protocol),
        fields.host,
        port_text,
        fields.account,
        authTitle(auth),
        "",
        "",
        fields.initial_remote_path,
        fields.initial_local_path,
    };
    return EditorDraft.create(gpa, &vals);
}

// ---------------------------------------------------------------------------
// Tests — headless per docs/spikes/ui.md: pure parsing/stores against tmp
// dirs, vtable-level sidebar checks, and the connect flow against a real
// manual-pump AppCore. Window-dependent sheets are phase 3 smoke territory;
// the gated visual test below shows the sidebar in a real window.
// ---------------------------------------------------------------------------

const testing = std.testing;
const FakeStore = relay.cred.fake.FakeStore;

test "parseTarget: full sftp URL with user, port and path" {
    const t = try parseTarget("sftp://deploy@web1.example.com:2222/var/www");
    try testing.expectEqual(sites_mod.Protocol.sftp, t.url.protocol);
    try testing.expectEqualStrings("deploy", t.url.user);
    try testing.expectEqualStrings("web1.example.com", t.url.host);
    try testing.expectEqual(@as(u16, 2222), t.url.port);
    try testing.expectEqualStrings("/var/www", t.url.path);
}

test "parseTarget: scheme variants, defaults, IPv6" {
    const ftp = try parseTarget("ftp://ftp.example.org");
    try testing.expectEqual(sites_mod.Protocol.ftp, ftp.url.protocol);
    try testing.expectEqual(@as(u16, 0), ftp.url.port);
    try testing.expectEqualStrings("", ftp.url.path);
    try testing.expectEqualStrings("", ftp.url.user);

    // Scheme is case-insensitive; IPv6 hosts ride in brackets.
    const ftps = try parseTarget("FTPS://[2001:db8::1]:990/pub");
    try testing.expectEqual(sites_mod.Protocol.ftps, ftps.url.protocol);
    try testing.expectEqualStrings("2001:db8::1", ftps.url.host);
    try testing.expectEqual(@as(u16, 990), ftps.url.port);
    try testing.expectEqualStrings("/pub", ftps.url.path);

    const v6_no_port = try parseTarget("sftp://root@[::1]/");
    try testing.expectEqualStrings("::1", v6_no_port.url.host);
    try testing.expectEqual(@as(u16, 0), v6_no_port.url.port);
    try testing.expectEqualStrings("/", v6_no_port.url.path);
    try testing.expectEqualStrings("root", v6_no_port.url.user);

    // Surrounding whitespace is trimmed.
    const trimmed = try parseTarget("  sftp://h  ");
    try testing.expectEqualStrings("h", trimmed.url.host);
}

test "parseTarget: bare ssh aliases" {
    const t = try parseTarget("work");
    try testing.expectEqualStrings("work", t.alias);
    const dotted = try parseTarget("web-1.example_x");
    try testing.expectEqualStrings("web-1.example_x", dotted.alias);
}

test "parseTarget: errors" {
    try testing.expectError(error.EmptyInput, parseTarget("   "));
    try testing.expectError(error.UnknownScheme, parseTarget("gopher://x"));
    try testing.expectError(error.MissingHost, parseTarget("sftp://"));
    try testing.expectError(error.MissingHost, parseTarget("sftp://user@:22"));
    try testing.expectError(error.BadPort, parseTarget("sftp://h:0"));
    try testing.expectError(error.BadPort, parseTarget("sftp://h:99999"));
    try testing.expectError(error.BadPort, parseTarget("sftp://h:abc"));
    try testing.expectError(error.BadHost, parseTarget("sftp://[::1")); // unclosed bracket
    try testing.expectError(error.BadHost, parseTarget("sftp://::1")); // bare IPv6
    try testing.expectError(error.BadAlias, parseTarget("two words"));
    try testing.expectError(error.BadAlias, parseTarget("a/b"));
    // Every error renders a user-facing message.
    inline for (@typeInfo(ParseTargetError).error_set.?) |e| {
        try testing.expect(parseErrorMessage(@field(ParseTargetError, e.name)).len > 0);
    }
}

test "inline validation: host and port" {
    try testing.expect(hostValid("example.com"));
    try testing.expect(hostValid("::1"));
    try testing.expect(!hostValid(""));
    try testing.expect(!hostValid("a b"));
    try testing.expect(!hostValid("a/b"));

    try testing.expectEqual(@as(?u16, 0), portFromText("")); // protocol default
    try testing.expectEqual(@as(?u16, 2222), portFromText("2222"));
    try testing.expectEqual(@as(?u16, null), portFromText("0"));
    try testing.expectEqual(@as(?u16, null), portFromText("banana"));
    try testing.expectEqual(@as(?u16, null), portFromText("70000"));
}

test "SiteStore: CRUD round-trips through sites.zon in a tmp dir" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var store = SiteStore.init(testing.allocator);
    defer store.deinit();

    const id1 = try store.add(.{
        .name = "prod web",
        .protocol = .sftp,
        .host = "web1.example.com",
        .port = 2222,
        .account = "deploy",
        .initial_remote_path = "/var/www",
        .initial_local_path = "/Users/x/dev",
    }, true);
    const id2 = try store.add(.{ .protocol = .ftps, .host = "ftp.example.org", .account = "anonymous" }, true);
    const eph = try store.add(.{ .protocol = .sftp, .host = "tmp.example" }, false);
    try testing.expect(id1 != id2 and id2 != eph);
    try testing.expectEqual(@as(usize, 2), store.persistedCount());

    // Ephemeral sites are visible to the core slice but never written out.
    const core_view = try store.coreSlice();
    try testing.expectEqual(@as(usize, 3), core_view.len);
    try store.saveTo(io, tmp.dir, "sites.zon", testing.allocator);
    const raw = try settings_mod.readFileZ(io, tmp.dir, "sites.zon", testing.allocator);
    defer testing.allocator.free(raw);
    try testing.expect(std.mem.indexOf(u8, raw, "tmp.example") == null);
    try testing.expect(std.mem.indexOf(u8, raw, "web1.example.com") != null);

    var loaded = try sites_mod.load(io, tmp.dir, "sites.zon", testing.allocator);
    defer loaded.deinit();
    try testing.expectEqual(@as(usize, 2), loaded.value.sites.len);
    try testing.expectEqualStrings("prod web", loaded.value.sites[0].name);
    try testing.expectEqual(@as(u16, 2222), loaded.value.sites[0].port);
    try testing.expectEqualStrings("/var/www", loaded.value.sites[0].initial_remote_path);

    // loadFrom preserves ids and keeps allocating past the max.
    var store2 = SiteStore.init(testing.allocator);
    defer store2.deinit();
    try store2.loadFrom(loaded.value);
    try testing.expectEqual(@as(usize, 2), store2.persistedCount());
    try testing.expectEqualStrings("deploy", store2.get(id1).?.account);
    const id_next = try store2.add(.{ .host = "new.example" }, true);
    try testing.expect(id_next > id2);

    // Update + remove.
    try testing.expect(try store.update(id1, .{
        .name = "prod web",
        .protocol = .sftp,
        .host = "web2.example.com",
        .account = "deploy",
    }));
    try testing.expectEqualStrings("web2.example.com", store.get(id1).?.host);
    try testing.expect(store.remove(id2));
    try testing.expect(!store.remove(id2));
    try testing.expectEqual(@as(usize, 1), store.persistedCount());
    try testing.expectEqualStrings("web2.example.com", store.persistedAt(0).?.site.host);
    try testing.expect(store.persistedAt(1) == null);

    // findMatching keys on (protocol, host, effective port, account).
    try testing.expectEqual(@as(?u64, eph), store.findMatching(.{ .protocol = .sftp, .host = "tmp.example", .port = 22 }));
    try testing.expectEqual(@as(?u64, null), store.findMatching(.{ .protocol = .sftp, .host = "tmp.example", .port = 2222 }));
}

test "History: ring semantics + persistence round-trip" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var h = History.init(testing.allocator);
    defer h.deinit();

    // Dedupe moves to front; same site with another path is a new entry.
    try h.push(1, "box", "/srv");
    try h.push(2, "ftp", "/pub");
    try h.push(1, "box", "/srv");
    try testing.expectEqual(@as(usize, 2), h.entries.items.len);
    try testing.expectEqual(@as(u64, 1), h.entries.items[0].site_id);
    try h.push(1, "box", "/other");
    try testing.expectEqual(@as(usize, 3), h.entries.items.len);

    // Ring caps at history_cap, evicting the oldest.
    var i: u64 = 0;
    while (i < history_cap + 5) : (i += 1) {
        var path_buf: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/dir/{d}", .{i});
        try h.push(100 + i, "site", path);
    }
    try testing.expectEqual(history_cap, h.entries.items.len);
    try testing.expectEqualStrings("/dir/24", h.entries.items[0].path);

    try h.save(io, tmp.dir, history_file);
    var fresh = History.init(testing.allocator);
    defer fresh.deinit();
    fresh.load(io, tmp.dir, history_file);
    try testing.expectEqual(history_cap, fresh.entries.items.len);
    try testing.expectEqualStrings("/dir/24", fresh.entries.items[0].path);
    try testing.expectEqualStrings("site", fresh.entries.items[0].label);

    // removeAt + clear + corrupt file degrade gracefully.
    fresh.removeAt(0);
    try testing.expectEqual(history_cap - 1, fresh.entries.items.len);
    fresh.clear();
    try testing.expectEqual(@as(usize, 0), fresh.entries.items.len);
    try tmp.dir.writeFile(io, .{ .sub_path = "corrupt.zon", .data = "}{ nope" });
    fresh.load(io, tmp.dir, "corrupt.zon");
    try testing.expectEqual(@as(usize, 0), fresh.entries.items.len);
}

test "AuthMetaStore: set/get/remove + zon round-trip" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var m = AuthMetaStore.init(testing.allocator);
    defer m.deinit();
    try m.set(1, .password, "");
    try m.set(2, .key_file, "/Users/x/.ssh/id_ed25519");
    try m.set(1, .agent, ""); // overwrite
    try testing.expectEqual(AuthMethod.agent, m.get(1).?.method);
    try testing.expectEqualStrings("/Users/x/.ssh/id_ed25519", m.get(2).?.key_path);

    try m.save(io, tmp.dir, meta_file);
    var fresh = AuthMetaStore.init(testing.allocator);
    defer fresh.deinit();
    fresh.load(io, tmp.dir, meta_file);
    try testing.expectEqual(AuthMethod.key_file, fresh.get(2).?.method);
    try testing.expectEqualStrings("/Users/x/.ssh/id_ed25519", fresh.get(2).?.key_path);
    try testing.expect(fresh.get(3) == null);
    try testing.expect(fresh.remove(1));
    try testing.expect(!fresh.remove(1));
}

test "SshGroup: concrete aliases only; materialization resolves the config" {
    var g = SshGroup.init(testing.allocator);
    defer g.deinit();

    try g.setFromText(
        \\# comment
        \\Host work *.wild ?.q
        \\  HostName files.example.com
        \\  User fredrik
        \\  Port 2200
        \\Host plain work
        \\  User other
        \\Host !nope bare
        \\Host *
        \\  User fallback
    );
    try testing.expectEqual(@as(usize, 3), g.aliases.items.len);
    try testing.expectEqualStrings("work", g.aliases.items[0]);
    try testing.expectEqualStrings("plain", g.aliases.items[1]);
    try testing.expectEqualStrings("bare", g.aliases.items[2]);

    // Ephemeral-site recipe: protocol sftp, resolved host/port/user.
    var work = try g.materialize(testing.allocator, "work", "/home/t");
    defer work.deinit();
    const wf = work.fields();
    try testing.expectEqual(sites_mod.Protocol.sftp, wf.protocol);
    try testing.expectEqualStrings("work", wf.name);
    try testing.expectEqualStrings("files.example.com", wf.host);
    try testing.expectEqual(@as(u16, 2200), wf.port);
    try testing.expectEqualStrings("fredrik", wf.account);

    // No HostName -> the alias is the host; port 22 stays implicit (0).
    var plain = try g.materialize(testing.allocator, "plain", "/home/t");
    defer plain.deinit();
    try testing.expectEqualStrings("plain", plain.fields().host);
    try testing.expectEqual(@as(u16, 0), plain.fields().port);
    try testing.expectEqualStrings("other", plain.fields().account);

    // Unknown alias still materializes (Host * applies).
    var zz = try g.materialize(testing.allocator, "zz.example", "/home/t");
    defer zz.deinit();
    try testing.expectEqualStrings("zz.example", zz.fields().host);
    try testing.expectEqualStrings("fallback", zz.fields().account);

    // A missing config file is an empty group, and materialize still works.
    var none = SshGroup.init(testing.allocator);
    defer none.deinit();
    var bare = try none.materialize(testing.allocator, "justhost", "/home/t");
    defer bare.deinit();
    try testing.expectEqualStrings("justhost", bare.fields().host);
    try testing.expectEqual(@as(usize, 0), none.aliases.items.len);

    try testing.expect(SshGroup.isConcreteAlias("a.b"));
    try testing.expect(!SshGroup.isConcreteAlias("*.b"));
    try testing.expect(!SshGroup.isConcreteAlias("a?b"));
    try testing.expect(!SshGroup.isConcreteAlias("!a"));
    try testing.expect(!SshGroup.isConcreteAlias(""));
}

// --- importer tests (fixture corpus: test/fixtures/importers/) --------------

/// Walks up from the test cwd to the repo root (marked by build.zig.zon),
/// because `zig build` does not normalize the runner's cwd — the same
/// pattern as the ftp listing corpus loaders.
fn readImporterFixture(gpa: Allocator, name: []const u8) ![]u8 {
    const io = std.testing.io;
    var prefix: [30]u8 = ("../" ** 10).*;
    var prefix_len: usize = 0;
    while (prefix_len <= prefix.len) : (prefix_len += 3) {
        var path_buf: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}test/fixtures/importers/{s}", .{
            prefix[0..prefix_len], name,
        });
        return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err|
            switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
    }
    return error.FileNotFound;
}

fn findImported(sites: []const ImportedSite, host: []const u8) ?*const ImportedSite {
    for (sites) |*site| {
        if (std.mem.eql(u8, site.fields.host, host)) return site;
    }
    return null;
}

test "xmlDecode: named entities + character references (ASCII range)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("a&b<c>d\"e'f", try xmlDecode(a, "a&amp;b&lt;c&gt;d&quot;e&apos;f"));
    try testing.expectEqualStrings("A/Z", try xmlDecode(a, "&#65;/&#x5A;"));
    // Malformed references copy verbatim instead of erroring.
    try testing.expectEqualStrings("&nope;&#xZZ;&", try xmlDecode(a, "&nope;&#xZZ;&"));
    // No-entity fast path.
    try testing.expectEqualStrings("plain", try xmlDecode(a, "plain"));
}

test "parseFileZilla: fixture corpus maps protocols, logontypes, ports, passwords" {
    const xml = try readImporterFixture(testing.allocator, "filezilla_sitemanager.xml");
    defer testing.allocator.free(xml);

    var result = try parseFileZilla(testing.allocator, xml);
    defer result.deinit();

    // 9 <Server> blocks: 7 supported, S3 (protocol 7) + empty host skipped.
    try testing.expectEqual(@as(usize, 7), result.sites.len);
    try testing.expectEqual(@as(usize, 2), result.skipped);
    try testing.expectEqual(@as(usize, 3), result.passwordCount());

    // Logontype 1 + base64 password; custom port survives.
    const web1 = findImported(result.sites, "web1.example.com").?;
    try testing.expectEqual(sites_mod.Protocol.sftp, web1.fields.protocol);
    try testing.expectEqual(@as(u16, 2222), web1.fields.port);
    try testing.expectEqualStrings("deploy", web1.fields.account);
    try testing.expectEqualStrings("Prod Web", web1.fields.name);
    try testing.expectEqualStrings("secret pa55!", web1.password.?);

    // Legacy plaintext password (entity-decoded); default port stored as 0;
    // LocalDir maps to initial_local_path.
    const legacy = findImported(result.sites, "ftp.example.org").?;
    try testing.expectEqual(sites_mod.Protocol.ftp, legacy.fields.protocol);
    try testing.expectEqual(@as(u16, 0), legacy.fields.port);
    try testing.expectEqualStrings("Legacy FTP & Friends", legacy.fields.name);
    try testing.expectEqualStrings("/Users/alice/Sites & Stuff", legacy.fields.initial_local_path);
    try testing.expectEqualStrings("plain&old", legacy.password.?);

    // Folder-nested server; protocol 3 = implicit FTPS (990 = default = 0);
    // Logontype 4 (account) keeps the password; UTF-8 user survives.
    const secure = findImported(result.sites, "secure.example.net").?;
    try testing.expectEqual(sites_mod.Protocol.ftps, secure.fields.protocol);
    try testing.expectEqual(@as(u16, 0), secure.fields.port);
    try testing.expectEqualStrings("café-user", secure.fields.account);
    try testing.expectEqualStrings("Key&Café pass'word", secure.password.?);

    // Protocol 4 = explicit TLS → ftps; Logontype 2 (ask) drops the stored
    // secret but keeps the identity; non-default port survives.
    const ask = findImported(result.sites, "ask.example.com").?;
    try testing.expectEqual(sites_mod.Protocol.ftps, ask.fields.protocol);
    try testing.expectEqual(@as(u16, 2121), ask.fields.port);
    try testing.expectEqualStrings("bob", ask.fields.account);
    try testing.expectEqual(@as(?[]const u8, null), ask.password);

    // Protocol 6 = insecure FTP; Logontype 0 = anonymous identity.
    const mirror = findImported(result.sites, "mirror.example.com").?;
    try testing.expectEqual(sites_mod.Protocol.ftp, mirror.fields.protocol);
    try testing.expectEqualStrings("anonymous", mirror.fields.account);
    try testing.expectEqual(@as(?[]const u8, null), mirror.password);

    // Logontype 5 (key file): identity only.
    const key = findImported(result.sites, "key.example.com").?;
    try testing.expectEqualStrings("git", key.fields.account);
    try testing.expectEqual(@as(?[]const u8, null), key.password);

    // Corrupt base64 yields a null password but the site still imports.
    const corrupt = findImported(result.sites, "corrupt.example.com").?;
    try testing.expectEqual(@as(?[]const u8, null), corrupt.password);
}

test "parseCyberduck: fixture bookmarks map the plist subset" {
    const gpa = testing.allocator;
    const names = [_][]const u8{
        "prod_web.duck", "mirror_ftp.duck", "secure_drop.duck", "s3_bucket.duck",
    };
    var files: [names.len][]u8 = undefined;
    var loaded: usize = 0;
    defer for (files[0..loaded]) |file| gpa.free(file);
    for (names, 0..) |name, i| {
        files[i] = try readImporterFixture(gpa, name);
        loaded = i + 1;
    }

    var result = try parseCyberduck(gpa, &.{ files[0], files[1], files[2], files[3] });
    defer result.deinit();

    try testing.expectEqual(@as(usize, 3), result.sites.len);
    try testing.expectEqual(@as(usize, 1), result.skipped); // the s3 bookmark
    try testing.expectEqual(@as(usize, 0), result.passwordCount()); // never any

    const prod = findImported(result.sites, "web1.example.com").?;
    try testing.expectEqual(sites_mod.Protocol.sftp, prod.fields.protocol);
    try testing.expectEqual(@as(u16, 2222), prod.fields.port);
    try testing.expectEqualStrings("deploy", prod.fields.account);
    try testing.expectEqualStrings("Prod Web & API", prod.fields.name);
    try testing.expectEqualStrings("/var/www/my site", prod.fields.initial_remote_path);

    // <integer> port at the protocol default canonicalizes to 0.
    const mirror = findImported(result.sites, "mirror.example.org").?;
    try testing.expectEqual(sites_mod.Protocol.ftp, mirror.fields.protocol);
    try testing.expectEqual(@as(u16, 0), mirror.fields.port);
    try testing.expectEqualStrings("anonymous", mirror.fields.account);

    const secure = findImported(result.sites, "secure.example.net").?;
    try testing.expectEqual(sites_mod.Protocol.ftps, secure.fields.protocol);
    try testing.expectEqual(@as(u16, 0), secure.fields.port); // 990 = default
    try testing.expectEqualStrings("café-user", secure.fields.account);
    try testing.expectEqualStrings("/drop", secure.fields.initial_remote_path);
}

// --- controller-level tests (real AppCore, manual pump, no window) ---------

const Harness = struct {
    tmp_conf: std.testing.TmpDir,
    tmp_root: std.testing.TmpDir,
    fake: FakeStore,
    core: *bridge.AppCore,

    fn start(h: *Harness, stage_sites: ?sites_mod.SiteList) !void {
        h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
        h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
        h.fake = .init(testing.allocator);
        if (stage_sites) |list| {
            try sites_mod.save(list, std.testing.io, h.tmp_conf.dir, bridge.sites_file, testing.allocator);
        }
        h.core = try bridge.AppCore.initOptions(testing.allocator, .{
            .pump = .manual,
            .config_dir = h.tmp_conf.dir,
            .local_root = h.tmp_root.dir,
            .cred_store = h.fake.credStore(),
        });
    }

    fn stop(h: *Harness) void {
        h.core.shutdown();
        h.fake.deinit();
        h.tmp_root.cleanup();
        h.tmp_conf.cleanup();
    }

    const wait_timeout_ms: u64 = 5_000;

    fn waitUntil(h: *Harness, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool) !void {
        const io = h.core.io;
        const deadline = std.Io.Clock.awake.now(io).nanoseconds +
            @as(i96, wait_timeout_ms) * std.time.ns_per_ms;
        while (true) {
            h.core.drainNow();
            if (pred(ctx)) return;
            if (std.Io.Clock.awake.now(io).nanoseconds > deadline) return error.Timeout;
            io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }
};

const test_pane: bridge.PaneToken = 42;

const TestPane = struct {
    connecting_site: u64 = 0,
    connecting_pane: bridge.PaneToken = 0,

    fn activeToken(_: ?*anyopaque) bridge.PaneToken {
        return test_pane;
    }

    fn connecting(ctx: ?*anyopaque, pane: bridge.PaneToken, site_id: u64) void {
        const self: *TestPane = @ptrCast(@alignCast(ctx.?));
        self.connecting_pane = pane;
        self.connecting_site = site_id;
    }
};

test "controller: sidebar vtable, connect flow, history persistence, status tracking" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{.{
        .id = 7,
        .name = "box",
        .protocol = .sftp,
        .host = "box.example",
        .account = "root",
        .initial_remote_path = "/srv",
    }} });

    var pane: TestPane = .{};
    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = true,
        .sidebar_autosave = null,
        .pane_host = .{
            .ctx = &pane,
            .active_token = TestPane.activeToken,
            .connecting = TestPane.connecting,
        },
    });
    // Listener ctx pointers live in the bridge: shut the core down BEFORE
    // freeing the controller.
    defer ctrl.destroy();
    defer h.stop();

    // Data-source vtable (what the outline asks at draw time).
    const ctx: *anyopaque = @ptrCast(ctrl);
    try testing.expectEqual(section_count, SitesController.dsSectionCount(ctx));
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("Servers", SitesController.dsSectionTitle(ctx, section_servers, &buf));
    try testing.expectEqualStrings("SSH Config", SitesController.dsSectionTitle(ctx, section_ssh, &buf));
    try testing.expectEqualStrings("History", SitesController.dsSectionTitle(ctx, section_history, &buf));
    try testing.expectEqual(@as(usize, 1), SitesController.dsRowCount(ctx, section_servers));
    try testing.expectEqual(@as(usize, 0), SitesController.dsRowCount(ctx, section_ssh));
    try testing.expectEqual(@as(usize, 0), SitesController.dsRowCount(ctx, section_history));
    const row = SitesController.dsRowItem(ctx, section_servers, 0, &buf);
    try testing.expectEqualStrings("box", row.title);
    try testing.expectEqual(outline_mod.StatusDot.none, row.status); // no status yet
    try testing.expect(ctrl.sidebarView() != null);

    // Return/double-click on the Servers row = connect in the active pane.
    SitesController.dsActivate(ctx, .{ .section = section_servers, .row = 0 });
    try testing.expectEqual(test_pane, pane.connecting_pane);
    try testing.expectEqual(@as(u64, 7), pane.connecting_site);
    try testing.expectEqual(@as(?u64, 7), ctrl.pane_sites.get(test_pane));

    // The unwired factory reports a classified offline status through the
    // pump; the controller tracks it.
    const Pred = struct {
        fn sawStatus(ctrl_ptr: *SitesController) bool {
            return ctrl_ptr.siteStatus(7) != null;
        }
    };
    try h.waitUntil(ctrl, Pred.sawStatus);
    try testing.expectEqual(events_mod.SiteStatus.offline, ctrl.siteStatus(7).?);

    // History recorded the (site, path) pair and persisted it.
    try testing.expectEqual(@as(usize, 1), ctrl.history.entries.items.len);
    try testing.expectEqualStrings("box", ctrl.history.entries.items[0].label);
    try testing.expectEqualStrings("/srv", ctrl.history.entries.items[0].path);
    try testing.expectEqual(@as(usize, 1), SitesController.dsRowCount(ctx, section_history));
    var persisted = History.init(testing.allocator);
    defer persisted.deinit();
    persisted.load(h.core.io, h.core.config_dir, history_file);
    try testing.expectEqual(@as(usize, 1), persisted.entries.items.len);
    try testing.expectEqualStrings("/srv", persisted.entries.items[0].path);

    // History row activation reconnects with the recorded path.
    SitesController.dsActivate(ctx, .{ .section = section_history, .row = 0 });
    try testing.expectEqual(@as(usize, 1), ctrl.history.entries.items.len);

    // Cmd+Shift+K clears the pane binding (disconnect of a never-connected
    // pool is a safe no-op).
    ctrl.disconnectActivePane();
    try testing.expectEqual(@as(?u64, null), ctrl.pane_sites.get(test_pane));
    ctrl.disconnectActivePane(); // idempotent

    // Prompts with no window auto-deny instead of hanging the core.
    ctrl.onPromptNeeded(.{
        .site_id = 7,
        .prompt_id = 1,
        .prompt = .{ .host_key = .{ .fingerprint = "SHA256:abcdef", .host = "box.example" } },
    });
    ctrl.onPromptNeeded(.{
        .site_id = 7,
        .prompt_id = 2,
        .prompt = .{ .password = .{ .user = "root", .host = "box.example" } },
    });

    // Server menu items for phase 3's menu bar.
    const items = ctrl.serverMenuItems();
    try testing.expectEqualStrings("Connect to Server…", items[0].leaf.title);
    try testing.expectEqualStrings("k", items[0].leaf.key);
    try testing.expect(items[1].leaf.mods.shift);
}

test "controller: dsRowItem maps site status to the sidebar dot" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{.{
        .id = 7,
        .name = "box",
        .protocol = .sftp,
        .host = "box.example",
        .account = "root",
    }} });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    const ctx: *anyopaque = @ptrCast(ctrl);
    var buf: [256]u8 = undefined;

    ctrl.onSiteStatus(.{ .site_id = 7, .status = .connected, .reason = "" });
    var server_row = SitesController.dsRowItem(ctx, section_servers, 0, &buf);
    try testing.expectEqual(outline_mod.StatusDot.connected, server_row.status);
    // The dot replaced the old " — connected" title suffix.
    try testing.expectEqualStrings("box", server_row.title);

    ctrl.onSiteStatus(.{ .site_id = 7, .status = .reconnecting, .reason = "" });
    server_row = SitesController.dsRowItem(ctx, section_servers, 0, &buf);
    try testing.expectEqual(outline_mod.StatusDot.reconnecting, server_row.status);

    // History rows carry the same dot via their recorded site id.
    try ctrl.history.push(7, "box", "/srv");
    try testing.expectEqual(
        outline_mod.StatusDot.reconnecting,
        SitesController.dsRowItem(ctx, section_history, 0, &buf).status,
    );

    // Offline (and never-seen) sites draw no dot.
    ctrl.onSiteStatus(.{ .site_id = 7, .status = .offline, .reason = "test" });
    try testing.expectEqual(
        outline_mod.StatusDot.none,
        SitesController.dsRowItem(ctx, section_servers, 0, &buf).status,
    );
    try testing.expectEqual(
        outline_mod.StatusDot.none,
        SitesController.dsRowItem(ctx, section_history, 0, &buf).status,
    );
}

test "controller: servers context menu swaps to the Disconnect variant by status" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{.{
        .id = 7,
        .name = "box",
        .protocol = .sftp,
        .host = "box.example",
        .account = "root",
    }} });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = true,
        .sidebar_autosave = null,
    });
    defer ctrl.destroy();
    defer h.stop();

    const ctx: *anyopaque = @ptrCast(ctrl);
    const plain = ctrl.menus[@intFromEnum(MenuKind.servers)].?.value;
    const connected = ctrl.menus[@intFromEnum(MenuKind.servers_connected)].?.value;
    const sr: outline_mod.SectionRow = .{ .section = section_servers, .row = 0 };

    // No status yet → the plain menu (no Disconnect).
    try testing.expectEqual(plain, SitesController.dsContextMenu(ctx, sr).?);

    ctrl.onSiteStatus(.{ .site_id = 7, .status = .connected, .reason = "" });
    try testing.expectEqual(connected, SitesController.dsContextMenu(ctx, sr).?);

    ctrl.onSiteStatus(.{ .site_id = 7, .status = .reconnecting, .reason = "" });
    try testing.expectEqual(connected, SitesController.dsContextMenu(ctx, sr).?);

    ctrl.onSiteStatus(.{ .site_id = 7, .status = .offline, .reason = "test" });
    try testing.expectEqual(plain, SitesController.dsContextMenu(ctx, sr).?);

    // Background (no row) keeps its own menu.
    try testing.expectEqual(
        ctrl.menus[@intFromEnum(MenuKind.background)].?.value,
        SitesController.dsContextMenu(ctx, null).?,
    );

    // cmDisconnect drops only the pane bindings pointing at the clicked
    // site (others must survive for Cmd+Shift+K).
    try ctrl.pane_sites.put(ctrl.gpa, 0, 7);
    try ctrl.pane_sites.put(ctrl.gpa, 1, 8);
    ctrl.clicked = sr;
    SitesController.cmDisconnect(ctrl);
    try testing.expectEqual(@as(?u64, null), ctrl.pane_sites.get(0));
    try testing.expectEqual(@as(?u64, 8), ctrl.pane_sites.get(1));
}

test "controller: disconnectAll disconnects exactly the connected/reconnecting sites" {
    var hub = relay.pool.site_pool.MockHub.init(testing.allocator);
    const Make = struct {
        fn make(ctx: *anyopaque, site: *const sites_mod.Site) relay.pool.site_pool.ConnFactory {
            _ = site;
            const hub_ptr: *relay.pool.site_pool.MockHub = @ptrCast(@alignCast(ctx));
            return hub_ptr.factory();
        }
    };

    // Harness.start has no factory seam, so wire the mock factory inline
    // (same setup as bridge.zig's mock-factory test).
    var h: Harness = undefined;
    h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
    h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
    h.fake = .init(testing.allocator);
    try sites_mod.save(.{ .sites = &.{
        .{ .id = 1, .name = "one", .protocol = .ftp, .host = "one.example", .account = "alice" },
        .{ .id = 2, .name = "two", .protocol = .ftp, .host = "two.example", .account = "alice" },
    } }, std.testing.io, h.tmp_conf.dir, bridge.sites_file, testing.allocator);
    var diag: Diagnostics = .{};
    try h.fake.set(&diag, .{ .protocol = .ftp, .host = "one.example", .port = 21, .account = "alice" }, "pw");
    try h.fake.set(&diag, .{ .protocol = .ftp, .host = "two.example", .port = 21, .account = "alice" }, "pw");
    h.core = try bridge.AppCore.initOptions(testing.allocator, .{
        .pump = .manual,
        .config_dir = h.tmp_conf.dir,
        .local_root = h.tmp_root.dir,
        .cred_store = h.fake.credStore(),
        .factory_provider = .{ .ctx = &hub, .makeFn = Make.make },
    });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    try h.core.connectSite(1);
    try h.core.connectSite(2);
    const Pred = struct {
        fn bothConnected(c_: *SitesController) bool {
            const one = c_.siteStatus(1) orelse return false;
            const two = c_.siteStatus(2) orelse return false;
            return one == .connected and two == .connected;
        }
        fn oneOffline(c_: *SitesController) bool {
            return (c_.siteStatus(1) orelse return false) == .offline;
        }
    };
    try h.waitUntil(ctrl, Pred.bothConnected);
    try testing.expectEqual(@as(usize, 2), hub.openConns());

    // Stale pane bindings, plus a site the controller believes is offline
    // even though its pool is open — exactly what disconnectAll must skip —
    // and a status entry for a site that never had a runtime.
    try ctrl.pane_sites.put(ctrl.gpa, 0, 1);
    try ctrl.pane_sites.put(ctrl.gpa, 1, 2);
    ctrl.onSiteStatus(.{ .site_id = 2, .status = .offline, .reason = "test" });
    ctrl.onSiteStatus(.{ .site_id = 99, .status = .offline, .reason = "test" });

    ctrl.disconnectAll();
    try h.waitUntil(ctrl, Pred.oneOffline);
    // Site 1 (connected) was disconnected; site 2 (offline per status) was
    // skipped, so its mock connection is still open.
    try testing.expectEqual(@as(usize, 1), hub.openConns());
    // Every pane binding is dropped — Cmd+Shift+K has nothing stale left.
    try testing.expectEqual(@as(usize, 0), ctrl.pane_sites.count());
}

test "controller: site CRUD propagates to sites.zon, the core list, and the keychain" {
    var h: Harness = undefined;
    try h.start(null);

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    // Quick-Connect URL target with save-as-site: persisted + connectable.
    const target = try parseTarget("ftps://alice@ftp.example.org:2121/pub");
    ctrl.connectTarget(target, true);
    try testing.expectEqual(@as(usize, 1), ctrl.store.persistedCount());
    const site_id = ctrl.store.persistedAt(0).?.site.id;
    try testing.expectEqual(@as(?u64, site_id), ctrl.pane_sites.get(default_pane_token));

    // The core sees the new site immediately (connect needs findSite).
    try testing.expect(h.core.findSite(site_id) != null);
    try testing.expectEqualStrings("ftp.example.org", h.core.findSite(site_id).?.host);

    // sites.zon was written; ephemeral quick connects would not be.
    var loaded = try sites_mod.load(h.core.io, h.core.config_dir, bridge.sites_file, testing.allocator);
    defer loaded.deinit();
    try testing.expectEqual(@as(usize, 1), loaded.value.sites.len);
    try testing.expectEqual(@as(u16, 2121), loaded.value.sites[0].port);
    try testing.expectEqualStrings("/pub", loaded.value.sites[0].initial_remote_path);

    // An unsaved quick connect to the same target reuses nothing persisted —
    // it matches the existing site instead of duplicating.
    const again = try parseTarget("ftps://alice@ftp.example.org:2121/pub");
    ctrl.connectTarget(again, false);
    try testing.expectEqual(@as(usize, 1), ctrl.store.entries.items.len);

    // A different unsaved target becomes an ephemeral site: core-visible,
    // not in sites.zon.
    const eph = try parseTarget("sftp://bob@other.example/home/bob");
    ctrl.connectTarget(eph, false);
    try testing.expectEqual(@as(usize, 2), ctrl.store.entries.items.len);
    try testing.expectEqual(@as(usize, 1), ctrl.store.persistedCount());
    const eph_id = ctrl.store.findMatching(.{ .protocol = .sftp, .host = "other.example", .account = "bob" }).?;
    try testing.expect(h.core.findSite(eph_id) != null);
    var reloaded = try sites_mod.load(h.core.io, h.core.config_dir, bridge.sites_file, testing.allocator);
    defer reloaded.deinit();
    try testing.expectEqual(@as(usize, 1), reloaded.value.sites.len);

    // storeSecret writes through the cred store (fake keychain here) and
    // the transient path deletes once the connect resolves.
    ctrl.storeSecret(site_id, "hunter2", false);
    var diag: Diagnostics = .{};
    const got = try h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .ftps,
        .host = "ftp.example.org",
        .port = 2121,
        .account = "alice",
    });
    defer cred_store_mod.freeSecret(testing.allocator, got);
    try testing.expectEqualStrings("hunter2", got);
    try testing.expectEqual(@as(usize, 1), ctrl.transients.items.len);
    ctrl.onSiteStatus(.{ .site_id = site_id, .status = .offline, .reason = "test" });
    try testing.expectEqual(@as(usize, 0), ctrl.transients.items.len);
    try testing.expectError(error.NotFound, h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .ftps,
        .host = "ftp.example.org",
        .port = 2121,
        .account = "alice",
    }));

    // deleteSite removes the site + meta and rewrites sites.zon.
    try ctrl.meta.set(site_id, .password, "");
    ctrl.deleteSite(site_id);
    try testing.expectEqual(@as(usize, 0), ctrl.store.persistedCount());
    try testing.expect(ctrl.meta.get(site_id) == null);
    try testing.expect(h.core.findSite(site_id) == null);
    var after = try sites_mod.load(h.core.io, h.core.config_dir, bridge.sites_file, testing.allocator);
    defer after.deinit();
    try testing.expectEqual(@as(usize, 0), after.value.sites.len);
}

test "controller: ssh-config rows materialize ephemeral sftp sites" {
    var h: Harness = undefined;
    try h.start(null);

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    // Feed the group directly (the file path variant is covered by refresh
    // falling back to empty above).
    try ctrl.ssh.setFromText(
        \\Host work
        \\  HostName files.example.com
        \\  User fredrik
        \\  Port 2200
    );
    try testing.expectEqual(@as(usize, 1), ctrl.ssh.aliases.items.len);

    ctrl.connectSshAlias(0);
    const site_id = ctrl.store.findMatching(.{
        .protocol = .sftp,
        .host = "files.example.com",
        .port = 2200,
        .account = "fredrik",
    }) orelse return error.TestUnexpectedResult;
    // Ephemeral: connectable through the core, absent from sites.zon.
    try testing.expect(h.core.findSite(site_id) != null);
    try testing.expectEqual(@as(usize, 0), ctrl.store.persistedCount());
    try testing.expectEqual(@as(?u64, site_id), ctrl.pane_sites.get(default_pane_token));
    // History recorded the alias label.
    try testing.expectEqualStrings("work", ctrl.history.entries.items[0].label);

    // Reconnecting the same alias reuses the ephemeral site.
    ctrl.connectSshAlias(0);
    try testing.expectEqual(@as(usize, 1), ctrl.store.entries.items.len);
}

test "controller: ssh-config re-parse on activation is mtime-gated" {
    var h: Harness = undefined;
    try h.start(null);

    // A real on-disk home (absolute path) so the mtime stat exercises the
    // same code path the app-activation hook uses.
    const io = std.testing.io;
    var home_buf: [64]u8 = undefined;
    const home = try std.fmt.bufPrint(&home_buf, "/tmp/relay-ssh-test-{d}", .{std.c.getpid()});
    var path_buf: [96]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, try std.fmt.bufPrint(&path_buf, "{s}/.ssh", .{home}));
    defer cwd.deleteTree(io, home) catch {};
    const config_path = try std.fmt.bufPrint(&path_buf, "{s}/.ssh/config", .{home});
    try cwd.writeFile(io, .{ .sub_path = config_path, .data = "Host one\n  HostName one.example\n" });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = home,
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    try testing.expectEqual(@as(usize, 1), ctrl.ssh.aliases.items.len);
    try testing.expect(ctrl.ssh_config_mtime_ns != 0);

    // Unchanged mtime: the activation hook short-circuits after the stat.
    ctrl.refreshSshConfigIfChanged();
    try testing.expectEqual(@as(usize, 1), ctrl.ssh.aliases.items.len);

    // Changed file: force a recorded-mtime mismatch (filesystem mtime
    // granularity makes "wait for a newer stamp" flaky) and re-parse.
    try cwd.writeFile(io, .{
        .sub_path = config_path,
        .data = "Host one\n  HostName one.example\nHost two\n  HostName two.example\n",
    });
    ctrl.ssh_config_mtime_ns = -1; // simulate "stat differs"
    ctrl.refreshSshConfigIfChanged();
    try testing.expectEqual(@as(usize, 2), ctrl.ssh.aliases.items.len);
    try testing.expect(ctrl.ssh_config_mtime_ns != -1); // stamp re-recorded

    // Deleting the file reads as a change too (stat = 0) and empties the
    // group instead of erroring.
    try cwd.deleteFile(io, config_path);
    ctrl.refreshSshConfigIfChanged();
    try testing.expectEqual(@as(usize, 0), ctrl.ssh.aliases.items.len);
    try testing.expectEqual(@as(i96, 0), ctrl.ssh_config_mtime_ns);
}

test "controller: applyImport dedupes by connection identity and stores passwords only with consent" {
    var h: Harness = undefined;
    // Stage one persisted site that collides with the fixture's first
    // FileZilla server AND with prod_web.duck (cross-importer dupes).
    try h.start(.{ .sites = &.{.{
        .id = 1,
        .name = "existing",
        .protocol = .sftp,
        .host = "web1.example.com",
        .port = 2222,
        .account = "deploy",
    }} });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    const xml = try readImporterFixture(testing.allocator, "filezilla_sitemanager.xml");
    defer testing.allocator.free(xml);

    // Consent given: passwords of NON-duplicate sites land in the store
    // (web1's secret is skipped with its duplicate site).
    var fz = try parseFileZilla(testing.allocator, xml);
    var stats = ctrl.applyImport(&fz, true);
    fz.deinit();
    try testing.expectEqual(@as(usize, 6), stats.imported);
    try testing.expectEqual(@as(usize, 1), stats.duplicates);
    try testing.expectEqual(@as(usize, 2), stats.skipped);
    try testing.expectEqual(@as(usize, 2), stats.passwords_stored);
    try testing.expectEqual(@as(usize, 7), ctrl.store.persistedCount());

    var diag: Diagnostics = .{};
    const alice = try h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .ftp,
        .host = "ftp.example.org",
        .port = 21, // effectivePort: the canonical 0 keys as the default
        .account = "alice",
    });
    defer cred_store_mod.freeSecret(testing.allocator, alice);
    try testing.expectEqualStrings("plain&old", alice);
    const cafe = try h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .ftps,
        .host = "secure.example.net",
        .port = 990,
        .account = "café-user",
    });
    defer cred_store_mod.freeSecret(testing.allocator, cafe);
    try testing.expectEqualStrings("Key&Café pass'word", cafe);
    // The duplicate's password was NOT written.
    try testing.expectError(error.NotFound, h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .sftp,
        .host = "web1.example.com",
        .port = 2222,
        .account = "deploy",
    }));

    // Imports propagate like CRUD: core list + persisted sites.zon.
    const mirror_id = ctrl.store.findMatching(.{
        .protocol = .ftp,
        .host = "mirror.example.com",
        .account = "anonymous",
    }).?;
    try testing.expect(h.core.findSite(mirror_id) != null);
    var loaded = try sites_mod.load(h.core.io, h.core.config_dir, bridge.sites_file, testing.allocator);
    defer loaded.deinit();
    try testing.expectEqual(@as(usize, 7), loaded.value.sites.len);

    // Cyberduck round on top: prod_web.duck and secure_drop.duck now hit
    // duplicates (one staged, one just imported); s3 skipped; mirror.org new.
    const duck_names = [_][]const u8{ "prod_web.duck", "mirror_ftp.duck", "secure_drop.duck", "s3_bucket.duck" };
    var ducks: [duck_names.len][]u8 = undefined;
    var loaded_ducks: usize = 0;
    defer for (ducks[0..loaded_ducks]) |file| testing.allocator.free(file);
    for (duck_names, 0..) |name, i| {
        ducks[i] = try readImporterFixture(testing.allocator, name);
        loaded_ducks = i + 1;
    }
    var duck = try parseCyberduck(testing.allocator, &.{ ducks[0], ducks[1], ducks[2], ducks[3] });
    stats = ctrl.applyImport(&duck, false);
    duck.deinit();
    try testing.expectEqual(@as(usize, 1), stats.imported);
    try testing.expectEqual(@as(usize, 2), stats.duplicates);
    try testing.expectEqual(@as(usize, 1), stats.skipped);
    try testing.expectEqual(@as(usize, 0), stats.passwords_stored);
    try testing.expectEqual(@as(usize, 8), ctrl.store.persistedCount());

    // Re-importing the same FileZilla export is now a pure-duplicate no-op.
    var again = try parseFileZilla(testing.allocator, xml);
    stats = ctrl.applyImport(&again, true);
    again.deinit();
    try testing.expectEqual(@as(usize, 0), stats.imported);
    try testing.expectEqual(@as(usize, 7), stats.duplicates);
    try testing.expectEqual(@as(usize, 0), stats.passwords_stored);
    try testing.expectEqual(@as(usize, 8), ctrl.store.persistedCount());
}

test "controller: applyImport without consent never touches the cred store" {
    var h: Harness = undefined;
    try h.start(null);

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    const xml = try readImporterFixture(testing.allocator, "filezilla_sitemanager.xml");
    defer testing.allocator.free(xml);
    var fz = try parseFileZilla(testing.allocator, xml);
    const stats = ctrl.applyImport(&fz, false);
    fz.deinit();

    try testing.expectEqual(@as(usize, 7), stats.imported);
    try testing.expectEqual(@as(usize, 0), stats.passwords_stored);
    var diag: Diagnostics = .{};
    try testing.expectError(error.NotFound, h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .sftp,
        .host = "web1.example.com",
        .port = 2222,
        .account = "deploy",
    }));
    try testing.expectError(error.NotFound, h.fake.credStore().get(testing.allocator, &diag, .{
        .protocol = .ftp,
        .host = "ftp.example.org",
        .port = 21,
        .account = "alice",
    }));
}

test "controller: connect-failure sheet fires once per user-initiated attempt" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{.{
        .id = 1,
        .name = "Prod Web",
        .protocol = .sftp,
        .host = "web.example.com",
        .port = 2222,
        .account = "deploy",
    }} });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null, // headless: showError logs, never blocks on a sheet
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    const site_id: u64 = 1;

    // Arming: connectAndList records the in-flight user attempt.
    ctrl.connectAndList(site_id, null);
    try testing.expect(ctrl.pending_connects.contains(site_id));

    // A .reconnecting tick mid-attempt is NOT terminal: still pending, no sheet.
    try testing.expect(!ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .reconnecting,
        .reason = "handshake retry",
        .error_class = .transient,
    }));
    try testing.expect(ctrl.pending_connects.contains(site_id));

    // First terminal status is a classified failure: sheet-eligible ONCE,
    // and the pending flag clears.
    try testing.expect(ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .offline,
        .reason = "Connection refused",
        .error_class = .transient,
    }));
    try testing.expect(!ctrl.pending_connects.contains(site_id));

    // A SECOND background offline (breaker churn) must NOT re-trigger.
    try testing.expect(!ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .offline,
        .reason = "breaker open",
        .error_class = .permanent,
    }));

    // The friendly title prefers the site nickname.
    var label_buf: [256]u8 = undefined;
    try testing.expectEqualStrings("Prod Web", h.core.siteLabel(site_id, &label_buf));
}

test "controller: pending-connect terminal-status variants (connected, clean offline, non-pending)" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{.{
        .id = 1,
        .name = "Box",
        .protocol = .sftp,
        .host = "box.example.com",
    }} });

    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = null,
        .home = "/nonexistent-relay-home",
        .build_sidebar = false,
    });
    defer ctrl.destroy();
    defer h.stop();

    const site_id: u64 = 1;

    // .connected clears the flag silently (no sheet).
    try ctrl.pending_connects.put(testing.allocator, site_id, {});
    try testing.expect(!ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .connected,
    }));
    try testing.expect(!ctrl.pending_connects.contains(site_id));

    // A clean user disconnect (.offline, error_class == null) clears silently.
    try ctrl.pending_connects.put(testing.allocator, site_id, {});
    try testing.expect(!ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .offline,
        .reason = "disconnected",
        .error_class = null,
    }));
    try testing.expect(!ctrl.pending_connects.contains(site_id));

    // A classified offline with NO pending flag (background reconnect that
    // tripped while the site was idle) is never sheet-eligible.
    try testing.expect(!ctrl.connectFailureSheetEligible(.{
        .site_id = site_id,
        .status = .offline,
        .reason = "421 dropped",
        .error_class = .transient,
    }));

    // onSiteStatus end-to-end: a pending failure runs the (headless) sheet
    // path without panicking and clears the flag.
    try ctrl.pending_connects.put(testing.allocator, site_id, {});
    ctrl.onSiteStatus(.{
        .site_id = site_id,
        .status = .offline,
        .reason = "auth failed",
        .error_class = .permanent,
    });
    try testing.expect(!ctrl.pending_connects.contains(site_id));
    try testing.expectEqual(@as(?events_mod.SiteStatus, .offline), ctrl.siteStatus(site_id));
}

test "visual: sidebar in a real window (set RELAY_SITES_VISUAL=1)" {
    if (std.c.getenv("RELAY_SITES_VISUAL") == null) return error.SkipZigTest;

    var h: Harness = undefined;
    try h.start(.{ .sites = &.{
        .{ .id = 1, .name = "prod web", .protocol = .sftp, .host = "web1.example.com", .account = "deploy" },
        .{ .id = 2, .protocol = .ftps, .host = "ftp.example.org" },
    } });

    const win = Window.create(mac.foundation.rect(200, 200, 260, 480), "Relay — sites", mac.appkit.window.StyleMask.standard);
    const ctrl = try SitesController.create(testing.allocator, h.core, .{
        .window = win,
        .build_sidebar = true,
        .sidebar_autosave = null,
    });
    defer ctrl.destroy();
    defer h.stop();
    defer win.release();

    try ctrl.history.push(1, "prod web", "/var/www");
    if (ctrl.sidebar) |sb| sb.reload();
    win.setContentView(objc.Object.fromId(ctrl.sidebarView().?));
    win.makeKeyAndOrderFront();
    h.core.io.sleep(.fromMilliseconds(1500), .awake) catch {};
    win.close();
}

test {
    std.testing.refAllDecls(@This());
}

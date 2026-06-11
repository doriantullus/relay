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
//! are tracked per site (sidebar row suffix now; the path-bar chip reads
//! `siteStatus()`); `prompt_needed` events present host-key / password /
//! keyboard-interactive sheets and reply through bridge.respondPrompt —
//! host-key acceptance persists via the core callback reply (known_hosts
//! append happens core-side once the M2 factories land). Quick Connect
//! (Cmd+K via `serverMenuItems`) accepts sftp:// | ftps:// | ftp:// URLs
//! and bare ssh-config aliases, with a save-as-site choice. Disconnect is
//! Cmd+Shift+K (`disconnectActivePane`).
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
// SitesController
// ---------------------------------------------------------------------------

const MenuKind = enum(usize) { servers, ssh, history, background };
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

    /// Last site_status per site id (sidebar suffix + `siteStatus()`).
    statuses: std.AutoHashMapUnmanaged(u64, events_mod.SiteStatus) = .empty,
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

    fn statusSuffix(self: *const SitesController, site_id: u64) []const u8 {
        const status = self.statuses.get(site_id) orelse return "";
        return switch (status) {
            .connected => " — connected",
            .reconnecting => " — reconnecting…",
            .offline => "",
        };
    }

    fn dsRowItem(ctx: *anyopaque, section: usize, row: usize, buf: []u8) outline_mod.Item {
        const self = fromCtx(ctx);
        switch (section) {
            section_servers => {
                const entry = self.store.persistedAt(row) orelse return .{ .title = "" };
                const label = siteLabel(entry.site);
                const title = std.fmt.bufPrint(buf, "{s}{s}", .{
                    label, self.statusSuffix(entry.site.id),
                }) catch label;
                return .{ .title = title, .symbol = "server.rack" };
            },
            section_ssh => {
                if (row >= self.ssh.aliases.items.len) return .{ .title = "" };
                return .{ .title = self.ssh.aliases.items[row], .symbol = "terminal" };
            },
            section_history => {
                if (row >= self.history.entries.items.len) return .{ .title = "" };
                const entry = self.history.entries.items[row];
                const title = std.fmt.bufPrint(buf, "{s} · {s}", .{
                    entry.label, entry.path,
                }) catch entry.label;
                return .{ .title = title, .symbol = "clock" };
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
            section_servers => .servers,
            section_ssh => .ssh,
            section_history => .history,
            else => MenuKind.background,
        } else .background;
        const m = self.menus[@intFromEnum(kind)] orelse return null;
        return m.value;
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
        const initial: []const u8 = blk: {
            if (path_override) |p| {
                if (p.len > 0) break :blk p;
            }
            if (site.initial_remote_path.len > 0) break :blk site.initial_remote_path;
            break :blk "/";
        };
        if (self.pane_host.navigate) |nav| {
            nav(self.pane_host.ctx, pane, site_id, initial);
        } else {
            _ = self.core.listPath(pane, site_id, initial) catch |err| {
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
        self.ssh.refresh(self.core.io, self.home);
        if (self.sidebar) |sb| sb.reloadSection(section_ssh);
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
        self.resolveTransients(e.site_id, e.status);
        if (self.sidebar) |sb| sb.reloadSection(section_servers);
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
        const site = self.store.get(site_id) orelse return;
        if (site.account.len == 0) return; // no account name = no cred key
        const key: cred_store_mod.Key = .{
            .protocol = credProtocol(site.protocol),
            .host = site.host,
            .port = site.effectivePort(),
            .account = site.account,
        };
        var diag: Diagnostics = .{};
        self.core.cred_store.set(&diag, key, secret) catch {
            self.showError("Could not store the credential", diag.message);
            return;
        };
        if (!keep) self.rememberTransient(site_id, key);
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
            .{ .label = "Remote Path", .initial = remote, .placeholder = "/" },
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

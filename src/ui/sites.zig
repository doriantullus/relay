//! sites — toolkit-free saved-site, history, SSH-config, quick-connect,
//! and importer models shared by both frontends.
//!
//! Defines the data behind a source-list sidebar with three sections:
//!
//!  - **Servers** — saved sites (sites.zon CRUD through settings/sites.zig;
//!    add/edit/delete are frontend responsibilities).
//!  - **SSH Config** — read-only smart group parsed from ~/.ssh/config via
//!    proto/ssh/ssh_config.zig (concrete Host aliases only; wildcard and
//!    negated patterns are skipped). Section headers are group rows and not
//!    selectable. Connecting a row materializes an ephemeral site (protocol
//!    sftp, fields from the resolved config); frontends may also offer a
//!    save-as-site action.
//!  - **History** — recent (site, path) pairs, newest first, persisted next
//!    to the settings as history.zon in the Application Support dir.
//!
//! Connect flow and presentation stay in each native frontend. Shared target
//! parsing accepts sftp:// | ftps:// | ftp:// URLs and bare SSH-config
//! aliases, while PaneHost supplies a toolkit-free active-pane seam.
//!
//! Secrets: passwords go ONLY to the injected credential store — never to
//! sites.zon. "Save in Keychain: No" stores the secret transiently (the
//! bridge's CredProvider can only fetch from the store) and deletes it as
//! soon as the connect attempt resolves (connected/offline). The site
//! editor's auth metadata (method + key file path) has no slot in the M1
//! Site schema, so it persists in the shared sites_meta.zon metadata store.
//!
//! Architectural law: this file imports relay_core and relay_ui only. It has
//! no AppKit, GTK, raw selector, or GObject dependency.

const std = @import("std");
const relay = @import("relay_core");
const bridge = @import("bridge.zig");

const Allocator = std.mem.Allocator;
const sites_mod = relay.sites;
const settings_mod = relay.settings;
const cred_store_mod = relay.cred.store;
const ssh_config_mod = relay.ssh.ssh_config;

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

    pub fn notifyConnecting(self: PaneHost, pane: bridge.PaneToken, site_id: u64) void {
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

pub fn credProtocol(p: sites_mod.Protocol) cred_store_mod.Protocol {
    return switch (p) {
        .ftp => .ftp,
        .ftps => .ftps,
        .sftp => .sftp,
    };
}

pub const protocol_titles = [_][]const u8{ "SFTP", "FTPS", "FTP" };
pub const auth_titles = [_][]const u8{ "SSH Agent", "Key File…", "Password" };

pub fn protocolTitle(p: sites_mod.Protocol) []const u8 {
    return switch (p) {
        .sftp => protocol_titles[0],
        .ftps => protocol_titles[1],
        .ftp => protocol_titles[2],
    };
}

pub fn protocolFromTitle(title: []const u8) sites_mod.Protocol {
    if (std.mem.eql(u8, title, protocol_titles[1])) return .ftps;
    if (std.mem.eql(u8, title, protocol_titles[2])) return .ftp;
    return .sftp;
}

pub fn authTitle(m: AuthMethod) []const u8 {
    return switch (m) {
        .agent => auth_titles[0],
        .key_file => auth_titles[1],
        .password => auth_titles[2],
    };
}

pub fn authFromTitle(title: []const u8) AuthMethod {
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

    /// Promote or demote an existing entry without changing its stable id.
    /// Quick Connect uses this when an ephemeral target is later saved.
    /// Returns true only when the persisted flag actually changed.
    pub fn setPersisted(self: *SiteStore, id: u64, persisted: bool) bool {
        const idx = self.indexOf(id) orelse return false;
        if (self.entries.items[idx].persisted == persisted) return false;
        self.entries.items[idx].persisted = persisted;
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

pub fn readWholeFile(gpa: Allocator, io: std.Io, abs_path: []const u8) ![]u8 {
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

pub const XmlTag = struct {
    /// Raw attribute text of the open tag (between the name and '>').
    attrs: []const u8,
    /// Raw inner text (undecoded); empty for self-closing tags.
    text: []const u8,
};

/// First `<tag …>text</tag>` inside `block`. Minimal by design: no nesting
/// of the SAME tag inside itself (true for every field FileZilla/Cyberduck
/// write), attributes are returned raw for the caller to scan.
pub fn xmlTag(block: []const u8, comptime tag: []const u8) ?XmlTag {
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

pub fn xmlTagText(block: []const u8, comptime tag: []const u8) ?[]const u8 {
    const found = xmlTag(block, tag) orelse return null;
    return found.text;
}

/// Decode the five named XML entities plus decimal/hex character
/// references (ASCII range only — enough for FileZilla/Cyberduck output);
/// malformed references are copied verbatim.
pub fn xmlDecode(a: Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
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
pub fn fzProtocol(value: i32) ?sites_mod.Protocol {
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
pub fn importedFieldSafe(field: []const u8) bool {
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

pub fn parseFzServer(a: Allocator, block: []const u8) error{OutOfMemory}!?ImportedSite {
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
pub fn decodeFzPass(a: Allocator, pass: XmlTag) error{OutOfMemory}!?[]const u8 {
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
pub fn duckProtocol(value: []const u8) ?sites_mod.Protocol {
    if (std.mem.eql(u8, value, "sftp")) return .sftp;
    if (std.mem.eql(u8, value, "ftps")) return .ftps;
    if (std.mem.eql(u8, value, "ftp")) return .ftp;
    return null;
}

/// `<key>K</key>` followed by `<string>…</string>` (or `<integer>`), the
/// XML-plist subset .duck files use. Returns the raw (undecoded) value.
pub fn plistValue(text: []const u8, comptime key: []const u8) ?[]const u8 {
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

pub fn parseDuck(a: Allocator, text: []const u8) error{OutOfMemory}!?ImportedSite {
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

test "quick-connect parsing and validation" {
    const target = try parseTarget("sftp://alice@example.com:2222/srv/www");
    try std.testing.expectEqualStrings("example.com", target.url.host);
    try std.testing.expectEqualStrings("alice", target.url.user);
    try std.testing.expectEqual(@as(u16, 2222), target.url.port);
    try std.testing.expectEqualStrings("/srv/www", target.url.path);
    try std.testing.expect(hostValid("example.com"));
    try std.testing.expect(!hostValid("bad host"));
    try std.testing.expectEqual(@as(?u16, 22), portFromText("22"));
    try std.testing.expectEqual(@as(?u16, null), portFromText("70000"));
}

test "import field guard rejects option and control injection" {
    try std.testing.expect(importedFieldSafe("example.com"));
    try std.testing.expect(!importedFieldSafe("-bad"));
    try std.testing.expect(!importedFieldSafe("bad\nvalue"));
}

test "SiteStore promotes an ephemeral Quick Connect target" {
    var store: SiteStore = .init(std.testing.allocator);
    defer store.deinit();

    const id = try store.add(.{ .host = "example.com", .account = "alice" }, false);
    try std.testing.expectEqual(@as(usize, 0), store.persistedCount());
    try std.testing.expect(store.setPersisted(id, true));
    try std.testing.expectEqual(@as(usize, 1), store.persistedCount());
    try std.testing.expect(!store.setPersisted(id, true));
    try std.testing.expect(!store.setPersisted(999, true));
}

test {
    std.testing.refAllDecls(@This());
}

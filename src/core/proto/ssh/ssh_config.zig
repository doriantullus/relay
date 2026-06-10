//! ~/.ssh/config subset parser + resolver. Supported: Host patterns
//! (wildcards + `!` negation), HostName, User, Port, IdentityFile,
//! IdentityAgent, ProxyJump and ProxyCommand (both parse-only in M1 —
//! execution lands in M3), and Include (one level deep).
//!
//! Semantics follow ssh_config(5): for each option the FIRST obtained value
//! wins, except IdentityFile which accumulates. Unknown keywords are
//! skipped, not errors — real-world configs are full of options we will
//! never support. Tokens: `%h` (final host name), `%p` (final port),
//! `%r` (remote user), `%%`; `~` expands at the start of paths.

const std = @import("std");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const known_hosts = @import("known_hosts.zig");

pub const Error = error{OutOfMemory};

/// Loads the contents of an `Include` target. The parser hands over the
/// argument verbatim (after `~` expansion it may still be relative; OpenSSH
/// resolves relative includes against ~/.ssh). Return null for "missing
/// file" — OpenSSH silently ignores those. Allocate with the provided
/// allocator (an arena owned by the Config).
pub const Loader = struct {
    ctx: ?*anyopaque = null,
    load: *const fn (ctx: ?*anyopaque, arena: Allocator, path: []const u8) Error!?[]const u8,

    /// Ignores all Include directives (resolve() on a single file).
    pub const none: Loader = .{ .load = loadNone };

    fn loadNone(_: ?*anyopaque, _: Allocator, _: []const u8) Error!?[]const u8 {
        return null;
    }
};

const Keyword = enum {
    host,
    hostname,
    user,
    port,
    identityfile,
    identityagent,
    proxyjump,
    proxycommand,
    include,
};

const Directive = union(enum) {
    /// Starts a Host block; patterns apply until the next `host`.
    host: []const []const u8,
    set: struct {
        key: Keyword,
        /// Verbatim argument (rest of line, outer quotes stripped).
        value: []const u8,
    },
};

pub const Config = struct {
    arena: ArenaAllocator,
    directives: []const Directive,

    pub fn deinit(c: *Config) void {
        c.arena.deinit();
        c.* = undefined;
    }

    /// Computes the effective options for `alias` (first-obtained wins).
    pub fn resolve(c: *const Config, gpa: Allocator, alias: []const u8, options: ResolveOptions) Error!Effective {
        var arena: ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        var host_name: ?[]const u8 = null;
        var user: ?[]const u8 = null;
        var port: ?u16 = null;
        var identity_agent: ?[]const u8 = null;
        var proxy_jump: ?[]const u8 = null;
        var proxy_command: ?[]const u8 = null;
        var identity_files: std.ArrayList([]const u8) = .empty;
        defer identity_files.deinit(gpa);

        var active = true; // options before any Host block apply to all
        for (c.directives) |d| switch (d) {
            .host => |patterns| active = hostMatches(patterns, alias),
            .set => |s| {
                if (!active) continue;
                switch (s.key) {
                    .host, .include => unreachable, // never stored as .set
                    .hostname => host_name = host_name orelse s.value,
                    .user => user = user orelse s.value,
                    .port => port = port orelse (std.fmt.parseInt(u16, s.value, 10) catch null),
                    .identityagent => identity_agent = identity_agent orelse s.value,
                    .proxyjump => proxy_jump = proxy_jump orelse s.value,
                    .proxycommand => proxy_command = proxy_command orelse s.value,
                    .identityfile => try identity_files.append(gpa, s.value),
                }
            },
        };

        const final_port = options.port orelse port orelse 22;
        // In HostName, %h refers to the alias as typed; elsewhere %h is the
        // final host name.
        const final_host = if (host_name) |hn|
            try expandTokens(a, hn, .{ .home = options.home, .host = alias, .port = final_port, .user = null })
        else
            try a.dupe(u8, alias);
        const final_user = options.user orelse user;

        const path_tokens: Tokens = .{
            .home = options.home,
            .host = final_host,
            .port = final_port,
            .user = final_user,
        };
        const files = try a.alloc([]const u8, identity_files.items.len);
        for (identity_files.items, files) |raw, *out| {
            out.* = try expandTokens(a, raw, path_tokens);
        }

        // All arena allocation must precede the struct literal: `.arena = arena`
        // copies the arena state, and later allocations would not survive deinit.
        const hops = if (proxy_jump) |pj| try parseProxyJump(a, pj) else &[_]Hop{};
        const user_copy = if (final_user) |u| try a.dupe(u8, u) else null;
        const agent_copy = if (identity_agent) |v| try expandTokens(a, v, path_tokens) else null;
        const proxy_cmd_copy = if (proxy_command) |v| try a.dupe(u8, v) else null;

        return .{
            .arena = arena,
            .host_name = final_host,
            .user = user_copy,
            .port = final_port,
            .identity_files = files,
            .identity_agent = agent_copy,
            .proxy_jump = hops,
            .proxy_command = proxy_cmd_copy,
        };
    }
};

pub const ResolveOptions = struct {
    /// Home directory for `~` expansion (callers pass $HOME; tests fake it).
    home: []const u8,
    /// Command-line/UI overrides beat the config file.
    port: ?u16 = null,
    user: ?[]const u8 = null,
};

/// One ProxyJump hop: [user@]host[:port], parse-only until M3.
pub const Hop = struct {
    user: ?[]const u8,
    host: []const u8,
    port: ?u16,
};

pub const Effective = struct {
    arena: ArenaAllocator,
    host_name: []const u8,
    user: ?[]const u8,
    port: u16,
    /// In config order; empty means "use default identities/agent".
    identity_files: []const []const u8,
    identity_agent: ?[]const u8,
    /// Empty slice = no jump proxy.
    proxy_jump: []const Hop,
    proxy_command: ?[]const u8,

    pub fn deinit(e: *Effective) void {
        e.arena.deinit();
        e.* = undefined;
    }
};

/// Parses config text into a directive list. `loader` feeds Include files
/// (use `.none` to skip); includes nest only one level — deeper Include
/// directives are ignored.
pub fn parse(gpa: Allocator, text: []const u8, loader: Loader) Error!Config {
    var arena: ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var directives: std.ArrayList(Directive) = .empty;
    defer directives.deinit(gpa);

    try parseInto(a, gpa, &directives, text, loader, 0);

    const owned = try a.dupe(Directive, directives.items);
    return .{ .arena = arena, .directives = owned };
}

fn parseInto(
    a: Allocator, // Config arena: all directive payloads live here
    gpa: Allocator, // scratch for the growing list only
    directives: *std.ArrayList(Directive),
    text: []const u8,
    loader: Loader,
    depth: u8,
) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var rest: []const u8 = line;
        const kw_tok = takeKeyword(&rest) orelse continue;
        var kw_lower_buf: [16]u8 = undefined;
        if (kw_tok.len > kw_lower_buf.len) continue;
        const kw_lower = std.ascii.lowerString(&kw_lower_buf, kw_tok);
        const kw = std.meta.stringToEnum(Keyword, kw_lower) orelse continue;

        switch (kw) {
            .host => {
                var patterns: std.ArrayList([]const u8) = .empty;
                defer patterns.deinit(gpa);
                while (takeArg(&rest)) |pat| {
                    try patterns.append(gpa, try a.dupe(u8, pat));
                }
                if (patterns.items.len == 0) continue; // pattern-less Host: skip
                try directives.append(gpa, .{ .host = try a.dupe([]const u8, patterns.items) });
            },
            .include => {
                if (depth >= 1) continue; // one level only
                const path = takeArg(&rest) orelse continue;
                if (try loader.load(loader.ctx, a, path)) |included| {
                    try parseInto(a, gpa, directives, included, loader, depth + 1);
                }
            },
            .proxycommand => {
                // Takes the rest of the line verbatim (commands contain spaces).
                const value = std.mem.trim(u8, rest, " \t");
                if (value.len == 0) continue;
                try directives.append(gpa, .{ .set = .{ .key = kw, .value = try a.dupe(u8, value) } });
            },
            else => {
                const value = takeArg(&rest) orelse continue;
                try directives.append(gpa, .{ .set = .{ .key = kw, .value = try a.dupe(u8, value) } });
            },
        }
    }
}

/// Keyword ends at whitespace or '='; ssh allows `Key=Value` and `Key Value`.
fn takeKeyword(rest: *[]const u8) ?[]const u8 {
    const s = std.mem.trimStart(u8, rest.*, " \t");
    if (s.len == 0) return null;
    const end = std.mem.indexOfAny(u8, s, " \t=") orelse s.len;
    rest.* = if (end < s.len and s[end] == '=') s[end + 1 ..] else s[end..];
    return s[0..end];
}

/// One whitespace-separated argument, honoring double quotes and an
/// optional leading '=' (the `Key = Value` form).
fn takeArg(rest: *[]const u8) ?[]const u8 {
    var s = std.mem.trimStart(u8, rest.*, " \t");
    if (s.len > 0 and s[0] == '=') s = std.mem.trimStart(u8, s[1..], " \t");
    if (s.len == 0) {
        rest.* = s;
        return null;
    }
    if (s[0] == '"') {
        const close = std.mem.indexOfScalarPos(u8, s, 1, '"') orelse {
            rest.* = s[s.len..];
            return s[1..]; // unterminated quote: take the rest, like ssh
        };
        rest.* = s[close + 1 ..];
        return s[1..close];
    }
    const end = std.mem.indexOfAny(u8, s, " \t") orelse s.len;
    rest.* = s[end..];
    return s[0..end];
}

fn hostMatches(patterns: []const []const u8, alias: []const u8) bool {
    var got = false;
    for (patterns) |raw| {
        var pat = raw;
        const negated = pat.len > 0 and pat[0] == '!';
        if (negated) pat = pat[1..];
        if (known_hosts.matchPattern(pat, alias)) {
            if (negated) return false;
            got = true;
        }
    }
    return got;
}

const Tokens = struct {
    home: []const u8,
    host: []const u8,
    port: u16,
    user: ?[]const u8,
};

/// `~` (leading) and %-token expansion. Unknown %-tokens are kept verbatim
/// rather than rejected — we parse other people's configs.
fn expandTokens(a: Allocator, value: []const u8, tokens: Tokens) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);

    var rest = value;
    if (std.mem.eql(u8, rest, "~") or std.mem.startsWith(u8, rest, "~/")) {
        try out.appendSlice(a, tokens.home);
        rest = rest[1..];
    }
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (rest[i] != '%' or i + 1 == rest.len) {
            try out.append(a, rest[i]);
            continue;
        }
        i += 1;
        switch (rest[i]) {
            '%' => try out.append(a, '%'),
            'h' => try out.appendSlice(a, tokens.host),
            'p' => {
                var buf: [5]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{tokens.port}) catch unreachable;
                try out.appendSlice(a, s);
            },
            'r' => try out.appendSlice(a, tokens.user orelse "%r"),
            else => {
                try out.append(a, '%');
                try out.append(a, rest[i]);
            },
        }
    }
    return out.toOwnedSlice(a);
}

/// "j1,j2,..." where each hop is [user@]host[:port]; IPv6 hosts in brackets.
/// "none" disables jumping. Malformed hops resolve to host-only (lenient).
fn parseProxyJump(a: Allocator, value: []const u8) Error![]const Hop {
    if (std.ascii.eqlIgnoreCase(value, "none")) return &.{};
    var hops: std.ArrayList(Hop) = .empty;
    defer hops.deinit(a);

    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const spec = std.mem.trim(u8, raw, " \t");
        if (spec.len == 0) continue;
        var user: ?[]const u8 = null;
        var host_part = spec;
        if (std.mem.lastIndexOfScalar(u8, spec, '@')) |at| {
            if (at > 0) user = spec[0..at];
            host_part = spec[at + 1 ..];
        }
        var host = host_part;
        var port: ?u16 = null;
        if (std.mem.startsWith(u8, host_part, "[")) {
            if (std.mem.indexOfScalar(u8, host_part, ']')) |close| {
                host = host_part[1..close];
                if (close + 2 < host_part.len and host_part[close + 1] == ':') {
                    port = std.fmt.parseInt(u16, host_part[close + 2 ..], 10) catch null;
                }
            }
        } else if (std.mem.lastIndexOfScalar(u8, host_part, ':')) |colon| {
            // Only when there is a single colon: bare IPv6 has several.
            if (std.mem.indexOfScalar(u8, host_part, ':') == colon) {
                host = host_part[0..colon];
                port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch null;
            }
        }
        if (host.len == 0) continue;
        try hops.append(a, .{
            .user = if (user) |u| try a.dupe(u8, u) else null,
            .host = try a.dupe(u8, host),
            .port = port,
        });
    }
    return hops.toOwnedSlice(a);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;
const keys = @import("keys.zig"); // fixture loading helper

const FixtureLoader = struct {
    extra: []const u8,

    fn load(ctx: ?*anyopaque, arena: Allocator, path: []const u8) Error!?[]const u8 {
        const self: *FixtureLoader = @ptrCast(@alignCast(ctx.?));
        if (std.mem.eql(u8, path, "ssh_config_extra")) return try arena.dupe(u8, self.extra);
        return null;
    }

    fn loader(self: *FixtureLoader) Loader {
        return .{ .ctx = self, .load = load };
    }
};

fn loadFixtureConfig(gpa: Allocator) !Config {
    const text = try keys.fixtures.load(t.allocator, "ssh_config");
    defer t.allocator.free(text);
    const extra = try keys.fixtures.load(t.allocator, "ssh_config_extra");
    defer t.allocator.free(extra);
    var fl: FixtureLoader = .{ .extra = extra };
    return parse(gpa, text, fl.loader());
}

test "resolve: first obtained value wins, IdentityFile accumulates" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();

    var eff = try cfg.resolve(t.allocator, "work", .{ .home = "/Users/relay" });
    defer eff.deinit();
    try t.expectEqualStrings("files.example.com", eff.host_name);
    try t.expectEqualStrings("fredrik", eff.user.?); // beats "shared" and "fallback"
    try t.expectEqual(@as(u16, 2200), eff.port); // beats 2022
    try t.expectEqualStrings("/Users/relay/.agent.sock", eff.identity_agent.?);
    // Accumulation order: work block, the *.example.com block ("work" is in
    // its pattern list too), then Host *.
    try t.expectEqual(@as(usize, 3), eff.identity_files.len);
    try t.expectEqualStrings("/Users/relay/.ssh/id_ed25519", eff.identity_files[0]);
    try t.expectEqualStrings("/Users/relay/.ssh/id_rsa_3072", eff.identity_files[1]);
    try t.expectEqualStrings("/Users/relay/.ssh/id_fallback", eff.identity_files[2]);
    try t.expectEqual(@as(usize, 0), eff.proxy_jump.len);
    try t.expectEqual(null, eff.proxy_command);
}

test "resolve: unknown alias gets Host * defaults and itself as HostName" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "unlisted.other.net", .{ .home = "/home/x" });
    defer eff.deinit();
    try t.expectEqualStrings("unlisted.other.net", eff.host_name);
    try t.expectEqualStrings("fallback", eff.user.?);
    try t.expectEqual(@as(u16, 22), eff.port);
    try t.expectEqual(@as(usize, 1), eff.identity_files.len);
    try t.expectEqualStrings("/home/x/.ssh/id_fallback", eff.identity_files[0]);
}

test "resolve: negation excludes, wildcard includes" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var alpha = try cfg.resolve(t.allocator, "alpha.example.com", .{ .home = "/h" });
    defer alpha.deinit();
    try t.expectEqualStrings("shared", alpha.user.?);
    try t.expectEqual(@as(u16, 2022), alpha.port);

    // beta is excluded by !beta.example.com despite *.example.com.
    var beta = try cfg.resolve(t.allocator, "beta.example.com", .{ .home = "/h" });
    defer beta.deinit();
    try t.expectEqualStrings("fallback", beta.user.?);
    try t.expectEqual(@as(u16, 22), beta.port);
}

test "resolve: %h/%p token expansion in IdentityFile" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "tokens.example.net", .{ .home = "/h" });
    defer eff.deinit();
    try t.expectEqual(@as(u16, 2222), eff.port);
    try t.expectEqualStrings("/keys/tokens.example.net_2222", eff.identity_files[0]);
}

test "resolve: quoted host alias and Key=Value form" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "spacey host", .{ .home = "/h" });
    defer eff.deinit();
    try t.expectEqualStrings("spacey.example.com", eff.host_name);
}

test "resolve: ProxyJump and ProxyCommand parse" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "jumped", .{ .home = "/h" });
    defer eff.deinit();
    try t.expectEqual(@as(usize, 2), eff.proxy_jump.len);
    try t.expectEqualStrings("alice", eff.proxy_jump[0].user.?);
    try t.expectEqualStrings("bastion.example.com", eff.proxy_jump[0].host);
    try t.expectEqual(@as(u16, 2222), eff.proxy_jump[0].port.?);
    try t.expectEqualStrings("bastion2", eff.proxy_jump[1].host);
    try t.expectEqual(null, eff.proxy_jump[1].port);

    var cmd = try cfg.resolve(t.allocator, "cmd-proxied", .{ .home = "/h" });
    defer cmd.deinit();
    // Parse-only: tokens inside ProxyCommand stay verbatim until M3.
    try t.expectEqualStrings("ssh -W %h:%p gateway", cmd.proxy_command.?);
}

test "resolve: Include one level + CLI overrides win" {
    var cfg = try loadFixtureConfig(t.allocator);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "included.example.net", .{ .home = "/h" });
    defer eff.deinit();
    try t.expectEqualStrings("from-include", eff.user.?);
    try t.expectEqual(@as(u16, 2422), eff.port);

    var cli = try cfg.resolve(t.allocator, "included.example.net", .{
        .home = "/h",
        .port = 9022,
        .user = "override",
    });
    defer cli.deinit();
    try t.expectEqual(@as(u16, 9022), cli.port);
    try t.expectEqualStrings("override", cli.user.?);
}

test "ipv6 proxy hop and none keyword" {
    const hops = try parseProxyJump(t.allocator, "root@[::1]:2222");
    defer t.allocator.free(hops);
    defer for (hops) |h| {
        if (h.user) |u| t.allocator.free(u);
        t.allocator.free(h.host);
    };
    try t.expectEqual(@as(usize, 1), hops.len);
    try t.expectEqualStrings("::1", hops[0].host);
    try t.expectEqual(@as(u16, 2222), hops[0].port.?);
    try t.expectEqualStrings("root", hops[0].user.?);

    const none = try parseProxyJump(t.allocator, "NONE");
    try t.expectEqual(@as(usize, 0), none.len);
}

test "parser skips junk without erroring" {
    var cfg = try parse(t.allocator,
        \\NotAKeyword whatever
        \\Host
        \\Port
        \\ThisKeywordIsWayTooLongToBeReal x
        \\Host h
        \\Port 22notanumber
        \\Port 2022
    , .none);
    defer cfg.deinit();
    var eff = try cfg.resolve(t.allocator, "h", .{ .home = "/h" });
    defer eff.deinit();
    // Unparseable Port is skipped; first VALID value wins.
    try t.expectEqual(@as(u16, 2022), eff.port);
}

test "parse and resolve survive allocation failure" {
    const text = try keys.fixtures.load(t.allocator, "ssh_config");
    defer t.allocator.free(text);
    const Check = struct {
        fn run(gpa: Allocator, cfg_text: []const u8) !void {
            var cfg = parse(gpa, cfg_text, .none) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            defer cfg.deinit();
            var eff = cfg.resolve(gpa, "work", .{ .home = "/h" }) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            eff.deinit();
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{text});
}

test "fuzz ssh_config parser" {
    try t.fuzz({}, fuzzConfig, .{});
}

fn fuzzConfig(_: void, smith: *t.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = smith.slice(&buf);
    var cfg = parse(t.allocator, buf[0..len], .none) catch return;
    defer cfg.deinit();
    var eff = cfg.resolve(t.allocator, "fuzz.example.com", .{ .home = "/h" }) catch return;
    eff.deinit();
}

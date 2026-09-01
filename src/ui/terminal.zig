//! Toolkit-free terminal command and copy-as builders shared by both native
//! frontends.
//!
//! ## Command builders (pure, headless-tested)
//!
//! Every shell line is assembled from an argv first and rendered with POSIX
//! single-quote quoting (`'…'`, embedded `'` becomes `'\''`), so spaces,
//! quotes, `$`, and glob characters survive verbatim. IPv6 hosts: the bare
//! literal for ssh destinations (OpenSSH accepts them), brackets for
//! scp/rsync remote specs and for URLs (the colon would otherwise read as
//! the path / port separator). NOTE: the ssh line puts `-p` BEFORE the
//! destination — ssh treats everything after the destination as the remote
//! command, so the "ssh -t user@host -p port" ordering from the spec sketch
//! would ship `-p` to the remote shell.
//!
//! ## Launch plans
//!
//! `ssh -t -p <port> user@host 'cd <dir> && exec $SHELL -l'` is represented as
//! argv plus a rendered POSIX shell line. The macOS controller currently maps
//! that plan to Ghostty, iTerm2, or Terminal.app. Linux can map the same plan
//! to `$TERMINAL`, foot, kitty, Konsole, Ghostty, or GNOME Console without
//! changing the builders here.
//!
//!  - Ghostty (`com.mitchellh.ghostty`): `/usr/bin/open -n -b <bundle>
//!    --args -e <ssh argv…>` — Ghostty's CLI runs the `-e` command in the
//!    new window, and argv elements pass through `open` unshelled, so no
//!    extra quoting layer is involved.
//!  - iTerm2 (`com.googlecode.iterm2`) and Terminal.app
//!    (`com.apple.Terminal`): write a `#!/bin/sh` temp `.command` file with
//!    the ssh line, mark it executable, `/usr/bin/open -b <bundle> <file>`
//!    — both apps execute `.command` files they are asked to open.
//!
//! The active pane's site/directory/selection is deliberately supplied by
//! frontend code. No terminal detection, process launch, clipboard, AppKit,
//! or GTK API lives in this module.

const std = @import("std");
const relay = @import("relay_core");

const sites_mod = relay.sites;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

/// Command ids per docs/UX.md naming (palette display strings derive from
/// these once the prefs.zig Command members land — see the file header).
pub const open_terminal_command = "server.openTerminal";
pub const copy_as_scp_command = "edit.copyAsScp";
pub const copy_as_rsync_command = "edit.copyAsRsync";
pub const copy_as_sftp_command = "edit.copyAsSftp";
pub const copy_as_curl_command = "edit.copyAsCurl";

pub const ssh_default_port: u16 = 22;

/// Login + endpoint for the ssh-family/curl builders. `port == 0` means
/// "service default" (22 for the ssh family; sites.defaultPort otherwise).
pub const HostSpec = struct {
    user: []const u8 = "",
    host: []const u8,
    port: u16 = 0,
};

pub fn hostSpecForSite(site: *const sites_mod.Site) HostSpec {
    return .{ .user = site.account, .host = site.host, .port = site.port };
}

/// Argument-injection guard. ssh/scp/rsync parse any argv word that starts
/// with '-' as an OPTION — a host or empty-user destination of
/// `-oProxyCommand=…` is silent RCE, and POSIX single-quoting does NOT save
/// us: the dash survives the shell's word-splitting, so the program still
/// sees an option. Control characters are never legitimate in a host/login
/// either (they corrupt the `.command` file and the rendered line). The
/// reachable source is a hostile import — sites.zig's FileZilla/Cyberduck
/// parsers take `<Host>`/`<User>` verbatim — so we vet the destination here,
/// before any argv is assembled. Shell metacharacters need no separate
/// reject: they are quoted in the rendered lines and pass as inert literals
/// on the no-shell `open --args -e` path.
fn fieldSafe(s: []const u8) bool {
    if (s.len == 0) return true; // empty user is normal; empty host is caught upstream
    if (s[0] == '-') return false; // leading dash → option injection
    for (s) |ch| {
        if (ch < 0x20 or ch == 0x7f) return false; // control characters
    }
    return true;
}

/// True when neither the host nor the login can be parsed as a command-line
/// option (or smuggle control characters). See `fieldSafe`.
pub fn destinationSafe(spec: HostSpec) bool {
    return fieldSafe(spec.host) and fieldSafe(spec.user);
}

pub const CopyKind = enum { scp, rsync, sftp_url, curl };

// ---------------------------------------------------------------------------
// Shell quoting (pure)
// ---------------------------------------------------------------------------

fn shellSafeChar(ch: u8) bool {
    return switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '@', '%', '_', '+', '=', ':', ',', '.', '/', '-' => true,
        else => false,
    };
}

pub fn needsShellQuote(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |ch| {
        if (!shellSafeChar(ch)) return true;
    }
    return false;
}

/// POSIX single-quote quoting; words made only of safe characters pass
/// through unquoted (readable command lines).
fn writeShellWord(w: *Writer, s: []const u8) Writer.Error!void {
    if (!needsShellQuote(s)) return w.writeAll(s);
    try w.writeByte('\'');
    for (s) |ch| {
        if (ch == '\'') {
            try w.writeAll("'\\''");
        } else {
            try w.writeByte(ch);
        }
    }
    try w.writeByte('\'');
}

/// One shell-quoted word, gpa-owned.
pub fn shellQuote(gpa: Allocator, s: []const u8) error{OutOfMemory}![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    writeShellWord(&out.writer, s) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

/// argv → one shell line, each element quoted as needed. gpa-owned.
pub fn renderCommandLine(gpa: Allocator, argv: []const []const u8) error{OutOfMemory}![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    render: {
        for (argv, 0..) |arg, i| {
            if (i != 0) out.writer.writeByte(' ') catch break :render;
            writeShellWord(&out.writer, arg) catch break :render;
        }
        return out.toOwnedSlice();
    }
    return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// ssh / scp / rsync builders (pure)
// ---------------------------------------------------------------------------

fn effectiveSshPort(spec: HostSpec) u16 {
    return if (spec.port == 0) ssh_default_port else spec.port;
}

/// `user@host` — ssh destinations accept bare IPv6 literals.
fn writeSshDestination(w: *Writer, spec: HostSpec) Writer.Error!void {
    if (spec.user.len > 0) {
        try w.writeAll(spec.user);
        try w.writeByte('@');
    }
    try w.writeAll(spec.host);
}

/// `user@host` with IPv6 literals bracketed — scp/rsync remote-spec form
/// (the bare colons would parse as the path separator).
fn writeRemoteSpecHost(w: *Writer, spec: HostSpec) Writer.Error!void {
    if (spec.user.len > 0) {
        try w.writeAll(spec.user);
        try w.writeByte('@');
    }
    const v6 = std.mem.indexOfScalar(u8, spec.host, ':') != null;
    if (v6) try w.writeByte('[');
    try w.writeAll(spec.host);
    if (v6) try w.writeByte(']');
}

/// The remote command "Open in Terminal" runs: cd into the pane's
/// directory (quoted for the REMOTE shell), then a login shell.
fn writeRemoteCdCommand(w: *Writer, remote_dir: []const u8) Writer.Error!void {
    try w.writeAll("cd ");
    try writeShellWord(w, remote_dir);
    try w.writeAll(" && exec $SHELL -l");
}

/// ssh argv (no shell involved): {"ssh","-t",["-p","<port>",]dest,cmd}.
/// All slices are allocated in `arena`.
pub fn sshArgv(arena: Allocator, spec: HostSpec, remote_dir: []const u8) error{OutOfMemory}![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, "ssh");
    try argv.append(arena, "-t");
    const port = effectiveSshPort(spec);
    if (port != ssh_default_port) {
        try argv.append(arena, "-p");
        try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{port}));
    }
    var dest: Writer.Allocating = .init(arena);
    writeSshDestination(&dest.writer, spec) catch return error.OutOfMemory;
    try argv.append(arena, try dest.toOwnedSlice());
    var cmd: Writer.Allocating = .init(arena);
    writeRemoteCdCommand(&cmd.writer, remote_dir) catch return error.OutOfMemory;
    try argv.append(arena, try cmd.toOwnedSlice());
    return argv.items;
}

/// The rendered ssh line, e.g.
/// `ssh -t -p 2222 deploy@web1 'cd /var/www && exec $SHELL -l'`. gpa-owned.
pub fn sshCommandLine(gpa: Allocator, spec: HostSpec, remote_dir: []const u8) error{OutOfMemory}![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const argv = try sshArgv(arena_state.allocator(), spec, remote_dir);
    return renderCommandLine(gpa, argv);
}

/// `scp [-r] [-P <port>] 'user@host:<path>' .` — the remote path is quoted
/// twice on purpose: once for the remote shell (classic scp expands the
/// path remotely) and the whole spec once more for the local shell.
pub fn scpCommandLine(gpa: Allocator, spec: HostSpec, remote_path: []const u8, is_dir: bool) error{OutOfMemory}![]u8 {
    var remote: Writer.Allocating = .init(gpa);
    defer remote.deinit();
    build: {
        writeRemoteSpecHost(&remote.writer, spec) catch break :build;
        remote.writer.writeByte(':') catch break :build;
        writeShellWord(&remote.writer, remote_path) catch break :build;

        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        out.writer.writeAll("scp") catch break :build;
        if (is_dir) out.writer.writeAll(" -r") catch break :build;
        const port = effectiveSshPort(spec);
        if (port != ssh_default_port) {
            out.writer.print(" -P {d}", .{port}) catch break :build;
        }
        out.writer.writeByte(' ') catch break :build;
        writeShellWord(&out.writer, remote.written()) catch break :build;
        out.writer.writeAll(" .") catch break :build;
        return out.toOwnedSlice();
    }
    return error.OutOfMemory;
}

/// `rsync -av [-e 'ssh -p <port>'] 'user@host:<path>' .` — `-e "ssh -p"`
/// only when the port is non-default (per the M3 spec sketch).
pub fn rsyncCommandLine(gpa: Allocator, spec: HostSpec, remote_path: []const u8) error{OutOfMemory}![]u8 {
    var remote: Writer.Allocating = .init(gpa);
    defer remote.deinit();
    build: {
        writeRemoteSpecHost(&remote.writer, spec) catch break :build;
        remote.writer.writeByte(':') catch break :build;
        writeShellWord(&remote.writer, remote_path) catch break :build;

        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        out.writer.writeAll("rsync -av") catch break :build;
        const port = effectiveSshPort(spec);
        if (port != ssh_default_port) {
            var ssh_buf: [24]u8 = undefined;
            const ssh_cmd = std.fmt.bufPrint(&ssh_buf, "ssh -p {d}", .{port}) catch break :build;
            out.writer.writeAll(" -e ") catch break :build;
            writeShellWord(&out.writer, ssh_cmd) catch break :build;
        }
        out.writer.writeByte(' ') catch break :build;
        writeShellWord(&out.writer, remote.written()) catch break :build;
        out.writer.writeAll(" .") catch break :build;
        return out.toOwnedSlice();
    }
    return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// URL builders (pure)
// ---------------------------------------------------------------------------

fn urlUnreserved(ch: u8) bool {
    return switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// RFC 3986 percent-encoding; `keep_slash` leaves '/' intact (paths).
fn writePercentEncoded(w: *Writer, s: []const u8, keep_slash: bool) Writer.Error!void {
    for (s) |ch| {
        if (urlUnreserved(ch) or (keep_slash and ch == '/')) {
            try w.writeByte(ch);
        } else {
            try w.print("%{X:0>2}", .{ch});
        }
    }
}

fn writeUrlAuthority(w: *Writer, spec: HostSpec, default_port: u16) Writer.Error!void {
    if (spec.user.len > 0) {
        try writePercentEncoded(w, spec.user, false);
        try w.writeByte('@');
    }
    const v6 = std.mem.indexOfScalar(u8, spec.host, ':') != null;
    if (v6) try w.writeByte('[');
    try w.writeAll(spec.host);
    if (v6) try w.writeByte(']');
    if (spec.port != 0 and spec.port != default_port) {
        try w.print(":{d}", .{spec.port});
    }
}

fn writeUrl(
    w: *Writer,
    scheme: []const u8,
    spec: HostSpec,
    default_port: u16,
    path: []const u8,
    trailing_slash: bool,
) Writer.Error!void {
    try w.writeAll(scheme);
    try w.writeAll("://");
    try writeUrlAuthority(w, spec, default_port);
    if (path.len == 0 or path[0] != '/') try w.writeByte('/');
    try writePercentEncoded(w, path, true);
    if (trailing_slash and (path.len == 0 or path[path.len - 1] != '/')) {
        try w.writeByte('/');
    }
}

/// `sftp://user@host[:port]/path`, percent-encoded; port omitted at 22.
pub fn sftpUrlText(gpa: Allocator, spec: HostSpec, path: []const u8) error{OutOfMemory}![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    writeUrl(&out.writer, "sftp", spec, ssh_default_port, path, false) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

/// curl line per protocol: plain `ftp://`, implicit-TLS `ftps://` (Relay's
/// ftps default is port 990) hardened with `--ssl-reqd`, and `sftp://`.
/// Directories get a trailing '/' so curl lists instead of fetching.
pub fn curlCommandLine(
    gpa: Allocator,
    protocol: sites_mod.Protocol,
    spec: HostSpec,
    path: []const u8,
    is_dir: bool,
) error{OutOfMemory}![]u8 {
    var url: Writer.Allocating = .init(gpa);
    defer url.deinit();
    build: {
        const scheme: []const u8 = switch (protocol) {
            .ftp => "ftp",
            .ftps => "ftps",
            .sftp => "sftp",
        };
        writeUrl(&url.writer, scheme, spec, sites_mod.defaultPort(protocol), path, is_dir) catch break :build;

        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        out.writer.writeAll("curl") catch break :build;
        if (protocol == .ftps) out.writer.writeAll(" --ssl-reqd") catch break :build;
        out.writer.writeByte(' ') catch break :build;
        writeShellWord(&out.writer, url.written()) catch break :build;
        return out.toOwnedSlice();
    }
    return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Terminal app detection + launch plans
// ---------------------------------------------------------------------------

pub const TerminalApp = enum {
    ghostty,
    iterm2,
    terminal,

    pub fn bundleId(self: TerminalApp) [:0]const u8 {
        return switch (self) {
            .ghostty => "com.mitchellh.ghostty",
            .iterm2 => "com.googlecode.iterm2",
            .terminal => "com.apple.Terminal",
        };
    }

    pub fn displayName(self: TerminalApp) []const u8 {
        return switch (self) {
            .ghostty => "Ghostty",
            .iterm2 => "iTerm2",
            .terminal => "Terminal",
        };
    }
};

/// M3: first found wins (prefs override later — see the file header).
pub const detect_order = [_]TerminalApp{ .ghostty, .iterm2, .terminal };

pub const LaunchStrategy = enum {
    /// `open -n -b <bundle> --args -e <argv…>` (CLI-style terminals).
    open_args_e,
    /// Executable `#!/bin/sh` `.command` temp file opened with the app.
    command_file,
};

pub fn launchStrategy(app: TerminalApp) LaunchStrategy {
    return switch (app) {
        .ghostty => .open_args_e,
        .iterm2, .terminal => .command_file,
    };
}

/// `/usr/bin/open` argv for the `--args -e` strategy. Arena-allocated.
pub fn openArgvForArgs(
    arena: Allocator,
    app: TerminalApp,
    cmd_argv: []const []const u8,
) error{OutOfMemory}![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "/usr/bin/open", "-n", "-b", app.bundleId(), "--args", "-e" });
    try argv.appendSlice(arena, cmd_argv);
    return argv.items;
}

/// `/usr/bin/open` argv for the `.command`-file strategy. Arena-allocated.
pub fn openArgvForCommandFile(
    arena: Allocator,
    app: TerminalApp,
    file_path: []const u8,
) error{OutOfMemory}![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "/usr/bin/open", "-b", app.bundleId(), file_path });
    return argv.items;
}

/// `.command` payload: `exec` replaces the shell so closing the ssh session
/// ends the window's process cleanly.
pub fn commandFileContents(gpa: Allocator, ssh_line: []const u8) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(gpa, "#!/bin/sh\n# Relay - Open in Terminal\nexec {s}\n", .{ssh_line});
}

// Platform detection and launching belong to each frontend.

test "shell quoting and hostile destinations" {
    const gpa = std.testing.allocator;
    const quoted = try shellQuote(gpa, "it's here");
    defer gpa.free(quoted);
    try std.testing.expectEqualStrings("'it'\\''s here'", quoted);
    try std.testing.expect(destinationSafe(.{ .user = "alice", .host = "example.com" }));
    try std.testing.expect(!destinationSafe(.{ .host = "-oProxyCommand=bad" }));
}

test "ssh, scp, and URL builders preserve ports and quoting" {
    const gpa = std.testing.allocator;
    const spec: HostSpec = .{ .user = "alice", .host = "2001:db8::1", .port = 2222 };
    const ssh = try sshCommandLine(gpa, spec, "/srv/my site");
    defer gpa.free(ssh);
    try std.testing.expect(std.mem.startsWith(u8, ssh, "ssh -t -p 2222 alice@2001:db8::1 "));
    try std.testing.expect(std.mem.indexOf(u8, ssh, "/srv/my site") != null);
    const scp = try scpCommandLine(gpa, spec, "/srv/a b", false);
    defer gpa.free(scp);
    try std.testing.expect(std.mem.indexOf(u8, scp, "alice@[2001:db8::1]") != null);
    const url = try sftpUrlText(gpa, spec, "/srv/a b");
    defer gpa.free(url);
    try std.testing.expectEqualStrings("sftp://alice@[2001:db8::1]:2222/srv/a%20b", url);
}

test {
    std.testing.refAllDecls(@This());
}

//! terminal — terminal interop (M3): "Open in Terminal" (Cmd+Opt+T,
//! "server.openTerminal") and the "Copy as" submenu ("edit.copyAsScp" /
//! "edit.copyAsRsync" / "edit.copyAsSftp" / "edit.copyAsCurl").
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
//! ## Open in Terminal
//!
//! `ssh -t -p <port> user@host 'cd <dir> && exec $SHELL -l'`, launched via
//! the user's terminal. Detection order (M3: first found wins; a prefs
//! override slots in later): Ghostty → iTerm2 → Terminal.app, resolved with
//! NSWorkspace `URLForApplicationWithBundleIdentifier:`. Per-app strategy:
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
//! Verification status (honest accounting): the argv/file builders and the
//! full headless plan (detection override → `.command` file on disk, +x,
//! exact `/usr/bin/open` argv) are pinned by the tests below. The LIVE
//! launches (a real window appearing) were NOT exercised in this
//! environment — Ghostty's `-e` flag and Terminal.app/iTerm2 running
//! opened `.command` files follow their documented behavior; phase 3's
//! interactive smoke should click "Open in Terminal" once per detected
//! app before this note is dropped.
//!
//! ## Integration seams (phase-3/integrator, documented per the M3 brief)
//!
//!  - TODO(m3-integrate): prefs.zig's `Command` enum (NOT this task's
//!    file) has no `open_terminal` / `copy_as_*` members and the menu tree
//!    has no "Open in Terminal" (Cmd+Opt+T) leaf or Edit ▸ "Copy as"
//!    submenu yet. `register()` binds through the CommandRegistry as soon
//!    as the enum members exist (comptime `@hasField` guards keep this
//!    file compiling either way); `serverMenuItem()` / `copyAsMenuItems()`
//!    are ready-made `menu.Item`s for the tree, same contract as
//!    sites.zig's `serverMenuItems()`.
//!  - The active pane's (site, directory, selection) is injected through
//!    `ContextProvider` — browser.zig owns selection truth; phase 3 wires
//!    the adapter (the PaneHost precedent in sites.zig).
//!
//! Laws honored: UI entry points are main-thread only; the two raw-selector
//! sections below (NSWorkspace detection, NSPasteboard write) carry the
//! same TODO(m3-dedupe)/(m2-dedupe) notes as the edit_sessions.zig and
//! transcript.zig precedents — nothing else in this file sends selectors.

const std = @import("std");
const builtin = @import("builtin");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");
const prefs_mod = @import("prefs.zig");

const objc = mac.objc;
const c = mac.runtime.c;
const foundation = mac.foundation;
const panels = mac.appkit.panels;
const menu_mod = mac.appkit.menu;
const Window = mac.appkit.window.Window;

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

// --- NSWorkspace detection.
//
// TODO(m3-dedupe): belongs in relay_mac (an appkit/workspace.zig) so the
// selector string lives in the wrapper layer — same convention note as
// edit_sessions.zig's workspaceOpen. Nothing below this section sends raw
// selectors except the pasteboard glue (its own TODO).

/// LaunchServices lookup; works headless (no window server needed).
pub fn terminalAppInstalled(app: TerminalApp) bool {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const workspace = foundation.class("NSWorkspace").msgSend(objc.Object, "sharedWorkspace", .{});
    const url = workspace.msgSend(c.id, "URLForApplicationWithBundleIdentifier:", .{
        foundation.nsString(app.bundleId()),
    });
    return url != null;
}

pub fn detectTerminal() ?TerminalApp {
    for (detect_order) |app| {
        if (terminalAppInstalled(app)) return app;
    }
    return null;
}

// --- NSPasteboard write.
//
// TODO(m2-dedupe): NSPasteboard glue → relay_mac (transcript.zig precedent).

const NSPasteboardTypeString = @extern(*const c.id, .{ .name = "NSPasteboardTypeString" });

fn clipboardWrite(text: []const u8) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const pb = foundation.class("NSPasteboard").msgSend(objc.Object, "generalPasteboard", .{});
    _ = pb.msgSend(foundation.NSInteger, "clearContents", .{});
    _ = pb.msgSend(c.BOOL, "setString:forType:", .{
        foundation.nsString(text), NSPasteboardTypeString.*,
    });
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// What the active remote pane is showing (slices are valid only for the
/// duration of the providing call; they may point into the caller's buf).
pub const RemoteContext = struct {
    site_id: u64,
    /// Current directory of the active remote pane (normalized).
    dir: []const u8,
    /// Full path of the selected entry; null = act on the directory.
    selected_path: ?[]const u8 = null,
    selected_is_dir: bool = false,
};

/// browser.zig owns selection truth; phase 3 injects this adapter (the
/// sites.zig PaneHost precedent). `f` fills `buf` and returns slices into
/// it; null = no remote pane is bound.
pub const ContextProvider = struct {
    ctx: ?*anyopaque = null,
    f: ?*const fn (ctx: ?*anyopaque, buf: []u8) ?RemoteContext = null,
};

pub const TerminalController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    win: ?Window,
    provider: ContextProvider,
    /// True: no detection, no launch, no pasteboard — the built artifacts
    /// land in the `last_*` fields instead (tests; the askPrompt "unseen
    /// surfaces refuse" precedent).
    headless: bool,
    /// Detection override (tests; the future prefs choice rides here too).
    forced_app: ?TerminalApp,

    /// Observability: most recent Copy-as payload (gpa-owned).
    last_copied: ?[]u8 = null,
    /// Observability: most recent /usr/bin/open invocation, rendered as a
    /// shell line (gpa-owned).
    last_open_invocation: ?[]u8 = null,
    /// Most recent `.command` temp file path (gpa-owned).
    last_command_file: ?[]u8 = null,

    pub const Options = struct {
        window: ?Window = null,
        provider: ContextProvider = .{},
        headless: bool = false,
        forced_app: ?TerminalApp = null,
    };

    pub fn create(gpa: Allocator, core: *bridge.AppCore, options: Options) error{OutOfMemory}!*TerminalController {
        const self = try gpa.create(TerminalController);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .win = options.window,
            .provider = options.provider,
            .headless = options.headless,
            .forced_app = options.forced_app,
        };
        return self;
    }

    pub fn destroy(self: *TerminalController) void {
        if (self.last_copied) |s| self.gpa.free(s);
        if (self.last_open_invocation) |s| self.gpa.free(s);
        if (self.last_command_file) |s| self.gpa.free(s);
        self.gpa.destroy(self);
    }

    pub fn setContextProvider(self: *TerminalController, provider: ContextProvider) void {
        self.provider = provider;
    }

    // ------------------------------------------------------------------ //
    // Menu / command surface

    /// Server-menu leaf for phase 3 (Cmd+Opt+T per the M3 brief).
    pub fn serverMenuItem(self: *TerminalController) menu_mod.Item {
        return menu_mod.Item.call(
            "Open in Terminal",
            .{ .ctx = self, .f = cmOpenTerminal },
            "t",
            .{ .option = true },
        );
    }

    /// Leaves for an Edit ▸ "Copy as" submenu (phase 3 installs it).
    pub fn copyAsMenuItems(self: *TerminalController) [4]menu_mod.Item {
        return .{
            menu_mod.Item.call("scp Command", .{ .ctx = self, .f = cmCopyScp }, "", .{}),
            menu_mod.Item.call("rsync Command", .{ .ctx = self, .f = cmCopyRsync }, "", .{}),
            menu_mod.Item.call("SFTP URL", .{ .ctx = self, .f = cmCopySftp }, "", .{}),
            menu_mod.Item.call("curl Command", .{ .ctx = self, .f = cmCopyCurl }, "", .{}),
        };
    }

    /// CommandRegistry binding. Compiles before AND after the integrator
    /// adds the enum members (file-header TODO): each bind is guarded on
    /// the member existing in prefs.Command.
    pub fn register(self: *TerminalController, commands: *prefs_mod.CommandRegistry) void {
        if (comptime @hasField(prefs_mod.Command, "open_terminal")) {
            commands.bind(@field(prefs_mod.Command, "open_terminal"), self, cmOpenTerminal);
        }
        if (comptime @hasField(prefs_mod.Command, "copy_as_scp")) {
            commands.bind(@field(prefs_mod.Command, "copy_as_scp"), self, cmCopyScp);
        }
        if (comptime @hasField(prefs_mod.Command, "copy_as_rsync")) {
            commands.bind(@field(prefs_mod.Command, "copy_as_rsync"), self, cmCopyRsync);
        }
        if (comptime @hasField(prefs_mod.Command, "copy_as_sftp")) {
            commands.bind(@field(prefs_mod.Command, "copy_as_sftp"), self, cmCopySftp);
        }
        if (comptime @hasField(prefs_mod.Command, "copy_as_curl")) {
            commands.bind(@field(prefs_mod.Command, "copy_as_curl"), self, cmCopyCurl);
        }
    }

    fn fromMenuCtx(ctx: ?*anyopaque) *TerminalController {
        return @ptrCast(@alignCast(ctx.?));
    }

    fn cmOpenTerminal(ctx: ?*anyopaque) void {
        _ = fromMenuCtx(ctx).openTerminalChecked();
    }

    fn cmCopyScp(ctx: ?*anyopaque) void {
        _ = fromMenuCtx(ctx).copyAsChecked(.scp);
    }

    fn cmCopyRsync(ctx: ?*anyopaque) void {
        _ = fromMenuCtx(ctx).copyAsChecked(.rsync);
    }

    fn cmCopySftp(ctx: ?*anyopaque) void {
        _ = fromMenuCtx(ctx).copyAsChecked(.sftp_url);
    }

    fn cmCopyCurl(ctx: ?*anyopaque) void {
        _ = fromMenuCtx(ctx).copyAsChecked(.curl);
    }

    // ------------------------------------------------------------------ //
    // Open in Terminal

    /// True when a launch was performed (or, headless, fully planned).
    pub fn openTerminalChecked(self: *TerminalController) bool {
        var ctx_buf: [2048]u8 = undefined;
        const ctx = self.currentContext(&ctx_buf) orelse {
            self.fail("Open in Terminal", "No remote pane is connected.");
            return false;
        };
        const site = self.core.findSite(ctx.site_id) orelse {
            self.fail("Open in Terminal", "The pane's site is gone from the site list.");
            return false;
        };
        if (site.protocol != .sftp) {
            self.fail("Open in Terminal", "Open in Terminal needs an SFTP (SSH) site.");
            return false;
        }
        const spec = hostSpecForSite(site);
        if (!destinationSafe(spec)) {
            self.fail("Open in Terminal", "This site's host or user is unsafe (leading dash or control character) and could inject ssh options.");
            return false;
        }
        const app = self.forced_app orelse
            (if (self.headless) null else detectTerminal()) orelse
            {
                self.fail("Open in Terminal", "No terminal application found (looked for Ghostty, iTerm2, Terminal).");
                return false;
            };
        return self.launchSsh(app, spec, ctx.dir);
    }

    fn launchSsh(self: *TerminalController, app: TerminalApp, spec: HostSpec, dir: []const u8) bool {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const open_argv: []const []const u8 = switch (launchStrategy(app)) {
            .open_args_e => blk: {
                const ssh = sshArgv(arena, spec, dir) catch return false;
                break :blk openArgvForArgs(arena, app, ssh) catch return false;
            },
            .command_file => blk: {
                const line = sshCommandLine(arena, spec, dir) catch return false;
                const contents = commandFileContents(arena, line) catch return false;
                const path = self.writeCommandFile(arena, contents) catch {
                    self.fail("Open in Terminal", "Couldn't write the terminal launcher file.");
                    return false;
                };
                self.replaceOwned(&self.last_command_file, self.gpa.dupe(u8, path) catch null);
                break :blk openArgvForCommandFile(arena, app, path) catch return false;
            },
        };

        self.replaceOwned(&self.last_open_invocation, renderCommandLine(self.gpa, open_argv) catch null);
        if (self.headless) return true;
        if (!self.runOpen(open_argv)) {
            self.fail("Open in Terminal", app.displayName());
            return false;
        }
        return true;
    }

    /// Unique executable `.command` file under $TMPDIR (or /tmp). The file
    /// is left for the OS temp reaper — the terminal may still be reading
    /// it after we return. Returned path is arena-owned.
    fn writeCommandFile(self: *TerminalController, arena: Allocator, contents: []const u8) ![]u8 {
        const io = self.core.io;
        const tmp_env = std.c.getenv("TMPDIR");
        const tmp: []const u8 = if (tmp_env) |t| std.mem.span(t) else "/tmp";
        const trimmed = std.mem.trimEnd(u8, tmp, "/");
        var suffix: [8]u8 = undefined;
        io.random(&suffix);
        const path = try std.fmt.allocPrint(arena, "{s}/relay-open-terminal-{x}.command", .{
            trimmed, @as(u64, @bitCast(suffix)),
        });
        const cwd = std.Io.Dir.cwd();
        try cwd.writeFile(io, .{ .sub_path = path, .data = contents });
        var file = try cwd.openFile(io, path, .{});
        defer file.close(io);
        try file.setPermissions(io, .executable_file);
        return path;
    }

    /// Spawn `/usr/bin/open` and wait — it is a short-lived LaunchServices
    /// broker, so the synchronous wait keeps zombie reaping trivial.
    fn runOpen(self: *TerminalController, argv: []const []const u8) bool {
        const result = std.process.run(self.gpa, self.core.io, .{
            .argv = argv,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        }) catch |err| {
            std.log.warn("relay terminal: spawning open failed: {t}", .{err});
            return false;
        };
        defer {
            self.gpa.free(result.stdout);
            self.gpa.free(result.stderr);
        }
        return switch (result.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    // ------------------------------------------------------------------ //
    // Copy as

    /// Builds the command/URL for the current selection (no selection =
    /// the pane directory) and puts it on the pasteboard. True on copy.
    pub fn copyAsChecked(self: *TerminalController, kind: CopyKind) bool {
        var ctx_buf: [2048]u8 = undefined;
        const ctx = self.currentContext(&ctx_buf) orelse {
            self.fail("Copy as", "No remote pane is connected.");
            return false;
        };
        const site = self.core.findSite(ctx.site_id) orelse {
            self.fail("Copy as", "The pane's site is gone from the site list.");
            return false;
        };
        const spec = hostSpecForSite(site);
        if (!destinationSafe(spec)) {
            self.fail("Copy as", "This site's host or user is unsafe (leading dash or control character).");
            return false;
        }
        const path = ctx.selected_path orelse ctx.dir;
        const is_dir = if (ctx.selected_path == null) true else ctx.selected_is_dir;

        const ssh_family = site.protocol == .sftp;
        const text: []u8 = switch (kind) {
            .scp => blk: {
                if (!ssh_family) {
                    self.fail("Copy as scp", "scp needs an SFTP (SSH) site.");
                    return false;
                }
                break :blk scpCommandLine(self.gpa, spec, path, is_dir) catch return false;
            },
            .rsync => blk: {
                if (!ssh_family) {
                    self.fail("Copy as rsync", "rsync needs an SFTP (SSH) site.");
                    return false;
                }
                break :blk rsyncCommandLine(self.gpa, spec, path) catch return false;
            },
            .sftp_url => blk: {
                if (!ssh_family) {
                    self.fail("Copy SFTP URL", "Only SFTP sites have sftp:// URLs.");
                    return false;
                }
                break :blk sftpUrlText(self.gpa, spec, path) catch return false;
            },
            .curl => curlCommandLine(self.gpa, site.protocol, spec, path, is_dir) catch return false,
        };

        self.replaceOwned(&self.last_copied, text);
        if (!self.headless) clipboardWrite(text);
        return true;
    }

    // ------------------------------------------------------------------ //
    // Helpers

    fn currentContext(self: *TerminalController, buf: []u8) ?RemoteContext {
        const f = self.provider.f orelse return null;
        return f(self.provider.ctx, buf);
    }

    fn replaceOwned(self: *TerminalController, slot: *?[]u8, new_value: ?[]u8) void {
        if (slot.*) |old| self.gpa.free(old);
        slot.* = new_value;
    }

    fn fail(self: *TerminalController, title: []const u8, detail: []const u8) void {
        const win = self.win orelse {
            std.log.warn("relay terminal: {s}: {s}", .{ title, detail });
            return;
        };
        panels.presentErrorSheet(win, title, detail);
    }
};

// ---------------------------------------------------------------------------
// Tests — headless: pure builders pinned exhaustively (spaces, quotes,
// IPv6, ports), plus the controller flow against a real manual-pump AppCore
// (launch + pasteboard suppressed via headless mode).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectOwned(expected: []const u8, actual: []u8) !void {
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings(expected, actual);
}

test "shellQuote: safe words pass through; everything else single-quotes" {
    try expectOwned("plain-word_1.txt", try shellQuote(testing.allocator, "plain-word_1.txt"));
    try expectOwned("/var/www", try shellQuote(testing.allocator, "/var/www"));
    try expectOwned("''", try shellQuote(testing.allocator, ""));
    try expectOwned("'a b'", try shellQuote(testing.allocator, "a b"));
    try expectOwned("'it'\\''s'", try shellQuote(testing.allocator, "it's"));
    try expectOwned("'$HOME'", try shellQuote(testing.allocator, "$HOME"));
    try expectOwned("'a;b&c|d'", try shellQuote(testing.allocator, "a;b&c|d"));
    try expectOwned("'*.zig'", try shellQuote(testing.allocator, "*.zig"));
    try expectOwned("'[::1]'", try shellQuote(testing.allocator, "[::1]")); // glob chars
    try expectOwned("'a\"b'", try shellQuote(testing.allocator, "a\"b"));
    try expectOwned("'back\\slash'", try shellQuote(testing.allocator, "back\\slash"));
}

test "sshCommandLine: default port, plain dir" {
    try expectOwned(
        "ssh -t deploy@web1.example 'cd /var/www && exec $SHELL -l'",
        try sshCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1.example" }, "/var/www"),
    );
}

test "sshCommandLine: custom port, no user, IPv6, hostile dir" {
    // -p must precede the destination (everything after it is the remote
    // command for ssh).
    try expectOwned(
        "ssh -t -p 2222 web1 'cd /srv && exec $SHELL -l'",
        try sshCommandLine(testing.allocator, .{ .host = "web1", .port = 2222 }, "/srv"),
    );
    // Bare IPv6 destination (no brackets for ssh).
    try expectOwned(
        "ssh -t -p 2200 root@2001:db8::1 'cd / && exec $SHELL -l'",
        try sshCommandLine(testing.allocator, .{ .user = "root", .host = "2001:db8::1", .port = 2200 }, "/"),
    );
    // Spaces + single quote in the remote dir: quoted for the remote shell
    // first, then the whole remote command for the local line.
    try expectOwned(
        "ssh -t u@h 'cd '\\''/my dir/it'\\''\\'\\'''\\''s'\\'' && exec $SHELL -l'",
        try sshCommandLine(testing.allocator, .{ .user = "u", .host = "h" }, "/my dir/it's"),
    );
}

test "sshArgv: exact argv (no shell involved on the --args -e path)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const argv = try sshArgv(arena_state.allocator(), .{
        .user = "deploy",
        .host = "web1",
        .port = 2222,
    }, "/var/my site");
    const expected = [_][]const u8{
        "ssh", "-t", "-p", "2222", "deploy@web1", "cd '/var/my site' && exec $SHELL -l",
    };
    try testing.expectEqual(expected.len, argv.len);
    for (expected, argv) |want, got| try testing.expectEqualStrings(want, got);

    // Port 22 (explicit or 0) drops the -p pair.
    const argv22 = try sshArgv(arena_state.allocator(), .{ .host = "h", .port = 22 }, "/");
    try testing.expectEqual(@as(usize, 4), argv22.len);
    try testing.expectEqualStrings("h", argv22[2]);
}

test "scpCommandLine: ports, dirs, spaces, quotes, IPv6 brackets" {
    try expectOwned(
        "scp deploy@web1:/var/www/index.html .",
        try scpCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1" }, "/var/www/index.html", false),
    );
    try expectOwned(
        "scp -P 2222 deploy@web1:/a.bin .",
        try scpCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1", .port = 2222 }, "/a.bin", false),
    );
    try expectOwned(
        "scp -r -P 2222 deploy@web1:/release .",
        try scpCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1", .port = 2222 }, "/release", true),
    );
    // Space in the path: remote-quoted, then the whole spec local-quoted.
    try expectOwned(
        "scp 'u@h:'\\''/my dir/a b.txt'\\''' .",
        try scpCommandLine(testing.allocator, .{ .user = "u", .host = "h" }, "/my dir/a b.txt", false),
    );
    // IPv6 host needs brackets in the remote spec (and the spec then needs
    // local quoting because of the brackets).
    try expectOwned(
        "scp -P 2200 'root@[2001:db8::1]:/etc/hosts' .",
        try scpCommandLine(testing.allocator, .{ .user = "root", .host = "2001:db8::1", .port = 2200 }, "/etc/hosts", false),
    );
    // No user: host-only spec.
    try expectOwned(
        "scp h:/f .",
        try scpCommandLine(testing.allocator, .{ .host = "h" }, "/f", false),
    );
}

test "rsyncCommandLine: -e \"ssh -p\" only for non-default ports" {
    try expectOwned(
        "rsync -av deploy@web1:/var/www .",
        try rsyncCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1" }, "/var/www"),
    );
    try expectOwned(
        "rsync -av -e 'ssh -p 2222' deploy@web1:/var/www .",
        try rsyncCommandLine(testing.allocator, .{ .user = "deploy", .host = "web1", .port = 2222 }, "/var/www"),
    );
    try expectOwned(
        "rsync -av -e 'ssh -p 2200' 'u@[::1]:'\\''/with space'\\''' .",
        try rsyncCommandLine(testing.allocator, .{ .user = "u", .host = "::1", .port = 2200 }, "/with space"),
    );
}

test "sftpUrlText: encoding, ports, IPv6" {
    try expectOwned(
        "sftp://deploy@web1.example/var/www",
        try sftpUrlText(testing.allocator, .{ .user = "deploy", .host = "web1.example" }, "/var/www"),
    );
    try expectOwned(
        "sftp://deploy@web1:2222/var/www",
        try sftpUrlText(testing.allocator, .{ .user = "deploy", .host = "web1", .port = 2222 }, "/var/www"),
    );
    // Port 22 is the scheme default and stays implicit.
    try expectOwned(
        "sftp://web1/",
        try sftpUrlText(testing.allocator, .{ .host = "web1", .port = 22 }, "/"),
    );
    // Spaces, quotes and unicode percent-encode; '/' survives.
    try expectOwned(
        "sftp://u@h/my%20dir/it%27s%20%E2%82%AC.txt",
        try sftpUrlText(testing.allocator, .{ .user = "u", .host = "h" }, "/my dir/it's €.txt"),
    );
    // The user part encodes too (an '@' in the login must not split the
    // authority).
    try expectOwned(
        "sftp://user%40corp@h/",
        try sftpUrlText(testing.allocator, .{ .user = "user@corp", .host = "h" }, "/"),
    );
    try expectOwned(
        "sftp://root@[2001:db8::1]:2200/etc",
        try sftpUrlText(testing.allocator, .{ .user = "root", .host = "2001:db8::1", .port = 2200 }, "/etc"),
    );
}

test "curlCommandLine: ftp plain, ftps --ssl-reqd, sftp, dirs, ports" {
    try expectOwned(
        "curl ftp://anonymous@ftp.example.org/pub/file.iso",
        try curlCommandLine(testing.allocator, .ftp, .{ .user = "anonymous", .host = "ftp.example.org" }, "/pub/file.iso", false),
    );
    // ftp default port 21 stays implicit; a custom one rides the URL.
    try expectOwned(
        "curl ftp://h:2121/f",
        try curlCommandLine(testing.allocator, .ftp, .{ .host = "h", .port = 2121 }, "/f", false),
    );
    // Relay ftps = implicit TLS (default 990): ftps:// scheme + --ssl-reqd.
    try expectOwned(
        "curl --ssl-reqd ftps://alice@secure.example/drop",
        try curlCommandLine(testing.allocator, .ftps, .{ .user = "alice", .host = "secure.example", .port = 990 }, "/drop", false),
    );
    // Directories get the trailing slash (curl lists them).
    try expectOwned(
        "curl --ssl-reqd ftps://secure.example/drop/",
        try curlCommandLine(testing.allocator, .ftps, .{ .host = "secure.example" }, "/drop", true),
    );
    try expectOwned(
        "curl sftp://deploy@web1:2222/var/www/app.tar",
        try curlCommandLine(testing.allocator, .sftp, .{ .user = "deploy", .host = "web1", .port = 2222 }, "/var/www/app.tar", false),
    );
    // Percent-encoded URLs need no shell quoting; IPv6 brackets do.
    try expectOwned(
        "curl 'ftp://[::1]/a%20b'",
        try curlCommandLine(testing.allocator, .ftp, .{ .host = "::1" }, "/a b", false),
    );
}

test "launch plans: strategy per app, exact open argv" {
    try testing.expectEqual(LaunchStrategy.open_args_e, launchStrategy(.ghostty));
    try testing.expectEqual(LaunchStrategy.command_file, launchStrategy(.iterm2));
    try testing.expectEqual(LaunchStrategy.command_file, launchStrategy(.terminal));

    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ssh = try sshArgv(arena, .{ .user = "u", .host = "h", .port = 2222 }, "/d");
    const ghostty = try openArgvForArgs(arena, .ghostty, ssh);
    const expected_head = [_][]const u8{
        "/usr/bin/open", "-n", "-b", "com.mitchellh.ghostty", "--args", "-e",
    };
    try testing.expectEqual(expected_head.len + ssh.len, ghostty.len);
    for (expected_head, ghostty[0..expected_head.len]) |want, got| {
        try testing.expectEqualStrings(want, got);
    }
    try testing.expectEqualStrings("ssh", ghostty[expected_head.len]);

    const term = try openArgvForCommandFile(arena, .terminal, "/tmp/x.command");
    const expected_term = [_][]const u8{ "/usr/bin/open", "-b", "com.apple.Terminal", "/tmp/x.command" };
    try testing.expectEqual(expected_term.len, term.len);
    for (expected_term, term) |want, got| try testing.expectEqualStrings(want, got);

    const iterm = try openArgvForCommandFile(arena, .iterm2, "/tmp/x.command");
    try testing.expectEqualStrings("com.googlecode.iterm2", iterm[2]);
}

test "commandFileContents: sh shebang + exec'd ssh line" {
    const contents = try commandFileContents(
        testing.allocator,
        "ssh -t -p 2222 u@h 'cd /d && exec $SHELL -l'",
    );
    defer testing.allocator.free(contents);
    try testing.expect(std.mem.startsWith(u8, contents, "#!/bin/sh\n"));
    try testing.expect(std.mem.endsWith(u8, contents, "exec ssh -t -p 2222 u@h 'cd /d && exec $SHELL -l'\n"));
}

test "destinationSafe: leading dash / control chars rejected, normal accepted" {
    // Normal destinations pass (with and without a login).
    try testing.expect(destinationSafe(.{ .user = "deploy", .host = "web1.example" }));
    try testing.expect(destinationSafe(.{ .host = "2001:db8::1" })); // IPv6, empty user
    try testing.expect(destinationSafe(.{ .host = "h" })); // empty user is normal

    // Leading-dash host (empty user emits it as a bare argv word) → option
    // injection (`-oProxyCommand=…` is RCE); single-quoting does not help.
    try testing.expect(!destinationSafe(.{ .host = "-oProxyCommand=touch /tmp/pwned" }));
    // Leading-dash login → `user@host` itself starts with '-'.
    try testing.expect(!destinationSafe(.{ .user = "-oProxyCommand=x", .host = "h" }));
    // Control characters never belong in a host/login.
    try testing.expect(!destinationSafe(.{ .host = "h\nrm -rf" }));
    try testing.expect(!destinationSafe(.{ .user = "a\x00b", .host = "h" }));
}

test "detection probe does not crash headless (assert presence only on request)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const detected = detectTerminal();
    // LaunchServices answers vary by machine/sandbox; only pin the result
    // when explicitly asked (Terminal.app ships with macOS).
    if (std.c.getenv("RELAY_TERMINAL_DETECT") != null) {
        try testing.expect(detected != null);
    }
}

// --- controller-level tests (real AppCore, manual pump, headless) -----------

const FakeStore = relay.cred.fake.FakeStore;

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
};

const TestPaneCtx = struct {
    site_id: u64,
    dir: []const u8,
    selected: ?[]const u8 = null,
    selected_is_dir: bool = false,

    fn get(ctx: ?*anyopaque, buf: []u8) ?RemoteContext {
        const self: *TestPaneCtx = @ptrCast(@alignCast(ctx.?));
        var n: usize = 0;
        @memcpy(buf[n..][0..self.dir.len], self.dir);
        const dir = buf[n..][0..self.dir.len];
        n += self.dir.len;
        var selected: ?[]const u8 = null;
        if (self.selected) |sel| {
            @memcpy(buf[n..][0..sel.len], sel);
            selected = buf[n..][0..sel.len];
            n += sel.len;
        }
        return .{
            .site_id = self.site_id,
            .dir = dir,
            .selected_path = selected,
            .selected_is_dir = self.selected_is_dir,
        };
    }

    fn provider(self: *TestPaneCtx) ContextProvider {
        return .{ .ctx = self, .f = get };
    }
};

test "controller: openTerminal plans the launch end to end (headless)" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{
        .{ .id = 3, .protocol = .sftp, .host = "web1.example", .port = 2222, .account = "deploy" },
        .{ .id = 4, .protocol = .ftp, .host = "ftp.example" },
    } });
    defer h.stop();

    var pane: TestPaneCtx = .{ .site_id = 3, .dir = "/var/my site" };
    const ctrl = try TerminalController.create(testing.allocator, h.core, .{
        .provider = pane.provider(),
        .headless = true,
        .forced_app = .terminal,
    });
    defer ctrl.destroy();

    // Terminal.app strategy: a .command file is written, +x, with the line.
    try testing.expect(ctrl.openTerminalChecked());
    const file_path = ctrl.last_command_file.?;
    try testing.expect(std.mem.endsWith(u8, file_path, ".command"));
    const io = h.core.io;
    var file = try std.Io.Dir.cwd().openFile(io, file_path, .{});
    var read_buf: [1024]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    const contents = try reader.interface.allocRemaining(testing.allocator, .limited(4096));
    defer testing.allocator.free(contents);
    const stat = try file.stat(io);
    file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, file_path) catch {};
    try testing.expect(std.mem.startsWith(u8, contents, "#!/bin/sh\n"));
    try testing.expect(std.mem.indexOf(
        u8,
        contents,
        "exec ssh -t -p 2222 deploy@web1.example 'cd '\\''/var/my site'\\'' && exec $SHELL -l'",
    ) != null);
    try testing.expect(stat.permissions.toMode() & 0o100 != 0);
    // The planned open invocation targets Terminal's bundle id.
    try testing.expect(std.mem.indexOf(u8, ctrl.last_open_invocation.?, "com.apple.Terminal") != null);

    // Ghostty strategy plans open --args -e (no temp file needed).
    ctrl.forced_app = .ghostty;
    try testing.expect(ctrl.openTerminalChecked());
    const invocation = ctrl.last_open_invocation.?;
    try testing.expect(std.mem.indexOf(u8, invocation, "com.mitchellh.ghostty") != null);
    try testing.expect(std.mem.indexOf(u8, invocation, "--args -e ssh -t -p 2222 deploy@web1.example") != null);

    // Non-SFTP sites refuse (ssh has nowhere to go).
    pane.site_id = 4;
    try testing.expect(!ctrl.openTerminalChecked());

    // Unknown sites and missing providers refuse instead of crashing.
    pane.site_id = 424242;
    try testing.expect(!ctrl.openTerminalChecked());
    ctrl.setContextProvider(.{});
    try testing.expect(!ctrl.openTerminalChecked());
}

test "controller: hostile leading-dash host (import) refuses before building argv" {
    var h: Harness = undefined;
    // A host an importer could carry verbatim: ssh would parse it as an
    // option (ProxyCommand RCE). Empty account so the host leads the dest.
    try h.start(.{ .sites = &.{
        .{ .id = 7, .protocol = .sftp, .host = "-oProxyCommand=touch /tmp/pwned" },
    } });
    defer h.stop();

    var pane: TestPaneCtx = .{ .site_id = 7, .dir = "/var/www" };
    const ctrl = try TerminalController.create(testing.allocator, h.core, .{
        .provider = pane.provider(),
        .headless = true,
        .forced_app = .terminal,
    });
    defer ctrl.destroy();

    // Open in Terminal refuses; no launcher artifacts are ever produced.
    try testing.expect(!ctrl.openTerminalChecked());
    try testing.expect(ctrl.last_command_file == null);
    try testing.expect(ctrl.last_open_invocation == null);

    // Every Copy-as kind refuses too; nothing reaches the pasteboard buffer.
    try testing.expect(!ctrl.copyAsChecked(.scp));
    try testing.expect(!ctrl.copyAsChecked(.rsync));
    try testing.expect(!ctrl.copyAsChecked(.sftp_url));
    try testing.expect(!ctrl.copyAsChecked(.curl));
    try testing.expect(ctrl.last_copied == null);
}

test "controller: copyAs builds the right payload per kind and protocol" {
    var h: Harness = undefined;
    try h.start(.{ .sites = &.{
        .{ .id = 3, .protocol = .sftp, .host = "web1.example", .port = 2222, .account = "deploy" },
        .{ .id = 5, .protocol = .ftps, .host = "secure.example", .account = "alice" },
    } });
    defer h.stop();

    var pane: TestPaneCtx = .{
        .site_id = 3,
        .dir = "/var/www",
        .selected = "/var/www/index.html",
    };
    const ctrl = try TerminalController.create(testing.allocator, h.core, .{
        .provider = pane.provider(),
        .headless = true,
    });
    defer ctrl.destroy();

    try testing.expect(ctrl.copyAsChecked(.scp));
    try testing.expectEqualStrings(
        "scp -P 2222 deploy@web1.example:/var/www/index.html .",
        ctrl.last_copied.?,
    );
    try testing.expect(ctrl.copyAsChecked(.rsync));
    try testing.expectEqualStrings(
        "rsync -av -e 'ssh -p 2222' deploy@web1.example:/var/www/index.html .",
        ctrl.last_copied.?,
    );
    try testing.expect(ctrl.copyAsChecked(.sftp_url));
    try testing.expectEqualStrings(
        "sftp://deploy@web1.example:2222/var/www/index.html",
        ctrl.last_copied.?,
    );
    try testing.expect(ctrl.copyAsChecked(.curl));
    try testing.expectEqualStrings(
        "curl sftp://deploy@web1.example:2222/var/www/index.html",
        ctrl.last_copied.?,
    );

    // No selection: the pane directory is the target (dir semantics).
    pane.selected = null;
    try testing.expect(ctrl.copyAsChecked(.scp));
    try testing.expectEqualStrings(
        "scp -r -P 2222 deploy@web1.example:/var/www .",
        ctrl.last_copied.?,
    );

    // FTPS sites: curl works (--ssl-reqd), the ssh-family kinds refuse.
    pane.site_id = 5;
    pane.dir = "/drop";
    try testing.expect(ctrl.copyAsChecked(.curl));
    try testing.expectEqualStrings(
        "curl --ssl-reqd ftps://alice@secure.example/drop/",
        ctrl.last_copied.?,
    );
    try testing.expect(!ctrl.copyAsChecked(.scp));
    try testing.expect(!ctrl.copyAsChecked(.rsync));
    try testing.expect(!ctrl.copyAsChecked(.sftp_url));
}

test "controller: menu surface + registry guards compile pre-integration" {
    var h: Harness = undefined;
    try h.start(null);
    defer h.stop();

    const ctrl = try TerminalController.create(testing.allocator, h.core, .{ .headless = true });
    defer ctrl.destroy();

    const item = ctrl.serverMenuItem();
    try testing.expectEqualStrings("Open in Terminal", item.leaf.title);
    try testing.expectEqualStrings("t", item.leaf.key);
    try testing.expect(item.leaf.mods.option);
    try testing.expect(item.leaf.mods.command);

    const copies = ctrl.copyAsMenuItems();
    try testing.expectEqualStrings("scp Command", copies[0].leaf.title);
    try testing.expectEqualStrings("curl Command", copies[3].leaf.title);

    // register() is a no-op until the prefs.Command members exist; it must
    // bind nothing and crash nothing today.
    const commands = try prefs_mod.CommandRegistry.create(testing.allocator);
    defer commands.destroy();
    ctrl.register(commands);
}

test {
    std.testing.refAllDecls(@This());
}

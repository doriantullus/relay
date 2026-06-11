//! Relay — native macOS FTP/FTPS/SFTP client. M3 entry point.
//!
//! Boot sequence (docs/UX.md, docs/ARCHITECTURE.md):
//!   AppCore (relay_core behind src/app/bridge.zig) → NSApplication +
//!   RelayAppDelegate → applicationDidFinishLaunching builds the window:
//!   toolbar; sidebar | [local pane | remote pane | inspector] | bottom
//!   panel (NSSplitViews with autosave names); all controllers; menu bar
//!   bound through the CommandRegistry → [NSApp run].
//!
//! M3 integration owned here: command palette (Cmd+Shift+P / Cmd+P),
//! edit-in-external-editor (Cmd+E), Quick Look (Space / Cmd+Y, remote files
//! through the preview TempCache), terminal interop (Cmd+Opt+T + Copy as),
//! site importers (File ▸ Import), sync browsing / compare / vim toggles,
//! transfer notifications, and session state restoration (ui.zon: per-pane
//! site+path, panel collapse states — remote reconnects only when they are
//! provably prompt-free: agent auth or a stored keychain secret).
//!
//! Self-test modes (exercised by `zig build run -- --smoke`):
//!   --smoke       scripted local→local transfer of a 50-file tmp tree
//!                 through the real GUI path; asserts byte-identical
//!                 copies, transfer-panel progress, settings window, the
//!                 Cmd+K sheet, the command palette (open + fuzzy query +
//!                 execute + close), a TempCache put/get round trip and a
//!                 full local edit-session round trip (FSEvents watch →
//!                 save → conflict re-stat on an unchanged mtime → upload);
//!                 prints RELAY-SMOKE PASS and exits 0.
//!   --smoke-sftp  same skeleton against a dockerized OpenSSH (atmoz/sftp)
//!                 with a real libssh2 connect factory: list /upload and
//!                 download one file end-to-end. Skips (exit 0) when no
//!                 docker daemon is reachable.

const std = @import("std");
const builtin = @import("builtin");
const relay = @import("relay_core");
const mac = @import("relay_mac");

pub const bridge = @import("bridge.zig");
pub const factories = @import("factories.zig");
pub const app_delegate = @import("app_delegate.zig");
pub const fuzzy = @import("fuzzy.zig");
pub const temp_cache = @import("temp_cache.zig");
pub const controllers = struct {
    pub const browser = @import("controllers/browser.zig");
    pub const sites = @import("controllers/sites.zig");
    pub const transfers = @import("controllers/transfers.zig");
    pub const transcript = @import("controllers/transcript.zig");
    pub const prefs = @import("controllers/prefs.zig");
    pub const inspector = @import("controllers/inspector.zig");
    pub const edit_sessions = @import("controllers/edit_sessions.zig");
    pub const palette = @import("controllers/palette.zig");
    pub const terminal = @import("controllers/terminal.zig");
};

const objc = mac.objc;
const foundation = mac.foundation;
const dispatch = mac.dispatch;
const windowkit = mac.appkit.window;
const split_view = mac.appkit.split_view;
const toolbar_mod = mac.appkit.toolbar;
const menu_kit = mac.appkit.menu;
const table_source = mac.appkit.table_source;

const browser_mod = controllers.browser;
const sites_mod = controllers.sites;
const transfers_mod = controllers.transfers;
const prefs_mod = controllers.prefs;
const inspector_mod = controllers.inspector;
const edit_mod = controllers.edit_sessions;
const palette_mod = controllers.palette;
const terminal_mod = controllers.terminal;
const quicklook = mac.quicklook;
const notifications = mac.notifications;

const item_mod = relay.queue.item;
const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;
const site_pool_mod = relay.pool.site_pool;
const session_mod = relay.sftp.session;
const sftp_client_mod = relay.sftp.client;
const diag_mod = relay.diag;
const cred_store_mod = relay.cred.store;
const core_sites_mod = relay.sites;
const CancelToken = relay.cancel.CancelToken;

const Allocator = std.mem.Allocator;
const gpa = std.heap.c_allocator;

const window_title = "Relay";
const default_frame = foundation.rect(0, 0, 1240, 780);

pub const Mode = enum { normal, smoke, smoke_sftp };

pub fn parseMode(arg: []const u8) ?Mode {
    if (std.mem.eql(u8, arg, "--smoke")) return .smoke;
    if (std.mem.eql(u8, arg, "--smoke-sftp")) return .smoke_sftp;
    return null;
}

// ---------------------------------------------------------------------------
// Process-lifetime state (pinned; the run loop never returns).
// ---------------------------------------------------------------------------
var g_core: *bridge.AppCore = undefined;
var g_hooks: app_delegate.Hooks = .{};
var g_delegate: app_delegate.AppDelegate = undefined;
var g_ui: Ui = undefined;
var g_ui_built = false;
var g_mode: Mode = .normal;
var g_smoke: Smoke = undefined;
/// Production connect factories (normal mode; smoke modes inject their own).
var g_factories: *factories.Factories = undefined;

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (parseMode(arg)) |mode| g_mode = mode;
    }

    const boot_pool = objc.AutoreleasePool.init();

    var options: bridge.Options = .{};
    if (g_mode != .normal) {
        g_smoke.setup(g_mode, init.environ) catch |err| smokeFail("setup", @errorName(err));
        options = g_smoke.coreOptions();
    }
    g_core = try bridge.AppCore.initOptions(gpa, options);

    const app = windowkit.App.shared();
    app.setRegularActivationPolicy();

    g_hooks = .{
        .core = g_core,
        .on_launch = onLaunch,
        .on_reopen = onReopen,
        .on_did_become_active = onDidBecomeActive,
        .on_will_terminate = onWillTerminate,
    };
    g_delegate = try app_delegate.AppDelegate.init(&g_hooks);
    g_delegate.install();

    boot_pool.deinit();
    app.run(); // never returns; quit goes through applicationShouldTerminate:
}

fn onLaunch(_: ?*anyopaque) void {
    buildUi() catch |err| {
        std.log.err("relay: failed to assemble the window: {t}", .{err});
        if (g_mode != .normal) smokeFail("launch", @errorName(err));
        std.process.exit(1);
    };
    if (g_mode != .normal) g_smoke.begin();
}

fn onReopen(_: ?*anyopaque) void {
    if (g_ui_built) g_ui.win.makeKeyAndOrderFront();
}

fn onDidBecomeActive(_: ?*anyopaque) void {
    // Cheap freshness check: the SSH-config smart group re-parses only
    // when ~/.ssh/config's mtime moved (BACKLOG: live-ish smart group).
    if (g_ui_built) g_ui.sites.refreshSshConfigIfChanged();
}

/// Foreground predicate for the transfers controller's background-only
/// failure notifications. The selector lives in the relay_mac wrapper
/// (windowkit.App.isActive) per the macOS-layer law; main only forwards.
fn appIsForeground(_: ?*anyopaque) bool {
    return windowkit.App.shared().isActive();
}

/// Runs inside applicationShouldTerminate, BEFORE the core teardown.
fn onWillTerminate(_: ?*anyopaque) void {
    // [NSApp terminate:] is silently swallowed while an NSAlert sheet is
    // attached (verified live; BACKLOG hygiene): dismiss attached sheets
    // first so the quit path always reaches teardown.
    if (g_ui_built) {
        dismissAttachedSheets(g_ui.win);
        if (g_ui.prefs.built) dismissAttachedSheets(g_ui.prefs.win);
        g_ui.palette.close();
        g_ui.preview.close();
        // Session restoration: persist per-pane (site, path) + panel
        // states into ui.zon while the views are still alive.
        if (g_mode == .normal) {
            g_ui.prefs.setSessionState(captureSessionState()) catch {};
        }
        // End every edit session BEFORE AppCore.shutdown(): stops the
        // FSEvents watchers, cancels in-flight items through the live
        // core, deletes the per-session temp dirs, releases the App Nap
        // activity. Idempotent.
        g_ui.edit.deinit();
    }
    if (g_mode != .normal) g_smoke.cleanup();
}

/// Quit-time snapshot for ui.zon (M3 state restoration). Remote sites are
/// recorded only when they are persisted (saved sites) — ephemeral
/// quick-connect ids are meaningless across runs.
fn captureSessionState() prefs_mod.SessionState {
    var session: prefs_mod.SessionState = .{
        .focused_pane = g_ui.browser.focused,
        .sidebar_collapsed = g_ui.root_split.isCollapsed(0),
        .transfers_collapsed = g_ui.content_split.isCollapsed(1),
        .inspector_collapsed = g_ui.inner_split.isCollapsed(1),
    };
    capturePane(0, &session.pane0_site, &session.pane0_path);
    capturePane(1, &session.pane1_site, &session.pane1_path);
    return session;
}

fn capturePane(index: u32, site_out: *u64, path_out: *[]const u8) void {
    const pane = g_ui.browser.panes[index];
    const site_id = pane.site orelse return;
    const path = pane.currentPath() orelse return;
    if (site_id != item_mod.local_site_id and !sitePersisted(site_id)) return;
    site_out.* = site_id;
    path_out.* = path;
}

fn sitePersisted(site_id: u64) bool {
    var row: usize = 0;
    while (g_ui.sites.store.persistedAt(row)) |entry| : (row += 1) {
        if (entry.site.id == site_id) return true;
    }
    return false;
}

/// End every attached sheet (cancel). Sheets can stack (an alert over a
/// form sheet) and endSheet detaches asynchronously, so the loop is
/// bounded and stops when the same sheet stays attached.
fn dismissAttachedSheets(win: windowkit.Window) void {
    var last: ?windowkit.Window = null;
    var guard: usize = 0;
    while (guard < 8) : (guard += 1) {
        const sheet = win.attachedSheet() orelse return;
        if (last) |prev| {
            if (prev.obj.value == sheet.obj.value) return; // detach pending
        }
        last = sheet;
        win.endSheet(sheet, windowkit.modal_response_cancel);
    }
}

// ---------------------------------------------------------------------------
// Window assembly
// ---------------------------------------------------------------------------
const Ui = struct {
    app: windowkit.App,
    win: windowkit.Window,
    menu_reg: *menu_kit.Registry,
    commands: *prefs_mod.CommandRegistry,
    tb: *toolbar_mod.Toolbar,
    prefs: *prefs_mod.PrefsController,
    browser: *browser_mod.BrowserController,
    transfers: *transfers_mod.TransfersController,
    inspector: *inspector_mod.InspectorController,
    sites: *sites_mod.SitesController,
    // M3 controllers.
    palette: *palette_mod.PaletteController,
    edit: *edit_mod.EditSessionsController,
    terminal: *terminal_mod.TerminalController,
    preview: *quicklook.Preview,
    notifier: *notifications.Notifier,
    /// Preview cache for remote Quick Look (download once per
    /// site/path/size/mtime). null = cache dir unavailable; remote
    /// previews degrade to a no-op.
    cache: ?temp_cache.TempCache,
    /// Lazily built right-click menu for the browser pane tables.
    pane_menu: ?objc.Object,
    /// sidebar | content.
    root_split: *split_view.SplitView,
    /// (panes+inspector) / bottom panel.
    content_split: *split_view.SplitView,
    /// browser panes | inspector.
    inner_split: *split_view.SplitView,
};

fn densityFromPrefs(d: prefs_mod.Density) table_source.Density {
    return switch (d) {
        .comfortable => .comfortable,
        .compact => .compact,
        .dense => .dense,
    };
}

fn dateFormatFromPrefs(f: prefs_mod.DateFormat) browser_mod.DateFormat {
    return switch (f) {
        .iso => .iso,
        .relative => .relative,
    };
}

fn buildUi() !void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const core = g_core;

    g_ui.app = windowkit.App.shared();
    g_ui.menu_reg = try menu_kit.Registry.create(gpa);
    g_ui.commands = try prefs_mod.CommandRegistry.create(gpa);

    g_ui.win = windowkit.Window.create(default_frame, window_title, windowkit.StyleMask.standard);
    _ = g_ui.win.setFrameAutosaveName("RelayMainWindow");

    g_ui.prefs = try prefs_mod.PrefsController.create(gpa, core);

    const ui_prefs = g_ui.prefs.uiPrefs();
    // Local-pane restore is silent: the saved path is statted first so a
    // vanished directory degrades to $HOME instead of a launch error sheet.
    const restored_local: ?[]const u8 = blk: {
        if (g_mode != .normal) break :blk g_smoke.localStartPath();
        const session = ui_prefs.session;
        if (session.pane0_site == item_mod.local_site_id and
            session.pane0_path.len > 0 and localDirExists(session.pane0_path))
            break :blk session.pane0_path;
        break :blk null;
    };
    g_ui.browser = try browser_mod.BrowserController.create(gpa, core, g_ui.win, .{
        .initial_local_path = restored_local,
        .density = densityFromPrefs(ui_prefs.density),
        .date_format = dateFormatFromPrefs(ui_prefs.date_format),
        .confirm_delete = ui_prefs.confirm_delete,
        .monospace_lists = ui_prefs.monospace_lists,
        .vim_mode = ui_prefs.vim_mode,
    });

    g_ui.transfers = try transfers_mod.TransfersController.create(gpa, core);

    g_ui.inspector = try inspector_mod.InspectorController.create(gpa, core);
    g_ui.inspector.setParentWindow(g_ui.win);

    g_ui.sites = try sites_mod.SitesController.create(gpa, core, .{
        .window = g_ui.win,
        .pane_host = .{
            .ctx = null,
            .active_token = paneHostActiveToken,
            .connecting = paneHostConnecting,
            .navigate = paneHostNavigate,
        },
    });

    // --- M3 controllers -------------------------------------------------

    g_ui.palette = try palette_mod.PaletteController.create(gpa, core, g_ui.commands);
    g_ui.palette.setParentWindow(g_ui.win);
    g_ui.palette.setIntegration(.{
        .ctx = null,
        .sites = paletteSites,
        .connect = paletteConnect,
        .pane_state = palettePaneState,
        .navigate = paletteNavigate,
    });

    g_ui.edit = try edit_mod.EditSessionsController.create(gpa, core, .{
        .cache_base = if (g_mode != .normal) g_smoke.editCachePath() else null,
        // --smoke runs the real watcher/upload pipeline but must not
        // launch an editor on the host.
        .open_in_editor = g_mode == .normal,
        .win = g_ui.win,
    });
    g_ui.edit.setTargetProvider(.{ .ctx = g_ui.browser, .collectFn = collectEditTargets });

    g_ui.terminal = try terminal_mod.TerminalController.create(gpa, core, .{
        .window = g_ui.win,
        .provider = .{ .ctx = null, .f = terminalContext },
    });

    g_ui.preview = try quicklook.Preview.create(gpa);
    g_ui.pane_menu = null;
    g_ui.cache = blk: {
        if (g_mode != .normal) {
            break :blk temp_cache.TempCache.initAt(
                gpa,
                core.io,
                std.Io.Dir.cwd(),
                g_smoke.previewCachePath(),
                temp_cache.default_budget_bytes,
            ) catch null;
        }
        break :blk temp_cache.TempCache.openDefault(
            gpa,
            core.io,
            bridge.app_support_bundle_id,
            temp_cache.default_budget_bytes,
        ) catch |err| no_cache: {
            std.log.warn("relay: preview cache unavailable ({t}); remote Quick Look disabled", .{err});
            break :no_cache null;
        };
    };
    try core.registerListener(.transfer_state, &g_preview_pending, onPreviewTransferState);

    g_ui.notifier = try notifications.Notifier.create(gpa);
    try g_ui.notifier.attach(core);
    // Background-only transfer-failure notifications: the transfers
    // controller coalesces a per-drain burst and posts via this notifier,
    // gated on NSApplication.isActive (foreground = silent; the Failed tab
    // covers it). Wired only in the real app (smoke modes stay quiet).
    if (g_mode == .normal) {
        g_ui.notifier.requestAuthorization();
        g_ui.transfers.attachFailureNotifier(g_ui.notifier, null, appIsForeground);
    }

    if (g_mode == .normal) {
        // Production FTP/FTPS/SFTP connect factories: known_hosts + prompt
        // wiring through the bridge, per-site auth meta from the sites
        // controller (--smoke-sftp injects its own factory at AppCore init).
        g_factories = try factories.Factories.create(gpa, core);
        g_factories.meta_lookup = .{ .ctx = g_ui.sites, .get = sitesAuthLookup };
        core.setFactoryProvider(g_factories.provider());
    }

    // Settings-window changes live-apply to open views: density, date
    // format, confirm-delete and monospaced lists all push through this
    // listener (the View-menu density path also pushes directly).
    try g_ui.prefs.addChangeListener(null, onPrefsChanged);

    // Inspector feed: focused-pane selection changes, snapshot swaps and
    // focus switches land in the Get Info panel (docs/UX.md).
    g_ui.browser.setSelectionHook(.{ .ctx = null, .notify = onPaneSelection });

    // Inspector Apply → optimistic chmod overlay on the owning pane
    // (pending-alpha Permissions cell until op_done/re-list reconciles).
    g_ui.inspector.setChmodStageHook(.{ .ctx = null, .stage = onChmodStaged });

    // M3 browser seams: successful navigations feed the palette frecency
    // store; plain Space Quick Looks the selection; right-click serves the
    // shared file context menu.
    g_ui.browser.setVisitHook(.{ .ctx = null, .notify = onPaneVisit });
    g_ui.browser.setSpaceHook(.{ .ctx = null, .handle = onPaneSpace });
    g_ui.browser.setContextMenuHook(.{ .ctx = null, .provide = paneContextMenu });

    // Splits per docs/UX.md, every one with an autosave name.
    g_ui.inner_split = try split_view.hSplit(gpa, &.{
        .{ .view = g_ui.browser.view(), .min_size = 520 },
        .{ .view = g_ui.inspector.view(), .min_size = inspector_mod.panel_width, .collapsible = true },
    }, .{ .autosave_name = "RelayContentInspector" });
    g_ui.inner_split.collapse(1); // inspector closed until Cmd+I

    g_ui.content_split = try split_view.vSplit(gpa, &.{
        .{ .view = g_ui.inner_split.view(), .min_size = 260 },
        .{ .view = g_ui.transfers.view(), .min_size = 150, .collapsible = true },
    }, .{ .autosave_name = "RelayContentBottom" });
    g_ui.transfers.attachPanelSplit(g_ui.content_split, 1);
    g_ui.content_split.collapse(1); // auto-expands on the first transfer

    const sidebar = g_ui.sites.sidebarView() orelse return error.NoSidebar;
    g_ui.root_split = try split_view.hSplit(gpa, &.{
        .{ .view = sidebar, .min_size = 180, .collapsible = true },
        .{ .view = g_ui.content_split.view(), .min_size = 640 },
    }, .{ .autosave_name = "RelayRootSplit" });

    g_ui.tb = try toolbar_mod.Toolbar.init(gpa, "RelayMainToolbar", &g_ui, &toolbar_items);
    g_ui.tb.installOnWindow(g_ui.win.obj.value);

    bindCommands();
    try prefs_mod.installMenuBar(gpa, g_ui.menu_reg, g_ui.commands);

    g_ui.transfers.setRevealHandler(null, revealInPane);

    g_ui.win.setContentView(objc.Object.fromId(g_ui.root_split.view()));
    g_ui.win.center();
    g_ui.win.makeKeyAndOrderFront();
    g_ui.app.activate();
    g_ui.browser.focusPane(0);

    // Restore the persisted queue (items come back paused; resume is a
    // user action, never forced) and reflect it in the panel.
    _ = core.restoreQueue();
    g_ui.transfers.refreshFromEngine();

    g_ui_built = true;

    // Session restoration (normal mode): panel collapse states + remote
    // pane reconnects. After g_ui_built so pane-host callbacks resolve the
    // real focused pane.
    if (g_mode == .normal) restoreSession(ui_prefs.session);
}

/// Re-apply the saved panel states and reconnect saved remote panes.
/// Reconnects never prompt: a site is restored only when its auth is
/// provably silent (SSH agent, or a secret already in the keychain).
fn restoreSession(session: prefs_mod.SessionState) void {
    if (session.sidebar_collapsed) g_ui.root_split.collapse(0);
    if (!session.transfers_collapsed) g_ui.content_split.uncollapse(1);
    if (!session.inspector_collapsed) g_ui.inner_split.uncollapse(1);

    restorePaneSite(0, session.pane0_site, session.pane0_path);
    restorePaneSite(1, session.pane1_site, session.pane1_path);

    g_ui.browser.focusPane(if (session.focused_pane < 2) session.focused_pane else 0);
}

fn restorePaneSite(index: u32, site_id: u64, path: []const u8) void {
    if (site_id == item_mod.local_site_id) return; // local: handled at create
    const site = g_ui.sites.store.get(site_id) orelse return;
    if (!sitePersisted(site_id)) return;
    if (!reconnectIsPromptFree(site)) return;
    // Connects land in the active pane (docs/UX.md): focus the saved one.
    g_ui.browser.focusPane(index);
    g_ui.sites.connectAndList(site_id, if (path.len > 0) path else null);
}

/// True when reconnecting `site` cannot pose a credential prompt: SFTP
/// with agent auth, or any protocol whose secret loads silently from the
/// keychain (our own items never trigger an ACL dialog). key_file SFTP is
/// excluded — an encrypted key would prompt for its passphrase.
fn reconnectIsPromptFree(site: *const core_sites_mod.Site) bool {
    if (site.protocol == .sftp) {
        if (g_ui.sites.meta.get(site.id)) |meta| switch (meta.method) {
            .agent => return true,
            .key_file => return false,
            .password => {},
        };
    }
    if (site.account.len == 0) return false;
    var diag: diag_mod.Diagnostics = .{};
    const secret = g_core.cred_store.get(gpa, &diag, .{
        .protocol = switch (site.protocol) {
            .ftp => .ftp,
            .ftps => .ftps,
            .sftp => .sftp,
        },
        .host = site.host,
        .port = site.effectivePort(),
        .account = site.account,
    }) catch return false;
    cred_store_mod.freeSecret(gpa, secret);
    return true;
}

/// Saved-local-path probe through the core's local root (the same
/// coordinate space the panes list).
fn localDirExists(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    const rel: []const u8 = if (path.len == 1) "." else path[1..];
    const st = g_core.local_root.statFile(g_core.io, rel, .{}) catch return false;
    return st.kind == .directory;
}

/// PrefsController change listener: re-read the prefs and push everything
/// with a live-apply hook into the open views (density, date format,
/// confirm-delete, monospaced lists).
fn onPrefsChanged(_: ?*anyopaque) void {
    const ui_prefs = g_ui.prefs.uiPrefs();
    g_ui.browser.setDensity(densityFromPrefs(ui_prefs.density));
    g_ui.browser.setDateFormat(dateFormatFromPrefs(ui_prefs.date_format));
    g_ui.browser.setConfirmDelete(ui_prefs.confirm_delete);
    g_ui.browser.setMonospaceLists(ui_prefs.monospace_lists);
    g_ui.browser.setVimMode(ui_prefs.vim_mode);
}

/// InspectorController.ChmodStageHook → browser optimistic overlay.
fn onChmodStaged(_: ?*anyopaque, pane_token: bridge.PaneToken, path: []const u8, mode: u16) void {
    g_ui.browser.stageChmod(pane_token, path, mode);
}

// --- PaneHost: connects land in the ACTIVE pane (docs/UX.md) ----------------

fn paneHostActiveToken(_: ?*anyopaque) bridge.PaneToken {
    // Connects land in the right-hand remote pane by default (the
    // conventional local-left / remote-right layout) so browsing the local
    // pane and connecting never clobbers it. Exception: when the FOCUSED
    // pane is already remote, target it — that preserves switching servers
    // in place and remote↔remote workflows.
    if (!g_ui_built) return @as(bridge.PaneToken, 2); // panes[1].token()
    const active = g_ui.browser.activePane();
    if (active.isRemote()) return active.token();
    return g_ui.browser.remotePane().token();
}

fn paneHostConnecting(_: ?*anyopaque, pane_token: bridge.PaneToken, site_id: u64) void {
    // Bind the chip target (and swap a local pane to the remote role)
    // before status events start flowing.
    g_ui.browser.prepareRemoteBind(pane_token, site_id);
}

fn paneHostNavigate(_: ?*anyopaque, pane_token: bridge.PaneToken, site_id: u64, path: []const u8) void {
    g_ui.browser.bindRemoteToPane(pane_token, site_id, path);
}

/// factories.MetaLookup → the sites controller's AuthMetaStore (main
/// thread only; the returned key_path is borrowed for the call, which is
/// the MetaLookup contract — `make` copies it under the meta mutex).
fn sitesAuthLookup(ctx: ?*anyopaque, site_id: u64) ?factories.AuthChoice {
    const sites: *sites_mod.SitesController = @ptrCast(@alignCast(ctx.?));
    const entry = sites.meta.get(site_id) orelse return null;
    return .{
        .method = switch (entry.method) {
            .agent => .agent,
            .key_file => .key_file,
            .password => .password,
        },
        .key_path = entry.key_path,
    };
}

/// BrowserController.SelectionHook → InspectorController.setSelection.
/// Names/paths are borrowed for the call (the inspector copies into its
/// own arena), so one short-lived arena covers the whole conversion.
fn onPaneSelection(_: ?*anyopaque, pane: *browser_mod.BrowserPane) void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const selection = paneSelection(arena.allocator(), pane) catch return;
    g_ui.inspector.setSelection(selection) catch {};
}

fn paneSelection(
    arena: Allocator,
    pane: *browser_mod.BrowserPane,
) error{OutOfMemory}!inspector_mod.Selection {
    const site_id = pane.site orelse item_mod.local_site_id;
    const snap = pane.snapshot orelse
        return .{ .pane_token = pane.token(), .site_id = site_id };
    var items: std.ArrayList(inspector_mod.SelectedItem) = .empty;
    for (pane.table.selectedRows()) |row| {
        if (row >= pane.visible.items.len) continue;
        const slot = pane.visible.items[row];
        if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) continue;
        const entry = &snap.entries[slot];
        const full_path = path_mod.join(arena, snap.path, entry.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidPath => continue, // overlong/garbled name: skip the row
        };
        try items.append(arena, .{
            .name = entry.name,
            .path = full_path,
            .kind = switch (entry.kind) {
                .file => .file,
                .dir => .dir,
                .symlink => .symlink,
                .special, .unknown => .other,
            },
            .size = entry.size,
            .mode = if (entry.mode) |m| m & 0o777 else null,
        });
    }
    return .{
        .pane_token = pane.token(),
        .site_id = site_id,
        .items = items.items,
    };
}

fn revealInPane(_: ?*anyopaque, site_id: u64, dir: []const u8) void {
    // Either pane can host either role (active-pane connects): reveal in
    // whichever pane currently shows the item's site.
    for (g_ui.browser.panes, 0..) |pane, i| {
        const pane_site = pane.site orelse continue;
        if (pane_site != site_id) continue;
        if (site_id == item_mod.local_site_id and pane.role != .local) continue;
        pane.navigateTo(dir, .push);
        g_ui.browser.focusPane(@intCast(i));
        return;
    }
}

// --- command registry bindings ----------------------------------------------

fn bindCommands() void {
    const cmds = g_ui.commands;
    cmds.bind(.show_settings, g_ui.prefs, prefs_mod.PrefsController.showCommand);
    cmds.bind(.new_window, null, cmdNewWindow);
    cmds.bind(.connect_server, null, cmdConnectServer);
    cmds.bind(.disconnect, null, cmdDisconnect);
    cmds.bind(.new_folder, null, cmdNewFolder);
    cmds.bind(.rename_selection, null, cmdRename);
    cmds.bind(.delete_selection, null, cmdDelete);
    cmds.bind(.toggle_sidebar, null, cmdToggleSidebar);
    cmds.bind(.toggle_transfers, null, cmdToggleTransfers);
    cmds.bind(.toggle_inspector, null, cmdToggleInspector);
    cmds.bind(.density_comfortable, null, cmdDensityComfortable);
    cmds.bind(.density_compact, null, cmdDensityCompact);
    cmds.bind(.density_dense, null, cmdDensityDense);
    cmds.bind(.toggle_hidden, null, cmdToggleHidden);
    cmds.bind(.filter, null, cmdFilter);
    cmds.bind(.go_back, null, cmdGoBack);
    cmds.bind(.go_forward, null, cmdGoForward);
    cmds.bind(.go_enclosing, null, cmdGoUp);
    cmds.bind(.go_to_path, null, cmdGoToPath);
    cmds.bind(.refresh, null, cmdRefresh);
    cmds.bind(.open_selection, null, cmdOpenSelection);
    cmds.bind(.transfer_selection, null, cmdTransferSelection);
    cmds.bind(.permissions, null, cmdPermissions);
    cmds.bind(.pause_all_transfers, null, cmdPauseAll);
    cmds.bind(.resume_all_transfers, null, cmdResumeAll);
    cmds.bind(.retry_failed_transfers, null, cmdRetryFailed);
    cmds.bind(.clear_completed_transfers, null, cmdClearCompleted);
    cmds.bind(.cancel_active, null, cmdCancelActive);
    // M3.
    cmds.bind(.quick_look, null, cmdQuickLook);
    cmds.bind(.import_filezilla, null, cmdImportFileZilla);
    cmds.bind(.import_cyberduck, null, cmdImportCyberduck);
    cmds.bind(.palette_commands, g_ui.palette, palette_mod.PaletteController.showCommandsCommand);
    cmds.bind(.palette_paths, g_ui.palette, palette_mod.PaletteController.showPathsCommand);
    cmds.bind(.toggle_sync_browsing, null, cmdToggleSyncBrowsing);
    cmds.bind(.toggle_compare, null, cmdToggleCompare);
    cmds.bind(.toggle_vim, null, cmdToggleVim);
    g_ui.edit.register(cmds); // .edit_external (Cmd+E)
    // Override with the local-aware wrapper: local files open directly, remote
    // files go through the download/watch/upload session.
    cmds.bind(.edit_external, null, cmdEditExternal);
    g_ui.terminal.register(cmds); // .open_terminal + the four .copy_as_*
}

fn cmdNewWindow(_: ?*anyopaque) void {
    // M2 ships a single window; Cmd+N re-fronts it (tabs land later).
    g_ui.win.makeKeyAndOrderFront();
}
fn cmdConnectServer(_: ?*anyopaque) void {
    g_ui.sites.quickConnect();
}
fn cmdDisconnect(_: ?*anyopaque) void {
    g_ui.sites.disconnectActivePane();
}
fn cmdNewFolder(_: ?*anyopaque) void {
    g_ui.browser.newFolderSheet();
}
fn cmdRename(_: ?*anyopaque) void {
    g_ui.browser.renameSelection();
}
fn cmdDelete(_: ?*anyopaque) void {
    g_ui.browser.deleteSelection();
}
fn cmdToggleSidebar(_: ?*anyopaque) void {
    _ = g_ui.root_split.toggleCollapse(0);
}
fn cmdToggleTransfers(_: ?*anyopaque) void {
    _ = g_ui.transfers.togglePanel();
}
fn cmdToggleInspector(_: ?*anyopaque) void {
    _ = g_ui.inner_split.toggleCollapse(1);
}
fn setDensity(d: prefs_mod.Density) void {
    g_ui.prefs.setDensity(d); // the change listener pushes it into the views
}
fn cmdDensityComfortable(_: ?*anyopaque) void {
    setDensity(.comfortable);
}
fn cmdDensityCompact(_: ?*anyopaque) void {
    setDensity(.compact);
}
fn cmdDensityDense(_: ?*anyopaque) void {
    setDensity(.dense);
}
fn cmdToggleHidden(_: ?*anyopaque) void {
    g_ui.browser.toggleHiddenFiles();
}
fn cmdFilter(_: ?*anyopaque) void {
    g_ui.browser.showFilter();
}
fn cmdGoBack(_: ?*anyopaque) void {
    g_ui.browser.goBack();
}
fn cmdGoForward(_: ?*anyopaque) void {
    g_ui.browser.goForward();
}
fn cmdGoUp(_: ?*anyopaque) void {
    g_ui.browser.goUp();
}
fn cmdGoToPath(_: ?*anyopaque) void {
    g_ui.browser.goToPathSheet();
}
fn cmdRefresh(_: ?*anyopaque) void {
    g_ui.browser.refresh();
}
fn cmdOpenSelection(_: ?*anyopaque) void {
    g_ui.browser.openSelection();
}
fn cmdTransferSelection(_: ?*anyopaque) void {
    g_ui.browser.transferSelection();
}
fn cmdPermissions(_: ?*anyopaque) void {
    g_ui.inner_split.uncollapse(1);
}
fn cmdPauseAll(_: ?*anyopaque) void {
    g_core.pauseAllTransfers();
}
fn cmdResumeAll(_: ?*anyopaque) void {
    g_core.resumeAllTransfers() catch {};
}
fn cmdRetryFailed(_: ?*anyopaque) void {
    _ = g_core.requeueFailed();
}
fn cmdClearCompleted(_: ?*anyopaque) void {
    g_ui.transfers.clearCompleted();
}
fn cmdCancelActive(_: ?*anyopaque) void {
    g_ui.browser.cancelActiveListing();
    g_ui.transfers.cancelSelected();
}
fn cmdImportFileZilla(_: ?*anyopaque) void {
    g_ui.sites.importFileZilla();
}
fn cmdImportCyberduck(_: ?*anyopaque) void {
    g_ui.sites.importCyberduck();
}
fn cmdToggleSyncBrowsing(_: ?*anyopaque) void {
    g_ui.browser.toggleSyncBrowsing();
}
fn cmdToggleCompare(_: ?*anyopaque) void {
    g_ui.browser.toggleComparePanes();
}
fn cmdToggleVim(_: ?*anyopaque) void {
    // Persisted pref ("ui.vimMode"); the change listener pushes it into
    // the browser's keymap layer.
    g_ui.prefs.setVimMode(!g_ui.prefs.uiPrefs().vim_mode);
}
fn cmdQuickLook(_: ?*anyopaque) void {
    _ = quickLookPane(g_ui.browser.activePane());
}

// ---------------------------------------------------------------------------
// Quick Look (M3): Space (browser key hook) / Cmd+Y / File menu. Local
// selections preview in place; remote files go through the preview
// TempCache (download once per site/path/size/mtime via the normal queue).
// ---------------------------------------------------------------------------

/// Pending remote preview download: one slot (the most recent request
/// wins; an older in-flight download simply lands in the cache for next
/// time). Scalars + a path copy rebuild the TempCache key at completion.
const PreviewPending = struct {
    item: ?bridge.ItemId = null,
    site_id: u64 = 0,
    size: u64 = 0,
    mtime: i64 = 0,
    path_buf: [1024]u8 = undefined,
    path_len: usize = 0,

    fn key(p: *const PreviewPending) temp_cache.Key {
        return .{
            .site_id = p.site_id,
            .remote_path = p.path_buf[0..p.path_len],
            .size = p.size,
            .mtime = p.mtime,
        };
    }
};
var g_preview_pending: PreviewPending = .{};

fn onPaneSpace(_: ?*anyopaque, pane: *browser_mod.BrowserPane) bool {
    return quickLookPane(pane);
}

/// Returns true when the key/command was meaningfully consumed.
fn quickLookPane(pane: *browser_mod.BrowserPane) bool {
    if (quicklook.isVisible()) {
        g_ui.preview.close();
        return true;
    }
    const snap = pane.snapshot orelse return false;
    const site_id = pane.site orelse item_mod.local_site_id;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    if (site_id == item_mod.local_site_id) {
        var paths: std.ArrayList([]const u8) = .empty;
        for (pane.table.selectedRows()) |row| {
            if (row >= pane.visible.items.len) continue;
            const slot = pane.visible.items[row];
            if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) continue;
            const full = path_mod.join(arena, snap.path, snap.entries[slot].name) catch continue;
            paths.append(arena, full) catch return false;
        }
        if (paths.items.len == 0) return false;
        g_ui.preview.setItems(paths.items) catch return false;
        g_ui.preview.show();
        return true;
    }

    // Remote: preview the first selected FILE through the temp cache.
    const cache = if (g_ui.cache) |*c| c else return false;
    const row = pane.table.selectedRow() orelse return false;
    if (row >= pane.visible.items.len) return false;
    const slot = pane.visible.items[row];
    if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) return false;
    const entry = &snap.entries[slot];
    if (entry.kind != .file) return false;
    const full = path_mod.join(arena, snap.path, entry.name) catch return false;
    if (full.len > g_preview_pending.path_buf.len) return false;

    const key: temp_cache.Key = .{
        .site_id = site_id,
        .remote_path = full,
        .size = entry.size orelse 0,
        .mtime = entry.mtime orelse 0,
    };
    if (cache.hit(key)) |local| {
        g_ui.preview.setItems(&.{local}) catch return false;
        g_ui.preview.show();
        return true;
    }

    // Miss: download into the cache's staged path; the transfer_state
    // listener commits + shows when it lands.
    var stage_buf: [1280]u8 = undefined;
    const stage = cache.stagePath(key, &stage_buf) catch return false;
    const item = g_core.enqueueTransfer(.{
        .direction = .download,
        .src = .{ .site_id = site_id, .path = full },
        .dst = .{ .site_id = item_mod.local_site_id, .path = stage },
        .bytes_total = entry.size orelse 0,
    }) catch return false;
    g_preview_pending = .{
        .item = item,
        .site_id = site_id,
        .size = entry.size orelse 0,
        .mtime = entry.mtime orelse 0,
        .path_len = full.len,
    };
    @memcpy(g_preview_pending.path_buf[0..full.len], full);
    return true;
}

fn onPreviewTransferState(pending: *PreviewPending, e: relay.events.CoreEvent.TransferStateChange) void {
    const item = pending.item orelse return;
    if (e.item_id != item) return;
    switch (e.state) {
        .completed => {
            pending.item = null;
            const cache = if (g_ui.cache) |*c| c else return;
            const local = cache.commit(pending.key()) catch return;
            g_ui.preview.setItems(&.{local}) catch return;
            g_ui.preview.show();
        },
        .failed, .canceled => pending.item = null,
        else => {},
    }
}

// ---------------------------------------------------------------------------
// M3 glue: palette integration, edit-target provider, terminal context,
// pane context menu, palette frecency feed.
// ---------------------------------------------------------------------------

fn onPaneVisit(_: ?*anyopaque, site_id: u64, path: []const u8) void {
    g_ui.palette.recordVisit(site_id, path);
}

fn paletteSites(_: ?*anyopaque, sink: *palette_mod.SiteSink) void {
    var row: usize = 0;
    while (g_ui.sites.store.persistedAt(row)) |entry| : (row += 1) {
        sink.add(entry.site.id, sites_mod.siteLabel(entry.site));
    }
}

fn paletteConnect(_: ?*anyopaque, site_id: u64) void {
    g_ui.sites.connectAndList(site_id, null);
}

fn palettePaneState(_: ?*anyopaque) palette_mod.PaneState {
    const pane = g_ui.browser.activePane();
    const snap = pane.snapshot orelse return .{};
    return .{
        .site_id = pane.site orelse item_mod.local_site_id,
        .path = snap.path,
        .entries = snap.entries,
    };
}

/// Palette path jump. `other` = Cmd+Return (the inactive pane). Paths on
/// the pane's bound site navigate in place; local paths fall back to a
/// local-role pane; remote paths on an unbound site go through the normal
/// connect path (which may prompt — this is a user action, not a launch).
fn paletteNavigate(_: ?*anyopaque, other: bool, site_id: u64, path: []const u8) void {
    const target: u32 = if (other) g_ui.browser.focused ^ 1 else g_ui.browser.focused;
    const pane = g_ui.browser.panes[target];
    if (pane.site) |bound| {
        if (bound == site_id) {
            g_ui.browser.focusPane(target);
            pane.navigateTo(path, .push);
            return;
        }
    }
    if (site_id == item_mod.local_site_id) {
        const fallback: u32 = target ^ 1;
        const local = if (pane.role == .local) pane else g_ui.browser.panes[fallback];
        if (local.role != .local) return;
        g_ui.browser.focusPane(local.index);
        local.navigateTo(path, .push);
        return;
    }
    g_ui.browser.focusPane(target);
    g_ui.sites.connectAndList(site_id, path);
}

/// Cmd+E / "Edit with External Editor". Remote files go through the
/// download→watch→upload edit session; LOCAL files are already on disk, so
/// they open in the editor directly (the session machinery would otherwise
/// silently no-op on them — the reported bug).
fn cmdEditExternal(_: ?*anyopaque) void {
    const pane = g_ui.browser.activePane();
    const site_id = pane.site orelse return;
    if (site_id != item_mod.local_site_id) {
        g_ui.edit.editSelection();
        return;
    }
    const snap = pane.snapshot orelse return;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    for (pane.table.selectedRows()) |row| {
        if (row >= pane.visible.items.len) continue;
        const slot = pane.visible.items[row];
        if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) continue;
        const entry = &snap.entries[slot];
        if (entry.kind != .file) continue;
        const abs = std.fmt.bufPrint(&buf, "{s}/{s}", .{ snap.path, entry.name }) catch continue;
        _ = g_ui.edit.openLocalFile(abs);
    }
}

/// EditSessions TargetProvider: every selected FILE of the active pane
/// when it is bound to a remote site (local files have no session — they
/// are already on disk).
fn collectEditTargets(
    _: *anyopaque,
    arena: Allocator,
    out: *std.ArrayList(edit_mod.EditTarget),
) error{OutOfMemory}!void {
    const pane = g_ui.browser.activePane();
    const site_id = pane.site orelse return;
    if (site_id == item_mod.local_site_id) return;
    const snap = pane.snapshot orelse return;
    for (pane.table.selectedRows()) |row| {
        if (row >= pane.visible.items.len) continue;
        const slot = pane.visible.items[row];
        if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) continue;
        const entry = &snap.entries[slot];
        if (entry.kind != .file) continue;
        try out.append(arena, .{
            .site_id = site_id,
            .dir = snap.path,
            .name = entry.name,
            .size = entry.size,
            .mtime = entry.mtime,
        });
    }
}

/// terminal.ContextProvider: the active remote pane (or the other pane
/// when only it is remote); fills `buf` with copies of dir/selection.
fn terminalContext(_: ?*anyopaque, buf: []u8) ?terminal_mod.RemoteContext {
    if (!g_ui_built) return null;
    const pane = remoteBoundPane() orelse return null;
    const site_id = pane.site.?;
    const dir = pane.currentPath() orelse return null;

    var fba: std.heap.FixedBufferAllocator = .init(buf);
    const a = fba.allocator();
    var out: terminal_mod.RemoteContext = .{
        .site_id = site_id,
        .dir = a.dupe(u8, dir) catch return null,
    };
    const snap = pane.snapshot orelse return out;
    const row = pane.table.selectedRow() orelse return out;
    if (row >= pane.visible.items.len) return out;
    const slot = pane.visible.items[row];
    if (slot == browser_mod.virtual_new_folder_row or slot >= snap.entries.len) return out;
    const entry = &snap.entries[slot];
    out.selected_path = path_mod.join(a, snap.path, entry.name) catch return out;
    out.selected_is_dir = entry.kind == .dir;
    return out;
}

fn remoteBoundPane() ?*browser_mod.BrowserPane {
    const active = g_ui.browser.activePane();
    if (active.site) |site| {
        if (site != item_mod.local_site_id) return active;
    }
    const other = g_ui.browser.panes[active.index ^ 1];
    if (other.site) |site| {
        if (site != item_mod.local_site_id) return other;
    }
    return null;
}

/// Shared right-click menu for both pane tables (built once, lazily).
/// Commands act on the focused pane — dsContextMenu focuses the clicked
/// pane first.
fn paneContextMenu(_: ?*anyopaque, pane: *browser_mod.BrowserPane, row: ?usize) ?objc.c.id {
    _ = pane;
    _ = row;
    if (g_ui.pane_menu == null) {
        const copy_as = g_ui.terminal.copyAsMenuItems();
        const items = [_]menu_kit.Item{
            menu_kit.Item.call("Quick Look", g_ui.commands.menuCallback(.quick_look), "", .{}),
            menu_kit.Item.call("Edit with External Editor", g_ui.commands.menuCallback(.edit_external), "", .{}),
            menu_kit.Item.call("Open in Terminal", g_ui.commands.menuCallback(.open_terminal), "", .{}),
            .separator,
            menu_kit.Item.sub("Copy as", &copy_as),
            .separator,
            menu_kit.Item.call("Rename", g_ui.commands.menuCallback(.rename_selection), "", .{}),
            menu_kit.Item.call("Delete", g_ui.commands.menuCallback(.delete_selection), "", .{}),
            .separator,
            menu_kit.Item.call("Transfer Selection", g_ui.commands.menuCallback(.transfer_selection), "", .{}),
        };
        g_ui.pane_menu = menu_kit.buildContextMenu(g_ui.menu_reg, &items) catch null;
    }
    return if (g_ui.pane_menu) |m| m.value else null;
}

// --- toolbar ------------------------------------------------------------------

const toolbar_items = [_]toolbar_mod.ItemSpec{
    .{ .identifier = "RelayBack", .label = "Back", .symbol = "chevron.left", .tooltip = "Back", .action = tbBack },
    .{ .identifier = "RelayForward", .label = "Forward", .symbol = "chevron.right", .tooltip = "Forward", .action = tbForward },
    .{ .identifier = "RelayConnect", .label = "Connect", .symbol = "bolt.horizontal.circle", .tooltip = "Connect to Server (Cmd+K)", .action = tbConnect },
    .{ .identifier = "RelayView", .label = "View", .symbol = "slider.horizontal.3", .tooltip = "Row density", .menu_provider = tbViewMenu },
    toolbar_mod.flexibleSpace(),
    .{ .identifier = "RelayTransfers", .label = "Transfers", .symbol = "arrow.up.arrow.down.circle", .tooltip = "Toggle transfer panel (Cmd+J)", .action = tbTransfers },
    .{ .identifier = "RelayInfo", .label = "Info", .symbol = "info.circle", .tooltip = "Inspector (Cmd+I)", .action = tbInfo },
};

fn tbBack(_: *anyopaque) void {
    g_ui.browser.goBack();
}
fn tbForward(_: *anyopaque) void {
    g_ui.browser.goForward();
}
fn tbConnect(_: *anyopaque) void {
    g_ui.sites.quickConnect();
}
fn tbTransfers(_: *anyopaque) void {
    _ = g_ui.transfers.togglePanel();
}
fn tbInfo(_: *anyopaque) void {
    _ = g_ui.inner_split.toggleCollapse(1);
}

/// Toolbar 'View' popup (docs/UX.md toolbar sketch): density choices
/// routed through the same density commands as the View menu. Built once,
/// lazily (the toolbar delegate may materialize items before bindCommands
/// runs — dispatch is safely a no-op until then).
var g_view_menu: ?objc.Object = null;

fn tbViewMenu(_: *anyopaque) ?objc.c.id {
    if (g_view_menu == null) {
        const items = [_]menu_kit.Item{
            menu_kit.Item.call("Comfortable", g_ui.commands.menuCallback(.density_comfortable), "", .{}),
            menu_kit.Item.call("Compact", g_ui.commands.menuCallback(.density_compact), "", .{}),
            menu_kit.Item.call("Dense", g_ui.commands.menuCallback(.density_dense), "", .{}),
        };
        g_view_menu = menu_kit.buildContextMenu(g_ui.menu_reg, &items) catch null;
    }
    return if (g_view_menu) |menu| menu.value else null;
}

// ---------------------------------------------------------------------------
// Smoke mode — scripted end-to-end self test on dispatch_after ticks.
// ---------------------------------------------------------------------------
const smoke_tick_s: f64 = 0.05;
const smoke_timeout_ticks: u32 = 1200; // 60 s
const smoke_big_len: usize = 2 * 1024 * 1024;
const smoke_small_len: usize = 1024;
const smoke_top_files: usize = 45;
const smoke_sub_files: usize = 5;
/// 45 top-level files + the "sub" folder row.
const smoke_local_rows: usize = smoke_top_files + 1;
/// Engine items: 45 files + 1 folder + 5 folder children.
const smoke_local_items: usize = smoke_top_files + 1 + smoke_sub_files;
const smoke_sftp_file = "hello.bin";
/// Big enough that the rate-limited download spans several ~30 Hz engine
/// progress ticks (the "panel saw progress" assertion needs >= 1 event).
const smoke_sftp_len: usize = 4 * 1024 * 1024;
/// Edit-session round trip (M3): a "remote" (site 0) file outside the
/// transfer tree so the row-count assertions stay untouched.
const smoke_edit_file = "draft.txt";
const smoke_edit_v1 = "relay edit round trip v1\n";
const smoke_edit_v2 = "relay edit round trip v2 — saved locally\n";

fn smokeFail(step: []const u8, reason: []const u8) noreturn {
    std.debug.print("RELAY-SMOKE FAIL step={s} reason={s}\n", .{ step, reason });
    if (g_mode != .normal) g_smoke.cleanup();
    std.process.exit(1);
}

fn smokeFileByte(seed: usize, i: usize) u8 {
    return @truncate(i *% 131 +% seed *% 31 +% (i >> 11) +% 7);
}

const Smoke = struct {
    mode: Mode = .normal,
    threaded: std.Io.Threaded = undefined,
    io: std.Io = undefined,
    base: []u8 = &.{},
    src: []u8 = &.{},
    dst: []u8 = &.{},
    conf_dir: std.Io.Dir = undefined,
    fake_creds: relay.cred.fake.FakeStore = undefined,

    step: Step = .wait_window,
    ticks: u32 = 0,
    progress_events: u64 = 0,
    state_events: u64 = 0,
    listed_rows: usize = 0,
    expected_items: usize = smoke_local_items,
    bytes_verified: u64 = 0,

    // M3 surfaces (paths gpa-owned, allocated in setup).
    edit_dir: []u8 = &.{},
    edit_file: []u8 = &.{},
    edit_cache: []u8 = &.{},
    preview_cache: []u8 = &.{},
    edit_session: u64 = 0,

    // --smoke-sftp
    container_port: u16 = 0,
    container_name: [48]u8 = undefined,
    container_name_len: usize = 0,
    container_started: bool = false,

    const Step = enum {
        wait_window,
        wait_dst,
        wait_drained,
        verify,
        settings_open,
        settings_closed,
        sheet_open,
        sheet_close,
        palette_check,
        cache_check,
        edit_start,
        edit_watch,
        edit_upload,
        finish,
    };

    fn containerName(s: *const Smoke) []const u8 {
        return s.container_name[0..s.container_name_len];
    }

    fn localStartPath(s: *const Smoke) []const u8 {
        // --smoke: the left pane lists the generated tree; --smoke-sftp:
        // it sits in the (empty) download target.
        return if (s.mode == .smoke) s.src else s.dst;
    }

    fn editCachePath(s: *const Smoke) []const u8 {
        return s.edit_cache;
    }

    fn previewCachePath(s: *const Smoke) []const u8 {
        return s.preview_cache;
    }

    // ------------------------------------------------------------------ //
    // Pre-AppCore setup (tmp tree, config dir, container)

    fn setup(s: *Smoke, mode: Mode, environ: std.process.Environ) !void {
        s.* = .{ .mode = mode };
        s.threaded = .init(gpa, .{ .environ = environ });
        s.io = s.threaded.io();
        const io = s.io;

        const pid: u32 = @intCast(std.c.getpid());
        // /private/tmp, not the /tmp symlink: the edit-session step runs a
        // real FSEvents watcher and FSEvents wants the canonical path.
        s.base = try std.fmt.allocPrint(gpa, "/private/tmp/relay-smoke-{d}", .{pid});
        s.src = try std.fmt.allocPrint(gpa, "{s}/src", .{s.base});
        s.dst = try std.fmt.allocPrint(gpa, "{s}/dst", .{s.base});
        s.edit_dir = try std.fmt.allocPrint(gpa, "{s}/editsrc", .{s.base});
        s.edit_file = try std.fmt.allocPrint(gpa, "{s}/editsrc/{s}", .{ s.base, smoke_edit_file });
        s.edit_cache = try std.fmt.allocPrint(gpa, "{s}/editcache", .{s.base});
        s.preview_cache = try std.fmt.allocPrint(gpa, "{s}/previewcache", .{s.base});

        const cwd = std.Io.Dir.cwd();
        var path_buf: [512]u8 = undefined;
        try cwd.createDirPath(io, try std.fmt.bufPrint(&path_buf, "{s}/sub", .{s.src}));
        try cwd.createDirPath(io, s.dst);
        try cwd.createDirPath(io, s.edit_dir);
        try cwd.writeFile(io, .{ .sub_path = s.edit_file, .data = smoke_edit_v1 });
        s.conf_dir = try cwd.createDirPathOpen(io, try std.fmt.bufPrint(&path_buf, "{s}/conf", .{s.base}), .{});

        s.fake_creds = .init(gpa);

        switch (mode) {
            .smoke => try s.makeLocalTree(),
            .smoke_sftp => try s.setupSftp(),
            .normal => unreachable,
        }
    }

    fn makeLocalTree(s: *Smoke) !void {
        const io = s.io;
        const cwd = std.Io.Dir.cwd();
        const data = try gpa.alloc(u8, smoke_big_len);
        defer gpa.free(data);
        var path_buf: [512]u8 = undefined;
        for (0..smoke_top_files) |i| {
            const len: usize = if (i == 0) smoke_big_len else smoke_small_len;
            for (data[0..len], 0..) |*b, j| b.* = smokeFileByte(i, j);
            try cwd.writeFile(io, .{
                .sub_path = try std.fmt.bufPrint(&path_buf, "{s}/f{d:0>2}.dat", .{ s.src, i }),
                .data = data[0..len],
            });
        }
        for (0..smoke_sub_files) |i| {
            for (data[0..smoke_small_len], 0..) |*b, j| b.* = smokeFileByte(100 + i, j);
            try cwd.writeFile(io, .{
                .sub_path = try std.fmt.bufPrint(&path_buf, "{s}/sub/s{d}.dat", .{ s.src, i }),
                .data = data[0..smoke_small_len],
            });
        }
    }

    fn coreOptions(s: *Smoke) bridge.Options {
        return .{
            .pump = .gcd,
            .config_dir = s.conf_dir,
            .cred_store = s.fake_creds.credStore(),
            .factory_provider = if (s.mode == .smoke_sftp) sftp_factory.provider() else null,
        };
    }

    // ------------------------------------------------------------------ //
    // Driver

    fn begin(s: *Smoke) void {
        g_core.registerListener(.transfer_progress, s, onProgress) catch
            smokeFail("begin", "listener registration failed");
        g_core.registerListener(.transfer_state, s, onState) catch
            smokeFail("begin", "listener registration failed");
        // Cap throughput so the big file spans several engine progress
        // ticks (~30 Hz) — the "panel saw progress" assertion is then
        // deterministic instead of racing a local SSD copy.
        g_core.engine.setGlobalRateLimit(.download, 8 * 1024 * 1024);
        s.expected_items = if (s.mode == .smoke) smoke_local_items else 1;
        dispatch.after(smoke_tick_s, s, tick);
    }

    fn onProgress(s: *Smoke, _: relay.events.CoreEvent.TransferProgress) void {
        s.progress_events += 1;
    }

    fn onState(s: *Smoke, _: relay.events.CoreEvent.TransferStateChange) void {
        s.state_events += 1;
    }

    fn tick(s: *Smoke) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        s.ticks += 1;
        if (s.ticks > smoke_timeout_ticks)
            smokeFail(@tagName(s.step), "timed out");
        _ = s.runStep();
        if (s.step != .finish) dispatch.after(smoke_tick_s, s, tick);
    }

    fn runStep(s: *Smoke) bool {
        switch (s.step) {
            .wait_window => {
                // (a) window + all panes exist.
                if (!g_ui_built or !g_ui.win.isVisible()) return false;
                if (g_ui.sites.sidebarView() == null) smokeFail("wait_window", "no sidebar");
                if (g_ui.browser.view() == null) smokeFail("wait_window", "no browser split");
                if (g_ui.transfers.view() == null) smokeFail("wait_window", "no transfer panel");
                if (g_ui.inspector.view() == null) smokeFail("wait_window", "no inspector");
                // (b) local pane listed its start directory.
                const local = g_ui.browser.localPane();
                if (local.snapshot == null) return false;
                s.listed_rows = local.visible.items.len;
                if (s.mode == .smoke) {
                    if (s.listed_rows != smoke_local_rows) smokeFail("wait_window", "local listing row count mismatch");
                    g_ui.browser.bindRemote(item_mod.local_site_id, s.dst);
                } else {
                    // Connects land in the ACTIVE pane: focus the right
                    // pane first so the smoke keeps its remote-pane shape.
                    g_ui.browser.focusPane(1);
                    g_ui.sites.connectAndList(1, "/upload");
                }
                s.step = .wait_dst;
                return true;
            },
            .wait_dst => {
                const remote = g_ui.browser.remotePane();
                const snap = remote.snapshot orelse return false;
                if (s.mode == .smoke) {
                    if (!std.mem.eql(u8, snap.path, s.dst)) return false;
                    // (c) select everything in the local pane, transfer it.
                    const local = g_ui.browser.localPane();
                    const n = local.visible.items.len;
                    if (n > smoke_local_rows) smokeFail("wait_dst", "more rows than expected");
                    var rows_buf: [smoke_local_rows]usize = undefined;
                    for (0..n) |i| rows_buf[i] = i;
                    local.table.setSelectedRows(rows_buf[0..n]);
                    g_ui.browser.focusPane(0);
                } else {
                    if (!std.mem.eql(u8, snap.path, "/upload")) return false;
                    const row = s.findRemoteRow(smoke_sftp_file) orelse return false;
                    remote.table.setSelectedRows(&.{row});
                    g_ui.browser.focusPane(1);
                }
                if (!g_ui.commands.dispatch(.transfer_selection))
                    smokeFail("wait_dst", "transfer_selection command refused");
                s.step = .wait_drained;
                return true;
            },
            .wait_drained => {
                var arena: std.heap.ArenaAllocator = .init(gpa);
                defer arena.deinit();
                const snaps = g_core.queueSnapshot(arena.allocator()) catch return false;
                if (snaps.len < s.expected_items) return false;
                var all_done = true;
                for (snaps) |snap| {
                    switch (snap.state) {
                        .done => {},
                        .failed, .canceled => smokeFail("wait_drained", snap.failure_message),
                        else => all_done = false,
                    }
                }
                if (!all_done) return false;
                if (snaps.len != s.expected_items) smokeFail("wait_drained", "unexpected queue item count");
                s.step = .verify;
                return true;
            },
            .verify => {
                s.verifyBytes();
                // Transfer panel saw the queue: rows synced + progress flowed.
                const rows = g_ui.transfers.model.rows.items;
                if (rows.len != s.expected_items) smokeFail("verify", "transfer panel row count mismatch");
                for (rows) |row| {
                    if (row.state != .completed) smokeFail("verify", "transfer panel row not completed");
                }
                if (s.progress_events == 0) smokeFail("verify", "no transfer_progress events observed");
                if (s.state_events == 0) smokeFail("verify", "no transfer_state events observed");
                s.step = .settings_open;
                return true;
            },
            .settings_open => {
                // (d) settings window open + close.
                g_ui.prefs.show();
                if (!g_ui.prefs.built or !g_ui.prefs.win.isVisible())
                    smokeFail("settings_open", "settings window did not appear");
                g_ui.prefs.win.close();
                s.step = .settings_closed;
                return true;
            },
            .settings_closed => {
                if (g_ui.prefs.win.isVisible()) smokeFail("settings_closed", "settings window still visible");
                if (!g_ui.commands.dispatch(.connect_server))
                    smokeFail("settings_closed", "connect_server command refused");
                s.step = .sheet_open;
                return true;
            },
            .sheet_open => {
                const sheet = g_ui.win.attachedSheet() orelse
                    smokeFail("sheet_open", "Cmd+K sheet did not attach");
                g_ui.win.endSheet(sheet, windowkit.modal_response_cancel);
                s.step = .sheet_close;
                return true;
            },
            .sheet_close => {
                if (g_ui.win.attachedSheet() != null) return false;
                s.step = .palette_check;
                return true;
            },
            .palette_check => {
                // (e) command palette: open, fuzzy-query the command
                // registry vocabulary, execute the top hit, close.
                g_ui.palette.show(.commands);
                if (!g_ui.palette.isVisible()) smokeFail("palette_check", "palette did not open");
                g_ui.palette.setQuery("refresh") catch smokeFail("palette_check", "setQuery failed");
                if (g_ui.palette.resultCount() == 0) smokeFail("palette_check", "fuzzy query returned nothing");
                const top = g_ui.palette.resultAt(0) orelse smokeFail("palette_check", "no top result");
                if (top.kind != .command or top.command != .refresh)
                    smokeFail("palette_check", "top result is not the Refresh command");
                g_ui.palette.executeResult(0, false); // dispatches .refresh, closes
                if (g_ui.palette.executes != 1) smokeFail("palette_check", "execute did not run");
                if (g_ui.palette.isVisible()) smokeFail("palette_check", "palette still open after execute");
                g_ui.palette.show(.paths);
                if (!g_ui.palette.isVisible()) smokeFail("palette_check", "paths palette did not open");
                g_ui.palette.close();
                if (g_ui.palette.isVisible()) smokeFail("palette_check", "palette did not close");
                s.step = .cache_check;
                return true;
            },
            .cache_check => {
                // (f) preview TempCache put/get round trip.
                const cache = if (g_ui.cache) |*c| c else smokeFail("cache_check", "preview cache unavailable");
                var payload: [256]u8 = undefined;
                for (&payload, 0..) |*b, i| b.* = smokeFileByte(9, i);
                const key: temp_cache.Key = .{
                    .site_id = 42,
                    .remote_path = "/smoke/preview.bin",
                    .size = payload.len,
                    .mtime = 1718000000,
                };
                const stored = cache.put(key, &payload) catch smokeFail("cache_check", "put failed");
                const found = cache.hit(key) orelse smokeFail("cache_check", "miss after put");
                if (!std.mem.eql(u8, stored, found)) smokeFail("cache_check", "hit path differs from put path");
                const got = std.Io.Dir.cwd().readFileAlloc(s.io, found, gpa, .unlimited) catch
                    smokeFail("cache_check", "cached file unreadable");
                defer gpa.free(got);
                if (!std.mem.eql(u8, got, &payload)) smokeFail("cache_check", "cached bytes differ");
                if (cache.entryCount() != 1) smokeFail("cache_check", "unexpected entry count");
                s.step = .edit_start;
                return true;
            },
            .edit_start => {
                // (g) local edit-session round trip over the REAL pipeline:
                // queue download → FSEvents watch → save → conflict re-stat
                // (unchanged mtime ⇒ silent upload) → queue upload →
                // baseline refresh. Baseline mtime in the same seconds the
                // local VFS reports.
                const st = std.Io.Dir.cwd().statFile(s.io, s.edit_file, .{}) catch
                    smokeFail("edit_start", "edit source missing");
                s.edit_session = g_ui.edit.editTarget(.{
                    .site_id = item_mod.local_site_id,
                    .dir = s.edit_dir,
                    .name = smoke_edit_file,
                    .size = st.size,
                    .mtime = st.mtime.toSeconds(),
                }) catch smokeFail("edit_start", "editTarget refused");
                s.step = .edit_watch;
                return true;
            },
            .edit_watch => {
                const state = g_ui.edit.sessionState(s.edit_session) orelse
                    smokeFail("edit_watch", "session vanished (download failed?)");
                if (state != .watching) return false; // download in flight
                const local = g_ui.edit.sessionLocalPath(s.edit_session) orelse
                    smokeFail("edit_watch", "no session local path");
                const got = std.Io.Dir.cwd().readFileAlloc(s.io, local, gpa, .unlimited) catch
                    smokeFail("edit_watch", "temp copy unreadable");
                defer gpa.free(got);
                if (!std.mem.eql(u8, got, smoke_edit_v1)) smokeFail("edit_watch", "temp copy bytes differ");
                // Save: the live FSEvents watcher must notice this write —
                // no manual noteLocalChange nudge.
                std.Io.Dir.cwd().writeFile(s.io, .{ .sub_path = local, .data = smoke_edit_v2 }) catch
                    smokeFail("edit_watch", "could not modify temp copy");
                s.step = .edit_upload;
                return true;
            },
            .edit_upload => {
                if (g_ui.edit.conflicts_seen != 0)
                    smokeFail("edit_upload", "conflict flagged on an unchanged mtime");
                if (g_ui.edit.uploads_enqueued == 0) return false; // watch → re-stat pending
                const state = g_ui.edit.sessionState(s.edit_session) orelse
                    smokeFail("edit_upload", "session vanished (upload failed?)");
                if (state != .watching) return false; // upload/refresh in flight
                const got = std.Io.Dir.cwd().readFileAlloc(s.io, s.edit_file, gpa, .unlimited) catch
                    smokeFail("edit_upload", "remote file unreadable");
                defer gpa.free(got);
                if (!std.mem.eql(u8, got, smoke_edit_v2))
                    smokeFail("edit_upload", "remote file does not carry the saved bytes");
                g_ui.edit.endSession(s.edit_session);
                if (g_ui.edit.sessionCount() != 0) smokeFail("edit_upload", "session not ended");
                if (g_ui.edit.sessionLocalPath(s.edit_session) != null)
                    smokeFail("edit_upload", "session table still has the entry");
                s.step = .finish;
                s.pass();
                return true;
            },
            .finish => return true,
        }
    }

    fn findRemoteRow(s: *Smoke, name: []const u8) ?usize {
        _ = s;
        const pane = g_ui.browser.remotePane();
        const snap = pane.snapshot orelse return null;
        for (pane.visible.items, 0..) |slot, row| {
            if (slot < snap.entries.len and std.mem.eql(u8, snap.entries[slot].name, name))
                return row;
        }
        return null;
    }

    fn verifyBytes(s: *Smoke) void {
        const io = s.io;
        const cwd = std.Io.Dir.cwd();
        var path_buf: [512]u8 = undefined;
        if (s.mode == .smoke) {
            for (0..smoke_top_files) |i| {
                const p = std.fmt.bufPrint(&path_buf, "{s}/f{d:0>2}.dat", .{ s.dst, i }) catch unreachable;
                s.verifyOne(cwd, io, p, i, if (i == 0) smoke_big_len else smoke_small_len);
            }
            for (0..smoke_sub_files) |i| {
                const p = std.fmt.bufPrint(&path_buf, "{s}/sub/s{d}.dat", .{ s.dst, i }) catch unreachable;
                s.verifyOne(cwd, io, p, 100 + i, smoke_small_len);
            }
        } else {
            const p = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ s.dst, smoke_sftp_file }) catch unreachable;
            s.verifyOne(cwd, io, p, 0, smoke_sftp_len);
        }
    }

    fn verifyOne(s: *Smoke, dir: std.Io.Dir, io: std.Io, path: []const u8, seed: usize, expected_len: usize) void {
        const got = dir.readFileAlloc(io, path, gpa, .unlimited) catch
            smokeFail("verify", "destination file missing");
        defer gpa.free(got);
        if (got.len != expected_len) smokeFail("verify", "destination size mismatch");
        for (got, 0..) |b, j| {
            if (b != smokeFileByte(seed, j)) smokeFail("verify", "destination bytes differ");
        }
        s.bytes_verified += got.len;
    }

    fn pass(s: *Smoke) void {
        const label: []const u8 = if (s.mode == .smoke) "RELAY-SMOKE" else "RELAY-SMOKE-SFTP";
        std.debug.print(
            "{s} PASS rows={d} transfers={d} bytes={d} progress_events={d} " ++
                "state_events={d} drains={d} events={d} cmds={d} " ++
                "pal_exec={d} edit_uploads={d} ticks={d}\n",
            .{
                label,                      s.listed_rows,
                s.expected_items,           s.bytes_verified,
                s.progress_events,          s.state_events,
                g_core.drains,              g_core.events_dispatched,
                g_ui.commands.dispatched,   g_ui.palette.executes,
                g_ui.edit.uploads_enqueued, s.ticks,
            },
        );
        g_ui.app.terminate(); // graceful: delegate shuts the core down
        std.process.exit(0); // terminate returned (sheet edge case): exit hard
    }

    fn cleanup(s: *Smoke) void {
        if (s.container_started) {
            _ = std.process.run(gpa, s.io, .{
                .argv = &.{ "docker", "rm", "-f", s.containerName() },
            }) catch {};
            s.container_started = false;
        }
        if (s.base.len > 0) std.Io.Dir.cwd().deleteTree(s.io, s.base) catch {};
    }

    // ------------------------------------------------------------------ //
    // --smoke-sftp plumbing

    fn dockerOk(s: *Smoke, argv: []const []const u8) bool {
        const res = std.process.run(gpa, s.io, .{ .argv = argv }) catch return false;
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        return switch (res.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    fn setupSftp(s: *Smoke) !void {
        const io = s.io;
        if (!s.dockerOk(&.{ "docker", "version", "--format", "{{.Server.Version}}" })) {
            std.debug.print("RELAY-SMOKE-SFTP SKIP no docker daemon\n", .{});
            s.cleanup();
            std.process.exit(0);
        }
        const image = "atmoz/sftp:alpine";
        if (!s.dockerOk(&.{ "docker", "image", "inspect", image })) {
            if (!s.dockerOk(&.{ "docker", "pull", image })) {
                std.debug.print("RELAY-SMOKE-SFTP SKIP image unavailable\n", .{});
                s.cleanup();
                std.process.exit(0);
            }
        }

        const pid: u32 = @intCast(std.c.getpid());
        s.container_port = 20000 + @as(u16, @intCast(pid % 30000));
        s.container_name_len = (std.fmt.bufPrint(&s.container_name, "relay-smoke-sftp-{d}", .{s.container_port}) catch unreachable).len;

        var port_buf: [40]u8 = undefined;
        const port_map = std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}:22", .{s.container_port}) catch unreachable;
        if (!s.dockerOk(&.{
            "docker", "run",    "-d",  "--rm",                          "--name", s.containerName(),
            "-p",     port_map, image, "relay:relaypw:1001:100:upload",
        })) return error.ContainerStartFailed;
        s.container_started = true;
        // TTL self-destruct so a crashed smoke never leaks the container.
        _ = s.dockerOk(&.{ "docker", "exec", "-d", s.containerName(), "sh", "-c", "sleep 600; kill 1" });

        if (!s.waitSshReady()) return error.SshdNeverReady;

        // Provision the download payload: generate locally, docker cp in.
        const data = try gpa.alloc(u8, smoke_sftp_len);
        defer gpa.free(data);
        for (data, 0..) |*b, j| b.* = smokeFileByte(0, j);
        var path_buf: [512]u8 = undefined;
        const local_payload = try std.fmt.bufPrint(&path_buf, "{s}/payload.bin", .{s.base});
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = local_payload, .data = data });
        var cp_buf: [128]u8 = undefined;
        const cp_dst = std.fmt.bufPrint(&cp_buf, "{s}:/home/relay/upload/{s}", .{ s.containerName(), smoke_sftp_file }) catch unreachable;
        if (!s.dockerOk(&.{ "docker", "cp", local_payload, cp_dst })) return error.ProvisionFailed;
        if (!s.dockerOk(&.{
            "docker",                                                "exec", s.containerName(), "sh", "-ec",
            "chown 1001:100 /home/relay/upload/" ++ smoke_sftp_file,
        })) return error.ProvisionFailed;

        // Site list + credential for the GUI connect path.
        var zon_buf: [512]u8 = undefined;
        const zon = std.fmt.bufPrint(&zon_buf,
            \\.{{
            \\    .schema_version = 1,
            \\    .sites = .{{ .{{
            \\        .id = 1,
            \\        .name = "smoke-sftp",
            \\        .protocol = .sftp,
            \\        .host = "127.0.0.1",
            \\        .port = {d},
            \\        .account = "relay",
            \\        .initial_remote_path = "/upload",
            \\    }} }},
            \\}}
            \\
        , .{s.container_port}) catch unreachable;
        try s.conf_dir.writeFile(io, .{ .sub_path = bridge.sites_file, .data = zon });

        var diag: diag_mod.Diagnostics = .{};
        try s.fake_creds.set(&diag, .{
            .protocol = .sftp,
            .host = "127.0.0.1",
            .port = s.container_port,
            .account = "relay",
        }, "relaypw");
    }

    /// Docker's proxy accepts TCP before sshd listens; wait for the banner.
    fn waitSshReady(s: *Smoke) bool {
        const io = s.io;
        for (0..150) |_| {
            if (s.sshBannerVisible()) return true;
            io.sleep(.fromMilliseconds(200), .awake) catch return false;
        }
        return false;
    }

    fn sshBannerVisible(s: *Smoke) bool {
        const io = s.io;
        const addr = std.Io.net.IpAddress.resolve(io, "127.0.0.1", s.container_port) catch return false;
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
};

// ---------------------------------------------------------------------------
// Smoke SFTP connect factory: the full dial → handshake → password-auth →
// SFTP-subsystem sequence over the real engines (libssh2 + poll.zig).
// Host keys are accepted blindly — this factory is injected ONLY in
// --smoke-sftp (throwaway container); normal runs get the production
// factories (factories.zig: known_hosts + agent/key/password + prompts).
// ---------------------------------------------------------------------------
const sftp_factory = struct {
    var ctx_storage: u8 = 0;

    fn provider() bridge.FactoryProvider {
        return .{ .ctx = @ptrCast(&ctx_storage), .makeFn = make };
    }

    fn make(_: *anyopaque, site: *const relay.sites.Site) site_pool_mod.ConnFactory {
        _ = site;
        return .{ .ctx = @ptrCast(&ctx_storage), .connectFn = connect };
    }

    fn acceptHostKey(_: *anyopaque, _: *const session_mod.HostKeyInfo) session_mod.HostKeyDecision {
        return .accept;
    }

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

    const State = struct {
        stream: std.Io.net.Stream,
        session: session_mod.SshSession,
        client: sftp_client_mod.SftpClient,
    };

    fn connect(
        _: *anyopaque,
        io: std.Io,
        cancel: *CancelToken,
        diag: *diag_mod.Diagnostics,
        site: *const site_pool_mod.SiteConfig,
        role: site_pool_mod.Role,
    ) vfs_mod.Error!site_pool_mod.Conn {
        _ = role;
        const creds = if (site.creds) |cp| try cp.fetch(diag) else site_pool_mod.Credentials{};

        const addr = std.Io.net.IpAddress.resolve(io, site.host, site.port) catch {
            diag.set(.transient, 0, "could not resolve {s}", .{site.host});
            return error.Unexpected;
        };
        const stream = addr.connect(io, .{ .mode = .stream }) catch {
            diag.set(.transient, 0, "could not connect to {s}:{d}", .{ site.host, site.port });
            return error.ConnectionLost;
        };
        var stream_owned = true;
        defer if (stream_owned) stream.close(io);

        const state = try gpa.create(State);
        errdefer gpa.destroy(state);
        state.stream = stream;

        state.session = session_mod.SshSession.init(
            gpa,
            io,
            stream.socket.handle,
            site.host,
            site.port,
            cancel,
            diag,
            .{ .context = @ptrCast(&ctx_storage), .verifyHostKey = acceptHostKey },
        ) catch |err| return mapSessionError(err);
        errdefer state.session.deinit();

        state.session.authenticate(cancel, diag, .{
            .username = creds.user,
            .try_agent = false,
            .password = creds.secret,
        }) catch |err| return mapSessionError(err);

        state.client = try sftp_client_mod.SftpClient.init(&state.session, cancel, diag);

        stream_owned = false; // the Conn owns everything from here
        return .{
            .engine = .{ .sftp = &state.client },
            .ctx = @ptrCast(state),
            .vtable = &conn_vtable,
        };
    }

    const conn_vtable: site_pool_mod.Conn.VTable = .{
        .noop = connNoop,
        .alive = connAlive,
        .close = connClose,
    };

    fn stateOf(ctx: *anyopaque) *State {
        return @ptrCast(@alignCast(ctx));
    }

    fn connNoop(ctx: *anyopaque, _: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics) vfs_mod.Error!void {
        var buf: [1024]u8 = undefined;
        _ = try stateOf(ctx).client.realpath(cancel, diag, ".", &buf);
    }

    fn connAlive(_: *anyopaque) bool {
        return true; // keepalive NOOPs discover drops
    }

    fn connClose(ctx: *anyopaque, io: std.Io) void {
        const state = stateOf(ctx);
        state.client.deinit();
        state.session.deinit();
        state.stream.close(io);
        gpa.destroy(state);
    }
};

// ---------------------------------------------------------------------------
// Tests (headless)
// ---------------------------------------------------------------------------
const testing = std.testing;

test parseMode {
    try testing.expectEqual(@as(?Mode, .smoke), parseMode("--smoke"));
    try testing.expectEqual(@as(?Mode, .smoke_sftp), parseMode("--smoke-sftp"));
    try testing.expectEqual(@as(?Mode, null), parseMode("--frobnicate"));
}

test "smoke file pattern is deterministic and seed-sensitive" {
    try testing.expectEqual(smokeFileByte(3, 17), smokeFileByte(3, 17));
    try testing.expect(smokeFileByte(0, 0) != smokeFileByte(1, 0) or
        smokeFileByte(0, 1) != smokeFileByte(1, 1));
}

test "density mapping covers every prefs density" {
    try testing.expectEqual(table_source.Density.comfortable, densityFromPrefs(.comfortable));
    try testing.expectEqual(table_source.Density.compact, densityFromPrefs(.compact));
    try testing.expectEqual(table_source.Density.dense, densityFromPrefs(.dense));
}

test "date-format mapping covers every prefs format" {
    try testing.expectEqual(browser_mod.DateFormat.iso, dateFormatFromPrefs(.iso));
    try testing.expectEqual(browser_mod.DateFormat.relative, dateFormatFromPrefs(.relative));
}

test {
    _ = bridge;
    _ = factories;
    _ = app_delegate;
    _ = controllers.browser;
    _ = controllers.sites;
    _ = controllers.transfers;
    _ = controllers.transcript;
    _ = controllers.prefs;
    _ = controllers.inspector;
    _ = controllers.edit_sessions;
    _ = controllers.palette;
    _ = controllers.terminal;
    _ = fuzzy;
    _ = temp_cache;
}

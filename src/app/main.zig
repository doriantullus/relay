//! Relay — native macOS FTP/FTPS/SFTP client. M2 entry point.
//!
//! Boot sequence (docs/UX.md, docs/ARCHITECTURE.md):
//!   AppCore (relay_core behind src/app/bridge.zig) → NSApplication +
//!   RelayAppDelegate → applicationDidFinishLaunching builds the window:
//!   toolbar; sidebar | [local pane | remote pane | inspector] | bottom
//!   panel (NSSplitViews with autosave names); all controllers; menu bar
//!   bound through the CommandRegistry → [NSApp run].
//!
//! Self-test modes (exercised by `zig build run -- --smoke`):
//!   --smoke       scripted local→local transfer of a 50-file tmp tree
//!                 through the real GUI path; asserts byte-identical
//!                 copies, transfer-panel progress, settings window and
//!                 the Cmd+K sheet; prints RELAY-SMOKE PASS and exits 0.
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

const item_mod = relay.queue.item;
const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;
const site_pool_mod = relay.pool.site_pool;
const session_mod = relay.sftp.session;
const sftp_client_mod = relay.sftp.client;
const diag_mod = relay.diag;
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

fn onWillTerminate(_: ?*anyopaque) void {
    if (g_mode != .normal) g_smoke.cleanup();
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

    g_ui.browser = try browser_mod.BrowserController.create(gpa, core, g_ui.win, .{
        .initial_local_path = if (g_mode != .normal) g_smoke.localStartPath() else null,
        .density = densityFromPrefs(g_ui.prefs.uiPrefs().density),
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

    if (g_mode == .normal) {
        // Production FTP/FTPS/SFTP connect factories: known_hosts + prompt
        // wiring through the bridge, per-site auth meta from the sites
        // controller (--smoke-sftp injects its own factory at AppCore init).
        g_factories = try factories.Factories.create(gpa, core);
        g_factories.meta_lookup = .{ .ctx = g_ui.sites, .get = sitesAuthLookup };
        core.setFactoryProvider(g_factories.provider());
    }

    // Settings-window changes live-apply to open views (the View-menu
    // density path already pushes directly; this covers the Settings
    // radios). Prefs without a live consumer (date format, monospace
    // lists, confirm-delete) only persist for now.
    try g_ui.prefs.addChangeListener(null, onPrefsChanged);

    // Inspector feed: focused-pane selection changes, snapshot swaps and
    // focus switches land in the Get Info panel (docs/UX.md).
    g_ui.browser.setSelectionHook(.{ .ctx = null, .notify = onPaneSelection });

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
}

/// PrefsController change listener: re-read the prefs and push everything
/// with a live-apply hook into the open views (currently just density).
fn onPrefsChanged(_: ?*anyopaque) void {
    g_ui.browser.setDensity(densityFromPrefs(g_ui.prefs.uiPrefs().density));
}

// --- PaneHost: connects land in the remote pane (M2: panes[1]) --------------

fn paneHostActiveToken(_: ?*anyopaque) bridge.PaneToken {
    return @as(bridge.PaneToken, g_ui.browser.remotePane().index) + 1;
}

fn paneHostConnecting(_: ?*anyopaque, _: bridge.PaneToken, site_id: u64) void {
    // Bind the chip target before status events start flowing.
    const pane = g_ui.browser.remotePane();
    pane.site = site_id;
    pane.chip = null;
}

fn paneHostNavigate(_: ?*anyopaque, _: bridge.PaneToken, site_id: u64, path: []const u8) void {
    g_ui.browser.bindRemote(site_id, path);
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
    if (site_id == item_mod.local_site_id) {
        g_ui.browser.localPane().navigateTo(dir, .push);
        g_ui.browser.focusPane(0);
    } else if (g_ui.browser.remotePane().site == site_id) {
        g_ui.browser.remotePane().navigateTo(dir, .push);
        g_ui.browser.focusPane(1);
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

// --- toolbar ------------------------------------------------------------------

const toolbar_items = [_]toolbar_mod.ItemSpec{
    .{ .identifier = "RelayBack", .label = "Back", .symbol = "chevron.left", .tooltip = "Back", .action = tbBack },
    .{ .identifier = "RelayForward", .label = "Forward", .symbol = "chevron.right", .tooltip = "Forward", .action = tbForward },
    .{ .identifier = "RelayConnect", .label = "Connect", .symbol = "bolt.horizontal.circle", .tooltip = "Connect to Server (Cmd+K)", .action = tbConnect },
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

    // ------------------------------------------------------------------ //
    // Pre-AppCore setup (tmp tree, config dir, container)

    fn setup(s: *Smoke, mode: Mode, environ: std.process.Environ) !void {
        s.* = .{ .mode = mode };
        s.threaded = .init(gpa, .{ .environ = environ });
        s.io = s.threaded.io();
        const io = s.io;

        const pid: u32 = @intCast(std.c.getpid());
        s.base = try std.fmt.allocPrint(gpa, "/tmp/relay-smoke-{d}", .{pid});
        s.src = try std.fmt.allocPrint(gpa, "{s}/src", .{s.base});
        s.dst = try std.fmt.allocPrint(gpa, "{s}/dst", .{s.base});

        const cwd = std.Io.Dir.cwd();
        var path_buf: [512]u8 = undefined;
        try cwd.createDirPath(io, try std.fmt.bufPrint(&path_buf, "{s}/sub", .{s.src}));
        try cwd.createDirPath(io, s.dst);
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
                "state_events={d} drains={d} events={d} cmds={d} ticks={d}\n",
            .{
                label,            s.listed_rows,            s.expected_items,
                s.bytes_verified, s.progress_events,        s.state_events,
                g_core.drains,    g_core.events_dispatched, g_ui.commands.dispatched,
                s.ticks,
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

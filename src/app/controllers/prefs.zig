//! prefs — three M2 surfaces live here:
//!
//!  1. The menu-bar TREE DEFINITION (`menu_bar` + `settings_leaf`) as pure
//!     data, following the docs/UX.md menu table. Phase 3 installs it via
//!     `installMenuBar`; every app action dispatches through the
//!     `CommandRegistry` (named command → callback), so controllers bind
//!     handlers without ever editing the tree. Standard Edit/Close/Help
//!     items stay first-responder selectors (nil target).
//!  2. `CommandRegistry` — Command → handler table with a validation hook:
//!     an app-state predicate consulted at dispatch time, so disabled
//!     commands no-op for menus AND key equivalents alike.
//!  3. `PrefsController` — the Settings window (Cmd+,) with General /
//!     Transfers / Appearance groups. Every change persists IMMEDIATELY
//!     (core knobs via `AppCore.saveSettings` → settings.zon, UI-only knobs
//!     via `ui.zon` written with settings.zig's crash-safe atomic writer)
//!     and fires the prefs-changed listeners so browser/transfers re-render.
//!
//! Phase 3 wiring sketch:
//!     const commands = try prefs.CommandRegistry.create(gpa);
//!     const menu_reg = try mac.appkit.menu.Registry.create(gpa);
//!     try prefs.installMenuBar(gpa, menu_reg, commands);
//!     const pc = try prefs.PrefsController.create(gpa, core);
//!     commands.bind(.show_settings, pc, prefs.PrefsController.showCommand);
//!     try pc.addChangeListener(browser, BrowserController.onPrefsChanged);

const std = @import("std");
const mac = @import("relay_mac");
const relay = @import("relay_core");
const bridge = @import("relay_ui").bridge;

const objc = mac.objc;
const foundation = mac.foundation;
const runtime = mac.runtime;
const menu = mac.appkit.menu;
const windowkit = mac.appkit.window;
const panels = mac.appkit.panels;
const settings_mod = relay.settings;

const Allocator = std.mem.Allocator;
const c = foundation.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;

// ---------------------------------------------------------------------------
// Named commands: the vocabulary menu items dispatch through. Phase 3 binds
// controllers to these ids; the tree below never needs editing for that.
// ---------------------------------------------------------------------------

pub const Command = enum {
    // App
    show_settings,
    // File
    new_window,
    connect_server,
    disconnect,
    /// Disconnect every connected site (no shortcut; palette picks it up).
    disconnect_all,
    new_folder,
    rename_selection,
    delete_selection,
    /// Edit-in-external-editor ("file.editExternal", Cmd+E); bound by
    /// controllers/edit_sessions.zig's register().
    edit_external,
    /// Quick Look the selection (Cmd+Y here; plain Space rides the browser
    /// key hook). Bound by main.zig to the relay_mac quicklook panel.
    quick_look,
    /// File ▸ Import — controllers/sites.zig importers (M3).
    import_filezilla,
    import_cyberduck,
    // Edit ▸ Copy as — controllers/terminal.zig's register() binds these.
    copy_as_scp,
    copy_as_rsync,
    copy_as_sftp,
    copy_as_curl,
    // View
    toggle_sidebar,
    toggle_transfers,
    toggle_inspector,
    density_comfortable,
    density_compact,
    density_dense,
    toggle_hidden,
    filter,
    /// Synchronized browsing ("view.syncBrowsing", Cmd+Shift+B).
    toggle_sync_browsing,
    /// Directory comparison ("view.comparePanes", Cmd+Shift+D).
    toggle_compare,
    /// Vim keymap layer (pref "ui.vimMode"; no key equivalent).
    toggle_vim,
    // Go
    go_back,
    go_forward,
    go_enclosing,
    go_to_path,
    refresh,
    /// Command palette ("palette.commands", Cmd+Shift+P) and the path jump
    /// ("palette.paths", Cmd+P); bound by main.zig to PaletteController.
    palette_commands,
    palette_paths,
    // Server
    open_selection,
    transfer_selection,
    permissions,
    /// "server.openTerminal" (Cmd+Opt+T); controllers/terminal.zig.
    open_terminal,
    // Transfers
    pause_all_transfers,
    resume_all_transfers,
    retry_failed_transfers,
    clear_completed_transfers,
    cancel_active,
    // Tabs (Phase B)
    new_tab,
    close_tab,
    next_tab,
    prev_tab,
    // Jump to tab N by number (Cmd+1…Cmd+9). Cmd+9 is the last tab, matching
    // Safari/Chrome; the rest are 1-based positions.
    select_tab_1,
    select_tab_2,
    select_tab_3,
    select_tab_4,
    select_tab_5,
    select_tab_6,
    select_tab_7,
    select_tab_8,
    select_tab_last,
};

/// Command → callback registry with a validation hook. Heap-pinned
/// (`create`) because the per-command trampolines hand stable pointers to
/// NSMenuItem callbacks. Main thread only (like all UI state).
pub const CommandRegistry = struct {
    pub const Handler = struct {
        ctx: ?*anyopaque = null,
        f: ?*const fn (?*anyopaque) void = null,
    };

    /// The menu validation hook: an app-state predicate deciding whether a
    /// command is currently enabled. Consulted on every dispatch, so menus
    /// AND their key equivalents both no-op while disabled.
    pub const Validator = struct {
        ctx: ?*anyopaque = null,
        f: *const fn (?*anyopaque, Command) bool,
    };

    const Trampoline = struct { reg: *CommandRegistry, cmd: Command };

    gpa: Allocator,
    handlers: std.enums.EnumArray(Command, Handler),
    trampolines: std.enums.EnumArray(Command, Trampoline),
    validator: ?Validator = null,
    /// Observability for the phase-3 smoke.
    dispatched: u64 = 0,

    pub fn create(gpa: Allocator) error{OutOfMemory}!*CommandRegistry {
        const self = try gpa.create(CommandRegistry);
        self.* = .{
            .gpa = gpa,
            .handlers = std.enums.EnumArray(Command, Handler).initFill(.{}),
            .trampolines = undefined,
        };
        for (std.enums.values(Command)) |cmd| {
            self.trampolines.set(cmd, .{ .reg = self, .cmd = cmd });
        }
        return self;
    }

    pub fn destroy(self: *CommandRegistry) void {
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Bind (or rebind) the handler for `cmd`. `ctx` must outlive the menus.
    pub fn bind(
        self: *CommandRegistry,
        cmd: Command,
        ctx: ?*anyopaque,
        f: *const fn (?*anyopaque) void,
    ) void {
        self.handlers.set(cmd, .{ .ctx = ctx, .f = f });
    }

    pub fn setValidator(self: *CommandRegistry, validator: ?Validator) void {
        self.validator = validator;
    }

    /// True when no validator is installed (everything enabled by default).
    pub fn isEnabled(self: *const CommandRegistry, cmd: Command) bool {
        const v = self.validator orelse return true;
        return v.f(v.ctx, cmd);
    }

    /// Run the handler for `cmd`. Returns false when the command is
    /// disabled by the validator or no handler is bound.
    pub fn dispatch(self: *CommandRegistry, cmd: Command) bool {
        if (!self.isEnabled(cmd)) return false;
        const handler = self.handlers.get(cmd);
        const f = handler.f orelse return false;
        self.dispatched += 1;
        f(handler.ctx);
        return true;
    }

    /// The menu.Callback that routes an NSMenuItem to `cmd`. The returned
    /// ctx points into this registry; it stays valid for the registry's
    /// lifetime, so menus built from it must not outlive the registry.
    pub fn menuCallback(self: *CommandRegistry, cmd: Command) menu.Callback {
        return .{ .ctx = @ptrCast(self.trampolines.getPtr(cmd)), .f = trampolineThunk };
    }

    fn trampolineThunk(ctx: ?*anyopaque) void {
        const t: *Trampoline = @ptrCast(@alignCast(ctx.?));
        _ = t.reg.dispatch(t.cmd);
    }
};

// ---------------------------------------------------------------------------
// Menu tree definition (docs/UX.md menu table). Pure data: phase 3 turns it
// into NSMenus with `installMenuBar`. The App menu (About / Settings… /
// Hide group / Quit) is built by relay_mac.menu.installMainMenu;
// `settings_leaf` mirrors the one M2 shortcut that lives there so shortcut
// accounting covers it. The standard Window menu is part of the tree so the
// bar order matches docs/UX.md (installMainMenu adopts it by title).
// ---------------------------------------------------------------------------

pub const app_name: [:0]const u8 = "Relay";

pub const MenuAction = union(enum) {
    none,
    /// Dispatch through the CommandRegistry.
    cmd: Command,
    /// First-responder selector (nil target, responder chain).
    sel: [:0]const u8,
};

pub const MenuLeaf = struct {
    title: [:0]const u8,
    action: MenuAction = .none,
    key: [:0]const u8 = "",
    mods: menu.Modifiers = .{},
};

pub const MenuNode = union(enum) {
    separator,
    leaf: MenuLeaf,
    submenu: struct { title: [:0]const u8, items: []const MenuNode },
};

pub const MenuDef = struct {
    title: [:0]const u8,
    items: []const MenuNode,
};

fn cmdLeaf(title: [:0]const u8, command: Command, key: [:0]const u8, mods: menu.Modifiers) MenuNode {
    return .{ .leaf = .{ .title = title, .action = .{ .cmd = command }, .key = key, .mods = mods } };
}

fn selLeaf(title: [:0]const u8, selector: [:0]const u8, key: [:0]const u8, mods: menu.Modifiers) MenuNode {
    return .{ .leaf = .{ .title = title, .action = .{ .sel = selector }, .key = key, .mods = mods } };
}

const K = menu.Keys;

/// App-menu Settings… (Cmd+,); installed via menu.AppMenuSpec, represented
/// here for the shortcut-integrity accounting.
pub const settings_leaf: MenuLeaf = .{
    .title = "Settings…",
    .action = .{ .cmd = .show_settings },
    .key = ",",
    .mods = .{},
};

pub const file_menu: MenuDef = .{
    .title = "File",
    .items = &.{
        // M2 ships a single window; Cmd+N re-fronts it.
        cmdLeaf("Show Main Window", .new_window, "n", .{}),
        cmdLeaf("New Tab", .new_tab, "t", .{}),
        // Close: Cmd+W closes the active tab when >1 tab open, else performClose: the window.
        cmdLeaf("Close", .close_tab, "w", .{}),
        .separator,
        cmdLeaf("Connect to Server…", .connect_server, "k", .{}),
        cmdLeaf("Disconnect", .disconnect, "k", .{ .shift = true }),
        cmdLeaf("Disconnect All", .disconnect_all, "", .{}),
        .separator,
        cmdLeaf("New Folder", .new_folder, "n", .{ .shift = true }),
        cmdLeaf("Rename", .rename_selection, "", .{}),
        cmdLeaf("Edit with External Editor", .edit_external, "e", .{}),
        cmdLeaf("Quick Look", .quick_look, "y", .{}),
        cmdLeaf("Delete", .delete_selection, K.backspace, .{}),
        .separator,
        .{ .submenu = .{ .title = "Import", .items = &.{
            cmdLeaf("FileZilla Sites…", .import_filezilla, "", .{}),
            cmdLeaf("Cyberduck Bookmarks…", .import_cyberduck, "", .{}),
        } } },
    },
};

pub const edit_menu: MenuDef = .{ .title = "Edit", .items = &.{
    selLeaf("Cut", "cut:", "x", .{}),
    selLeaf("Copy", "copy:", "c", .{}),
    selLeaf("Paste", "paste:", "v", .{}),
    .separator,
    .{ .submenu = .{ .title = "Copy as", .items = &.{
        cmdLeaf("scp Command", .copy_as_scp, "", .{}),
        cmdLeaf("rsync Command", .copy_as_rsync, "", .{}),
        cmdLeaf("SFTP URL", .copy_as_sftp, "", .{}),
        cmdLeaf("curl Command", .copy_as_curl, "", .{}),
    } } },
    .separator,
    selLeaf("Select All", "selectAll:", "a", .{}),
} };

pub const view_menu: MenuDef = .{ .title = "View", .items = &.{
    cmdLeaf("Toggle Sidebar", .toggle_sidebar, "s", .{ .option = true }),
    cmdLeaf("Toggle Transfers", .toggle_transfers, "j", .{}),
    cmdLeaf("Inspector", .toggle_inspector, "i", .{}),
    .separator,
    .{ .submenu = .{ .title = "Density", .items = &.{
        cmdLeaf("Comfortable", .density_comfortable, "", .{}),
        cmdLeaf("Compact", .density_compact, "", .{}),
        cmdLeaf("Dense", .density_dense, "", .{}),
    } } },
    .separator,
    cmdLeaf("Synchronized Browsing", .toggle_sync_browsing, "b", .{ .shift = true }),
    cmdLeaf("Compare Panes", .toggle_compare, "d", .{ .shift = true }),
    cmdLeaf("Vim Key Bindings", .toggle_vim, "", .{}),
    .separator,
    cmdLeaf("Toggle Hidden Files", .toggle_hidden, ".", .{ .shift = true }),
    cmdLeaf("Filter", .filter, "f", .{}),
    .separator,
    cmdLeaf("Next Tab", .next_tab, "]", .{ .shift = true }),
    cmdLeaf("Previous Tab", .prev_tab, "[", .{ .shift = true }),
    .{ .submenu = .{ .title = "Go to Tab", .items = &.{
        cmdLeaf("Tab 1", .select_tab_1, "1", .{}),
        cmdLeaf("Tab 2", .select_tab_2, "2", .{}),
        cmdLeaf("Tab 3", .select_tab_3, "3", .{}),
        cmdLeaf("Tab 4", .select_tab_4, "4", .{}),
        cmdLeaf("Tab 5", .select_tab_5, "5", .{}),
        cmdLeaf("Tab 6", .select_tab_6, "6", .{}),
        cmdLeaf("Tab 7", .select_tab_7, "7", .{}),
        cmdLeaf("Tab 8", .select_tab_8, "8", .{}),
        cmdLeaf("Last Tab", .select_tab_last, "9", .{}),
    } } },
} };

pub const go_menu: MenuDef = .{ .title = "Go", .items = &.{
    cmdLeaf("Back", .go_back, "[", .{}),
    cmdLeaf("Forward", .go_forward, "]", .{}),
    cmdLeaf("Enclosing Folder", .go_enclosing, K.up, .{}),
    .separator,
    cmdLeaf("Go to Path…", .go_to_path, "g", .{ .shift = true }),
    cmdLeaf("Refresh", .refresh, "r", .{}),
    .separator,
    cmdLeaf("Command Palette…", .palette_commands, "p", .{ .shift = true }),
    cmdLeaf("Go to Anything…", .palette_paths, "p", .{}),
} };

pub const server_menu: MenuDef = .{ .title = "Server", .items = &.{
    cmdLeaf("Open Selection", .open_selection, K.down, .{}),
    cmdLeaf("Transfer Selection", .transfer_selection, K.ret, .{}),
    .separator,
    cmdLeaf("Open in Terminal", .open_terminal, "t", .{ .option = true }),
    .separator,
    cmdLeaf("Permissions…", .permissions, "", .{}),
} };

pub const transfers_menu: MenuDef = .{ .title = "Transfers", .items = &.{
    cmdLeaf("Pause All", .pause_all_transfers, "", .{}),
    cmdLeaf("Resume All", .resume_all_transfers, "", .{}),
    .separator,
    cmdLeaf("Retry Failed", .retry_failed_transfers, "", .{}),
    cmdLeaf("Clear Completed", .clear_completed_transfers, "", .{}),
    .separator,
    cmdLeaf("Cancel", .cancel_active, ".", .{}),
} };

/// Standard Window menu, provided here (rather than letting installMainMenu
/// append its own) so the bar order matches docs/UX.md: … Transfers ·
/// Window · Help. installMainMenu recognizes the "Window" title and
/// registers it as the app's windows menu (AppKit appends the open-windows
/// list).
pub const window_menu: MenuDef = .{ .title = "Window", .items = &.{
    selLeaf("Minimize", "performMiniaturize:", "m", .{}),
    selLeaf("Zoom", "performZoom:", "", .{}),
    .separator,
    selLeaf("Bring All to Front", "arrangeInFront:", "", .{}),
} };

pub const help_menu: MenuDef = .{ .title = "Help", .items = &.{
    selLeaf("Relay Help", "showHelp:", "?", .{}),
} };

/// The whole bar after the App menu (which menu.installMainMenu builds from
/// AppMenuSpec). Order per docs/UX.md.
pub const menu_bar: []const MenuDef = &.{
    file_menu, edit_menu, view_menu, go_menu, server_menu, transfers_menu, window_menu, help_menu,
};

/// Lower a MenuNode tree into relay_mac menu Items, routing every command
/// leaf through `commands`. All Item slices live in `arena`; the resulting
/// NSMenus copy what they need, so the arena may be freed after building.
pub fn buildItems(
    arena: Allocator,
    commands: *CommandRegistry,
    nodes: []const MenuNode,
) error{OutOfMemory}![]menu.Item {
    const out = try arena.alloc(menu.Item, nodes.len);
    for (nodes, out) |node, *slot| {
        slot.* = switch (node) {
            .separator => .separator,
            .leaf => |leaf| switch (leaf.action) {
                .none => .{ .leaf = .{ .title = leaf.title, .action = .none, .key = leaf.key, .mods = leaf.mods } },
                .sel => |selector| menu.Item.sel(leaf.title, selector, leaf.key, leaf.mods),
                .cmd => |command| menu.Item.call(leaf.title, commands.menuCallback(command), leaf.key, leaf.mods),
            },
            .submenu => |sub| menu.Item.sub(sub.title, try buildItems(arena, commands, sub.items)),
        };
    }
    return out;
}

/// Build + install the full menu bar (phase 3 calls this once at launch,
/// main thread). The CommandRegistry must outlive the installed menus.
pub fn installMenuBar(
    gpa: Allocator,
    menu_reg: *menu.Registry,
    commands: *CommandRegistry,
) error{OutOfMemory}!void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const specs = try arena.alloc(menu.MenuSpec, menu_bar.len);
    for (menu_bar, specs) |def, *spec| {
        spec.* = .{ .title = def.title, .items = try buildItems(arena, commands, def.items) };
    }
    try menu.installMainMenu(menu_reg, .{
        .app_name = app_name,
        .settings = .{ .call = commands.menuCallback(settings_leaf.action.cmd) },
    }, specs);
}

// --- shortcut accounting (menu-tree integrity tests) -------------------------

fn leafHasShortcut(leaf: MenuLeaf, key: []const u8, mask: NSUInteger) bool {
    return leaf.key.len > 0 and std.mem.eql(u8, leaf.key, key) and leaf.mods.mask() == mask;
}

fn countShortcutIn(nodes: []const MenuNode, key: []const u8, mask: NSUInteger) usize {
    var n: usize = 0;
    for (nodes) |node| switch (node) {
        .separator => {},
        .leaf => |leaf| {
            if (leafHasShortcut(leaf, key, mask)) n += 1;
        },
        .submenu => |sub| n += countShortcutIn(sub.items, key, mask),
    };
    return n;
}

/// How many menu items (including the app-menu Settings… item) carry this
/// key equivalent. The integrity test asserts == 1 for every M2 shortcut.
pub fn countShortcut(key: []const u8, mods: menu.Modifiers) usize {
    var n: usize = 0;
    if (leafHasShortcut(settings_leaf, key, mods.mask())) n += 1;
    for (menu_bar) |def| n += countShortcutIn(def.items, key, mods.mask());
    return n;
}

// ---------------------------------------------------------------------------
// Control kit — small AppKit control builders shared by the prefs window and
// the inspector panel.
// ---------------------------------------------------------------------------
/// The shared AppKit control kit now lives in relay_mac (selectors stay in
/// the wrapper layer). Re-exported here so existing call sites — and the
/// inspector/palette/transfers controllers that import `prefs.controls` —
/// keep working unchanged.
pub const controls = mac.appkit.controls;

// ---------------------------------------------------------------------------
// UI-only preferences (ui.zon). Core knobs (connections, rate limits, hidden
// files) live in relay_core settings.zon; these are presentation knobs the
// core never reads. Persisted with settings.zig's atomic writer; a missing
// or corrupt file degrades to defaults (same policy as settings.zon).
// ---------------------------------------------------------------------------

pub const ui_prefs_file = "ui.zon";

pub const Density = enum { comfortable, compact, dense };
pub const DateFormat = enum { iso, relative };

/// What main.zig saves on quit / restores on launch (M3 state restoration):
/// Per-tab session state. Fields mirror the legacy pane0/pane1 fields for
/// the active tab; the tabs array carries all tabs (Phase B).
pub const TabState = struct {
    pane0_site: u64 = 0,
    pane0_path: []const u8 = "",
    pane1_site: u64 = 0,
    pane1_path: []const u8 = "",
};

/// per-pane (site, path) plus the panel collapse states. site_id 0 = local
/// pane; an empty path means "nothing to restore" for that pane. Remote
/// reconnects are gated by main.zig (agent/keychain auth only — a restore
/// must never prompt at launch).
pub const SessionState = struct {
    /// Legacy fields — still written from the ACTIVE tab for back-compat
    /// with older ui.zon readers. New code reads from `tabs`.
    pane0_site: u64 = 0,
    pane0_path: []const u8 = "",
    pane1_site: u64 = 0,
    pane1_path: []const u8 = "",
    focused_pane: u32 = 0,
    sidebar_collapsed: bool = false,
    transfers_collapsed: bool = true,
    inspector_collapsed: bool = true,
    /// Phase B: all tabs. Slice owned by UiPrefs (dup'd in loadUiPrefs,
    /// freed in freeUiPrefs). Empty = fall back to legacy pane0/pane1 fields.
    tabs: []TabState = &.{},
    active_tab: u32 = 0,
};

pub const UiPrefs = struct {
    schema_version: u32 = 1,
    /// Default download directory; empty = ~/Downloads at use time.
    download_dir: []const u8 = "",
    confirm_delete: bool = true,
    density: Density = .compact,
    monospace_lists: bool = false,
    date_format: DateFormat = .iso,
    /// Pref "ui.vimMode" (View ▸ Vim Key Bindings; off by default).
    vim_mode: bool = false,
    /// Reconnect saved remote panes at launch (off by default). Even when
    /// on, reconnects only happen when auth is provably prompt-free (see
    /// main.zig reconnectIsPromptFree).
    reconnect_on_launch: bool = false,
    /// Last session's pane/panel layout (saved on quit by main.zig).
    session: SessionState = .{},
};

/// Loads ui.zon; `download_dir` and the session pane paths in the result
/// are owned by `gpa` (free with `freeUiPrefs`). Missing/corrupt files
/// yield defaults.
pub fn loadUiPrefs(io: std.Io, dir: std.Io.Dir, gpa: Allocator) error{OutOfMemory}!UiPrefs {
    const source = settings_mod.readFileZ(io, dir, ui_prefs_file, gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return defaultUiPrefs(gpa),
    };
    defer gpa.free(source);

    var zon_diag: std.zon.parse.Diagnostics = .{};
    defer zon_diag.deinit(gpa);
    const parsed = std.zon.parse.fromSliceAlloc(UiPrefs, gpa, source, &zon_diag, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => return defaultUiPrefs(gpa),
    };
    defer std.zon.parse.free(gpa, parsed);
    var out = parsed;
    out.download_dir = "";
    out.session.pane0_path = "";
    out.session.pane1_path = "";
    out.session.tabs = &.{};
    errdefer freeUiPrefs(gpa, &out);
    out.download_dir = try gpa.dupe(u8, parsed.download_dir);
    out.session.pane0_path = try gpa.dupe(u8, parsed.session.pane0_path);
    out.session.pane1_path = try gpa.dupe(u8, parsed.session.pane1_path);
    out.session.tabs = try dupTabStates(gpa, parsed.session.tabs);
    return out;
}

fn defaultUiPrefs(gpa: Allocator) error{OutOfMemory}!UiPrefs {
    var prefs: UiPrefs = .{};
    prefs.download_dir = try gpa.dupe(u8, "");
    errdefer gpa.free(prefs.download_dir);
    prefs.session.pane0_path = try gpa.dupe(u8, "");
    errdefer gpa.free(prefs.session.pane0_path);
    prefs.session.pane1_path = try gpa.dupe(u8, "");
    // tabs = &.{} is the zero value; no allocation needed.
    return prefs;
}

pub fn freeUiPrefs(gpa: Allocator, prefs: *UiPrefs) void {
    gpa.free(prefs.download_dir);
    prefs.download_dir = "";
    gpa.free(prefs.session.pane0_path);
    prefs.session.pane0_path = "";
    gpa.free(prefs.session.pane1_path);
    prefs.session.pane1_path = "";
    freeTabStates(gpa, prefs.session.tabs);
    prefs.session.tabs = &.{};
}

/// Free a heap-allocated TabState slice and all path strings within it.
pub fn freeTabStates(gpa: Allocator, tabs: []TabState) void {
    for (tabs) |*t| {
        gpa.free(t.pane0_path);
        gpa.free(t.pane1_path);
    }
    if (tabs.len > 0) gpa.free(tabs);
}

/// Deep-copy a TabState slice: the array plus each tab's path strings.
/// Returns &.{} for empty input (no allocation). Mirror of freeTabStates;
/// fully unwinds its partial allocations on OOM.
fn dupTabStates(gpa: Allocator, src: []const TabState) error{OutOfMemory}![]TabState {
    if (src.len == 0) return &.{};
    const tabs = try gpa.alloc(TabState, src.len);
    errdefer gpa.free(tabs);
    var done: usize = 0;
    errdefer for (tabs[0..done]) |*t| {
        gpa.free(t.pane0_path);
        gpa.free(t.pane1_path);
    };
    for (src, 0..) |s, i| {
        tabs[i] = s;
        tabs[i].pane0_path = "";
        tabs[i].pane1_path = "";
        tabs[i].pane0_path = try gpa.dupe(u8, s.pane0_path);
        errdefer gpa.free(tabs[i].pane0_path);
        tabs[i].pane1_path = try gpa.dupe(u8, s.pane1_path);
        done = i + 1;
    }
    return tabs;
}

/// Crash-safe persist (temp file + fsync + rename, via settings.zig).
pub fn saveUiPrefs(prefs: UiPrefs, io: std.Io, dir: std.Io.Dir, gpa: Allocator) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    std.zon.stringify.serialize(prefs, .{}, &out.writer) catch return error.OutOfMemory;
    out.writer.writeByte('\n') catch return error.OutOfMemory;
    try settings_mod.atomicWriteFile(io, dir, ui_prefs_file, out.written());
}

// ---------------------------------------------------------------------------
// PrefsController — the Settings window.
// ---------------------------------------------------------------------------

/// Slider/field range per the M2 spec. NOTE: the bridge clamps the live
/// engine budget to 8 connections (bridge.clampConns); values above that
/// persist but only take effect once the budget cap is lifted.
pub const conns_min: u8 = 1;
pub const conns_max: u8 = 32;

pub const RateDirection = enum { download, upload };

pub const ChangeListener = struct {
    ctx: ?*anyopaque = null,
    f: *const fn (?*anyopaque) void,
};

// Fixed-frame layout (sheet-style; the window does not resize in M2).
const win_w: f64 = 470;
const win_h: f64 = 402;
const label_x: f64 = 20;
const label_w: f64 = 130;
const control_x: f64 = 160;

fn fromTop(top: f64, height: f64) f64 {
    return win_h - top - height;
}

pub const PrefsController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    ui: UiPrefs,
    listeners: std.ArrayList(ChangeListener) = .empty,

    // Window + controls; valid only when `built`. Built lazily on first
    // show() so headless tests never touch window state.
    built: bool = false,
    win: windowkit.Window = undefined,
    target: ?*controls.ControlTarget = null,
    download_path_label: objc.Object = undefined,
    confirm_check: objc.Object = undefined,
    reconnect_check: objc.Object = undefined,
    conns_slider: objc.Object = undefined,
    conns_field: objc.Object = undefined,
    rate_down_check: objc.Object = undefined,
    rate_down_field: objc.Object = undefined,
    rate_up_check: objc.Object = undefined,
    rate_up_field: objc.Object = undefined,
    density_radios: [3]objc.Object = undefined,
    mono_check: objc.Object = undefined,
    date_popup: objc.Object = undefined,

    pub fn create(gpa: Allocator, core: *bridge.AppCore) error{OutOfMemory}!*PrefsController {
        const self = try gpa.create(PrefsController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .ui = try loadUiPrefs(core.io, core.config_dir, gpa),
        };
        return self;
    }

    pub fn destroy(self: *PrefsController) void {
        if (self.built) self.win.release();
        if (self.target) |target| target.destroy();
        self.listeners.deinit(self.gpa);
        freeUiPrefs(self.gpa, &self.ui);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    // --- prefs-changed publication -----------------------------------------

    /// Registered listeners fire after EVERY persisted change (main thread).
    pub fn addChangeListener(
        self: *PrefsController,
        ctx: ?*anyopaque,
        f: *const fn (?*anyopaque) void,
    ) error{OutOfMemory}!void {
        try self.listeners.append(self.gpa, .{ .ctx = ctx, .f = f });
    }

    fn notifyChanged(self: *PrefsController) void {
        for (self.listeners.items) |listener| listener.f(listener.ctx);
    }

    // --- state access --------------------------------------------------------

    /// Borrowed view of the UI prefs (valid until the next mutation).
    pub fn uiPrefs(self: *const PrefsController) UiPrefs {
        return self.ui;
    }

    /// The effective default download dir: the configured one, or
    /// ~/Downloads. May return a slice into `buf`.
    pub fn effectiveDownloadDir(self: *const PrefsController, buf: []u8) []const u8 {
        if (self.ui.download_dir.len > 0) return self.ui.download_dir;
        const home = std.c.getenv("HOME") orelse return "/tmp";
        return std.fmt.bufPrint(buf, "{s}/Downloads", .{std.mem.span(home)}) catch "/tmp";
    }

    // --- mutation API (control handlers, tests, phase 3) --------------------
    // Every setter persists immediately, syncs the window controls (if
    // built) and fires the prefs-changed listeners. No-change calls no-op.

    pub fn setDownloadDir(self: *PrefsController, path: []const u8) error{OutOfMemory}!void {
        if (std.mem.eql(u8, self.ui.download_dir, path)) return;
        const copy = try self.gpa.dupe(u8, path);
        self.gpa.free(self.ui.download_dir);
        self.ui.download_dir = copy;
        self.persistUi();
        self.changed();
    }

    pub fn setConfirmDelete(self: *PrefsController, confirm: bool) void {
        if (self.ui.confirm_delete == confirm) return;
        self.ui.confirm_delete = confirm;
        self.persistUi();
        self.changed();
    }

    pub fn setDensity(self: *PrefsController, density: Density) void {
        if (self.ui.density == density) return;
        self.ui.density = density;
        self.persistUi();
        self.changed();
    }

    pub fn setReconnectOnLaunch(self: *PrefsController, on: bool) void {
        if (self.ui.reconnect_on_launch == on) return;
        self.ui.reconnect_on_launch = on;
        self.persistUi();
        self.changed();
    }

    pub fn setMonospaceLists(self: *PrefsController, mono: bool) void {
        if (self.ui.monospace_lists == mono) return;
        self.ui.monospace_lists = mono;
        self.persistUi();
        self.changed();
    }

    pub fn setDateFormat(self: *PrefsController, format: DateFormat) void {
        if (self.ui.date_format == format) return;
        self.ui.date_format = format;
        self.persistUi();
        self.changed();
    }

    /// View ▸ Vim Key Bindings (pref "ui.vimMode"); the change listener
    /// pushes it into the browser like every other live-apply pref.
    pub fn setVimMode(self: *PrefsController, on: bool) void {
        if (self.ui.vim_mode == on) return;
        self.ui.vim_mode = on;
        self.persistUi();
        self.changed();
    }

    /// Persist the quit-time session snapshot (M3 state restoration).
    /// Silent: no listener notification — this runs on the terminate path
    /// where re-rendering views is pointless. Pane paths and tabs are copied.
    pub fn setSessionState(self: *PrefsController, session: SessionState) error{OutOfMemory}!void {
        const p0 = try self.gpa.dupe(u8, session.pane0_path);
        errdefer self.gpa.free(p0);
        const p1 = try self.gpa.dupe(u8, session.pane1_path);
        errdefer self.gpa.free(p1);
        const new_tabs = try dupTabStates(self.gpa, session.tabs);
        // Free old state AFTER all allocations succeed.
        self.gpa.free(self.ui.session.pane0_path);
        self.gpa.free(self.ui.session.pane1_path);
        freeTabStates(self.gpa, self.ui.session.tabs);
        self.ui.session = session;
        self.ui.session.pane0_path = p0;
        self.ui.session.pane1_path = p1;
        self.ui.session.tabs = new_tabs;
        self.persistUi();
    }

    pub fn setConnectionsPerSite(self: *PrefsController, conns: u8) void {
        const clamped = @max(conns_min, @min(conns, conns_max));
        if (self.core.settings.connections_per_site == clamped) return;
        self.core.settings.connections_per_site = clamped;
        self.persistSettings();
        self.changed();
    }

    /// 0 = unlimited. Persists AND live-applies to the running engine
    /// (AppCore.saveSettings only refreshes the connection budget; the
    /// engine's token-bucket setter is main-thread safe — it locks briefly,
    /// never across I/O. TODO(m2-dedupe): promote to a bridge command).
    pub fn setRateLimit(self: *PrefsController, direction: RateDirection, bytes_per_s: u64) void {
        const slot = switch (direction) {
            .download => &self.core.settings.rate_limit_down,
            .upload => &self.core.settings.rate_limit_up,
        };
        if (slot.* == bytes_per_s) return;
        slot.* = bytes_per_s;
        self.persistSettings();
        self.core.engine.setGlobalRateLimit(switch (direction) {
            .download => .download,
            .upload => .upload,
        }, bytes_per_s);
        self.changed();
    }

    fn changed(self: *PrefsController) void {
        self.syncControls();
        self.notifyChanged();
    }

    fn persistUi(self: *PrefsController) void {
        saveUiPrefs(self.ui, self.core.io, self.core.config_dir, self.gpa) catch |err| {
            std.log.warn("prefs: failed to persist {s}: {t}", .{ ui_prefs_file, err });
        };
    }

    fn persistSettings(self: *PrefsController) void {
        self.core.saveSettings() catch |err| {
            std.log.warn("prefs: failed to persist settings: {t}", .{err});
        };
    }

    // --- window --------------------------------------------------------------

    /// Show the Settings window (Cmd+,). Builds it on first use.
    pub fn show(self: *PrefsController) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        if (!self.built) {
            self.buildWindow() catch |err| {
                std.log.err("prefs: failed to build the Settings window: {t}", .{err});
                return;
            };
        }
        self.syncControls();
        self.win.makeKeyAndOrderFront();
    }

    /// CommandRegistry adapter: commands.bind(.show_settings, pc, showCommand).
    pub fn showCommand(ctx: ?*anyopaque) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.show();
    }

    fn buildWindow(self: *PrefsController) !void {
        const target = try controls.ControlTarget.create(self.gpa);
        errdefer target.destroy();

        const style = windowkit.StyleMask.titled |
            windowkit.StyleMask.closable |
            windowkit.StyleMask.miniaturizable;
        const win = windowkit.Window.create(foundation.rect(0, 0, win_w, win_h), "Settings", style);
        errdefer win.release();
        const content = win.contentView();

        // --- General ---------------------------------------------------------
        controls.addSubview(content, controls.makeLabel(
            "General",
            foundation.rect(label_x, fromTop(20, 17), 200, 17),
            .{ .bold = true },
        ));

        controls.addSubview(content, controls.makeLabel(
            "Download to:",
            foundation.rect(label_x, fromTop(49, 17), label_w, 17),
            .{ .right = true },
        ));
        self.download_path_label = controls.makeLabel(
            "",
            foundation.rect(control_x, fromTop(49, 17), 200, 17),
            .{ .secondary = true, .truncate_middle = true },
        );
        controls.addSubview(content, self.download_path_label);
        const choose = controls.makePushButton(
            "Choose…",
            foundation.rect(win_w - 20 - 86, fromTop(45, 24), 86, 24),
        );
        controls.addSubview(content, choose);
        try target.wire(choose, self, onChooseDownloadDir);

        self.confirm_check = controls.makeCheckbox(
            "Ask before deleting",
            foundation.rect(control_x, fromTop(78, 18), 250, 18),
        );
        controls.addSubview(content, self.confirm_check);
        try target.wire(self.confirm_check, self, onConfirmToggled);

        self.reconnect_check = controls.makeCheckbox(
            "Reconnect to servers at launch",
            foundation.rect(control_x, fromTop(108, 18), 250, 18),
        );
        controls.addSubview(content, self.reconnect_check);
        try target.wire(self.reconnect_check, self, onReconnectToggled);

        // --- Transfers ---------------------------------------------------------
        controls.addSubview(content, controls.makeLabel(
            "Transfers",
            foundation.rect(label_x, fromTop(142, 17), 200, 17),
            .{ .bold = true },
        ));

        controls.addSubview(content, controls.makeLabel(
            "Connections per site:",
            foundation.rect(label_x, fromTop(171, 17), label_w, 17),
            .{ .right = true },
        ));
        self.conns_slider = controls.makeSlider(
            foundation.rect(control_x, fromTop(170, 21), 170, 21),
            @floatFromInt(conns_min),
            @floatFromInt(conns_max),
            @floatFromInt(self.core.settings.connections_per_site),
        );
        controls.addSubview(content, self.conns_slider);
        try target.wire(self.conns_slider, self, onConnsSlider);
        self.conns_field = controls.makeTextField(
            foundation.rect(control_x + 178, fromTop(169, 22), 44, 22),
            "",
        );
        controls.addSubview(content, self.conns_field);
        try target.wire(self.conns_field, self, onConnsField);
        controls.addSubview(content, controls.makeLabel(
            "1–32",
            foundation.rect(control_x + 230, fromTop(171, 16), 50, 16),
            .{ .secondary = true, .small = true },
        ));

        self.rate_down_check = controls.makeCheckbox(
            "Limit download rate",
            foundation.rect(control_x, fromTop(203, 18), 160, 18),
        );
        controls.addSubview(content, self.rate_down_check);
        try target.wire(self.rate_down_check, self, onRateDownChanged);
        self.rate_down_field = controls.makeTextField(
            foundation.rect(control_x + 170, fromTop(201, 22), 70, 22),
            "",
        );
        controls.addSubview(content, self.rate_down_field);
        try target.wire(self.rate_down_field, self, onRateDownChanged);
        controls.addSubview(content, controls.makeLabel(
            "KB/s",
            foundation.rect(control_x + 246, fromTop(203, 16), 40, 16),
            .{ .secondary = true, .small = true },
        ));

        self.rate_up_check = controls.makeCheckbox(
            "Limit upload rate",
            foundation.rect(control_x, fromTop(233, 18), 160, 18),
        );
        controls.addSubview(content, self.rate_up_check);
        try target.wire(self.rate_up_check, self, onRateUpChanged);
        self.rate_up_field = controls.makeTextField(
            foundation.rect(control_x + 170, fromTop(231, 22), 70, 22),
            "",
        );
        controls.addSubview(content, self.rate_up_field);
        try target.wire(self.rate_up_field, self, onRateUpChanged);
        controls.addSubview(content, controls.makeLabel(
            "KB/s",
            foundation.rect(control_x + 246, fromTop(233, 16), 40, 16),
            .{ .secondary = true, .small = true },
        ));

        // --- Appearance --------------------------------------------------------
        controls.addSubview(content, controls.makeLabel(
            "Appearance",
            foundation.rect(label_x, fromTop(267, 17), 200, 17),
            .{ .bold = true },
        ));

        controls.addSubview(content, controls.makeLabel(
            "Density:",
            foundation.rect(label_x, fromTop(296, 17), label_w, 17),
            .{ .right = true },
        ));
        const radio_titles = [3][]const u8{ "Comfortable", "Compact", "Dense" };
        const radio_x = [3]f64{ control_x, control_x + 112, control_x + 206 };
        const radio_w = [3]f64{ 108, 90, 76 };
        for (radio_titles, radio_x, radio_w, 0..) |title, x, w, i| {
            const radio = controls.makeRadio(title, foundation.rect(x, fromTop(296, 18), w, 18));
            controls.addSubview(content, radio);
            try target.wire(radio, self, onDensityRadio);
            self.density_radios[i] = radio;
        }

        self.mono_check = controls.makeCheckbox(
            "Monospaced file lists",
            foundation.rect(control_x, fromTop(326, 18), 250, 18),
        );
        controls.addSubview(content, self.mono_check);
        try target.wire(self.mono_check, self, onMonoToggled);

        controls.addSubview(content, controls.makeLabel(
            "Date format:",
            foundation.rect(label_x, fromTop(360, 17), label_w, 17),
            .{ .right = true },
        ));
        self.date_popup = controls.makePopup(
            foundation.rect(control_x, fromTop(358, 25), 170, 25),
            &.{ "ISO 8601", "Relative" },
        );
        controls.addSubview(content, self.date_popup);
        try target.wire(self.date_popup, self, onDateFormatChanged);

        win.center();
        self.target = target;
        self.win = win;
        self.built = true;
    }

    /// Push current state into the window controls (no-op headless).
    fn syncControls(self: *PrefsController) void {
        if (!self.built) return;
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        var dir_buf: [1024]u8 = undefined;
        controls.setLabelText(self.download_path_label, self.effectiveDownloadDir(&dir_buf));
        controls.setChecked(self.confirm_check, self.ui.confirm_delete);
        controls.setChecked(self.reconnect_check, self.ui.reconnect_on_launch);

        const conns = self.core.settings.connections_per_site;
        controls.setSliderValue(self.conns_slider, @floatFromInt(conns));
        var num_buf: [8]u8 = undefined;
        controls.setTextValue(self.conns_field, std.fmt.bufPrint(&num_buf, "{d}", .{conns}) catch "?");

        self.syncRateRow(self.rate_down_check, self.rate_down_field, self.core.settings.rate_limit_down);
        self.syncRateRow(self.rate_up_check, self.rate_up_field, self.core.settings.rate_limit_up);

        const selected: usize = switch (self.ui.density) {
            .comfortable => 0,
            .compact => 1,
            .dense => 2,
        };
        for (self.density_radios, 0..) |radio, i| controls.setChecked(radio, i == selected);

        controls.setChecked(self.mono_check, self.ui.monospace_lists);
        controls.setPopupIndex(self.date_popup, switch (self.ui.date_format) {
            .iso => 0,
            .relative => 1,
        });
    }

    fn syncRateRow(self: *PrefsController, check: objc.Object, field: objc.Object, bytes_per_s: u64) void {
        _ = self;
        const on = bytes_per_s > 0;
        controls.setChecked(check, on);
        controls.setEnabled(field, on);
        if (on) {
            var buf: [24]u8 = undefined;
            controls.setTextValue(field, std.fmt.bufPrint(&buf, "{d}", .{bytes_per_s / 1024}) catch "?");
        }
    }

    // --- control handlers (main thread; pool-wrapped by the target IMP) ----

    fn onConfirmToggled(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.setConfirmDelete(controls.isChecked(objc.Object.fromId(sender)));
    }

    fn onChooseDownloadDir(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        _ = panels.beginOpenPanel(self.win, .{
            .choose_files = false,
            .choose_directories = true,
            .can_create_directories = true,
            .message = "Choose the default download folder",
            .prompt = "Choose",
            .directory = self.ui.download_dir,
        }, self, onDownloadDirChosen);
    }

    fn onDownloadDirChosen(self: *PrefsController, paths: []const []const u8) void {
        if (paths.len == 0) return;
        self.setDownloadDir(paths[0]) catch |err| {
            std.log.warn("prefs: failed to set download dir: {t}", .{err});
        };
    }

    fn onConnsSlider(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        const value = controls.sliderValue(objc.Object.fromId(sender));
        self.setConnectionsPerSite(@intFromFloat(@round(@max(1.0, @min(value, 255.0)))));
    }

    fn onConnsField(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        const text = controls.textValue(self.gpa, objc.Object.fromId(sender)) catch return;
        defer self.gpa.free(text);
        const trimmed = std.mem.trim(u8, text, " \t");
        const parsed = std.fmt.parseInt(u8, trimmed, 10) catch {
            self.syncControls(); // revert invalid input
            return;
        };
        self.setConnectionsPerSite(parsed);
        self.syncControls(); // reflect clamping in the field
    }

    fn onRateDownChanged(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.applyRateRow(.download, self.rate_down_check, self.rate_down_field);
    }

    fn onRateUpChanged(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.applyRateRow(.upload, self.rate_up_check, self.rate_up_field);
    }

    fn applyRateRow(self: *PrefsController, direction: RateDirection, check: objc.Object, field: objc.Object) void {
        if (!controls.isChecked(check)) {
            self.setRateLimit(direction, 0);
            return;
        }
        controls.setEnabled(field, true);
        const text = controls.textValue(self.gpa, field) catch return;
        defer self.gpa.free(text);
        const trimmed = std.mem.trim(u8, text, " \t");
        const kb = std.fmt.parseInt(u64, trimmed, 10) catch 0;
        if (kb == 0) {
            // Checked but no number yet: default to 1 MB/s so the limiter
            // is observable instead of silently unlimited.
            self.setRateLimit(direction, 1024 * 1024);
            return;
        }
        self.setRateLimit(direction, kb *| 1024);
    }

    fn onDensityRadio(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        for (self.density_radios, 0..) |radio, i| {
            if (radio.value == sender) {
                self.setDensity(switch (i) {
                    0 => .comfortable,
                    1 => .compact,
                    else => .dense,
                });
                return;
            }
        }
    }

    fn onMonoToggled(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.setMonospaceLists(controls.isChecked(objc.Object.fromId(sender)));
    }

    fn onReconnectToggled(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        self.setReconnectOnLaunch(controls.isChecked(objc.Object.fromId(sender)));
    }

    fn onDateFormatChanged(ctx: ?*anyopaque, sender: c.id) void {
        const self: *PrefsController = @ptrCast(@alignCast(ctx.?));
        const index = controls.popupIndex(objc.Object.fromId(sender));
        self.setDateFormat(if (index == 1) .relative else .iso);
    }
};

// ---------------------------------------------------------------------------
// Tests — headless: tree integrity, registry dispatch, item lowering,
// persistence round-trips, control kit state. Window-dependent behavior is
// phase 3's smoke + the RELAY_VISUAL_SMOKE-gated run in inspector.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;

// Mirror of bridge.zig's TestHarness (kept local; the bridge's is not pub).
const TestHarness = struct {
    tmp_conf: std.testing.TmpDir,
    tmp_root: std.testing.TmpDir,
    fake: relay.cred.fake.FakeStore,
    core: *bridge.AppCore,

    fn start(h: *TestHarness) !void {
        h.tmp_conf = std.testing.tmpDir(.{ .iterate = true });
        h.tmp_root = std.testing.tmpDir(.{ .iterate = true });
        h.fake = .init(testing.allocator);
        h.core = try bridge.AppCore.initOptions(testing.allocator, .{
            .pump = .manual,
            .config_dir = h.tmp_conf.dir,
            .local_root = h.tmp_root.dir,
            .cred_store = h.fake.credStore(),
        });
    }

    fn stop(h: *TestHarness) void {
        h.core.shutdown();
        h.fake.deinit();
        h.tmp_root.cleanup();
        h.tmp_conf.cleanup();
    }
};

test "menu tree integrity: every UX.md M2 menu shortcut appears exactly once" {
    const Expected = struct { key: [:0]const u8, mods: menu.Modifiers };
    const m2_shortcuts = [_]Expected{
        .{ .key = "k", .mods = .{} }, // Connect to Server…
        .{ .key = "k", .mods = .{ .shift = true } }, // Disconnect
        .{ .key = "n", .mods = .{} }, // Show Main Window
        .{ .key = "w", .mods = .{} }, // Close
        .{ .key = "[", .mods = .{} }, // Back
        .{ .key = "]", .mods = .{} }, // Forward
        .{ .key = K.up, .mods = .{} }, // Enclosing folder
        .{ .key = K.down, .mods = .{} }, // Open selection
        .{ .key = "g", .mods = .{ .shift = true } }, // Go to Path…
        .{ .key = "r", .mods = .{} }, // Refresh
        .{ .key = "f", .mods = .{} }, // Filter
        .{ .key = ".", .mods = .{ .shift = true } }, // Toggle hidden
        .{ .key = K.ret, .mods = .{} }, // Transfer selection
        .{ .key = K.backspace, .mods = .{} }, // Delete
        .{ .key = "n", .mods = .{ .shift = true } }, // New folder
        .{ .key = "i", .mods = .{} }, // Inspector
        .{ .key = "j", .mods = .{} }, // Transfers panel
        .{ .key = "s", .mods = .{ .option = true } }, // Sidebar
        .{ .key = ",", .mods = .{} }, // Settings
        .{ .key = ".", .mods = .{} }, // Cancel
        // M3 additions.
        .{ .key = "e", .mods = .{} }, // Edit with External Editor
        .{ .key = "y", .mods = .{} }, // Quick Look
        .{ .key = "b", .mods = .{ .shift = true } }, // Synchronized Browsing
        .{ .key = "d", .mods = .{ .shift = true } }, // Compare Panes
        .{ .key = "p", .mods = .{ .shift = true } }, // Command Palette…
        .{ .key = "p", .mods = .{} }, // Go to Anything…
        .{ .key = "t", .mods = .{ .option = true } }, // Open in Terminal
        // Tab additions (Phase B).
        .{ .key = "t", .mods = .{} }, // New Tab
        .{ .key = "]", .mods = .{ .shift = true } }, // Next Tab
        .{ .key = "[", .mods = .{ .shift = true } }, // Previous Tab
    };
    for (m2_shortcuts) |shortcut| {
        try testing.expectEqual(@as(usize, 1), countShortcut(shortcut.key, shortcut.mods));
    }
}

const ShortcutEntry = struct { key: []const u8, mask: NSUInteger };

fn collectShortcuts(list: *std.ArrayList(ShortcutEntry), nodes: []const MenuNode) !void {
    for (nodes) |node| switch (node) {
        .separator => {},
        .leaf => |leaf| if (leaf.key.len > 0) {
            try list.append(testing.allocator, .{ .key = leaf.key, .mask = leaf.mods.mask() });
        },
        .submenu => |sub| try collectShortcuts(list, sub.items),
    };
}

test "menu tree integrity: no duplicate key equivalents anywhere in the bar" {
    var list: std.ArrayList(ShortcutEntry) = .empty;
    defer list.deinit(testing.allocator);
    try list.append(testing.allocator, .{ .key = settings_leaf.key, .mask = settings_leaf.mods.mask() });
    for (menu_bar) |def| try collectShortcuts(&list, def.items);

    for (list.items, 0..) |a, i| {
        for (list.items[i + 1 ..]) |b| {
            const duplicate = std.mem.eql(u8, a.key, b.key) and a.mask == b.mask;
            if (duplicate) {
                std.debug.print("duplicate shortcut: key={s} mask={d}\n", .{ a.key, a.mask });
            }
            try testing.expect(!duplicate);
        }
    }
    // Sanity: the walker saw a plausible number of shortcuts.
    try testing.expect(list.items.len >= 20);
}

test "menu tree integrity: density submenu carries all three modes exactly once" {
    const density_cmds = [_]Command{ .density_comfortable, .density_compact, .density_dense };
    for (density_cmds) |cmd| {
        var count: usize = 0;
        for (view_menu.items) |node| {
            if (node == .submenu) {
                for (node.submenu.items) |sub_node| {
                    if (sub_node == .leaf and sub_node.leaf.action == .cmd and
                        sub_node.leaf.action.cmd == cmd) count += 1;
                }
            }
        }
        try testing.expectEqual(@as(usize, 1), count);
    }
}

const DispatchRecorder = struct {
    hits: u32 = 0,
    enabled: bool = true,

    fn onCommand(ctx: ?*anyopaque) void {
        const self: *DispatchRecorder = @ptrCast(@alignCast(ctx.?));
        self.hits += 1;
    }

    fn validate(ctx: ?*anyopaque, cmd: Command) bool {
        const self: *DispatchRecorder = @ptrCast(@alignCast(ctx.?));
        _ = cmd;
        return self.enabled;
    }
};

test "command registry: bind/dispatch, unbound no-op, validation hook gates" {
    const reg = try CommandRegistry.create(testing.allocator);
    defer reg.destroy();

    var rec: DispatchRecorder = .{};
    try testing.expect(!reg.dispatch(.refresh)); // unbound

    reg.bind(.refresh, &rec, DispatchRecorder.onCommand);
    try testing.expect(reg.dispatch(.refresh));
    try testing.expectEqual(@as(u32, 1), rec.hits);
    try testing.expectEqual(@as(u64, 1), reg.dispatched);

    // Validation hook: disabled commands no-op for menus AND shortcuts.
    reg.setValidator(.{ .ctx = &rec, .f = DispatchRecorder.validate });
    rec.enabled = false;
    try testing.expect(!reg.isEnabled(.refresh));
    try testing.expect(!reg.dispatch(.refresh));
    try testing.expectEqual(@as(u32, 1), rec.hits);

    rec.enabled = true;
    try testing.expect(reg.isEnabled(.refresh));
    try testing.expect(reg.dispatch(.refresh));
    try testing.expectEqual(@as(u32, 2), rec.hits);

    // Rebinding replaces the handler in place.
    var rec2: DispatchRecorder = .{};
    reg.bind(.refresh, &rec2, DispatchRecorder.onCommand);
    try testing.expect(reg.dispatch(.refresh));
    try testing.expectEqual(@as(u32, 2), rec.hits);
    try testing.expectEqual(@as(u32, 1), rec2.hits);
}

test "buildItems lowers the tree: separators, selectors, commands, submenus" {
    const reg = try CommandRegistry.create(testing.allocator);
    defer reg.destroy();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const items = try buildItems(arena_state.allocator(), reg, file_menu.items);
    try testing.expectEqual(file_menu.items.len, items.len);

    // Command leaf → registry callback that really dispatches.
    var rec: DispatchRecorder = .{};
    reg.bind(.new_window, &rec, DispatchRecorder.onCommand);
    try testing.expect(items[0] == .leaf);
    try testing.expect(items[0].leaf.action == .call);
    const cb = items[0].leaf.action.call;
    cb.f(cb.ctx);
    try testing.expectEqual(@as(u32, 1), rec.hits);

    // New Tab (Phase B): items[1] is a command leaf (not a selector).
    try testing.expect(items[1] == .leaf);
    try testing.expect(items[1].leaf.action == .call);
    try testing.expectEqualStrings("t", items[1].leaf.key);

    // Close tab: items[2] is a command leaf.
    try testing.expect(items[2] == .leaf);
    try testing.expect(items[2].leaf.action == .call);
    try testing.expectEqualStrings("w", items[2].leaf.key);

    try testing.expect(items[3] == .separator);

    // Submenu lowering (View ▸ Density and View ▸ Go to Tab).
    const view_items = try buildItems(arena_state.allocator(), reg, view_menu.items);
    var found_density = false;
    var found_goto = false;
    for (view_items) |item| {
        if (item != .submenu) continue;
        if (std.mem.eql(u8, item.submenu.title, "Density")) {
            try testing.expectEqual(@as(usize, 3), item.submenu.items.len);
            found_density = true;
        } else if (std.mem.eql(u8, item.submenu.title, "Go to Tab")) {
            try testing.expectEqual(@as(usize, 9), item.submenu.items.len);
            found_goto = true;
        }
    }
    try testing.expect(found_density);
    try testing.expect(found_goto);
}

test "ui prefs: save/load round-trip; corrupt or missing file degrades to defaults" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Missing file → defaults (reconnect-on-launch ships OFF).
    var missing = try loadUiPrefs(io, tmp.dir, testing.allocator);
    defer freeUiPrefs(testing.allocator, &missing);
    try testing.expectEqual(Density.compact, missing.density);
    try testing.expect(missing.confirm_delete);
    try testing.expect(!missing.reconnect_on_launch);

    const custom: UiPrefs = .{
        .download_dir = "/Users/relay/Downloads",
        .confirm_delete = false,
        .density = .dense,
        .monospace_lists = true,
        .date_format = .relative,
        .vim_mode = true,
        .reconnect_on_launch = true,
        .session = .{
            .pane0_site = 0,
            .pane0_path = "/Users/relay/projects",
            .pane1_site = 7,
            .pane1_path = "/var/www",
            .focused_pane = 1,
            .sidebar_collapsed = true,
            .transfers_collapsed = false,
            .inspector_collapsed = false,
        },
    };
    try saveUiPrefs(custom, io, tmp.dir, testing.allocator);
    var loaded = try loadUiPrefs(io, tmp.dir, testing.allocator);
    defer freeUiPrefs(testing.allocator, &loaded);
    try testing.expectEqualStrings(custom.download_dir, loaded.download_dir);
    try testing.expectEqual(custom.confirm_delete, loaded.confirm_delete);
    try testing.expectEqual(custom.density, loaded.density);
    try testing.expectEqual(custom.monospace_lists, loaded.monospace_lists);
    try testing.expectEqual(custom.date_format, loaded.date_format);
    try testing.expectEqual(custom.vim_mode, loaded.vim_mode);
    try testing.expectEqual(custom.reconnect_on_launch, loaded.reconnect_on_launch);
    // M3 session restoration block round-trips, strings included.
    try testing.expectEqualStrings(custom.session.pane0_path, loaded.session.pane0_path);
    try testing.expectEqualStrings(custom.session.pane1_path, loaded.session.pane1_path);
    try testing.expectEqual(custom.session.pane1_site, loaded.session.pane1_site);
    try testing.expectEqual(custom.session.focused_pane, loaded.session.focused_pane);
    try testing.expectEqual(custom.session.sidebar_collapsed, loaded.session.sidebar_collapsed);
    try testing.expectEqual(custom.session.transfers_collapsed, loaded.session.transfers_collapsed);
    try testing.expectEqual(custom.session.inspector_collapsed, loaded.session.inspector_collapsed);

    // Corrupt file → defaults, never a crash.
    try tmp.dir.writeFile(io, .{ .sub_path = ui_prefs_file, .data = "}{ garbage \x00" });
    var corrupt = try loadUiPrefs(io, tmp.dir, testing.allocator);
    defer freeUiPrefs(testing.allocator, &corrupt);
    try testing.expectEqual(Density.compact, corrupt.density);
}

test "ui prefs: a pre-reconnect ui.zon (field absent) parses with the default" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // A minimal file written before reconnect_on_launch existed: missing
    // fields take their ZON defaults instead of failing the parse.
    try tmp.dir.writeFile(io, .{
        .sub_path = ui_prefs_file,
        .data = ".{ .density = .dense, .vim_mode = true }",
    });
    var loaded = try loadUiPrefs(io, tmp.dir, testing.allocator);
    defer freeUiPrefs(testing.allocator, &loaded);
    try testing.expectEqual(Density.dense, loaded.density);
    try testing.expect(loaded.vim_mode);
    try testing.expect(!loaded.reconnect_on_launch);
}

const ChangeCounter = struct {
    count: u32 = 0,

    fn onChanged(ctx: ?*anyopaque) void {
        const self: *ChangeCounter = @ptrCast(@alignCast(ctx.?));
        self.count += 1;
    }
};

test "PrefsController: every setter persists immediately and fires listeners" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pc = try PrefsController.create(testing.allocator, h.core);
    defer pc.destroy();
    var counter: ChangeCounter = .{};
    try pc.addChangeListener(&counter, ChangeCounter.onChanged);

    // With nothing set yet, the effective download dir falls back to ~/Downloads.
    var fb_buf: [1024]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, pc.effectiveDownloadDir(&fb_buf), "/Downloads"));

    // Core settings: persisted via AppCore.saveSettings → settings.zon.
    pc.setConnectionsPerSite(7);
    try testing.expectEqual(@as(u8, 7), h.core.settings.connections_per_site);
    pc.setConnectionsPerSite(99); // clamps to the 1..32 UI range
    try testing.expectEqual(@as(u8, 32), h.core.settings.connections_per_site);
    pc.setRateLimit(.download, 512 * 1024);
    pc.setRateLimit(.upload, 256 * 1024);
    const on_disk = try settings_mod.load(h.core.io, h.tmp_conf.dir, bridge.settings_file, testing.allocator);
    try testing.expectEqual(@as(u8, 32), on_disk.connections_per_site);
    try testing.expectEqual(@as(u64, 512 * 1024), on_disk.rate_limit_down);
    try testing.expectEqual(@as(u64, 256 * 1024), on_disk.rate_limit_up);

    // UI prefs: persisted via ui.zon.
    pc.setDensity(.dense);
    pc.setDateFormat(.relative);
    pc.setMonospaceLists(true);
    pc.setConfirmDelete(false);
    pc.setVimMode(true);
    pc.setReconnectOnLaunch(true);
    try pc.setDownloadDir("/tmp/relay-downloads");
    // Quit-time session snapshot (M3): persists, fires NO listener.
    try pc.setSessionState(.{
        .pane0_path = "/srv/data",
        .pane1_site = 3,
        .pane1_path = "/var/www",
        .focused_pane = 1,
        .transfers_collapsed = false,
    });
    var loaded = try loadUiPrefs(h.core.io, h.tmp_conf.dir, testing.allocator);
    defer freeUiPrefs(testing.allocator, &loaded);
    try testing.expectEqual(Density.dense, loaded.density);
    try testing.expectEqual(DateFormat.relative, loaded.date_format);
    try testing.expect(loaded.monospace_lists);
    try testing.expect(!loaded.confirm_delete);
    try testing.expect(loaded.vim_mode);
    try testing.expect(loaded.reconnect_on_launch);
    try testing.expectEqualStrings("/tmp/relay-downloads", loaded.download_dir);
    try testing.expectEqualStrings("/srv/data", loaded.session.pane0_path);
    try testing.expectEqual(@as(u64, 3), loaded.session.pane1_site);
    try testing.expectEqualStrings("/var/www", loaded.session.pane1_path);
    try testing.expectEqual(@as(u32, 1), loaded.session.focused_pane);
    try testing.expect(!loaded.session.transfers_collapsed);

    // One notification per persisted change; no-change setters are silent
    // (setSessionState is always silent — it runs on the terminate path).
    try testing.expectEqual(@as(u32, 11), counter.count);
    pc.setDensity(.dense);
    pc.setConnectionsPerSite(32);
    pc.setVimMode(true);
    pc.setReconnectOnLaunch(true);
    try testing.expectEqual(@as(u32, 11), counter.count);

    // Effective download dir honors the explicit setting.
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("/tmp/relay-downloads", pc.effectiveDownloadDir(&buf));
}

const ControlProbe = struct {
    hits: u32 = 0,
    last_sender: c.id = null,

    fn onAction(ctx: ?*anyopaque, sender: c.id) void {
        const self: *ControlProbe = @ptrCast(@alignCast(ctx.?));
        self.hits += 1;
        self.last_sender = sender;
    }
};

test "control kit: state round-trips and tag-dispatched actions (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const checkbox = controls.makeCheckbox("Ask before deleting", foundation.rect(0, 0, 200, 18));
    try testing.expect(!controls.isChecked(checkbox));
    controls.setChecked(checkbox, true);
    try testing.expect(controls.isChecked(checkbox));

    const slider = controls.makeSlider(foundation.rect(0, 0, 160, 21), 1, 32, 3);
    try testing.expectEqual(@as(f64, 3), controls.sliderValue(slider));
    controls.setSliderValue(slider, 17);
    try testing.expectEqual(@as(f64, 17), controls.sliderValue(slider));

    const field = controls.makeTextField(foundation.rect(0, 0, 60, 22), "1024");
    const text = try controls.textValue(testing.allocator, field);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("1024", text);

    const popup = controls.makePopup(foundation.rect(0, 0, 140, 25), &.{ "ISO 8601", "Relative" });
    controls.setPopupIndex(popup, 1);
    try testing.expectEqual(@as(NSInteger, 1), controls.popupIndex(popup));

    controls.setEnabled(field, false);
    try testing.expect(!controls.isEnabled(field));

    // Target/action dispatch, driven exactly as AppKit would.
    const target = try controls.ControlTarget.create(testing.allocator);
    defer target.destroy();
    var probe: ControlProbe = .{};
    try target.wire(checkbox, &probe, ControlProbe.onAction);
    target.target.msgSend(void, "relayControlChanged:", .{checkbox});
    try testing.expectEqual(@as(u32, 1), probe.hits);
    try testing.expectEqual(checkbox.value, probe.last_sender.?);
}

test {
    testing.refAllDecls(@This());
}

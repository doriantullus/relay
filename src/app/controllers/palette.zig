//! palette — the command palette (Cmd+Shift+P) and fuzzy path jump (Cmd+P):
//! one borderless floating panel (text field on top, results table below)
//! shared by both modes. Esc closes, arrows navigate, Return executes,
//! Cmd+Return runs the secondary action (path jump: target the OTHER pane).
//!
//! Candidates:
//!   • commands mode — every CommandRegistry-routed menu leaf (display
//!     title + shortcut hint right-aligned in the custom cell) plus saved
//!     sites as "Connect: <nickname>" rows.
//!   • paths mode — visited remote/local paths (the integrator feeds
//!     `recordVisit` from pane navigation; persisted via the fuzzy.Frecency
//!     store as palette.zon in the settings dir) plus the entries of the
//!     active pane's current snapshot.
//!
//! Ranking: fuzzy match score × frecency boost (src/app/fuzzy.zig).
//!
//! Integrator wiring (named commands "palette.commands"/"palette.paths"):
//!     const pal = try palette.PaletteController.create(gpa, core, commands);
//!     pal.setParentWindow(main_window);
//!     pal.setIntegration(.{ .ctx = ..., .sites = ..., .connect = ...,
//!                           .pane_state = ..., .navigate = ... });
//!     // menu leaves / key equivalents for the two named commands:
//!     //   "palette.commands" (Cmd+Shift+P) → PaletteController.showCommandsCommand
//!     //   "palette.paths"    (Cmd+P)       → PaletteController.showPathsCommand
//!     // pane navigation success: pal.recordVisit(site_id, path);

const std = @import("std");
const mac = @import("relay_mac");
const relay = @import("relay_core");
const bridge = @import("relay_ui").bridge;
const prefs = @import("prefs.zig");
const fuzzy = @import("relay_ui").fuzzy;
const shared = @import("relay_ui").palette;

// TODO(m2-dedupe): the control kit moves to relay_mac together with the copy
// in prefs.zig; this import follows it (same note as inspector.zig).
const controls = prefs.controls;

const objc = mac.objc;
const foundation = mac.foundation;
const runtime = mac.runtime;
const windowkit = mac.appkit.window;
const menu_kit = mac.appkit.menu;
const table_source = mac.appkit.table_source;

const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;

const Allocator = std.mem.Allocator;
const c = foundation.c;
const NSUInteger = foundation.NSUInteger;

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

/// Frecency store file in the settings dir (bridge config_dir).
pub const palette_file = "palette.zon";

/// Named commands the integrator binds (menu leaves / key equivalents).
pub const command_names = struct {
    pub const commands: [:0]const u8 = "palette.commands"; // Cmd+Shift+P
    pub const paths: [:0]const u8 = "palette.paths"; // Cmd+P
};

/// Adapter lookup by name ("palette.commands"/"palette.paths"); ctx for the
/// returned fn is the *PaletteController.
pub fn commandHandler(name: []const u8) ?*const fn (?*anyopaque) void {
    if (std.mem.eql(u8, name, command_names.commands)) return PaletteController.showCommandsCommand;
    if (std.mem.eql(u8, name, command_names.paths)) return PaletteController.showPathsCommand;
    return null;
}

pub const Mode = enum { commands, paths };

pub const Kind = enum {
    /// CommandRegistry dispatch.
    command,
    /// Saved site: "Connect: <nickname>".
    site,
    /// Previously visited path (frecency store).
    visited_path,
    /// Entry of the active pane's current snapshot.
    entry_path,
};

pub const Candidate = struct {
    /// Display title; what the fuzzy query matches against.
    title: []const u8,
    /// Right-aligned column (shortcut hint for commands; context for paths).
    hint: []const u8 = "",
    /// Frecency key ("" = unranked by frecency).
    key: []const u8 = "",
    kind: Kind,
    /// Valid for kind == .command.
    command: prefs.Command = .show_settings,
    /// Valid for site/path kinds (0 = local).
    site_id: u64 = 0,
    /// Navigation target for path kinds.
    path: []const u8 = "",
};

/// Visible result rows (the panel shows at most this many).
pub const max_results: usize = 12;

// ---------------------------------------------------------------------------
// Shortcut hint formatting (headless).
// ---------------------------------------------------------------------------

const KeySymbol = struct { key: []const u8, symbol: []const u8 };
const key_symbols = [_]KeySymbol{
    .{ .key = menu_kit.Keys.up, .symbol = "↑" },
    .{ .key = menu_kit.Keys.down, .symbol = "↓" },
    .{ .key = menu_kit.Keys.left, .symbol = "←" },
    .{ .key = menu_kit.Keys.right, .symbol = "→" },
    .{ .key = menu_kit.Keys.backspace, .symbol = "⌫" },
    .{ .key = menu_kit.Keys.delete_forward, .symbol = "⌦" },
    .{ .key = menu_kit.Keys.escape, .symbol = "⎋" },
    .{ .key = menu_kit.Keys.ret, .symbol = "↩" },
    .{ .key = menu_kit.Keys.tab, .symbol = "⇥" },
};

/// "⇧⌘P"-style hint for a menu shortcut; "" when the leaf has no key.
/// Modifier order follows the Apple convention: ⌃ ⌥ ⇧ ⌘.
pub fn shortcutHint(buf: []u8, key: []const u8, mods: menu_kit.Modifiers) []const u8 {
    if (key.len == 0) return "";
    var w: std.Io.Writer = .fixed(buf);
    const sym = blk: {
        for (key_symbols) |entry| {
            if (std.mem.eql(u8, entry.key, key)) break :blk entry.symbol;
        }
        break :blk key;
    };
    out: {
        if (mods.control) w.writeAll("⌃") catch break :out;
        if (mods.option) w.writeAll("⌥") catch break :out;
        if (mods.shift) w.writeAll("⇧") catch break :out;
        if (mods.command) w.writeAll("⌘") catch break :out;
        if (sym.len == 1 and std.ascii.isLower(sym[0])) {
            w.writeByte(std.ascii.toUpper(sym[0])) catch break :out;
        } else {
            w.writeAll(sym) catch break :out;
        }
    }
    return w.buffered();
}

// ---------------------------------------------------------------------------
// Model — shared from relay_ui.
// ---------------------------------------------------------------------------

pub const Model = shared.Model(Candidate, max_results);

// ---------------------------------------------------------------------------
// Integration hooks (set by the phase-3 integrator; all main thread).
// ---------------------------------------------------------------------------

/// Active-pane state for paths mode. Everything is borrowed for the
/// duration of the `pane_state` call (the model deep-copies).
pub const PaneState = struct {
    /// 0 = local pane.
    site_id: u64 = 0,
    /// Current (normalized) directory; "" = nothing listed yet.
    path: []const u8 = "",
    entries: []const vfs_mod.Entry = &.{},
};

pub const SiteSink = struct {
    model: *Model,
    err: ?error{OutOfMemory} = null,

    /// Add one saved site ("Connect: <nickname>"); strings borrowed.
    pub fn add(self: *SiteSink, site_id: u64, nickname: []const u8) void {
        var title_buf: [192]u8 = undefined;
        var key_buf: [32]u8 = undefined;
        const title = std.fmt.bufPrint(&title_buf, "Connect: {s}", .{nickname}) catch
            return; // absurd nickname length: skip the row
        const key = std.fmt.bufPrint(&key_buf, "site:{d}", .{site_id}) catch unreachable;
        self.model.add(.{
            .title = title,
            .key = key,
            .kind = .site,
            .site_id = site_id,
        }) catch |err| {
            self.err = err;
        };
    }
};

pub const Integration = struct {
    ctx: ?*anyopaque = null,
    /// Enumerate saved sites into the sink (commands mode).
    sites: ?*const fn (ctx: ?*anyopaque, sink: *SiteSink) void = null,
    /// Connect a saved site ("Connect: <nickname>" executed).
    connect: ?*const fn (ctx: ?*anyopaque, site_id: u64) void = null,
    /// Active-pane state for paths mode.
    pane_state: ?*const fn (ctx: ?*anyopaque) PaneState = null,
    /// Navigate to `path` on `site_id`; `other` = target the inactive pane
    /// (Cmd+Return), else the active one.
    navigate: ?*const fn (ctx: ?*anyopaque, other: bool, site_id: u64, path: []const u8) void = null,
};

// ---------------------------------------------------------------------------
// PaletteController
// ---------------------------------------------------------------------------

// Panel geometry (fixed; the panel does not resize).
pub const panel_w: f64 = 560;
pub const panel_h: f64 = 404;
const pad: f64 = 10;
const field_h: f64 = 28;
/// Vertical offset of the panel's top below the parent window's top.
const top_offset: f64 = 96;

const ns_event_type_key_down: NSUInteger = 10;

pub const PaletteController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    commands: *prefs.CommandRegistry,
    integration: Integration = .{},
    model: Model,
    frecency: fuzzy.Frecency,
    mode: Mode = .commands,
    query: std.ArrayList(u8) = .empty,

    /// Observability (tests + smoke).
    executes: u64 = 0,

    // UI state; valid only when `built`. Built lazily on first show() so
    // headless tests never touch panel state.
    built: bool = false,
    panel: windowkit.Window = undefined,
    field: objc.Object = undefined,
    table: *table_source.TableView = undefined,
    parent: ?windowkit.Window = null,

    pub fn create(
        gpa: Allocator,
        core: *bridge.AppCore,
        commands: *prefs.CommandRegistry,
    ) error{OutOfMemory}!*PaletteController {
        const self = try gpa.create(PaletteController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .commands = commands,
            .model = Model.init(gpa),
            .frecency = fuzzy.Frecency.init(gpa),
        };
        errdefer self.model.deinit();
        errdefer self.frecency.deinit();
        try self.frecency.load(core.io, core.config_dir, palette_file);
        return self;
    }

    pub fn destroy(self: *PaletteController) void {
        if (self.built) {
            self.table.deinit();
            self.panel.release();
        }
        self.query.deinit(self.gpa);
        self.frecency.deinit();
        self.model.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    pub fn setIntegration(self: *PaletteController, integration: Integration) void {
        self.integration = integration;
    }

    /// Main window: the palette floats centered near its top edge.
    pub fn setParentWindow(self: *PaletteController, window: windowkit.Window) void {
        self.parent = window;
    }

    fn nowSeconds(self: *const PaletteController) i64 {
        const ts = std.Io.Clock.real.now(self.core.io);
        return @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
    }

    // ------------------------------------------------------------------ //
    // Visit log (the integrator calls this from pane navigation success).

    pub fn recordVisit(self: *PaletteController, site_id: u64, path: []const u8) void {
        if (path.len == 0) return;
        const key = std.fmt.allocPrint(self.gpa, "path:{d}:{s}", .{ site_id, path }) catch return;
        defer self.gpa.free(key);
        self.frecency.bump(key, self.nowSeconds()) catch return;
        self.persistFrecency();
    }

    fn persistFrecency(self: *PaletteController) void {
        self.frecency.save(self.core.io, self.core.config_dir, palette_file) catch |err| {
            std.log.warn("palette: could not persist {s}: {t}", .{ palette_file, err });
        };
    }

    // ------------------------------------------------------------------ //
    // Candidate building (headless; show() calls prepare + the UI bits).

    /// Rebuild the candidate list for `mode` and reset the query/ranking.
    pub fn prepare(self: *PaletteController, mode: Mode) error{OutOfMemory}!void {
        self.mode = mode;
        self.model.reset();
        switch (mode) {
            .commands => try self.buildCommandCandidates(),
            .paths => try self.buildPathCandidates(),
        }
        self.query.clearRetainingCapacity();
        self.model.filter("", &self.frecency, self.nowSeconds());
    }

    fn buildCommandCandidates(self: *PaletteController) error{OutOfMemory}!void {
        try self.addCommandLeaf(prefs.settings_leaf);
        for (prefs.menu_bar) |def| try self.addMenuNodes(def.items);
        if (self.integration.sites) |sites_fn| {
            var sink: SiteSink = .{ .model = &self.model };
            sites_fn(self.integration.ctx, &sink);
            if (sink.err) |err| return err;
        }
    }

    fn addMenuNodes(self: *PaletteController, nodes: []const prefs.MenuNode) error{OutOfMemory}!void {
        for (nodes) |node| switch (node) {
            .separator => {},
            .leaf => |leaf| try self.addCommandLeaf(leaf),
            .submenu => |sub| try self.addMenuNodes(sub.items),
        };
    }

    fn addCommandLeaf(self: *PaletteController, leaf: prefs.MenuLeaf) error{OutOfMemory}!void {
        const command = switch (leaf.action) {
            .cmd => |command| command,
            else => return, // responder-chain selectors are not palette rows
        };
        var hint_buf: [32]u8 = undefined;
        var key_buf: [192]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "cmd:{s}", .{leaf.title}) catch "";
        try self.model.add(.{
            .title = leaf.title,
            .hint = shortcutHint(&hint_buf, leaf.key, leaf.mods),
            .key = key,
            .kind = .command,
            .command = command,
        });
    }

    fn buildPathCandidates(self: *PaletteController) error{OutOfMemory}!void {
        // Visited paths from the frecency store ("path:<site>:<path>").
        for (self.frecency.map.keys()) |key| {
            const parsed = parsePathKey(key) orelse continue;
            try self.model.add(.{
                .title = parsed.path,
                .hint = if (parsed.site_id == 0) "local" else "remote",
                .key = key,
                .kind = .visited_path,
                .site_id = parsed.site_id,
                .path = parsed.path,
            });
        }

        // Entries of the active pane's current snapshot.
        const state_fn = self.integration.pane_state orelse return;
        const state = state_fn(self.integration.ctx);
        if (state.path.len == 0) return;
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena.deinit();
        var key_buf: [1024]u8 = undefined;
        for (state.entries) |entry| {
            const full = path_mod.join(arena.allocator(), state.path, entry.name) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.InvalidPath => continue, // garbled name: skip
                };
            const is_dir = entry.kind == .dir;
            // Files navigate to their enclosing dir (= the current path).
            const target = if (is_dir) full else state.path;
            const key = std.fmt.bufPrint(&key_buf, "path:{d}:{s}", .{ state.site_id, target }) catch "";
            if (key.len > 0 and self.model.hasKey(key)) continue; // already a visited row
            try self.model.add(.{
                .title = full,
                .hint = if (is_dir) "folder" else "file",
                .key = key,
                .kind = .entry_path,
                .site_id = state.site_id,
                .path = target,
            });
        }
    }

    const PathKey = struct { site_id: u64, path: []const u8 };

    fn parsePathKey(key: []const u8) ?PathKey {
        const prefix = "path:";
        if (!std.mem.startsWith(u8, key, prefix)) return null;
        const rest = key[prefix.len..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        const site_id = std.fmt.parseInt(u64, rest[0..colon], 10) catch return null;
        const path = rest[colon + 1 ..];
        if (path.len == 0) return null;
        return .{ .site_id = site_id, .path = path };
    }

    // ------------------------------------------------------------------ //
    // Query + ranking

    /// Replace the query and re-rank (UI reload when built).
    pub fn setQuery(self: *PaletteController, text: []const u8) error{OutOfMemory}!void {
        self.query.clearRetainingCapacity();
        try self.query.appendSlice(self.gpa, text);
        self.runFilter();
    }

    fn runFilter(self: *PaletteController) void {
        self.model.filter(self.query.items, &self.frecency, self.nowSeconds());
        if (self.built) {
            self.table.reloadData();
            if (self.model.resultCount() > 0) {
                self.table.setSelectedRows(&.{0});
                self.table.scrollRowToVisible(0);
            } else {
                self.table.setSelectedRows(&.{});
            }
        }
    }

    pub fn resultCount(self: *const PaletteController) usize {
        return self.model.resultCount();
    }

    pub fn resultAt(self: *const PaletteController, row: usize) ?*const Candidate {
        return self.model.resultAt(row);
    }

    // ------------------------------------------------------------------ //
    // Execution

    /// Run result `row`. `secondary` = Cmd+Return (path jump: the other
    /// pane; commands/sites: same as Return).
    pub fn executeResult(self: *PaletteController, row: usize, secondary: bool) void {
        const cand = self.model.resultAt(row) orelse return;
        self.executes += 1;
        if (cand.key.len > 0) {
            self.frecency.bump(cand.key, self.nowSeconds()) catch {};
            self.persistFrecency();
        }
        // Candidate strings live in the model arena: stable until the next
        // prepare(), so handing them to the hooks below is safe.
        switch (cand.kind) {
            .command => _ = self.commands.dispatch(cand.command),
            .site => if (self.integration.connect) |connect_fn| {
                connect_fn(self.integration.ctx, cand.site_id);
            },
            .visited_path, .entry_path => if (self.integration.navigate) |navigate_fn| {
                navigate_fn(self.integration.ctx, secondary, cand.site_id, cand.path);
            },
        }
        if (self.built) self.close();
    }

    fn executeSelected(self: *PaletteController, secondary: bool) void {
        if (self.model.resultCount() == 0) return;
        const row = if (self.built) (self.table.selectedRow() orelse 0) else 0;
        self.executeResult(row, secondary);
    }

    // ------------------------------------------------------------------ //
    // Named-command adapters ("palette.commands"/"palette.paths").

    pub fn showCommands(self: *PaletteController) void {
        self.show(.commands);
    }

    pub fn showPaths(self: *PaletteController) void {
        self.show(.paths);
    }

    /// commands.bind(<palette.commands leaf>, pal, showCommandsCommand).
    pub fn showCommandsCommand(ctx: ?*anyopaque) void {
        const self: *PaletteController = @ptrCast(@alignCast(ctx.?));
        self.showCommands();
    }

    /// commands.bind(<palette.paths leaf>, pal, showPathsCommand).
    pub fn showPathsCommand(ctx: ?*anyopaque) void {
        const self: *PaletteController = @ptrCast(@alignCast(ctx.?));
        self.showPaths();
    }

    // ------------------------------------------------------------------ //
    // Panel UI

    pub fn show(self: *PaletteController, mode: Mode) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        self.prepare(mode) catch return;
        self.ensureBuilt() catch return;
        controls.setTextValue(self.field, "");
        self.runFilter();
        self.position();
        self.panel.makeKeyAndOrderFront();
        _ = self.panel.makeFirstResponder(self.field);
    }

    pub fn close(self: *PaletteController) void {
        if (!self.built) return;
        self.panel.orderOut();
        if (self.parent) |p| p.makeKeyAndOrderFront();
    }

    pub fn isVisible(self: *PaletteController) bool {
        return self.built and self.panel.isVisible();
    }

    fn position(self: *PaletteController) void {
        const p = self.parent orelse {
            self.panel.center();
            return;
        };
        const pf = p.frame();
        const x = pf.origin.x + (pf.size.width - panel_w) / 2;
        var y = pf.origin.y + pf.size.height - top_offset - panel_h;
        if (y < pf.origin.y) y = pf.origin.y;
        self.panel.setFrameOrigin(foundation.point(x, y));
    }

    fn ensureBuilt(self: *PaletteController) error{OutOfMemory}!void {
        if (self.built) return;

        self.panel = windowkit.Window.createWithClass(
            palettePanelClass().class,
            foundation.rect(0, 0, panel_w, panel_h),
            windowkit.StyleMask.borderless | windowkit.StyleMask.nonactivating_panel,
        );
        errdefer self.panel.release();
        palettePanelClass().attach(self.panel.obj.value, self);
        self.panel.setLevel(windowkit.level_floating);

        const content = self.panel.contentView();
        self.field = controls.makeTextField(
            foundation.rect(pad, panel_h - pad - field_h, panel_w - 2 * pad, field_h),
            "",
        );
        controls.addSubview(content, self.field);

        self.table = try table_source.TableView.init(self.gpa, .{
            .columns = &.{
                .{ .id = "title", .title = "Title", .width = 430, .min_width = 200 },
                .{ .id = "hint", .title = "Hint", .width = 96, .min_width = 60, .alignment = .right },
            },
            .data_source = .{
                .ctx = self,
                .rowCount = dsRowCount,
                .cellText = dsCellText,
                .doubleAction = dsDoubleAction,
                .returnAction = dsReturnAction,
                .keyDown = dsKeyDown,
            },
            .density = .comfortable,
            .allows_multiple_selection = false,
            .header_visible = false,
        });
        setViewFrame(
            objc.Object.fromId(self.table.view()),
            foundation.rect(pad, pad, panel_w - 2 * pad, panel_h - field_h - 3 * pad),
        );
        controls.addSubview(content, objc.Object.fromId(self.table.view()));

        self.built = true;
    }

    // --- key handling (panel sendEvent: hook) -----------------------------

    /// True = consumed (never reaches the field editor / table).
    fn handleKey(self: *PaletteController, ev: table_source.KeyEvent) bool {
        switch (ev.key_code) {
            table_source.key_escape => {
                self.close();
                return true;
            },
            table_source.key_up_arrow => {
                self.moveSelection(-1);
                return true;
            },
            table_source.key_down_arrow => {
                self.moveSelection(1);
                return true;
            },
            table_source.key_return, table_source.key_keypad_enter => {
                self.executeSelected(ev.command);
                return true;
            },
            else => return false,
        }
    }

    fn moveSelection(self: *PaletteController, delta: i64) void {
        const n = self.model.resultCount();
        if (n == 0 or !self.built) return;
        const cur: i64 = if (self.table.selectedRow()) |row| @intCast(row) else -1;
        var next = cur + delta;
        if (next < 0) next = 0;
        if (next > @as(i64, @intCast(n - 1))) next = @intCast(n - 1);
        const row: usize = @intCast(next);
        self.table.setSelectedRows(&.{row});
        self.table.scrollRowToVisible(row);
    }

    /// After the field editor processed a key: adopt the field text as the
    /// query when it changed (covers typing, backspace and Cmd+V).
    fn syncQueryFromField(self: *PaletteController) void {
        if (!self.built) return;
        const text = controls.textValue(self.gpa, self.field) catch return;
        defer self.gpa.free(text);
        if (std.mem.eql(u8, text, self.query.items)) return;
        self.setQuery(text) catch {};
    }

    // --- table_source.DataSource vtable ------------------------------------

    fn dsRowCount(ctx: *anyopaque) usize {
        const self: *PaletteController = @ptrCast(@alignCast(ctx));
        return self.model.resultCount();
    }

    fn dsCellText(ctx: *anyopaque, row: usize, col: usize, buf: []u8) []const u8 {
        const self: *PaletteController = @ptrCast(@alignCast(ctx));
        const cand = self.model.resultAt(row) orelse return buf[0..0];
        const text = switch (col) {
            0 => cand.title,
            1 => cand.hint,
            else => "",
        };
        var n = @min(text.len, buf.len);
        // Never split a UTF-8 sequence when truncating.
        while (n > 0 and n < text.len and (text[n] & 0xC0) == 0x80) n -= 1;
        @memcpy(buf[0..n], text[0..n]);
        return buf[0..n];
    }

    fn dsDoubleAction(ctx: *anyopaque, row: ?usize) void {
        const self: *PaletteController = @ptrCast(@alignCast(ctx));
        self.executeResult(row orelse return, false);
    }

    fn dsReturnAction(ctx: *anyopaque, row: ?usize) void {
        const self: *PaletteController = @ptrCast(@alignCast(ctx));
        self.executeResult(row orelse return, false);
    }

    fn dsKeyDown(ctx: *anyopaque, ev: table_source.KeyEvent) bool {
        const self: *PaletteController = @ptrCast(@alignCast(ctx));
        // Table focused (mouse click): Esc still closes, Cmd+Return still
        // runs the secondary action; plain Return rides returnAction.
        if (ev.key_code == table_source.key_escape) {
            self.close();
            return true;
        }
        if ((ev.key_code == table_source.key_return or
            ev.key_code == table_source.key_keypad_enter) and ev.command)
        {
            self.executeSelected(true);
            return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Palette panel helper — a generic key-grabbing floating panel built from
// relay_mac primitives (runtime.defineClass + window wrappers).
//
// TODO(m2-dedupe): the raw selector sends in this section (NSEvent
// accessors, sendEvent: super-call, setFrame:) belong in relay_mac once an
// appkit/controls.zig exists; kept here under the prefs.zig `controls`
// precedent. Nothing outside this section sends raw selectors.
// ---------------------------------------------------------------------------

var g_panel_class: ?runtime.DefinedClass = null;

/// NSPanel subclass: borderless panels refuse key status, so
/// canBecomeKeyWindow is overridden; sendEvent: routes key-downs through
/// PaletteController.handleKey before AppKit sees them.
fn palettePanelClass() runtime.DefinedClass {
    if (g_panel_class) |dc| return dc;
    const dc = runtime.defineClass("RelayPalettePanel", "NSPanel", &.{}, .{
        .{ "canBecomeKeyWindow", panelCanBecomeKey },
        .{ "sendEvent:", panelSendEvent },
    }) catch @panic("palette: failed to define RelayPalettePanel");
    g_panel_class = dc;
    return dc;
}

fn panelCanBecomeKey(_: c.id, _: c.SEL) callconv(.c) foundation.BOOL {
    return foundation.YES;
}

fn panelSendEvent(target: c.id, _: c.SEL, event_id: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const self = palettePanelClass().state(PaletteController, target);
    const event = objc.Object.fromId(event_id);
    const event_type = event.msgSend(NSUInteger, "type", .{});

    if (event_type == ns_event_type_key_down) {
        const key_code: u16 = event.msgSend(c_ushort, "keyCode", .{});
        const flags = event.msgSend(NSUInteger, "modifierFlags", .{});
        var chars_buf: [16]u8 = undefined;
        var chars: []const u8 = chars_buf[0..0];
        if (event.msgSend(c.id, "characters", .{})) |chars_ns| {
            const utf8 = objc.Object.fromId(chars_ns).msgSend([*:0]const u8, "UTF8String", .{});
            const span = std.mem.span(utf8);
            const n = @min(span.len, chars_buf.len);
            @memcpy(chars_buf[0..n], span[0..n]);
            chars = chars_buf[0..n];
        }
        if (self.handleKey(table_source.keyEventFrom(key_code, flags, chars))) return;
    }

    objc.Object.fromId(target).msgSendSuper(
        foundation.class("NSPanel"),
        void,
        "sendEvent:",
        .{event_id},
    );
    // The field editor consumed the key: adopt the new text as the query.
    if (event_type == ns_event_type_key_down) self.syncQueryFromField();
}

fn setViewFrame(view: objc.Object, frame: foundation.NSRect) void {
    view.msgSend(void, "setFrame:", .{frame});
}

// ---------------------------------------------------------------------------
// Tests — headless: hint formatting, candidate ranking end-to-end against a
// real CommandRegistry, path candidates + recordVisit frecency round-trip,
// and the built panel's key plumbing (never ordered on screen).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "shortcut hint formatting" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("⌘K", shortcutHint(&buf, "k", .{}));
    try testing.expectEqualStrings("⇧⌘P", shortcutHint(&buf, "p", .{ .shift = true }));
    try testing.expectEqualStrings("⌥⌘S", shortcutHint(&buf, "s", .{ .option = true }));
    try testing.expectEqualStrings(
        "⌃⌥⇧⌘X",
        shortcutHint(&buf, "x", .{ .control = true, .option = true, .shift = true }),
    );
    try testing.expectEqualStrings("⌘↑", shortcutHint(&buf, menu_kit.Keys.up, .{}));
    try testing.expectEqualStrings("⌘⌫", shortcutHint(&buf, menu_kit.Keys.backspace, .{}));
    try testing.expectEqualStrings("⌘↩", shortcutHint(&buf, menu_kit.Keys.ret, .{}));
    try testing.expectEqualStrings("⇧⌘.", shortcutHint(&buf, ".", .{ .shift = true }));
    try testing.expectEqualStrings("", shortcutHint(&buf, "", .{}));

    // Tiny buffer: degrades to whatever fits, never crashes.
    var tiny: [2]u8 = undefined;
    _ = shortcutHint(&tiny, "k", .{ .shift = true });
}

test "command handler lookup by name" {
    try testing.expectEqual(
        @as(?*const fn (?*anyopaque) void, PaletteController.showCommandsCommand),
        commandHandler("palette.commands"),
    );
    try testing.expectEqual(
        @as(?*const fn (?*anyopaque) void, PaletteController.showPathsCommand),
        commandHandler("palette.paths"),
    );
    try testing.expectEqual(@as(?*const fn (?*anyopaque) void, null), commandHandler("palette.nope"));
}

// Mirror of inspector.zig's TestHarness (the bridge's is not pub).
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

const FakeIntegration = struct {
    connect_calls: u64 = 0,
    last_connect_site: u64 = 0,
    navigate_calls: u64 = 0,
    last_navigate_other: bool = false,
    last_navigate_site: u64 = 0,
    last_navigate_path: [256]u8 = undefined,
    last_navigate_path_len: usize = 0,
    pane: PaneState = .{},

    fn lastNavigatePath(f: *const FakeIntegration) []const u8 {
        return f.last_navigate_path[0..f.last_navigate_path_len];
    }

    fn integration(f: *FakeIntegration) Integration {
        return .{
            .ctx = f,
            .sites = sites,
            .connect = connect,
            .pane_state = paneState,
            .navigate = navigate,
        };
    }

    fn sites(ctx: ?*anyopaque, sink: *SiteSink) void {
        _ = ctx;
        sink.add(7, "prod-web");
        sink.add(9, "staging");
    }

    fn connect(ctx: ?*anyopaque, site_id: u64) void {
        const f: *FakeIntegration = @ptrCast(@alignCast(ctx.?));
        f.connect_calls += 1;
        f.last_connect_site = site_id;
    }

    fn paneState(ctx: ?*anyopaque) PaneState {
        const f: *FakeIntegration = @ptrCast(@alignCast(ctx.?));
        return f.pane;
    }

    fn navigate(ctx: ?*anyopaque, other: bool, site_id: u64, path: []const u8) void {
        const f: *FakeIntegration = @ptrCast(@alignCast(ctx.?));
        f.navigate_calls += 1;
        f.last_navigate_other = other;
        f.last_navigate_site = site_id;
        const n = @min(path.len, f.last_navigate_path.len);
        @memcpy(f.last_navigate_path[0..n], path[0..n]);
        f.last_navigate_path_len = n;
    }
};

var g_dispatched: std.enums.EnumArray(prefs.Command, u32) = undefined;

fn countingHandler(comptime cmd: prefs.Command) *const fn (?*anyopaque) void {
    return struct {
        fn run(_: ?*anyopaque) void {
            g_dispatched.set(cmd, g_dispatched.get(cmd) + 1);
        }
    }.run;
}

fn findResult(pal: *PaletteController, title: []const u8) ?usize {
    var i: usize = 0;
    while (i < pal.resultCount()) : (i += 1) {
        if (std.mem.eql(u8, pal.resultAt(i).?.title, title)) return i;
    }
    return null;
}

test "command palette: ranking + dispatch end-to-end with a fake registry" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const reg = try prefs.CommandRegistry.create(testing.allocator);
    defer reg.destroy();
    g_dispatched = .initFill(0);
    reg.bind(.connect_server, null, countingHandler(.connect_server));
    reg.bind(.toggle_hidden, null, countingHandler(.toggle_hidden));

    var fake: FakeIntegration = .{};
    const pal = try PaletteController.create(testing.allocator, h.core, reg);
    defer pal.destroy();
    pal.setIntegration(fake.integration());

    // Candidates: every command leaf of the menu tree + the two sites.
    try pal.prepare(.commands);
    var n_commands: usize = 0;
    var n_sites: usize = 0;
    for (pal.model.candidates.items) |cand| switch (cand.kind) {
        .command => n_commands += 1,
        .site => n_sites += 1,
        else => {},
    };
    try testing.expect(n_commands > 20); // the whole docs/UX.md command set
    try testing.expectEqual(@as(usize, 2), n_sites);

    // The Connect leaf carries its shortcut hint for the right column.
    try pal.setQuery("connect to server");
    try testing.expect(pal.resultCount() >= 1);
    const connect_row = pal.resultAt(0).?;
    try testing.expectEqualStrings("Connect to Server…", connect_row.title);
    try testing.expectEqualStrings("⌘K", connect_row.hint);

    // Fuzzy subsequence: "tgh" hits "Toggle Hidden Files".
    try pal.setQuery("tghidden");
    try testing.expect(findResult(pal, "Toggle Hidden Files") != null);

    // Execute dispatches through the registry and bumps frecency.
    try pal.setQuery("connect to server");
    pal.executeResult(0, false);
    try testing.expectEqual(@as(u32, 1), g_dispatched.get(.connect_server));
    try testing.expectEqual(@as(u64, 1), pal.executes);
    try testing.expect(pal.frecency.get("cmd:Connect to Server…") != null);

    // Saved sites surface as "Connect: <nickname>" with a connect action.
    try pal.setQuery("staging");
    const site_row = findResult(pal, "Connect: staging").?;
    pal.executeResult(site_row, false);
    try testing.expectEqual(@as(u64, 1), fake.connect_calls);
    try testing.expectEqual(@as(u64, 9), fake.last_connect_site);

    // Frecency reorder: repeated use floats a row over an equal match.
    try pal.prepare(.commands);
    try pal.setQuery("connect");
    const before = findResult(pal, "Connect: prod-web").?;
    try testing.expect(before > 0); // ties break by menu order first
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        const row = findResult(pal, "Connect: prod-web").?;
        pal.executeResult(row, false);
        try pal.setQuery("connect");
    }
    try testing.expectEqual(@as(usize, 0), findResult(pal, "Connect: prod-web").?);
}

test "path jump: visited paths + snapshot entries, Return/Cmd+Return targets" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const reg = try prefs.CommandRegistry.create(testing.allocator);
    defer reg.destroy();

    var fake: FakeIntegration = .{};
    fake.pane = .{
        .site_id = 7,
        .path = "/srv",
        .entries = &.{
            .{ .name = "www", .kind = .dir },
            .{ .name = "notes.txt", .kind = .file, .size = 12 },
        },
    };

    const pal = try PaletteController.create(testing.allocator, h.core, reg);
    defer pal.destroy();
    pal.setIntegration(fake.integration());

    pal.recordVisit(7, "/var/www/html");
    pal.recordVisit(0, "/Users/relay/Downloads");

    try pal.prepare(.paths);
    try testing.expect(findResult(pal, "/var/www/html") != null);
    try testing.expect(findResult(pal, "/Users/relay/Downloads") != null);
    try testing.expect(findResult(pal, "/srv/www") != null);
    try testing.expect(findResult(pal, "/srv/notes.txt") != null);

    const visited = pal.resultAt(findResult(pal, "/var/www/html").?).?;
    try testing.expectEqual(Kind.visited_path, visited.kind);
    try testing.expectEqualStrings("remote", visited.hint);
    const local = pal.resultAt(findResult(pal, "/Users/relay/Downloads").?).?;
    try testing.expectEqualStrings("local", local.hint);

    // Fuzzy query narrows; Return navigates the active pane.
    try pal.setQuery("html");
    try testing.expect(pal.resultCount() >= 1);
    try testing.expectEqualStrings("/var/www/html", pal.resultAt(0).?.title);
    pal.executeResult(0, false);
    try testing.expectEqual(@as(u64, 1), fake.navigate_calls);
    try testing.expect(!fake.last_navigate_other);
    try testing.expectEqual(@as(u64, 7), fake.last_navigate_site);
    try testing.expectEqualStrings("/var/www/html", fake.lastNavigatePath());

    // Snapshot dir entry: full path; Cmd+Return targets the other pane.
    try pal.prepare(.paths);
    try pal.setQuery("srv/www");
    const dir_row = findResult(pal, "/srv/www").?;
    pal.executeResult(dir_row, true);
    try testing.expect(fake.last_navigate_other);
    try testing.expectEqualStrings("/srv/www", fake.lastNavigatePath());

    // File entries navigate to their enclosing dir.
    try pal.prepare(.paths);
    const file_row = findResult(pal, "/srv/notes.txt").?;
    pal.executeResult(file_row, false);
    try testing.expectEqualStrings("/srv", fake.lastNavigatePath());

    // Visited dirs that are also snapshot entries are deduped by key.
    pal.recordVisit(7, "/srv/www");
    try pal.prepare(.paths);
    var hits: usize = 0;
    for (pal.model.candidates.items) |cand| {
        if (std.mem.eql(u8, cand.title, "/srv/www")) hits += 1;
    }
    try testing.expectEqual(@as(usize, 1), hits);
}

test "recordVisit persists: a fresh controller sees the visited paths" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const reg = try prefs.CommandRegistry.create(testing.allocator);
    defer reg.destroy();

    {
        const pal = try PaletteController.create(testing.allocator, h.core, reg);
        defer pal.destroy();
        pal.recordVisit(3, "/data/incoming");
        pal.recordVisit(3, "/data/incoming");
        pal.recordVisit(0, "/tmp");
    }

    const pal2 = try PaletteController.create(testing.allocator, h.core, reg);
    defer pal2.destroy();
    try testing.expectEqual(@as(u32, 2), pal2.frecency.get("path:3:/data/incoming").?.count);
    try pal2.prepare(.paths);
    try testing.expect(findResult(pal2, "/data/incoming") != null);
    try testing.expect(findResult(pal2, "/tmp") != null);
}

test "panel key plumbing: build headless, arrows/Return/Esc (never on screen)" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const reg = try prefs.CommandRegistry.create(testing.allocator);
    defer reg.destroy();
    g_dispatched = .initFill(0);
    reg.bind(.refresh, null, countingHandler(.refresh));

    var fake: FakeIntegration = .{};
    const pal = try PaletteController.create(testing.allocator, h.core, reg);
    defer pal.destroy();
    pal.setIntegration(fake.integration());

    try pal.prepare(.commands);
    try pal.ensureBuilt();
    try testing.expect(pal.built);
    pal.runFilter();

    // Table reflects the ranked rows through the data source.
    try testing.expectEqual(pal.resultCount(), PaletteController.dsRowCount(pal));
    var buf: [512]u8 = undefined;
    const cell = PaletteController.dsCellText(pal, 0, 0, &buf);
    try testing.expectEqualStrings(pal.resultAt(0).?.title, cell);

    // Type a query through the real field + sync path.
    controls.setTextValue(pal.field, "refresh");
    pal.syncQueryFromField();
    try testing.expectEqualStrings("refresh", pal.query.items);
    try testing.expect(pal.resultCount() >= 1);
    try testing.expectEqualStrings("Refresh", pal.resultAt(0).?.title);

    // Arrow keys move the table selection; clamped at both ends.
    try pal.setQuery("");
    try testing.expect(pal.resultCount() > 2);
    try testing.expectEqual(@as(?usize, 0), pal.table.selectedRow());
    try testing.expect(pal.handleKey(.{ .key_code = table_source.key_down_arrow, .chars = "" }));
    try testing.expectEqual(@as(?usize, 1), pal.table.selectedRow());
    try testing.expect(pal.handleKey(.{ .key_code = table_source.key_up_arrow, .chars = "" }));
    try testing.expect(pal.handleKey(.{ .key_code = table_source.key_up_arrow, .chars = "" }));
    try testing.expectEqual(@as(?usize, 0), pal.table.selectedRow());

    // Return executes the selected row through the registry.
    try pal.setQuery("refresh");
    try testing.expect(pal.handleKey(.{ .key_code = table_source.key_return, .chars = "\r" }));
    try testing.expectEqual(@as(u32, 1), g_dispatched.get(.refresh));

    // Esc is consumed (close on a never-shown panel is a no-op orderOut).
    try testing.expect(pal.handleKey(.{ .key_code = table_source.key_escape, .chars = "" }));
    try testing.expect(!pal.isVisible());

    // Unhandled keys fall through to the field editor.
    try testing.expect(!pal.handleKey(.{ .key_code = table_source.key_space, .chars = " " }));
}

// Visual smoke (GUI testing policy): RELAY_VISUAL_SMOKE=1 orders the palette
// onto the screen for ~1.5s over a host window. Skipped headless.
test "visual smoke: palette panel appears over a host window" {
    if (std.c.getenv("RELAY_VISUAL_SMOKE") == null) return error.SkipZigTest;

    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const app = windowkit.App.shared();
    app.setRegularActivationPolicy();
    app.activate();

    const reg = try prefs.CommandRegistry.create(testing.allocator);
    defer reg.destroy();
    const pal = try PaletteController.create(testing.allocator, h.core, reg);
    defer pal.destroy();

    const host = windowkit.Window.create(
        foundation.rect(0, 0, 900, 600),
        "Palette Host",
        windowkit.StyleMask.standard,
    );
    defer host.release();
    host.center();
    host.makeKeyAndOrderFront();
    pal.setParentWindow(host);

    pal.show(.commands);
    try testing.expect(pal.isVisible());
    h.core.io.sleep(.fromMilliseconds(1500), .awake) catch {};
    pal.close();
}

test {
    testing.refAllDecls(@This());
}

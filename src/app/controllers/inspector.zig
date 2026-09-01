//! inspector — the trailing info panel (Cmd+I, M2: simple panel per
//! docs/UX.md): selection name(s)/kind/size sum fed live from the pane
//! selection callback, the full path (copyable), and the permissions editor
//! for remote selections — octal field <-> 9 rwx checkboxes (two-way sync),
//! Apply → bridge chmod (optimistic: the bridge re-lists on success;
//! refusals surface as an NSAlert sheet). Multi-select applies to all.
//!
//! Phase 3 wiring sketch:
//!     const insp = try inspector.InspectorController.create(gpa, core);
//!     insp.setParentWindow(main_window);
//!     commands.bind(.toggle_inspector, insp, InspectorController.toggleCommand);
//!     // browser pane selection callback:
//!     try insp.setSelection(.{ .pane_token = t, .site_id = id, .items = items });
//!     // embed insp.view() as the trailing split child.

const std = @import("std");
const mac = @import("relay_mac");
const bridge = @import("relay_ui").bridge;
const model = @import("relay_ui").inspector;
const prefs = @import("prefs.zig");

// TODO(m2-dedupe): the control kit moves to relay_mac together with the copy
// in prefs.zig; this import follows it.
const controls = prefs.controls;

const objc = mac.objc;
const foundation = mac.foundation;
const runtime = mac.runtime;
const windowkit = mac.appkit.window;
const panels = mac.appkit.panels;

const Allocator = std.mem.Allocator;
const c = foundation.c;

// ---------------------------------------------------------------------------
// Selection vocabulary (filled by the browser's selection callback).
// ---------------------------------------------------------------------------

pub const ItemKind = model.ItemKind;
pub const SelectedItem = model.SelectedItem;
pub const Selection = model.Selection;
pub const ChmodStageHook = model.ChmodStageHook;

// ---------------------------------------------------------------------------
// Pure permission/format logic (headless-tested).
// ---------------------------------------------------------------------------

pub const rwxFromMode = model.rwxFromMode;
pub const modeFromRwx = model.modeFromRwx;
pub const modeFromOctalText = model.modeFromOctalText;
pub const octalTextFromMode = model.octalTextFromMode;
pub const sizeSum = model.sizeSum;
pub const formatBytes = model.formatBytes;

// ---------------------------------------------------------------------------
// Flipped container view (layout flows top-down like the docs/UX.md panel).
// ---------------------------------------------------------------------------

var g_view_class: ?runtime.DefinedClass = null;

fn inspectorViewClass() runtime.DefinedClass {
    if (g_view_class) |dc| return dc;
    const dc = runtime.defineClass("RelayInspectorView", "NSView", &.{}, .{
        .{ "isFlipped", impIsFlipped },
    }) catch @panic("inspector: failed to define RelayInspectorView");
    g_view_class = dc;
    return dc;
}

fn impIsFlipped(_: c.id, _: c.SEL) callconv(.c) foundation.BOOL {
    return foundation.YES;
}

// ---------------------------------------------------------------------------
// InspectorController
// ---------------------------------------------------------------------------

pub const panel_width: f64 = 240;
pub const panel_height: f64 = 300;

const pad: f64 = 12;
const check_w: f64 = 44;
const perm_cols = [3]f64{ 76, 128, 180 };
const perm_rows = [3]f64{ 152, 176, 200 };

pub const InspectorController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    target: *controls.ControlTarget,
    view_obj: objc.Object,
    parent_window: ?windowkit.Window = null,

    /// Owns the current selection copy (reset per setSelection).
    arena: std.heap.ArenaAllocator,
    selection: Selection = .{},
    path_text: []const u8 = "",
    pending_mode: u16 = 0o644,

    /// Observability (tests + phase-3 smoke).
    chmod_dispatched: u64 = 0,
    chmod_failures: u64 = 0,

    /// Optimistic-UI bridge to the browser: fired once per DISPATCHED
    /// chmod so the owning pane can stage its mode overlay (pending-alpha
    /// treatment) before op_done/re-list reconciles. main.zig binds it.
    stage_hook: ChmodStageHook = .{},

    // Controls (all retained by the view tree).
    name_label: objc.Object = undefined,
    info_label: objc.Object = undefined,
    path_label: objc.Object = undefined,
    octal_field: objc.Object = undefined,
    perm_checks: [9]objc.Object = undefined,
    apply_button: objc.Object = undefined,

    pub fn create(gpa: Allocator, core: *bridge.AppCore) error{OutOfMemory}!*InspectorController {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        const self = try gpa.create(InspectorController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .target = undefined,
            .view_obj = undefined,
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
        errdefer self.arena.deinit();
        self.target = try controls.ControlTarget.create(gpa);
        errdefer self.target.destroy();

        try self.buildView();
        // chmod refusals roll back through the bridge re-list; surface the
        // server's verbatim refusal here (NSAlert sheet in M2).
        try core.registerListener(.op_done, self, onOpDone);
        self.refreshViews();
        return self;
    }

    /// Controllers normally live for the app; in tests, destroy only after
    /// the final bridge drain (the op_done listener cannot unregister).
    pub fn destroy(self: *InspectorController) void {
        controls.release(self.view_obj);
        self.target.destroy();
        self.arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// The panel view (caller embeds it as the trailing split child).
    pub fn view(self: *InspectorController) c.id {
        return self.view_obj.value;
    }

    /// Window for permission-error sheets (phase 3: the main window).
    pub fn setParentWindow(self: *InspectorController, window: windowkit.Window) void {
        self.parent_window = window;
    }

    // --- visibility (Cmd+I) -------------------------------------------------

    pub fn isVisible(self: *InspectorController) bool {
        return !controls.isHidden(self.view_obj);
    }

    pub fn setVisible(self: *InspectorController, visible: bool) void {
        controls.setHidden(self.view_obj, !visible);
    }

    pub fn toggle(self: *InspectorController) void {
        self.setVisible(!self.isVisible());
    }

    /// CommandRegistry adapter: commands.bind(.toggle_inspector, insp, toggleCommand).
    pub fn toggleCommand(ctx: ?*anyopaque) void {
        const self: *InspectorController = @ptrCast(@alignCast(ctx.?));
        self.toggle();
    }

    // --- selection (live from the pane selection callback) -------------------

    /// Copies `selection` (names/paths are borrowed only for this call).
    pub fn setSelection(self: *InspectorController, selection: Selection) error{OutOfMemory}!void {
        _ = self.arena.reset(.retain_capacity);
        // The reset just invalidated whatever selection/path_text pointed
        // at; clear them BEFORE any fallible allocation so an OOM below
        // cannot leave refreshViews/applyToSelection dangling.
        self.selection = .{};
        self.path_text = "";
        const arena = self.arena.allocator();

        const items = try arena.alloc(SelectedItem, selection.items.len);
        for (selection.items, items) |src, *dst| {
            dst.* = .{
                .name = try arena.dupe(u8, src.name),
                .path = try arena.dupe(u8, src.path),
                .kind = src.kind,
                .size = src.size,
                .mode = src.mode,
            };
        }
        self.selection = .{
            .pane_token = selection.pane_token,
            .site_id = selection.site_id,
            .items = items,
        };

        // Full path(s), copyable: one per line for multi-selections.
        var paths: std.ArrayList(u8) = .empty;
        for (items, 0..) |item, i| {
            if (i > 0) try paths.append(arena, '\n');
            try paths.appendSlice(arena, item.path);
        }
        self.path_text = paths.items;

        // Seed the editor from the first item that knows its mode.
        for (items) |item| {
            if (item.mode) |mode| {
                self.pending_mode = mode & 0o777;
                break;
            }
        }
        self.refreshViews();
    }

    // --- permissions editor ---------------------------------------------------

    pub fn pendingMode(self: *const InspectorController) u16 {
        return self.pending_mode;
    }

    /// Set the staged mode and sync octal field + checkboxes (two-way sync
    /// entry point for both directions).
    pub fn setPendingMode(self: *InspectorController, mode: u16) void {
        self.pending_mode = mode & 0o777;
        self.syncPermissionControls();
    }

    /// Octal-field input: valid text updates the checkboxes; invalid text
    /// reverts the field to the staged mode. Returns validity.
    pub fn handleOctalText(self: *InspectorController, text: []const u8) bool {
        if (modeFromOctalText(text)) |mode| {
            self.setPendingMode(mode);
            return true;
        }
        self.syncPermissionControls();
        return false;
    }

    /// True when the permissions editor applies to the current selection.
    pub fn permissionsApplicable(self: *const InspectorController) bool {
        return self.selection.site_id != 0 and self.selection.items.len > 0;
    }

    /// Wire the per-dispatch staging hook (browser overlay; main.zig).
    pub fn setChmodStageHook(self: *InspectorController, hook: ChmodStageHook) void {
        self.stage_hook = hook;
    }

    /// Apply (optimistic chmod) to every selected item; returns how many
    /// operations were dispatched. Results stream back as op_done events.
    pub fn applyToSelection(self: *InspectorController) usize {
        if (!self.permissionsApplicable()) return 0;
        var dispatched: usize = 0;
        for (self.selection.items) |item| {
            self.core.chmodPath(
                self.selection.pane_token,
                self.selection.site_id,
                item.path,
                self.pending_mode,
            ) catch |err| {
                std.log.warn("inspector: chmod {s} not dispatched: {t}", .{ item.path, err });
                continue;
            };
            dispatched += 1;
            self.chmod_dispatched += 1;
            // Optimistic overlay: only ops that really dispatched stage.
            if (self.stage_hook.stage) |stage|
                stage(self.stage_hook.ctx, self.selection.pane_token, item.path, self.pending_mode);
        }
        return dispatched;
    }

    fn onOpDone(self: *InspectorController, payload: bridge.OpDone) void {
        if (payload.op != .chmod or payload.success) return;
        self.chmod_failures += 1;
        const message = if (payload.failure) |failure| failure.message else "permission change refused";
        if (self.parent_window) |window| {
            panels.presentErrorSheet(window, "Couldn't change permissions", message);
        } else {
            std.log.warn("inspector: chmod {s} failed: {s}", .{ payload.path, message });
        }
    }

    // --- view construction -----------------------------------------------------

    fn buildView(self: *InspectorController) error{OutOfMemory}!void {
        const root = inspectorViewClass()
            .newWithFrame(foundation.rect(0, 0, panel_width, panel_height));
        self.view_obj = root;
        const inner_w = panel_width - 2 * pad;

        self.name_label = controls.makeLabel(
            "No Selection",
            foundation.rect(pad, 12, inner_w, 17),
            .{ .bold = true, .truncate_middle = true },
        );
        controls.addSubview(root, self.name_label);

        self.info_label = controls.makeLabel(
            "",
            foundation.rect(pad, 33, inner_w, 15),
            .{ .secondary = true, .small = true },
        );
        controls.addSubview(root, self.info_label);

        controls.addSubview(root, controls.makeLabel(
            "Path",
            foundation.rect(pad, 60, inner_w, 14),
            .{ .secondary = true, .small = true },
        ));
        self.path_label = controls.makeLabel(
            "",
            foundation.rect(pad, 76, inner_w, 17),
            .{ .selectable = true, .truncate_middle = true, .small = true },
        );
        controls.addSubview(root, self.path_label);

        controls.addSubview(root, controls.makeLabel(
            "Permissions",
            foundation.rect(pad, 104, inner_w, 14),
            .{ .secondary = true, .small = true },
        ));
        controls.addSubview(root, controls.makeLabel(
            "Octal",
            foundation.rect(pad, 126, 52, 17),
            .{},
        ));
        self.octal_field = controls.makeTextField(foundation.rect(perm_cols[0], 124, 64, 22), "644");
        controls.addSubview(root, self.octal_field);
        try self.target.wire(self.octal_field, self, onOctalAction);

        const row_titles = [3][]const u8{ "Owner", "Group", "Others" };
        const check_titles = [3][]const u8{ "r", "w", "x" };
        for (row_titles, perm_rows, 0..) |row_title, row_y, row| {
            controls.addSubview(root, controls.makeLabel(
                row_title,
                foundation.rect(pad, row_y + 1, 56, 16),
                .{ .small = true },
            ));
            for (check_titles, perm_cols, 0..) |check_title, col_x, col| {
                const check = controls.makeCheckbox(
                    check_title,
                    foundation.rect(col_x, row_y, check_w, 18),
                );
                controls.addSubview(root, check);
                try self.target.wire(check, self, onPermToggled);
                self.perm_checks[row * 3 + col] = check;
            }
        }

        self.apply_button = controls.makePushButton(
            "Apply",
            foundation.rect(perm_cols[0], 232, 88, 26),
        );
        controls.addSubview(root, self.apply_button);
        try self.target.wire(self.apply_button, self, onApply);
    }

    fn refreshViews(self: *InspectorController) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        const items = self.selection.items;
        var buf: [160]u8 = undefined;
        switch (items.len) {
            0 => {
                controls.setLabelText(self.name_label, "No Selection");
                controls.setLabelText(self.info_label, "");
                controls.setLabelText(self.path_label, "");
            },
            1 => {
                const item = items[0];
                controls.setLabelText(self.name_label, item.name);
                var size_buf: [32]u8 = undefined;
                const size_text = if (item.size) |size|
                    formatBytes(size, &size_buf)
                else
                    "—";
                const info = std.fmt.bufPrint(&buf, "{s} · {s}", .{
                    item.kind.label(), size_text,
                }) catch item.kind.label();
                controls.setLabelText(self.info_label, info);
                controls.setLabelText(self.path_label, self.path_text);
            },
            else => {
                const head = std.fmt.bufPrint(&buf, "{d} items", .{items.len}) catch "items";
                controls.setLabelText(self.name_label, head);
                var size_buf: [32]u8 = undefined;
                var info_buf: [64]u8 = undefined;
                const info = std.fmt.bufPrint(&info_buf, "Total · {s}", .{
                    formatBytes(sizeSum(items), &size_buf),
                }) catch "";
                controls.setLabelText(self.info_label, info);
                controls.setLabelText(self.path_label, self.path_text);
            },
        }
        self.syncPermissionControls();
    }

    /// Octal field + checkboxes + Apply from `pending_mode` and selection.
    fn syncPermissionControls(self: *InspectorController) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        var octal_buf: [3]u8 = undefined;
        controls.setTextValue(self.octal_field, octalTextFromMode(self.pending_mode, &octal_buf));
        const flags = rwxFromMode(self.pending_mode);
        for (self.perm_checks, flags) |check, flag| controls.setChecked(check, flag);

        const enabled = self.permissionsApplicable();
        controls.setEnabled(self.octal_field, enabled);
        for (self.perm_checks) |check| controls.setEnabled(check, enabled);
        controls.setEnabled(self.apply_button, enabled);
    }

    // --- control handlers (pool-wrapped by the target IMP) --------------------

    fn onOctalAction(ctx: ?*anyopaque, sender: c.id) void {
        const self: *InspectorController = @ptrCast(@alignCast(ctx.?));
        const text = controls.textValue(self.gpa, objc.Object.fromId(sender)) catch return;
        defer self.gpa.free(text);
        _ = self.handleOctalText(text);
    }

    fn onPermToggled(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *InspectorController = @ptrCast(@alignCast(ctx.?));
        var flags: [9]bool = undefined;
        for (self.perm_checks, &flags) |check, *flag| flag.* = controls.isChecked(check);
        self.setPendingMode(modeFromRwx(flags));
    }

    fn onApply(ctx: ?*anyopaque, sender: c.id) void {
        _ = sender;
        const self: *InspectorController = @ptrCast(@alignCast(ctx.?));
        _ = self.applyToSelection();
    }
};

// ---------------------------------------------------------------------------
// Tests — headless: the pure octal/rwx mapping, selection plumbing, two-way
// permission sync against real AppKit controls, and the chmod dispatch +
// failure-event round trip through a manual-pump AppCore.
// ---------------------------------------------------------------------------

const testing = std.testing;
const relay = @import("relay_core");

test "rwx mapping: edges 0000/0777 and exhaustive round trip" {
    const none = rwxFromMode(0o000);
    for (none) |flag| try testing.expect(!flag);
    try testing.expectEqual(@as(u16, 0o000), modeFromRwx(none));

    const all = rwxFromMode(0o777);
    for (all) |flag| try testing.expect(flag);
    try testing.expectEqual(@as(u16, 0o777), modeFromRwx(all));

    // Spot checks: 644 = rw- r-- r--, 421 = r-- -w- --x.
    try testing.expectEqual(
        [9]bool{ true, true, false, true, false, false, true, false, false },
        rwxFromMode(0o644),
    );
    try testing.expectEqual(
        [9]bool{ true, false, false, false, true, false, false, false, true },
        rwxFromMode(0o421),
    );

    var mode: u16 = 0;
    while (mode <= 0o777) : (mode += 1) {
        try testing.expectEqual(mode, modeFromRwx(rwxFromMode(mode)));
    }
}

test "octal text parsing and formatting" {
    try testing.expectEqual(@as(?u16, 0o644), modeFromOctalText("644"));
    try testing.expectEqual(@as(?u16, 0o644), modeFromOctalText("0644"));
    try testing.expectEqual(@as(?u16, 0o644), modeFromOctalText("  644 "));
    try testing.expectEqual(@as(?u16, 0o000), modeFromOctalText("0"));
    try testing.expectEqual(@as(?u16, 0o000), modeFromOctalText("0000"));
    try testing.expectEqual(@as(?u16, 0o777), modeFromOctalText("777"));
    try testing.expectEqual(@as(?u16, 0o7), modeFromOctalText("7"));

    try testing.expectEqual(@as(?u16, null), modeFromOctalText(""));
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("   "));
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("8"));
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("64a"));
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("-644"));
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("1777")); // special bits out of scope
    try testing.expectEqual(@as(?u16, null), modeFromOctalText("77777"));

    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("000", octalTextFromMode(0o000, &buf));
    try testing.expectEqualStrings("777", octalTextFromMode(0o777, &buf));
    try testing.expectEqualStrings("644", octalTextFromMode(0o644, &buf));
    try testing.expectEqualStrings("421", octalTextFromMode(0o421, &buf));
}

test "size sum and byte formatting" {
    const items = [_]SelectedItem{
        .{ .name = "a", .path = "/a", .size = 1024 },
        .{ .name = "b", .path = "/b", .kind = .dir, .size = null },
        .{ .name = "c", .path = "/c", .size = 512 },
    };
    try testing.expectEqual(@as(u64, 1536), sizeSum(&items));

    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0 B", formatBytes(0, &buf));
    try testing.expectEqualStrings("999 B", formatBytes(999, &buf));
    try testing.expectEqualStrings("1.0 KB", formatBytes(1024, &buf));
    try testing.expectEqualStrings("1.5 KB", formatBytes(1536, &buf));
    try testing.expectEqualStrings("2.0 MB", formatBytes(2 * 1024 * 1024, &buf));
}

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

    const wait_timeout_ms: u64 = 5_000;

    fn waitUntil(h: *TestHarness, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool) !void {
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

test "inspector: selection plumbing + two-way octal/checkbox sync on real controls" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const insp = try InspectorController.create(testing.allocator, h.core);
    defer insp.destroy();

    // Empty selection: permissions editor disabled.
    try testing.expect(!insp.permissionsApplicable());
    try testing.expect(!controls.isEnabled(insp.octal_field));

    // Remote two-file selection seeded from the first known mode.
    const items = [_]SelectedItem{
        .{ .name = "notes.txt", .path = "/srv/notes.txt", .size = 1024, .mode = 0o644 },
        .{ .name = "site", .path = "/srv/site", .kind = .dir, .mode = 0o755 },
    };
    try insp.setSelection(.{ .pane_token = 11, .site_id = 42, .items = &items });
    try testing.expect(insp.permissionsApplicable());
    try testing.expectEqual(@as(u16, 0o644), insp.pendingMode());

    const octal_text = try controls.textValue(testing.allocator, insp.octal_field);
    defer testing.allocator.free(octal_text);
    try testing.expectEqualStrings("644", octal_text);
    try testing.expectEqual(rwxFromMode(0o644)[0], controls.isChecked(insp.perm_checks[0]));
    for (insp.perm_checks, rwxFromMode(0o644)) |check, expected| {
        try testing.expectEqual(expected, controls.isChecked(check));
    }

    // Octal → checkboxes.
    try testing.expect(insp.handleOctalText("755"));
    try testing.expectEqual(@as(u16, 0o755), insp.pendingMode());
    for (insp.perm_checks, rwxFromMode(0o755)) |check, expected| {
        try testing.expectEqual(expected, controls.isChecked(check));
    }

    // Invalid octal reverts the field, keeps the staged mode.
    try testing.expect(!insp.handleOctalText("9x"));
    try testing.expectEqual(@as(u16, 0o755), insp.pendingMode());
    const reverted = try controls.textValue(testing.allocator, insp.octal_field);
    defer testing.allocator.free(reverted);
    try testing.expectEqualStrings("755", reverted);

    // Checkboxes → octal (simulate a click: flip state, then the handler).
    controls.setChecked(insp.perm_checks[8], false); // drop others-x
    InspectorController.onPermToggled(insp, insp.perm_checks[8].value);
    try testing.expectEqual(@as(u16, 0o754), insp.pendingMode());
    const after_toggle = try controls.textValue(testing.allocator, insp.octal_field);
    defer testing.allocator.free(after_toggle);
    try testing.expectEqualStrings("754", after_toggle);

    // Multi-selection summary text.
    const name_text = try controls.textValue(testing.allocator, insp.name_label);
    defer testing.allocator.free(name_text);
    try testing.expectEqualStrings("2 items", name_text);
    const path_text = try controls.textValue(testing.allocator, insp.path_label);
    defer testing.allocator.free(path_text);
    try testing.expectEqualStrings("/srv/notes.txt\n/srv/site", path_text);

    // Visibility toggle (Cmd+I).
    try testing.expect(insp.isVisible());
    insp.toggle();
    try testing.expect(!insp.isVisible());
    InspectorController.toggleCommand(insp);
    try testing.expect(insp.isVisible());

    // Local selections never enable the editor and dispatch nothing.
    try insp.setSelection(.{ .pane_token = 11, .site_id = 0, .items = &items });
    try testing.expect(!insp.permissionsApplicable());
    try testing.expectEqual(@as(usize, 0), insp.applyToSelection());
}

test "inspector: Apply dispatches chmod per selected item; refusals come back as op_done failures" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const insp = try InspectorController.create(testing.allocator, h.core);

    const items = [_]SelectedItem{
        .{ .name = "a.bin", .path = "/data/a.bin", .mode = 0o600 },
        .{ .name = "b.bin", .path = "/data/b.bin", .mode = 0o600 },
        .{ .name = "c.bin", .path = "/data/c.bin", .mode = 0o600 },
    };
    try insp.setSelection(.{ .pane_token = 7, .site_id = 99, .items = &items });
    insp.setPendingMode(0o640);

    // The optimistic-overlay hook fires once per dispatched chmod.
    const StageRecorder = struct {
        calls: usize = 0,
        pane: bridge.PaneToken = 0,
        mode: u16 = 0,
        last_path_ok: bool = false,

        fn onStage(ctx: ?*anyopaque, pane_token: bridge.PaneToken, path: []const u8, mode: u16) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.pane = pane_token;
            self.mode = mode;
            self.last_path_ok = std.mem.eql(u8, path, "/data/c.bin");
        }
    };
    var stage_rec: StageRecorder = .{};
    insp.setChmodStageHook(.{ .ctx = &stage_rec, .stage = StageRecorder.onStage });

    // Site 99 is not connected: every op must come back as a classified
    // chmod failure through the bridge (optimistic UI's refusal path).
    try testing.expectEqual(@as(usize, 3), insp.applyToSelection());
    try testing.expectEqual(@as(u64, 3), insp.chmod_dispatched);
    try testing.expectEqual(@as(usize, 3), stage_rec.calls);
    try testing.expectEqual(@as(bridge.PaneToken, 7), stage_rec.pane);
    try testing.expectEqual(@as(u16, 0o640), stage_rec.mode);
    try testing.expect(stage_rec.last_path_ok);

    const Wait = struct {
        fn allFailed(ctl: *InspectorController) bool {
            return ctl.chmod_failures == 3;
        }
    };
    try h.waitUntil(insp, Wait.allFailed);
    try testing.expectEqual(@as(u64, 3), insp.chmod_failures);

    // No drains after this point: safe to drop the listener's controller.
    insp.destroy();
}

// Visual smoke (build + briefly RUN per the GUI testing policy): set
// RELAY_VISUAL_SMOKE=1 to order the Settings window and an inspector host
// window onto the screen for ~1.5s. Skipped in normal headless runs.
test "visual smoke: prefs window + inspector panel appear on screen" {
    if (std.c.getenv("RELAY_VISUAL_SMOKE") == null) return error.SkipZigTest;

    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const app = windowkit.App.shared();
    app.setRegularActivationPolicy();
    app.activate();

    const pc = try prefs.PrefsController.create(testing.allocator, h.core);
    defer pc.destroy();
    pc.show();
    try testing.expect(pc.built);
    try testing.expect(pc.win.isVisible());

    const insp = try InspectorController.create(testing.allocator, h.core);
    defer insp.destroy();
    const items = [_]SelectedItem{
        .{ .name = "release.tar.gz", .path = "/srv/www/release.tar.gz", .size = 48_234_511, .mode = 0o644 },
    };
    try insp.setSelection(.{ .pane_token = 1, .site_id = 7, .items = &items });

    const host = windowkit.Window.create(
        foundation.rect(0, 0, panel_width, panel_height),
        "Inspector",
        windowkit.StyleMask.standard,
    );
    defer host.release();
    host.setContentView(insp.view_obj);
    host.center();
    host.makeKeyAndOrderFront();
    try testing.expect(host.isVisible());

    h.core.io.sleep(.fromMilliseconds(1500), .awake) catch {};
}

test {
    testing.refAllDecls(@This());
}

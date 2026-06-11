//! panels — NSAlert (sheet + app-modal), confirm sheets, NSOpenPanel /
//! NSSavePanel, the form-sheet builder used by the site editor, and the M2
//! inline-error presenter (an NSAlert sheet per docs/UX.md).
//!
//! Completion flows: AppKit calls a zig-objc Block on the main thread; the
//! block body is pool-wrapped and forwards into a comptime Zig callback with
//! a caller context pointer. ObjC objects captured as `c.id` are retained by
//! the block copy, which is what keeps alerts/panels alive while presented.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("../foundation.zig");
const runtime = @import("../runtime.zig");
const window = @import("window.zig");

const c = objc.c;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const Window = window.Window;

const c_gpa = std.heap.c_allocator;

// ---------------------------------------------------------------------------
// NSAlert
// ---------------------------------------------------------------------------
pub const AlertStyle = enum(NSUInteger) {
    warning = 0,
    informational = 1,
    critical = 2,
};

pub const AlertSpec = struct {
    style: AlertStyle = .warning,
    message: []const u8,
    informative: []const u8 = "",
    /// First button is the default (Return). Order follows AppKit layout
    /// rules: index 0 rightmost.
    buttons: []const []const u8 = &.{"OK"},
    /// Marks one button destructive (red treatment).
    destructive_button: ?usize = null,
    /// Adds a suppression checkbox with this title.
    suppression_title: ?[]const u8 = null,
};

pub const AlertResult = struct {
    /// Index into AlertSpec.buttons.
    button: usize,
    /// Suppression checkbox state at dismissal.
    suppressed: bool = false,
};

const ns_alert_first_button_return: NSInteger = 1000;
const ns_control_state_on: NSInteger = 1;

fn makeAlert(spec: AlertSpec) objc.Object {
    const alert = foundation.class("NSAlert").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "init", .{})
        .msgSend(objc.Object, "autorelease", .{});
    alert.msgSend(void, "setAlertStyle:", .{@intFromEnum(spec.style)});
    alert.msgSend(void, "setMessageText:", .{foundation.nsString(spec.message)});
    if (spec.informative.len > 0) {
        alert.msgSend(void, "setInformativeText:", .{foundation.nsString(spec.informative)});
    }
    for (spec.buttons, 0..) |title, i| {
        const button = alert.msgSend(objc.Object, "addButtonWithTitle:", .{foundation.nsString(title)});
        if (spec.destructive_button == i) {
            button.msgSend(void, "setHasDestructiveAction:", .{true});
        }
    }
    if (spec.suppression_title) |title| {
        alert.msgSend(void, "setShowsSuppressionButton:", .{true});
        alert.msgSend(objc.Object, "suppressionButton", .{})
            .msgSend(void, "setTitle:", .{foundation.nsString(title)});
    }
    return alert;
}

fn alertResult(alert: objc.Object, response: NSInteger) AlertResult {
    const button: usize = if (response >= ns_alert_first_button_return)
        @intCast(response - ns_alert_first_button_return)
    else
        0;
    var suppressed = false;
    if (foundation.toBool(alert.msgSend(foundation.BOOL, "showsSuppressionButton", .{}))) {
        const state = alert.msgSend(objc.Object, "suppressionButton", .{})
            .msgSend(NSInteger, "state", .{});
        suppressed = state == ns_control_state_on;
    }
    return .{ .button = button, .suppressed = suppressed };
}

/// App-modal alert (blocks the main thread until dismissed). Sheets are
/// preferred; this is for pre-window failures.
pub fn runAlert(spec: AlertSpec) AlertResult {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const alert = makeAlert(spec);
    const response = alert.msgSend(NSInteger, "runModal", .{});
    return alertResult(alert, response);
}

/// Window-modal alert; `f(ctx, result)` runs pool-wrapped on the main thread.
pub fn beginAlertSheet(
    parent: Window,
    spec: AlertSpec,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), AlertResult) void,
) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    comptime {
        if (@typeInfo(@TypeOf(ctx)) != .pointer) @compileError("beginAlertSheet ctx must be a pointer");
    }

    const alert = makeAlert(spec);
    const B = objc.Block(struct { alert: c.id, ctx: usize }, .{NSInteger}, void);
    const Fns = struct {
        fn invoke(block: *const B.Context, response: NSInteger) callconv(.c) void {
            const inner = objc.AutoreleasePool.init();
            defer inner.deinit();
            const alert_obj = objc.Object.fromId(block.alert);
            f(@ptrFromInt(block.ctx), alertResult(alert_obj, response));
        }
    };
    var block = B.init(.{ .alert = alert.value, .ctx = @intFromPtr(ctx) }, Fns.invoke);
    alert.msgSend(void, "beginSheetModalForWindow:completionHandler:", .{ parent.obj, &block });
}

/// Two-button confirm sheet; `f(ctx, confirmed)`.
pub fn confirmSheet(
    parent: Window,
    message: []const u8,
    informative: []const u8,
    confirm_title: []const u8,
    destructive: bool,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), bool) void,
) void {
    const Ptr = @TypeOf(ctx);
    const Fns = struct {
        fn done(inner_ctx: Ptr, result: AlertResult) void {
            f(inner_ctx, result.button == 0);
        }
    };
    beginAlertSheet(parent, .{
        .message = message,
        .informative = informative,
        .buttons = &.{ confirm_title, "Cancel" },
        .destructive_button = if (destructive) 0 else null,
    }, ctx, Fns.done);
}

/// M2 inline-error presenter (docs/UX.md: "inline error toast — NSAlert
/// sheet in M2"). Fire-and-forget; falls back to app-modal without a window.
pub fn presentErrorSheet(parent: ?Window, message: []const u8, detail: []const u8) void {
    const spec: AlertSpec = .{ .style = .critical, .message = message, .informative = detail };
    const parent_win = parent orelse {
        _ = runAlert(spec);
        return;
    };

    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const alert = makeAlert(spec);
    // The copied block's retained `alert` capture keeps the alert alive
    // while the sheet is up; the completion body has nothing to do.
    const B = objc.Block(struct { alert: c.id }, .{NSInteger}, void);
    const Fns = struct {
        fn invoke(_: *const B.Context, _: NSInteger) callconv(.c) void {}
    };
    var block = B.init(.{ .alert = alert.value }, Fns.invoke);
    alert.msgSend(void, "beginSheetModalForWindow:completionHandler:", .{ parent_win.obj, &block });
}

// ---------------------------------------------------------------------------
// NSOpenPanel / NSSavePanel
// ---------------------------------------------------------------------------
pub const OpenPanelOptions = struct {
    choose_files: bool = true,
    choose_directories: bool = false,
    allows_multiple: bool = false,
    can_create_directories: bool = false,
    /// Text above the file browser.
    message: []const u8 = "",
    /// Default-button title ("Choose", "Upload", ...).
    prompt: []const u8 = "",
    /// Initial directory (absolute path); empty = AppKit default.
    directory: []const u8 = "",
};

pub const SavePanelOptions = struct {
    can_create_directories: bool = true,
    message: []const u8 = "",
    prompt: []const u8 = "",
    /// Pre-filled file name.
    filename: []const u8 = "",
    directory: []const u8 = "",
};

const ns_modal_response_ok: NSInteger = 1;

fn makeOpenPanel(opts: OpenPanelOptions) objc.Object {
    const panel = foundation.class("NSOpenPanel").msgSend(objc.Object, "openPanel", .{});
    panel.msgSend(void, "setCanChooseFiles:", .{opts.choose_files});
    panel.msgSend(void, "setCanChooseDirectories:", .{opts.choose_directories});
    panel.msgSend(void, "setAllowsMultipleSelection:", .{opts.allows_multiple});
    applyCommonPanelOptions(panel, opts.can_create_directories, opts.message, opts.prompt, opts.directory);
    return panel;
}

fn makeSavePanel(opts: SavePanelOptions) objc.Object {
    const panel = foundation.class("NSSavePanel").msgSend(objc.Object, "savePanel", .{});
    if (opts.filename.len > 0) {
        panel.msgSend(void, "setNameFieldStringValue:", .{foundation.nsString(opts.filename)});
    }
    applyCommonPanelOptions(panel, opts.can_create_directories, opts.message, opts.prompt, opts.directory);
    return panel;
}

fn applyCommonPanelOptions(
    panel: objc.Object,
    can_create_directories: bool,
    message: []const u8,
    prompt: []const u8,
    directory: []const u8,
) void {
    panel.msgSend(void, "setCanCreateDirectories:", .{can_create_directories});
    if (message.len > 0) panel.msgSend(void, "setMessage:", .{foundation.nsString(message)});
    if (prompt.len > 0) panel.msgSend(void, "setPrompt:", .{foundation.nsString(prompt)});
    if (directory.len > 0) panel.msgSend(void, "setDirectoryURL:", .{foundation.fileURL(directory)});
}

/// Choose files/directories. `f(ctx, paths)` runs pool-wrapped on the main
/// thread; `paths` is empty on cancel and only valid for the duration of the
/// callback (dupe to keep). Returns the panel (for programmatic dismissal).
pub fn beginOpenPanel(
    parent: ?Window,
    opts: OpenPanelOptions,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), []const []const u8) void,
) objc.Object {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    comptime {
        if (@typeInfo(@TypeOf(ctx)) != .pointer) @compileError("beginOpenPanel ctx must be a pointer");
    }

    const panel = makeOpenPanel(opts);
    const B = objc.Block(struct { panel: c.id, ctx: usize }, .{NSInteger}, void);
    const Fns = struct {
        fn invoke(block: *const B.Context, response: NSInteger) callconv(.c) void {
            const inner = objc.AutoreleasePool.init();
            defer inner.deinit();
            const panel_obj = objc.Object.fromId(block.panel);

            if (response != ns_modal_response_ok) {
                f(@ptrFromInt(block.ctx), &.{});
                return;
            }
            const urls = panel_obj.msgSend(objc.Object, "URLs", .{});
            const count: usize = @intCast(urls.msgSend(NSUInteger, "count", .{}));
            const paths = c_gpa.alloc([]const u8, count) catch {
                f(@ptrFromInt(block.ctx), &.{});
                return;
            };
            var filled: usize = 0;
            for (0..count) |i| {
                const url = urls.msgSend(objc.Object, "objectAtIndex:", .{@as(NSUInteger, i)});
                paths[filled] = foundation.pathFromURL(c_gpa, url) catch continue;
                filled += 1;
            }
            f(@ptrFromInt(block.ctx), paths[0..filled]);
            for (paths[0..filled]) |p| c_gpa.free(p);
            c_gpa.free(paths);
        }
    };
    var block = B.init(.{ .panel = panel.value, .ctx = @intFromPtr(ctx) }, Fns.invoke);
    presentPanel(panel, parent, &block);
    return panel;
}

/// Choose a save destination. `f(ctx, path)`: null on cancel; the path is
/// only valid for the duration of the callback.
pub fn beginSavePanel(
    parent: ?Window,
    opts: SavePanelOptions,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), ?[]const u8) void,
) objc.Object {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    comptime {
        if (@typeInfo(@TypeOf(ctx)) != .pointer) @compileError("beginSavePanel ctx must be a pointer");
    }

    const panel = makeSavePanel(opts);
    const B = objc.Block(struct { panel: c.id, ctx: usize }, .{NSInteger}, void);
    const Fns = struct {
        fn invoke(block: *const B.Context, response: NSInteger) callconv(.c) void {
            const inner = objc.AutoreleasePool.init();
            defer inner.deinit();
            const panel_obj = objc.Object.fromId(block.panel);

            if (response != ns_modal_response_ok) {
                f(@ptrFromInt(block.ctx), null);
                return;
            }
            const url = panel_obj.msgSend(objc.Object, "URL", .{});
            const path = foundation.pathFromURL(c_gpa, url) catch {
                f(@ptrFromInt(block.ctx), null);
                return;
            };
            f(@ptrFromInt(block.ctx), path);
            c_gpa.free(path);
        }
    };
    var block = B.init(.{ .panel = panel.value, .ctx = @intFromPtr(ctx) }, Fns.invoke);
    presentPanel(panel, parent, &block);
    return panel;
}

fn presentPanel(panel: objc.Object, parent: ?Window, block: *anyopaque) void {
    if (parent) |p| {
        panel.msgSend(void, "beginSheetModalForWindow:completionHandler:", .{ p.obj, block });
    } else {
        panel.msgSend(void, "beginWithCompletionHandler:", .{block});
    }
}

/// Programmatically dismiss an open/save panel (tests, teardown).
pub fn dismissPanel(panel: objc.Object) void {
    panel.msgSend(void, "cancel:", .{foundation.nil});
}

// ---------------------------------------------------------------------------
// Form sheet (site editor): rows of label + NSTextField / NSSecureTextField /
// NSPopUpButton, with OK/Cancel. Values come back as a FormResult.
// ---------------------------------------------------------------------------
pub const FieldKind = enum { text, secure, popup };

pub const FormField = struct {
    label: []const u8,
    kind: FieldKind = .text,
    initial: []const u8 = "",
    placeholder: []const u8 = "",
    /// Popup choices (popup kind only).
    options: []const []const u8 = &.{},
};

pub const FormResult = struct {
    /// Index-aligned with the FormField slice; popups yield the selected
    /// title. Only valid for the duration of the completion callback.
    values: []const []const u8,
};

// Layout (fixed-frame, no autolayout; sheet windows do not resize in M2).
const form_width: f64 = 430;
const form_row_h: f64 = 32;
const form_label_w: f64 = 130;
const form_field_x: f64 = 165;
const form_field_w: f64 = 240;
const form_top_pad: f64 = 20;
const form_button_area_h: f64 = 52;

const ns_text_alignment_right: NSInteger = 1;
const ns_bezel_style_rounded: NSUInteger = 1;

const FormControl = struct {
    obj: c.id,
    kind: FieldKind,
};

const FormState = struct {
    parent: c.id,
    sheet: c.id,
    target: c.id,
    controls: []FormControl,
};

var g_form_target_class: ?runtime.DefinedClass = null;

fn formTargetClass() runtime.DefinedClass {
    if (g_form_target_class) |dc| return dc;
    const dc = runtime.defineClass("RelayFormTarget", "NSObject", &.{}, .{
        .{ "relayFormOK:", formOkImp },
        .{ "relayFormCancel:", formCancelImp },
    }) catch @panic("relay_mac/panels: failed to define RelayFormTarget");
    g_form_target_class = dc;
    return dc;
}

fn formOkImp(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    formEnd(target, window.modal_response_ok);
}

fn formCancelImp(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    formEnd(target, window.modal_response_cancel);
}

fn formEnd(target: c.id, code: NSInteger) void {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    const st = formTargetClass().state(FormState, target);
    Window.fromObject(objc.Object.fromId(st.parent))
        .endSheet(Window.fromObject(objc.Object.fromId(st.sheet)), code);
}

fn makeLabel(text: []const u8, frame: foundation.NSRect) objc.Object {
    const label = foundation.class("NSTextField")
        .msgSend(objc.Object, "labelWithString:", .{foundation.nsString(text)});
    label.msgSend(void, "setFrame:", .{frame});
    label.msgSend(void, "setAlignment:", .{ns_text_alignment_right});
    return label;
}

fn makeFormControl(field: FormField, frame: foundation.NSRect) objc.Object {
    switch (field.kind) {
        .text, .secure => {
            const cls = if (field.kind == .secure) "NSSecureTextField" else "NSTextField";
            const control = foundation.class(cls).msgSend(objc.Object, "alloc", .{})
                .msgSend(objc.Object, "initWithFrame:", .{frame})
                .msgSend(objc.Object, "autorelease", .{});
            if (field.placeholder.len > 0) {
                control.msgSend(void, "setPlaceholderString:", .{foundation.nsString(field.placeholder)});
            }
            if (field.initial.len > 0) {
                control.msgSend(void, "setStringValue:", .{foundation.nsString(field.initial)});
            }
            return control;
        },
        .popup => {
            const control = foundation.class("NSPopUpButton").msgSend(objc.Object, "alloc", .{})
                .msgSend(objc.Object, "initWithFrame:pullsDown:", .{ frame, false })
                .msgSend(objc.Object, "autorelease", .{});
            for (field.options) |option| {
                control.msgSend(void, "addItemWithTitle:", .{foundation.nsString(option)});
            }
            if (field.initial.len > 0) {
                control.msgSend(void, "selectItemWithTitle:", .{foundation.nsString(field.initial)});
            }
            return control;
        },
    }
}

fn makeFormButton(
    title: []const u8,
    frame: foundation.NSRect,
    target: c.id,
    action: [:0]const u8,
    key: [:0]const u8,
) objc.Object {
    const button = foundation.class("NSButton").msgSend(objc.Object, "alloc", .{})
        .msgSend(objc.Object, "initWithFrame:", .{frame})
        .msgSend(objc.Object, "autorelease", .{});
    button.msgSend(void, "setTitle:", .{foundation.nsString(title)});
    button.msgSend(void, "setBezelStyle:", .{ns_bezel_style_rounded});
    button.msgSend(void, "setTarget:", .{target});
    button.msgSend(void, "setAction:", .{objc.sel(action)});
    if (key.len > 0) button.msgSend(void, "setKeyEquivalent:", .{foundation.nsStringZ(key)});
    return button;
}

/// Builds the sheet window + controls + OK/Cancel and the heap FormState.
/// Split from beginFormSheet so tests can exercise it headless.
fn buildForm(
    parent: Window,
    title: []const u8,
    ok_title: []const u8,
    fields: []const FormField,
) *FormState {
    const rows: f64 = @floatFromInt(fields.len);
    const content_h = form_top_pad + rows * form_row_h + form_button_area_h;
    const sheet = Window.create(
        foundation.rect(0, 0, form_width, content_h),
        title,
        window.StyleMask.titled,
    );
    const content = sheet.contentView();

    const st = c_gpa.create(FormState) catch @panic("relay_mac/panels: OOM (FormState)");
    const controls = c_gpa.alloc(FormControl, fields.len) catch
        @panic("relay_mac/panels: OOM (form controls)");
    st.* = .{
        .parent = parent.obj.value,
        .sheet = sheet.obj.value,
        .target = formTargetClass().newWithState(st).value, // rc 1, owned by st
        .controls = controls,
    };

    for (fields, 0..) |field, i| {
        const row_top = content_h - form_top_pad - (@as(f64, @floatFromInt(i)) + 1) * form_row_h;
        const label = makeLabel(field.label, foundation.rect(20, row_top + 6, form_label_w, 20));
        content.msgSend(void, "addSubview:", .{label});
        const control_h: f64 = if (field.kind == .popup) 25 else 22;
        const control = makeFormControl(
            field,
            foundation.rect(form_field_x, row_top + 4, form_field_w, control_h),
        );
        content.msgSend(void, "addSubview:", .{control});
        controls[i] = .{ .obj = control.value, .kind = field.kind };
    }

    const ok = makeFormButton(
        ok_title,
        foundation.rect(form_width - 20 - 96, 14, 96, 26),
        st.target,
        "relayFormOK:",
        "\r",
    );
    content.msgSend(void, "addSubview:", .{ok});
    const cancel = makeFormButton(
        "Cancel",
        foundation.rect(form_width - 20 - 96 - 8 - 96, 14, 96, 26),
        st.target,
        "relayFormCancel:",
        "\u{001B}",
    );
    content.msgSend(void, "addSubview:", .{cancel});

    return st;
}

fn destroyForm(st: *FormState) void {
    objc.Object.fromId(st.target).msgSend(void, "release", .{});
    Window.fromObject(objc.Object.fromId(st.sheet)).release();
    c_gpa.free(st.controls);
    c_gpa.destroy(st);
}

/// Reads every control into c-allocator strings (caller frees via freeValues).
fn collectValues(st: *FormState) [][]const u8 {
    const values = c_gpa.alloc([]const u8, st.controls.len) catch
        @panic("relay_mac/panels: OOM (form values)");
    for (st.controls, 0..) |control, i| {
        const obj = objc.Object.fromId(control.obj);
        const str = switch (control.kind) {
            .text, .secure => obj.msgSend(objc.Object, "stringValue", .{}),
            .popup => obj.msgSend(objc.Object, "titleOfSelectedItem", .{}),
        };
        values[i] = if (str.value == null)
            c_gpa.dupe(u8, "") catch @panic("relay_mac/panels: OOM (form value)")
        else
            foundation.utf8FromNSString(c_gpa, str) catch
                @panic("relay_mac/panels: OOM (form value)");
    }
    return values;
}

fn freeValues(values: [][]const u8) void {
    for (values) |v| c_gpa.free(v);
    c_gpa.free(values);
}

/// Present a form sheet on `parent`. On OK, `f(ctx, FormResult)` receives the
/// field values (valid only during the callback); on Cancel, `f(ctx, null)`.
/// Returns the sheet window for programmatic dismissal via
/// `parent.endSheet(sheet, code)`. The sheet destroys itself on completion.
pub fn beginFormSheet(
    parent: Window,
    title: []const u8,
    ok_title: []const u8,
    fields: []const FormField,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), ?FormResult) void,
) Window {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();
    comptime {
        if (@typeInfo(@TypeOf(ctx)) != .pointer) @compileError("beginFormSheet ctx must be a pointer");
    }

    const st = buildForm(parent, title, ok_title, fields);
    const sheet = Window.fromObject(objc.Object.fromId(st.sheet));

    const B = objc.Block(struct { st: usize, ctx: usize }, .{NSInteger}, void);
    const Fns = struct {
        fn invoke(block: *const B.Context, response: NSInteger) callconv(.c) void {
            const inner = objc.AutoreleasePool.init();
            defer inner.deinit();
            const form: *FormState = @ptrFromInt(block.st);
            if (response == window.modal_response_ok) {
                const values = collectValues(form);
                f(@ptrFromInt(block.ctx), .{ .values = values });
                freeValues(values);
            } else {
                f(@ptrFromInt(block.ctx), null);
            }
            destroyForm(form);
        }
    };
    var block = B.init(.{ .st = @intFromPtr(st), .ctx = @intFromPtr(ctx) }, Fns.invoke);
    parent.obj.msgSend(void, "beginSheet:completionHandler:", .{ sheet.obj, &block });
    if (st.controls.len > 0) {
        _ = sheet.makeFirstResponder(objc.Object.fromId(st.controls[0].obj));
    }
    return sheet;
}

// ---------------------------------------------------------------------------
// Tests (headless: build + inspect; nothing is presented).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "makeAlert applies the full spec" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const alert = makeAlert(.{
        .style = .critical,
        .message = "Delete 3 items?",
        .informative = "This cannot be undone.",
        .buttons = &.{ "Delete", "Cancel" },
        .destructive_button = 0,
        .suppression_title = "Do not ask again",
    });

    try testing.expectEqual(@as(NSUInteger, 2), alert.msgSend(NSUInteger, "alertStyle", .{}));
    const buttons = alert.msgSend(objc.Object, "buttons", .{});
    try testing.expectEqual(@as(NSUInteger, 2), buttons.msgSend(NSUInteger, "count", .{}));

    const first = buttons.msgSend(objc.Object, "objectAtIndex:", .{@as(NSUInteger, 0)});
    const first_title = try foundation.utf8FromNSString(
        testing.allocator,
        first.msgSend(objc.Object, "title", .{}),
    );
    defer testing.allocator.free(first_title);
    try testing.expectEqualStrings("Delete", first_title);
    try testing.expect(foundation.toBool(first.msgSend(foundation.BOOL, "hasDestructiveAction", .{})));

    try testing.expect(foundation.toBool(alert.msgSend(foundation.BOOL, "showsSuppressionButton", .{})));
    const sup_title = try foundation.utf8FromNSString(
        testing.allocator,
        alert.msgSend(objc.Object, "suppressionButton", .{}).msgSend(objc.Object, "title", .{}),
    );
    defer testing.allocator.free(sup_title);
    try testing.expectEqualStrings("Do not ask again", sup_title);

    // Response mapping: second button, suppression off.
    const result = alertResult(alert, ns_alert_first_button_return + 1);
    try testing.expectEqual(@as(usize, 1), result.button);
    try testing.expect(!result.suppressed);
}

test "open/save panel options are applied" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const open = makeOpenPanel(.{
        .choose_files = false,
        .choose_directories = true,
        .allows_multiple = true,
        .can_create_directories = true,
        .prompt = "Choose Folder",
    });
    try testing.expect(!foundation.toBool(open.msgSend(foundation.BOOL, "canChooseFiles", .{})));
    try testing.expect(foundation.toBool(open.msgSend(foundation.BOOL, "canChooseDirectories", .{})));
    try testing.expect(foundation.toBool(open.msgSend(foundation.BOOL, "allowsMultipleSelection", .{})));
    try testing.expect(foundation.toBool(open.msgSend(foundation.BOOL, "canCreateDirectories", .{})));
    const prompt = try foundation.utf8FromNSString(
        testing.allocator,
        open.msgSend(objc.Object, "prompt", .{}),
    );
    defer testing.allocator.free(prompt);
    try testing.expectEqualStrings("Choose Folder", prompt);

    const save = makeSavePanel(.{ .filename = "download.bin" });
    const name = try foundation.utf8FromNSString(
        testing.allocator,
        save.msgSend(objc.Object, "nameFieldStringValue", .{}),
    );
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("download.bin", name);
}

test "form build + value collection round-trip" {
    const pool = objc.AutoreleasePool.init();
    defer pool.deinit();

    const parent = Window.create(foundation.rect(0, 0, 600, 400), "form-parent", window.StyleMask.standard);
    defer parent.release();

    const fields = [_]FormField{
        .{ .label = "Server", .initial = "sftp.example.com", .placeholder = "host" },
        .{ .label = "Password", .kind = .secure },
        .{ .label = "Protocol", .kind = .popup, .options = &.{ "SFTP", "FTP", "FTPS" }, .initial = "FTPS" },
    };
    const st = buildForm(parent, "Edit Site", "Save", &fields);
    defer destroyForm(st);

    try testing.expectEqual(@as(usize, 3), st.controls.len);
    try testing.expectEqualStrings("NSSecureTextField", objc.Object.fromId(st.controls[1].obj).getClassName());

    // Simulate user edits, then collect.
    objc.Object.fromId(st.controls[1].obj)
        .msgSend(void, "setStringValue:", .{foundation.nsString("s3cret")});
    const values = collectValues(st);
    defer freeValues(values);
    try testing.expectEqualStrings("sftp.example.com", values[0]);
    try testing.expectEqualStrings("s3cret", values[1]);
    try testing.expectEqualStrings("FTPS", values[2]);

    // OK/Cancel buttons are wired at the shared form target.
    const dc = formTargetClass();
    try testing.expectEqual(st, dc.state(FormState, st.target));
}

test {
    testing.refAllDecls(@This());
}

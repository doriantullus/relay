//! Toolkit-neutral UI preferences and session persistence.

const std = @import("std");
const relay = @import("relay_core");

const Allocator = std.mem.Allocator;
const settings = relay.settings;

pub const file_name = "ui.zon";

pub const Density = enum { comfortable, compact, dense };
pub const DateFormat = enum { iso, relative };

pub const TabState = struct {
    pane0_site: u64 = 0,
    pane0_path: []const u8 = "",
    pane1_site: u64 = 0,
    pane1_path: []const u8 = "",
};

pub const SessionState = struct {
    pane0_site: u64 = 0,
    pane0_path: []const u8 = "",
    pane1_site: u64 = 0,
    pane1_path: []const u8 = "",
    focused_pane: u32 = 0,
    sidebar_collapsed: bool = false,
    transfers_collapsed: bool = true,
    inspector_collapsed: bool = true,
    tabs: []TabState = &.{},
    active_tab: u32 = 0,
    restore_queue: bool = false,
};

pub const UiPrefs = struct {
    schema_version: u32 = 1,
    download_dir: []const u8 = "",
    confirm_delete: bool = true,
    density: Density = .compact,
    monospace_lists: bool = false,
    date_format: DateFormat = .iso,
    vim_mode: bool = false,
    reconnect_on_launch: bool = false,
    session: SessionState = .{},
};

pub fn load(io: std.Io, dir: std.Io.Dir, gpa: Allocator) error{OutOfMemory}!UiPrefs {
    const source = settings.readFileZ(io, dir, file_name, gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return defaults(gpa),
    };
    defer gpa.free(source);

    var zon_diag: std.zon.parse.Diagnostics = .{};
    defer zon_diag.deinit(gpa);
    const parsed = std.zon.parse.fromSliceAlloc(UiPrefs, gpa, source, &zon_diag, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => return defaults(gpa),
    };
    defer std.zon.parse.free(gpa, parsed);
    return clone(gpa, parsed);
}

pub fn defaults(gpa: Allocator) error{OutOfMemory}!UiPrefs {
    return clone(gpa, .{});
}

pub fn clone(gpa: Allocator, source: UiPrefs) error{OutOfMemory}!UiPrefs {
    var result = source;
    result.download_dir = "";
    result.session.pane0_path = "";
    result.session.pane1_path = "";
    result.session.tabs = &.{};
    errdefer deinit(gpa, &result);
    result.download_dir = try gpa.dupe(u8, source.download_dir);
    result.session.pane0_path = try gpa.dupe(u8, source.session.pane0_path);
    result.session.pane1_path = try gpa.dupe(u8, source.session.pane1_path);
    result.session.tabs = try cloneTabs(gpa, source.session.tabs);
    return result;
}

pub fn deinit(gpa: Allocator, prefs: *UiPrefs) void {
    gpa.free(prefs.download_dir);
    prefs.download_dir = "";
    gpa.free(prefs.session.pane0_path);
    prefs.session.pane0_path = "";
    gpa.free(prefs.session.pane1_path);
    prefs.session.pane1_path = "";
    freeTabs(gpa, prefs.session.tabs);
    prefs.session.tabs = &.{};
}

pub fn save(prefs: UiPrefs, io: std.Io, dir: std.Io.Dir, gpa: Allocator) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    std.zon.stringify.serialize(prefs, .{}, &out.writer) catch return error.OutOfMemory;
    out.writer.writeByte('\n') catch return error.OutOfMemory;
    try settings.atomicWriteFile(io, dir, file_name, out.written());
}

pub fn cloneTabs(gpa: Allocator, source: []const TabState) error{OutOfMemory}![]TabState {
    if (source.len == 0) return &.{};
    const tabs = try gpa.alloc(TabState, source.len);
    errdefer gpa.free(tabs);
    var initialized: usize = 0;
    errdefer for (tabs[0..initialized]) |tab| {
        gpa.free(tab.pane0_path);
        gpa.free(tab.pane1_path);
    };
    for (source, 0..) |tab, i| {
        tabs[i] = tab;
        tabs[i].pane0_path = "";
        tabs[i].pane1_path = "";
        tabs[i].pane0_path = try gpa.dupe(u8, tab.pane0_path);
        errdefer gpa.free(tabs[i].pane0_path);
        tabs[i].pane1_path = try gpa.dupe(u8, tab.pane1_path);
        initialized = i + 1;
    }
    return tabs;
}

pub fn freeTabs(gpa: Allocator, tabs: []TabState) void {
    for (tabs) |tab| {
        gpa.free(tab.pane0_path);
        gpa.free(tab.pane1_path);
    }
    if (tabs.len > 0) gpa.free(tabs);
}

test "preferences and session round trip" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var tabs = [_]TabState{.{
        .pane0_path = "/home/relay",
        .pane1_site = 7,
        .pane1_path = "/srv",
    }};
    const original: UiPrefs = .{
        .download_dir = "/tmp/downloads",
        .confirm_delete = false,
        .density = .dense,
        .monospace_lists = true,
        .date_format = .relative,
        .vim_mode = true,
        .reconnect_on_launch = true,
        .session = .{
            .pane0_path = "/home/relay",
            .pane1_site = 7,
            .pane1_path = "/srv",
            .focused_pane = 1,
            .restore_queue = true,
            .tabs = &tabs,
        },
    };
    try save(original, io, tmp.dir, std.testing.allocator);
    var loaded = try load(io, tmp.dir, std.testing.allocator);
    defer deinit(std.testing.allocator, &loaded);
    try std.testing.expectEqualStrings(original.download_dir, loaded.download_dir);
    try std.testing.expectEqual(original.density, loaded.density);
    try std.testing.expectEqualStrings(original.session.pane1_path, loaded.session.pane1_path);
    try std.testing.expect(loaded.session.restore_queue);
    try std.testing.expectEqual(@as(usize, 1), loaded.session.tabs.len);
}

test "missing and corrupt preferences use safe defaults" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var missing = try load(io, tmp.dir, std.testing.allocator);
    defer deinit(std.testing.allocator, &missing);
    try std.testing.expect(missing.confirm_delete);
    try std.testing.expect(!missing.reconnect_on_launch);
    try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = "not zon" });
    var corrupt = try load(io, tmp.dir, std.testing.allocator);
    defer deinit(std.testing.allocator, &corrupt);
    try std.testing.expectEqual(Density.compact, corrupt.density);
}

test {
    std.testing.refAllDecls(@This());
}

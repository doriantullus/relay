//! transcript — the bottom-panel Transcript tab (docs/UX.md): a read-only
//! monospace NSTextView fed by `transcript_line` bridge events, appended via
//! NSTextStorage. Per-connection filter popup, direction-colored lines
//! (semantic colors only), follow-tail unless the user scrolled up, ring cap
//! of ~20k lines matching the core transcript, Copy All + Save….
//!
//! Structure: `Model` is pure Zig (ring, filter, UTF-16 range accounting for
//! NSTextStorage edits) and fully headless-tested; `TranscriptController`
//! owns the AppKit surface and mutates UI state on the main thread only,
//! driven by the bridge drain (run-to-completion batches).
//!
//! Also exports `uiglue`: the small set of AppKit control helpers this task
//! and transfers.zig share. TODO(m2-dedupe): promote uiglue (and the few
//! raw selectors in the view layer below) into relay_mac in phase 3 — they
//! live here only because adding files to src/macos/root.zig is out of this
//! task's footprint.

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");

const objc = mac.objc;
const c = objc.c;
const foundation = mac.foundation;
const runtime = mac.runtime;
const panels = mac.appkit.panels;

const Allocator = std.mem.Allocator;
const NSInteger = foundation.NSInteger;
const NSUInteger = foundation.NSUInteger;
const NSRange = foundation.NSRange;
const NSRect = foundation.NSRect;

// ---------------------------------------------------------------------------
// Pure model — headless-tested.
// ---------------------------------------------------------------------------

/// Ring cap; matches relay_core's transcript ring (log/transcript.zig).
pub const ring_capacity: usize = 20_000;

/// Stored bytes per line; longer input is truncated (core caps at 256).
pub const max_line_bytes: usize = 512;

/// Render class for one line. Direction maps to semantic colors per
/// docs/UX.md: client=labelColor, server=secondaryLabelColor, errors=
/// systemRed; info chatter renders tertiary.
pub const LineKind = enum(u2) { client, server, err, info };

/// FTP 4xx/5xx server replies and info lines announcing errors render red;
/// everything else colors by direction.
pub fn classifyLine(dir: relay.transcript.Direction, text: []const u8) LineKind {
    switch (dir) {
        .client => return .client,
        .server => {
            if (text.len >= 3 and (text[0] == '4' or text[0] == '5') and
                std.ascii.isDigit(text[1]) and std.ascii.isDigit(text[2]))
                return .err;
            return .server;
        },
        .info => {
            if (std.ascii.startsWithIgnoreCase(text, "error")) return .err;
            return .info;
        },
    }
}

/// Copies `src` into `dst` replacing every invalid UTF-8 byte with '?', so
/// downstream NSString creation and UTF-16 length math never fail.
/// `dst.len >= src.len` required; returns the written prefix.
pub fn sanitizeUtf8(src: []const u8, dst: []u8) []const u8 {
    std.debug.assert(dst.len >= src.len);
    var i: usize = 0;
    var n: usize = 0;
    while (i < src.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(src[i]) catch {
            dst[n] = '?';
            n += 1;
            i += 1;
            continue;
        };
        if (i + seq_len > src.len or !std.unicode.utf8ValidateSlice(src[i..][0..seq_len])) {
            dst[n] = '?';
            n += 1;
            i += 1;
            continue;
        }
        @memcpy(dst[n..][0..seq_len], src[i..][0..seq_len]);
        n += seq_len;
        i += seq_len;
    }
    return dst[0..n];
}

/// Follow-tail geometry: the view counts as "at the bottom" when the gap
/// between the document end and the visible bottom edge is within `slack`
/// points (scroll-position float noise).
pub fn isAtBottom(doc_height: f64, clip_origin_y: f64, clip_height: f64, slack: f64) bool {
    return doc_height - (clip_origin_y + clip_height) <= slack;
}

pub const Model = struct {
    pub const Line = struct {
        conn: u64,
        kind: LineKind,
        /// UTF-16 code units of `text` — NSTextStorage range math operates
        /// in UTF-16, so trims must subtract this (+1 for the newline).
        utf16_len: u32,
        /// Sanitized UTF-8, gpa-owned by the model.
        text: []u8,
    };

    pub const Appended = struct {
        /// The new line matches the filter passed to `append`.
        visible: bool,
        /// First line ever seen from this connection id (popup grows).
        new_conn: bool,
        /// Live lines dropped from the front to hold the cap.
        trimmed_lines: usize = 0,
        /// UTF-16 units (newline included) of the dropped lines that
        /// matched the filter — delete this prefix from the text storage.
        trimmed_visible_utf16: u64 = 0,
    };

    gpa: Allocator,
    capacity: usize,
    /// Live lines are `lines.items[head..]`; the head offset amortizes
    /// front-trims, compacted once it crosses `compact_threshold`.
    lines: std.ArrayList(Line) = .empty,
    head: usize = 0,
    compact_threshold: usize = 4096,
    /// Connection ids in first-seen order (drives the filter popup).
    conns: std.AutoArrayHashMapUnmanaged(u64, void) = .empty,

    pub fn init(gpa: Allocator, capacity: usize) Model {
        std.debug.assert(capacity > 0);
        return .{ .gpa = gpa, .capacity = capacity };
    }

    pub fn deinit(self: *Model) void {
        for (self.live()) |line| self.gpa.free(line.text);
        self.lines.deinit(self.gpa);
        self.conns.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Model) usize {
        return self.lines.items.len - self.head;
    }

    pub fn live(self: *const Model) []const Line {
        return self.lines.items[self.head..];
    }

    pub fn connCount(self: *const Model) usize {
        return self.conns.count();
    }

    pub fn connAt(self: *const Model, index: usize) u64 {
        return self.conns.keys()[index];
    }

    pub fn matchesFilter(line: Line, filter: ?u64) bool {
        const want = filter orelse return true;
        return line.conn == want;
    }

    /// Sanitizes, truncates, appends, and trims the ring back to capacity.
    /// `filter` is the controller's CURRENT filter, so the result carries
    /// exactly the text-storage edits the view must mirror.
    pub fn append(
        self: *Model,
        conn: u64,
        kind: LineKind,
        raw: []const u8,
        filter: ?u64,
    ) error{OutOfMemory}!Appended {
        const trimmed_input = std.mem.trimEnd(u8, raw, "\r\n");
        const capped = trimmed_input[0..@min(trimmed_input.len, max_line_bytes)];
        var buf: [max_line_bytes]u8 = undefined;
        const clean = sanitizeUtf8(capped, &buf);
        // Valid UTF-8 by construction; cannot fail.
        const utf16_len = std.unicode.calcUtf16LeLen(clean) catch unreachable;

        const text = try self.gpa.dupe(u8, clean);
        errdefer self.gpa.free(text);
        const gop = try self.conns.getOrPut(self.gpa, conn);
        const new_conn = !gop.found_existing;
        const line: Line = .{
            .conn = conn,
            .kind = kind,
            .utf16_len = @intCast(utf16_len),
            .text = text,
        };
        try self.lines.append(self.gpa, line);

        var result: Appended = .{
            .visible = matchesFilter(line, filter),
            .new_conn = new_conn,
        };
        while (self.count() > self.capacity) {
            const dropped = self.lines.items[self.head];
            if (matchesFilter(dropped, filter)) {
                result.trimmed_visible_utf16 += @as(u64, dropped.utf16_len) + 1;
            }
            result.trimmed_lines += 1;
            self.gpa.free(dropped.text);
            self.head += 1;
        }
        if (self.head >= self.compact_threshold) self.compact();
        return result;
    }

    fn compact(self: *Model) void {
        const n = self.count();
        std.mem.copyForwards(Line, self.lines.items[0..n], self.lines.items[self.head..]);
        self.lines.shrinkRetainingCapacity(n);
        self.head = 0;
    }

    /// All live lines matching `filter`, newline-joined; caller frees.
    pub fn visibleText(self: *const Model, gpa: Allocator, filter: ?u64) error{OutOfMemory}![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (self.live()) |line| {
            if (!matchesFilter(line, filter)) continue;
            try out.appendSlice(gpa, line.text);
            try out.append(gpa, '\n');
        }
        return out.toOwnedSlice(gpa);
    }
};

// ---------------------------------------------------------------------------
// Shared AppKit control glue.
// ---------------------------------------------------------------------------
/// The shared AppKit control kit now lives in relay_mac. Re-exported under
/// the historical `uiglue` name so transfers.zig (which imports it) and
/// this file keep working. The two retained/target-action builders are
/// `makeFieldLabel` and `makeEmptyPopup` (see appkit/controls.zig).
pub const uiglue = mac.appkit.controls;

// ---------------------------------------------------------------------------
// Controller — AppKit view layer (main thread only).
// ---------------------------------------------------------------------------

const NSFontAttributeName = @extern(*const c.id, .{ .name = "NSFontAttributeName" });
const NSForegroundColorAttributeName = @extern(*const c.id, .{ .name = "NSForegroundColorAttributeName" });

var g_target_class: ?runtime.DefinedClass = null;

fn targetClass() runtime.Error!runtime.DefinedClass {
    if (g_target_class) |dc| return dc;
    const dc = try runtime.defineClass("RelayTranscriptTarget", "NSObject", &.{}, .{
        .{ "relayTranscriptFilter:", impFilterChanged },
        .{ "relayTranscriptCopyAll:", impCopyAll },
        .{ "relayTranscriptSave:", impSave },
        .{ "relayTranscriptBounds:", impBoundsChanged },
    });
    g_target_class = dc;
    return dc;
}

const bar_h: f64 = 28;
const default_w: f64 = 860;
const default_h: f64 = 200;
const bottom_slack: f64 = 2.0;

pub const TranscriptController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    model: Model,
    /// null = all connections; else the connection id to show.
    filter: ?u64 = null,
    follow_tail: bool = true,
    /// Verbose lines (keepalive chatter) hidden by default, matching the
    /// core transcript contract. TODO(m2-followup): View-menu toggle.
    show_verbose: bool = false,

    // AppKit handles (owned).
    root: objc.Object,
    bar: objc.Object,
    popup: objc.Object,
    copy_button: objc.Object,
    save_button: objc.Object,
    scroll: objc.Object,
    text_view: objc.Object,
    target: objc.Object,
    /// Cached attribute dictionaries, indexed by LineKind.
    attrs: [4]objc.Object,

    pub fn create(gpa: Allocator, core: *bridge.AppCore) !*TranscriptController {
        const self = try gpa.create(TranscriptController);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .core = core,
            .model = Model.init(gpa, ring_capacity),
            .root = undefined,
            .bar = undefined,
            .popup = undefined,
            .copy_button = undefined,
            .save_button = undefined,
            .scroll = undefined,
            .text_view = undefined,
            .target = undefined,
            .attrs = undefined,
        };
        errdefer self.model.deinit();

        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();

        const dc = try targetClass();
        self.target = dc.newWithState(self);
        self.buildViews();
        self.buildAttrs();

        try core.registerListener(.transcript_line, self, onTranscriptLine);
        self.seedFromCore();
        return self;
    }

    /// Tests/teardown only — listeners cannot unregister, so destroy only
    /// after the core stopped dispatching (post-shutdown).
    pub fn destroy(self: *TranscriptController) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        foundation.removeObserver(self.target);
        for (self.attrs) |dict| uiglue.release(dict);
        uiglue.release(self.text_view);
        uiglue.release(self.scroll);
        uiglue.release(self.popup);
        uiglue.release(self.copy_button);
        uiglue.release(self.save_button);
        uiglue.release(self.bar);
        uiglue.release(self.root);
        uiglue.release(self.target);
        self.model.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// The view to embed as the panel's Transcript tab.
    pub fn view(self: *TranscriptController) c.id {
        return self.root.value;
    }

    // --- view construction ------------------------------------------------

    fn buildViews(self: *TranscriptController) void {
        self.root = uiglue.makeView(foundation.rect(0, 0, default_w, default_h));

        // Top bar: filter popup + Copy All + Save…; pinned to the top edge.
        self.bar = uiglue.makeView(foundation.rect(0, default_h - bar_h, default_w, bar_h));
        uiglue.setAutoresizing(self.bar, uiglue.mask_width_sizable | uiglue.mask_min_y_margin);
        self.popup = uiglue.makeEmptyPopup(
            foundation.rect(8, 3, 190, 22),
            self.target.value,
            "relayTranscriptFilter:",
        );
        uiglue.popupAddItem(self.popup, "All Connections");
        self.copy_button = uiglue.makeButton(
            "Copy All",
            foundation.rect(206, 3, 86, 22),
            self.target.value,
            "relayTranscriptCopyAll:",
        );
        self.save_button = uiglue.makeButton(
            "Save…",
            foundation.rect(298, 3, 76, 22),
            self.target.value,
            "relayTranscriptSave:",
        );
        uiglue.addSubview(self.bar, self.popup);
        uiglue.addSubview(self.bar, self.copy_button);
        uiglue.addSubview(self.bar, self.save_button);

        // TextKit stack. TODO(m2-dedupe): NSTextView setup belongs in a
        // relay_mac text_view.zig wrapper.
        const text_h = default_h - bar_h;
        const scroll = foundation.class("NSScrollView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{foundation.rect(0, 0, default_w, text_h)});
        scroll.msgSend(void, "setHasVerticalScroller:", .{true});
        scroll.msgSend(void, "setAutohidesScrollers:", .{true});
        uiglue.setAutoresizing(scroll, uiglue.mask_width_sizable | uiglue.mask_height_sizable);
        self.scroll = scroll;

        const huge: f64 = 1.0e7;
        const tv = foundation.class("NSTextView").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{foundation.rect(0, 0, default_w, text_h)});
        tv.msgSend(void, "setEditable:", .{false});
        tv.msgSend(void, "setSelectable:", .{true});
        tv.msgSend(void, "setMinSize:", .{foundation.size(0, 0)});
        tv.msgSend(void, "setMaxSize:", .{foundation.size(huge, huge)});
        tv.msgSend(void, "setVerticallyResizable:", .{true});
        tv.msgSend(void, "setHorizontallyResizable:", .{false});
        uiglue.setAutoresizing(tv, uiglue.mask_width_sizable);
        const container = tv.msgSend(objc.Object, "textContainer", .{});
        container.msgSend(void, "setContainerSize:", .{foundation.size(default_w, huge)});
        container.msgSend(void, "setWidthTracksTextView:", .{true});
        self.text_view = tv;
        scroll.msgSend(void, "setDocumentView:", .{tv});

        // Follow-tail tracking: the clip view posts bounds changes on
        // scroll; the handler filters by object (the wrapper observes with
        // object:nil by convention).
        const clip = scroll.msgSend(objc.Object, "contentView", .{});
        clip.msgSend(void, "setPostsBoundsChangedNotifications:", .{true});
        foundation.observeNotification(
            "NSViewBoundsDidChangeNotification",
            self.target,
            "relayTranscriptBounds:",
        );

        uiglue.addSubview(self.root, self.bar);
        uiglue.addSubview(self.root, self.scroll);
    }

    fn buildAttrs(self: *TranscriptController) void {
        const font = foundation.monospacedSystemFont(11, .regular);
        for (std.enums.values(LineKind)) |kind| {
            const color = switch (kind) {
                .client => foundation.Color.label.object(),
                .server => foundation.Color.secondary_label.object(),
                .err => foundation.Color.system_red.object(),
                .info => foundation.Color.tertiary_label.object(),
            };
            const dict = foundation.class("NSMutableDictionary").msgSend(objc.Object, "dictionary", .{});
            dict.msgSend(void, "setObject:forKey:", .{ font.value, NSFontAttributeName.* });
            dict.msgSend(void, "setObject:forKey:", .{ color.value, NSForegroundColorAttributeName.* });
            _ = dict.msgSend(c.id, "retain", .{});
            self.attrs[@intFromEnum(kind)] = dict;
        }
    }

    // --- event intake -------------------------------------------------------

    fn onTranscriptLine(self: *TranscriptController, line: relay.events.CoreEvent.TranscriptLine) void {
        if (line.verbose and !self.show_verbose) return;
        self.ingest(line.connection_id, line.dir, line.text);
    }

    /// Pre-listener backlog: the app-level transcript ring (no connection
    /// ids there; seeded as connection 0 = "App").
    fn seedFromCore(self: *TranscriptController) void {
        var snap = self.core.transcriptSnapshot(self.gpa) catch return;
        defer snap.deinit(self.gpa);
        for (snap.lines) |line| {
            if (line.verbose and !self.show_verbose) continue;
            self.ingest(0, line.dir, line.text);
        }
    }

    fn ingest(self: *TranscriptController, conn: u64, dir: relay.transcript.Direction, text: []const u8) void {
        const kind = classifyLine(dir, text);
        const appended = self.model.append(conn, kind, text, self.filter) catch return;
        if (appended.new_conn) {
            var buf: [32]u8 = undefined;
            uiglue.popupAddItem(self.popup, connTitle(&buf, conn));
        }
        if (!appended.visible) return;

        const live = self.model.live();
        const line = live[live.len - 1];
        self.appendLineToStorage(line.kind, line.text);
        if (appended.trimmed_visible_utf16 > 0) self.trimStorageFront(appended.trimmed_visible_utf16);
        if (self.follow_tail) self.scrollToEnd();
    }

    // --- text storage edits -------------------------------------------------

    fn storage(self: *TranscriptController) objc.Object {
        return self.text_view.msgSend(objc.Object, "textStorage", .{});
    }

    fn appendLineToStorage(self: *TranscriptController, kind: LineKind, text: []const u8) void {
        var buf: [max_line_bytes + 1]u8 = undefined;
        @memcpy(buf[0..text.len], text);
        buf[text.len] = '\n';
        const str = foundation.nsString(buf[0 .. text.len + 1]);
        const attr_str = foundation.class("NSAttributedString").msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithString:attributes:", .{ str, self.attrs[@intFromEnum(kind)] });
        self.storage().msgSend(void, "appendAttributedString:", .{attr_str});
        attr_str.msgSend(void, "release", .{});
    }

    fn trimStorageFront(self: *TranscriptController, utf16_units: u64) void {
        const ts = self.storage();
        const len = ts.msgSend(NSUInteger, "length", .{});
        const n = @min(utf16_units, len);
        if (n == 0) return;
        ts.msgSend(void, "deleteCharactersInRange:", .{NSRange{ .location = 0, .length = n }});
    }

    fn scrollToEnd(self: *TranscriptController) void {
        const len = self.storage().msgSend(NSUInteger, "length", .{});
        self.text_view.msgSend(void, "scrollRangeToVisible:", .{NSRange{ .location = len, .length = 0 }});
    }

    /// Full re-render under the current filter (filter popup changes).
    fn rebuildStorage(self: *TranscriptController) void {
        const ts = self.storage();
        ts.msgSend(void, "beginEditing", .{});
        const len = ts.msgSend(NSUInteger, "length", .{});
        ts.msgSend(void, "deleteCharactersInRange:", .{NSRange{ .location = 0, .length = len }});
        ts.msgSend(void, "endEditing", .{});
        for (self.model.live()) |line| {
            if (!Model.matchesFilter(line, self.filter)) continue;
            self.appendLineToStorage(line.kind, line.text);
        }
        self.follow_tail = true;
        self.scrollToEnd();
    }

    // --- actions --------------------------------------------------------------

    fn applyFilterSelection(self: *TranscriptController) void {
        const idx = uiglue.popupSelectedIndex(self.popup);
        const new_filter: ?u64 = if (idx <= 0)
            null
        else if (@as(usize, @intCast(idx)) - 1 < self.model.connCount())
            self.model.connAt(@as(usize, @intCast(idx)) - 1)
        else
            null;
        if (std.meta.eql(new_filter, self.filter)) return;
        self.filter = new_filter;
        self.rebuildStorage();
    }

    fn copyAll(self: *TranscriptController) void {
        const text = self.model.visibleText(self.gpa, self.filter) catch return;
        defer self.gpa.free(text);
        foundation.writeStringToPasteboard(text);
    }

    fn beginSave(self: *TranscriptController) void {
        _ = panels.beginSavePanel(null, .{
            .filename = "relay-transcript.txt",
            .prompt = "Save",
            .message = "Save the visible transcript lines as plain text.",
        }, self, onSavePath);
    }

    fn onSavePath(self: *TranscriptController, maybe_path: ?[]const u8) void {
        const path = maybe_path orelse return;
        const text = self.model.visibleText(self.gpa, self.filter) catch return;
        defer self.gpa.free(text);
        std.Io.Dir.cwd().writeFile(self.core.io, .{ .sub_path = path, .data = text }) catch |err| {
            std.log.warn("transcript save to {s} failed: {t}", .{ path, err });
        };
    }

    fn boundsChanged(self: *TranscriptController, note_object: c.id) void {
        const clip = self.scroll.msgSend(objc.Object, "contentView", .{});
        if (note_object != clip.value) return;
        const doc = self.scroll.msgSend(objc.Object, "documentView", .{});
        if (doc.value == null) return;
        const doc_frame = doc.msgSend(NSRect, "frame", .{});
        const clip_bounds = clip.msgSend(NSRect, "bounds", .{});
        self.follow_tail = isAtBottom(
            doc_frame.size.height,
            clip_bounds.origin.y,
            clip_bounds.size.height,
            bottom_slack,
        );
    }
};

pub fn connTitle(buf: []u8, conn: u64) []const u8 {
    if (conn == 0) return "App";
    return std.fmt.bufPrint(buf, "Connection {d}", .{conn}) catch "Connection";
}

// --- target class IMPs -------------------------------------------------------

fn controllerOf(target: c.id) *TranscriptController {
    return g_target_class.?.state(TranscriptController, target);
}

fn impFilterChanged(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).applyFilterSelection();
}

fn impCopyAll(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).copyAll();
}

fn impSave(target: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    controllerOf(target).beginSave();
}

fn impBoundsChanged(target: c.id, _: c.SEL, note: c.id) callconv(.c) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    // TODO(m2-dedupe): notification-object accessor → relay_mac foundation.
    const obj = objc.Object.fromId(note).msgSend(c.id, "object", .{});
    controllerOf(target).boundsChanged(obj);
}

// ---------------------------------------------------------------------------
// Headless tests
// ---------------------------------------------------------------------------
const testing = std.testing;

test "model: append, ring trim, utf16 accounting" {
    var model = Model.init(testing.allocator, 4);
    defer model.deinit();

    var buf: [16]u8 = undefined;
    for (0..4) |i| {
        const text = try std.fmt.bufPrint(&buf, "line{d}", .{i});
        const appended = try model.append(1, .server, text, null);
        try testing.expect(appended.visible);
        try testing.expectEqual(@as(usize, 0), appended.trimmed_lines);
    }
    try testing.expectEqual(@as(usize, 4), model.count());

    // Fifth append evicts "line0": 5 chars + newline = 6 utf16 units.
    const appended = try model.append(1, .client, "line4", null);
    try testing.expectEqual(@as(usize, 1), appended.trimmed_lines);
    try testing.expectEqual(@as(u64, 6), appended.trimmed_visible_utf16);
    try testing.expectEqual(@as(usize, 4), model.count());
    try testing.expectEqualStrings("line1", model.live()[0].text);
    try testing.expectEqualStrings("line4", model.live()[3].text);
    try testing.expectEqual(LineKind.client, model.live()[3].kind);
}

test "model: trim accounting respects the active filter" {
    var model = Model.init(testing.allocator, 2);
    defer model.deinit();

    _ = try model.append(1, .client, "aa", 2); // not visible under filter 2
    _ = try model.append(2, .server, "bbb", 2);
    // Evicts the conn-1 line: zero visible utf16 should be trimmed.
    const third = try model.append(2, .server, "cc", 2);
    try testing.expect(third.visible);
    try testing.expectEqual(@as(usize, 1), third.trimmed_lines);
    try testing.expectEqual(@as(u64, 0), third.trimmed_visible_utf16);
    // Evicts the first conn-2 line ("bbb"): 3 + newline = 4 units.
    const fourth = try model.append(2, .server, "dd", 2);
    try testing.expectEqual(@as(u64, 4), fourth.trimmed_visible_utf16);
}

test "model: utf16 length counts non-BMP as surrogate pairs" {
    var model = Model.init(testing.allocator, 4);
    defer model.deinit();
    _ = try model.append(1, .info, "héj", null); // 3 UTF-16 units
    _ = try model.append(1, .info, "a😀", null); // 1 + 2 (surrogate pair)
    try testing.expectEqual(@as(u32, 3), model.live()[0].utf16_len);
    try testing.expectEqual(@as(u32, 3), model.live()[1].utf16_len);
}

test "model: head compaction keeps live lines intact" {
    var model = Model.init(testing.allocator, 2);
    defer model.deinit();
    model.compact_threshold = 2;

    var buf: [16]u8 = undefined;
    for (0..7) |i| {
        _ = try model.append(9, .server, try std.fmt.bufPrint(&buf, "l{d}", .{i}), null);
    }
    try testing.expectEqual(@as(usize, 2), model.count());
    try testing.expect(model.head < 2); // compacted at least once
    try testing.expectEqualStrings("l5", model.live()[0].text);
    try testing.expectEqualStrings("l6", model.live()[1].text);
}

test "model: connection registry is first-seen ordered and deduped" {
    var model = Model.init(testing.allocator, 8);
    defer model.deinit();
    try testing.expect((try model.append(7, .client, "a", null)).new_conn);
    try testing.expect(!(try model.append(7, .server, "b", null)).new_conn);
    try testing.expect((try model.append(3, .client, "c", null)).new_conn);
    try testing.expectEqual(@as(usize, 2), model.connCount());
    try testing.expectEqual(@as(u64, 7), model.connAt(0));
    try testing.expectEqual(@as(u64, 3), model.connAt(1));
}

test "model: visibleText honors the filter and joins with newlines" {
    var model = Model.init(testing.allocator, 8);
    defer model.deinit();
    _ = try model.append(1, .client, "USER fred", null);
    _ = try model.append(2, .server, "230 OK", null);
    _ = try model.append(1, .server, "331 Password", null);

    const all = try model.visibleText(testing.allocator, null);
    defer testing.allocator.free(all);
    try testing.expectEqualStrings("USER fred\n230 OK\n331 Password\n", all);

    const only1 = try model.visibleText(testing.allocator, 1);
    defer testing.allocator.free(only1);
    try testing.expectEqualStrings("USER fred\n331 Password\n", only1);
}

test "model: input is CRLF-trimmed, truncated, and sanitized" {
    var model = Model.init(testing.allocator, 4);
    defer model.deinit();
    _ = try model.append(1, .server, "226 Done\r\n", null);
    try testing.expectEqualStrings("226 Done", model.live()[0].text);

    const long = "x" ** (max_line_bytes + 100);
    _ = try model.append(1, .server, long, null);
    try testing.expectEqual(max_line_bytes, model.live()[1].text.len);

    _ = try model.append(1, .server, "ok\xff\xfeend", null);
    try testing.expectEqualStrings("ok??end", model.live()[2].text);
}

test "sanitizeUtf8 passes valid text through and replaces invalid bytes" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("héllo ☃", sanitizeUtf8("héllo ☃", &buf));
    try testing.expectEqualStrings("a?b", sanitizeUtf8("a\xc3b", &buf)); // truncated seq
    try testing.expectEqualStrings("??", sanitizeUtf8("\xff\xff", &buf));
    try testing.expectEqualStrings("", sanitizeUtf8("", &buf));
}

test "classifyLine: direction + error detection" {
    try testing.expectEqual(LineKind.client, classifyLine(.client, "PASS ****"));
    try testing.expectEqual(LineKind.server, classifyLine(.server, "230 Login successful"));
    try testing.expectEqual(LineKind.err, classifyLine(.server, "550 No such file"));
    try testing.expectEqual(LineKind.err, classifyLine(.server, "421 Service not available"));
    try testing.expectEqual(LineKind.server, classifyLine(.server, "5x not a code"));
    try testing.expectEqual(LineKind.info, classifyLine(.info, "reconnecting"));
    try testing.expectEqual(LineKind.err, classifyLine(.info, "ERROR: handshake failed"));
}

test "isAtBottom: follow-tail geometry" {
    // Document 1000pt tall, viewport 200pt.
    try testing.expect(isAtBottom(1000, 800, 200, 2)); // exactly at end
    try testing.expect(isAtBottom(1000, 799, 200, 2)); // within slack
    try testing.expect(!isAtBottom(1000, 500, 200, 2)); // scrolled up
    try testing.expect(isAtBottom(100, 0, 200, 2)); // doc shorter than view
}

test "connTitle formats" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("App", connTitle(&buf, 0));
    try testing.expectEqualStrings("Connection 12", connTitle(&buf, 12));
}

test "model: allocation failures neither leak nor corrupt" {
    const Fns = struct {
        fn cycle(gpa: Allocator) !void {
            var model = Model.init(gpa, 2);
            defer model.deinit();
            _ = try model.append(1, .client, "one", null);
            _ = try model.append(2, .server, "two", null);
            _ = try model.append(1, .info, "three", 1);
            const text = try model.visibleText(gpa, null);
            gpa.free(text);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Fns.cycle, .{});
}

test "target class defines and round-trips state (headless)" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const dc = try targetClass();
    var probe: TranscriptController = undefined;
    probe.filter = 42;
    const obj = dc.newWithState(&probe);
    defer obj.msgSend(void, "release", .{});
    try testing.expectEqual(&probe, dc.state(TranscriptController, obj.value));
}

test {
    std.testing.refAllDecls(@This());
}

//! edit_sessions — edit-in-external-editor (M3), the Transmit workflow done
//! right. One `EditSession` per edited remote file:
//!
//!  1. DOWNLOAD: the remote file lands in a per-session temp dir
//!     (`~/Library/Caches/us.doriantull.relay/edit/<session>/<name>`)
//!     through the normal bridge queue, so the session is visible in the
//!     Transfers panel like any other item. The listing entry's mtime is
//!     recorded as the conflict baseline.
//!  2. OPEN: NSWorkspace opens the temp file in the default app for its
//!     type ("open" semantics), falling back to the stock text editor
//!     ("open -t"). A prefs editor choice can slot in later; spawning
//!     $EDITOR terminal editors is out of scope for M3.
//!  3. WATCH: an FSEvents watcher (relay_mac.fsevents, main-queue callback)
//!     covers the session dir. Any change counts as a save.
//!  4. SAVE → RE-STAT → UPLOAD: on save the REMOTE mtime is re-checked
//!     first (a bridge listing of the parent dir — stat by entry). If it
//!     changed since download, a conflict sheet offers Overwrite /
//!     Save as Copy / Cancel; otherwise the upload is enqueued straight
//!     back to the original remote path. After an overwrite completes the
//!     baseline mtime refreshes via one more re-stat, so the session's own
//!     upload never reads as a foreign change.
//!
//! An app_nap Activity (user_initiated) is held while ANY session has a
//! live watcher — the classic Transmit stall: App Nap pausing FSEvents
//! delivery minutes into an editing session.
//!
//! Threading: everything here runs on the main thread (FSEvents callbacks
//! ride the main queue; core results arrive through AppCore's listener
//! dispatch). Lifetime: listeners cannot unregister, so call `deinit`
//! (ends sessions: watchers stopped, temp dirs deleted) BEFORE
//! `AppCore.shutdown()`, and `destroy` only after it (or never — app
//! lifetime), mirroring BrowserController.

const std = @import("std");
const relay = @import("relay_core");
const mac = @import("relay_mac");
const bridge = @import("../bridge.zig");
const prefs_mod = @import("prefs.zig");

const objc = mac.objc;
const foundation = mac.foundation;
const fsevents = mac.fsevents;
const app_nap = mac.app_nap;
const panels = mac.appkit.panels;
const window_mod = mac.appkit.window;

const vfs_mod = relay.vfs.iface;
const path_mod = relay.vfs.path;
const item_mod = relay.queue.item;
const events_mod = relay.events;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Command-palette identifier for the Cmd+E command (`prefs.Command
/// .edit_external` is the registry id; this is the palette-facing name).
pub const command_id = "file.editExternal";

/// Pane token for the controller's re-stat listings: never collides with
/// the browser panes (1, 2), so their listeners drop these results.
pub const edit_pane_token: bridge.PaneToken = 0xED17_0000;

/// FSEvents coalescing window for save detection: long enough to fold an
/// editor's atomic-save dance (tmp write + rename) into one trigger.
pub const watch_latency_s: f64 = 0.35;

/// One file the user asked to edit (the active pane's selection, captured
/// by the integrator's TargetProvider). All slices are BORROWED for the
/// duration of the editTarget(s) call; the session copies what it keeps.
pub const EditTarget = struct {
    site_id: u64,
    /// Remote directory containing the file.
    dir: []const u8,
    name: []const u8,
    /// From the listing entry at selection time.
    size: ?u64 = null,
    /// Conflict baseline; null = unknown (first save uploads unprompted).
    mtime: ?i64 = null,
};

/// Supplies the current selection when the Cmd+E command fires. The
/// integrator wires the browser's active pane in; appended targets must
/// stay valid for the duration of the collect call only.
pub const TargetProvider = struct {
    ctx: *anyopaque,
    collectFn: *const fn (
        ctx: *anyopaque,
        gpa: Allocator,
        out: *std.ArrayList(EditTarget),
    ) error{OutOfMemory}!void,
};

pub const ConflictChoice = enum { overwrite, duplicate, cancel };

/// Conflict presentation override (headless tests, future custom UI).
/// Called with the sheet up conceptually: answer via `resolveConflict`.
pub const ConflictHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, controller: *EditSessionsController, session_id: u64, name: []const u8) void,
};

pub const SessionState = enum {
    /// Download item in flight.
    downloading,
    /// Watching the temp dir for saves.
    watching,
    /// Save seen; remote re-stat (conflict check) in flight.
    checking,
    /// Conflict sheet up; waiting for resolveConflict.
    conflict,
    /// Upload item in flight.
    uploading,
    /// Post-overwrite re-stat in flight (adopting the new remote mtime).
    refreshing,
};

// ---------------------------------------------------------------------------
// Pure logic (headless-tested)
// ---------------------------------------------------------------------------

pub const SaveDecision = enum { upload, conflict };

/// The conflict rule, pure over mtimes: a conflict exists exactly when both
/// the recorded (at-download) and re-statted remote mtimes are known and
/// differ. Either side unknown (server without mtimes, file deleted
/// remotely, listing failed) degrades to upload — the queue item's own
/// failure handling covers an unreachable site.
pub fn decideOnSave(recorded_mtime: ?i64, restat_mtime: ?i64) SaveDecision {
    const recorded = recorded_mtime orelse return .upload;
    const current = restat_mtime orelse return .upload;
    return if (recorded == current) .upload else .conflict;
}

/// mtime of the named entry in a listing, null when absent or unknown —
/// the "stat" half of the conflict check, pure for testing.
pub fn entryMtime(entries: []const vfs_mod.Entry, name: []const u8) ?i64 {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.mtime;
    }
    return null;
}

/// Default cache base in local-VFS coordinates (the app's local root is
/// "/", so this is also the real filesystem path):
/// `$HOME/Library/Caches/us.doriantull.relay/edit`.
pub fn defaultCacheBase(gpa: Allocator) error{ OutOfMemory, NoHomeDirectory }![]u8 {
    const home = std.c.getenv("HOME") orelse return error.NoHomeDirectory;
    return std.fmt.allocPrint(gpa, "{s}/Library/Caches/{s}/edit", .{
        std.mem.span(home), bridge.app_support_bundle_id,
    }) catch return error.OutOfMemory;
}

/// `<base>/<session-id>` — the per-session temp dir.
pub fn sessionDir(gpa: Allocator, base: []const u8, session_id: u64) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{d}", .{ base, session_id });
}

/// "Save as Copy" name: `notes.txt` → `notes copy.txt`; extensionless and
/// dotfile names get a plain ` copy` suffix.
pub fn duplicateName(gpa: Allocator, name: []const u8) error{OutOfMemory}![]u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.');
    if (dot == null or dot.? == 0) {
        return std.fmt.allocPrint(gpa, "{s} copy", .{name});
    }
    return std.fmt.allocPrint(gpa, "{s} copy{s}", .{ name[0..dot.?], name[dot.?..] });
}

/// Normalized local-VFS path → sub-path relative to the core's local root
/// ("." for the root itself); mirrors core/vfs/local.zig's mapping so
/// std.Io.Dir operations land exactly where queue transfers do.
fn relFromVfs(p: []const u8) []const u8 {
    std.debug.assert(path_mod.isNormalized(p));
    return if (p.len == 1) "." else p[1..];
}

// ---------------------------------------------------------------------------
// EditSession
// ---------------------------------------------------------------------------

const EditSession = struct {
    id: u64,
    controller: *EditSessionsController,
    site_id: u64,
    /// All gpa-owned by the session.
    remote_dir: []u8,
    remote_path: []u8,
    name: []u8,
    local_dir: []u8,
    local_path: []u8,

    state: SessionState,
    /// Conflict baseline: the remote mtime this session last synced with.
    recorded_mtime: ?i64,
    /// A save landed while a check/upload/sheet was in flight; re-run the
    /// save flow when the session returns to watching.
    dirty: bool = false,

    download_item: ?bridge.ItemId = null,
    upload_item: ?bridge.ItemId = null,
    /// The in-flight upload targets remote_path (true) or a duplicate
    /// (false): only original-path uploads refresh the baseline after.
    upload_to_original: bool = true,
    stat_request: ?bridge.RequestId = null,
    watcher: ?*fsevents.Watcher = null,

    /// FSEvents callback (main queue): any change in the session dir is a
    /// save. The download itself never triggers this — the watcher starts
    /// only after the download completed.
    fn onFsEvent(session: *EditSession, event: fsevents.Event) void {
        _ = event;
        session.controller.noteLocalChange(session.id);
    }
};

// ---------------------------------------------------------------------------
// EditSessionsController
// ---------------------------------------------------------------------------

pub const EditSessionsController = struct {
    gpa: Allocator,
    core: *bridge.AppCore,
    /// Normalized local-VFS path under which session dirs are created.
    cache_base: []u8,
    /// Headless mode (tests): no NSWorkspace open, no FSEvents watcher, no
    /// App Nap activity, no sheets. Saves are injected via noteLocalChange.
    headless: bool,
    /// false: keep the real FSEvents watcher but skip the NSWorkspace open
    /// (--smoke: the round trip must not launch an editor on the host).
    open_in_editor: bool,
    /// Sheet parent; null falls back to app-modal alerts.
    win: ?window_mod.Window,

    sessions: std.AutoHashMapUnmanaged(u64, *EditSession) = .empty,
    next_session_id: u64 = 1,
    /// Held while any session has a live watcher (App Nap stall fix).
    activity: ?app_nap.Activity = null,
    target_provider: ?TargetProvider = null,
    conflict_hook: ?ConflictHook = null,
    shut_down: bool = false,

    // Observability (tests, smoke).
    uploads_enqueued: u64 = 0,
    conflicts_seen: u64 = 0,

    pub const Options = struct {
        /// Cache base in local-VFS coordinates (== real filesystem path in
        /// the app, whose local root is "/"). null = defaultCacheBase().
        cache_base: ?[]const u8 = null,
        headless: bool = false,
        /// false: watch + upload as usual, but never open an editor
        /// (--smoke's local round trip).
        open_in_editor: bool = true,
        win: ?window_mod.Window = null,
    };

    pub const StartError = error{
        OutOfMemory,
        InvalidPath,
        UnsafeName,
        CacheUnavailable,
        QueueUnavailable,
        ShutDown,
    };

    // ------------------------------------------------------------------ //
    // Lifecycle

    pub fn create(gpa: Allocator, core: *bridge.AppCore, options: Options) !*EditSessionsController {
        const self = try gpa.create(EditSessionsController);
        errdefer gpa.destroy(self);

        var base: []u8 = undefined;
        if (options.cache_base) |b| {
            base = try path_mod.normalize(gpa, b);
        } else {
            const def = try defaultCacheBase(gpa);
            defer gpa.free(def);
            base = try path_mod.normalize(gpa, def);
        }
        errdefer gpa.free(base);

        self.* = .{
            .gpa = gpa,
            .core = core,
            .cache_base = base,
            .headless = options.headless,
            .open_in_editor = options.open_in_editor,
            .win = options.win,
        };
        try core.registerListener(.transfer_state, self, onTransferState);
        try core.registerListener(.listing_done, self, onListingDone);
        return self;
    }

    /// End every session (stop watchers, delete temp dirs, release the
    /// activity). Idempotent. Call BEFORE AppCore.shutdown() — ending a
    /// session cancels its in-flight queue items through the core.
    pub fn deinit(self: *EditSessionsController) void {
        if (self.shut_down) return;
        self.shut_down = true;
        while (true) {
            var it = self.sessions.valueIterator();
            const session = (it.next() orelse break).*;
            self.endSessionInternal(session);
        }
        self.sessions.deinit(self.gpa);
        self.sessions = .empty;
    }

    /// deinit() + free. Only after AppCore.shutdown() (listener entries
    /// reference this controller until then), or never — app lifetime.
    pub fn destroy(self: *EditSessionsController) void {
        self.deinit();
        const gpa = self.gpa;
        gpa.free(self.cache_base);
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------ //
    // Command surface

    /// Bind the Cmd+E command ("file.editExternal"). The integrator calls
    /// this once after creating the registry; the menu leaf lives in
    /// prefs.zig's File menu.
    pub fn register(self: *EditSessionsController, commands: *prefs_mod.CommandRegistry) void {
        commands.bind(.edit_external, self, editExternalCommand);
    }

    /// CommandRegistry adapter: commands.bind(.edit_external, self, ...).
    pub fn editExternalCommand(ctx: ?*anyopaque) void {
        const self: *EditSessionsController = @ptrCast(@alignCast(ctx.?));
        self.editSelection();
    }

    pub fn setTargetProvider(self: *EditSessionsController, provider: TargetProvider) void {
        self.target_provider = provider;
    }

    /// Open an already-local file directly in the editor — no download/watch/
    /// upload session (local files edit in place). Returns whether it opened.
    pub fn openLocalFile(self: *EditSessionsController, abs_path: []const u8) bool {
        if (!self.open_in_editor) return true; // headless test mode
        return workspaceOpen(abs_path);
    }

    pub fn setConflictHook(self: *EditSessionsController, hook: ?ConflictHook) void {
        self.conflict_hook = hook;
    }

    /// Start sessions for the active selection (via the TargetProvider).
    pub fn editSelection(self: *EditSessionsController) void {
        const provider = self.target_provider orelse return;
        var targets: std.ArrayList(EditTarget) = .empty;
        defer targets.deinit(self.gpa);
        provider.collectFn(provider.ctx, self.gpa, &targets) catch return;
        _ = self.editTargets(targets.items);
    }

    /// Start one session per target; returns how many started.
    pub fn editTargets(self: *EditSessionsController, targets: []const EditTarget) usize {
        var started: usize = 0;
        for (targets) |target| {
            _ = self.editTarget(target) catch continue;
            started += 1;
        }
        return started;
    }

    /// Start one edit session: temp dir + download enqueue. Returns the
    /// session id. The session surfaces in the Transfers panel through its
    /// ordinary queue items.
    pub fn editTarget(self: *EditSessionsController, target: EditTarget) StartError!u64 {
        if (self.shut_down) return error.ShutDown;
        if (!path_mod.isSafeChildName(target.name)) return error.UnsafeName;
        const gpa = self.gpa;
        const core = self.core;

        const remote_dir = path_mod.normalize(gpa, target.dir) catch |err| return mapPathErr(err);
        errdefer gpa.free(remote_dir);
        const remote_path = path_mod.join(gpa, remote_dir, target.name) catch |err| return mapPathErr(err);
        errdefer gpa.free(remote_path);
        const name = try gpa.dupe(u8, target.name);
        errdefer gpa.free(name);

        const id = self.next_session_id;
        const local_dir = try sessionDir(gpa, self.cache_base, id);
        errdefer gpa.free(local_dir);
        const local_path = path_mod.join(gpa, local_dir, target.name) catch |err| return mapPathErr(err);
        errdefer gpa.free(local_path);

        // Per-session temp dir via std.Io.Dir, in the same coordinate
        // space the queue's local VFS writes to.
        core.local_root.createDirPath(core.io, relFromVfs(local_dir)) catch
            return error.CacheUnavailable;
        errdefer core.local_root.deleteTree(core.io, relFromVfs(local_dir)) catch {};

        const session = try gpa.create(EditSession);
        errdefer gpa.destroy(session);
        session.* = .{
            .id = id,
            .controller = self,
            .site_id = target.site_id,
            .remote_dir = remote_dir,
            .remote_path = remote_path,
            .name = name,
            .local_dir = local_dir,
            .local_path = local_path,
            .state = .downloading,
            .recorded_mtime = target.mtime,
        };
        try self.sessions.put(gpa, id, session);
        errdefer _ = self.sessions.remove(id);

        const item = core.enqueueTransfer(.{
            .direction = .download,
            .src = .{ .site_id = target.site_id, .path = remote_path },
            .dst = .{ .site_id = item_mod.local_site_id, .path = local_path },
            .bytes_total = target.size orelse 0,
        }) catch return error.QueueUnavailable;
        session.download_item = item;
        self.next_session_id += 1;
        return id;
    }

    // ------------------------------------------------------------------ //
    // Session table

    pub fn sessionCount(self: *const EditSessionsController) usize {
        return self.sessions.count();
    }

    pub fn sessionState(self: *const EditSessionsController, session_id: u64) ?SessionState {
        const session = self.sessions.get(session_id) orelse return null;
        return session.state;
    }

    pub fn sessionLocalPath(self: *const EditSessionsController, session_id: u64) ?[]const u8 {
        const session = self.sessions.get(session_id) orelse return null;
        return session.local_path;
    }

    /// End one session: stop its watcher, cancel in-flight items, delete
    /// the temp dir, drop the table entry (window close of a session).
    pub fn endSession(self: *EditSessionsController, session_id: u64) void {
        const session = self.sessions.get(session_id) orelse return;
        self.endSessionInternal(session);
    }

    fn endSessionInternal(self: *EditSessionsController, session: *EditSession) void {
        if (session.watcher) |watcher| {
            watcher.deinit();
            session.watcher = null;
        }
        if (session.download_item) |id| _ = self.core.cancelTransfer(id);
        if (session.upload_item) |id| _ = self.core.cancelTransfer(id);
        self.core.local_root.deleteTree(self.core.io, relFromVfs(session.local_dir)) catch {};
        _ = self.sessions.remove(session.id);
        self.destroySession(session);
        self.maybeEndActivity();
    }

    fn destroySession(self: *EditSessionsController, session: *EditSession) void {
        const gpa = self.gpa;
        gpa.free(session.remote_dir);
        gpa.free(session.remote_path);
        gpa.free(session.name);
        gpa.free(session.local_dir);
        gpa.free(session.local_path);
        gpa.destroy(session);
    }

    // ------------------------------------------------------------------ //
    // Save flow

    /// A save landed in the session's temp dir (FSEvents callback, or a
    /// test/manual trigger). Kicks the re-stat → conflict-check → upload
    /// pipeline, or marks the session dirty when one is already running.
    pub fn noteLocalChange(self: *EditSessionsController, session_id: u64) void {
        if (self.shut_down) return;
        const session = self.sessions.get(session_id) orelse return;
        switch (session.state) {
            .watching => self.startConflictCheck(session),
            .checking, .conflict, .uploading, .refreshing => session.dirty = true,
            .downloading => {},
        }
    }

    /// Answer a pending conflict (the sheet's completion, a ConflictHook,
    /// or a test).
    pub fn resolveConflict(self: *EditSessionsController, session_id: u64, choice: ConflictChoice) void {
        if (self.shut_down) return;
        const session = self.sessions.get(session_id) orelse return;
        if (session.state != .conflict) return;
        switch (choice) {
            .overwrite => self.enqueueUpload(session, session.remote_path, true),
            .duplicate => {
                const gpa = self.gpa;
                const dup = duplicateName(gpa, session.name) catch return self.backToWatching(session);
                defer gpa.free(dup);
                const dup_path = path_mod.join(gpa, session.remote_dir, dup) catch
                    return self.backToWatching(session);
                defer gpa.free(dup_path);
                self.enqueueUpload(session, dup_path, false);
            },
            .cancel => self.backToWatching(session),
        }
    }

    fn startConflictCheck(self: *EditSessionsController, session: *EditSession) void {
        session.dirty = false;
        session.state = .checking;
        session.stat_request = self.core.listPath(
            edit_pane_token,
            session.site_id,
            session.remote_dir,
        ) catch {
            // Could not even start the re-stat: unknown remote state —
            // never silently overwrite; let the user decide.
            self.presentConflict(session);
            return;
        };
    }

    fn startRefresh(self: *EditSessionsController, session: *EditSession) void {
        session.state = .refreshing;
        session.stat_request = self.core.listPath(
            edit_pane_token,
            session.site_id,
            session.remote_dir,
        ) catch {
            session.recorded_mtime = null; // unknown baseline: next save uploads unprompted
            self.backToWatching(session);
            return;
        };
    }

    fn backToWatching(self: *EditSessionsController, session: *EditSession) void {
        session.state = .watching;
        if (session.dirty) self.startConflictCheck(session);
    }

    fn enqueueUpload(self: *EditSessionsController, session: *EditSession, dst_path: []const u8, to_original: bool) void {
        const core = self.core;
        var bytes_total: u64 = 0;
        if (core.local_root.statFile(core.io, relFromVfs(session.local_path), .{})) |st| {
            bytes_total = st.size;
        } else |_| {}
        const item = core.enqueueTransfer(.{
            .direction = .upload,
            .src = .{ .site_id = item_mod.local_site_id, .path = session.local_path },
            .dst = .{ .site_id = session.site_id, .path = dst_path },
            .bytes_total = bytes_total,
        }) catch {
            self.presentError("Couldn't upload edited file", session.name);
            self.backToWatching(session);
            return;
        };
        session.upload_item = item;
        session.upload_to_original = to_original;
        session.state = .uploading;
        self.uploads_enqueued += 1;
    }

    // ------------------------------------------------------------------ //
    // Bridge listeners (main thread, run-to-completion)

    fn onTransferState(self: *EditSessionsController, e: events_mod.CoreEvent.TransferStateChange) void {
        if (self.shut_down) return;
        var it = self.sessions.valueIterator();
        while (it.next()) |entry| {
            const session = entry.*;
            if (session.download_item) |id| {
                if (id == e.item_id) {
                    self.onDownloadState(session, e);
                    return;
                }
            }
            if (session.upload_item) |id| {
                if (id == e.item_id) {
                    self.onUploadState(session, e);
                    return;
                }
            }
        }
    }

    fn onDownloadState(self: *EditSessionsController, session: *EditSession, e: events_mod.CoreEvent.TransferStateChange) void {
        switch (e.state) {
            .completed => {
                session.download_item = null;
                self.beginWatch(session);
            },
            .failed, .canceled => {
                if (e.state == .failed) {
                    self.presentError("Couldn't download file for editing", session.name);
                }
                self.endSessionInternal(session); // also clears download_item
            },
            else => {},
        }
    }

    fn onUploadState(self: *EditSessionsController, session: *EditSession, e: events_mod.CoreEvent.TransferStateChange) void {
        switch (e.state) {
            .completed => {
                session.upload_item = null;
                if (session.upload_to_original) {
                    self.startRefresh(session); // adopt the new remote mtime
                } else {
                    self.backToWatching(session); // duplicate: original untouched
                }
            },
            .failed, .canceled => {
                session.upload_item = null;
                if (e.state == .failed) {
                    self.presentError("Couldn't upload edited file", session.name);
                }
                self.backToWatching(session); // local edits persist; next save retries
            },
            else => {},
        }
    }

    fn onListingDone(self: *EditSessionsController, d: bridge.ListingDone) void {
        if (self.shut_down) return;
        const session = self.sessionForStat(d.request_id) orelse return;
        session.stat_request = null;
        var current: ?i64 = null;
        if (d.failure == null) {
            if (d.snapshot) |snap| current = entryMtime(snap.entries, session.name);
        }
        switch (session.state) {
            .checking => switch (decideOnSave(session.recorded_mtime, current)) {
                .upload => self.enqueueUpload(session, session.remote_path, true),
                .conflict => self.presentConflict(session),
            },
            .refreshing => {
                session.recorded_mtime = current;
                self.backToWatching(session);
            },
            else => {},
        }
    }

    fn sessionForStat(self: *EditSessionsController, request_id: bridge.RequestId) ?*EditSession {
        var it = self.sessions.valueIterator();
        while (it.next()) |entry| {
            const session = entry.*;
            if (session.stat_request) |req| {
                if (req == request_id) return session;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ //
    // Watch + open + App Nap

    fn beginWatch(self: *EditSessionsController, session: *EditSession) void {
        session.state = .watching;
        if (self.headless) return;
        if (self.open_in_editor and !workspaceOpen(session.local_path)) {
            self.presentError("Couldn't open file in an editor", session.local_path);
        }
        session.watcher = fsevents.watch(
            self.gpa,
            &.{session.local_dir},
            watch_latency_s,
            session,
            EditSession.onFsEvent,
        ) catch null;
        if (session.watcher != null) self.ensureActivity();
        // Watcher failure degrades to manual noteLocalChange triggers; the
        // session (and its queue items) still works.
    }

    fn ensureActivity(self: *EditSessionsController) void {
        if (self.activity != null) return;
        self.activity = app_nap.Activity.begin(
            .user_initiated,
            "Relay is watching files being edited externally",
        );
    }

    fn maybeEndActivity(self: *EditSessionsController) void {
        if (self.activity == null) return;
        var it = self.sessions.valueIterator();
        while (it.next()) |entry| {
            if (entry.*.watcher != null) return; // still someone watching
        }
        self.activity.?.end();
        self.activity = null;
    }

    // ------------------------------------------------------------------ //
    // Conflict + error presentation

    const ConflictPromptCtx = struct {
        controller: *EditSessionsController,
        session_id: u64,
    };

    fn presentConflict(self: *EditSessionsController, session: *EditSession) void {
        self.conflicts_seen += 1;
        session.state = .conflict;
        if (self.conflict_hook) |hook| {
            hook.f(hook.ctx, self, session.id, session.name);
            return;
        }
        if (self.headless) {
            // A conflict nobody can see must never overwrite fresher
            // remote data (the askPrompt precedent: unseen prompts refuse).
            self.resolveConflict(session.id, .cancel);
            return;
        }
        const parent = self.win orelse {
            self.resolveConflict(session.id, .cancel);
            return;
        };
        const ctx = self.gpa.create(ConflictPromptCtx) catch {
            self.resolveConflict(session.id, .cancel);
            return;
        };
        ctx.* = .{ .controller = self, .session_id = session.id };
        var buf: [512]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, "\u{201C}{s}\u{201D} changed on the server", .{session.name}) catch
            "The file changed on the server";
        panels.beginAlertSheet(parent, .{
            .style = .warning,
            .message = message,
            .informative = "The remote file was modified after it was downloaded for " ++
                "editing. Uploading will overwrite those changes.",
            .buttons = &.{ "Overwrite", "Save as Copy", "Cancel Upload" },
            .destructive_button = 0,
        }, ctx, onConflictSheet);
    }

    fn onConflictSheet(ctx: *ConflictPromptCtx, result: panels.AlertResult) void {
        const self = ctx.controller;
        const session_id = ctx.session_id;
        self.gpa.destroy(ctx);
        self.resolveConflict(session_id, switch (result.button) {
            0 => .overwrite,
            1 => .duplicate,
            else => .cancel,
        });
    }

    fn presentError(self: *EditSessionsController, title: []const u8, detail: []const u8) void {
        if (self.headless) return;
        panels.presentErrorSheet(self.win, title, detail);
    }

    fn mapPathErr(err: path_mod.Error) StartError {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidPath => error.InvalidPath,
        };
    }
};

// ---------------------------------------------------------------------------
// NSWorkspace open.
//
// TODO(m3-dedupe): belongs in relay_mac (an appkit/workspace.zig) so its
// selector strings live in the wrapper layer — same convention note as
// prefs.zig's controls section. Nothing else in this file sends raw
// selectors.
// ---------------------------------------------------------------------------

/// Open `path` in the default app for its type ("open" semantics), falling
/// back to the stock text editor ("open -t"). Returns false when both fail.
fn workspaceOpen(path: []const u8) bool {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const workspace = foundation.class("NSWorkspace").msgSend(objc.Object, "sharedWorkspace", .{});
    if (foundation.toBool(workspace.msgSend(foundation.BOOL, "openURL:", .{foundation.fileURL(path)})))
        return true;
    return foundation.toBool(workspace.msgSend(foundation.BOOL, "openFile:withApplication:", .{
        foundation.nsString(path), foundation.nsString("TextEdit"),
    }));
}

// ---------------------------------------------------------------------------
// Tests — all headless: manual pump, tmp dirs, fake cred store, local↔local
// "remote" (site 0) so the full download→save→re-stat→upload pipeline runs
// through the real queue engine without a server.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "decideOnSave: conflict exactly when both mtimes known and different" {
    try testing.expectEqual(SaveDecision.upload, decideOnSave(null, null));
    try testing.expectEqual(SaveDecision.upload, decideOnSave(null, 5));
    try testing.expectEqual(SaveDecision.upload, decideOnSave(5, null));
    try testing.expectEqual(SaveDecision.upload, decideOnSave(5, 5));
    try testing.expectEqual(SaveDecision.conflict, decideOnSave(5, 6));
    try testing.expectEqual(SaveDecision.conflict, decideOnSave(6, 5));
    try testing.expectEqual(SaveDecision.conflict, decideOnSave(0, 1));
}

test "entryMtime finds the named entry's mtime; absent or unknown is null" {
    const entries = [_]vfs_mod.Entry{
        .{ .name = "a.txt", .mtime = 100 },
        .{ .name = "b.txt", .mtime = null },
        .{ .name = "c.txt", .mtime = 300 },
    };
    try testing.expectEqual(@as(?i64, 100), entryMtime(&entries, "a.txt"));
    try testing.expectEqual(@as(?i64, null), entryMtime(&entries, "b.txt"));
    try testing.expectEqual(@as(?i64, 300), entryMtime(&entries, "c.txt"));
    try testing.expectEqual(@as(?i64, null), entryMtime(&entries, "missing.txt"));
    try testing.expectEqual(@as(?i64, null), entryMtime(&.{}, "a.txt"));
}

test "temp path construction: session dirs, file paths, default base shape" {
    const gpa = testing.allocator;

    const dir = try sessionDir(gpa, "/edit-cache", 7);
    defer gpa.free(dir);
    try testing.expectEqualStrings("/edit-cache/7", dir);

    const file = try path_mod.join(gpa, dir, "notes.txt");
    defer gpa.free(file);
    try testing.expectEqualStrings("/edit-cache/7/notes.txt", file);

    try testing.expectEqualStrings("edit-cache/7", relFromVfs(dir));
    try testing.expectEqualStrings(".", relFromVfs("/"));

    if (defaultCacheBase(gpa)) |base| {
        defer gpa.free(base);
        try testing.expect(std.mem.endsWith(u8, base, "/Library/Caches/us.doriantull.relay/edit"));
        try testing.expect(base[0] == '/');
    } else |err| try testing.expectEqual(error.NoHomeDirectory, err);
}

test "duplicateName: ' copy' before the extension" {
    const gpa = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "notes.txt", "notes copy.txt" },
        .{ "Makefile", "Makefile copy" },
        .{ ".profile", ".profile copy" },
        .{ "archive.tar.gz", "archive.tar copy.gz" },
    };
    for (cases) |case| {
        const dup = try duplicateName(gpa, case[0]);
        defer gpa.free(dup);
        try testing.expectEqualStrings(case[1], dup);
    }
}

// --- live-pipeline harness (mirrors bridge.zig's TestHarness) ---------------

const FakeStore = relay.cred.fake.FakeStore;

const TestHarness = struct {
    tmp_conf: std.testing.TmpDir,
    tmp_root: std.testing.TmpDir,
    fake: FakeStore,
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

    fn readSmall(h: *TestHarness, sub_path: []const u8, buf: []u8) ![]const u8 {
        var file = try h.tmp_root.dir.openFile(h.core.io, sub_path, .{});
        defer file.close(h.core.io);
        var rbuf: [256]u8 = undefined;
        var reader = file.reader(h.core.io, &rbuf);
        const n = try reader.interface.readSliceShort(buf);
        return buf[0..n];
    }
};

const StateWaiter = struct {
    ctrl: *EditSessionsController,
    id: u64,
    want: SessionState,

    fn reached(self: *StateWaiter) bool {
        return self.ctrl.sessionState(self.id) == self.want;
    }
};

const HookRecorder = struct {
    calls: u64 = 0,
    last_session: u64 = 0,
    name_ok: bool = false,
    /// Answer applied synchronously from inside the hook; null = leave the
    /// session parked in .conflict.
    answer: ?ConflictChoice = null,

    fn onConflict(ctx: *anyopaque, ctrl: *EditSessionsController, session_id: u64, name: []const u8) void {
        const self: *HookRecorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.last_session = session_id;
        self.name_ok = std.mem.eql(u8, name, "notes.txt");
        if (self.answer) |choice| ctrl.resolveConflict(session_id, choice);
    }
};

test "session lifecycle: download → watch → save → re-stat → upload → refresh" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.createDir(io, "src", .default_dir);
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "src/notes.txt", .data = "v1" });

    const ctrl = try EditSessionsController.create(testing.allocator, h.core, .{
        .cache_base = "/edit-cache",
        .headless = true,
    });
    defer ctrl.destroy(); // runs before h.stop (LIFO): core still alive ✓

    // Start: session table gains one entry in .downloading.
    const id = try ctrl.editTarget(.{
        .site_id = item_mod.local_site_id, // local↔local stand-in remote
        .dir = "/src",
        .name = "notes.txt",
        .size = 2,
        .mtime = null, // unknown baseline: first save uploads unprompted
    });
    try testing.expectEqual(@as(usize, 1), ctrl.sessionCount());
    try testing.expectEqual(SessionState.downloading, ctrl.sessionState(id).?);
    try testing.expectEqualStrings("/edit-cache/1/notes.txt", ctrl.sessionLocalPath(id).?);

    // Unsafe names never start sessions.
    try testing.expectError(error.UnsafeName, ctrl.editTarget(.{
        .site_id = item_mod.local_site_id,
        .dir = "/src",
        .name = "../escape",
    }));

    // Download completes into the per-session temp dir; state → watching.
    var watching: StateWaiter = .{ .ctrl = ctrl, .id = id, .want = .watching };
    try h.waitUntil(&watching, StateWaiter.reached);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("v1", try h.readSmall("edit-cache/1/notes.txt", &buf));

    // Save: edit the temp file, trigger the save flow (headless stand-in
    // for the FSEvents callback). Unknown baseline → upload unprompted;
    // post-upload refresh adopts the real remote mtime.
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "edit-cache/1/notes.txt", .data = "v2-local" });
    ctrl.noteLocalChange(id);
    try testing.expectEqual(SessionState.checking, ctrl.sessionState(id).?);
    try h.waitUntil(&watching, StateWaiter.reached);
    try testing.expectEqualStrings("v2-local", try h.readSmall("src/notes.txt", &buf));
    try testing.expectEqual(@as(u64, 1), ctrl.uploads_enqueued);
    try testing.expectEqual(@as(u64, 0), ctrl.conflicts_seen);
    const session = ctrl.sessions.get(id).?;
    try testing.expect(session.recorded_mtime != null); // refreshed baseline

    // Conflict: simulate a foreign remote change by skewing the baseline.
    var hook: HookRecorder = .{ .answer = .cancel };
    ctrl.setConflictHook(.{ .ctx = &hook, .f = HookRecorder.onConflict });
    session.recorded_mtime = session.recorded_mtime.? - 100;
    ctrl.noteLocalChange(id);
    try h.waitUntil(&watching, StateWaiter.reached); // cancel → back to watching
    try testing.expectEqual(@as(u64, 1), hook.calls);
    try testing.expectEqual(id, hook.last_session);
    try testing.expect(hook.name_ok);
    try testing.expectEqual(@as(u64, 1), ctrl.conflicts_seen);
    try testing.expectEqual(@as(u64, 1), ctrl.uploads_enqueued); // cancel uploaded nothing

    // Conflict → Overwrite: upload runs, refresh re-adopts the baseline.
    hook.answer = .overwrite;
    session.recorded_mtime = session.recorded_mtime.? - 100;
    ctrl.noteLocalChange(id);
    try h.waitUntil(&watching, StateWaiter.reached);
    try testing.expectEqual(@as(u64, 2), ctrl.uploads_enqueued);
    try testing.expectEqual(@as(u64, 2), ctrl.conflicts_seen);

    // Conflict → Save as Copy: the duplicate lands beside the original,
    // which keeps its content and baseline.
    hook.answer = .duplicate;
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "edit-cache/1/notes.txt", .data = "v3-copy" });
    session.recorded_mtime = session.recorded_mtime.? - 100;
    ctrl.noteLocalChange(id);
    try h.waitUntil(&watching, StateWaiter.reached);
    try testing.expectEqual(@as(u64, 3), ctrl.uploads_enqueued);
    try testing.expectEqualStrings("v3-copy", try h.readSmall("src/notes copy.txt", &buf));
    try testing.expectEqualStrings("v2-local", try h.readSmall("src/notes.txt", &buf));

    // End: watcher-less headless session cleans its temp dir + table slot.
    ctrl.endSession(id);
    try testing.expectEqual(@as(usize, 0), ctrl.sessionCount());
    try testing.expectEqual(@as(?SessionState, null), ctrl.sessionState(id));
    try testing.expectError(
        error.FileNotFound,
        h.tmp_root.dir.statFile(io, "edit-cache/1/notes.txt", .{}),
    );
    ctrl.endSession(id); // unknown id: no-op

    // deinit is idempotent and editTarget refuses after shutdown.
    ctrl.deinit();
    ctrl.deinit();
    try testing.expectError(error.ShutDown, ctrl.editTarget(.{
        .site_id = item_mod.local_site_id,
        .dir = "/src",
        .name = "notes.txt",
    }));
}

test "deinit ends every live session: temp dirs deleted, queue items canceled" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.createDir(io, "src", .default_dir);
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "src/a.txt", .data = "a" });
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "src/b.txt", .data = "b" });

    const ctrl = try EditSessionsController.create(testing.allocator, h.core, .{
        .cache_base = "/edit-cache",
        .headless = true,
    });
    defer ctrl.destroy();

    const targets = [_]EditTarget{
        .{ .site_id = item_mod.local_site_id, .dir = "/src", .name = "a.txt" },
        .{ .site_id = item_mod.local_site_id, .dir = "/src", .name = "b.txt" },
        .{ .site_id = item_mod.local_site_id, .dir = "/src", .name = "../nope" }, // skipped
    };
    try testing.expectEqual(@as(usize, 2), ctrl.editTargets(&targets));
    try testing.expectEqual(@as(usize, 2), ctrl.sessionCount());

    ctrl.deinit(); // sessions may still be .downloading: items get canceled
    try testing.expectEqual(@as(usize, 0), ctrl.sessionCount());
    try testing.expectError(error.FileNotFound, h.tmp_root.dir.statFile(io, "edit-cache/1", .{}));
    try testing.expectError(error.FileNotFound, h.tmp_root.dir.statFile(io, "edit-cache/2", .{}));
}

test "command surface: register binds Cmd+E and routes through the provider" {
    var h: TestHarness = undefined;
    try h.start();
    defer h.stop();
    const io = h.core.io;

    try h.tmp_root.dir.createDir(io, "src", .default_dir);
    try h.tmp_root.dir.writeFile(io, .{ .sub_path = "src/sel.txt", .data = "s" });

    const ctrl = try EditSessionsController.create(testing.allocator, h.core, .{
        .cache_base = "/edit-cache",
        .headless = true,
    });
    defer ctrl.destroy();

    const Provider = struct {
        calls: u64 = 0,

        fn collect(ctx: *anyopaque, gpa: Allocator, out: *std.ArrayList(EditTarget)) error{OutOfMemory}!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            try out.append(gpa, .{
                .site_id = item_mod.local_site_id,
                .dir = "/src",
                .name = "sel.txt",
            });
        }
    };
    var provider: Provider = .{};
    ctrl.setTargetProvider(.{ .ctx = &provider, .collectFn = Provider.collect });

    const commands = try prefs_mod.CommandRegistry.create(testing.allocator);
    defer commands.destroy();
    ctrl.register(commands);

    try testing.expect(commands.dispatch(.edit_external));
    try testing.expectEqual(@as(u64, 1), provider.calls);
    try testing.expectEqual(@as(usize, 1), ctrl.sessionCount());

    // The Cmd+E leaf exists exactly once in the menu tree.
    try testing.expectEqual(@as(usize, 1), prefs_mod.countShortcut("e", .{}));

    ctrl.deinit();
}

test {
    testing.refAllDecls(@This());
}

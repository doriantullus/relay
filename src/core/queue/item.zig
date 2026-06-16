//! item — one transfer queue entry: identity, endpoints, the state machine,
//! and the progress counters workers update without taking the engine lock.
//!
//! Field ownership is split three ways (the engine never holds its lock
//! across I/O, so this split is what makes the queue race-free):
//! - engine-lock-guarded: `state`, `attempts`, `pending`, `removed`,
//!   `not_before_ns`, `failure`, the endpoint paths;
//! - lock-free atomics: `bytes_total`/`bytes_done`/`rate_bps` (workers
//!   store, the snapshot timer loads) and `token`;
//! - timer-thread-private: `timer_last_bytes`/`timer_emitted_bytes`.

const std = @import("std");
const diag_mod = @import("../diag.zig");
const events = @import("../events.zig");
const cancel_mod = @import("../cancel.zig");

pub const ItemId = u64;

/// Endpoint site id reserved for the local filesystem side; nonzero values
/// are site ids from settings/sites.zig.
pub const local_site_id: u64 = 0;

pub const Direction = enum { upload, download };

pub const Kind = enum { file, folder };

/// What to do when the destination already exists. `ask` parks the item in
/// `paused` until the UI picks a policy and resumes it.
pub const ConflictPolicy = enum { overwrite, resume_existing, rename, skip, ask };

pub const Endpoint = struct {
    site_id: u64 = local_site_id,
    path: []const u8,
};

pub const State = enum {
    queued,
    /// Folder item walking its source directory, streaming children in.
    resolving,
    connecting,
    transferring,
    verifying,
    done,
    failed,
    canceled,
    paused,
    /// Destination exists and the policy is `.ask`; parked until the UI
    /// resolves it (resolveConflict re-queues with a real policy, or skips).
    conflict,

    pub fn isTerminal(s: State) bool {
        return switch (s) {
            .done, .failed, .canceled => true,
            else => false,
        };
    }

    /// A worker thread currently owns the item.
    pub fn isActive(s: State) bool {
        return switch (s) {
            .resolving, .connecting, .transferring, .verifying => true,
            else => false,
        };
    }

    /// Projection onto the coarser UI event vocabulary (events.zig has no
    /// resolving/verifying; they render as their nearest neighbor).
    pub fn toEventState(s: State) events.TransferState {
        return switch (s) {
            .queued => .queued,
            .resolving, .connecting => .connecting,
            .transferring, .verifying => .transferring,
            .done => .completed,
            .failed => .failed,
            .canceled => .canceled,
            .paused => .paused,
            .conflict => .conflict,
        };
    }
};

/// The retry matrix in edge form. Active states may unwind to `queued`
/// (transient retry / auth requeue), which is what makes backoff a
/// re-enqueue rather than a worker that sleeps holding a connection.
pub fn legalTransition(from: State, to: State) bool {
    if (from == to) return false;
    return switch (from) {
        .queued => switch (to) {
            .resolving, .connecting, .paused, .canceled, .failed => true,
            else => false,
        },
        .resolving, .connecting, .transferring, .verifying => switch (to) {
            .queued, .done, .failed, .canceled, .paused, .conflict => true,
            .transferring => from == .connecting,
            .verifying => from == .transferring,
            else => false,
        },
        .paused => switch (to) {
            .queued, .canceled => true,
            else => false,
        },
        // conflict parks like paused: the UI re-queues it (overwrite) or skips it.
        .conflict => switch (to) {
            .queued, .canceled => true,
            else => false,
        },
        .failed => to == .queued,
        .done, .canceled => false,
    };
}

/// What the owner asked of a running worker. The worker unwinds via the
/// item's CancelToken either way; this disambiguates pause from cancel when
/// it applies the outcome.
pub const Pending = enum(u8) { none, pause, cancel };

/// Terminal failure detail kept for snapshots after the Diagnostics that
/// produced it has gone out of scope (fixed buffer, no allocation).
pub const StoredFailure = struct {
    class: diag_mod.ErrorClass = .permanent,
    protocol_code: u32 = 0,
    len: usize = 0,
    buf: [256]u8 = undefined,

    pub fn set(self: *StoredFailure, class: diag_mod.ErrorClass, code: u32, msg: []const u8) void {
        self.class = class;
        self.protocol_code = code;
        self.len = @min(msg.len, self.buf.len);
        @memcpy(self.buf[0..self.len], msg[0..self.len]);
    }

    pub fn message(self: *const StoredFailure) []const u8 {
        return self.buf[0..self.len];
    }
};

/// EWMA smoothing for the published transfer rate, α = 1/8. A zero previous
/// value means "no estimate yet" and adopts the instantaneous rate.
pub fn ewma(prev: u64, inst: u64) u64 {
    if (prev == 0) return inst;
    return (prev * 7 + inst) / 8;
}

pub const CreateOptions = struct {
    id: ItemId,
    direction: Direction,
    kind: Kind = .file,
    src: Endpoint,
    dst: Endpoint,
    conflict: ConflictPolicy = .overwrite,
    parent: ItemId = 0,
    bytes_total: u64 = 0,
    state: State = .queued,
    attempts: u32 = 0,
};

/// Heap-pinned (workers and the timer hold pointers across unlocks; the
/// atomics must never move). Create via `create`, free via `destroy`.
pub const TransferItem = struct {
    id: ItemId,
    direction: Direction,
    kind: Kind,
    /// Paths are gpa-owned by the item.
    src: Endpoint,
    dst: Endpoint,
    conflict: ConflictPolicy,
    /// Folder item that spawned this one; 0 = top-level.
    parent: ItemId,

    // Engine-lock-guarded.
    state: State,
    attempts: u32,
    /// Earliest retry time, ns on the engine's awake clock; 0 = now.
    not_before_ns: i96 = 0,
    pending: Pending = .none,
    removed: bool = false,
    /// Set when the item was paused mid-transfer with partial bytes on the
    /// destination: the next run may resume from offset even on attempt 0.
    resume_hint: bool = false,
    failure: ?StoredFailure = null,

    /// Worker-side cooperative cancellation; reset before each run.
    token: cancel_mod.CancelToken = .{},

    bytes_total: std.atomic.Value(u64),
    bytes_done: std.atomic.Value(u64) = .init(0),
    rate_bps: std.atomic.Value(u64) = .init(0),

    // Progress-timer-thread private.
    timer_last_bytes: u64 = 0,
    timer_emitted_bytes: u64 = 0,

    pub fn create(gpa: std.mem.Allocator, opts: CreateOptions) error{OutOfMemory}!*TransferItem {
        const src_path = try gpa.dupe(u8, opts.src.path);
        errdefer gpa.free(src_path);
        const dst_path = try gpa.dupe(u8, opts.dst.path);
        errdefer gpa.free(dst_path);
        const self = try gpa.create(TransferItem);
        self.* = .{
            .id = opts.id,
            .direction = opts.direction,
            .kind = opts.kind,
            .src = .{ .site_id = opts.src.site_id, .path = src_path },
            .dst = .{ .site_id = opts.dst.site_id, .path = dst_path },
            .conflict = opts.conflict,
            .parent = opts.parent,
            .state = opts.state,
            .attempts = opts.attempts,
            .bytes_total = .init(opts.bytes_total),
        };
        return self;
    }

    pub fn destroy(self: *TransferItem, gpa: std.mem.Allocator) void {
        gpa.free(self.src.path);
        gpa.free(self.dst.path);
        gpa.destroy(self);
    }

    /// The site whose connection budget this item consumes: the remote end.
    /// (For local↔local copies both ends are `local_site_id`.)
    pub fn siteId(self: *const TransferItem) u64 {
        return switch (self.direction) {
            .upload => self.dst.site_id,
            .download => self.src.site_id,
        };
    }
};

test "state machine: legal edges only" {
    // Spot-check the load-bearing edges of the retry matrix.
    try std.testing.expect(legalTransition(.queued, .connecting));
    try std.testing.expect(legalTransition(.queued, .resolving));
    try std.testing.expect(legalTransition(.connecting, .transferring));
    try std.testing.expect(legalTransition(.transferring, .verifying));
    try std.testing.expect(legalTransition(.transferring, .done));
    try std.testing.expect(legalTransition(.transferring, .queued)); // transient retry
    try std.testing.expect(legalTransition(.connecting, .queued)); // auth requeue
    try std.testing.expect(legalTransition(.connecting, .done)); // conflict skip
    try std.testing.expect(legalTransition(.failed, .queued)); // requeueFailed
    try std.testing.expect(legalTransition(.paused, .queued));
    try std.testing.expect(legalTransition(.paused, .canceled));

    try std.testing.expect(!legalTransition(.queued, .transferring)); // must connect first
    try std.testing.expect(!legalTransition(.connecting, .verifying));
    try std.testing.expect(!legalTransition(.resolving, .transferring));
    try std.testing.expect(!legalTransition(.done, .queued));
    try std.testing.expect(!legalTransition(.canceled, .queued));
    try std.testing.expect(!legalTransition(.failed, .done));
    try std.testing.expect(!legalTransition(.queued, .queued));

    // Terminal states have no outgoing edges at all.
    for (std.enums.values(State)) |to| {
        try std.testing.expect(!legalTransition(.done, to));
        try std.testing.expect(!legalTransition(.canceled, to));
    }
}

test "state classification and event mapping" {
    try std.testing.expect(State.done.isTerminal());
    try std.testing.expect(State.failed.isTerminal());
    try std.testing.expect(State.canceled.isTerminal());
    try std.testing.expect(!State.paused.isTerminal());
    try std.testing.expect(State.resolving.isActive());
    try std.testing.expect(!State.queued.isActive());
    try std.testing.expect(!State.failed.isActive());

    try std.testing.expectEqual(events.TransferState.connecting, State.resolving.toEventState());
    try std.testing.expectEqual(events.TransferState.transferring, State.verifying.toEventState());
    try std.testing.expectEqual(events.TransferState.completed, State.done.toEventState());
}

test "create dupes paths and destroy frees them" {
    var path_buf: [16]u8 = undefined;
    @memcpy(path_buf[0..8], "/src/a.b");
    const it = try TransferItem.create(std.testing.allocator, .{
        .id = 7,
        .direction = .download,
        .src = .{ .site_id = 3, .path = path_buf[0..8] },
        .dst = .{ .path = "/dl/a.b" },
        .bytes_total = 42,
    });
    defer it.destroy(std.testing.allocator);

    @memset(path_buf[0..8], 'x'); // item must have copied
    try std.testing.expectEqualStrings("/src/a.b", it.src.path);
    try std.testing.expectEqualStrings("/dl/a.b", it.dst.path);
    try std.testing.expectEqual(@as(u64, 3), it.siteId()); // download → src site
    try std.testing.expectEqual(@as(u64, 42), it.bytes_total.load(.monotonic));
    try std.testing.expectEqual(State.queued, it.state);
}

test "siteId follows direction" {
    const up = try TransferItem.create(std.testing.allocator, .{
        .id = 1,
        .direction = .upload,
        .src = .{ .path = "/local/f" },
        .dst = .{ .site_id = 9, .path = "/remote/f" },
    });
    defer up.destroy(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 9), up.siteId());
}

test "stored failure truncates long messages" {
    var f: StoredFailure = .{};
    const long = "x" ** 1000;
    f.set(.transient, 421, long);
    try std.testing.expectEqual(@as(usize, 256), f.message().len);
    try std.testing.expectEqual(diag_mod.ErrorClass.transient, f.class);
    f.set(.auth, 530, "530 Login incorrect");
    try std.testing.expectEqualStrings("530 Login incorrect", f.message());
}

test "ewma adopts first sample then smooths" {
    try std.testing.expectEqual(@as(u64, 1000), ewma(0, 1000));
    try std.testing.expectEqual(@as(u64, 1000), ewma(1000, 1000));
    // Single zero sample decays, does not zero out.
    try std.testing.expectEqual(@as(u64, 875), ewma(1000, 0));
}

test {
    std.testing.refAllDecls(@This());
}

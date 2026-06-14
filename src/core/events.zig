//! events — the core→UI contract. Worker threads post `CoreEvent`s into an
//! `EventQueue`; the UI bridge drains them on the main thread (at most one
//! drain scheduled per runloop turn, coalescing). Payload slices are copied
//! into a per-drain arena at post time, so producers never transfer
//! ownership and the UI frees a whole batch as one arena reset.

const std = @import("std");
const diag_mod = @import("diag.zig");
const transcript_mod = @import("log/transcript.zig");

/// Classified failure attached to terminal events. `message` follows the
/// Diagnostics convention (verbatim server context); it is arena-owned by
/// the queue batch carrying the event.
pub const Failure = struct {
    class: diag_mod.ErrorClass,
    /// FTP reply code, SFTP status, or 0 (see diag.zig).
    protocol_code: u32 = 0,
    message: []const u8 = "",
};

pub const TransferState = enum(u8) {
    queued,
    connecting,
    transferring,
    paused,
    completed,
    failed,
    canceled,
};

pub const SiteStatus = enum(u8) { connected, reconnecting, offline };

/// One keyboard-interactive sub-prompt (SSH userauth "keyboard-interactive").
pub const KiPrompt = struct {
    text: []const u8,
    /// False means the answer must be masked (it is a password-like secret).
    echo: bool,
};

pub const Prompt = union(enum) {
    host_key: HostKey,
    password: Password,
    keyboard_interactive: KeyboardInteractive,

    pub const HostKey = struct {
        /// OpenSSH-style "SHA256:..." fingerprint.
        fingerprint: []const u8,
        host: []const u8,
    };
    pub const Password = struct {
        user: []const u8,
        host: []const u8,
    };
    pub const KeyboardInteractive = struct {
        instruction: []const u8 = "",
        prompts: []const KiPrompt,
    };
};

pub const CoreEvent = union(enum) {
    listing_batch: ListingBatch,
    listing_done: ListingDone,
    transfer_progress: TransferProgress,
    transfer_state: TransferStateChange,
    site_status: SiteStatusChange,
    prompt_needed: PromptNeeded,
    transcript_line: TranscriptLine,

    pub const ListingBatch = struct {
        request_id: u64,
        /// Entries parsed so far (progress count). The actual snapshot is
        /// delivered out-of-band via the bridge's pending-listing table.
        entry_count: u32,
    };

    pub const ListingDone = struct {
        request_id: u64,
        /// null on success. The finished snapshot is delivered out-of-band
        /// via the bridge's pending-listing table, not this event.
        failure: ?Failure = null,
    };

    pub const TransferProgress = struct {
        item_id: u64,
        bytes_done: u64,
        /// Smoothed bytes/second.
        rate: u64,
    };

    pub const TransferStateChange = struct {
        item_id: u64,
        state: TransferState,
        /// Set when `state == .failed` (and for .canceled where useful).
        failure: ?Failure = null,
    };

    pub const SiteStatusChange = struct {
        site_id: u64,
        status: SiteStatus,
        /// Why (e.g. the disconnect cause while .reconnecting/.offline).
        reason: []const u8 = "",
        /// Set ONLY when this status reflects a real failure (connect refused,
        /// auth, breaker trip, dropped link). `null` = clean/expected (a user
        /// disconnect still posts .offline, but with no error_class). This is
        /// the unambiguous error signal: `reason` alone is unreliable because
        /// a clean disconnect can also carry a non-empty reason string.
        error_class: ?diag_mod.ErrorClass = null,
    };

    pub const PromptNeeded = struct {
        site_id: u64,
        /// Echoed back by the UI's answer command to route the reply.
        prompt_id: u64,
        prompt: Prompt,
    };

    pub const TranscriptLine = struct {
        connection_id: u64,
        seq: u64,
        dir: transcript_mod.Direction,
        verbose: bool,
        text: []const u8,
    };
};

/// One-word spin mutex; see sync.zig for the 0.16 lock-choice rationale.
const lockSpin = @import("sync.zig").lockSpin;

/// MPSC double-buffered event queue. Producers append to the active buffer
/// under the lock; `drain` (main thread only) swaps buffers and returns the
/// filled one, so producers never block on UI work. The "drain scheduled"
/// flag coalesces wakeups: of all posts between two drains, exactly one is
/// told to schedule (worst case is one extra empty drain, never a lost
/// event).
///
/// Pin the queue (heap or long-lived stack frame) before the first `post`;
/// moving it while threads hold references is UB like any mutex.
pub const EventQueue = struct {
    gpa: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    /// True while a drain is scheduled but not yet started.
    drain_scheduled: std.atomic.Value(bool) = .init(false),
    /// Index of the buffer producers append to. Written only by `drain`.
    active: u1 = 0,
    buffers: [2]Buffer,

    const Buffer = struct {
        events: std.ArrayList(CoreEvent),
        /// Owns every slice payload of the events in `events`.
        arena: std.heap.ArenaAllocator,
    };

    pub fn init(gpa: std.mem.Allocator) EventQueue {
        return .{
            .gpa = gpa,
            .buffers = .{
                .{ .events = .empty, .arena = .init(gpa) },
                .{ .events = .empty, .arena = .init(gpa) },
            },
        };
    }

    /// Illegal while producer threads or a pending drain may still touch the
    /// queue.
    pub fn deinit(self: *EventQueue) void {
        for (&self.buffers) |*buffer| {
            buffer.events.deinit(self.gpa);
            buffer.arena.deinit();
        }
        self.* = undefined;
    }

    /// Thread-safe. Appends `event`, deep-copying slice payloads into the
    /// active buffer's arena (producers keep ownership of what they passed).
    /// Returns true exactly when the caller must schedule a drain on the
    /// main thread; false means one is already pending.
    pub fn post(self: *EventQueue, event: CoreEvent) error{OutOfMemory}!bool {
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            const buffer = &self.buffers[self.active];
            const owned = try dupeEvent(buffer.arena.allocator(), event);
            try buffer.events.append(self.gpa, owned);
        }
        return self.drain_scheduled.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null;
    }

    /// Main thread only (single drainer). Returns the events posted since
    /// the last drain, in post order (per-producer order is preserved). The
    /// returned slice and every slice payload in it are owned by the queue
    /// and valid only until the NEXT `drain` call.
    pub fn drain(self: *EventQueue) []const CoreEvent {
        // The inactive buffer holds the previous batch; the UI is done with
        // it by the time it drains again (drains are serialized on the main
        // thread, events applied run-to-completion), so reclaim it before
        // swapping it back in. Reading `active` without the lock is fine:
        // this is its only writer.
        const incoming = self.active ^ 1;
        const buffer = &self.buffers[incoming];
        buffer.events.clearRetainingCapacity();
        // .free_all, not .retain_capacity: retain may call the child
        // allocator and swallow its failure (ArenaAllocator.reset returns
        // false) — a hidden allocation on a must-not-fail path and a trap
        // for failure-injection tests. The high-rate event
        // (transfer_progress) carries no payload, so the arena only sees
        // low-rate traffic; the event list capacity is retained above.
        _ = buffer.arena.reset(.free_all);

        // Clear before the swap: a post that lands after the swap missed
        // this batch, but its flag transition (or another producer's) then
        // schedules the drain that picks it up — no lost wakeups.
        self.drain_scheduled.store(false, .seq_cst);

        lockSpin(&self.mutex);
        self.active = incoming;
        self.mutex.unlock();

        return self.buffers[incoming ^ 1].events.items;
    }
};

/// Copies every slice payload of `event` into `arena`. Events whose payload
/// is plain values pass through. NOTE: when adding a slice-bearing field to
/// an event, extend this switch — a shallow copy here would hand the UI a
/// dangling producer-owned pointer.
fn dupeEvent(arena: std.mem.Allocator, event: CoreEvent) error{OutOfMemory}!CoreEvent {
    return switch (event) {
        .listing_batch, .transfer_progress => event,
        .listing_done => |e| .{ .listing_done = .{
            .request_id = e.request_id,
            .failure = try dupeFailure(arena, e.failure),
        } },
        .transfer_state => |e| .{ .transfer_state = .{
            .item_id = e.item_id,
            .state = e.state,
            .failure = try dupeFailure(arena, e.failure),
        } },
        .site_status => |e| .{ .site_status = .{
            .site_id = e.site_id,
            .status = e.status,
            .reason = try arena.dupe(u8, e.reason),
            .error_class = e.error_class,
        } },
        .prompt_needed => |e| .{ .prompt_needed = .{
            .site_id = e.site_id,
            .prompt_id = e.prompt_id,
            .prompt = switch (e.prompt) {
                .host_key => |p| .{ .host_key = .{
                    .fingerprint = try arena.dupe(u8, p.fingerprint),
                    .host = try arena.dupe(u8, p.host),
                } },
                .password => |p| .{ .password = .{
                    .user = try arena.dupe(u8, p.user),
                    .host = try arena.dupe(u8, p.host),
                } },
                .keyboard_interactive => |p| blk: {
                    const prompts = try arena.alloc(KiPrompt, p.prompts.len);
                    for (prompts, p.prompts) |*dst, src| dst.* = .{
                        .text = try arena.dupe(u8, src.text),
                        .echo = src.echo,
                    };
                    break :blk .{ .keyboard_interactive = .{
                        .instruction = try arena.dupe(u8, p.instruction),
                        .prompts = prompts,
                    } };
                },
            },
        } },
        .transcript_line => |e| .{ .transcript_line = .{
            .connection_id = e.connection_id,
            .seq = e.seq,
            .dir = e.dir,
            .verbose = e.verbose,
            .text = try arena.dupe(u8, e.text),
        } },
    };
}

fn dupeFailure(arena: std.mem.Allocator, failure: ?Failure) error{OutOfMemory}!?Failure {
    const f = failure orelse return null;
    return .{
        .class = f.class,
        .protocol_code = f.protocol_code,
        .message = try arena.dupe(u8, f.message),
    };
}

test "event queue: payload copy, post order, drain-scheduled coalescing" {
    var queue: EventQueue = .init(std.testing.allocator);
    defer queue.deinit();

    var reason_buf: [16]u8 = undefined;
    @memcpy(reason_buf[0..7], "timeout");
    try std.testing.expect(try queue.post(.{ .site_status = .{
        .site_id = 1,
        .status = .reconnecting,
        .reason = reason_buf[0..7],
        .error_class = .transient,
    } }));
    // A drain is already scheduled: second post must not schedule another.
    try std.testing.expect(!try queue.post(.{ .transfer_progress = .{
        .item_id = 9,
        .bytes_done = 1024,
        .rate = 512,
    } }));
    // Producer reuses its buffer; the queue must have copied.
    @memset(reason_buf[0..7], 'x');

    const batch = queue.drain();
    try std.testing.expectEqual(@as(usize, 2), batch.len);
    try std.testing.expectEqual(@as(u64, 1), batch[0].site_status.site_id);
    try std.testing.expectEqualStrings("timeout", batch[0].site_status.reason);
    try std.testing.expectEqual(diag_mod.ErrorClass.transient, batch[0].site_status.error_class.?);
    try std.testing.expectEqual(@as(u64, 1024), batch[1].transfer_progress.bytes_done);

    // Flag re-arms after a drain; empty drains are fine.
    try std.testing.expect(try queue.post(.{ .transfer_state = .{
        .item_id = 9,
        .state = .failed,
        .failure = .{ .class = .transient, .protocol_code = 421, .message = "421 busy" },
    } }));
    const batch2 = queue.drain();
    try std.testing.expectEqual(@as(usize, 1), batch2.len);
    try std.testing.expectEqual(diag_mod.ErrorClass.transient, batch2[0].transfer_state.failure.?.class);
    try std.testing.expectEqualStrings("421 busy", batch2[0].transfer_state.failure.?.message);
    try std.testing.expectEqual(@as(usize, 0), queue.drain().len);
}

test "event queue: site_status error_class distinguishes clean disconnect from failure" {
    var queue: EventQueue = .init(std.testing.allocator);
    defer queue.deinit();

    // Clean user disconnect: offline, a non-empty reason is allowed, but
    // error_class stays null — NOT an error to surface.
    _ = try queue.post(.{ .site_status = .{
        .site_id = 7,
        .status = .offline,
        .reason = "disconnected",
    } });
    // Real failure: offline with a classified cause and a reason.
    var reason_buf: [32]u8 = undefined;
    const reason = std.fmt.bufPrint(&reason_buf, "421 connection refused", .{}) catch unreachable;
    _ = try queue.post(.{ .site_status = .{
        .site_id = 7,
        .status = .offline,
        .reason = reason,
        .error_class = .transient,
    } });
    // Producer reuses its buffer; the failure reason must have been copied.
    @memset(&reason_buf, 'x');

    const batch = queue.drain();
    try std.testing.expectEqual(@as(usize, 2), batch.len);

    // Clean disconnect: error_class round-trips as null through dupeEvent.
    try std.testing.expectEqual(@as(?diag_mod.ErrorClass, null), batch[0].site_status.error_class);
    try std.testing.expectEqualStrings("disconnected", batch[0].site_status.reason);

    // Failure: error_class and reason both round-trip.
    try std.testing.expectEqual(diag_mod.ErrorClass.transient, batch[1].site_status.error_class.?);
    try std.testing.expectEqualStrings("421 connection refused", batch[1].site_status.reason);
}

test "event queue: prompt payloads are deep-copied" {
    var queue: EventQueue = .init(std.testing.allocator);
    defer queue.deinit();

    var prompt_text: [9]u8 = undefined;
    @memcpy(&prompt_text, "Password:");
    const prompts = [_]KiPrompt{.{ .text = &prompt_text, .echo = false }};
    _ = try queue.post(.{ .prompt_needed = .{
        .site_id = 3,
        .prompt_id = 77,
        .prompt = .{ .keyboard_interactive = .{
            .instruction = "Two-factor login",
            .prompts = &prompts,
        } },
    } });
    @memset(&prompt_text, '?');

    const batch = queue.drain();
    const ki = batch[0].prompt_needed.prompt.keyboard_interactive;
    try std.testing.expectEqualStrings("Two-factor login", ki.instruction);
    try std.testing.expectEqual(@as(usize, 1), ki.prompts.len);
    try std.testing.expectEqualStrings("Password:", ki.prompts[0].text);
    try std.testing.expect(!ki.prompts[0].echo);
}

test "event queue: concurrent producers, single drainer, no lost or duplicated events" {
    const producer_count = 4;
    const events_per_producer = 2000;

    var queue: EventQueue = .init(std.testing.allocator);
    defer queue.deinit();

    const Producer = struct {
        fn run(q: *EventQueue, id: u64, count: u64) void {
            var text_buf: [32]u8 = undefined;
            var seq: u64 = 0;
            while (seq < count) : (seq += 1) {
                // Alternate a no-payload and a payload-carrying event so the
                // arena copy path is exercised under contention; the stack
                // buffer is reused immediately, so a missed copy shows up as
                // corrupted text on the drain side.
                if (seq % 2 == 0) {
                    _ = q.post(.{ .transfer_progress = .{
                        .item_id = id,
                        .bytes_done = seq,
                        .rate = 0,
                    } }) catch unreachable;
                } else {
                    const text = std.fmt.bufPrint(&text_buf, "p{d}-s{d}", .{ id, seq }) catch unreachable;
                    _ = q.post(.{ .transcript_line = .{
                        .connection_id = id,
                        .seq = seq,
                        .dir = .info,
                        .verbose = false,
                        .text = text,
                    } }) catch unreachable;
                    @memset(&text_buf, 0xaa);
                }
            }
        }
    };

    var threads: [producer_count]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{
            &queue, @as(u64, i), @as(u64, events_per_producer),
        });
    }
    defer for (&threads) |*thread| thread.join();

    var next_seq = [_]u64{0} ** producer_count;
    var total: usize = 0;
    var expected_buf: [32]u8 = undefined;
    while (total < producer_count * events_per_producer) {
        const batch = queue.drain();
        if (batch.len == 0) {
            std.Thread.yield() catch {};
            continue;
        }
        for (batch) |event| {
            switch (event) {
                .transfer_progress => |p| {
                    const id: usize = @intCast(p.item_id);
                    try std.testing.expectEqual(next_seq[id], p.bytes_done);
                    next_seq[id] += 1;
                },
                .transcript_line => |line| {
                    const id: usize = @intCast(line.connection_id);
                    try std.testing.expectEqual(next_seq[id], line.seq);
                    const expected = try std.fmt.bufPrint(&expected_buf, "p{d}-s{d}", .{ line.connection_id, line.seq });
                    try std.testing.expectEqualStrings(expected, line.text);
                    next_seq[id] += 1;
                },
                else => return error.TestUnexpectedResult,
            }
            total += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 0), queue.drain().len);
    for (next_seq) |seq| try std.testing.expectEqual(@as(u64, events_per_producer), seq);
}

fn postDrainCycle(gpa: std.mem.Allocator) !void {
    var queue: EventQueue = .init(gpa);
    defer queue.deinit();

    _ = try queue.post(.{ .site_status = .{ .site_id = 1, .status = .offline, .reason = "550 gone" } });
    const prompts = [_]KiPrompt{
        .{ .text = "Password:", .echo = false },
        .{ .text = "Token:", .echo = true },
    };
    _ = try queue.post(.{ .prompt_needed = .{
        .site_id = 1,
        .prompt_id = 2,
        .prompt = .{ .keyboard_interactive = .{ .instruction = "2FA", .prompts = &prompts } },
    } });
    const batch = queue.drain();
    if (batch.len != 2) return error.TestUnexpectedResult;
    _ = try queue.post(.{ .transfer_progress = .{ .item_id = 1, .bytes_done = 2, .rate = 3 } });
    if (queue.drain().len != 1) return error.TestUnexpectedResult;
}

test "event queue: allocation failures neither leak nor corrupt" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, postDrainCycle, .{});
}

test {
    std.testing.refAllDecls(@This());
}

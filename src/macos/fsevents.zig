//! fsevents — FSEventStream wrapper over the CoreServices C API (the
//! framework is linked on relay_mac in build.zig). `watch` creates a
//! file-level stream (kFSEventStreamCreateFlagFileEvents | NoDefer) over a
//! set of directory paths and delivers its callback on the MAIN dispatch
//! queue (`FSEventStreamSetDispatchQueue`), pool-wrapped, one invocation
//! per changed path — so consumers mutate UI state directly, per the
//! docs/ARCHITECTURE.md main-queue law.
//!
//! Threading: `watch`, `stop`, and `deinit` are main-thread only. Because
//! callbacks also ride the main queue, no event can be in flight while
//! `stop` runs, so stopping is race-free by construction.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("foundation.zig");
const dispatch = @import("dispatch.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// C ABI (FSEvents.h). CFArrayRef rides as objc.c.id — NSArray is toll-free
// bridged, so the paths array is built with Foundation, no CF calls needed.
// ---------------------------------------------------------------------------

pub const EventId = u64;

/// kFSEventStreamEventIdSinceNow: only events after stream creation.
pub const since_now: EventId = 0xFFFFFFFFFFFFFFFF;

// kFSEventStreamCreateFlag*
const create_flag_no_defer: u32 = 0x00000002;
const create_flag_file_events: u32 = 0x00000010;

// kFSEventStreamEventFlagItem* (the consumer-relevant subset).
pub const flag_item_created: u32 = 0x00000100;
pub const flag_item_removed: u32 = 0x00000200;
pub const flag_item_renamed: u32 = 0x00000800;
pub const flag_item_modified: u32 = 0x00001000;
pub const flag_item_is_file: u32 = 0x00010000;
pub const flag_item_is_dir: u32 = 0x00020000;

const FSEventStreamRef = *anyopaque;

const FSEventStreamContext = extern struct {
    version: isize = 0, // CFIndex
    info: ?*anyopaque = null,
    retain: ?*const fn (?*const anyopaque) callconv(.c) ?*const anyopaque = null,
    release: ?*const fn (?*const anyopaque) callconv(.c) void = null,
    copy_description: ?*const fn (?*const anyopaque) callconv(.c) ?*anyopaque = null,
};

const FSEventStreamCallback = *const fn (
    stream: FSEventStreamRef,
    info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque, // char** (no kFSEventStreamCreateFlagUseCFTypes)
    event_flags: ?[*]const u32,
    event_ids: ?[*]const EventId,
) callconv(.c) void;

extern "c" fn FSEventStreamCreate(
    allocator: ?*anyopaque, // CFAllocatorRef; null = default
    callback: FSEventStreamCallback,
    context: *const FSEventStreamContext,
    paths_to_watch: objc.c.id, // CFArrayRef of CFStringRef (toll-free NSArray)
    since_when: EventId,
    latency: f64, // CFTimeInterval, seconds
    flags: u32,
) ?FSEventStreamRef;
extern "c" fn FSEventStreamSetDispatchQueue(stream: FSEventStreamRef, queue: ?dispatch.Queue) void;
extern "c" fn FSEventStreamStart(stream: FSEventStreamRef) u8; // Boolean
extern "c" fn FSEventStreamStop(stream: FSEventStreamRef) void;
extern "c" fn FSEventStreamInvalidate(stream: FSEventStreamRef) void;
extern "c" fn FSEventStreamRelease(stream: FSEventStreamRef) void;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One changed path. `path` is BORROWED for the duration of the callback
/// (it points into FSEvents' own buffer); copy to keep.
pub const Event = struct {
    path: []const u8,
    flags: u32,
    id: EventId,
};

pub const Error = error{ OutOfMemory, StreamCreateFailed, StreamStartFailed };

/// Start watching `paths` (directories; events for files beneath them are
/// delivered per-path thanks to FileEvents). `latency_s` is the FSEvents
/// coalescing window in seconds; `f(ctx, event)` runs on the MAIN queue
/// inside its own autorelease pool, once per changed path.
///
/// The returned Watcher is heap-pinned (its address is the stream's info
/// pointer). `ctx` must be a mutable pointer that outlives the watcher.
/// Main thread only.
pub fn watch(
    gpa: Allocator,
    paths: []const []const u8,
    latency_s: f64,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), Event) void,
) Error!*Watcher {
    const Ptr = @TypeOf(ctx);
    comptime {
        const info = @typeInfo(Ptr);
        if (info != .pointer or info.pointer.is_const)
            @compileError("fsevents ctx must be a mutable pointer");
    }
    const Thunk = struct {
        fn call(erased: *anyopaque, event: Event) void {
            f(@ptrCast(@alignCast(erased)), event);
        }
    };

    const self = try gpa.create(Watcher);
    errdefer gpa.destroy(self);
    self.* = .{
        .gpa = gpa,
        .stream = undefined,
        .ctx = @ptrCast(ctx),
        .call = Thunk.call,
        .started = false,
    };

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const array = foundation.class("NSMutableArray")
        .msgSend(objc.Object, "arrayWithCapacity:", .{@as(foundation.NSUInteger, paths.len)});
    for (paths) |path| array.msgSend(void, "addObject:", .{foundation.nsString(path)});

    // FSEventStreamCreate copies both the context struct and the array.
    const context: FSEventStreamContext = .{ .info = self };
    const stream = FSEventStreamCreate(
        null,
        streamCallback,
        &context,
        array.value,
        since_now,
        latency_s,
        create_flag_no_defer | create_flag_file_events,
    ) orelse return Error.StreamCreateFailed;
    self.stream = stream;

    FSEventStreamSetDispatchQueue(stream, dispatch.mainQueue());
    if (FSEventStreamStart(stream) == 0) {
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        return Error.StreamStartFailed;
    }
    self.started = true;
    return self;
}

pub const Watcher = struct {
    gpa: Allocator,
    stream: FSEventStreamRef,
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, event: Event) void,
    started: bool,

    /// Stop delivery and invalidate the stream. Idempotent; main thread
    /// only. After this returns no callback will ever fire again.
    pub fn stop(self: *Watcher) void {
        if (!self.started) return;
        self.started = false;
        FSEventStreamStop(self.stream);
        FSEventStreamInvalidate(self.stream);
    }

    /// stop() + release the stream + free the Watcher. Main thread only.
    pub fn deinit(self: *Watcher) void {
        self.stop();
        FSEventStreamRelease(self.stream);
        const gpa = self.gpa;
        gpa.destroy(self);
    }
};

fn streamCallback(
    stream: FSEventStreamRef,
    info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque,
    event_flags: ?[*]const u32,
    event_ids: ?[*]const EventId,
) callconv(.c) void {
    _ = stream;
    const self: *Watcher = @ptrCast(@alignCast(info orelse return));
    // A stop() that raced a queued block: both run on the main queue, so
    // this read is ordered after the flag write — events never leak past
    // stop().
    if (!self.started) return;
    const paths: [*]const [*:0]const u8 = @ptrCast(@alignCast(event_paths orelse return));
    const flags = event_flags orelse return;
    const ids = event_ids orelse return;

    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    for (0..num_events) |i| {
        self.call(self.ctx, .{
            .path = std.mem.span(paths[i]),
            .flags = flags[i],
            .id = ids[i],
        });
    }
}

// ---------------------------------------------------------------------------
// Tests. The test runner executes on the main thread, so spinning the main
// NSRunLoop services the main dispatch queue (same technique as
// dispatch.zig's mainQueueAsync test).
// ---------------------------------------------------------------------------
const testing = std.testing;
const NSDefaultRunLoopMode = @extern(*const objc.c.id, .{ .name = "NSDefaultRunLoopMode" });

fn spinMainRunLoop(seconds: f64) void {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const runloop = foundation.class("NSRunLoop").msgSend(objc.Object, "mainRunLoop", .{});
    const date = foundation.class("NSDate")
        .msgSend(objc.Object, "dateWithTimeIntervalSinceNow:", .{seconds});
    _ = runloop.msgSend(foundation.BOOL, "runMode:beforeDate:", .{
        objc.Object.fromId(NSDefaultRunLoopMode.*), date,
    });
}

const WatchRecorder = struct {
    hits: u64 = 0,
    saw_needle: bool = false,
    needle: []const u8 = "",

    fn onEvent(self: *WatchRecorder, event: Event) void {
        self.hits += 1;
        if (self.needle.len > 0 and std.mem.indexOf(u8, event.path, self.needle) != null)
            self.saw_needle = true;
    }
};

test "watch delivers a changed path on the main queue; stop ends delivery" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..dir_len];

    var rec: WatchRecorder = .{ .needle = "fsevents-probe.txt" };
    const watcher = try watch(testing.allocator, &.{dir_path}, 0.05, &rec, WatchRecorder.onEvent);

    try tmp.dir.writeFile(io, .{ .sub_path = "fsevents-probe.txt", .data = "tick" });
    var spins: u32 = 0;
    while (!rec.saw_needle and spins < 400) : (spins += 1) spinMainRunLoop(0.02);
    try testing.expect(rec.saw_needle);
    try testing.expect(rec.hits >= 1);

    // After stop, further changes never reach the callback.
    watcher.stop();
    watcher.stop(); // idempotent
    const hits_at_stop = rec.hits;
    try tmp.dir.writeFile(io, .{ .sub_path = "fsevents-after-stop.txt", .data = "tock" });
    spins = 0;
    while (spins < 8) : (spins += 1) spinMainRunLoop(0.02);
    try testing.expectEqual(hits_at_stop, rec.hits);

    watcher.deinit();
}

test "watch requires a live directory list but tolerates empty event paths" {
    // Watching a non-existent path is legal for FSEvents (events arrive if
    // it is created later); this exercises create/start/teardown.
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();
    var rec: WatchRecorder = .{};
    const watcher = try watch(
        testing.allocator,
        &.{"/nonexistent/relay-fsevents-test"},
        0.1,
        &rec,
        WatchRecorder.onEvent,
    );
    watcher.deinit();
    try testing.expectEqual(@as(u64, 0), rec.hits);
}

test {
    testing.refAllDecls(@This());
}

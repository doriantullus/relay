//! runtime — the class-definition kit: docs/spikes/ui.md conventions as API.
//!
//! Every runtime-defined ObjC class in Relay gets an id-sized `relayState`
//! ivar holding a raw Zig pointer. The Ivar handle is looked up ONCE after
//! registerClassPair and cached in the returned `DefinedClass`, so callbacks
//! recover state with a single object_getIvar (no string lookup, supports
//! multiple instances). Runtime-allocated classes have no ARC ivar layout:
//! object_setIvar is a plain pointer store, never a retain/release.
//!
//! Define classes BEFORE the first setDelegate:/setDataSource: call — AppKit
//! probes respondsToSelector: at set time (e.g. to decide a table is
//! view-based).

const std = @import("std");
const objc = @import("objc");
const foundation = @import("foundation.zig");

pub const c = objc.c;

pub const Error = error{
    SuperclassNotFound,
    /// allocateClassPair failed — almost always a duplicate class name.
    ClassAlreadyDefined,
    AddIvarFailed,
    AddMethodFailed,
    IvarNotFound,
};

/// The id-sized state slot every kit-defined class carries.
pub const state_ivar_name: [:0]const u8 = "relayState";

/// Define and register an ObjC class.
///
/// `methods` is a comptime tuple of `.{ "selector:", imp }` pairs where each
/// imp is a plain `callconv(.c)` fn taking `(c.id, c.SEL, ...)`; the ObjC
/// type encoding is derived from the fn type. Overriding superclass methods
/// (drawRect:, isFlipped, ...) works with the same mechanism.
///
/// `extra_ivars` adds further id-sized slots (e.g. a smuggled row index;
/// see `idFromUsize`). Handles for those are fetched via `DefinedClass.ivar`.
pub fn defineClass(
    comptime name: [:0]const u8,
    comptime superclass: [:0]const u8,
    comptime extra_ivars: []const [:0]const u8,
    comptime methods: anytype,
) Error!DefinedClass {
    const super = objc.getClass(superclass) orelse return Error.SuperclassNotFound;
    const cls = objc.allocateClassPair(super, name) orelse return Error.ClassAlreadyDefined;
    if (!cls.addIvar(state_ivar_name)) return Error.AddIvarFailed;
    inline for (extra_ivars) |ivar_name| {
        if (!cls.addIvar(ivar_name)) return Error.AddIvarFailed;
    }
    inline for (methods) |m| {
        if (!cls.addMethod(m[0], m[1])) return Error.AddMethodFailed;
    }
    objc.registerClassPair(cls);
    const state_ivar = c.class_getInstanceVariable(cls.value, state_ivar_name) orelse
        return Error.IvarNotFound;
    return .{ .class = cls, .state_ivar = state_ivar };
}

pub const DefinedClass = struct {
    class: objc.Class,
    state_ivar: c.Ivar,

    /// Handle for an `extra_ivars` slot. Fetch once, cache in a global —
    /// exactly the spike convention.
    pub fn ivar(self: DefinedClass, name: [:0]const u8) Error!c.Ivar {
        return c.class_getInstanceVariable(self.class.value, name) orelse Error.IvarNotFound;
    }

    /// alloc/init an instance (retain count 1, caller-owned).
    pub fn new(self: DefinedClass) objc.Object {
        return self.class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "init", .{});
    }

    /// alloc/initWithFrame: for NSView subclasses.
    pub fn newWithFrame(self: DefinedClass, frame: foundation.NSRect) objc.Object {
        return self.class.msgSend(objc.Object, "alloc", .{})
            .msgSend(objc.Object, "initWithFrame:", .{frame});
    }

    /// alloc/init and attach the Zig state pointer in one step.
    pub fn newWithState(self: DefinedClass, state_ptr: *anyopaque) objc.Object {
        const obj = self.new();
        self.attach(obj.value, state_ptr);
        return obj;
    }

    /// Store the raw Zig state pointer in the instance's relayState ivar.
    pub fn attach(self: DefinedClass, obj: c.id, state_ptr: *anyopaque) void {
        c.object_setIvar(obj, self.state_ivar, @ptrCast(@alignCast(state_ptr)));
    }

    /// Recover the Zig state pointer in a callback. Panics if unattached
    /// (programmer error: instance created without newWithState/attach).
    pub fn state(self: DefinedClass, comptime T: type, target: c.id) *T {
        return stateFromIvar(T, target, self.state_ivar);
    }
};

/// Free-fn variant for callbacks that cache only the Ivar handle.
pub fn stateFromIvar(comptime T: type, target: c.id, ivar: c.Ivar) *T {
    const raw = c.object_getIvar(target, ivar) orelse
        @panic("relay_mac/runtime: state ivar is null (instance not attached)");
    return @ptrCast(@alignCast(raw));
}

// ---------------------------------------------------------------------------
// Integer-in-ivar encoding: a plain integer (row index, tag) smuggled through
// an id-sized ivar must look like a valid pointer in Debug builds —
// @ptrFromInt enforces non-null + alignment — so it rides as (value+1) << 3.
// ---------------------------------------------------------------------------
pub fn idFromUsize(value: usize) c.id {
    return @ptrFromInt((value + 1) << 3);
}

/// Null id (slot never written) decodes as null.
pub fn usizeFromId(id_val: c.id) ?usize {
    const raw = @intFromPtr(id_val);
    if (raw == 0) return null;
    return (raw >> 3) - 1;
}

pub fn setIvarUsize(target: c.id, ivar: c.Ivar, value: usize) void {
    c.object_setIvar(target, ivar, idFromUsize(value));
}

pub fn ivarUsize(target: c.id, ivar: c.Ivar) ?usize {
    return usizeFromId(c.object_getIvar(target, ivar));
}

// ---------------------------------------------------------------------------
// Tests (headless: class definition, dispatch, state recovery, encodings).
// Class names are process-global — each test uses a distinct name.
// ---------------------------------------------------------------------------
const testing = std.testing;

const TestState = struct {
    counter: u64 = 0,
    last_arg: i64 = 0,
};

fn testBump(target: c.id, _: c.SEL, arg: i64) callconv(.c) i64 {
    const st = stateFromIvar(TestState, target, g_test_state_ivar);
    st.counter += 1;
    st.last_arg = arg;
    return arg * 2;
}

var g_test_state_ivar: c.Ivar = null;

test "defineClass + method dispatch + state recovery" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const dc = try defineClass("RelayRuntimeTestA", "NSObject", &.{}, .{
        .{ "relayBump:", testBump },
    });
    g_test_state_ivar = dc.state_ivar;

    var st_a: TestState = .{};
    var st_b: TestState = .{};
    const obj_a = dc.newWithState(&st_a);
    const obj_b = dc.newWithState(&st_b);
    defer obj_a.msgSend(void, "release", .{});
    defer obj_b.msgSend(void, "release", .{});

    try testing.expectEqual(@as(i64, 14), obj_a.msgSend(i64, "relayBump:", .{@as(i64, 7)}));
    try testing.expectEqual(@as(i64, -6), obj_b.msgSend(i64, "relayBump:", .{@as(i64, -3)}));
    _ = obj_b.msgSend(i64, "relayBump:", .{@as(i64, 9)});

    // Per-instance state: two instances, two distinct Zig structs.
    try testing.expectEqual(@as(u64, 1), st_a.counter);
    try testing.expectEqual(@as(i64, 7), st_a.last_arg);
    try testing.expectEqual(@as(u64, 2), st_b.counter);
    try testing.expectEqual(@as(i64, 9), st_b.last_arg);

    // DefinedClass.state recovers the same pointer.
    try testing.expectEqual(&st_a, dc.state(TestState, obj_a.value));
}

test "duplicate class name surfaces as ClassAlreadyDefined" {
    _ = try defineClass("RelayRuntimeTestDup", "NSObject", &.{}, .{});
    try testing.expectError(
        Error.ClassAlreadyDefined,
        defineClass("RelayRuntimeTestDup", "NSObject", &.{}, .{}),
    );
}

test "missing superclass surfaces as SuperclassNotFound" {
    try testing.expectError(
        Error.SuperclassNotFound,
        defineClass("RelayRuntimeTestNoSuper", "RelayDoesNotExist", &.{}, .{}),
    );
}

test "integer-in-ivar encoding round-trips" {
    try testing.expectEqual(@as(?usize, 0), usizeFromId(idFromUsize(0)));
    try testing.expectEqual(@as(?usize, 1), usizeFromId(idFromUsize(1)));
    try testing.expectEqual(@as(?usize, 104_999), usizeFromId(idFromUsize(104_999)));
    try testing.expectEqual(@as(?usize, null), usizeFromId(null));
}

test "extra ivars: usize slot on an instance" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const dc = try defineClass("RelayRuntimeTestB", "NSObject", &.{"relayRowIndex"}, .{});
    const row_ivar = try dc.ivar("relayRowIndex");
    try testing.expectError(Error.IvarNotFound, dc.ivar("relayNope"));

    var st: TestState = .{};
    const obj = dc.newWithState(&st);
    defer obj.msgSend(void, "release", .{});

    // Unwritten slot reads as null.
    try testing.expectEqual(@as(?usize, null), ivarUsize(obj.value, row_ivar));
    setIvarUsize(obj.value, row_ivar, 42);
    try testing.expectEqual(@as(?usize, 42), ivarUsize(obj.value, row_ivar));
    setIvarUsize(obj.value, row_ivar, 0);
    try testing.expectEqual(@as(?usize, 0), ivarUsize(obj.value, row_ivar));
}

var g_note_count: u64 = 0;

fn testOnNote(_: c.id, _: c.SEL, _: c.id) callconv(.c) void {
    g_note_count += 1;
}

test "NSNotificationCenter observe + post round-trip" {
    const pool = foundation.AutoreleasePool.init();
    defer pool.deinit();

    const dc = try defineClass("RelayRuntimeTestObserver", "NSObject", &.{}, .{
        .{ "relayOnNote:", testOnNote },
    });
    var st: TestState = .{};
    const obj = dc.newWithState(&st);
    defer obj.msgSend(void, "release", .{});

    foundation.observeNotification("RelayRuntimeTestNote", obj, "relayOnNote:");
    foundation.postNotification("RelayRuntimeTestNote");
    foundation.postNotification("RelayRuntimeTestNote");
    foundation.removeObserver(obj);
    foundation.postNotification("RelayRuntimeTestNote");
    try testing.expectEqual(@as(u64, 2), g_note_count);
}

test {
    testing.refAllDecls(@This());
}

//! GLib implementation of relay_ui's main-loop service.

const std = @import("std");
const glib = @import("glib");
const ui = @import("relay_ui");

const MainLoop = ui.platform.MainLoop;
const allocator = std.heap.c_allocator;

const Call = struct {
    arg: *anyopaque,
    f: *const fn (*anyopaque) void,
};

pub const GlibMainLoop = struct {
    pub fn service(self: *GlibMainLoop) MainLoop {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    fn post(
        _: *anyopaque,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) void {
        const call = allocator.create(Call) catch @panic("relay_gtk: main-loop post OOM");
        call.* = .{ .arg = arg, .f = f };
        glib.MainContext.invokeFull(null, glib.PRIORITY_DEFAULT, runOnce, call, destroyCall);
    }

    fn startTimer(
        _: *anyopaque,
        interval_ms: u64,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) MainLoop.TimerError!MainLoop.Timer {
        if (interval_ms == 0 or interval_ms > std.math.maxInt(c_uint))
            return error.TimerCreateFailed;
        const call = allocator.create(Call) catch return error.TimerCreateFailed;
        call.* = .{ .arg = arg, .f = f };
        const id = glib.timeoutAddFull(
            glib.PRIORITY_DEFAULT,
            @intCast(interval_ms),
            runTimer,
            call,
            destroyCall,
        );
        if (id == 0) {
            allocator.destroy(call);
            return error.TimerCreateFailed;
        }
        return .{ .handle = @ptrFromInt(@as(usize, id)) };
    }

    fn cancelTimer(_: *anyopaque, timer: MainLoop.Timer) void {
        const id: c_uint = @intCast(@intFromPtr(timer.handle));
        _ = glib.Source.remove(id);
    }

    fn runOnce(data: ?*anyopaque) callconv(.c) c_int {
        const call: *Call = @ptrCast(@alignCast(data.?));
        call.f(call.arg);
        return @intFromBool(glib.SOURCE_REMOVE);
    }

    fn runTimer(data: ?*anyopaque) callconv(.c) c_int {
        const call: *Call = @ptrCast(@alignCast(data.?));
        call.f(call.arg);
        return @intFromBool(glib.SOURCE_CONTINUE);
    }

    fn destroyCall(data: ?*anyopaque) callconv(.c) void {
        const call: *Call = @ptrCast(@alignCast(data.?));
        allocator.destroy(call);
    }

    const vtable: MainLoop.VTable = .{
        .post = post,
        .startTimer = startTimer,
        .cancelTimer = cancelTimer,
    };
};

test {
    std.testing.refAllDecls(GlibMainLoop);
}

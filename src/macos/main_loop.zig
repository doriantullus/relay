//! libdispatch implementation of relay_ui's main-loop service.

const ui = @import("relay_ui");
const dispatch = @import("dispatch.zig");

const MainLoop = ui.platform.MainLoop;

pub const DispatchMainLoop = struct {
    pub fn service(self: *DispatchMainLoop) MainLoop {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    fn post(
        _: *anyopaque,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) void {
        dispatch.mainQueueAsyncErased(arg, f);
    }

    fn startTimer(
        _: *anyopaque,
        interval_ms: u64,
        arg: *anyopaque,
        f: *const fn (*anyopaque) void,
    ) MainLoop.TimerError!MainLoop.Timer {
        const timer = dispatch.RepeatingTimer.startOnMainErased(interval_ms, arg, f) catch
            return error.TimerCreateFailed;
        return .{ .handle = timer.source };
    }

    fn cancelTimer(_: *anyopaque, timer: MainLoop.Timer) void {
        (dispatch.RepeatingTimer{ .source = timer.handle }).cancel();
    }

    const vtable: MainLoop.VTable = .{
        .post = post,
        .startTimer = startTimer,
        .cancelTimer = cancelTimer,
    };
};

test {
    @import("std").testing.refAllDecls(DispatchMainLoop);
}

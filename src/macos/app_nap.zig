//! app_nap — NSProcessInfo activity assertions (the Transmit App Nap stall
//! fix): while Relay watches an edit session or runs a long transfer the
//! process must not be napped, or FSEvents/timer delivery stalls for
//! minutes. `Activity.begin` wraps `beginActivityWithOptions:reason:` and
//! retains the returned token so it survives the caller's autorelease pool;
//! `end` hands it back to `endActivity:` and releases it.
//!
//! Token holders: begin/end in pairs, exactly once each. The API is
//! thread-safe per NSProcessInfo, but Relay's holders (controllers) run on
//! the main thread.

const std = @import("std");
const objc = @import("objc");
const foundation = @import("foundation.zig");

const NSUInteger = foundation.NSUInteger;

// NSActivityOptions (NSProcessInfo.h, NS_OPTIONS(uint64_t)).
const idle_display_sleep_disabled: NSUInteger = 1 << 40;
const idle_system_sleep_disabled: NSUInteger = 1 << 20;
const sudden_termination_disabled: NSUInteger = 1 << 14;
const automatic_termination_disabled: NSUInteger = 1 << 15;
const user_initiated_mask: NSUInteger = 0x00FFFFFF | idle_system_sleep_disabled;
const background_mask: NSUInteger = 0x000000FF;
const latency_critical_mask: NSUInteger = 0xFF00000000;

/// The Relay-relevant subset of NSActivityOptions.
pub const Option = enum {
    /// User-initiated work (edit-session watches, explicit transfers):
    /// disables App Nap and idle system sleep.
    user_initiated,
    /// Same, but the machine may still idle-sleep (long background syncs).
    user_initiated_allowing_idle_system_sleep,
    /// Background maintenance (cache cleanup): nap-resistant only.
    background,
    /// Latency-critical bursts; not used by M3 but part of the vocabulary.
    latency_critical,

    pub fn mask(self: Option) NSUInteger {
        return switch (self) {
            .user_initiated => user_initiated_mask,
            .user_initiated_allowing_idle_system_sleep => user_initiated_mask & ~idle_system_sleep_disabled,
            .background => background_mask,
            .latency_critical => latency_critical_mask,
        };
    }
};

fn processInfo() objc.Object {
    return foundation.class("NSProcessInfo").msgSend(objc.Object, "processInfo", .{});
}

/// One live activity assertion. Value type: copy freely, but begin/end the
/// SAME token exactly once each.
pub const Activity = struct {
    /// Retained NSObject token from beginActivityWithOptions:reason:.
    token: objc.Object,

    /// Start an assertion. `reason` is the user-visible diagnostic string
    /// (`pmset -g assertions`, Activity Monitor).
    pub fn begin(option: Option, reason: []const u8) Activity {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        const token = processInfo().msgSend(objc.Object, "beginActivityWithOptions:reason:", .{
            option.mask(), foundation.nsString(reason),
        });
        // The token is autoreleased; retain it past this pool. endActivity:
        // releases the system side, our release balances this retain.
        _ = token.msgSend(objc.Object, "retain", .{});
        return .{ .token = token };
    }

    /// End the assertion and release the token. Call exactly once.
    pub fn end(self: Activity) void {
        const pool = foundation.AutoreleasePool.init();
        defer pool.deinit();
        processInfo().msgSend(void, "endActivity:", .{self.token});
        self.token.msgSend(void, "release", .{});
    }
};

// ---------------------------------------------------------------------------
// Tests (headless: real NSProcessInfo round-trips, no UI).
// ---------------------------------------------------------------------------
const testing = std.testing;

test "begin/end round-trips a live token for every option" {
    inline for (comptime std.enums.values(Option)) |option| {
        const activity = Activity.begin(option, "relay app_nap test");
        try testing.expect(activity.token.value != null);
        activity.end();
    }
}

test "option masks match NSProcessInfo.h" {
    try testing.expectEqual(@as(NSUInteger, 0x00FFFFFF | (1 << 20)), Option.user_initiated.mask());
    try testing.expectEqual(
        @as(NSUInteger, 0x00FFFFFF & ~@as(NSUInteger, 1 << 20) | 0),
        Option.user_initiated_allowing_idle_system_sleep.mask() & ~@as(NSUInteger, 1 << 20),
    );
    try testing.expect(Option.user_initiated_allowing_idle_system_sleep.mask() & (1 << 20) == 0);
    try testing.expectEqual(@as(NSUInteger, 0x000000FF), Option.background.mask());
    try testing.expectEqual(@as(NSUInteger, 0xFF00000000), Option.latency_critical.mask());
}

test "concurrent assertions stack independently" {
    const a = Activity.begin(.user_initiated, "relay test a");
    const b = Activity.begin(.background, "relay test b");
    try testing.expect(a.token.value != b.token.value);
    b.end();
    a.end();
}

test {
    testing.refAllDecls(@This());
}

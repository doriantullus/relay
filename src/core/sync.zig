//! Tiny synchronization helpers shared across relay_core (and the app, via
//! the `relay_core` re-export). Pure Zig, no ObjC — safe for Law 2.

const std = @import("std");

/// Lock choice: producers (pool workers, libssh2/LibreSSL poll loops) and
/// the AppKit main thread do not share an `Io`, which rules out
/// `std.Io.Mutex` (lock/unlock take `io` and park on its futex), and 0.16
/// has no io-free blocking mutex (`std.Thread.Mutex` is gone). That leaves
/// `std.atomic.Mutex` — a one-word try-lock — so we spin with
/// `spinLoopHint`. Critical sections at the call sites are a few word writes
/// plus an arena bump allocation, so contention windows are nanoseconds.
pub fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

test "lockSpin acquires an uncontended mutex" {
    var m: std.atomic.Mutex = .unlocked;
    lockSpin(&m);
    defer m.unlock();
    try std.testing.expect(!m.tryLock());
}

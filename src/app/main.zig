//! Relay — native macOS FTP/FTPS/SFTP client.
//!
//! Scaffold entry point. The NSApplication run loop lands here once the M0
//! UI spike (src/spikes/ui_spike.zig) validates the zig-objc AppKit approach.

const std = @import("std");
const core = @import("relay_core");

pub fn main() !void {
    std.debug.print("Relay {f} (scaffold — GUI arrives with M2)\n", .{core.version});
}

//! Relay — native macOS FTP/FTPS/SFTP client.
//!
//! Entry point: NSApplication bootstrap on the main thread; all protocol
//! work lives in relay_core behind the bridge (src/app/bridge.zig).
//! M2 wiring is assigned per the M2 workflow.

const std = @import("std");
const core = @import("relay_core");

pub const bridge = @import("bridge.zig");
pub const app_delegate = @import("app_delegate.zig");
pub const controllers = struct {
    pub const browser = @import("controllers/browser.zig");
    pub const sites = @import("controllers/sites.zig");
    pub const transfers = @import("controllers/transfers.zig");
    pub const transcript = @import("controllers/transcript.zig");
    pub const prefs = @import("controllers/prefs.zig");
    pub const inspector = @import("controllers/inspector.zig");
};

pub fn main() !void {
    std.debug.print("Relay {f} (scaffold — GUI arrives with M2)\n", .{core.version});
}

test {
    _ = bridge;
    _ = app_delegate;
    _ = controllers.browser;
    _ = controllers.sites;
    _ = controllers.transfers;
    _ = controllers.transcript;
    _ = controllers.prefs;
    _ = controllers.inspector;
}

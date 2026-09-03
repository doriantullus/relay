//! relay_gtk — GTK4 bindings and Linux implementations of relay_ui's
//! platform-service vtables. Direct GTK/GLib contact stays in this module.

const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) @compileError("relay_gtk is Linux-only");
}

pub const gtk = @import("gtk");
pub const gdk = @import("gdk");
pub const gio = @import("gio");
pub const glib = @import("glib");
pub const gobject = @import("gobject");

pub const paths = @import("paths.zig");
pub const main_loop = @import("main_loop.zig");
pub const secret_store = @import("secret_store.zig");
pub const services = @import("services.zig");
pub const application = @import("application.zig");

test {
    _ = paths;
    _ = main_loop;
    _ = secret_store;
    _ = services;
    _ = application;
}

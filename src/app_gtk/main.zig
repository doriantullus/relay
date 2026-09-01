//! Linux executable assembly. GTK contact is isolated in relay_gtk.

const std = @import("std");
const ui = @import("relay_ui");
const platform = @import("relay_gtk");

const gpa = std.heap.smp_allocator;
const app_id = "us.doriantull.relay";

pub fn main(init: std.process.Init.Minimal) !void {
    var paths = platform.paths.AppPaths.init(app_id);
    var main_loop: platform.main_loop.GlibMainLoop = .{};
    var secret_store: platform.secret_store.SecretStore = .{};
    const core = try ui.bridge.AppCore.initOptions(gpa, .{
        .paths = paths.service(),
        .main_loop = main_loop.service(),
        .cred_store = secret_store.credStore(),
    });
    errdefer core.shutdown();
    const factories = try ui.factories.Factories.create(gpa, core);
    defer {
        core.shutdown();
        factories.destroy();
    }
    core.setFactoryProvider(factories.provider());
    try platform.application.run(gpa, core, init);
}

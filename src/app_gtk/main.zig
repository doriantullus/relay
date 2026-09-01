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

    // SiteStore owns every string published to AppCore after Quick Connect.
    // Keep it alive until after core.shutdown(), because live pools borrow
    // site host strings while their workers wind down.
    var site_store: ui.sites.SiteStore = .init(gpa);
    site_store.loadFrom(core.site_list) catch |err| {
        site_store.deinit();
        return err;
    };
    defer site_store.deinit();

    const factories = try ui.factories.Factories.create(gpa, core);
    defer {
        core.shutdown();
        factories.destroy();
    }
    core.setFactoryProvider(factories.provider());
    try platform.application.run(gpa, core, &site_store, init);
}

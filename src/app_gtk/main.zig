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

    var history: ui.sites.History = .init(gpa);
    history.load(core.io, core.config_dir, ui.sites.history_file);
    defer history.deinit();

    var auth_meta: ui.sites.AuthMetaStore = .init(gpa);
    auth_meta.load(core.io, core.config_dir, ui.sites.meta_file);
    defer auth_meta.deinit();

    var prefs = try ui.prefs.load(core.io, core.config_dir, gpa);
    defer ui.prefs.deinit(gpa, &prefs);

    const factories = try ui.factories.Factories.create(gpa, core);
    defer {
        core.shutdown();
        factories.destroy();
    }
    factories.meta_lookup = .{ .ctx = &auth_meta, .get = authChoice };
    core.setFactoryProvider(factories.provider());
    try platform.application.run(gpa, core, &site_store, &history, &auth_meta, &prefs, init);
}

fn authChoice(ctx: ?*anyopaque, site_id: u64) ?ui.factories.AuthChoice {
    const store: *ui.sites.AuthMetaStore = @ptrCast(@alignCast(ctx.?));
    const entry = store.get(site_id) orelse return null;
    return .{
        .method = switch (entry.method) {
            .agent => .agent,
            .key_file => .key_file,
            .password => .password,
        },
        .key_path = entry.key_path,
    };
}

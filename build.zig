const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const is_macos = target.result.os.tag == .macos;
    const is_linux = target.result.os.tag == .linux;

    const test_step = b.step("test", "Run all unit tests");

    // ------------------------------------------------------------------
    // relay_core — protocol engines, queue, VFS, plus vendored C.
    // No ObjC; builds anywhere.
    // ------------------------------------------------------------------
    const libressl_dep = b.dependency("libressl", .{
        .target = target,
        .optimize = optimize,
    });
    const libcrypto = libressl_dep.artifact("crypto");
    const libssl = libressl_dep.artifact("ssl");

    const ssh2_lib = addLibssh2(b, target, optimize, libssl, libcrypto);

    // C bindings module for libssh2 + LibreSSL (translate-c; @cImport-free).
    const c_translate = b.addTranslateC(.{
        .root_source_file = b.path("src/core/c_includes.h"),
        .target = target,
        .optimize = optimize,
    });
    c_translate.addIncludePath(b.dependency("libssh2", .{}).path("include"));
    c_translate.addIncludePath(libssl.getEmittedIncludeTree());
    c_translate.addIncludePath(libcrypto.getEmittedIncludeTree());
    const c_mod = c_translate.createModule();

    const core_mod = b.addModule("relay_core", .{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = c_mod },
        },
    });
    core_mod.linkLibrary(ssh2_lib);
    core_mod.linkLibrary(libssl);
    core_mod.linkLibrary(libcrypto);
    if (is_macos) {
        core_mod.linkFramework("Security", .{});
        core_mod.linkFramework("CoreFoundation", .{});
    }

    const core_tests = b.addTest(.{ .root_module = core_mod });
    test_step.dependOn(&b.addRunArtifact(core_tests).step);

    // ------------------------------------------------------------------
    // relay_ui — shared app logic. Imports core only; builds everywhere.
    // ------------------------------------------------------------------
    const ui_mod = b.addModule("relay_ui", .{
        .root_source_file = b.path("src/ui/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "relay_core", .module = core_mod },
        },
    });

    const ui_tests = b.addTest(.{ .root_module = ui_mod });
    test_step.dependOn(&b.addRunArtifact(ui_tests).step);

    // ------------------------------------------------------------------
    // Spike: ssh — proves libssh2 + LibreSSL static link on aarch64-macos.
    // ------------------------------------------------------------------
    const spike_ssh_mod = b.createModule(.{
        .root_source_file = b.path("src/spikes/ssh_spike.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = c_mod },
        },
    });
    spike_ssh_mod.linkLibrary(ssh2_lib);
    spike_ssh_mod.linkLibrary(libssl);
    spike_ssh_mod.linkLibrary(libcrypto);
    const spike_ssh_exe = b.addExecutable(.{
        .name = "spike-ssh",
        .root_module = spike_ssh_mod,
    });
    const spike_ssh_run = b.addRunArtifact(spike_ssh_exe);
    if (b.args) |args| spike_ssh_run.addArgs(args);
    b.step("spike-ssh", "Run the libssh2+LibreSSL link spike").dependOn(&spike_ssh_run.step);

    const spikes_step = b.step("spikes", "Build all spike executables");
    spikes_step.dependOn(&spike_ssh_exe.step);

    // ------------------------------------------------------------------
    // Live integration suite: real servers in Docker (test/integration/).
    // Skips itself cleanly when no docker daemon is reachable.
    // ------------------------------------------------------------------
    const integration_mod = b.createModule(.{
        .root_source_file = b.path("test/integration/runner.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "relay_core", .module = core_mod },
        },
    });
    const integration_exe = b.addExecutable(.{
        .name = "relay-integration",
        .root_module = integration_mod,
    });
    const integration_run = b.addRunArtifact(integration_exe);
    integration_run.addArg("--compose-file");
    integration_run.addFileArg(b.path("test/integration/docker-compose.yml"));
    if (b.args) |args| integration_run.addArgs(args);
    b.step("integration", "Run the live Docker integration suite").dependOn(&integration_run.step);

    // Headless FTP/FTPS probe against a real server (diagnostics).
    const ftp_probe_mod = b.createModule(.{
        .root_source_file = b.path("src/spikes/ftp_probe.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "relay_core", .module = core_mod }},
    });
    const ftp_probe_exe = b.addExecutable(.{ .name = "ftp-probe", .root_module = ftp_probe_mod });
    const ftp_probe_run = b.addRunArtifact(ftp_probe_exe);
    if (b.args) |args| ftp_probe_run.addArgs(args);
    b.step("ftp-probe", "Probe a real FTP/FTPS server").dependOn(&ftp_probe_run.step);

    // ------------------------------------------------------------------
    // macOS-only: relay_mac module, the Relay app bundle, and the UI spike.
    // ------------------------------------------------------------------
    if (is_macos) {
        const objc_dep = b.dependency("objc", .{
            .target = target,
            .optimize = optimize,
        });
        const objc_mod = objc_dep.module("objc");

        const mac_mod = b.addModule("relay_mac", .{
            .root_source_file = b.path("src/macos/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "objc", .module = objc_mod },
                .{ .name = "relay_core", .module = core_mod },
                .{ .name = "relay_ui", .module = ui_mod },
            },
        });
        mac_mod.linkFramework("AppKit", .{});
        mac_mod.linkFramework("Foundation", .{});
        mac_mod.linkFramework("QuickLookUI", .{}); // quicklook.zig (QLPreviewPanel)
        mac_mod.linkFramework("CoreServices", .{}); // fsevents.zig (FSEventStream*)

        const mac_tests = b.addTest(.{ .root_module = mac_mod });
        test_step.dependOn(&b.addRunArtifact(mac_tests).step);

        // Relay.app
        const app_mod = b.createModule(.{
            .root_source_file = b.path("src/app/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "relay_core", .module = core_mod },
                .{ .name = "relay_mac", .module = mac_mod },
                .{ .name = "relay_ui", .module = ui_mod },
            },
        });
        const app_exe = b.addExecutable(.{
            .name = "Relay",
            .root_module = app_mod,
        });

        const app_tests = b.addTest(.{ .root_module = app_mod });
        test_step.dependOn(&b.addRunArtifact(app_tests).step);

        const install_app = b.addInstallArtifact(app_exe, .{
            .dest_dir = .{ .override = .{ .custom = "Relay.app/Contents/MacOS" } },
        });
        const install_plist = b.addInstallFileWithDir(
            b.path("resources/Info.plist"),
            .{ .custom = "Relay.app/Contents" },
            "Info.plist",
        );
        b.getInstallStep().dependOn(&install_app.step);
        b.getInstallStep().dependOn(&install_plist.step);

        const run_app = b.addRunArtifact(app_exe);
        run_app.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_app.addArgs(args); // zig build run -- --smoke
        b.step("run", "Run Relay").dependOn(&run_app.step);

        // Spike: ui — NSTableView with a Zig data source via zig-objc (the M0 gate).
        const spike_ui_mod = b.createModule(.{
            .root_source_file = b.path("src/spikes/ui_spike.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "objc", .module = objc_mod },
            },
        });
        spike_ui_mod.linkFramework("AppKit", .{});
        spike_ui_mod.linkFramework("Foundation", .{});
        spike_ui_mod.linkFramework("QuartzCore", .{});
        const spike_ui_exe = b.addExecutable(.{
            .name = "spike-ui",
            .root_module = spike_ui_mod,
        });
        const spike_ui_run = b.addRunArtifact(spike_ui_exe);
        if (b.args) |args| spike_ui_run.addArgs(args);
        b.step("spike-ui", "Run the zig-objc NSTableView spike (M0 gate)").dependOn(&spike_ui_run.step);
        spikes_step.dependOn(&spike_ui_exe.step);
    }

    // ------------------------------------------------------------------
    // Linux-only: relay_gtk binding/services module and GTK app shell.
    // ------------------------------------------------------------------
    if (is_linux) {
        const gobject = b.dependency("gobject", .{
            .target = target,
            .optimize = optimize,
        });

        const gtk_mod = b.addModule("relay_gtk", .{
            .root_source_file = b.path("src/gtk/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "relay_core", .module = core_mod },
                .{ .name = "relay_ui", .module = ui_mod },
                .{ .name = "gtk", .module = gobject.module("gtk4") },
                .{ .name = "gdk", .module = gobject.module("gdk4") },
                .{ .name = "gio", .module = gobject.module("gio2") },
                .{ .name = "glib", .module = gobject.module("glib2") },
                .{ .name = "gobject", .module = gobject.module("gobject2") },
            },
        });
        gtk_mod.addCSourceFile(.{ .file = b.path("src/gtk/secret_store.c") });
        gtk_mod.addCSourceFile(.{ .file = b.path("src/gtk/helpers.c") });
        gtk_mod.linkSystemLibrary("gtk4", .{ .use_pkg_config = .force });
        gtk_mod.linkSystemLibrary("libsecret-1", .{ .use_pkg_config = .force });

        const gtk_tests = b.addTest(.{ .root_module = gtk_mod });
        test_step.dependOn(&b.addRunArtifact(gtk_tests).step);

        const linux_app_mod = b.createModule(.{
            .root_source_file = b.path("src/app_gtk/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "relay_ui", .module = ui_mod },
                .{ .name = "relay_gtk", .module = gtk_mod },
            },
        });
        const linux_app = b.addExecutable(.{
            .name = "relay",
            .root_module = linux_app_mod,
        });
        b.getInstallStep().dependOn(&b.addInstallArtifact(linux_app, .{}).step);
        b.getInstallStep().dependOn(&b.addInstallFileWithDir(
            b.path("packaging/linux/us.doriantull.relay.desktop"),
            .{ .custom = "share/applications" },
            "us.doriantull.relay.desktop",
        ).step);
        b.getInstallStep().dependOn(&b.addInstallFileWithDir(
            b.path("packaging/linux/us.doriantull.relay.metainfo.xml"),
            .{ .custom = "share/metainfo" },
            "us.doriantull.relay.metainfo.xml",
        ).step);
        b.getInstallStep().dependOn(&b.addInstallFileWithDir(
            b.path("packaging/linux/us.doriantull.relay.svg"),
            .{ .custom = "share/icons/hicolor/scalable/apps" },
            "us.doriantull.relay.svg",
        ).step);
        spikes_step.dependOn(&linux_app.step);
    }
}

/// libssh2 1.11.1 compiled from upstream source against our static LibreSSL.
/// Recipe mirrors allyourcodebase/libssh2's build.zig, with the system
/// ssl/crypto linkage replaced by the LibreSSL artifacts (hermetic).
fn addLibssh2(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libssl: *std.Build.Step.Compile,
    libcrypto: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const upstream = b.dependency("libssh2", .{});

    const config_header = b.addConfigHeader(.{
        .style = .{ .cmake = upstream.path("src/libssh2_config_cmake.h.in") },
        .include_path = "libssh2_config.h",
    }, .{
        .LIBSSH2_API = "",
        .LIBSSH2_HAVE_ZLIB = false,
        .HAVE_SYS_UIO_H = true,
        .HAVE_WRITEV = true,
        .HAVE_SYS_SOCKET_H = true,
        .HAVE_NETINET_IN_H = true,
        .HAVE_ARPA_INET_H = true,
        .HAVE_SYS_TYPES_H = true,
        .HAVE_INTTYPES_H = true,
        .HAVE_STDINT_H = true,
    });

    const lib = b.addLibrary(.{
        .name = "ssh2",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.installHeadersDirectory(upstream.path("include"), "", .{});
    lib.root_module.addConfigHeader(config_header);
    lib.root_module.addIncludePath(upstream.path("include"));
    lib.root_module.addCMacro("HAVE_CONFIG_H", "1");
    lib.root_module.addCMacro("LIBSSH2_OPENSSL", "1");
    lib.root_module.addCSourceFiles(.{ .files = &libssh2_sources, .root = upstream.path("") });
    lib.root_module.linkLibrary(libssl);
    lib.root_module.linkLibrary(libcrypto);
    return lib;
}

const libssh2_sources = [_][]const u8{
    "src/agent.c",
    "src/bcrypt_pbkdf.c",
    "src/blowfish.c",
    "src/chacha.c",
    "src/channel.c",
    "src/cipher-chachapoly.c",
    "src/comp.c",
    "src/crypt.c",
    "src/global.c",
    "src/hostkey.c",
    "src/keepalive.c",
    "src/kex.c",
    "src/knownhost.c",
    "src/mac.c",
    "src/misc.c",
    "src/packet.c",
    "src/pem.c",
    "src/poly1305.c",
    "src/publickey.c",
    "src/scp.c",
    "src/session.c",
    "src/sftp.c",
    "src/transport.c",
    "src/userauth.c",
    "src/userauth_kbd_packet.c",
    "src/version.c",
    "src/crypto.c",
};

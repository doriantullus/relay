# Linux build box

One **native arm64** container that produces **both** Linux architectures at
native speed. Zig cross-compiles without a foreign-arch toolchain, so it needs
only the foreign-arch *libraries* — which Debian multiarch installs side by
side. No qemu, no second CI runner.

```sh
docker build -t relay-linux-build docker/linux-build
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh
```

`ZIG_GLOBAL_CACHE_DIR` is optional but wanted: it persists the fetched
LibreSSL/libssh2 packages across container runs (~75 MB) instead of
re-downloading them every time. `zig-pkg-linux/` is gitignored, and is kept
separate from the host's `zig-pkg/` so macOS and Linux artifacts never mix.
Pass a build step as the first argument (`spikes`, `test`, …); it defaults to
`install`.

Validated 2026-08-31: Debian 13.6 (trixie), glibc 2.41, GTK 4.18.6 for arm64
and amd64 co-installed with zero conflicts. Both arches built from scratch in
**9.6s**.

Only the GUI needs this container. `relay_core` and `relay_ui` cross-compile
straight from macOS (`zig build -Dtarget=x86_64-linux-gnu`, ~8s) because their
C dependencies — LibreSSL, libssh2 — are vendored and built from source. GTK is
the one non-hermetic dependency, which is why it is quarantined here.

## Findings

Four things cost real time to discover. They are encoded in `build-linux.sh`;
this is the why.

### 1. `translate-c` cannot process GTK4 headers (Zig 0.16.0)

It SEGVs on aarch64 and emits **9,155 errors** on x86_64. Every one traces to
`_Pragma("GCC diagnostic pop")` inside glib's `G_DECLARE_FINAL_TYPE` /
`G_GNUC_BEGIN_IGNORE_DEPRECATIONS` macros — Aro cannot expand `_Pragma` there,
and glib uses it pervasively. `@cImport` is the same frontend.

So `src/gtk/` reaches GTK the way `src/macos/` reaches AppKit: **declared by
hand, in one module**. `relay_mac` imports no AppKit headers either — it
hand-writes selector strings under the law in `src/macos/root.zig`. The same
law applies here: ALL `extern fn` declarations live in `relay_gtk`.

```zig
const GtkApplication = opaque {};
extern fn gtk_application_new(app_id: [*:0]const u8, flags: c_uint) ?*GtkApplication;
extern fn gtk_window_present(window: *GtkWindow) void;
```

Before committing to hand-declaring the full surface (GtkColumnView,
GListModel, header bar, popovers, dialogs, DnD, GSettings), evaluate
**zig-gobject** — it generates bindings from GIR XML rather than C headers, so
it sidesteps this entirely. `gir1.2-gtk-4.0` is already in the image; it
arrives as a dependency of `libgtk-4-dev`.

### 2. `PKG_CONFIG_LIBDIR` must include `/usr/share/pkgconfig`

It **replaces** the default search path rather than prepending to it.
`gtk4.pc` and `x11.pc` are per-arch under `/usr/lib/<triple>/pkgconfig`, but
`xproto`, `kbproto`, `xextproto`, `renderproto` and `bzip2` are
arch-independent and live in `/usr/share/pkgconfig`. Omit it and the build
fails with a wall of `Package 'xproto', required by 'x11', not found`.

### 3. `--libs-only-L` is empty; use `--variable=libdir`

Debian ships GTK on the default linker path, so pkg-config emits no `-L` at
all. A cross target will not search the host's `/usr/lib`, so the link fails
with `unable to find dynamic system library 'gtk-4' … searched paths: none`.
`pkg-config --variable=libdir gtk4` returns `/usr/lib/<triple>` directly, and
is arch-correct because `PKG_CONFIG_LIBDIR` already selected the arch.

In `build.zig`:

```zig
fn addPkgConfigLibs(b: *std.Build, mod: *std.Build.Module, pkg: []const u8) void {
    const libdir = std.mem.trim(u8, b.run(&.{ "pkg-config", "--variable=libdir", pkg }), " \n\r\t");
    if (libdir.len > 0) mod.addLibraryPath(.{ .cwd_relative = libdir });
    var libs = std.mem.tokenizeAny(u8, b.run(&.{ "pkg-config", "--libs-only-l", pkg }), " \n\r\t");
    while (libs.next()) |tok| {
        if (std.mem.startsWith(u8, tok, "-l"))
            mod.linkSystemLibrary(tok[2..], .{ .use_pkg_config = .no });
    }
}
```

`.use_pkg_config = .no` matters: Zig would otherwise re-invoke pkg-config
itself and lose the arch selection.

### 4. Pin the glibc floor to the container's

`-Dtarget=x86_64-linux-gnu.2.41`, not `-Dtarget=x86_64-linux-gnu`. Zig
defaults to a 2.31 floor; trixie's `libvulkan.so` references `dlopen@GLIBC_2.34`
and `__isoc23_sscanf@GLIBC_2.38`, and `ld.lld` rejects the mismatch under
`--no-allow-shlib-undefined`.

The consequence is a policy, not just a flag: **the base image's glibc is
Relay's minimum supported distro.** trixie ⇒ 2.41, which is recent. Ship
Flatpak (the runtime fixes the ABI) or drop to an older base if raw binaries
need broader reach. Bump `GLIBC` in `build-linux.sh` only together with the
Dockerfile's `FROM`.

## Flatpak

This container does not produce the Flatpak. `flatpak-builder` builds against
`org.gnome.Sdk` from a manifest, and Flathub's farm builds both arches from
that one manifest. The two paths are complementary: this box for dev and CI
binaries, the manifest for shipping. `flatpak-builder` can be added to this
image later so it stays the single Linux build environment.

# Linux build box

One container that runs natively on either **arm64 or amd64** and produces
**both** Linux architectures. Zig cross-compiles without a foreign-arch
toolchain, so it needs only the foreign-arch *libraries* — which Debian
multiarch installs side by side. No qemu, no second CI runner.

```sh
docker build -t relay-linux-build docker/linux-build

# Generate GTK bindings matching this container's GTK exactly (once, vendored).
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/gen-bindings.sh

# Build both arches.
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh

# Exercise real GTK widget construction and two asynchronous local listings.
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build sh -lc \
  'zig build && GTK_A11Y=none RELAY_GTK_SMOKE=1 dbus-run-session -- xvfb-run -a zig-out/bin/relay'
```

`ZIG_GLOBAL_CACHE_DIR` is optional but wanted: it persists the fetched
LibreSSL/libssh2 packages across container runs (~75 MB) instead of
re-downloading them every time. `zig-pkg-linux/` is gitignored, and is kept
separate from the host's `zig-pkg/` so macOS and Linux artifacts never mix.
Pass a build step as the first argument (`spikes`, `test`, …); it defaults to
`install`.

Validated 2026-09-01: Debian 13.6 (trixie), glibc 2.41, GTK 4.18.6 and
libsecret 0.21.7 for arm64 and amd64 co-installed with zero conflicts. The
AppCore-connected GTK executable links for both targets; the native unit suite
also passes in this image.

Only the GUI and Secret Service adapter need this container. `relay_core` and `relay_ui` cross-compile
straight from macOS (`zig build -Dtarget=x86_64-linux-gnu`, ~8s) because their
C dependencies — LibreSSL, libssh2 — are vendored and built from source. GTK is
the one non-hermetic dependency, which is why it is quarantined here.

## Findings

Five things cost real time to discover. They are encoded in `build-linux.sh`
and `gen-bindings.sh`; this is the why.

### 1. Bindings come from zig-gobject, not `translate-c`

`translate-c` **cannot process GTK4 headers** on Zig 0.16.0. It SEGVs on
aarch64 and emits **9,155 errors** on x86_64, every one tracing to
`_Pragma("GCC diagnostic pop")` inside glib's `G_DECLARE_FINAL_TYPE` /
`G_GNUC_BEGIN_IGNORE_DEPRECATIONS` macros — Aro cannot expand `_Pragma` there,
and glib uses it pervasively. `@cImport` is the same frontend, so it fails too.

**zig-gobject is the answer.** v0.3.2 declares `minimum_zig_version = "0.16.0"`,
an exact match for our pinned toolchain. It generates Zig from GIR XML rather
than parsing C headers, so it sidesteps the frontend entirely, and the result
is a properly typed API — not raw externs:

```zig
const list_view = gtk.ListView.new(selection_model.as(gtk.SelectionModel),
                                   item_factory.as(gtk.ListItemFactory));
_ = gtk.SignalListItemFactory.signals.bind.connect(
    item_factory, ?*anyopaque, &bindListItem, null, .{});
```

`gen-bindings.sh` generates from **this container's own GIR**, so the bindings
match the installed GTK 4.18.6 exactly. The upstream pre-generated artifacts
track the latest two GNOME releases (49/50 = GTK 4.20/4.22) and would be ahead
of the runtime. Output: **194,338 lines across 14 modules** (gtk4 alone is
75,180) in ~12s — that is the binding surface not written by hand. For scale,
`relay_mac` is 8,104 lines of hand-written AppKit binding.

Verified: zig-gobject's own example suite — including `list_view.zig`, which
exercises the `GtkListView` + selection-model + factory pattern that Relay's
file table needs — builds for **both** arches in this container.

Two wrinkles, both handled by `gen-bindings.sh`:

- **`xsltproc` is required.** The GIR fix-ups are XSLT; without it codegen dies
  with `failed to execute xsltproc Gtk-4.0: error.FileNotFound`.
- **GIR files are split by arch, like pkg-config data.** Most live in the
  shared `/usr/share/gir-1.0`, but GLib/GObject ship theirs per-arch under
  `/usr/lib/<triple>/gir-1.0`. Pass BOTH or codegen fails with `no GIR file
  found for GLib-2.0`. The two arches' generated output differs by exactly one
  unused constant (`VA_COPY_AS_ARRAY`), with no type-width differences — so
  generating once from the native arch serves both.

### 2. `PKG_CONFIG_LIBDIR` must include `/usr/share/pkgconfig`

It **replaces** the default search path rather than prepending to it.
`gtk4.pc` and `x11.pc` are per-arch under `/usr/lib/<triple>/pkgconfig`, but
`xproto`, `kbproto`, `xextproto`, `renderproto` and `bzip2` are
arch-independent and live in `/usr/share/pkgconfig`. Omit it and the build
fails with a wall of `Package 'xproto', required by 'x11', not found`.

### 3. `--libs-only-L` is empty

Debian ships GTK on its default linker path, so pkg-config emits the `-l`
flags and header paths but no `-L` at all. A Zig cross target does not search
the host's `/usr/lib/<triple>` automatically, so pkg-config by itself still
leads to `unable to find dynamic system library 'gtk-4' … searched paths:
none`. The next section describes the library-only search prefix that solves
this without adding system headers to the hermetic core build.

### 4. `--search-prefix` must be LIB-ONLY

pkg-config emits no `-L`, and a cross target will not search the host's
`/usr/lib`, so linking fails with `unable to find dynamic system library
'gtk-4' … searched paths: none`. Zig appends `lib/` and `include/` to a
`--search-prefix`, so the Dockerfile builds `/opt/sys-<arch>/lib ->
/usr/lib/<triple>` — **with no `include/` symlink**.

That omission is load-bearing. Adding `/usr/include` to the prefix poisons
every C compilation in the build: the vendored LibreSSL picks up system glibc
headers over Zig's bundled libc and the hermetic core build collapses
(`'__INT64_C' macro redefined`, `call to undeclared function 'freezero'`,
`use of undeclared identifier 'SYSLOG_DATA_INIT'`). GTK's header paths already
arrive as `-I` flags from pkg-config, scoped to the module that asked for them,
which is where they belong.

`build-linux.sh` passes `--search-prefix /opt/sys-<arch>` for this reason;
`relay_core` builds hermetically alongside it, unaffected.

### 5. Pin the glibc floor to the container's

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

# Relay — Linux port plan

**Status (2026-09-01): remote browsing slice builds on arm64 and x86_64.**
Steps 1–4 are complete: `relay_ui` contains AppCore, factories, paths/main-loop
seams, and the extracted pure feature models. Step 5 has vendored GTK 4.18.6
bindings, GLib/XDG implementations, and a libsecret credential backend. Step
6 now launches a native GTK app with a local left pane and a right pane that
connects to saved or ad-hoc FTP/FTPS/SFTP sites. Saved-site selection, URL and
SSH-config-alias Quick Connect, password/keyboard-interactive and host-key
prompts, connection status, disconnect, and asynchronous remote navigation all
use the shared AppCore and production factories. It is a usable remote browser,
not feature parity with the M3 AppKit frontend; transfers and the remaining
power-feature views are tracked below.

Verify the current state:

```sh
test -d src/ui && test -d src/gtk && test -d src/app_gtk
rg 'relay_mac|@import\("(gtk|gio|glib|gobject)' src/ui  # expect: no matches
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build zig build test
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build sh -lc \
  'zig build && GTK_A11Y=none RELAY_GTK_SMOKE=1 dbus-run-session -- xvfb-run -a zig-out/bin/relay'
```

---

## 1. Goal and shape

Relay is a native macOS FTP/FTPS/SFTP client in Zig 0.16 (see
`docs/ARCHITECTURE.md`, `docs/UX.md`). The goal is a Linux GUI **as a second
frontend**, not a port of the first.

`src/macos/` remains macOS-only. It is gated by `build.zig` and
`src/macos/root.zig`, so a Linux target never compiles it. The extraction did
add small `Paths` and `MainLoop` adapters there; no AppKit view was rewritten.

At the original handoff, the work was concentrated in `src/app/` (25,623
lines): 13 files imported `relay_mac`, while the core↔UI bridge, connect
factories, fuzzy ranking, session restore, and vim keymap lived inside
AppKit-shaped files. The completed extraction below prevents the GTK frontend
from reimplementing that logic.

### Target layering

```
src/core/      relay_core   protocol, portable            exists, untouched
src/ui/        relay_ui     shared app logic, NO toolkit  BUILT
src/macos/     relay_mac    AppKit binding + adapters     exists
src/gtk/       relay_gtk    GTK4 binding + services       BUILT, expanding
src/app/       Relay        AppKit views + assembly       shrinks
src/app_gtk/   relay        Linux process assembly        BUILT
```

**Fourth architectural law**, mirroring law 2 in `docs/ARCHITECTURE.md`:
*`relay_ui` imports `relay_core` only, never a toolkit.* The bindings and view
layers import `relay_ui`; never the reverse. This is now recorded in
`ARCHITECTURE.md` and enforced by the module import graph.

Renaming `src/app/` → `src/app_mac/` is cheap (relative imports survive a
directory move; only `build.zig`'s `root_source_file` changes) but belongs in
a separate follow-up commit so the extraction history stays readable.

---

## 2. Decisions already made — do not relitigate

These were investigated with working code. Reversing one means redoing that
work, so the evidence is recorded here.

### GTK4, not wxWidgets or Qt

Zig cannot import C++. wxWidgets and Qt are C++ APIs, and **no Zig binding
exists for either** — you would hand-write an `extern "C"` shim in C++ for
every widget and method touched, and link libstdc++/libc++ into a build that
is currently hermetic Zig + vendored C. Qt additionally needs `moc` driven
from `build.zig`.

GTK4 is plain C with GObject introspection, and has a generator (below).

The "native look on every platform" argument for wx does not apply here,
because Relay **already has** a hand-tuned AppKit frontend. Adopting wx means
deleting `relay_mac` (8,104 lines) and rewriting `src/app`'s view layer —
and wx's macOS output would be *worse* than what exists. Relay's UI is also
largely non-standard controls (custom-drawn table cells with progress tint,
NSToolbar, sheets, source-list sidebar, Quick Look, per-site accent strips);
wx abstracts none of those, so the distinctive parts get hand-written anyway.

AppKit on macOS + GTK on Linux is *more* native than wx on both: each
platform's own toolkit, used directly. The cost is two view layers, which is
exactly what `relay_ui` exists to make affordable.

### zig-gobject, not translate-c

`zig translate-c` **cannot process GTK4 headers** on Zig 0.16.0. It SEGVs on
aarch64 and emits 9,155 errors on x86_64, all from `_Pragma("GCC diagnostic
pop")` inside glib's `G_DECLARE_FINAL_TYPE` / `G_GNUC_BEGIN_IGNORE_DEPRECATIONS`
macros — Aro cannot expand `_Pragma` there. `@cImport` is the same frontend.

[zig-gobject](https://github.com/ianprime0509/zig-gobject) v0.3.2 declares
`minimum_zig_version = "0.16.0"`, an exact match for the pinned toolchain. It
generates Zig from GIR XML instead of parsing headers. Verified: it produces
**194,338 lines across 14 modules** (gtk4 alone 75,180) in ~12s, and its own
example suite — including `list_view.zig`, which exercises the
`GtkListView` + selection-model + factory pattern Relay's file table needs —
builds for both architectures.

The generated API is properly typed, not raw externs:

```zig
const list_view = gtk.ListView.new(selection_model.as(gtk.SelectionModel),
                                   item_factory.as(gtk.ListItemFactory));
_ = gtk.SignalListItemFactory.signals.bind.connect(
    item_factory, ?*anyopaque, &bindListItem, null, .{});
```

Bindings are generated from the build container's own GIR so they match the
installed GTK exactly (4.18.6 on trixie). The upstream pre-generated artifacts
track GNOME 49/50 (GTK 4.20/4.22) and would be *ahead* of the runtime.

### Vtable seams, not conditional compilation

Platform services use the vtable idiom the codebase already uses twice —
`CredStore` (`src/core/cred/store.zig`) and `TlsProvider`
(`src/core/tls/provider.zig`): a `VTable` struct, a thin `{vtable, ctx}`
wrapper, real impl in the app and a fake in tests. Follow that shape exactly.
Do not use `builtin.os.tag` branches inside `relay_ui`.

---

## 3. Step 0 — build environment (DONE)

`docker/linux-build/` — one **native arm64** container producing both Linux
architectures at native speed. Zig cross-compiles without a foreign-arch
toolchain, so it needs only the foreign-arch *libraries*, which Debian
multiarch installs side by side. No qemu, no second CI runner.

```sh
docker build -t relay-linux-build docker/linux-build

# Generate GTK bindings matching this container's GTK (once, vendored).
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/gen-bindings.sh

# Compile and install both GTK executables.
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh

# Run tests (native arch only — see §8).
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build zig build test
```

`relay_core` and `relay_ui` also cross-compile **straight from macOS** —
`zig build spikes -Dtarget=x86_64-linux-gnu` takes ~8s — because their C
dependencies (LibreSSL, libssh2) are vendored and built from source. Only the
GTK layer needs the container.

`docker/linux-build/README.md` documents five findings that cost real time:
translate-c, `PKG_CONFIG_LIBDIR` needing `/usr/share/pkgconfig`,
`--libs-only-L` being empty, the lib-only `--search-prefix` (adding
`/usr/include` breaks the hermetic LibreSSL build), and pinning the glibc
floor. **Read that file before changing anything under `docker/`.**

---

## 4. Steps 1–4 — the `relay_ui` extraction (DONE)

macOS must keep building and passing throughout. The 201 headless tests in
`src/app` are the safety net.

### Step 1 — land the empty module (DONE)

Nothing moves yet.

- `build.zig`: `b.addModule("relay_ui", …)` importing only `relay_core`;
  `test_step.dependOn` its `addTest`. Place it **outside** the `is_macos`
  branch.
- `.github/workflows/ci.yml`: the `linux-core` job picks it up via
  `zig build test`; rename it `linux-core-ui`.
- `docs/ARCHITECTURE.md`: add the fourth law and the layer diagram from §1.
- `README.md`: it currently opens "A native macOS FTP / FTPS / SFTP client" —
  note the second frontend.

**Done when** `zig build test` passes on macOS and Linux with an empty module.

### Step 2 — move the five zero-dependency files (DONE)

These import no toolkit at all. Pure moves.

| file | lines |
|---|---|
| `src/ui/factories.zig` | 1302 |
| `src/ui/fuzzy.zig` | 665 |
| `src/ui/temp_cache.zig` | 502 |
| `src/ui/vim.zig` | 216 |
| `src/ui/format.zig` | 32 |

~2,720 lines. `src/ui/temp_cache.zig:101` now asks `Paths` for
the preview cache instead of building a Library path from `HOME`:

```zig
/// src/ui/platform/paths.zig
pub const Paths = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const Error = error{ OutOfMemory, NoHomeDirectory, NameTooLong };

    pub const VTable = struct {
        /// Durable app data. Caller owns the returned path.
        ///   macOS: ~/Library/Application Support/<bundle_id>
        ///   Linux: $XDG_CONFIG_HOME/<app_id>  (default ~/.config/<app_id>)
        configDir: *const fn (ctx: *anyopaque, gpa: Allocator) Error![]u8,

        /// Discardable data, `sub` appended ("preview", "edit").
        ///   macOS: ~/Library/Caches/<bundle_id>/<sub>
        ///   Linux: $XDG_CACHE_HOME/<app_id>/<sub>  (default ~/.cache/…)
        cacheDir: *const fn (ctx: *anyopaque, gpa: Allocator, sub: []const u8) Error![]u8,
    };
};
```

The current call sites are `src/ui/bridge.zig:407` (config),
`src/ui/temp_cache.zig:101` (cache/preview), and
`src/ui/edit_sessions.zig:27` (cache/edit).

**Done when** the five files live in `src/ui/`, `src/app/` imports them from
`relay_ui`, and both suites pass.

### Step 3 — `MainLoop`, then move `bridge.zig` (DONE)

The highest-leverage step in the project: **2,499 lines for three call sites.**
`bridge.zig`'s entire macOS dependency is:

```
328:    pump_timer: ?mac.dispatch.RepeatingTimer = null,
450:            self.pump_timer = mac.dispatch.RepeatingTimer.startOnMain(
609:        mac.dispatch.mainQueueAsync(self, drainFromDispatch);
```

`mac.dispatch` is comptime-generic (`ctx: anytype, comptime f: fn (@TypeOf(ctx)) void`),
which a vtable cannot express. Erase to `*anyopaque` and restore ergonomics
with a comptime wrapper:

```zig
/// src/ui/platform/main_loop.zig
pub const MainLoop = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const Timer = struct { handle: *anyopaque };
    pub const TimerError = error{TimerCreateFailed};

    pub const VTable = struct {
        /// Enqueue `f(arg)` on the UI thread. Must not block.
        post: *const fn (ctx: *anyopaque, arg: *anyopaque,
                         f: *const fn (*anyopaque) void) void,
        startTimer: *const fn (ctx: *anyopaque, interval_ms: u64, arg: *anyopaque,
                               f: *const fn (*anyopaque) void) TimerError!Timer,
        cancelTimer: *const fn (ctx: *anyopaque, timer: Timer) void,
    };

    /// Typed sugar: `loop.post(self, AppCore.drainFromDispatch)`.
    /// `arg` must be a pointer.
    pub fn post(self: MainLoop, arg: anytype, comptime f: fn (@TypeOf(arg)) void) void {
        const shim = struct {
            fn call(raw: *anyopaque) void { f(@ptrCast(@alignCast(raw))); }
        };
        self.vtable.post(self.ctx, @ptrCast(arg), shim.call);
    }
};
```

Implementations: `src/macos/` wraps `dispatch.mainQueueAsync` /
`RepeatingTimer.startOnMain`; `src/gtk/` wraps `g_main_context_invoke` /
`g_timeout_add` (step 5); `src/ui/` ships a manual fake for tests, which
`pump = .manual` (`src/ui/bridge.zig:124`) already models.

**Done when** `bridge.zig` lives in `src/ui/` with zero toolkit imports and
its headless tests run in the Linux CI job.

Other `dispatch` users stay in the macOS view layer for now — notably
`src/app/controllers/browser.zig:2868` (background compare) and the scripted
smoke cadence in `src/app/main.zig`. Widen `MainLoop` only when shared logic
actually needs those operations.

### Step 4 — lift the already-marked pure models (DONE for the pure halves)

Each file is *already* split by its author into a pure section and a
controller section. Lift the pure half; leave the controller behind.

| current shared file | extracted responsibility | lines |
|---|---|---:|
| `src/ui/sites.zig` | saved sites, history, SSH config, quick connect, importers | 1137 |
| `src/ui/terminal.zig` | command builders and launch-plan derivation | 470 |
| `src/ui/palette.zig` | candidates and fuzzy ranking model | 104 |
| `src/ui/edit_sessions.zig` | cache paths and conflict decisions | 72 |
| `src/ui/inspector.zig` | selection, permission, and format model | 123 |
| `src/ui/transcript.zig` | ring, sanitization, filtering, follow-tail | 197 |

The pure halves are now in `src/ui/{sites,terminal,palette,edit_sessions,
inspector,transcript}.zig`; the macOS controllers import and alias them. The
remaining platform services are still needed as their controller logic moves:

- `FileWatcher` — FSEvents (`src/macos/fsevents.zig`) vs inotify;
  `edit_sessions`. Note inotify is per-directory with watch limits — different
  semantics, not a drop-in.
- `Opener` — `NSWorkspace` (`src/app/controllers/edit_sessions.zig:737`) vs
  `xdg-open`/`GAppInfo`.
- `Notifier` — `UNUserNotification` (`src/macos/notifications.zig`) vs
  `GNotification`.
- `TerminalLauncher` — bundle-ID detection
  (`src/app/controllers/terminal.zig:121`) vs `$TERMINAL`
  plus a configurable list (foot, kitty, konsole, ghostty, gnome-terminal).
  The plan derivation is already pure.

`CredStore` is **not** one of these — the interface already exists at core
level. The Linux libsecret implementation lives in `relay_gtk`, next to the
system library it links, and is injected into AppCore by `src/app_gtk/main.zig`.

**Done when** each listed file imports its model from `relay_ui` and those
tests run on Linux CI.

---

## 5. Steps 5–6 — the GTK frontend (IN PROGRESS)

The foundations and first native view are implemented. Feature parity remains
large enough that each remaining controller should land as a reviewable slice.

### Step 5 — `src/gtk/` (relay_gtk, FOUNDATION DONE)

The GTK4 binding layer, mirroring `relay_mac`'s role. Same law as
`src/macos/root.zig`: **all** direct GTK contact lives in this module; feature
code never touches it.

- Vendor the generated bindings (`gen-bindings.sh` → `vendor/zig-gobject-bindings/`)
  and consume via `b.dependency("gobject", …)` + `mod.addImport("gtk", …)`.
- Implement `MainLoop` (`g_main_context_invoke`, `g_timeout_add`) and `Paths`
  (XDG). **Done and headless-tested.** `FileWatcher` (inotify), `Opener`,
  `Notifier`, and `TerminalLauncher` remain.
- Inject a Secret Service backend via libsecret. **Done; compile-tested without
  touching the developer/CI keyring.**
- Wrap the widgets `relay_mac` wraps: a virtual table over `GtkColumnView` +
  `GListModel` (the analogue of `table_source.zig`), tree/outline for the
  sidebar, split view, dialogs, drag & drop. **The application/header bar,
  split view, path controls, scrollers, list rows, saved-site picker, Quick
  Connect form, and authentication/host-key dialogs exist; virtualized column
  views, a full sites sidebar/editor, transfer dialogs, and drag/drop remain.**

### Step 6 — `src/app_gtk/` (REMOTE BROWSING DONE)

`src/app_gtk/main.zig` is intentionally only process assembly. It pins the
shared `SiteStore` until after AppCore shutdown because protocol workers borrow
site strings. GTK contact stays in `relay_gtk/application.zig`, which supplies
a local left pane and a local-or-remote right pane with path entry, up, refresh,
async loading status, sorted AppCore snapshots, directory activation, stale-
request rejection, and deterministic listener/snapshot cleanup.

The connection slice supports saved sites and Quick Connect targets
(`sftp://`, `ftps://`, `ftp://`, or an SSH-config alias), optional persistence
to `sites.zon`, Secret Service password prompts (including transient/non-saved
credentials), keyboard-interactive and host-key prompts, live connection
status, server switching, and disconnect back to a local pane. Site CRUD/import
UI and connection history still belong to later reviewable slices.

The remaining view layer should keep deliberate UX divergences —
do not try to clone `docs/UX.md` literally:

| macOS | Linux |
|---|---|
| Quick Look panel | no equivalent — build a preview window |
| global menu bar | `GtkPopoverMenuBar` exists, but convention is a header bar + primary menu |
| sheets | `GtkAlertDialog` / modal windows |
| Cmd-based keymap | remap the whole `docs/UX.md` map to Ctrl |
| NSToolbar | `GtkHeaderBar` |

---

## 6. Required work outside the six steps

- **`CredStore` Linux backend — DONE.** `src/gtk/secret_store.{zig,c}` maps the
  portable CredStore key to Secret Service schema attributes and is injected
  explicitly. The macOS-only `KeychainStore` remains unchanged.
- **TLS trust on Linux — BASELINE DONE.** LibreSSL uses the distro default CA
  paths plus `SSL_set1_host`; both Linux binaries link this path. Richer
  failure-detail parity with SecTrust remains desirable.
- **Packaging.** Flatpak, built against `org.gnome.Platform`. Flathub's farm
  builds x86_64 and aarch64 from one manifest — the multiarch container is for
  dev and CI, and does **not** produce the Flatpak.
- **CI — DONE.** The Linux job installs GTK/libsecret, builds the executable,
  constructs the real GTK window under Xvfb (both local AppCore listings must
  finish), and runs core/shared-UI/GTK tests. The live Docker integration job
  remains separate so server flakes cannot mask deterministic failures.

---

## 7. Verification protocol

Every step must leave both platforms green.

```sh
# macOS: core + ui + mac + app
zig build test

# Linux: core + ui. Tests must RUN, so use the container's NATIVE arch.
# build-linux.sh compiles both arches; the foreign-arch leg cannot execute
# its own test binaries without qemu.
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build zig build test

# Both arches still COMPILE and install the GTK executable:
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh

# GTK construction + AppCore event-loop smoke (native arch, virtual display):
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build sh -lc \
  'zig build && GTK_A11Y=none RELAY_GTK_SMOKE=1 dbus-run-session -- xvfb-run -a zig-out/bin/relay'

zig fmt --check build.zig build.zig.zon src
```

The step-3 payoff is now live: AppCore and the extracted models run on Linux
CI as `relay_ui`, alongside compile-only GTK service tests that never touch a
real keyring or display. `relay_ui` is platform-neutral by construction, so
the same tests also run natively on macOS — no container or emulation.

### On timing-sensitive tests

The `queue` subsystem had a family of tests asserting wall-clock behaviour
with margins calibrated to a quiet, fast machine. They are the first thing to
break when shared code starts running in more environments — which is exactly
what steps 1–4 cause. Two were fixed:

- `engine.zig` compared a timer-derived count against a payload-derived one,
  silently requiring mean per-read wall time under `progress_interval_ms / 4`.
  Now asserts the design invariant: the ticker cannot emit more than one event
  per interval.
- `rate_limit.zig` measured pacing through real sleeps. Now driven by
  `rate_limit.Clock`, whose `.virtual` variant advances a counter instead of
  sleeping, so accuracy is exact and instant; one real-clock test keeps the
  `std.Io` wiring covered by asserting only a **lower** bound.

**Apply this pattern in steps 1–4.** When a shared-layer test needs time,
inject the clock rather than widen a tolerance — a tolerance encodes the speed
of whoever ran it last. `MainLoop` is the same seam one level up, and its test
fake should advance virtual time the same way.

---

## 8. Key files

| path | role |
|---|---|
| `docs/ARCHITECTURE.md` | the four laws and current layer diagram |
| `docs/UX.md` | keyboard map and interaction spec |
| `docker/linux-build/README.md` | build environment + five findings |
| `src/core/cred/store.zig` | the vtable idiom to copy |
| `src/ui/bridge.zig` | AppCore; the only core↔UI crossing |
| `src/macos/root.zig` | "all selector strings live here" — the law relay_gtk mirrors |
| `src/macos/appkit/table_source.zig` | the virtual table relay_gtk must match |
| `src/gtk/application.zig` | current GTK window and dual-pane listing slice |
| `src/gtk/secret_store.zig` | Linux Secret Service CredStore adapter |

Current shared/GTK/bootstrap surface: about 8.1k lines across `src/ui`,
`src/gtk`, and `src/app_gtk`, excluding the generated bindings.

# Relay — Linux port plan

**Status: not started.** Everything below step 0 is unbuilt. `src/ui/`,
`src/gtk/` and `src/app_gtk/` do not exist; all 13 files in `src/app/` still
`@import("relay_mac")`. What *has* been done is de-risking: the build
environment and the GTK binding strategy are settled and proven (step 0).

This document is written to be executed by someone — or something — with no
prior context. Read it start to finish before touching code.

Verify the starting state:

```sh
ls -d src/ui src/gtk src/app_gtk        # expect: all missing
grep -c relay_ui build.zig              # expect: 0
grep -rl '@import("relay_mac")' src/app | wc -l   # expect: 13
```

---

## 1. Goal and shape

Relay is a native macOS FTP/FTPS/SFTP client in Zig 0.16 (see
`docs/ARCHITECTURE.md`, `docs/UX.md`). The goal is a Linux GUI **as a second
frontend**, not a port of the first.

`src/macos/` is never touched. It is already gated — `build.zig` on
`target.result.os.tag`, `src/macos/root.zig` on `@compileError` — so a Linux
target never compiles it.

The work is in `src/app/` (25,623 lines). All 13 controllers import
`relay_mac`, and the *app logic* — the core↔UI bridge, connect factories,
fuzzy ranking, session restore, the vim keymap — lives inside AppKit-shaped
files. Left alone, a GTK frontend reimplements all of it, and every feature
after M3 gets written twice, forever.

So: extract the platform-neutral half into a new `relay_ui` module (steps
1–4), then build the GTK binding and view layer against it (steps 5–6).

### Target layering

```
src/core/      relay_core   protocol, portable            exists, untouched
src/ui/        relay_ui     shared app logic, NO toolkit  NEW — steps 1–4
src/macos/     relay_mac    AppKit binding                exists, untouched
src/gtk/       relay_gtk    GTK4 binding                  NEW — step 5
src/app/       Relay        AppKit views + assembly       shrinks
src/app_gtk/   relay        GTK views + assembly          NEW — step 6
```

**Fourth architectural law**, mirroring law 2 in `docs/ARCHITECTURE.md`:
*`relay_ui` imports `relay_core` only, never a toolkit.* The bindings and view
layers import `relay_ui`; never the reverse. Add this to `ARCHITECTURE.md` in
step 1 and enforce it in review.

Renaming `src/app/` → `src/app_mac/` is cheap (relative imports survive a
directory move; only `build.zig`'s `root_source_file` changes) but belongs in
its own commit *after* step 4, so the extraction diffs stay pure moves.

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

# Compile both arches.
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh spikes

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

## 4. Steps 1–4 — the `relay_ui` extraction

macOS must keep building and passing throughout. The 201 headless tests in
`src/app` are the safety net.

### Step 1 — land the empty module

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

### Step 2 — move the five zero-dependency files

These import no toolkit at all. Pure moves.

| file | lines |
|---|---|
| `src/app/factories.zig` | 1302 |
| `src/app/fuzzy.zig` | 665 |
| `src/app/temp_cache.zig` | 505 |
| `src/app/controllers/vim.zig` | 216 |
| `src/app/format.zig` | 32 |

~2,720 lines. Only `temp_cache.zig:103` needs surgery — it builds
`~/Library/Caches/<id>/preview` from `getenv("HOME")`. Introduce `Paths`:

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

Three call sites total, spread across steps 2–4: `bridge.zig:396` (config),
`temp_cache.zig:103` (cache/preview), `edit_sessions.zig:152` (cache/edit).

**Done when** the five files live in `src/ui/`, `src/app/` imports them from
`relay_ui`, and both suites pass.

### Step 3 — `MainLoop`, then move `bridge.zig`

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
`pump = .manual` (`bridge.zig:124`) already models.

**Done when** `bridge.zig` lives in `src/ui/` with zero toolkit imports and
its headless tests run in the Linux CI job.

Other `dispatch` users stay in the view layer for now — `browser.zig:2868`
(`globalQueue`, compare diff), `browser.zig:2893`, `transfers.zig:1349`,
`main.zig:1578`/`:1596` (`after`). Widen `MainLoop` only if step 4 pulls logic
that needs them.

### Step 4 — lift the already-marked pure models

Each file is *already* split by its author into a pure section and a
controller section. Lift the pure half; leave the controller behind.

| file | marker | lines |
|---|---|---|
| `src/app/controllers/sites.zig:127` | "Quick Connect target parsing (pure; headless-tested)" | 3953 |
| `src/app/controllers/terminal.zig:5` | "Command builders (pure, headless-tested)" | 1305 |
| `src/app/controllers/palette.zig:148` | "Model — candidates + ranking (headless; no ObjC)" | 1202 |
| `src/app/controllers/edit_sessions.zig:122` | "Pure logic (headless-tested)" | 1116 |
| `src/app/controllers/inspector.zig:78` | "Pure permission/format logic (headless-tested)" | 828 |
| `src/app/controllers/transcript.zig:36` | "Pure model — headless-tested" | 776 |

Expect ~3–5k lines to move, bringing the shared layer to **~8–10k**.

Add the remaining service vtables as the lifts demand them:

- `FileWatcher` — FSEvents (`src/macos/fsevents.zig`) vs inotify;
  `edit_sessions`. Note inotify is per-directory with watch limits — different
  semantics, not a drop-in.
- `Opener` — `NSWorkspace` (`edit_sessions.zig:780`) vs `xdg-open`/`GAppInfo`.
- `Notifier` — `UNUserNotification` (`src/macos/notifications.zig`) vs
  `GNotification`.
- `TerminalLauncher` — bundle-ID detection (`terminal.zig:489`) vs `$TERMINAL`
  plus a configurable list (foot, kitty, konsole, ghostty, gnome-terminal).
  The plan derivation is already pure.

`CredStore` is **not** one of these — it already exists at core level, so the
Linux backend lands in `src/core/cred/` (see §6).

**Done when** each listed file imports its model from `relay_ui` and those
tests run on Linux CI.

---

## 5. Steps 5–6 — the GTK frontend

Not yet planned in detail; plan it properly once step 4 lands and the real
shape of `relay_ui` is known. What is settled:

### Step 5 — `src/gtk/` (relay_gtk)

The GTK4 binding layer, mirroring `relay_mac`'s role. Same law as
`src/macos/root.zig`: **all** direct GTK contact lives in this module; feature
code never touches it.

- Vendor the generated bindings (`gen-bindings.sh` → `vendor/zig-gobject-bindings/`)
  and consume via `b.dependency("gobject", …)` + `mod.addImport("gtk", …)`.
- Implement `MainLoop` (`g_main_context_invoke`, `g_timeout_add`), `Paths`
  (XDG), `FileWatcher` (inotify), `Opener`, `Notifier`, `TerminalLauncher`.
- Wrap the widgets `relay_mac` wraps: a virtual table over `GtkColumnView` +
  `GListModel` (the analogue of `table_source.zig`), tree/outline for the
  sidebar, split view, dialogs, drag & drop.

### Step 6 — `src/app_gtk/` (the view layer)

~10–12k lines of view code against `relay_ui`. Deliberate UX divergences —
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

- **`CredStore` Linux backend.** `src/core/cred/keychain.zig:18` is
  `if (macos) MacKeychainStore else UnsupportedStore`. Needs Secret Service /
  libsecret, or an encrypted file store. ~300–500 lines plus a policy decision.
  Lands beside `keychain.zig`.
- **TLS trust on Linux.** `src/core/tls/verify_sectrust.zig:23` already has the
  Linux branch (`SSL_CTX_set_default_verify_paths` + `SSL_set1_host`). Needs
  distro CA-path probing and failure-detail parity with the SecTrust path.
- **Packaging.** Flatpak, built against `org.gnome.Platform`. Flathub's farm
  builds x86_64 and aarch64 from one manifest — the multiarch container is for
  dev and CI, and does **not** produce the Flatpak.
- **CI.** Add a `linux-gui` job only when `src/gtk/` exists; before that it is
  a green no-op.

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

# Both arches still COMPILE:
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh spikes

zig fmt --check build.zig build.zig.zon src
```

The payoff lands at step 3: a large share of the 201 headless tests in
`src/app` begin running on Linux CI, so the shared layer is verified on both
platforms **before** any GTK code exists. `relay_ui` is platform-neutral by
construction, so its tests also run natively on macOS — no container, no
emulation.

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
| `docs/ARCHITECTURE.md` | the three (soon four) laws, layer diagram |
| `docs/UX.md` | keyboard map and interaction spec |
| `docker/linux-build/README.md` | build environment + five findings |
| `src/core/cred/store.zig` | the vtable idiom to copy |
| `src/app/bridge.zig` | AppCore; the only core↔UI crossing |
| `src/macos/root.zig` | "all selector strings live here" — the law relay_gtk mirrors |
| `src/macos/appkit/table_source.zig` | the virtual table relay_gtk must match |

Sizes at time of writing: `src/core` 24,406 lines (44 files), `src/macos`
8,104 (19), `src/app` 25,623 (18).

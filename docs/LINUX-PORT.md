# Relay — Linux port, steps 1–4: the `relay_ui` extraction

The Linux GUI is a second frontend, not a port of the first. `src/macos/`
is never touched: it is already gated (`build.zig` on `target.result.os.tag`,
`src/macos/root.zig` on `@compileError`), so a Linux target never compiles it.

The work is in `src/app/`. All 13 controllers `@import("relay_mac")`, and the
app logic — the bridge, the connect factories, fuzzy ranking, session restore,
the vim keymap — lives *inside* AppKit-shaped files. Left alone, the GTK
frontend reimplements ~25k lines and every feature after M3 gets written twice.

Steps 1–4 extract the platform-neutral half into a new `relay_ui` module,
leaving `src/app/` a thin AppKit view layer over it. macOS keeps building and
passing throughout; the 201 headless tests in `src/app` are the safety net.
Steps 5–6 (the GTK binding and view layer) are out of scope here.

## Target layering

```
src/core/      relay_core   protocol, portable            exists, untouched
src/ui/        relay_ui     shared app logic, NO toolkit  NEW ← steps 1–4
src/macos/     relay_mac    AppKit binding                exists, untouched
src/gtk/       relay_gtk    GTK4 binding (zig-gobject)    step 6
src/app/       Relay        AppKit views + assembly       shrinks
src/app_gtk/   relay        GTK views + assembly          step 6
```

**Fourth architectural law**, mirroring law 2: *`relay_ui` imports
`relay_core` only, never a toolkit.* The bindings and view layers import
`relay_ui`; never the reverse.

Platform services follow the vtable idiom the codebase already uses twice —
`CredStore` (`src/core/cred/store.zig`) and `TlsProvider`
(`src/core/tls/provider.zig`): a `VTable` struct, a thin `{vtable, ctx}`
wrapper, real impl in the app and a fake in tests.

Renaming `src/app/` → `src/app_mac/` is cheap (relative imports survive a
directory move; only `build.zig`'s `root_source_file` changes) but belongs in
its own commit *after* step 4, so the extraction diffs stay pure moves.

---

## Step 1 — land the empty module

Wire `relay_ui` into `build.zig` with its own test step, added to **both** CI
jobs. Nothing moves yet.

- `build.zig`: `b.addModule("relay_ui", …)` importing only `relay_core`;
  `test_step.dependOn` its `addTest`. Outside the `is_macos` branch.
- `.github/workflows/ci.yml`: the existing `linux-core` job picks it up via
  `zig build test`; rename the job to `linux-core-ui`.
- `docs/ARCHITECTURE.md`: add the fourth law and the layer diagram above.
- `README.md`: "Native macOS FTP/FTPS/SFTP client" → note the second frontend.

**Done when** `zig build test` passes on macOS and on Linux CI with an empty
`relay_ui`.

## Step 2 — move the five zero-dependency files

These import no toolkit at all. Pure moves.

| file | lines | note |
|---|---|---|
| `src/app/factories.zig` | 1302 | production connect factories |
| `src/app/fuzzy.zig` | 665 | matcher + frecency |
| `src/app/temp_cache.zig` | 505 | needs `Paths` (below) |
| `src/app/controllers/vim.zig` | 216 | pure keymap state machine |
| `src/app/format.zig` | 32 | |

~2.7k lines. Only `temp_cache.zig:103` needs real surgery: it builds
`~/Library/Caches/<id>/preview` from `getenv("HOME")`. Introduce `Paths` and
route it through:

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

Three call sites total, all in step 2/3/4 scope: `bridge.zig:396` (config),
`temp_cache.zig:103` (cache/preview), `edit_sessions.zig:152` (cache/edit).

**Done when** the five files live in `src/ui/`, `src/app/` imports them from
`relay_ui`, and both test suites pass.

## Step 3 — `MainLoop`, then move `bridge.zig`

The highest-leverage step in the project: **2,499 lines for three call sites.**
`bridge.zig`'s entire macOS dependency is

```
328:    pump_timer: ?mac.dispatch.RepeatingTimer = null,
450:            self.pump_timer = mac.dispatch.RepeatingTimer.startOnMain(
609:        mac.dispatch.mainQueueAsync(self, drainFromDispatch);
```

`mac.dispatch` is comptime-generic (`ctx: anytype, comptime f: fn (@TypeOf(ctx)) void`),
which a vtable cannot be. Erase to `*anyopaque` in the vtable and restore the
ergonomics with a comptime wrapper, so the call sites barely change:

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
`RepeatingTimer.startOnMain`; `src/gtk/` will wrap `g_main_context_invoke` /
`g_timeout_add` (step 6); `src/ui/` ships a manual fake for tests, which is
what `pump = .manual` (`bridge.zig:124`) already models.

**Done when** `bridge.zig` lives in `src/ui/` with zero toolkit imports, and
its existing headless tests run in the Linux CI job.

Note: `dispatch` is used elsewhere in `src/app/` — `browser.zig:2868`
(`globalQueue` for the compare diff), `browser.zig:2893`, `transfers.zig:1349`,
`main.zig:1578`/`:1596` (`after`). Those sites stay in the view layer for now;
widen `MainLoop` only if step 4 pulls logic that needs them.

## Step 4 — lift the already-marked pure models

Each of these files is *already* split by its author into a pure section and a
controller section. Lift the pure half; leave the controller behind.

| file | marker | lines |
|---|---|---|
| `src/app/controllers/sites.zig:127` | "Quick Connect target parsing (pure; headless-tested)" | 3953 |
| `src/app/controllers/terminal.zig:5` | "Command builders (pure, headless-tested)" | 1305 |
| `src/app/controllers/edit_sessions.zig:122` | "Pure logic (headless-tested)" | 1116 |
| `src/app/controllers/inspector.zig:78` | "Pure permission/format logic (headless-tested)" | 828 |
| `src/app/controllers/transcript.zig:36` | "Pure model — headless-tested" | 776 |
| `src/app/controllers/palette.zig:148` | "Model — candidates + ranking (headless; no ObjC)" | 1202 |

Expect ~3–5k lines to move, bringing the shared layer to **~8–10k**.

Add the remaining platform-service vtables as the lifts demand them — these
are the ones the macOS code already implies:

- `FileWatcher` — FSEvents (`src/macos/fsevents.zig`) vs inotify; `edit_sessions`.
- `Opener` — `NSWorkspace` (`edit_sessions.zig:780`) vs `xdg-open`/`GAppInfo`.
- `Notifier` — `UNUserNotification` (`src/macos/notifications.zig`) vs `GNotification`.
- `TerminalLauncher` — bundle-ID detection (`terminal.zig:489`) vs `$TERMINAL`
  plus a configurable list. The plan derivation is already pure.

`CredStore` is **not** one of these: it already exists at core level, so the
Linux Secret Service backend lands in `src/core/cred/` beside `keychain.zig`.

**Done when** each listed file imports its model from `relay_ui`, and the
model's tests run on Linux CI.

---

## Verification

Every step must leave both green:

```sh
# macOS: core + ui + mac + app
zig build test

# Linux: core + ui. Tests must RUN, so use the container's native arch —
# build-linux.sh is for compiling both arches, and the foreign-arch leg
# cannot execute its own test binaries without qemu.
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build zig build test

# Both arches still COMPILE (no execution):
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh spikes
```

**On timing-sensitive tests.** The `queue` subsystem has a family of tests
that assert wall-clock behaviour with margins calibrated to a quiet, fast
machine. They are the first thing to break when the shared layer starts running
in more environments — which is exactly what steps 1–4 cause.

`engine.zig`'s "progress events are coalesced far below chunk count" was one:
it compared a timer-derived count against a payload-derived count, which
silently required mean per-read wall time under `progress_interval_ms / 4`
against a mock stall of half that. It passed on a dev machine (0.65 ms/read)
and on CI, and failed in a loaded VM (3 ms/read) where the engine was
coalescing perfectly correctly. Now fixed to assert the design invariant —
the ticker cannot emit more than one event per interval — which holds at any
host speed.

`queue/rate_limit.zig`'s "rate accuracy within 20% over a short window" has the
same shape and is **currently red on the macOS CI runner**, so `main` is not
green today. Worth settling before step 1, so "both platforms green" means
something.

See `docker/linux-build/README.md` for the build environment and the five
findings that shaped it — notably that `relay_gtk` is generated by zig-gobject
rather than hand-written, which is what makes step 6 tractable.

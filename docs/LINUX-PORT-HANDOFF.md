# Relay Linux Port: Remaining Work Handoff

Last updated: 2026-09-02

This document is the handoff for finishing Relay's Linux frontend. It is intentionally
self-contained: start here, then use `docs/LINUX-PORT.md` for the history and detailed
design notes behind the port.

## Starting state

The functional baseline described here is `main` at merge commit `eb1ae60`, which
includes pull request #5 (Linux file operations). This document itself is the only
change after that baseline.

The following Linux work is already merged:

- Reproducible Docker build environment and the original porting plan.
- Portable timing-test fixes and the injected `Clock` seam.
- A native GTK 4 application with the shared core running on its worker thread.
- Local and remote browsing, including FTP, FTPS, and SFTP connections.
- Saved-site connections, Quick Connect, SSH-config aliases, libsecret credentials,
  host-key confirmation, and keyboard-interactive authentication.
- Pane navigation and file selection.
- Uploads and downloads for files and directories.
- Transfer progress, speed, state, failure display, pause, resume, cancel, retry,
  clear, and overwrite/skip conflict handling.
- New folder, rename, copy, and recursive delete from the toolbar, context menu,
  and keyboard shortcuts.
- A deterministic Xvfb smoke test that lists a directory and creates and removes a
  uniquely named directory through `AppCore`.
- Linux builds for both x86_64 and aarch64.

The working application is useful, but it is not yet at macOS feature parity. The
remaining work is primarily frontend depth, Linux platform services, session state,
and distribution packaging—not a rewrite of the protocol or transfer core.

## Confirm the baseline

Run these from the repository root:

```sh
git status --short
git log -1 --oneline

test -d src/ui
test -d src/gtk
test -d src/app_gtk

# Shared UI code must remain toolkit- and platform-neutral. This should print no
# matches.
rg 'relay_mac|@import\("(gtk|gdk|gio|glib|gobject)' src/ui

# macOS build and unit tests.
zig build
zig build test

# Linux unit tests and both release architectures.
docker build -t relay-linux-build docker/linux-build
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build zig build test
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh

# Headless GTK lifecycle and file-operation smoke test.
docker run --rm -v "$PWD:/src" \
  -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build sh -lc \
  'zig build && GTK_A11Y=none RELAY_GTK_SMOKE=1 dbus-run-session -- xvfb-run -a zig-out/bin/relay'

zig fmt --check build.zig build.zig.zon src
```

On macOS, native tests that exercise FSEvents or system panels may need to run outside
a restricted sandbox. Do not interpret that restriction as a product failure.

## Architecture rules

Preserve this dependency direction:

```text
src/core       portable protocol, filesystem, queue, persistence, and AppCore
    ^
src/ui         portable, toolkit-free UI state and decision models
    ^
src/gtk        GTK widgets, adapters, and Linux platform services
    ^
src/app_gtk    Linux process assembly and lifetime ownership

src/macos      AppKit wrappers and macOS platform adapters
src/app        macOS application/controllers; useful as behavior reference only
```

Hard rules:

- `src/ui` may import `relay_core`, but it must not import GTK, AppKit, `relay_mac`,
  or branch on the host operating system.
- Put reusable state transitions, validation, formatting, and command construction
  in `src/ui`. Keep GTK object ownership and signal handling in `src/gtk`.
- Add Linux-specific behavior through small service/vtable seams, following the
  existing Paths, MainLoop, and credential-store patterns.
- Do not duplicate transfer, persistence, or protocol behavior in GTK when `AppCore`
  already exposes it.
- Keep secrets out of `sites.zon`, logs, transcripts, and tests. Linux credentials
  continue to use libsecret.
- `src/app_gtk/main.zig` must keep `SiteStore` alive until after `AppCore` shuts down:
  core workers borrow strings from the store.
- The vendored GTK bindings were generated against GTK 4.18.6. Do not regenerate
  them as part of an unrelated feature.

## Recommended next pull request: full sites sidebar and editor

This is the highest-value next slice because the connection machinery already works,
while managing saved connections is still much thinner than on macOS.

### Deliverables

- Add sidebar sections for Servers, SSH Config, and History.
- Add create, edit, duplicate, and delete flows for persisted sites.
- Support all persisted connection fields:
  - display name
  - protocol
  - host and port
  - account/user name
  - initial local and remote paths
  - TLS insecure-certificate flag
  - accent/environment metadata
  - authentication method and key-file selection
- Keep SSH-config entries read-only and visually distinct from saved sites.
- Connect the selected server, alias, or history item into the active pane (the
  current right-pane-only topology may be used only until active-pane support lands).
- Add FileZilla and Cyberduck import entry points and a result/error summary.
- Persist edits atomically and refresh `AppCore.site_list` safely.
- Add headless tests for validation, selection, edits, deletion, and import decisions.
- Extend the GTK smoke test only where behavior can be driven deterministically
  without a modal native chooser.

### Existing code to reuse

- `src/core/settings/sites.zig`: the persisted site schema and `sites.zon`
  load/save implementation.
- `src/ui/sites.zig`: `SiteStore` (including add/update/remove, persisted-state
  accessors, `coreSlice`, and save operations), `History`, `AuthMetaStore`,
  `SshGroup`, and the FileZilla and Cyberduck import parsers.
- `src/core/proto/ssh/ssh_config.zig`: SSH-config parsing and resolution.
- `src/app/controllers/sites.zig`: macOS behavior reference. Extract concepts from
  it; do not import it from Linux.
- `src/gtk/application.zig`: the current compact saved-site/Quick Connect UI and
  the `Window.syncCore` ownership/update pattern.

### Acceptance criteria

- A user can create a site, quit, relaunch, and connect to it.
- Editing and deleting a site survives relaunch.
- A secret is never written into any Relay persistence file.
- Imported sites can be reviewed before they are persisted.
- Site-list updates cannot leave `AppCore` with borrowed strings whose owner has
  been destroyed or mutated unsafely.
- macOS and Linux builds and tests remain green.

## Remaining feature work

The sections below are in recommended implementation order. Each should normally be
its own reviewable pull request, or a short sequence of tightly related pull requests.

### 1. Replace the browser list with a scalable file table

The current GTK browser uses `GtkListBox` and intentionally caps visible entries at
2,000. Replace it with `GtkColumnView` backed by a `GListModel`, an appropriate
selection model, and item factories.

Deliverables:

- Columns for name/icon, size, modified time, and remote permissions.
- Sortable headers with directories-first behavior.
- Multiple selection that continues to feed transfers and file operations.
- Type-to-select, a filter field, and a hidden-files toggle.
- User-selectable row density and optional monospace presentation.
- Back/forward navigation history and a go-to-path action.
- Clear active-pane focus treatment and consistent keyboard traversal.
- Allow either pane to host a local or remote location; the current fixed local-left,
  local-or-remote-right topology is an intermediate state.
- Open/download-and-open behavior for files.
- A per-pane status row with item/selection counts, connection state, and remote
  latency where available.
- Visible accent/environment and insecure-TLS warnings, including a Linux-appropriate
  safeguard for destructive operations on production-tagged sites.
- Optimistic pending treatment and rollback/error presentation for file operations.
- Efficient refreshes using snapshots without copying every entry unnecessarily.
- Partial/streaming listing presentation if the bridge currently exposes only a
  count during progress and a full snapshot at completion.

Be explicit about ownership: GTK row objects may outlive a render pass, while core
snapshots have their own lifetime. Do not keep pointers into released snapshots.

### 2. Add drag and drop

Deliverables:

- Drag between Relay panes to enqueue uploads/downloads.
- Accept URI-list drops from the desktop/file manager when supported.
- Export local files to the desktop/file manager when supported.
- Validate payloads and reject unsafe traversal, self-copy, and recursive
  directory-into-itself operations.
- Reuse the existing conflict policy and queue machinery.

### 3. Finish the transfer center

The current transfer panel covers the basic queue lifecycle. Add the rest of the
macOS behavior:

- Separate active/queued, failed, and transcript views.
- Aggregate progress, throughput, and ETA.
- Pause All, Resume All, Cancel All, and Requeue Failed.
- Per-row remove, reorder, and requeue actions.
- Folder-transfer grouping and child visibility.
- Queue restore/resume controls on launch.
- Keyboard queue actions.
- Global and directional bandwidth-limit controls.

Existing core APIs include queue snapshots, pause/resume/cancel/remove/reorder,
bulk actions, failed requeue, restore, and conflict handling. Start from those APIs
rather than introducing GTK-owned queue state.

Useful references:

- `src/app/controllers/transfers.zig`: macOS behavior and queue-model reference.
- `src/ui/format.zig`: shared formatting.
- `src/ui/transcript.zig`: portable transcript model.
- The AppCore listener event for transcript lines.

If GTK needs to change runtime rate limits, first expose a narrow AppCore/bridge
command. Do not reach through the frontend into `core.engine` merely because the
macOS controller currently does so.

### 4. Add the inspector

Deliverables:

- Single- and multi-selection summaries.
- Size, modification time, file type, and remote permission display.
- Editable remote permissions using `AppCore.chmodPath`.
- Clear staged/applying/error states and refresh after a successful change.

Reuse `src/ui/inspector.zig` and use the macOS inspector controller as a behavior
reference.

### 5. Add Settings, menus, and the full shortcut map

Linux needs a proper settings surface for core settings and portable UI preferences:

- Default download directory.
- Delete confirmation.
- Reconnect behavior and connection limits.
- Upload/download bandwidth caps.
- Density, monospace, date format, hidden-files default, and Vim mode.
- A GTK primary menu/action map matching the relevant commands in `docs/UX.md`.
- Normal Linux Control-based shortcuts and discoverable menu accelerators.

At present, several portable-looking `UiPrefs` and `SessionState` types still live in
`src/app/controllers/prefs.zig`. Extract their platform-neutral representation and
persistence decisions into `src/ui` before using them from GTK. Do not make Linux
depend on an AppKit controller.

The current GTK file-operation shortcuts are only a starting point: F2, Delete, and
Ctrl+Shift+N.

### 6. Implement missing Linux platform services

Add small adapters with portable interfaces, not OS checks inside shared UI code:

- File watcher: inotify or `GFileMonitor`, needed by external edit sessions.
- File/URL opener: `GAppInfo` or a carefully contained `xdg-open` fallback.
- Notifications: `GNotification`, especially for background completion/failure.
- Terminal launcher: support common terminals and honor a usable `$TERMINAL`
  configuration without shell-injection hazards.

`src/ui/terminal.zig` contains reusable command-construction concepts but its current
terminal discovery is macOS-oriented. Treat it as a partial reference, not as the
Linux implementation.

### 7. Port the power features

After the browser and platform services are solid, add:

- Command palette, fuzzy matching, frecency, and path mode. Reuse
  `src/ui/palette.zig` and `src/ui/fuzzy.zig`.
- Quick preview in a GTK window. Linux has no Quick Look equivalent; use an internal
  preview and the existing temporary-cache concepts in `src/ui/temp_cache.zig`.
- External edit sessions: download/cache, watch, reopen/upload, and remote-mtime
  conflict choices (overwrite, duplicate, cancel). Reuse the pure decisions in
  `src/ui/edit_sessions.zig`.
- Open in terminal and copy-as-SCP/rsync/SFTP/curl commands. Reuse portable command
  construction where safe.
- Synchronized browsing and directory comparison.
- Vim navigation using `src/ui/vim.zig`.
- Multiple tabs/windows if full macOS product parity remains the goal.

External-process arguments must be passed as argument arrays. Never build a shell
command by interpolating a remote path, host, account name, or user-entered value.

### 8. Restore sessions

Persist and restore:

- Pane site/path state.
- Focused pane.
- Sidebar, transfer center, and inspector collapsed state.
- Tabs/windows if those have landed.
- Queue state when the user has opted into queue restoration.

Reconnect a remote session automatically only when it is prompt-free. If credentials,
a host-key decision, keyboard interaction, or another confirmation is required, show
the disconnected/restorable state and let the user initiate the connection.

This work should follow extraction of portable `UiPrefs`/`SessionState` from the
macOS preferences controller.

### 9. Package and polish the Linux application

Flatpak is the recommended primary distribution target.

Deliverables:

- Flatpak manifest using compatible GNOME Platform and SDK runtimes.
- Application ID, icons at required sizes, `.desktop` file, and AppStream metadata.
- Documented sandbox permissions for network access, chosen filesystem scope,
  secret service, notifications, and SSH configuration access.
- A release build/install smoke test in CI.
- Accessibility pass with screen-reader names and keyboard-only operation.
- GNOME and KDE visual/behavior checks, including light and dark themes.
- Localization extraction and translation-ready strings.
- Documented release artifact and update process.

The raw binaries built in `docker/linux-build` inherit the Debian trixie glibc floor
(currently glibc 2.41). They are useful for CI and controlled systems but are not a
portable general Linux release. Flatpak avoids tying the user-visible artifact to
that host libc floor.

Also improve Linux TLS trust errors where possible. The connection works today, but
failure detail is less rich than the macOS SecTrust presentation.

## Cross-cutting test requirements

Every feature slice should satisfy all applicable gates:

- Pure state/decision logic has unit tests in `src/ui` or `src/core`.
- `zig build` and `zig build test` pass on macOS.
- Linux `zig build test` passes in `relay-linux-build`.
- Both Linux architectures compile through `build-linux.sh`.
- `zig fmt --check build.zig build.zig.zon src` passes.
- The GTK Xvfb smoke test exits successfully.
- New bridge commands are exercised without touching a real keyring.
- User-visible errors are retained long enough to be actionable and do not leak
  secrets.
- Teardown tests cover callbacks arriving during or after window shutdown.

Extend `RELAY_GTK_SMOKE` for deterministic, main-loop-driven behavior. Do not make
the smoke test depend on clicking modal dialogs, a desktop portal, a live network,
or a user's credential store.

Run with `G_DEBUG=fatal-warnings` during GTK development. It previously caught a real
popover-parenting bug that a normal smoke run only printed as a warning.

The live integration suite (`zig build integration`) exercises real protocol servers.
It has had an occasional ProFTPD cancel-mid-download timing failure. Reproduce a
failure before changing production code, and do not mix an unrelated flake fix into
a Linux UI pull request.

## Known implementation traps

- GTK context popovers must be parented to a stable widget. Parenting a popover to a
  list that is cleared and rebuilt can leave the popover destroyed or unparented.
- Removing `GtkListBox` children while iterating via a cached sibling pointer is
  unsafe. The file table replacement should make this pattern unnecessary.
- UI callbacks can outlive the visible window. Preserve the bridge's main-loop
  dispatch and shutdown guards.
- Never call worker-owned core state directly from a GTK signal handler when a bridge
  command/event already exists or can be added.
- `pkg-config --libs-only-L` can legitimately be empty in the Docker image.
- `PKG_CONFIG_LIBDIR` must include `/usr/share/pkgconfig`.
- Zig's `--search-prefix` must point at library-only prefixes; feeding it a broad
  system prefix can shadow unrelated headers and libraries.
- The build uses generated zig-gobject bindings, not `translate-c`.
- Do not casually upgrade the container, GTK, Zig, or generated bindings in a feature
  PR. Version changes deserve their own build-system review.
- Copy, delete, drag/drop, and sync operations must reject recursive self-targets and
  path traversal before dispatch.
- Site and queue persistence should be atomic and recover cleanly from a partial or
  invalid file.

## Suggested pull-request sequence

1. Full sites sidebar/editor and import UI.
2. Scalable file table and browser navigation/filtering.
3. Pane drag/drop.
4. Advanced transfer center and rate-limit bridge commands.
5. Inspector and chmod UI.
6. Settings/preferences extraction, GTK settings, menus, and keybindings.
7. Linux watcher, opener, notifier, and terminal-launcher services.
8. Command palette, preview, external edit, terminal commands, comparison/sync, and
   Vim mode in small independent slices.
9. Session restoration.
10. Flatpak packaging, release CI, accessibility, localization, and desktop polish.

A source-layout cleanup such as renaming `src/app` to `src/app_mac` can improve
clarity, but it should be a separate mechanical change. It does not block any Linux
feature and should not be bundled with one.

## Definition of “Linux port complete”

The port is complete when a Linux user can install the packaged application, manage
connections without editing files by hand, browse large local and remote directories,
perform and monitor all supported transfers and file operations, recover useful
session state, use the application entirely by keyboard, and receive actionable
errors—without a macOS dependency anywhere in the Linux build graph.

At that point:

- All cross-cutting test gates above pass in CI.
- The Flatpak installs and launches on supported GNOME and KDE systems.
- No secrets are stored in plaintext.
- GTK shutdown is clean under fatal warnings and sanitizing/debug builds.
- `src/ui` remains platform- and toolkit-neutral.
- `docs/UX.md`, `docs/ARCHITECTURE.md`, and release documentation accurately describe
  the Linux application rather than treating it as an experimental frontend.

## Implementation status

The handoff is implemented on this branch. The GTK frontend now includes the
saved-sites editor/importer, virtualized file tables, pane and desktop
drag/drop, grouped transfer center, inspector, settings/action menus,
Control-based shortcuts, Linux opener/watcher/notifier/terminal services,
command and path palettes with persisted frecency, preview, external editing
with remote-change conflict choices, synchronized browsing, comparison, Vim
navigation, session and opt-in queue restoration, and Flatpak desktop
metadata. The release workflow validates a fatal-warning GTK smoke, installed
resources, and both raw Linux architectures.

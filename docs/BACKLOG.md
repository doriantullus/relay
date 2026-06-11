# Relay — Backlog (deferred review findings & followups)

Carried forward deliberately; sourced from the M1/M2/M3 adversarial reviews
and implementer reports. Ordered roughly by user-visible impact.

## M4 candidates (user-visible)

- **SSH Config FSEvents watcher**: the smart group re-parses on
  applicationDidBecomeActive gated by a cheap ~/.ssh/config mtime stat
  (plus startup + manual refresh); the fsevents kit now exists (edit
  sessions use it) — wire a live watcher to the smart group.
- **Real multi-window / native NSWindow tabs** (Cmd+N currently retitled
  "Show Main Window").
- **Outgoing Finder drags via NSFilePromiseProvider**: verify/complete
  (incoming drops and pane-to-pane drags work).
- **Context-menu row targeting**: the pane right-click menu acts on the
  pane's current selection; a right-click on an unselected row should act
  on that row (Finder semantics).
- **Remote Quick Look batch**: only the first selected remote file
  previews (one pending download slot); local selections preview as a set.
- **Editor choice pref for edit sessions** (NSWorkspace default-app open
  today; $EDITOR/terminal editors out of scope in M3).
- **Restore-session prompt-free gate vs unknown host keys**: restored SFTP
  reconnects assume the host key is already in known_hosts (true for sites
  connected before quit). A first-launch restore against a changed host
  key falls back to the normal prompt path — audit that it lands after the
  window is up, not mid-launch.

## Hygiene / hardening

- **Menu validation**: autoenablesItems is ON; callback items are always
  enabled. Add validateMenuItem: to RelayMenuTarget when per-item enable
  logic is needed.
- **menu.Registry tags are append-only**; dynamic menus need a fresh
  Registry or a reset API.
- **FTP stat() dir-probe mutates the browse connection's CWD** (unrestored;
  benign today because all commands use absolute paths). Prefer MLST or
  restore CWD after probing.
- **vfs/sftp.zig adapter has near-zero offline coverage** (lease lifetime,
  markBroken paths) — add stub-session tests like vfs/ftp.zig's.
- **Fuzz mode is broken on Zig 0.16.0** (bundled fuzz test_runner compile
  error). The 12 fuzz harnesses run corpus-only. Re-add the nightly
  `zig build test --fuzz` CI job on the next toolchain bump.

## Process notes

- Live tests are env-gated by design: RELAY_SFTP_LIVE, RELAY_TLS_LIVE,
  RELAY_KEYCHAIN_SMOKE, RELAY_PERF. CI unit runs stay offline.
- vfs.Caps was ratified as a plain struct (not packed) — tri-state ?bool.

## Closed by the M2 backlog sweep (for the record)

- Latency honesty: the bridge worker brackets the protocol list call;
  elapsed_ms rides ListingProgress/ListingDone; remote status bars render
  "· {d} ms".
- Active-pane connects / pane roles: connects land in the focused pane
  (pane[1] fallback while the UI assembles); a local pane role-switches to
  remote (Permissions column shows) and restores role + path on disconnect.
- chmod optimistic overlay: inspector Apply stages a mode override (pending
  alpha) per dispatched op; rolled back on op_done failure, reconciled by
  the re-list.
- Esc in the Cmd+F filter field clears/dismisses it
  (control:textView:doCommandBySelector: → cancelOperation:).
- Unwired Settings: date_format (ISO/relative Modified column),
  confirm_delete (deleteSelection sheet skip), monospace_lists
  (table_source font hook) all have live consumers.
- Toolbar 'View' density popup (NSMenuToolbarItem → density commands).
- Quit path vs attached sheets: onWillTerminate (inside
  applicationShouldTerminate) ends attached sheets before teardown.
- EventQueue OOM policy: explicit drop-and-warn documented at
  bridge.postEvent; core producers (engine.post, site_pool) share the
  documented best-effort drop policy.

## Closed by M3 (for the record)

- Command palette (Cmd+Shift+P / Cmd+P): fuzzy matcher + frecency store
  (palette.zon) over the CommandRegistry vocabulary, saved sites, visited
  paths and the active pane's entries; browser navigations feed frecency
  via the visit hook.
- Edit in external editor (Cmd+E): per-session temp dirs, queue-visible
  download/upload, FSEvents save detection (0.35 s coalescing), remote
  re-stat conflict rule (conflict ⇔ both mtimes known and different),
  Overwrite / Save as Copy / Cancel sheet, App Nap held off while watching;
  sessions ended (watchers stopped, temp dirs deleted) before
  AppCore.shutdown() on quit.
- Quick Look: Space (browser key hook, ahead of the vim layer) + Cmd+Y +
  File menu; remote files through the content-addressed preview TempCache
  (LRU, 512 MiB budget).
- Terminal interop: Open in Terminal (Ghostty/iTerm2/Terminal detection,
  Cmd+Opt+T) + Copy as scp/rsync/SFTP-URL/curl in Edit ▸ and the pane
  context menu.
- Importers: File ▸ Import ▸ FileZilla XML / Cyberduck .duck with optional
  password import into the Keychain.
- View menu: Synchronized Browsing (Cmd+Shift+B), Compare Panes
  (Cmd+Shift+D), Vim Key Bindings (persisted pref "ui.vimMode").
- Transfer notifications (UNUserNotificationCenter; batch summaries,
  unbundled processes degrade to no-ops) + bandwidth limit controls in the
  transfers panel header.
- Session restoration: ui.zon carries per-pane (site, path), focused pane,
  panel collapse states; saved on quit, restored on launch; remote
  reconnects only when prompt-free (agent meta or Keychain secret probe) —
  launches never prompt.
- --smoke extended: palette open/fuzzy-query/execute/close, TempCache
  put/get, full local edit-session round trip (real FSEvents watcher;
  conflict check on an unchanged mtime ⇒ silent upload).

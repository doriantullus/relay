# Relay — Backlog (deferred review findings & followups)

Carried forward deliberately; sourced from the M1/M2 adversarial reviews and
implementer reports. Ordered roughly by user-visible impact.

## M3 candidates (user-visible)

- **Latency honesty**: remote pane status bar should show last round-trip ms
  (UX.md). Needs a timing field on the bridge's ListingDone (worker brackets
  the protocol call) or keepalive RTT via SiteStatusChange.
- **Active-pane connects / pane roles**: connects always land in pane[1];
  spec says "connects in active pane" and "either pane can host local or
  remote". Either teach BrowserPane role switching or amend the spec.
- **chmod optimistic overlay**: rename/delete/mkdir show the 60%-alpha
  pending treatment; chmod doesn't (Permissions column updates only after
  the post-success re-list).
- **Esc while typing in the Cmd+F filter field** should clear/dismiss it
  (needs control:textView:doCommandBySelector: → cancelOperation: on
  RelayBrowserFieldTarget).
- **SSH Config smart group is startup-snapshot + manual refresh**, not live.
  Cheapest: re-parse on applicationDidBecomeActive or stat mtime; proper:
  FSEvents watcher (arrives with M3 edit-in-editor anyway).
- **Unwired Settings**: `date_format`, `monospace_lists`, `confirm_delete`
  persist but have no consumers yet.
- **Toolbar 'View' item** from the UX sketch (density popup) is absent;
  functionality lives in the View menu.
- **Real multi-window / native NSWindow tabs** (Cmd+N currently retitled
  "Show Main Window").
- **Outgoing Finder drags via NSFilePromiseProvider**: verify/complete
  (incoming drops and pane-to-pane drags work).

## Hygiene / hardening

- **Quit path vs attached sheets**: [NSApp terminate:] is silently swallowed
  while an NSAlert sheet is attached (verified live). Dismiss attached
  sheets in applicationShouldTerminate before tearing down.
- **Menu validation**: autoenablesItems is ON; callback items are always
  enabled. Add validateMenuItem: to RelayMenuTarget when per-item enable
  logic is needed.
- **EventQueue OOM policy**: post() can return OutOfMemory; call sites need
  an explicit drop-vs-crash decision on the event path.
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

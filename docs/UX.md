# Relay — UX Specification

Design benchmark: Transmit's polish + ForkLift's keyboard power. Native
AppKit and GTK 4 frontends are dark-mode-native and keyboard-first.
Anti-patterns we exist to avoid:
popup-only transfer activity (Transmit 5), modal enumeration of big
directories (Cyberduck), GUI-inaccessible config + plaintext secrets
(FileZilla).

## Window layout (one window class, native NSWindow tabs later)

```
┌──────────────────────────────────────────────────────────────────────┐
│ NSToolbar: ◀ ▶ | Connect | View | … | Transfers | Info               │
│┌─────────┬───────────────────────────┬──────────────────────────────┐│
││ SIDEBAR │ LOCAL PANE                │ REMOTE PANE                  ││
││ Servers │ path bar                  │ path bar                     ││
││ SSH Cfg │ Name    Size    Modified  │ Name   Size  Mode  Modified  ││
││ History │ …virtualized table…       │ …virtualized table…          ││
││         │ status: 1,204 items       │ status: 98,412 items · 12ms  ││
│├─────────┴───────────────────────────┴──────────────────────────────┤│
││ ⏍ TRANSFERS │ Failed (2) │ Transcript      ⏸ all  ⟳ retry  2.4MB/s ││
││ ▸ per-item rows: name, progress bar, rate, ETA                     ││
│└─────────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

- Root: `NSSplitView` (sidebar | content); content = vertical split
  (panes | bottom panel); panes = horizontal split (two browser panes).
  Every split has an autosave name.
- Sidebar: source-list `NSOutlineView`. Sections: **Servers** (saved sites,
  Return/double-click connects in active pane), **SSH Config** (read-only
  smart group parsed live from ~/.ssh/config — zero setup), **History**.
- Dual pane is default; either pane can host local or remote. Cmd+Opt+←/→
  (and Tab between file lists) switches pane focus.
- Bottom panel: segmented **Transfers · Failed · Transcript**; `Cmd+J`
  toggles; auto-expands once when the first transfer starts; NEVER a popup.
- Inspector (`Cmd+I`, M2: simple panel): selection info + permissions
  editor (octal field + rwx checkboxes, Apply via chmod).

## File list (the core surface)

- View-based `NSTableView`, fixed rowHeight, `usesAutomaticRowHeights=false`,
  custom-DRAWN cells (no per-row subview stacks) per docs/spikes/ui.md.
- Columns: Name (icon+text, custom cell), Size (right-aligned, monospaced
  digits, "—" for dirs), Modified (ISO 8601 `2026-06-11 14:03`), and for
  remote panes Permissions (octal). Sortable headers; dirs-first option on.
- Data source = DirSnapshot + sort/filter permutation from relay_core —
  the UI never copies entries. Streaming listings: listing_batch events
  append + re-sort coalesced per frame; first rows visible immediately;
  status bar counts up ("Listing… 12,400").
- Type-to-select; `Cmd+F` reveals a filter field (live-narrows the
  permutation; Esc clears); `Cmd+Shift+.` toggles hidden files.
- Return = rename (Finder parity; M2 may stub rename-inline as a sheet),
  `Cmd+↓`/double-click = open (descend dir / download+open file later).
- Density modes (View menu): Comfortable 28pt / Compact 22pt / Dense 18pt.
- Linux uses `GtkColumnView` with multi-selection, sortable headers,
  streaming snapshots, filter/hidden controls, active-pane styling, and
  Control-based accelerators exposed in the primary menu.

## Status & feel (policy, enforced)

- NEVER block the main thread on protocol work; everything arrives as
  CoreEvents through the bridge drain.
- No modal progress, no skeletons: connect shows a status chip in the path
  bar; listings stream in; cached snapshot (if any) shows instantly.
- Optimistic UI for rename/delete/mkdir/chmod: apply to the visible list
  with a pending treatment (60% opacity), roll back + inline error toast
  (NSAlert sheet in M2) on refusal.
- Status bar per pane: item count, selection summary, and for remote panes
  the connection chip + last round-trip ms ("latency honesty").
- Semantic NSColors ONLY (labelColor, controlAccentColor, …) — zero
  hard-coded colors; dark mode must be automatic.

## Transfer panel

- Queue table rows: filename, direction arrow, per-file progress bar
  (custom-drawn flat rect — NOT one NSProgressIndicator per row), rate,
  ETA; folder items aggregate. Actions: pause/resume (Space), remove
  (Delete), Pause All / Resume All / Retry Failed / Clear Completed.
- Failed tab: verbatim server error per item (from Diagnostics), one-click
  "Requeue All".
- Aggregate strip in the panel header: total progress, current rate.

## M2 keyboard map (subset; full map in the plan)

| Shortcut | Action |
|---|---|
| Cmd+K | Connect to Server… (URL `sftp://user@host:port/path` or ssh alias) |
| Cmd+Shift+K | Disconnect active pane |
| Cmd+N / Cmd+W | New window / close window |
| Cmd+[ / Cmd+] / Cmd+↑ | Back / forward / enclosing folder |
| Cmd+↓ | Open selection |
| Cmd+Shift+G | Go to Path… |
| Cmd+R | Refresh listing |
| Cmd+F | Filter listing |
| Cmd+Shift+. | Toggle hidden files |
| Cmd+Return | Transfer selection to other pane |
| Cmd+Backspace | Delete (confirm sheet) |
| Cmd+Shift+N | New folder |
| Cmd+I / Cmd+J / Cmd+Opt+S | Inspector / transfer panel / sidebar |
| Cmd+, | Settings |
| Cmd+. | Cancel active listing / selected transfers |
| Space / Delete (queue focused) | Pause-resume / remove queue item |

On Linux, replace Command with Control. Additional Linux shortcuts include
Ctrl+Shift+P for the command palette, Ctrl+P for path mode, Ctrl+Alt+T for
Open in Terminal, Ctrl+E for external editing, Ctrl+Y for preview,
Ctrl+Shift+B for synchronized browsing, and Ctrl+Shift+D for pane comparison.

Menu bar: App · File · Edit · View · Go · Server · Transfers · Window ·
Help — every action above lives in a menu with its shortcut visible.

## Conventions (law, from docs/spikes/ui.md)

- ALL selector strings live in the relay_mac wrapper layer; feature code
  never calls msgSend with raw strings.
- Runtime-defined classes use the cached-Ivar state-pointer convention.
- BOOL is i8 at the ABI (`!= 0` to read, 0/1 to write); NSInteger is i64.
- objc.AutoreleasePool around every callback body and worker iteration;
  value-returning callbacks use the retain/pop/autorelease dance.
- UI state mutates ONLY on the main thread; the bridge drain applies event
  batches run-to-completion.

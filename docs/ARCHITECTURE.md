# Relay — Architecture

Native FTP/FTPS/SFTP client in Zig 0.16. The AppKit frontend targets macOS
15+ on aarch64; a GTK4 frontend targets Linux.

## Four architectural laws

1. **Streams, not sockets.** Every protocol layer codes against
   `*std.Io.Reader` / `*std.Io.Writer`. TLS is stream-stacking; the whole FTP
   engine unit-tests against in-memory pipes (`test/mock/duplex.zig`).
2. **`relay_core` never imports ObjC** and stays Linux-buildable. Protocol
   integration tests run against real Docker servers on Linux CI; the macOS
   runner only builds, unit-tests, bundles, and signs.
3. **The core↔UI boundary is centralized at the bridge layer.** CoreEvent
   (`src/core/events.zig`) stays a native Zig union — ergonomic for both
   pure-Zig native frontends. AppCore and the typed listener conversion live
   in `src/ui/bridge.zig`; no toolkit reaches around that boundary.
4. **`relay_ui` imports `relay_core` only, never a toolkit.** Platform
   bindings and view layers import `relay_ui`; `relay_ui` never imports them.
   Shared app logic therefore builds and tests on both macOS and Linux.

## Layers

```
app_gtk (Linux exe)      process assembly: XDG/GLib/Secret Service injection,
                         SiteStore + factories lifetime, relay_gtk launch
app (macOS exe)          main.zig window assembly + M3 integration (state
                         restoration, Quick Look temp-cache flow, palette/
                         edit/terminal glue) · app_delegate · controllers/
                         (browser+vim, sites+
                         importers, transfers+transcript+bandwidth,
                         prefs+commands+menus, inspector, palette,
                         edit_sessions, terminal) · --smoke driver
relay_mac (module)       zig-objc AppKit wrappers: window/table/outline/
                         menu/toolbar/split_view/panels/drag · libdispatch
                         glue · foundation+runtime kits · fsevents ·
                         quicklook · notifications · app_nap (all selector
                         strings live here)
relay_gtk (module)       GTK4 4.18.6 bindings · GLib MainLoop · XDG Paths ·
                         libsecret CredStore · GTK application/header bar ·
                         dual local panes with async AppCore listings
── shared app layer ──
relay_ui (module)        toolkit-free app logic shared by both frontends;
                         AppCore bridge · connect factories · fuzzy/frecency ·
                         preview cache · vim · sites/import/history · terminal
                         builders · transcript/palette/inspector/edit models;
                         imports relay_core only
── core boundary ──
relay_core (module)      vfs · pool · queue · cred · settings · transcript
                         proto/ftp (first-party) · proto/sftp (libssh2,
                         + jump-host/ProxyCommand transports)
                         proto/ssh (pure-Zig agent/keys/known_hosts/config)
                         tls (TlsProvider → LibreSSL)
vendored C (static)      LibreSSL 4.0 (crypto/ssl), libssh2 1.11.1
```

The extraction is complete: `src/ui/bridge.zig` is the only core↔UI crossing.
Its `Paths` and `MainLoop` dependencies are injected vtables, implemented by
libdispatch/Foundation on macOS and GLib/XDG on Linux.

## M3 integration seams (who owns what)

- **CommandRegistry (prefs.zig)** is the single command vocabulary: every
  menu leaf, key equivalent, palette row, and context-menu item dispatches
  through it. The palette enumerates the menu tree itself, so new commands
  surface there for free.
- **main.zig-injected hooks on the browser**: selection (inspector feed),
  visit (palette frecency), Space (Quick Look), context menu. Browser owns
  pane truth; integrations read it through these seams only.
- **Edit sessions** (controllers/edit_sessions.zig): queue download →
  FSEvents watch (relay_mac.fsevents, main-queue callbacks; App Nap held
  off while watching) → save → remote re-stat → conflict sheet or upload.
  Ended (watchers stopped, temp dirs deleted) in onWillTerminate BEFORE
  AppCore.shutdown().
- **Session restoration**: ui.zon carries per-pane (site, path), focused
  pane, panel collapse states, vim pref. Saved on quit; restored on launch.
  Local pane restores silently (statted first); remote panes reconnect only
  when provably prompt-free (SSH agent meta, or the secret already loads
  from the Keychain). Nothing at launch may prompt.
- **Quick Look**: local selections preview in place; remote files download
  once into the content-addressed TempCache (site/path/size/mtime key) and
  preview from there.

## Threading

- The native toolkit owns the main thread: AppKit starts `[NSApp run]`; GTK
  runs `GApplication`. Both inject the same `relay_ui.MainLoop` contract.
- One `std.Io.Threaded` pool for all core work (`io.async`, per-site `Io.Group`).
- Core→UI: MPSC double-buffered event queue; at most one injected-main-loop
  post per turn (`dispatch_async` or `g_main_context_invoke`), coalesced;
  events apply run-to-completion.
- Cancellation: `Future.cancel` + atomic `CancelToken` checked on ≤100 ms poll
  wakeups inside LibreSSL/libssh2 loops + protocol courtesy (`ABOR`, clean
  SFTP close).

## Memory

- `init.gpa` for long-lived state; arena-per-`DirSnapshot` for listings
  (immutable, refcounted; sort/filter are index permutations; a 100k-entry
  listing frees as one arena destroy).
- Per-connection command arenas, `reset(.retain_capacity)` after each command.
- Fixed stream buffers (4 KiB control / 256 KiB data); pooled transfer slabs.

## Key protocol decisions

- FTPS **requires** TLS session reuse on data connections
  (`SSL_get1_session`/`SSL_set_session`); `std.crypto.tls` cannot do this —
  hence vendored LibreSSL behind a first-party `TlsProvider` interface.
  FTPS pinned to TLS 1.2 by default (LibreSSL lacks TLS 1.3 resumption).
- libssh2 is compiled from upstream source in our `build.zig` against the
  LibreSSL artifacts (the allyourcodebase wrapper links *system* ssl/crypto,
  which is booby-trapped on macOS).
- ssh-agent, openssh-key-v1, known_hosts, and `~/.ssh/config` parsing are
  first-party pure Zig (`std.crypto.bcrypt.opensshKdf` for encrypted keys).

The full approved plan (features, UX spec, milestones, risk register) lives in
the project planning docs; this file tracks what is actually built.

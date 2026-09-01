# Relay

A native FTP / FTPS / SFTP client written in Zig — Transmit-level polish with
ForkLift-level keyboard power, for programmers who dislike FileZilla. The
existing frontend is native AppKit on macOS. The Linux port now has a native
GTK4 executable with two AppCore-driven local panes; remote sites and the M3
power-feature views are the next parity slices.

**Status: M3 complete (power features).** The M1 protocol core (FTP/FTPS/
SFTP engines, SSH userland, VFS, pool, queue; the live Docker integration
matrix) drives a pure-Zig AppKit app: dual-pane browser, sites sidebar
(saved sites · ~/.ssh/config · history), transfer panel with Failed/
Transcript tabs + per-direction bandwidth limits, inspector, settings
window, full menu bar + keyboard map per docs/UX.md. Production connect
factories (`src/ui/factories.zig`) wire real FTP/FTPS/SFTP connects:
known_hosts verification with a host-key sheet, agent/key-file/password
auth, Keychain-backed password prompts with retry, and SSH proxy jumps.

M3 adds the power layer: a fuzzy command palette with frecency ranking
(Cmd+Shift+P commands / Cmd+P paths), edit-in-external-editor with FSEvents
save detection and remote-mtime conflict resolution (Cmd+E), Quick Look
(Space / Cmd+Y; remote files through a content-addressed preview cache),
terminal interop (Open in Terminal Cmd+Opt+T + Copy as scp/rsync/SFTP-URL/
curl), FileZilla/Cyberduck importers, synchronized browsing, directory
comparison, an opt-in vim keymap layer, transfer notifications, and session
restoration on launch (per-pane site+path and panel states from ui.zon;
remote reconnects only when prompt-free via agent or Keychain auth).

`zig build run -- --smoke` runs a scripted end-to-end self test (50-file
local transfer through the real GUI path, plus palette/temp-cache/edit-
session round trips); `--smoke-sftp` does the same against a dockerized
OpenSSH server.

## Building

Requires Zig 0.16.0. The AppKit frontend requires macOS 15+ (Apple Silicon).
The Linux frontend requires GTK4 and libsecret. Its pinned Debian build box
contains both architectures and is the reproducible path for local builds:

```sh
zig build            # Relay.app into zig-out/
zig build test       # unit tests (core everywhere, mac module on macOS)
zig build spikes     # build the M0 spike executables
zig build spike-ssh  # run the libssh2 + static LibreSSL link spike
zig build spike-ui   # run the zig-objc NSTableView spike (the M0 gate)

# Linux, from the repository root (build the image once):
docker build -t relay-linux-build docker/linux-build
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh
```

That produces `zig-out/linux-arm64/bin/relay` and
`zig-out/linux-amd64/bin/relay`. See `docs/LINUX-PORT.md` for current parity
and `docker/linux-build/README.md` for the cross-linking constraints.

## Architecture

- `src/core/` — `relay_core`: FTP/FTPS/SFTP engines, transfer queue, VFS,
  credentials. Pure Zig + vendored C (LibreSSL, libssh2). No ObjC; portable.
- `src/ui/` — `relay_ui`: platform-neutral app logic shared by both frontends.
- `src/macos/` — `relay_mac`: AppKit via [zig-objc], dispatch/CF/Security glue.
- `src/app/` — the macOS Relay executable: NSApplication run loop, views.
- `src/gtk/` — `relay_gtk`: GTK4/GLib wrappers, XDG paths, Secret Service,
  and the current dual-pane Linux window.
- `src/app_gtk/` — Linux process assembly; injects platform services into
  `relay_ui` and starts `relay_gtk`.

See `docs/ARCHITECTURE.md` for the design, and the full plan in the project
planning documents.

[zig-objc]: https://github.com/mitchellh/zig-objc

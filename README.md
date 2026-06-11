# Relay

A native macOS FTP / FTPS / SFTP client written in Zig — Transmit-level polish
with ForkLift-level keyboard power, for programmers who dislike FileZilla.

**Status: M3 complete (power features).** The M1 protocol core (FTP/FTPS/
SFTP engines, SSH userland, VFS, pool, queue; the live Docker integration
matrix) drives a pure-Zig AppKit app: dual-pane browser, sites sidebar
(saved sites · ~/.ssh/config · history), transfer panel with Failed/
Transcript tabs + per-direction bandwidth limits, inspector, settings
window, full menu bar + keyboard map per docs/UX.md. Production connect
factories (src/app/factories.zig) wire real FTP/FTPS/SFTP connects:
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

Requires Zig 0.16.0 and macOS 15+ (Apple Silicon). The protocol core
(`relay_core`) also builds and tests on Linux.

```sh
zig build            # Relay.app into zig-out/
zig build test       # unit tests (core everywhere, mac module on macOS)
zig build spikes     # build the M0 spike executables
zig build spike-ssh  # run the libssh2 + static LibreSSL link spike
zig build spike-ui   # run the zig-objc NSTableView spike (the M0 gate)
```

## Architecture

- `src/core/` — `relay_core`: FTP/FTPS/SFTP engines, transfer queue, VFS,
  credentials. Pure Zig + vendored C (LibreSSL, libssh2). No ObjC; portable.
- `src/macos/` — `relay_mac`: AppKit via [zig-objc], dispatch/CF/Security glue.
- `src/app/` — the Relay executable: NSApplication run loop, controllers.

See `docs/ARCHITECTURE.md` for the design, and the full plan in the project
planning documents.

[zig-objc]: https://github.com/mitchellh/zig-objc

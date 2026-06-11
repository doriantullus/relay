# Relay

A native macOS FTP / FTPS / SFTP client written in Zig — Transmit-level polish
with ForkLift-level keyboard power, for programmers who dislike FileZilla.

**Status: M2 complete (native GUI shell).** The M1 protocol core (FTP/FTPS/
SFTP engines, SSH userland, VFS, pool, queue; 321 unit tests + the live
Docker integration matrix) now drives a pure-Zig AppKit app: dual-pane
browser, sites sidebar (saved sites · ~/.ssh/config · history), transfer
panel with Failed/Transcript tabs, inspector, settings window, full menu
bar + keyboard map per docs/UX.md. Production connect factories
(src/app/factories.zig) wire real FTP/FTPS/SFTP connects: known_hosts
verification with a host-key sheet, agent/key-file/password auth, and
Keychain-backed password prompts with retry. `zig build run -- --smoke`
runs a scripted end-to-end self test (50-file local transfer through the
real GUI path); `--smoke-sftp` does the same against a dockerized OpenSSH
server.

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

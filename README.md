# Relay

A native macOS FTP / FTPS / SFTP client written in Zig — Transmit-level polish
with ForkLift-level keyboard power, for programmers who dislike FileZilla.

**Status: M1 complete (headless protocol core).** FTP/FTPS/SFTP engines,
SSH userland (agent/keys/known_hosts/ssh_config), VFS, connection pool, and
transfer queue are implemented and tested (321 unit tests + a 50-case live
Docker integration matrix incl. FTPS TLS session reuse against vsftpd
`require_ssl_reuse=YES`). No GUI yet — that's M2.

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

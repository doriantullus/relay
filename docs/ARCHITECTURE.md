# Relay — Architecture

Native macOS FTP/FTPS/SFTP client in Zig 0.16. Target: macOS 15+, aarch64.

## Three architectural laws

1. **Streams, not sockets.** Every protocol layer codes against
   `*std.Io.Reader` / `*std.Io.Writer`. TLS is stream-stacking; the whole FTP
   engine unit-tests against in-memory pipes (`test/mock/duplex.zig`).
2. **`relay_core` never imports ObjC** and stays Linux-buildable. Protocol
   integration tests run against real Docker servers on Linux CI; the macOS
   runner only builds, unit-tests, bundles, and signs.
3. **The core↔UI boundary is C-ABI-clean at the bridge layer.** CoreEvent
   (src/core/events.zig) stays a native Zig union — ergonomic for the
   pure-Zig UI we chose. The extern-struct conversion lives in one place:
   the app's bridge (M2's `src/app/bridge.zig`, later `capi.zig` if the
   Ghostty-style Swift-shell pivot or CLI companion ever needs it). No
   other file may assume either representation crosses the boundary.

## Layers

```
app (exe, main thread)   NSApplication run loop, controllers,
                         zig-objc delegate classes
relay_mac (module)       zig-objc AppKit wrappers, dispatch/CF/Security,
                         FSEvents, QuickLook, drag & drop
── UI bridge: C-ABI-clean event/command boundary ──
relay_core (module)      vfs · pool · queue · cred · settings · transcript
                         proto/ftp (first-party) · proto/sftp (libssh2)
                         proto/ssh (pure-Zig agent/keys/known_hosts/config)
                         tls (TlsProvider → LibreSSL)
vendored C (static)      LibreSSL 4.0 (crypto/ssl), libssh2 1.11.1
```

## Threading

- AppKit owns the main thread; Zig `main()` runs there and starts `[NSApp run]`.
- One `std.Io.Threaded` pool for all core work (`io.async`, per-site `Io.Group`).
- Core→UI: MPSC double-buffered event queue; at most one
  `dispatch_async(main_queue)` drain per runloop turn (coalescing); events
  applied run-to-completion.
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

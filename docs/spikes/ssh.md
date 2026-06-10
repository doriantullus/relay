# M0 Spike 1 — libssh2 + LibreSSL SSH-2 handshake from Zig

Status: **passed** (2026-06-10, Zig 0.16.0, macOS 15 / Apple Silicon).

## What was proven

1. The vendored stack (libssh2 1.11.1 compiled from upstream source against
   static LibreSSL 4.0.0) performs a **real SSH-2 handshake** end to end from
   Zig — banner exchange, KEX, host key — against a live server (github.com).
2. The TCP connection is established with **Zig 0.16 `std.Io` networking**
   (`std.Io.Threaded`), not raw `std.posix`, and the socket fd extracted from
   the `std.Io.net.Stream` is handed to blocking libssh2. This is exactly the
   seam M1 needs: Zig owns connect/DNS, libssh2 owns the wire protocol.
3. The binary stays hermetic: `otool -L` shows only `/usr/lib/libSystem.B.dylib`.
4. Clean shutdown: `libssh2_session_disconnect_ex` + `libssh2_session_free`,
   exit code 0.

## Actual output

`zig build spike-ssh` (no local sshd on 127.0.0.1:22, automatic fallback):

```
libssh2:  1.11.1_DEV
crypto:   LibreSSL 4.0.0
libssh2_init: ok
dial 127.0.0.1:22 ...
127.0.0.1:22 not listening (ConnectionRefused); falling back to github.com
dial github.com:22 (dns) ...
connected, stream fd: 5
handshake: ok (568 ms)
kex     : curve25519-sha256
hostkey : ecdsa-sha2-nistp256
crypt_cs: chacha20-poly1305@openssh.com
mac_cs  : hmac-sha2-256
fingerprint: SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM
disconnect: ok
```

The fingerprint is an exact match for GitHub's published ECDSA host key
(`SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM`), so the digest + the
OpenSSH-style base64 formatting are both verified against ground truth.

Also exercised:

- `zig build spike-ssh -- --host github.com --port 22` → same result, 438 ms,
  exit 0 (explicit-arg + DNS path).
- `zig build spike-ssh -- --host 4.225.11.194` → same result, 447 ms, exit 0
  (IP-literal path: `IpAddress.resolve` + `connect`, no DNS machinery; note
  fd was 3 here vs 5 on the DNS path — the resolver briefly opens fds first).

Hermeticity re-check on the built spike:

```
$ otool -L .zig-cache/o/91ad8afa.../spike-ssh
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1356.0.0)
```

`zig build`, `zig build test`, `zig build spikes` all remain green.

## Stream → fd extraction (the M1-critical finding)

It is trivial and fully public — no workaround needed:

```zig
const stream: std.Io.net.Stream = try addr.connect(io, .{ .mode = .stream });
const fd: c.libssh2_socket_t = stream.socket.handle;
```

- `std.Io.net.Stream` is `struct { socket: Socket }`.
- `Socket.handle` is `pub` and typed `std.posix.fd_t` (`c_int` on macOS),
  which is exactly `libssh2_socket_t` on POSIX. They coerce with no cast.
- `std.Io.Threaded`'s `netConnectIp` creates the socket **blocking** (only
  `SOCK.CLOEXEC` is set, see `openSocketPosix` in `std/Io/Threaded.zig`), so
  it is safe to use with `libssh2_session_set_blocking(session, 1)`. If we
  later move to a non-blocking libssh2 loop, we set `O_NONBLOCK` ourselves.

Connect paths used:

- IP literal: `Io.net.IpAddress.resolve(io, text, port)` then
  `addr.connect(io, .{ .mode = .stream })`.
- Hostname: `Io.net.HostName.init(text)` then
  `name.connect(io, port, .{ .mode = .stream })`, which runs
  lookup + happy-eyeballs over all resolved addresses internally.

Caveats that matter for M1:

- `HostName.connect` uses `io.async` internally, so the `Threaded` instance
  must be initialized with a real allocator (`Allocator.failing` would break
  DNS connects). The spike uses `std.heap.c_allocator` (we link libc anyway).
- `IpAddress.ConnectOptions.timeout` is **not implemented** in `Threaded` on
  POSIX yet: `if (options.timeout != .none) @panic("TODO ...")`. Connect
  timeouts for M1 have to be built another way (e.g. cancellation via
  `io.async` + deadline, or our own non-blocking connect).
- Zig 0.16 main-entry idiom: `pub fn main(init: std.process.Init.Minimal) !void`
  gives allocation-free argv (`init.args.iterate()`); we instantiate
  `std.Io.Threaded` ourselves in main and pass `threaded.io()` down.

## libssh2 / LibreSSL / translate-c quirks hit

- **`libssh2_version()` reports `1.11.1_DEV`.** The GitHub
  `archive/refs/tags/libssh2-1.11.1.tar.gz` tarball is the raw git tree; the
  `_DEV` suffix is only stripped by upstream's release script. Cosmetic, but
  don't string-compare the version exactly.
- **`OpenSSL_version(OPENSSL_VERSION)` returns `LibreSSL 4.0.0`** — LibreSSL
  implements the OpenSSL version API and the constant translates fine.
- **Translate-c handled everything needed**: `LIBSSH2_METHOD_*`,
  `LIBSSH2_HOSTKEY_HASH_SHA256` (= 3), `SSH_DISCONNECT_BY_APPLICATION` all
  come through as `c_int` constants. The function-like macros
  `libssh2_session_init()` / `libssh2_session_disconnect()` are emitted as
  `pub inline fn`s and are callable, but the spike calls the `_ex` forms
  directly (`libssh2_session_init_ex(null, null, null, null)`) to avoid
  depending on macro translation. No missing constants encountered.
- **`libssh2_hostkey_hash` returns raw bytes**, not a C string: 32 bytes for
  SHA256. OpenSSH formatting is `"SHA256:" ++ base64-no-pad(digest)` →
  `std.base64.standard_no_pad.Encoder` (43 chars output).
- **`mac_cs` reports `hmac-sha2-256` even though the cipher is
  `chacha20-poly1305@openssh.com`** (an AEAD with an implicit MAC). libssh2
  still negotiates and reports a MAC name; it just isn't used on the wire.
  Display code shouldn't infer "MAC in use" from this field alone.
- **`std.Io.Clock` has no `.monotonic`** — the members are `awake`
  (macOS `CLOCK_UPTIME_RAW`) and `boot` (macOS `CLOCK_MONOTONIC_RAW`); the
  spike times the handshake with `.awake` via
  `Io.Clock.Timestamp.now(io, .awake)` / `durationTo`.

## Not yet covered (later milestones)

- Authentication, channels, SFTP (M1).
- Known-hosts verification — we only print the fingerprint here.
- Non-blocking libssh2 (`LIBSSH2_ERROR_EAGAIN` loop) integration with
  `std.Io`; this spike runs libssh2 in blocking mode on the extracted fd.

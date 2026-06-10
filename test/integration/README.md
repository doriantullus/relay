# Live integration suite

`zig build integration` builds `test/integration/runner.zig` against
`relay_core` and runs the full protocol matrix against real servers in
Docker. The runner owns the compose lifecycle (`down` → `up --build
--wait` → matrix → `down`) and **skips itself with exit 0** when no usable
docker daemon is reachable, so docker-less machines and unit-test CI never
fail because of it.

```
zig build integration                     # the whole matrix
zig build integration -- --only vsftpd    # one server while iterating
zig build integration -- --keep           # leave containers up afterwards
zig build integration -- --no-compose     # reuse already-running servers
```

## Servers and ports

Passive FTP advertises port numbers in-protocol, so container and host
ports are mapped 1:1 on fixed high ports (loopback only):

| service  | image                  | control     | passive       | role |
|----------|------------------------|-------------|---------------|------|
| vsftpd   | `vsftpd/` (Debian)     | 42121       | 42130–42139   | FTPS with `require_ssl_reuse=YES` — the make-or-break interop case |
| pureftpd | `pureftpd/` (Debian)   | 42221       | 42230–42239   | plain FTP **and** AUTH TLS (`-Y 1`) |
| proftpd  | `proftpd/` (Debian)    | 42321       | 42330–42339   | mod_tls; requires data-connection session reuse by default |
| sftp     | `atmoz/sftp:alpine`    | 42422       | —             | OpenSSH, password + ed25519 key auth |

Credentials everywhere: `relay` / `relaypw`. Data directories are tmpfs
mounts — state lives only as long as the containers. The runner provisions
a 5000-file tree (`many/d0..d4`, 1000 files each) per server and installs
a deterministic ed25519 `authorized_keys` line for the SFTP key-auth leg
via `docker compose exec`.

## What the matrix covers

Per FTP server (plain and/or FTPS as applicable): connect/auth + FEAT
caps, MLSD and LIST listings of the 5k tree, 10 MiB upload + download with
byte-exact pattern comparison, REST resume in both directions (the
connection is killed abruptly at 50%, a fresh connection resumes from
`SIZE`), UTF-8 filenames (store/list/rename/delete), mkdir/rename/SITE
CHMOD/delete, and cancel mid-transfer (CancelToken → ABOR → control
connection stays usable).

FTPS only: every data connection resumes the control connection's TLS
session. Against vsftpd (`require_ssl_reuse=YES`) success is positive
proof the resumption path works; a second probe connects with the
`disable_session_reuse` escape hatch ON and asserts the listing **fails**
— proving the suite exercises the real code path rather than a tolerant
server.

SFTP: password and publickey auth, readdir of the 5k tree, 10 MiB upload
with offset resume, pipelined download with throughput printed,
rename/chmod/mkdir/delete, cancel mid-download with a latency bound.

## Server config quirks (workarounds baked into the images)

- **vsftpd's standalone listener SIGSEGVs on TLS session teardown on
  linux/arm64** — reproduced with Debian 3.0.3, Ubuntu 3.0.5 and
  Alpine/musl 3.0.5, with `openssl s_client` as well as Relay, and with
  every config permutation tried (seccomp/isolate off, cipher list, TLS
  version caps). Sessions complete correctly; the parent dies afterwards.
  Workarounds: the entrypoint runs vsftpd under a restart loop, and the
  runner retries refused connections for a few seconds when opening a
  control connection.
- **vsftpd 3.0.3 + OpenSSL 3 segfaults on TLS 1.3 data connections**, and
  the `ssl_tlsv1_1`/`ssl_tlsv1_2` config options are a Red Hat patch that
  Debian/Ubuntu builds reject (silent exit 2). The TLS 1.2 cap is applied
  via `OPENSSL_CONF` (`MaxProtocol = TLSv1.2`) instead.
- **vsftpd refuses to start under Docker's default confinement.** Its
  seccomp sandbox and namespace isolation both fail in unprivileged
  containers: `seccomp_sandbox=NO`, `isolate=NO`, `isolate_network=NO`.
- **vsftpd's default TLS cipher list is `DES-CBC3-SHA`.** Modern stacks
  (including our LibreSSL) refuse 3DES, failing the handshake before
  session reuse is even exercised: `ssl_ciphers=HIGH`.
- **vsftpd refuses writable chroot roots.** The test home is intentionally
  writable: `allow_writeable_chroot=YES`.
- **Debian's pure-ftpd is built with libcap and dies with "Unable to
  switch capabilities"** under Docker's default capability set (silently —
  the message only reaches syslog). No single `cap_add` suffices; the
  compose service gets `cap_add: [ALL]`.
- **ProFTPD advertises `MLST` but never `MLSD` in FEAT** (RFC 3659 says
  MLSD is implied). The engine stays literal, so the suite flips
  `caps.mlsd` on when only MLST is advertised.
- **ProFTPD's mod_tls maps a failed data-connection session-reuse check to
  "425 Unable to build data connection: Operation not permitted"** — the
  EPERM is fabricated (strace shows no failing syscall). Plain curl
  triggers it on TLS 1.3; Relay (TLS 1.2 + reuse) passes.
- **ProFTPD can emit its 426 abort reply after the ABOR drain finished**;
  the cancel test tolerates one stray reply on the next command.
- **PASV advertises an address; the container IP is unroutable from the
  host.** All three FTP servers pin the advertised address to 127.0.0.1
  (`pasv_address` / `-P` / `MasqueradeAddress`). The engine prefers EPSV
  (port-only) when advertised, so this only covers PASV fallbacks.
- **pure-ftpd needs `-l unix`** to authenticate against `/etc/shadow`
  (Debian defaults to PAM, which isn't usable in the slim container).
- **Passive data ports must be published 1:1** (the port number travels
  in-protocol); each server gets a fixed 10-port range.
- **ProFTPD exits with "no valid servers configured"** when the container
  hostname doesn't resolve: `DefaultAddress 0.0.0.0`.
- **ProFTPD refuses REST+STOR by default**: `AllowStoreRestart on`.
- **ProFTPD's mod_tls is a DSO on Debian** (`proftpd-mod-crypto`),
  loaded with `LoadModule mod_tls.c`.
- **tmpfs data mounts erase image-time ownership**, so each FTP image
  re-creates and re-owns `/home/relay` in its entrypoint at start.
- **vsftpd never implemented MLSD** — its matrix leg marks the MLSD test
  SKIP and exercises the LIST parser instead (both parsers run against
  the servers that do advertise MLSD).

## Engine bugs this suite has caught

Both fixed in `proto/ftp/client.zig` (surgical, unit tests unchanged):

- **FTPS download deadlock**: vsftpd (TLS data connections) sends the 226
  completion reply only after the client closes the data connection. The
  engine's RETR path held the data link open while waiting for the final
  reply → both sides waited until vsftpd's 600 s data timeout. Fix: close
  the link on data EOF, then confirm — the order the LIST path always
  used. The same fix took ProFTPD downloads from ~1 MiB/s (trickling
  against the held-open link) to full speed.
- **Cancel/abort deadlock**: the abort path sent ABOR and waited for the
  426/226 pair while the data link was still open; a server blocked
  writing data (client stopped reading) never processes control input —
  vsftpd over TLS hung until its data timeout. Fix: close the data link
  first, then run the ABOR exchange (cut ProFTPD aborts from ~11 s to
  ~0.5 s as well).

## CI

`.github/workflows/ci.yml` runs this suite as a separate
`linux-integration` job on ubuntu-latest (Docker preinstalled there), so
live-server flakes are visible apart from unit-test failures.

A nightly bounded fuzz smoke (`zig build test --fuzz=100K`) is deferred:
zig 0.16.0's bundled fuzz test runner does not compile (upstream
`compiler/test_runner.zig` type error), so fuzz mode cannot run on the
pinned toolchain; see the note in ci.yml.

# Relay

Relay is a native, keyboard-friendly FTP, FTPS, and SFTP client for macOS and
Linux, written in Zig. It combines a polished dual-pane browser with secure
connection management, a persistent transfer queue, and power-user workflows
for navigating and editing local and remote files.

## Features

- **Connections:** saved sites, Quick Connect, `~/.ssh/config` aliases,
  connection history, and reviewed FileZilla/Cyberduck imports.
- **Secure authentication:** system credential storage through Keychain or
  libsecret, SSH agent/key/password and keyboard-interactive authentication,
  `known_hosts` verification, proxy jumps, and configurable TLS handling.
- **Dual-pane browsing:** either pane can show a local or remote location, with
  scalable sortable tables, directories-first ordering, filtering, hidden-file
  controls, multiple selection, configurable density/date/monospace display,
  type-to-select, and back/forward or direct-path navigation.
- **File operations:** upload, download, copy, new folder, rename, permissions,
  confirmed recursive delete, pane-to-pane drag and drop, and desktop file
  import/export with traversal and recursive-target safeguards.
- **Transfer center:** active/queued and failed views, transcript, progress and
  throughput, folder grouping, pause/resume/cancel/retry/remove/reorder actions,
  bulk controls, directional bandwidth limits, conflict handling, queue
  persistence, and completion/failure notifications.
- **Inspection and editing:** single/multi-selection metadata, remote chmod,
  internal text/binary preview, download-and-open, and external editing with
  file watching and remote-modification conflict choices.
- **Power tools:** command and path palettes with persisted frecency, terminal
  launching, copy-as SCP/rsync/SFTP/curl commands, synchronized browsing,
  directory comparison, optional Vim navigation, comprehensive shortcuts, and
  multiple windows.
- **Restoration and preferences:** pane sites and paths, focused pane, panel
  state, prompt-safe remote reconnection, optional queue restoration, and
  portable UI/core settings.
- **Native frontends:** AppKit on macOS and GTK4 on Linux, sharing the portable
  protocol, queue, persistence, and UI-decision layers.

Relay includes headless unit tests, fatal-warning GTK lifecycle smokes, and a
live Docker integration matrix covering FTP, FTPS, and SFTP servers.

## Building

Requires Zig 0.16.0. The AppKit frontend requires macOS 15+ (Apple Silicon).
The Linux frontend requires GTK4 and libsecret; Flatpak is the supported
portable Linux package. The pinned Debian build box contains both architectures
and is the reproducible path for raw local builds:

```sh
zig build            # Relay.app on macOS, relay + desktop resources on Linux
zig build test       # unit tests (core everywhere, mac module on macOS)
zig build spikes     # build diagnostic spike executables
zig build integration # live FTP/FTPS/SFTP servers through Docker

# Linux, from the repository root (build the image once):
docker build -t relay-linux-build docker/linux-build
docker run --rm -v "$PWD:/src" -e ZIG_GLOBAL_CACHE_DIR=/src/zig-pkg-linux \
  relay-linux-build ./docker/linux-build/build-linux.sh
```

That produces `zig-out/linux-arm64/bin/relay` and
`zig-out/linux-amd64/bin/relay`. Every merge to `main` also publishes a
versioned macOS application archive and Linux Flatpak through GitHub Actions.
See `packaging/linux/README.md` for Flatpak details and
`docker/linux-build/README.md` for the raw cross-linking constraints.

## Architecture

- `src/core/` — `relay_core`: FTP/FTPS/SFTP engines, transfer queue, VFS,
  credentials. Pure Zig + vendored C (LibreSSL, libssh2). No ObjC; portable.
- `src/ui/` — `relay_ui`: platform-neutral app logic shared by both frontends.
- `src/macos/` — `relay_mac`: AppKit via [zig-objc], dispatch/CF/Security glue.
- `src/app/` — the macOS Relay executable: NSApplication run loop, views.
- `src/gtk/` — `relay_gtk`: GTK4/GLib wrappers, XDG paths, Secret Service,
  Linux platform services, and the dual-pane Linux window.
- `src/app_gtk/` — Linux process assembly; injects platform services into
  `relay_ui` and starts `relay_gtk`.

See `docs/ARCHITECTURE.md` for the design and `docs/UX.md` for application
behavior and shortcuts.

[zig-objc]: https://github.com/mitchellh/zig-objc

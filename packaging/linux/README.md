# Linux packaging

Flatpak is the supported portable Linux artifact. The manifest targets GNOME
Platform 48 because Relay's generated bindings target GTK 4.18.

Build and install locally:

```sh
flatpak install --user flathub org.gnome.Platform//48 org.gnome.Sdk//48
flatpak-builder --user --install --force-clean build-dir \
  packaging/linux/us.doriantull.relay.yml
flatpak run us.doriantull.relay
```

The sandbox grants network access, the user's home directory for local-pane
browsing and `~/.ssh/config`, Secret Service access, notifications, and
`org.freedesktop.Flatpak` so `flatpak-spawn --host` can launch a configured
terminal without a shell. Relay passes all external-process arguments as an
argv and never interpolates site or path data into a shell command.

Raw dual-architecture binaries remain available through
`docker/linux-build/build-linux.sh`, but inherit Debian trixie's glibc 2.41
floor and are intended for controlled deployments rather than general Linux
distribution.

Every push to `main` runs `.github/workflows/main-artifacts.yml`. It uploads a
ReleaseSafe macOS application bundle, an x86_64 Flatpak bundle, and an Ubuntu
24.04 amd64 `.deb`. Artifact versions use the commit date plus the commit's
zero-based position on main for that date, for example `2026-09-02.0` and
`2026-09-02.1`.

See `../debian/README.md` for the Ubuntu 24.04 package build.

For a release, build the Flatpak in a clean checkout, run the Xvfb smoke test,
export the repository with `flatpak build-export`, and publish a signed update
summary with `flatpak build-update-repo`.

Before publishing, run keyboard-only and screen-reader checks under GNOME and
KDE, with both light and dark themes. CI covers Adwaita light/dark lifecycle
smokes and validates the desktop/AppStream/Flatpak metadata; compositor and
screen-reader behavior remains a release-candidate check on real desktops.

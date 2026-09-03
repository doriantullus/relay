# Debian package

The post-merge artifact workflow builds Relay natively on Ubuntu 24.04 amd64
and publishes an installable `.deb`. Building on the target distribution keeps
the package compatible with Ubuntu 24.04's glibc and GTK versions; the Debian
trixie cross-build image is intentionally not used because its glibc floor is
newer.

Build locally on Ubuntu 24.04 after installing Zig 0.16.0, `libgtk-4-dev`,
`libsecret-1-dev`, and `dpkg-dev`:

```sh
packaging/debian/build-deb.sh 2026-09-03.0
sudo apt install ./zig-out/relay_2026-09-03.0_amd64.deb
```

The script performs a ReleaseSafe install into a temporary package root,
derives runtime dependencies from the linked executable with
`dpkg-shlibdeps`, includes the desktop/AppStream/icon resources installed by
`build.zig`, and creates the package with root ownership metadata.

#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 VERSION [OUTPUT_DIR]" >&2
    exit 2
fi

VERSION="$1"
OUTPUT_DIR="${2:-zig-out}"
ARCH="$(dpkg --print-architecture)"

case "$VERSION" in
    *[!0-9A-Za-z.+:~-]* | "")
        echo "invalid Debian package version: $VERSION" >&2
        exit 2
        ;;
esac

mkdir -p "$OUTPUT_DIR"
PACKAGE_ROOT="$(mktemp -d "$OUTPUT_DIR/relay-deb.XXXXXX")"
trap 'rm -rf "$PACKAGE_ROOT"' EXIT HUP INT TERM

zig build -Doptimize=ReleaseSafe --prefix "$PACKAGE_ROOT/usr"

mkdir -p "$PACKAGE_ROOT/DEBIAN"
mkdir -p "$PACKAGE_ROOT/debian"
cat >"$PACKAGE_ROOT/debian/control" <<EOF
Source: relay
Section: net
Priority: optional
Maintainer: Relay contributors <doriantullus@users.noreply.github.com>
Standards-Version: 4.7.0

Package: relay
Architecture: any
Description: Native FTP, FTPS, and SFTP client
EOF
DEPENDS="$(
    cd "$PACKAGE_ROOT"
    dpkg-shlibdeps -O -eusr/bin/relay |
        sed -n 's/^shlibs:Depends=//p'
)"
rm -rf "$PACKAGE_ROOT/debian"
if [ -z "$DEPENDS" ]; then
    echo "could not determine shared-library dependencies" >&2
    exit 1
fi

INSTALLED_SIZE="$(du -sk "$PACKAGE_ROOT/usr" | awk '{print $1}')"
cat >"$PACKAGE_ROOT/DEBIAN/control" <<EOF
Package: relay
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Relay contributors <doriantullus@users.noreply.github.com>
Installed-Size: $INSTALLED_SIZE
Depends: $DEPENDS
Homepage: https://github.com/doriantullus/relay
Description: Native FTP, FTPS, and SFTP client
 Relay is a keyboard-friendly dual-pane file transfer client for macOS and
 Linux with saved sites, secure credential storage, transfer queues, previews,
 external editing, synchronized browsing, and session restoration.
EOF

OUTPUT="$OUTPUT_DIR/relay_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" "$OUTPUT"
echo "$OUTPUT"

#!/bin/sh
# Generate zig-gobject bindings from THIS container's GIR data, so the
# bindings match the installed GTK exactly (4.18.6 on trixie) rather than
# the upstream pre-generated artifacts, which track the latest two GNOME
# releases (GTK 4.20/4.22) and would be ahead of the runtime.
#
#   docker run --rm -v "$PWD:/src" relay-linux-build ./docker/linux-build/gen-bindings.sh
#
# Output: vendor/zig-gobject-bindings/ — a Zig package exposing gtk4, gdk4,
# gsk4, gio2, gobject2, glib2, pango1, cairo1, graphene1 and friends.
# Consume it from build.zig:
#   const gobject = b.dependency("gobject", .{ .target = target, .optimize = optimize });
#   mod.addImport("gtk", gobject.module("gtk4"));
set -e

VERSION="${ZIG_GOBJECT_VERSION:-v0.3.2}"   # requires Zig 0.16
OUT="${1:-vendor/zig-gobject-bindings}"
WORK=/tmp/zig-gobject

# GIR files are split the same way pkg-config data is: most are
# arch-independent in /usr/share/gir-1.0, but GLib/GObject ship theirs
# per-arch under /usr/lib/<triple>/gir-1.0. BOTH paths are required.
# The two arches' output differs by exactly one unused constant
# (VA_COPY_AS_ARRAY), so generating once from the native arch is fine.
case "$(dpkg --print-architecture)" in
    arm64) GIR_NATIVE=/usr/lib/aarch64-linux-gnu/gir-1.0 ;;
    amd64) GIR_NATIVE=/usr/lib/x86_64-linux-gnu/gir-1.0 ;;
    *)     echo "unsupported build arch: $(dpkg --print-architecture)" >&2; exit 1 ;;
esac

rm -rf "$WORK"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$VERSION" https://github.com/ianprime0509/zig-gobject.git "$WORK"
cd "$WORK"
zig build codegen -Dmodules=Gtk-4.0 \
    -Dgir-files-path=/usr/share/gir-1.0 \
    -Dgir-files-path="$GIR_NATIVE"

cd - >/dev/null
rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
cp -r "$WORK/zig-out/bindings" "$OUT"
cp "$WORK/LICENSE" "$OUT/LICENSE"
echo "=== generated into $OUT ==="
find "$OUT/src" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | tr '\n' ' '; echo
echo "$(find "$OUT/src" -name '*.zig' | wc -l) files, $(find "$OUT/src" -name '*.zig' -exec cat {} + | wc -l) lines"

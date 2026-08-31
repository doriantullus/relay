#!/bin/sh
# Build Relay's Linux artifacts for both architectures from ONE native
# container — no qemu, no second runner. Zig cross-compiles without a
# foreign-arch toolchain, so it needs only the foreign-arch libraries,
# which Debian multiarch installs side by side under /usr/lib/<triple>/.
#
#   docker build -t relay-linux-build docker/linux-build
#   docker run --rm -v "$PWD:/src" relay-linux-build ./docker/linux-build/build-linux.sh
#
# Validated 2026-08-31 on Debian 13.6 (trixie), glibc 2.41, GTK 4.18.6:
# both arches built clean from scratch in 9.6s.
#
# Three non-obvious constraints are encoded below — see README.md:
#  1. PKG_CONFIG_LIBDIR must ALSO carry /usr/share/pkgconfig. It REPLACES
#     the default search path; gtk4.pc/x11.pc are per-arch, but the
#     xproto/kbproto/xextproto/renderproto/bzip2 .pc files are
#     arch-independent and live in /usr/share.
#  2. `pkg-config --libs-only-L gtk4` is EMPTY (Debian ships GTK on the
#     default linker path). `--variable=libdir` is what yields the arch dir,
#     and a cross target will not search the host's /usr/lib without it.
#  3. The glibc floor MUST be pinned to the container's. Zig defaults to
#     2.31; trixie's libvulkan references 2.34/2.38 symbols and ld.lld
#     rejects the mismatch. This makes the base image your minimum
#     supported distro — bump GLIBC with the base image, never alone.
set -e

# Keep in step with the Dockerfile's FROM. `ldd --version` in the image.
GLIBC=2.41

# Which build step to run. Until src/gtk/ exists this is the portable core;
# it becomes the GUI step at plan step 6.
STEP="${1:-install}"

for pair in aarch64:arm64 x86_64:amd64; do
    triple="${pair%%:*}-linux-gnu"
    name="${pair##*:}"
    echo "=== $name ($triple.$GLIBC) ==="
    PKG_CONFIG_LIBDIR="/usr/lib/$triple/pkgconfig:/usr/share/pkgconfig" \
        zig build "$STEP" -Dtarget="$triple.$GLIBC" -p "zig-out/linux-$name"
done

echo "=== done ==="
ls -la zig-out/linux-*/bin/ 2>/dev/null || echo "(no binaries: step '$STEP' installs nothing yet)"

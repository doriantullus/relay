# Relay Linux build box — native on the Docker host, both target arches.
FROM debian:trixie

ARG ZIG_VERSION=0.16.0

# Install both GTK architectures regardless of whether the image is built
# on an amd64 CI runner or an arm64 development machine.
RUN dpkg --add-architecture amd64 \
 && dpkg --add-architecture arm64 \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils pkg-config git xvfb xauth \
      xsltproc \
      libgtk-4-dev:arm64 libgtk-4-dev:amd64 \
      libsecret-1-dev:arm64 libsecret-1-dev:amd64 \
 && rm -rf /var/lib/apt/lists/*

# Zig is the only toolchain. Install the binary matching the container's
# native architecture; that binary cross-compiles both Relay targets.
RUN case "$(dpkg --print-architecture)" in \
      arm64) zig_arch=aarch64 ;; \
      amd64) zig_arch=x86_64 ;; \
      *) echo "unsupported build architecture" >&2; exit 1 ;; \
    esac \
 && curl -sL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt \
 && ln -s "/opt/zig-${zig_arch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

# Per-arch LIB-ONLY search prefixes. Zig appends lib/ and include/ to a
# --search-prefix; Debian's GTK emits no -L from pkg-config, so a cross
# target otherwise links with "searched paths: none".
#
# Deliberately NO include/ symlink. Adding /usr/include here poisons every
# C compilation in the build — the vendored LibreSSL then picks up system
# glibc headers over Zig's bundled libc ("__INT64_C macro redefined",
# "freezero undeclared") and the hermetic core build breaks. The GTK header
# paths already arrive as -I flags from pkg-config, which is where they
# belong: scoped to the module that asked for them.
RUN for pair in aarch64:arm64 x86_64:amd64; do \
        triple="${pair%%:*}-linux-gnu"; name="${pair##*:}"; \
        mkdir -p "/opt/sys-$name"; \
        ln -sfn "/usr/lib/$triple" "/opt/sys-$name/lib"; \
    done

WORKDIR /src

# Relay Linux build box — one native arm64 container, both arches.
FROM debian:trixie

ARG ZIG_VERSION=0.16.0

# amd64 alongside the native arm64: GTK4 dev files for both live under
# /usr/lib/<triple>/, headers are shared in /usr/include.
RUN dpkg --add-architecture amd64 \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils pkg-config git \
      xsltproc \
      libgtk-4-dev:arm64 libgtk-4-dev:amd64 \
 && rm -rf /var/lib/apt/lists/*

# Zig is the only toolchain: it cross-compiles without a foreign-arch gcc.
RUN curl -sL "https://ziglang.org/download/${ZIG_VERSION}/zig-aarch64-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt \
 && ln -s "/opt/zig-aarch64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

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

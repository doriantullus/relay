# Relay Linux build box — one native arm64 container, both arches.
FROM debian:trixie

ARG ZIG_VERSION=0.16.0

# amd64 alongside the native arm64: GTK4 dev files for both live under
# /usr/lib/<triple>/, headers are shared in /usr/include.
RUN dpkg --add-architecture amd64 \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils pkg-config git \
      libgtk-4-dev:arm64 libgtk-4-dev:amd64 \
 && rm -rf /var/lib/apt/lists/*

# Zig is the only toolchain: it cross-compiles without a foreign-arch gcc.
RUN curl -sL "https://ziglang.org/download/${ZIG_VERSION}/zig-aarch64-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt \
 && ln -s "/opt/zig-aarch64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /src

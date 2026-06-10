#!/bin/sh
# /home/relay is a tmpfs mount (fresh per `compose up`), so ownership has
# to be re-established at container start, not image build.
#
# Supervisor loop: every vsftpd build tested on linux/arm64 (Debian 3.0.3,
# Ubuntu 3.0.5, Alpine/musl 3.0.5) SIGSEGVs its standalone listener when a
# TLS session is torn down. Sessions themselves complete correctly, so the
# pragmatic fix is systemd-style restart; the integration runner retries
# refused connections for a few seconds to ride over the gap.
set -e
mkdir -p /home/relay
chown -R relay:relay /home/relay
while true; do
    /usr/sbin/vsftpd /etc/vsftpd.conf || echo "vsftpd exited $? — restarting" >&2
    sleep 0.2
done

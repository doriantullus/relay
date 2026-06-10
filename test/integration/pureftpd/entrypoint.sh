#!/bin/sh
# /home/relay is a tmpfs mount; re-own it at start. Flags:
#   -S ,21        bind 0.0.0.0:21
#   -p 42230:42239 passive range (matches the published host ports 1:1)
#   -E            authenticated users only (no anonymous)
#   -l unix       authenticate against /etc/passwd//etc/shadow
#   -A            chroot everyone to $HOME
#   -Y 1          accept both plaintext FTP and AUTH TLS
#   -P 127.0.0.1  force the PASV-advertised address (the container IP is
#                 unroutable from the host; EPSV does not carry one)
set -e
mkdir -p /home/relay
chown -R relay:relay /home/relay
exec /usr/sbin/pure-ftpd -S ,21 -p 42230:42239 -E -l unix -A -Y 1 -P 127.0.0.1

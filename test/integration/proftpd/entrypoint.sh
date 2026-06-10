#!/bin/sh
# /home/relay is a tmpfs mount; re-own it at start.
set -e
mkdir -p /home/relay
chown -R relay:relay /home/relay
exec /usr/sbin/proftpd --nodaemon -c /etc/proftpd/proftpd.conf

# ProFTPD with mod_tls (explicit FTPS). mod_tls requires TLS session reuse
# on data connections BY DEFAULT since 1.3.3 — a second, independent server
# exercising Relay's session-resumption path.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends proftpd-core proftpd-mod-crypto openssl \
    && rm -rf /var/lib/apt/lists/*

RUN openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=127.0.0.1" \
    -keyout /etc/ssl/private/proftpd.key \
    -out /etc/ssl/certs/proftpd.crt \
    && chmod 600 /etc/ssl/private/proftpd.key

RUN useradd -m -d /home/relay -s /bin/sh relay && echo 'relay:relaypw' | chpasswd

COPY proftpd.conf /etc/proftpd/proftpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21
CMD ["/entrypoint.sh"]

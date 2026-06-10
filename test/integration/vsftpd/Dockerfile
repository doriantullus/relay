# vsftpd with ssl_enable=YES + require_ssl_reuse=YES — the FTPS
# make-or-break configuration Relay exists to interop with. Built from the
# Debian package (the Alpine build historically ships without SSL).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends vsftpd openssl \
    && rm -rf /var/lib/apt/lists/*

RUN openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=127.0.0.1" \
    -keyout /etc/ssl/private/vsftpd.key \
    -out /etc/ssl/certs/vsftpd.crt \
    && chmod 600 /etc/ssl/private/vsftpd.key

RUN useradd -m -d /home/relay -s /bin/sh relay && echo 'relay:relaypw' | chpasswd \
    && mkdir -p /var/run/vsftpd/empty

COPY vsftpd.conf /etc/vsftpd.conf
# vsftpd 3.0.3 + OpenSSL 3 SEGFAULTS on TLS 1.3 data connections and has
# no ssl_tlsv1_3 option to turn it off; cap the library instead. (Relay
# itself always negotiates 1.2 — this guards against other clients.)
COPY openssl-tls12.cnf /etc/vsftpd-openssl.cnf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV OPENSSL_CONF=/etc/vsftpd-openssl.cnf

EXPOSE 21
CMD ["/entrypoint.sh"]

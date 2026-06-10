# pure-ftpd accepting both plain FTP and explicit FTPS (-Y 1). Debian's
# package is built with TLS and reads /etc/ssl/private/pure-ftpd.pem
# (combined key+cert) by default.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends pure-ftpd openssl \
    && rm -rf /var/lib/apt/lists/*

RUN openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=127.0.0.1" \
    -keyout /tmp/key.pem -out /tmp/crt.pem \
    && cat /tmp/key.pem /tmp/crt.pem > /etc/ssl/private/pure-ftpd.pem \
    && chmod 600 /etc/ssl/private/pure-ftpd.pem \
    && rm /tmp/key.pem /tmp/crt.pem

RUN useradd -m -d /home/relay -s /bin/sh relay && echo 'relay:relaypw' | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21
CMD ["/entrypoint.sh"]

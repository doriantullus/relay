#!/bin/sh
# Regenerates the SSH test fixtures in this directory with the system
# ssh-keygen, then records ssh-keygen's own SHA256 fingerprints into
# fingerprints.txt so unit tests can validate our parsers against OpenSSH
# ground truth without invoking ssh-keygen at test time.
#
# Run from anywhere: ./test/fixtures/ssh/gen.sh
# Requires: OpenSSH ssh-keygen (tested with the macOS 15 system one).
set -eu
cd "$(dirname "$0")"

PASS=relay-test

rm -f id_ed25519 id_ed25519.pub \
      id_ed25519_pw id_ed25519_pw.pub \
      id_ed25519_gcm id_ed25519_gcm.pub \
      id_rsa_3072 id_rsa_3072.pub \
      id_ecdsa_p256 id_ecdsa_p256.pub \
      hostkey_a hostkey_a.pub hostkey_b hostkey_b.pub \
      hostkey_rsa hostkey_rsa.pub ca_key ca_key.pub \
      known_hosts known_hosts.old fingerprints.txt

# --- user keys ------------------------------------------------------------
ssh-keygen -q -t ed25519 -N ''      -C relay-test -f id_ed25519
ssh-keygen -q -t ed25519 -N "$PASS" -C relay-test -a 16 -f id_ed25519_pw
ssh-keygen -q -t ed25519 -N "$PASS" -C relay-test -a 8 \
           -Z aes256-gcm@openssh.com -f id_ed25519_gcm
ssh-keygen -q -t rsa -b 3072 -N '' -C relay-test -f id_rsa_3072
ssh-keygen -q -t ecdsa -b 256 -N '' -C relay-test -f id_ecdsa_p256

# --- host keys for known_hosts --------------------------------------------
ssh-keygen -q -t ed25519 -N '' -C hostkey-a   -f hostkey_a
ssh-keygen -q -t ed25519 -N '' -C hostkey-b   -f hostkey_b
ssh-keygen -q -t rsa -b 3072 -N '' -C hostkey-rsa -f hostkey_rsa
ssh-keygen -q -t ed25519 -N '' -C relay-ca    -f ca_key

key_a=$(cut -d' ' -f1-2 hostkey_a.pub)
key_b=$(cut -d' ' -f1-2 hostkey_b.pub)
key_rsa=$(cut -d' ' -f1-2 hostkey_rsa.pub)
key_ca=$(cut -d' ' -f1-2 ca_key.pub)

# known_hosts layout (tests reference these by line number):
#  1: plain host, key A
#  2: comma host list + wildcard pattern, key RSA
#  3: non-default port, key A
#  4: hashed entry for hashed.example.com:22, key A   (hashed below via -H)
#  5: @revoked marker, key B
#  6: @cert-authority wildcard, CA key
#  7: mismatch trap: files.example.com pinned to key A (tests present key B)
cat > known_hosts <<EOF
plain.example.com $key_a
alpha.example.com,beta.example.com,*.wild.example.com $key_rsa
[port.example.com]:2222 $key_a
hashed.example.com $key_a
@revoked revoked.example.com $key_b
@cert-authority *.corp.example.com $key_ca
files.example.com $key_a
EOF

# Hash ONLY line 4: split the file, hash the one line, reassemble.
head -3 known_hosts > known_hosts.head
sed -n '4p' known_hosts > known_hosts.line4
tail -3 known_hosts > known_hosts.tail
mv known_hosts.line4 known_hosts
ssh-keygen -H -f "$PWD/known_hosts" > /dev/null
cat known_hosts.head known_hosts known_hosts.tail > known_hosts.new
mv known_hosts.new known_hosts
rm -f known_hosts.head known_hosts.tail known_hosts.old

# --- ssh-keygen ground truth ----------------------------------------------
# Format: <name> <sha256-fingerprint> (fingerprint as printed by ssh-keygen -lf)
for f in id_ed25519 id_ed25519_pw id_ed25519_gcm id_rsa_3072 id_ecdsa_p256 \
         hostkey_a hostkey_b hostkey_rsa ca_key; do
    fp=$(ssh-keygen -lf "$f.pub" | awk '{print $2}')
    printf '%s %s\n' "$f" "$fp" >> fingerprints.txt
done

echo "fixtures regenerated; fingerprints:"
cat fingerprints.txt

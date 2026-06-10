# SSH test fixtures

Real OpenSSH artifacts consumed by the unit tests of
`src/core/proto/ssh/{keys,known_hosts,ssh_config}.zig`. Everything except
`ssh_config*` and this README is produced by `./gen.sh` (system `ssh-keygen`);
`fingerprints.txt` records `ssh-keygen -lf` SHA256 fingerprints as ground
truth, so tests validate our parsers against OpenSSH itself without invoking
ssh-keygen at test time.

These are throwaway test keys. They are committed on purpose; never use them
for anything real. Passphrase for the encrypted keys: `relay-test`.

| file | what |
| --- | --- |
| `id_ed25519[.pub]` | ed25519, unencrypted, comment `relay-test` |
| `id_ed25519_pw[.pub]` | ed25519, passphrase, aes256-ctr + bcrypt rounds 16 |
| `id_ed25519_gcm[.pub]` | ed25519, passphrase, aes256-gcm@openssh.com + bcrypt rounds 8 |
| `id_rsa_3072[.pub]` | RSA-3072, unencrypted |
| `id_ecdsa_p256[.pub]` | ECDSA P-256, unencrypted |
| `hostkey_a/b`, `hostkey_rsa`, `ca_key` | host/CA keys referenced by `known_hosts` |
| `known_hosts` | plain, list+wildcard, `[host]:port`, hashed (`ssh-keygen -H`), `@revoked`, `@cert-authority`, mismatch trap (line layout documented in `gen.sh`) |
| `ssh_config`, `ssh_config_extra` | hand-written config subset incl. `Include` (values asserted by tests) |
| `fingerprints.txt` | `<name> <SHA256:...>` per key, from `ssh-keygen -lf` |

Regenerating (`./gen.sh`) creates entirely new key material; the tests read
expected fingerprints from `fingerprints.txt`, so they keep passing. The
`known_hosts` *line layout* and the `ssh_config` values are load-bearing.

The mismatch trap: `files.example.com` is pinned to `hostkey_a`; tests present
`hostkey_b` for it and must get the MISMATCH (key changed) result, not
"unknown host".

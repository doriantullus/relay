# Importer fixtures

Consumed by the headless importer tests in `src/app/controllers/sites.zig`
(loaded at runtime by walking up to the repo root, same pattern as the ftp
listing corpus).

- `filezilla_sitemanager.xml` — a FileZilla `File ▸ Export…` shape covering:
  every supported `ServerProtocol` (0 FTP, 1 SFTP, 3 FTPS, 4 FTPES,
  6 insecure FTP), an unsupported one (7, S3), nested `<Folder>` blocks,
  base64 + legacy plaintext + corrupt-base64 `<Pass>`, every Logontype
  branch (0 anonymous, 1 normal, 2 ask, 4 account, 5 key file), XML
  entities, an empty `<Host>` (skipped), default vs. custom ports, and a
  `LocalDir`. The first server deliberately shares its connection identity
  (sftp, web1.example.com, 2222, deploy) with `prod_web.duck` for the
  cross-importer duplicate tests.
- `*.duck` — one Cyberduck bookmark per file (the XML-plist subset
  Cyberduck writes): sftp with `Path` + custom port, ftp with an
  `<integer>` port at the protocol default, ftps with a non-ASCII
  username, and an unsupported `s3` bookmark. Cyberduck keeps secrets in
  its own keychain entries, so `.duck` files never carry passwords.

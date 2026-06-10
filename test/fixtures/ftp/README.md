# FTP listing fixture corpus

Wire-format directory listings consumed by the table-driven tests in
`src/core/proto/ftp/listing_list.zig` and
`src/core/proto/ftp/listing_mlsd.zig`. Files are byte-exact: line
terminators (CRLF vs bare LF) and column padding are part of the test.

Expected `vfs.Entry` values for every line live in the test tables next to
the parsers; the reference timestamp used to resolve year-less Unix dates
is 2026-06-10 00:00:00 UTC (epoch 1781049600).

## Provenance

| file | terminators | provenance |
|---|---|---|
| `unix_vsftpd.txt` | CRLF | vsftpd 3.x built-in `ls` emulation (`ls.c`): numeric uid/gid columns, `%b %d %H:%M` / `%b %d  %Y` dates, symlink arrow. Reconstructed from a vsftpd 3.0.5 session transcript layout. |
| `unix_proftpd.txt` | CRLF | ProFTPD 1.3.x `mod_ls` default `LIST` output: named owner/group, setuid (`rws`) and sticky (`rwt`) permission characters, name containing spaces, relative symlink target. |
| `unix_pureftpd.txt` | bare LF | Pure-FTPd 1.0.x `LIST -a` shape: `.`/`..` entries, numeric owner + named group, single-digit day double-space alignment (`Sep  6  2003`), UTF-8 name with space, leading-dash name. Bare-LF terminators exercise tolerant line splitting (some embedded servers omit CR). |
| `unix_busybox.txt` | bare LF | busybox 1.3x `ls -l` (musl) as used by embedded FTP daemons: `total` header line, character/block device major,minor columns replacing size, FIFO, setgid (`r-s`) bit. |
| `unix_names_edge.txt` | CRLF | Synthetic edge-case battery (Relay project, 2026): double spaces inside names, leading-dash name, UTF-8 (Latin + CJK), symlink whose target contains `" -> "`, owner literally named `May` next to a real `May` date, and a year-rollover time-form date one day in the future of the reference clock. |
| `dos_iis.txt` | CRLF | Microsoft IIS FTP (MSDOS directory style, the IIS default): `MM-DD-YY  HH:MMAM/PM`, `<DIR>` marker column, sizes right-aligned, names with spaces, 2-digit-year pivot cases (`95` -> 1995, `00` -> 2000). |
| `eplf.txt` | CRLF | EPLF examples from D. J. Bernstein's specification page (<https://cr.yp.to/ftp/list/eplf.html>): `+i<id>,m<mtime>,r,s<size>,\tname` lines (`djb.html`, `514`, `514.html`); final line adds the `up<octal-mode>` fact and a name with a space. |
| `mlsd_rfc3659.txt` | CRLF | RFC 3659 section 7.7.3 MLSD example (`/iana/assignments/media-types`), lightly extended with a second file: `cdir`/`pdir` entries, `perm` fact, no `unique` fact. |
| `mlsd_filezilla.txt` | CRLF | FileZilla Server 1.x MLSD shape (server documentation/forum transcripts): `type;modify;size` ordering, fractional-second `modify` values (`.997`), and a mixed-case fact-name variant (fact names are case-insensitive per RFC 3659). |
| `mlsd_proftpd.txt` | CRLF | ProFTPD 1.3.x `mod_facts` MLSD output: alphabetised facts, `unique`, `UNIX.group`/`UNIX.groupname`/`UNIX.mode`/`UNIX.owner`/`UNIX.ownername`/`UNIX.uid` facts, `type=OS.unix=slink:<target>` symlink form, plus a synthetic line with an unknown fact that parsers must tolerate. |

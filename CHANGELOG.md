# Changelog

## 0.5.0

**Added**
- PE triage (`ctf_lens/pe.py`, `analyzers/pe.py`): stdlib-only parser; section entropy/MD5, packer section names, high-entropy code, W+X sections, empty executable sections, entry point anomalies, TLS callbacks, compile-timestamp sanity, overlay with embedded-file detection, Authenticode presence, .NET detection, imports/exports, imphash. Import groups are mapped to ATT&CK ids as hints. Structured data is available as `details.pe` in `--json`.
- IOC extraction (`ctf_lens/ioc.py`): domains, public IPv4, e-mails, registry keys (persistence keys highlighted), PDB paths, suspicious drop paths, Bitcoin addresses with checksum verification, `.onion`, Telegram bot tokens, chat webhooks. New `--iocs` option and `iocs` key in `--json`.

**Fixed**
- The "Re-run with --extract" hint no longer appears when `--extract` was already used.

**Verification**
- The PE parser was compared with `objdump` on real x86/x64 binaries: header fields, section table and per-DLL import lists are identical. Synthetic test files are validated with `objdump` as well.
- IOC false positives were measured on random data: unfiltered domain matching fired on 60/60 random 2 MB files; with the shipped filters 1/200 (and none once high-entropy unknown files are skipped).

**Known limitations**
- See the PE and IOC notes in the README. Searching for flags in very large single-line files is slow (pre-existing; every 9 MB of such text costs several seconds) — planned.

## 0.4.0

**Fixed**
- `example_lsb.png`: the hidden flag was not found. LSB extraction no longer depends on an entropy verdict; layouts are brute-forced instead.
- False `Embedded EXE/GZIP` findings on random and compressed data: carving and type detection now validate structure behind the magic bytes. Text starting with `BM` or `MZ` is no longer classified as BMP/EXE.
- A deliberately corrupted PNG no longer aborts image analysis (PNG/JPEG structure is parsed without Pillow).
- PNG data after `IEND` is reported explicitly instead of as "Corrupted PNG structure".
- PDF: flags inside Flate-compressed streams are found.
- Hex strings are no longer decoded as base64 garbage.
- `.gitignore` started with a BOM.

**Added**
- LSB brute-force (channel subsets, bit planes, row/column order, bit order) and hidden-file detection in LSB.
- PNG CRC verification and recovery of tampered IHDR width/height.
- Multi-layer decoding (`--depth`): base16/32/58/64/85, rot13, atbash, url, html, binary, morse, zlib/gzip/bzip2/lzma.
- Repeating-key XOR and flag-prefix known-plaintext XOR (`--xor`).
- ZIP password guessing with a built-in CTF list and `--wordlist`.
- UTF-16 string extraction; flag-shaped strings with an unknown prefix; a warning when a flag match is glued to a longer prefix.
- CLI: `--json`, `-q`, `--exit-code`, `--flag-format`, `--depth`, `--wordlist`, `--extract`; status and errors on stderr; broken pipes handled.
- CI job that runs the suite with no optional dependencies; tests per feature with false-positive guards.

**Known limitations**
- Flag patterns have no word boundary: `MYCTF{x}` matches as `CTF{x}` (a hint is attached; use `--flag-format`).
- About 25% slower than 0.3.0 on very large random files because of UTF-16 scanning.

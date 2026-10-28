# Changelog

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

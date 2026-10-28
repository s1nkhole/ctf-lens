# ctf-lens

[![CI](https://github.com/s1nkhole/ctf-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/s1nkhole/ctf-lens/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Static analysis tool for CTF challenge files. Drop a file — it finds flags, unwraps layered encodings, carves embedded files, repairs tampered PNG headers, detects steganography, and triages Windows executables (packers, imports, overlay, IOCs). Pure Python, zero mandatory dependencies, never executes the file it analyses.

```text
$ ctf-lens examples/example_polyglot.png
  Type           PNG (image)
  Size           59,608 bytes (58.2 KB)
  🔴 Critical: 3  🟡 Medium: 1  ⚪ Info: 2

🔴 🚩 Flag found!  Flag Pattern
   Source: direct file content
   flag{appended_after_eof_example}

🔴 Data after PNG IEND  File Carving  (offset 0xE8A4)
   52 bytes follow the IEND chunk. Classic polyglot / appended-payload trick.
   💡 Re-run with --extract DIR to save the trailing bytes.

🔴 🚩 Flag found!  Flag Pattern
   Source: LSB [R bit 0, rows, msb-first]
   flag{lsb_steganography_example}
```

One file, two independent hiding techniques, both reported — with the exact offset and the extraction layout, so the finding can be reproduced by hand.

**Why it is useful**

- **Quiet by design.** Embedded-file carving validates structure instead of matching bare magic bytes, so random or compressed data no longer produces phantom `EXE`/`GZIP` hits (covered by regression tests on random input).
- **Finds what entropy tests miss.** LSB extraction is brute-forced across channels, bit planes, scan order and bit order, so a 30-byte message in a noisy channel is still found.
- **Unwraps layers.** `rot13 → base64 → gzip` and similar chains are searched automatically and the winning chain is printed.
- **Robust to damaged files.** PNG/JPEG structure is parsed without Pillow; a tampered IHDR is detected and the original dimensions are recovered from the CRC.
- **Malware triage without a disassembler.** The PE parser (stdlib only, checked against `objdump` on real binaries) reports packer and layout anomalies, import behaviour mapped to ATT&CK ids, overlay payloads and imphash; an IOC extractor with checksum-validated wallets and benign-domain filtering keeps ordinary files quiet.
- **Built for pipelines.** `--json`, `-q`, `--exit-code`, status on stderr, clean stdout.

---

## Quick start

```bash
pip install "ctf-lens[full] @ git+https://github.com/s1nkhole/ctf-lens.git"
ctf-lens challenge.png
ctf-lens challenge.bin --xor --extract out/    # + XOR attacks, save carved files
```

---

## Installation

```bash
# Clone
git clone https://github.com/s1nkhole/ctf-lens.git
cd ctf-lens

# Install with optional dependencies (recommended)
pip install -e ".[full]"

# Or install only what you need
pip install rich          # coloured terminal output
pip install Pillow numpy  # image LSB steganography analysis
```

**Python 3.10+ required. Zero mandatory dependencies — runs on stdlib alone.**

### Backward compatibility

The tool used to ship as a single `ctf_lens.py` monolith. It has since been refactored into a proper package (see [Project structure](#project-structure)), but the old invocation still works via a compatibility shim:

```bash
python ctf_lens.py challenge.png   # still works
ctf-lens challenge.png             # new, after pip install
```

---

## Usage

### Interactive mode

```bash
ctf-lens
```

Launches a keyboard-driven TUI (built with `rich`): ASCII banner, tool description, mode selection. Drag & drop a file into the terminal to set the path — no typing required.

### Direct analysis

```bash
ctf-lens challenge.png          # standard analysis
ctf-lens challenge.png --deep   # extended checks (slower)
ctf-lens challenge.png --xor    # + XOR attacks: single-byte, repeating-key, flag-prefix crib
ctf-lens challenge.png --deep --xor
ctf-lens --version
```

Options for scripting and harder challenges:

| Option | What it does |
|---|---|
| `--flag-format REGEX` | Treat your event's flags as real flags, e.g. `--flag-format 'EVT2026\{[^}]+\}'` |
| `--depth N` | Longest decoding chain to try (`base64 → hex → rot13 → …`), default 4, `0` = off |
| `--extract DIR` | Save carved embedded files, data after EOF and decoded binary layers into `DIR` |
| `--wordlist FILE` | Extra passwords for encrypted ZIPs (a built-in CTF list is always tried first) |
| `--iocs` | Print only indicators of compromise as `type<TAB>value` lines (domains, IPs, e-mails, registry keys, wallets, …) |
| `--json` | Full result as JSON on stdout |
| `-q`, `--quiet` | Print only the flags found, one per line |
| `--exit-code` | Exit with status `10` when a flag was found (otherwise `0`) |

**Exit status:** `0` analysed (or no flag with `--exit-code`) · `10` flag found (only with `--exit-code`) · `1` error (missing file, bad option value) · `2` invalid command line.

**`--json` result** (stable top-level keys): `file`, `size`, `type`, `category`, `md5`, `sha256`, `entropy`, `flags` (deduplicated flag strings), `findings` and `decoded` (lists of `{title, description, severity, data, technique, hint, offset}`), `extracted` (paths written by `--extract`), `iocs` (`{type: [values]}`), `details` (structured per-format data; for PEs `details.pe` has sections, imports, imphash, exports, overlay, …).

Progress messages and errors go to **stderr**, so stdout is always safe to pipe:

```bash
ctf-lens challenge.png --json | jq '.flags'
ctf-lens challenge.png -q --exit-code && echo "no flag" || echo "got one"
for f in dump/*; do ctf-lens "$f" -q; done        # one flag per line across many files
```

### As a Python package

```python
from ctf_lens import analyze, AnalysisResult, Finding

result = analyze("challenge.png")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  {finding.data}")

for decoded in result.decoded:
    print(f"{decoded.title}: {decoded.data}")
```

---

### Windows executable example

Abridged output for a synthetic UPX-style sample (built by `tests/helpers.py`, no real malware is shipped):

```text
[HIGH]   Packer indicator: UPX
[HIGH]   High-entropy code section 'UPX1' (7.89)
[MEDIUM] Executable section 'UPX0' is empty on disk
[MEDIUM] Writable + executable section 'UPX1'
[MEDIUM] TLS callbacks (1)
[MEDIUM] Very few imports (2)
[INFO]   PE EXE: x86-64, PE32+, Windows console
```

A normal program (the setuptools launchers used while testing) produces only `INFO` lines.

---

## How it works

```
file ─► type detection (validated signatures) ─► strings (ASCII + UTF-16)
        │
        ├─► general pass: entropy · flags · multi-layer decode (peel) · base64/hex/rot13 · carving · URLs
        ├─► optional:     --xor  single-byte · repeating-key · flag-prefix crib
        └─► by category:  image · audio · archive · text · executable · network · PDF
                              │
                              ▼
        findings sorted by severity ─► console │ --json │ -q (flags only) │ --extract (files on disk)
```

Flags found by the analyzers are deduplicated through one registry (`registry.py`), so the same flag found via base64, LSB and a ZIP member is reported once, with the first source that found it; the `flags` list in the result merges any that were reported directly. Noisy raw-string matches are filtered by `flag_is_clean()`.

**Safety.** The analysis is static: the package contains no `subprocess`, `eval`/`exec` or network calls, and decompression is capped (256 MB per stream, at most 20 ZIP members inspected, files above the size limit are read only partially). When you open suspicious samples, do it inside a VM anyway.

---

## What it detects

| Category | Techniques |
|---|---|
| **Flags** | 28 CTF platform prefixes: `flag{}`, `HTB{}`, `picoCTF{}`, `THM{}`, `DUCTF{}`, `CSAW{}`, `DEFCON{}` and more, with a garbage-guard (`flag_is_clean`) to filter false positives out of noisy binary strings |
| **Encodings** | Base64, Base32, Base85/Ascii85, Base58, Hex, ROT13, URL-encoding, HTML entities, binary code, Morse code |
| **Decoding chains** | Multi-layer search up to `--depth` steps, e.g. `rot13 → base64 → gzip`; the winning chain is shown in the finding |
| **Ciphers** | Caesar (ROT1–25), Atbash, Vigenère hint (Index of Coincidence), single-byte XOR, repeating-key XOR (key length via Hamming distance), known-plaintext XOR with flag prefixes |
| **Steganography** | LSB brute-force over channel subsets (R/G/B/A, RGB, BGR, …) × bit planes × row/column order × bit order — finds short messages that entropy tests miss; hidden files inside LSB; whitespace stego |
| **Images** | EXIF metadata, PNG chunk tree with CRC verification, **tampered IHDR dimensions recovered via CRC**, data after IEND, tEXt/iTXt/zTXt/non-standard chunks, JPEG markers and comments, data after EOI. PNG/JPEG structure is parsed without Pillow, so deliberately corrupted files still get analysed |
| **Audio** | WAV LSB on samples, non-standard RIFF chunks, MP3 ID3 tags, data after last frame |
| **Archives** | ZIP (comment, file contents, encrypted entries cracked with built-in CTF passwords / `--wordlist`), GZIP, BZIP2 with decompression bomb protection |
| **Executables** | ELF/PE strings and sections, Java CLASS, interesting keywords |
| **Network** | PCAP/PCAPNG flag search, HTTP traffic detection, credential patterns |
| **Windows executables** | PE32/PE32+ parsed without dependencies: sections with entropy and MD5, packer section names (UPX, ASPack, VMProtect, …), high-entropy code, W+X sections, entry point outside the code section, TLS callbacks, forged compile timestamps, overlay (with embedded-file detection), Authenticode presence, .NET detection, imports/exports, imphash. Import groups are mapped to MITRE ATT&CK ids (process injection/hollowing, service installation, downloaders, keylogging, …) as hints, not verdicts |
| **Indicators (IOC)** | Domains, public IPv4, e-mails, registry keys (persistence keys called out), PDB paths, suspicious drop paths, Bitcoin addresses (Base58Check/Bech32 checksum verified), `.onion`, Telegram bot tokens, chat webhooks — from ASCII and UTF-16 strings. Common benign domains are filtered |
| **PDF** | Flate streams are decompressed and searched (including text split by kerning operators), JavaScript, `/Launch`, `/OpenAction`, embedded files |
| **General** | Embedded file carving with structural validation (no false hits on random data), UTF-16 strings, Shannon entropy, URL extraction, flag-shaped strings with unknown prefixes |

---

## Supported formats

| Type | Formats |
|---|---|
| Images | PNG, JPEG, BMP, TIFF, GIF, WEBP |
| Audio | WAV, MP3, FLAC, OGG |
| Archives | ZIP, GZIP, BZIP2, XZ, 7ZIP, RAR |
| Executables | ELF, EXE/DLL, Java .class, Mach-O |
| Documents | PDF, DOC |
| Network | PCAP, PCAPNG |
| Crypto | PEM, DER |
| Database / data | SQLite, HDF5 |
| Text | TXT, any printable file |

---

## Project structure

```
ctf_lens/
├── config.py          — all constants, thresholds, flag prefixes, magic bytes
├── models.py          — Finding, AnalysisResult dataclasses
├── registry.py        — flag registration and deduplication
├── utils.py           — entropy, file type detection, hashing, string extraction, flag_is_clean
├── decoders.py        — Base64, Hex, ROT13, XOR, URL, HTML, binary, Morse
├── peel.py            — multi-layer decoding search (base64 → hex → gzip → …)
├── xorcrack.py        — repeating-key XOR and known-plaintext XOR
├── signatures.py      — structural validation of file signatures, embedded-file end estimation
├── carving.py         — embedded-file carving built on signatures.py
├── extract.py         — --extract: write carved files and decoded layers to disk
├── pe.py              — defensive stdlib PE parser (sections, imports, exports, TLS, overlay)
├── ioc.py             — indicator extraction with validators (checksums, TLD list, benign filter)
├── _lsb_common.py     — shared LSB math (used by image and audio independently)
├── core.py            — main analyze() orchestrator + general analysis
├── output.py          — Rich coloured output and plain-text fallback, __version__
├── tui.py             — interactive terminal UI
├── cli.py             — argparse CLI entry point (ctf-lens command)
└── analyzers/
    ├── image.py       — EXIF, PNG chunks, JPEG DCT
    ├── lsb_image.py   — LSB steganography for images
    ├── audio.py       — WAV, MP3, FLAC + audio LSB
    ├── archive.py     — ZIP, GZIP, BZIP2
    ├── text.py        — Caesar, Atbash, Vigenère, whitespace stego
    ├── binary.py      — ELF, PE
    ├── network.py     — PCAP
    └── pdf.py         — PDF

tests/
├── conftest.py
├── test_registry.py
├── test_decoders.py
├── test_utils.py
├── helpers.py                           — builders for synthetic PNG / PE / PDF / ZipCrypto test files
├── test_examples.py                     — end-to-end checks against examples/
├── test_lsb.py, test_png.py, test_pdf.py, test_peel.py, test_xor.py,
│   test_zip_crack.py, test_carving.py,
│   test_pe.py, test_ioc.py              — one file per feature, incl. false-positive guards and fuzzing
├── test_cli.py                          — JSON / exit codes / --flag-format contract
├── test_project.py                      — version and .gitignore consistency
└── test_flag_consistency_regressions.py — flag_is_clean() ROT13/Atbash edge cases
```

---

## Testing & CI

```bash
pip install -e ".[test]"
pytest -v
```

Every push and pull request against `main` runs the full suite on Python 3.10–3.13, runs it again in a **stdlib-only** environment (no `rich`, `Pillow`, `numpy`) to keep the zero-dependency promise honest, then builds and validates the sdist/wheel with `twine check`. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Examples

The `examples/` folder contains sample files demonstrating different hiding techniques:

| File | Technique |
|---|---|
| `example_text.txt` | Flag directly in file |
| `example_base64.txt` | Flag encoded as Base64 |
| `example_hex.txt` | Flag encoded as hex |
| `example_archive.zip` | Flag inside an archive |
| `example_lsb.png` | Flag in LSB of channel R |
| `example_polyglot.png` | Flag appended after PNG EOF marker |
| `example_chain.txt` | Flag wrapped in two layers: Base64 of hex |

Run against all examples:

```bash
for f in examples/*; do
    echo "=== $f ==="; ctf-lens "$f"
done
```

---

## Limitations

- XOR: single-byte, repeating-key (needs a few hundred bytes of readable plaintext for the statistics) and flag-prefix known-plaintext for short keys. RC4 and other stream ciphers are not supported.
- LSB: tries the common layouts (channel subsets, bit planes 0–1 with `--deep`, row/column order, MSB/LSB-first). Exotic schemes — key-seeded pixel permutations, palette-index (GIF/PNG-P) embedding, steghide — are out of scope.
- Encrypted ZIPs: only ZipCrypto is tested against passwords (stdlib limitation). AES-encrypted archives are reported with a `zip2john` hint. Other archive formats are not cracked.
- Archives are not recursively unpacked — nested ZIPs are detected and reported, not opened. (Decoded layers and carved files can be saved with `--extract` and analysed again.)
- PDF: Flate streams are inflated and searched; other filters (LZW, ASCII85, DCT) and encrypted PDFs are not decoded. For full PDF forensics use `pdf-parser.py` or `peepdf`.
- PE: delay-load imports, resources, the Rich header and Authenticode validation are not parsed; ordinal imports from `ws2_32`/`oleaut32` are hashed as `ordN`, so the imphash can differ from other tools for those; API-group findings are hints (an imported API is not proof of behaviour). The parser was cross-checked against `objdump` on x86 and x64 binaries; ARM64 files parse but had no independent reference.
- IOC: IPv6, Ethereum and Monero addresses are not extracted; domains need a known TLD and a registrable label of 4+ characters (5+ under two-letter country TLDs) because random bytes otherwise produce `rx.ai`-style matches; packed executables can still yield an occasional spurious short domain.
- Flags with an unknown prefix are reported as "flag-shaped strings" (MEDIUM); add `--flag-format` to promote them to real flags.
- FLAC analysis is basic (metadata string scan). PICTURE metadata blocks are not parsed.
- `flag_is_clean()` is applied to noisy raw-string extraction (`core.py`, `audio.py`, `binary.py`, `text.py`, `network.py`, `pdf.py`) but not to structured-field extraction (`archive.py`, `image.py`, `lsb_image.py`), since those pull flags from discrete metadata fields rather than raw string soup.

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest -q
```

Adding an analyzer: write `analyze_<name>(data: bytes, result: AnalysisResult) -> None` in `ctf_lens/analyzers/`, register it for a file category in the dispatcher inside `core.py`, report through `Finding(...)` and `register_flag(...)`. Test files are generated by `tests/helpers.py` at test time, so no binaries are committed; every false-positive fix should come with a test that fails without it.

---

## Roadmap

Planned, not yet implemented:

- PE: resources, delay-load imports, Rich header, Authenticode validation; ELF/Mach-O triage
- Faster flag search on huge single-line files (the current regex scan dominates run time there)
- PCAP parsing: TCP stream reassembly, HTTP objects, DNS exfiltration
- Recursive unpacking of nested archives and carved files
- Static typing and linting in CI, fuzz tests for the parsers

See [CHANGELOG.md](CHANGELOG.md) for what each release added.

---

## Windows notes

PowerShell uses cp1251 encoding by default, which may cause `UnicodeEncodeError` when piping output. Fix:

```powershell
$env:PYTHONUTF8 = "1"
ctf-lens challenge.png
```

Or set it permanently in your PowerShell profile.

---

## License

MIT

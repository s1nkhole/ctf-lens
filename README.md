# ctf-lens

[![CI](https://github.com/s1nkhole/ctf-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/s1nkhole/ctf-lens/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Static analysis tool for CTF challenge files. Drop a file — it finds flags, decodes encodings, carves embedded files, and detects steganography. No external binaries required beyond optional Python packages.

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
| `--json` | Full result as JSON on stdout |
| `-q`, `--quiet` | Print only the flags found, one per line |
| `--exit-code` | Exit with status `10` when a flag was found (otherwise `0`) |

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
│   test_zip_crack.py, test_carving.py   — one file per feature, incl. false-positive guards
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
- Flags with an unknown prefix are reported as "flag-shaped strings" (MEDIUM); add `--flag-format` to promote them to real flags.
- FLAC analysis is basic (metadata string scan). PICTURE metadata blocks are not parsed.
- `flag_is_clean()` is applied to noisy raw-string extraction (`core.py`, `audio.py`, `binary.py`, `text.py`, `network.py`, `pdf.py`) but not to structured-field extraction (`archive.py`, `image.py`, `lsb_image.py`), since those pull flags from discrete metadata fields rather than raw string soup.

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

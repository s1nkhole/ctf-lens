# ctf-lens

Static analysis tool for CTF challenge files. Drop a file — it finds flags, decodes encodings, carves embedded files, and detects steganography. No external binaries required beyond optional Python packages.

---

## Installation

```bash
# Clone
git clone https://github.com/entropixlabs/ctf-lens.git
cd ctf-lens

# Install with optional dependencies (recommended)
pip install -e ".[full]"

# Or install only what you need
pip install rich          # coloured terminal output
pip install Pillow numpy  # image LSB steganography analysis
```

**Python 3.10+ required. Zero mandatory dependencies — runs on stdlib alone.**

---

## Usage

### Interactive mode

```bash
ctf-lens
```

Launches a keyboard-driven TUI: ASCII banner, tool description, mode selection. Drag & drop a file into the terminal to set the path — no typing required.

### Direct analysis

```bash
ctf-lens challenge.png          # standard analysis
ctf-lens challenge.png --deep   # extended checks (slower)
ctf-lens challenge.png --xor    # + XOR brute-force (keys 0x01–0xFF)
ctf-lens challenge.png --deep --xor
```

### As a Python package

```python
from ctf_lens import analyze, AnalysisResult

result = analyze("challenge.png")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  {finding.data}")

for decoded in result.decoded:
    print(f"{finding.title}: {decoded.data}")
```

---

## What it detects

| Category | Techniques |
|---|---|
| **Flags** | 25+ CTF platform prefixes: `flag{}`, `HTB{}`, `picoCTF{}`, `THM{}`, `DUCTF{}` and more |
| **Encodings** | Base64, Hex, ROT13, URL-encoding, HTML entities, binary code, Morse code |
| **Ciphers** | Caesar (ROT1–25), Atbash, Vigenère hint (Index of Coincidence) |
| **Steganography** | LSB per-channel (R/G/B/A/L), bit-plane analysis, whitespace stego |
| **Images** | EXIF metadata, PNG chunks (tEXt/iTXt/zTXt/non-standard), JPEG markers and comments, data after EOI |
| **Audio** | WAV LSB on samples, non-standard RIFF chunks, MP3 ID3 tags, data after last frame |
| **Archives** | ZIP (comment, file contents, password detection), GZIP, BZIP2 with decompression bomb protection |
| **Executables** | ELF/PE strings and sections, Java CLASS, interesting keywords |
| **Network** | PCAP/PCAPNG flag search, HTTP traffic detection, credential patterns |
| **General** | Embedded file carving (magic bytes), Shannon entropy analysis, XOR brute-force, URL extraction |

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
| Text | TXT, any printable file |

---

## Project structure

```
ctf_lens/
├── config.py          — all constants and thresholds
├── models.py          — Finding, AnalysisResult dataclasses
├── registry.py        — flag registration and deduplication
├── utils.py           — entropy, file type detection, hashing, string extraction
├── decoders.py        — Base64, Hex, ROT13, XOR, URL, HTML, binary, Morse
├── _lsb_common.py     — shared LSB math (used by image and audio independently)
├── core.py            — main analyze() orchestrator + general analysis
├── output.py          — Rich coloured output and plain-text fallback
├── tui.py             — interactive terminal UI
├── cli.py             — argparse CLI for power users
└── analyzers/
    ├── image.py       — EXIF, PNG chunks, JPEG DCT
    ├── lsb_image.py   — LSB steganography for images
    ├── audio.py       — WAV, MP3, FLAC + audio LSB
    ├── archive.py     — ZIP, GZIP, BZIP2
    ├── text.py        — Caesar, Atbash, Vigenère, whitespace stego
    ├── binary.py      — ELF, PE
    ├── network.py     — PCAP
    └── pdf.py         — PDF
```

---

## Examples

The `examples/` folder contains sample files demonstrating different hiding techniques:

| File | Technique |
|---|---|
| `plaintext_flag.txt` | Flag directly in file |
| `base64_flag.txt` | Flag encoded as Base64 |
| `hex_flag.txt` | Flag encoded as hex |
| `nested.zip` | Flag inside a nested ZIP |
| `lsb_stego.png` | Flag in LSB of channel R |
| `polyglot.png` | Flag appended after PNG EOF marker |

Run against all examples:

```bash
for f in examples/*; do
    echo "=== $f ==="; ctf-lens "$f"
done
```

---

## Limitations

- Single-byte XOR only (`--xor` flag). Multi-byte XOR and RC4 are not supported.
- LSB extraction reads bits in order R→G→B, MSB-first per pixel. Tools using a different bit order (some online stego sites) will give unreadable output.
- Encrypted archives are detected but not cracked. Use `hashcat` or `john` for password recovery.
- Archives are not recursively unpacked — nested ZIPs are detected and reported, not opened.
- PDF analysis covers keyword search and embedded file detection only. For full PDF forensics use `pdf-parser.py` or `peepdf`.
- FLAC analysis is basic (metadata string scan). PICTURE metadata blocks are not parsed.

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

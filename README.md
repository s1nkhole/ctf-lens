# ctf-lens

A static analysis tool for CTF challenges. Feed it a file — it finds flags, decodes encodings, carves embedded files, and detects steganography. No external binaries required beyond optional Python packages.

```
python ctf_lens.py challenge.png --deep --xor
```

---

## Features

| Category | What it does |
|---|---|
| **Flag detection** | Regex match for 25+ CTF formats: `flag{}`, `HTB{}`, `picoCTF{}`, `THM{}`, `DUCTF{}` and more |
| **Encodings** | Base64, hex, ROT13, URL encoding, HTML entities, binary, Morse code |
| **Steganography** | LSB extraction (PNG/BMP, per-channel), bit-plane analysis, whitespace stego, JPEG DCT comment scan |
| **File carving** | Magic byte search for embedded JPEG, PNG, ZIP, GZIP, ELF, PDF inside any file |
| **Archives** | ZIP content listing, encrypted entry detection, nested ZIP detection, comment extraction |
| **Audio** | WAV/MP3/FLAC metadata scan, ID3v2 tag parsing, LSB audio analysis |
| **Images** | EXIF metadata, PNG chunk inspection (tEXt, zTXt, iTXt), JPEG APP/COM segment scan |
| **Executables** | ELF section headers + strings, PE import table, suspicious string extraction |
| **Network** | PCAP magic detection, basic frame inspection |
| **Entropy** | Per-file Shannon entropy with context-aware interpretation |
| **XOR brute-force** | Single-byte XOR 0x01–0xFF with English-text scoring (`--xor` flag) |
| **Caesar / Atbash / Vigenère** | Cipher detection with word-frequency scoring |

---

## Requirements

Python 3.10+. No mandatory dependencies — the tool works without any extras.

Optional (better output):
```
pip install rich pillow numpy
```

- `rich` — coloured terminal output with panels and tables
- `pillow` + `numpy` — LSB steganography extraction from images

---

## Usage

```bash
# Basic scan
python ctf_lens.py challenge.png

# Deep scan: wider string coverage + more encoding checks
python ctf_lens.py challenge.wav --deep

# Deep scan + XOR brute-force
python ctf_lens.py unknown.bin --deep --xor
```

### Options

| Flag | Description |
|---|---|
| `--deep` | Increases scan limits for ROT13 and extra encodings (slower) |
| `--xor` | Brute-forces single-byte XOR keys 0x01–0xFF |
| `--version` | Print version and exit |
| `-h` / `--help` | Print help |

---

## Supported file types

PNG · JPEG · BMP · GIF · WAV · MP3 · FLAC · ZIP · GZIP · BZ2 · ELF · PE (EXE/DLL) · PDF · PCAP · plain text

Unknown file types fall back to general analysis (strings, entropy, carving, encodings).

---

## Example output

```
─────────────────────────────────── ctf-lens v0.3.0 ───────────────────────────────────

  File        challenge.png
  Type        PNG (image)
  Size        325,983 bytes (318.3 KB)
  Entropy     7.986 / 8.0
  MD5         9b2a3884547d0fc65418243cba308373

╭──────────────────────────────────────────────────╮
│ 🔴 Critical: 3   🟡 Medium: 0   ⚪ Info: 4        │
╰──────────────────────────────────────────────────╯

🔴 🚩 Flag found!
   flag{example_flag_hidden_in_lsb}
   Source: LSB extraction, channel R

🔴 ⚠️ LSB stego suspected — channel R
   LSB entropy: 0.030 (normal ≈1.0). Bits are non-random.

🔴 ⚠️ LSB stego suspected — channel G
   LSB entropy: 0.028
```

---

## Examples

The `examples/` folder contains six files that demonstrate different hiding techniques. Run the tool against them to see what it finds:

```bash
python ctf_lens.py examples/example_text.txt
python ctf_lens.py examples/example_base64.txt
python ctf_lens.py examples/example_hex.txt
python ctf_lens.py examples/example_archive.zip
python ctf_lens.py examples/example_lsb.png --deep
python ctf_lens.py examples/example_polyglot.png
```

| File | Technique used |
|---|---|
| `example_text.txt` | Plaintext flag |
| `example_base64.txt` | Base64-encoded flag |
| `example_hex.txt` | Hex-encoded flag |
| `example_archive.zip` | Flag inside nested ZIP entry |
| `example_lsb.png` | LSB steganography, channel R |
| `example_polyglot.png` | Flag appended after PNG EOF marker |

---

## Windows notes

PowerShell cp1251 terminals may produce `UnicodeEncodeError` when piping output (e.g. with `Tee-Object`). Set UTF-8 mode before running:

```powershell
$env:PYTHONUTF8 = "1"
python ctf_lens.py challenge.png
```

Or run directly in Windows Terminal without redirection.

---

## Limitations

- Single-byte XOR only. Multi-byte keys require manual work.
- LSB extraction reads bits in `R→G→B`, MSB-first order per pixel. Tools using different bit orders (e.g. some online stego sites) will produce unreadable output — use `zsteg` in that case.
- Encrypted archives are detected but not cracked.
- No recursive archive unpacking.

---

## License

MIT

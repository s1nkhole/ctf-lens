"""
Utility functions shared across the entire package.
All functions are pure (no side effects on AnalysisResult).
"""

import math
import re
import string
import struct
import hashlib
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .signatures import validate as _validate_signature, DETECTION_VALIDATED
from .config import (
    ALLOWED_BASE_PATH, MAGIC_SIGNATURES, MIN_STRING_LEN, MIN_STRING_LEN_EXEC,
    RE_PRINTABLE_STRINGS, RE_PRINTABLE_STRINGS_EXEC, FLAG_PATTERNS,
)


# ── Entropy ───────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Range 0.0–8.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


# ── File type detection ───────────────────────────────────────────────────────

def detect_filetype(data: bytes) -> tuple[str, str]:
    """
    Identify file type from magic bytes.
    Special cases:
      RIFF     → refined by bytes 8–12 (WAVE/WEBP/AVI/...)
      CAFEBABE → Java CLASS vs Mach-O fat binary (distinguished by major version)
    Returns (filetype, category).
    """
    if len(data) < 4:
        return 'UNKNOWN', 'unknown'

    # CAFEBABE: distinguish Mach-O from Java .class
    if data[:4] == b'\xca\xfe\xba\xbe':
        if len(data) >= 8:
            major = struct.unpack('>H', data[6:8])[0]
            if 44 <= major <= 100:   # Java 1.1 (45) .. Java 23 (67)
                return 'CLASS', 'java'
        return 'MACHO', 'executable'

    for magic, ftype, category in MAGIC_SIGNATURES:
        if not data.startswith(magic):
            continue
        if ftype == '_CAFEBABE':
            continue
        # A magic number alone is weak ('BM', 'MZ', 0x1f8b show up in plain text
        # and random data) — require the structural fields behind it to be sane.
        if ftype in DETECTION_VALIDATED and not _validate_signature(ftype, data, 0):
            continue

        # RIFF: refine subtype from bytes 8–12
        if ftype == 'RIFF' and len(data) > 12:
            subtype = data[8:12]
            if subtype == b'WAVE':
                return 'WAV', 'audio'
            elif subtype == b'WEBP':
                return 'WEBP', 'image'
            elif subtype == b'AVI ':
                return 'AVI', 'video'
            else:
                return 'RIFF', 'unknown'

        return ftype, category

    # Fallback: try to decode as text
    sample = data[:512]
    for enc in ('utf-8', 'utf-16', 'latin-1'):
        try:
            decoded = sample.decode(enc)
            printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
            if printable_ratio > 0.85:
                return 'TEXT', 'text'
        except (UnicodeDecodeError, ValueError):
            continue

    return 'UNKNOWN', 'unknown'


# ── String extraction ─────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """
    Extract printable ASCII strings via compiled re.findall.
    50–100x faster than a pure-Python byte loop.
    """
    if min_len == MIN_STRING_LEN:
        pattern = RE_PRINTABLE_STRINGS
    elif min_len == MIN_STRING_LEN_EXEC:
        pattern = RE_PRINTABLE_STRINGS_EXEC
    else:
        pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')

    return [m.group(0).decode('ascii', errors='replace') for m in pattern.finditer(data)]


# Both patterns START with a literal NUL byte, which lets the regex engine skip
# straight between NULs instead of trying every offset (~3x faster on random data).
# LE strings are "c\0c\0…": the lookbehind demands the first character and the
# match is widened by one byte below.
_RE_UTF16LE = re.compile(rb'(?<=[ -~])\x00(?:[ -~]\x00){5,}')
_RE_UTF16BE = re.compile(rb'\x00[ -~](?:\x00[ -~]){5,}')
UTF16_SCAN_LIMIT = 64 * 1024 * 1024


def extract_utf16_strings(data: bytes, limit: int = 50_000) -> list[str]:
    """Printable UTF-16 (LE and BE, 6+ chars) strings — Windows binaries, .NET, some CTF tricks."""
    data = data[:UTF16_SCAN_LIMIT]
    out: list[str] = []
    for m in _RE_UTF16LE.finditer(data):
        out.append(data[m.start() - 1:m.end()].decode('utf-16-le', errors='ignore'))
        if len(out) >= limit:
            return out
    for m in _RE_UTF16BE.finditer(data):
        out.append(m.group(0).decode('utf-16-be', errors='ignore'))
        if len(out) >= limit:
            return out
    return out


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII or common whitespace."""
    if not data:
        return 0.0
    ok = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return ok / len(data)


@contextmanager
def custom_flag_format(regex: str | None):
    """
    Temporarily add a user-supplied flag regex (e.g. r'MYCTF\\{[^}]+\\}') in front of
    the built-in patterns. Every module shares the FLAG_PATTERNS list object, so
    inserting here makes looks_like_flag / register_flag / flag_is_clean see it.
    """
    if not regex:
        yield
        return
    try:
        pat = re.compile(regex)
    except re.error as e:
        raise ValueError(f'Invalid flag format regex {regex!r}: {e}') from e
    FLAG_PATTERNS.insert(0, pat)
    try:
        yield
    finally:
        try:
            FLAG_PATTERNS.remove(pat)
        except ValueError:
            pass


# ── Flag detection ────────────────────────────────────────────────────────────

def looks_like_flag(s: str) -> bool:
    """Return True if s matches any known CTF flag pattern."""
    for pattern in FLAG_PATTERNS:
        if pattern.search(s):
            return True
    return False


def flag_is_clean(text: str) -> bool:
    """
    Verify the matched flag is not surrounded by binary garbage.
    Prevents ROT13/Atbash false positives from ZIP internal structures
    where picoCTF{flag} appears inside 'file.txtpicoCTF{flag}PK\\x03\\x04'.
    Rules:
      — no non-printable chars immediately before/after the flag match
      — flag occupies >40% of the string OR the string is short (<80 chars)
    """
    for pat in FLAG_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        flag   = m.group(0)
        ratio  = len(flag) / max(len(text), 1)
        prefix = text[:m.start()]
        suffix = text[m.end():]
        has_junk = any(c not in string.printable for c in prefix[-10:] + suffix[:10])
        if has_junk:
            return False
        if ratio > 0.4 or len(text) < 80:
            return True
    return False


# ── Hashing ───────────────────────────────────────────────────────────────────

def compute_hashes(data: bytes) -> tuple[str, str]:
    """Return (md5_hex, sha256_hex)."""
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


# ── Safe text decode ──────────────────────────────────────────────────────────

def safe_decode(data: bytes, encodings: tuple[str, ...] = ('utf-8', 'latin-1')) -> str:
    """Try to decode bytes to str through a list of encodings."""
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return data.decode('latin-1', errors='replace')


# ── Path validation ───────────────────────────────────────────────────────────

def validate_path(filepath: str) -> Path:
    """
    Resolve and validate a file path.
    If ALLOWED_BASE_PATH is set, enforces that the file stays inside it
    (prevents path traversal when embedded in an API).
    """
    path = Path(filepath).resolve()
    if ALLOWED_BASE_PATH is not None:
        try:
            path.relative_to(ALLOWED_BASE_PATH)
        except ValueError:
            raise PermissionError(
                f"Access denied: '{path}' is outside '{ALLOWED_BASE_PATH}'"
            )
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Not a file: {filepath}")
    return path

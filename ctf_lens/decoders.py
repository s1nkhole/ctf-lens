"""
Decoder functions.
Each function is pure: takes a string/bytes, returns Optional[str] or bytes.
They do NOT mutate AnalysisResult — that happens in core.py.
"""

import re
import string
import base64
from urllib.parse import unquote as _url_unquote
import html as _html

from .config import (
    MIN_B64_LEN, MIN_HEX_LEN, MIN_DECODED_LEN, B64_CHARS,
    XOR_SAMPLE_SIZE, MORSE, RE_WORD_3PLUS,
)
from .utils import safe_decode


# ── Base64 ────────────────────────────────────────────────────────────────────

def try_decode_base64(s: str) -> str | None:
    """
    Decode a base64 string.
    Padding formula: (4 - n%4) % 4 handles all cases including n%4==0.
    raw is decoded once and reused for both text and binary output.
    """
    s = s.strip().replace(' ', '').replace('\n', '')
    if len(s) < MIN_B64_LEN:
        return None
    if not all(c in B64_CHARS for c in s):
        return None
    try:
        stripped = s.rstrip('=')
        if len(stripped) % 4 == 1:
            return None
        padding = (4 - len(stripped) % 4) % 4
        raw = base64.b64decode(stripped + '=' * padding)
    except Exception:
        return None

    for enc in ('utf-8', 'latin-1'):
        try:
            text = raw.decode(enc)
            if len(text) >= MIN_DECODED_LEN and any(c in string.printable for c in text[:20]):
                return text
        except (UnicodeDecodeError, ValueError):
            continue

    if len(raw) >= MIN_DECODED_LEN:
        return f'[binary] {raw.hex()[:80]}'
    return None


# ── Hex ───────────────────────────────────────────────────────────────────────

def try_decode_hex(s: str) -> str | None:
    """Decode a hex string to text or return a hex+ASCII preview."""
    s = s.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    if len(s) < MIN_HEX_LEN or len(s) % 2 != 0:
        return None
    if not all(c in string.hexdigits for c in s):
        return None
    try:
        raw = bytes.fromhex(s)
        try:
            text = raw.decode('utf-8')
            if len(text) >= MIN_DECODED_LEN and any(c in string.printable for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:40])
        return f'[binary] {printable}'
    except Exception:
        return None


# ── ROT13 ─────────────────────────────────────────────────────────────────────

def try_rot13(s: str) -> str | None:
    """Apply ROT13; return result only if it contains readable words."""
    if not s.isascii():
        return None
    result = s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
    ))
    if result != s and len(RE_WORD_3PLUS.findall(result)) >= 2:
        return result
    return None


# ── XOR ───────────────────────────────────────────────────────────────────────

def try_decode_xor(data: bytes, key: int) -> bytes:
    """
    XOR all bytes with a single-byte key.
    bytes(map(...)) is faster than a list comprehension:
    map is a C function with no Python interpreter overhead.
    """
    return bytes(map(key.__xor__, data))


def score_xor_result(data: bytes) -> float:
    """
    Score how text-like an XOR result looks (0.0–1.0).
    Counts the fraction of printable ASCII bytes in the sample.
    """
    if not data:
        return 0.0
    sample = data[:XOR_SAMPLE_SIZE]
    printable_count = sum(
        32 <= b < 127 or b in (9, 10, 13)
        for b in sample
    )
    return printable_count / len(sample)


# ── URL encoding ──────────────────────────────────────────────────────────────

def try_decode_url_encoding(s: str) -> str | None:
    """Decode a percent-encoded (%XX) string."""
    if '%' not in s:
        return None
    try:
        decoded = _url_unquote(s)
        if decoded != s and len(decoded) >= MIN_DECODED_LEN:
            return decoded
    except Exception:
        pass
    return None


# ── HTML entities ─────────────────────────────────────────────────────────────

def try_decode_html_entities(s: str) -> str | None:
    """Decode HTML entities (&amp; &#...; etc.)."""
    if '&' not in s:
        return None
    try:
        decoded = _html.unescape(s)
        if decoded != s and len(decoded) >= MIN_DECODED_LEN:
            return decoded
    except Exception:
        pass
    return None


# ── Binary string ─────────────────────────────────────────────────────────────

def try_decode_binary_string(s: str) -> str | None:
    """Decode a string of 0s and 1s as ASCII (8 bits per character)."""
    clean = s.replace(' ', '').replace('\n', '')
    if not all(c in '01' for c in clean):
        return None
    if len(clean) < 8 or len(clean) % 8 != 0:
        return None
    try:
        result = ''
        for i in range(0, len(clean), 8):
            byte = int(clean[i:i + 8], 2)
            if byte == 0:
                break
            result += chr(byte)
        if len(result) >= MIN_DECODED_LEN and result.isprintable():
            return result
    except Exception:
        pass
    return None


# ── Morse code ────────────────────────────────────────────────────────────────

def try_decode_morse(s: str) -> str | None:
    """Decode a Morse code string (dots and dashes)."""
    clean = s.strip()
    if not re.fullmatch(r'[.\- /]+', clean):
        return None
    words = clean.split(' / ')
    result_parts = []
    for word in words:
        chars = word.split(' ')
        decoded_word = ''
        for char in chars:
            if char in MORSE:
                decoded_word += MORSE[char]
            elif char:
                return None
        result_parts.append(decoded_word)
    result = ' '.join(result_parts)
    if len(result) >= MIN_DECODED_LEN:
        return result
    return None

"""
XOR attacks beyond single-byte brute force:
  * repeating-key XOR  — key length from normalised Hamming distance, then each
                         key byte by letter-frequency scoring of its column
  * known-plaintext    — XOR the start of the data with common flag prefixes
                         ('flag{', 'CTF{', ...); a short repeating key shows up
                         as a period in the recovered key stream
"""

from __future__ import annotations

from .config import CTF_KNOWN_PREFIXES, XOR_MAX_KEY_LEN, XOR_MIN_DATA
from .models import Finding, AnalysisResult
from .registry import register_flag
from .utils import looks_like_flag, printable_ratio

# Letter-frequency weights: space > lowercase > uppercase/digits/_{} > other printable > rest.
_WEIGHTS = bytes(
    3 if c == 32 else 2 if 97 <= c <= 122 else 1 if (65 <= c <= 90 or 48 <= c <= 57 or c in (95, 123, 125))
    else 1 if 33 <= c < 127 or c in (9, 10, 13) else 0
    for c in range(256)
)
_XOR_TABLES = [bytes(c ^ k for c in range(256)) for k in range(256)]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def _key_sizes(data: bytes, limit: int) -> list[int]:
    scored: list[tuple[float, int]] = []
    for ks in range(2, limit + 1):
        blocks = [data[i * ks:(i + 1) * ks] for i in range(min(len(data) // ks, 24))]
        if len(blocks) < 4:
            break
        pairs = list(zip(blocks, blocks[1:]))
        dist  = sum(_hamming(a, b) for a, b in pairs) / (len(pairs) * ks)
        scored.append((dist, ks))
    scored.sort()
    return [ks for _d, ks in scored[:4]]


def _best_key_byte(column: bytes) -> int:
    best, best_score = 0, -1
    for k in range(256):
        score = sum(column.translate(_XOR_TABLES[k]).translate(_WEIGHTS))
        if score > best_score:
            best, best_score = k, score
    return best


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def _show_key(key: bytes) -> str:
    return key.decode('ascii') if all(32 <= b < 127 for b in key) else key.hex()


def crack_repeating_xor(data: bytes, result: AnalysisResult) -> None:
    sample = data[:8192]
    if len(sample) < XOR_MIN_DATA:
        return
    reported = 0
    for ks in _key_sizes(sample, min(XOR_MAX_KEY_LEN, len(sample) // 4)):
        key = bytes(_best_key_byte(sample[i::ks]) for i in range(ks))
        if len(set(key)) == 1:
            continue                                  # plain single-byte XOR — handled elsewhere
        plain = _xor_repeat(sample, key)
        if printable_ratio(plain) < 0.93:
            continue
        full = _xor_repeat(data, key)
        text = full.decode('latin-1')
        if looks_like_flag(text):
            register_flag(text, result, source=f'repeating-key XOR, key={_show_key(key)!r} (len {ks})',
                          hint=f'Key: {_show_key(key)}')
        elif reported < 2:
            reported += 1
            result.decoded.append(Finding(
                title       = f'Repeating-key XOR, key={_show_key(key)!r}',
                severity    = 'MEDIUM',
                description = f'Key length {ks} gives readable text:',
                data        = plain[:200].decode('latin-1'),
                technique   = 'XOR Cipher',
            ))


def known_plaintext_xor(data: bytes, result: AnalysisResult) -> None:
    """Flag at the start of the file, short repeating key (period ≤ len(prefix) − 2)."""
    prefixes: set[bytes] = set()
    for p in CTF_KNOWN_PREFIXES.split('|'):
        for variant in (p, p.lower(), p.upper()):
            prefixes.add(variant.encode() + b'{')
    for prefix in sorted(prefixes):
        if len(data) < len(prefix):
            continue
        stream = bytes(a ^ b for a, b in zip(data, prefix))
        for period in range(1, len(prefix) - 1):
            if all(stream[i] == stream[i + period] for i in range(len(prefix) - period)):
                key  = stream[:period]
                full = _xor_repeat(data, key)
                if printable_ratio(full[:4096]) >= 0.85 and looks_like_flag(full.decode('latin-1')):
                    register_flag(full.decode('latin-1'), result,
                                  source=f'known-plaintext XOR ({prefix.decode()}), key={_show_key(key)!r}',
                                  hint=f'Key: {_show_key(key)}')
                    return
                break

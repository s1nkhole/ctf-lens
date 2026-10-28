"""
Multi-layer decoding ("peel the onion", in the spirit of CyberChef's Magic).

Challenge authors love chains such as  rot13( base64( hex( flag ) ) ).  Single-layer
decoders miss those because the intermediate layer is just another opaque string.
Here a bounded search applies every transform to every reachable intermediate and
reports the shortest chain that ends in a flag.

Pruning is what keeps this cheap and quiet. A candidate survives only if it is
(a) readable text, (b) a recognised compressed stream / file, or (c) for the
text-only transforms (rot13, atbash, reverse), still looks like an encoded blob.
Everything else — i.e. nearly all wrong guesses — is dropped immediately.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import lzma
import re
import time
import zlib
from collections import deque
from typing import Callable

from .config import (
    FLAG_PATTERNS, PEEL_MAX_NODES, PEEL_MAX_BLOB, PEEL_MAX_SECONDS,
    PEEL_MAX_TOKENS, PEEL_MAX_OUTPUT, RE_B64, RE_HEX,
)
from .models import Finding, AnalysisResult
from .registry import register_flag
from .utils import printable_ratio, flag_is_clean, detect_filetype
from . import decoders

_RE_B32   = re.compile(r'[A-Z2-7]{16,}={0,6}')
_B58_ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_MAP  = {c: i for i, c in enumerate(_B58_ALPH)}
_ROT13    = bytes.maketrans(
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    b'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
)
_ATBASH   = bytes.maketrans(
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    b'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba',
)
# Streams that a transform below can still unpack — keep peeling instead of stopping.
_UNPACKABLE = frozenset({'GZIP', 'BZIP2', 'XZ'})
_FILE_TYPES = frozenset({
    'PNG', 'JPEG', 'GIF', 'ZIP', 'GZIP', 'BZIP2', 'XZ', '7ZIP', 'RAR', 'PDF',
    'ELF', 'EXE', 'SQLITE', 'WAV',
})
_ZLIB_HEADERS = (b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda')
TEXT_ONLY = frozenset({'rot13', 'atbash', 'reverse'})


# ── transforms: bytes -> bytes | None ────────────────────────────────────────

def _nl_strip(b: bytes) -> bytes:
    return re.sub(rb'[\r\n]', b'', b.strip())


def t_hex(b: bytes) -> bytes | None:
    s = re.sub(rb'0x|\\x|[\s,:]', b'', b.strip())
    if len(s) < 8 or len(s) % 2 or not re.fullmatch(rb'[0-9a-fA-F]+', s):
        return None
    return bytes.fromhex(s.decode())


def t_base64(b: bytes) -> bytes | None:
    s = _nl_strip(b)
    if len(s) < 8 or not re.fullmatch(rb'[A-Za-z0-9+/_-]+={0,2}', s):
        return None
    s = s.replace(b'-', b'+').replace(b'_', b'/').rstrip(b'=')
    if len(s) % 4 == 1:
        return None
    try:
        return base64.b64decode(s + b'=' * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def t_base32(b: bytes) -> bytes | None:
    s = _nl_strip(b).rstrip(b'=')
    if len(s) < 8 or not re.fullmatch(rb'[A-Z2-7]+', s) or len(s) % 8 in (1, 3, 6):
        return None
    try:
        return base64.b32decode(s + b'=' * (-len(s) % 8))
    except (binascii.Error, ValueError):
        return None


def t_base85(b: bytes) -> bytes | None:
    s = _nl_strip(b)
    if len(s) < 10 or b' ' in s:
        return None
    for fn in (base64.b85decode, base64.a85decode):
        try:
            return fn(s)
        except (ValueError, binascii.Error):
            continue
    return None


def t_base58(b: bytes) -> bytes | None:
    s = _nl_strip(b).decode('latin-1')
    if len(s) < 8 or any(c not in _B58_MAP for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + _B58_MAP[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\x00' * (len(s) - len(s.lstrip('1'))) + body


def t_binary(b: bytes) -> bytes | None:
    s = re.sub(rb'\s', b'', b)
    if len(s) < 16 or len(s) % 8 or not re.fullmatch(rb'[01]+', s):
        return None
    return int(s, 2).to_bytes(len(s) // 8, 'big')


def _via_text(fn: Callable[[str], str | None]) -> Callable[[bytes], bytes | None]:
    def run(b: bytes) -> bytes | None:
        if printable_ratio(b[:4096]) < 0.9:
            return None
        out = fn(b.decode('latin-1'))
        return out.encode('latin-1', errors='ignore') if out else None
    return run


def t_zlib(b: bytes) -> bytes | None:
    if b[:2] not in _ZLIB_HEADERS:
        return None
    try:
        return zlib.decompressobj().decompress(b, PEEL_MAX_OUTPUT)
    except zlib.error:
        return None


def t_gzip(b: bytes) -> bytes | None:
    if b[:2] != b'\x1f\x8b':
        return None
    try:
        return zlib.decompressobj(wbits=31).decompress(b, PEEL_MAX_OUTPUT)
    except zlib.error:
        return None


def t_bz2(b: bytes) -> bytes | None:
    if b[:3] != b'BZh':
        return None
    try:
        return bz2.BZ2Decompressor().decompress(b, PEEL_MAX_OUTPUT)
    except (OSError, ValueError):
        return None


def t_lzma(b: bytes) -> bytes | None:
    if b[:6] != b'\xfd7zXZ\x00':
        return None
    try:
        return lzma.LZMADecompressor().decompress(b, PEEL_MAX_OUTPUT)
    except lzma.LZMAError:
        return None


# (name, function, text_only) — text_only transforms keep a node only when the
# output still looks like an encoded blob (or is a flag); see _keep().
TRANSFORMS: list[tuple[str, Callable[[bytes], bytes | None], bool]] = [
    ('hex',      t_hex,      False),
    ('base64',   t_base64,   False),
    ('base32',   t_base32,   False),
    ('base85',   t_base85,   False),
    ('base58',   t_base58,   False),
    ('binary',   t_binary,   False),
    ('url',      _via_text(decoders.try_decode_url_encoding),  False),
    ('html',     _via_text(decoders.try_decode_html_entities), False),
    ('morse',    _via_text(decoders.try_decode_morse),         False),
    ('zlib',     t_zlib,     False),
    ('gzip',     t_gzip,     False),
    ('bzip2',    t_bz2,      False),
    ('lzma',     t_lzma,     False),
    ('rot13',    lambda b: b.translate(_ROT13),   True),
    ('atbash',   lambda b: b.translate(_ATBASH),  True),
    ('reverse',  lambda b: b[::-1],               True),
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _find_flag(blob: bytes) -> str | None:
    text = blob[:PEEL_MAX_BLOB].decode('latin-1')
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            ctx = text[max(0, m.start() - 10): m.end() + 10]
            if flag_is_clean(ctx):
                return m.group(0)
    return None


def _looks_encoded(b: bytes) -> bool:
    s = _nl_strip(b)
    return len(s) >= 8 and bool(re.fullmatch(rb'[A-Za-z0-9+/=_-]+|[0-9a-fA-F]+|[A-Z2-7=]+', s))


def _keep(out: bytes, text_only: bool) -> bool:
    if text_only:
        return _looks_encoded(out)
    if printable_ratio(out[:4096]) >= 0.85:
        return True
    ftype, _ = detect_filetype(out[:64]) if len(out) >= 16 else ('UNKNOWN', '')
    return ftype in _FILE_TYPES or out[:2] in _ZLIB_HEADERS


def _roots(data: bytes, strings: list[str]) -> list[bytes]:
    roots: list[bytes] = []
    seen:  set[bytes]  = set()

    def add(b: bytes) -> None:
        if b and b not in seen:
            seen.add(b)
            roots.append(b)

    if len(data) <= PEEL_MAX_BLOB:
        add(data)
    tokens = 0
    for s in strings:
        for rx in (RE_B64, RE_HEX, _RE_B32):
            for m in rx.finditer(s):
                add(m.group(0).encode('ascii'))
                tokens += 1
                if tokens >= PEEL_MAX_TOKENS:
                    return roots
        if len(s) >= 12 and ' ' not in s:
            add(s.encode('ascii', errors='ignore'))      # base85/base58/binary/morse candidates
            tokens += 1
            if tokens >= PEEL_MAX_TOKENS:
                return roots
    return roots


def _is_leaf(chain: tuple[str, ...], blob: bytes) -> bool:
    """A readable end point worth showing: >= 2 real decode layers and no text-only (rot13/atbash/reverse) step."""
    return (
        len(chain) >= 2
        and not any(c in TEXT_ONLY for c in chain)
        and printable_ratio(blob[:4096]) >= 0.9
    )


# ── public entry point ───────────────────────────────────────────────────────

def peel_layers(data: bytes, strings: list[str], result: AnalysisResult, max_depth: int) -> None:
    if max_depth <= 0:
        return
    deadline = time.monotonic() + PEEL_MAX_SECONDS
    visited: set[int] = set()
    nodes   = 0
    leaves: list[tuple[int, str, bytes]] = []        # (depth, chain, bytes) of readable end points

    for root in _roots(data, strings):
        queue: deque[tuple[bytes, tuple[str, ...]]] = deque([(root, ())])
        while queue:
            if nodes >= PEEL_MAX_NODES or time.monotonic() > deadline:
                break
            cur, chain = queue.popleft()
            expanded = False
            for name, fn, text_only in TRANSFORMS:
                if text_only and chain and chain[-1] in TEXT_ONLY:
                    continue                      # rot13→atbash→reverse… only creates noise
                try:
                    out = fn(cur)
                except Exception:
                    continue
                if not out or out == cur:
                    continue
                key = hash(out)
                if key in visited:
                    continue
                visited.add(key)
                nodes += 1
                new_chain = chain + (name,)
                desc      = ' → '.join(new_chain)

                flag = _find_flag(out)
                if flag:
                    register_flag(flag, result, source=f'decoded via {desc}',
                                  hint='Decoding chain found automatically (ctf-lens peel).')
                    expanded = True
                    continue
                if not _keep(out, text_only):
                    continue
                expanded = True

                ftype, _cat = detect_filetype(out[:64]) if len(out) >= 16 else ('UNKNOWN', '')
                if ftype in _FILE_TYPES and ftype not in _UNPACKABLE:
                    result.findings.append(Finding(
                        title       = f'Decoded layer is a {ftype} file',
                        severity    = 'HIGH',
                        description = f'Decoding chain: {desc}',
                        technique   = 'Decode Chain',
                        hint        = 'Re-run with --extract DIR to save it.',
                    ))
                    result.layers.append((desc, out))
                    continue
                if len(new_chain) < max_depth:
                    queue.append((out, new_chain))
                elif _is_leaf(new_chain, out):
                    leaves.append((len(new_chain), desc, out))
            if not expanded and _is_leaf(chain, cur):
                leaves.append((len(chain), ' → '.join(chain), cur))

    # Readable end points of multi-step chains that are not flags (e.g. a password).
    leaves.sort(key=lambda t: -t[0])
    for depth, desc, blob in leaves[:5]:
        result.decoded.append(Finding(
            title       = f'Decoded ({depth} layers)',
            severity    = 'INFO',
            description = f'Chain: {desc}',
            data        = blob[:200].decode('latin-1'),
            technique   = 'Decode Chain',
        ))

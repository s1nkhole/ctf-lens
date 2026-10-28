"""
Structural validation of file signatures.

A bare magic number is a weak signal: 'MZ' (2 bytes) or '\\x1f\\x8b' appear
by chance every ~64 KB in any random/compressed data, and plain text can start
with 'BM' or 'MZ'. Every validator here checks a few *structural* fields behind
the magic so that detection and carving report real files only.

All validators have the signature  validator(data, pos) -> bool  and never raise.
"""

from __future__ import annotations

import struct
import zlib

_ZIP_METHODS = frozenset({0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99})


def _png(d: bytes, p: int) -> bool:
    return (
        len(d) >= p + 33
        and d[p:p + 8] == b'\x89PNG\r\n\x1a\n'
        and struct.unpack_from('>I', d, p + 8)[0] == 13
        and d[p + 12:p + 16] == b'IHDR'
    )


def _jpeg(d: bytes, p: int) -> bool:
    return d[p:p + 3] == b'\xff\xd8\xff' and len(d) >= p + 4 and 0xC0 <= d[p + 3] < 0xFF


def _zip(d: bytes, p: int) -> bool:
    if len(d) < p + 30 or d[p:p + 4] != b'PK\x03\x04':
        return False
    version, _flags, method = struct.unpack_from('<HHH', d, p + 4)
    name_len = struct.unpack_from('<H', d, p + 26)[0]
    if version > 63 or method not in _ZIP_METHODS or name_len == 0:
        return False
    name = d[p + 30:p + 30 + name_len]
    return len(name) == name_len and all(c >= 32 for c in name)


def _gzip(d: bytes, p: int) -> bool:
    if len(d) < p + 18 or d[p:p + 2] != b'\x1f\x8b' or d[p + 2] != 8 or d[p + 3] & 0xE0:
        return False
    try:
        zlib.decompressobj(wbits=31).decompress(d[p:p + 4096], 1 << 16)
        return True
    except zlib.error:
        return False


def _bzip2(d: bytes, p: int) -> bool:
    return (
        len(d) >= p + 10
        and d[p:p + 3] == b'BZh'
        and 0x31 <= d[p + 3] <= 0x39
        and d[p + 4:p + 10] == b'1AY&SY'
    )


def _pdf(d: bytes, p: int) -> bool:
    return d[p:p + 5] == b'%PDF-' and d[p + 5:p + 6].isdigit()


def _elf(d: bytes, p: int) -> bool:
    return (
        len(d) >= p + 20
        and d[p:p + 4] == b'\x7fELF'
        and d[p + 4] in (1, 2)
        and d[p + 5] in (1, 2)
        and d[p + 6] == 1
    )


def _mz(d: bytes, p: int) -> bool:
    """DOS header 'MZ' only counts if e_lfanew points at a real 'PE\\0\\0'."""
    if len(d) < p + 0x40 or d[p:p + 2] != b'MZ':
        return False
    e_lfanew = struct.unpack_from('<I', d, p + 0x3C)[0]
    if not 0x40 <= e_lfanew <= 0x10000:
        return False
    q = p + e_lfanew
    return d[q:q + 4] == b'PE\x00\x00'


def _7z(d: bytes, p: int) -> bool:
    return d[p:p + 6] == b"7z\xbc\xaf'\x1c"


def _bmp(d: bytes, p: int) -> bool:
    if len(d) < p + 18 or d[p:p + 2] != b'BM':
        return False
    reserved = d[p + 6:p + 10]
    dib = struct.unpack_from('<I', d, p + 14)[0]
    return reserved == b'\x00\x00\x00\x00' and dib in (12, 40, 52, 56, 64, 108, 124)


def _mp3(d: bytes, p: int) -> bool:
    if d[p:p + 3] == b'ID3':
        return (
            len(d) >= p + 10
            and d[p + 3] < 5
            and d[p + 5] & 0x0F == 0
            and all(b < 0x80 for b in d[p + 6:p + 10])
        )
    if len(d) < p + 4 or d[p] != 0xFF or d[p + 1] & 0xE0 != 0xE0:
        return False
    version = (d[p + 1] >> 3) & 3
    layer   = (d[p + 1] >> 1) & 3
    bitrate = (d[p + 2] >> 4) & 0xF
    srate   = (d[p + 2] >> 2) & 3
    return version != 1 and layer != 0 and bitrate != 0xF and srate != 3


VALIDATORS = {
    'PNG': _png, 'JPEG': _jpeg, 'ZIP': _zip, 'GZIP': _gzip, 'BZIP2': _bzip2,
    'PDF': _pdf, 'ELF': _elf, 'EXE': _mz, '7ZIP': _7z, 'BMP': _bmp, 'MP3': _mp3,
}


# Signatures too short/common to trust on their own when classifying a whole file.
# Strong ones (8-byte PNG, 'PK\x03\x04', '%PDF', '\x7fELF', ...) are accepted as-is by
# detect_filetype(); carving applies the full validators to everything.
DETECTION_VALIDATED = frozenset({'BMP', 'EXE', 'GZIP', 'MP3', 'BZIP2'})


def validate(ftype: str, data: bytes, pos: int = 0) -> bool:
    """True if the signature at data[pos:] passes the structural check for ftype."""
    check = VALIDATORS.get(ftype)
    if check is None:
        return True
    try:
        return bool(check(data, pos))
    except (struct.error, IndexError, ValueError):
        return False


# ── Estimating where an embedded file ends (used by --extract) ────────────────

_EXTENSIONS = {
    'PNG': 'png', 'JPEG': 'jpg', 'ZIP': 'zip', 'GZIP': 'gz', 'PDF': 'pdf',
    'ELF': 'elf', 'EXE': 'exe', 'BZIP2': 'bz2', '7ZIP': '7z',
}


def extension_for(ftype: str) -> str:
    return _EXTENSIONS.get(ftype, 'bin')


def estimate_end(ftype: str, data: bytes, pos: int) -> int:
    """Best-effort end offset of the file starting at pos (falls back to EOF)."""
    n = len(data)
    try:
        if ftype == 'PNG':
            q = pos + 8
            while q + 12 <= n:
                length = struct.unpack_from('>I', data, q)[0]
                kind = data[q + 4:q + 8]
                q += 12 + length
                if kind == b'IEND':
                    return min(q, n)
                if q > n:
                    break
        elif ftype == 'ZIP':
            e = data.find(b'PK\x05\x06', pos)
            if e != -1 and e + 22 <= n:
                comment_len = struct.unpack_from('<H', data, e + 20)[0]
                return min(e + 22 + comment_len, n)
        elif ftype == 'JPEG':
            e = data.find(b'\xff\xd9', pos + 4)
            if e != -1:
                return e + 2
        elif ftype == 'GZIP':
            window = data[pos:pos + (64 << 20)]
            d = zlib.decompressobj(wbits=31)
            d.decompress(window)
            if d.eof:
                return pos + len(window) - len(d.unused_data)
    except (struct.error, zlib.error):
        pass
    return n

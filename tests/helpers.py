"""Builders for synthetic test files. Stdlib only, so the same tests run in a
zero-dependency environment (generated at test time instead of committing binaries)."""
from __future__ import annotations

import struct
import zlib


# ── PNG ──────────────────────────────────────────────────────────────────────

def png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)


def build_png(width: int = 16, height: int = 16, extra_chunks: tuple[tuple[bytes, bytes], ...] = ()) -> bytes:
    """A valid 8-bit RGB PNG with a deterministic gradient; extra chunks go before IEND."""
    rows = b''.join(
        b'\x00' + bytes((x * 7 + y * 13 + c * 40) % 256 for x in range(width) for c in range(3))
        for y in range(height)
    )
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    out  = b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', ihdr)
    for kind, data in extra_chunks:
        out += png_chunk(kind, data)
    return out + png_chunk(b'IDAT', zlib.compress(rows)) + png_chunk(b'IEND', b'')


# ── PE (just enough structure for signature validation) ──────────────────────

def build_pe_stub(size: int = 400) -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    return bytes(dos) + b'PE\x00\x00' + b'\x4c\x01' + b'\x00' * (size - 0x86)


# ── ZipCrypto (the legacy "password" zip) ────────────────────────────────────

_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


class _ZipCryptoKeys:
    def __init__(self, password: bytes) -> None:
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in password:
            self.update(b)

    @staticmethod
    def _crc(c: int, b: int) -> int:
        return _CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)

    def update(self, b: int) -> None:
        self.k[0] = self._crc(self.k[0], b)
        self.k[1] = ((self.k[1] + (self.k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k[2] = self._crc(self.k[2], self.k[1] >> 24)

    def stream_byte(self) -> int:
        t = (self.k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, plain: bytes) -> bytes:
        out = bytearray()
        for p in plain:
            out.append(p ^ self.stream_byte())
            self.update(p)
        return bytes(out)


def build_zipcrypto_zip(name: str, content: bytes, password: str) -> bytes:
    """Single-file ZIP, stored (no compression), encrypted with ZipCrypto."""
    crc    = zlib.crc32(content) & 0xFFFFFFFF
    header = bytes(range(1, 12)) + bytes([crc >> 24])         # 11 filler bytes + check byte
    body   = _ZipCryptoKeys(password.encode()).encrypt(header + content)
    nm     = name.encode()
    local  = struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', 20, 1, 0, 0, 0x21, crc, len(body), len(content), len(nm), 0) + nm + body
    central = struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', 20, 20, 1, 0, 0, 0x21, crc,
                          len(body), len(content), len(nm), 0, 0, 0, 0, 0, 0) + nm
    eocd = struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


# ── PDF ──────────────────────────────────────────────────────────────────────

def build_pdf(streams: list[bytes], extra_objects: bytes = b'') -> bytes:
    """Minimal PDF whose content streams are Flate-compressed."""
    out = b'%PDF-1.4\n'
    for i, raw in enumerate(streams, 1):
        comp = zlib.compress(raw)
        out += (f'{i} 0 obj\n<< /Length {len(comp)} /Filter /FlateDecode >>\nstream\n').encode() + comp + b'\nendstream\nendobj\n'
    return out + extra_objects + b'trailer\n<< /Root 1 0 R >>\n%%EOF\n'

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


# ── Full synthetic PE builder ─────────────────────────────────────────────────

def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


DEFAULT_IMPORTS = {
    'KERNEL32.dll': ['ExitProcess', 'GetLastError', 'GetModuleHandleA', 'CreateFileA', 'ReadFile',
                     'WriteFile', 'CloseHandle', 'GetCommandLineA'],
    'USER32.dll':   ['MessageBoxA', 'GetMessageA'],
}


def build_pe(
    *,
    is64: bool = True,
    sections: list[dict] | None = None,
    imports: dict[str, list[str]] | None = None,
    timestamp: int = 1_700_000_000,
    entry_section: int = 0,
    dll: bool = False,
    subsystem: int = 3,
    tls_callbacks: int = 0,
    clr: bool = False,
    overlay: bytes = b'',
    cert: bytes = b'',
    export_names: list[str] | None = None,
) -> bytes:
    """
    Spec-conforming PE32/PE32+ assembled from parts (no compiler needed).
    sections: [{'name', 'data', 'flags', 'vsize'(optional)}]; data=b'' with a vsize gives an
    on-disk-empty section (UPX0 style). imports=None uses a plausible default table, {} means none.
    """
    width   = 8 if is64 else 4
    imports = DEFAULT_IMPORTS if imports is None else imports
    sections = sections if sections is not None else [
        {'name': '.text', 'data': b'\x55\x8b\xec' + bytes(range(32, 120)) * 6, 'flags': 0x60000020},
        {'name': '.data', 'data': b'hello world, plain data section. ' * 20, 'flags': 0xC0000040},
    ]
    entries = [dict(s) for s in sections]
    if imports:
        entries.append({'name': '.idata', 'gen': 'idata', 'flags': 0x40000040})
    if export_names:
        entries.append({'name': '.edata', 'gen': 'edata', 'flags': 0x40000040})
    if tls_callbacks:
        entries.append({'name': '.tls', 'gen': 'tls', 'flags': 0xC0000040})

    # Pass 1: RVAs (generated sections are sized after their content, so assign provisional pages).
    optsize  = 240 if is64 else 224
    nsec     = len(entries)
    hdr_size = _align(0x80 + 24 + optsize + 40 * nsec, 0x200)
    image_base = 0x140000000 if is64 else 0x400000
    rva = 0x1000
    for e in entries:
        e['rva'] = rva
        provisional = len(e.get('data', b'')) if 'gen' not in e else 0x1000
        rva += _align(max(e.get('vsize', 0), provisional, 1), 0x1000)
    dirs = {}

    def idata(base: int) -> bytes:
        dlls = list(imports.items())
        desc = (len(dlls) + 1) * 20
        pos, int_pos, iat_pos = desc, [], []
        for _d, fs in dlls:
            int_pos.append(pos); pos += (len(fs) + 1) * width
        for _d, fs in dlls:
            iat_pos.append(pos); pos += (len(fs) + 1) * width
        hn: list[list[int]] = []
        blob = bytearray()
        for _d, fs in dlls:
            row = []
            for f in fs:
                if f.startswith('#'):
                    row.append(-1); continue
                row.append(pos + len(blob))
                entry = struct.pack('<H', 0) + f.encode() + b'\x00'
                blob += entry + (b'\x00' if len(entry) % 2 else b'')
            hn.append(row)
        name_pos = []
        for d, _fs in dlls:
            name_pos.append(pos + len(blob)); blob += d.encode() + b'\x00'
        out = bytearray(pos + len(blob))
        out[pos:] = blob
        ordflag = 1 << (63 if is64 else 31)
        for k, (_d, fs) in enumerate(dlls):
            struct.pack_into('<IIIII', out, 20 * k, base + int_pos[k], 0, 0, base + name_pos[k], base + iat_pos[k])
            for j, f in enumerate(fs):
                val = (ordflag | int(f[1:])) if f.startswith('#') else base + hn[k][j]
                for arr in (int_pos[k], iat_pos[k]):
                    struct.pack_into('<Q' if is64 else '<I', out, arr + width * j, val)
        dirs[1] = (base, desc)
        return bytes(out)

    def edata(base: int) -> bytes:
        names = export_names or []
        n = len(names)
        head = 40
        addr, nptr, ords = head, head + 4 * n, head + 8 * n
        strs_at = head + 10 * n
        blob, name_rvas = bytearray(), []
        for nm in names:
            name_rvas.append(base + strs_at + len(blob)); blob += nm.encode() + b'\x00'
        dll_name_rva = base + strs_at + len(blob); blob += b'sample.dll\x00'
        out = bytearray(strs_at) + blob
        struct.pack_into('<IIHHIIIIIII', out, 0, 0, 0, 0, 0, dll_name_rva, 1, n, n, base + addr, base + nptr, base + ords)
        for i in range(n):
            struct.pack_into('<I', out, addr + 4 * i, 0x1000)
            struct.pack_into('<I', out, nptr + 4 * i, name_rvas[i])
            struct.pack_into('<H', out, ords + 2 * i, i)
        dirs[0] = (base, len(out))
        return bytes(out)

    def tls(base: int) -> bytes:
        dir_size = 40 if is64 else 24
        idx_at, cb_at, raw_at = dir_size, dir_size + 8, dir_size + 8 + (tls_callbacks + 1) * width
        out = bytearray(raw_at + 8)
        code_va = image_base + 0x1000
        fmt = '<QQQQII' if is64 else '<IIIIII'
        struct.pack_into(fmt, out, 0, image_base + base + raw_at, image_base + base + raw_at + 8,
                         image_base + base + idx_at, image_base + base + cb_at, 0, 0)
        for i in range(tls_callbacks):
            struct.pack_into('<Q' if is64 else '<I', out, cb_at + width * i, code_va + 0x10 * i)
        dirs[9] = (base, dir_size)
        return bytes(out)

    for e in entries:
        if 'gen' in e:
            e['data'] = {'idata': idata, 'edata': edata, 'tls': tls}[e['gen']](e['rva'])
    if clr:
        dirs[14] = (0x1000, 0x48)

    # Pass 2: file layout
    raw_ptr = hdr_size
    for e in entries:
        data = e.get('data', b'')
        e['rsize'] = _align(len(data), 0x200) if data else 0
        e['rptr']  = raw_ptr if data else 0
        e['vsize_f'] = max(e.get('vsize', 0), len(data))
        raw_ptr += e['rsize']
    last_rva_end = max((e['rva'] + _align(max(e['vsize_f'], 1), 0x1000) for e in entries), default=0x1000)

    out = bytearray(hdr_size)
    out[0:2] = b'MZ'
    struct.pack_into('<I', out, 0x3C, 0x80)
    out[0x80:0x84] = b'PE\x00\x00'
    chars = (0x22 if is64 else 0x102) | (0x2000 if dll else 0)
    struct.pack_into('<HHIIIHH', out, 0x84, 0x8664 if is64 else 0x14C, nsec, timestamp, 0, 0, optsize, chars)
    opt = 0x98
    struct.pack_into('<H', out, opt, 0x20B if is64 else 0x10B)
    struct.pack_into('<I', out, opt + 16, entries[entry_section]['rva'] if entries else 0)
    if is64:
        struct.pack_into('<Q', out, opt + 24, image_base)
    else:
        struct.pack_into('<I', out, opt + 28, image_base)
    struct.pack_into('<IIIIH', out, opt + 32, 0x1000, 0x200, 0, 0, 0)       # alignments, versions (unused)
    struct.pack_into('<I', out, opt + 56, last_rva_end)
    struct.pack_into('<I', out, opt + 60, hdr_size)
    struct.pack_into('<HH', out, opt + 68, subsystem, 0x8160)
    struct.pack_into('<I', out, opt + (108 if is64 else 92), 16)
    dd = opt + (112 if is64 else 96)

    body = b''.join(e.get('data', b'').ljust(e['rsize'], b'\x00') for e in entries)
    file_end = hdr_size + len(body) + len(overlay)
    if cert:
        dirs[4] = (file_end, len(cert))
    for k, (r, sz) in dirs.items():
        struct.pack_into('<II', out, dd + 8 * k, r, sz)
    table = opt + optsize
    for i, e in enumerate(entries):
        name = e['name'].encode()[:8].ljust(8, b'\x00')
        struct.pack_into('<8sIIIIIIHHI', out, table + 40 * i, name, e['vsize_f'], e['rva'],
                         e['rsize'], e['rptr'], 0, 0, 0, 0, e['flags'])
    return bytes(out) + body + overlay + cert

"""
Defensive PE (Windows executable) parser — stdlib only.

Parses just what triage needs: headers, sections (with entropy), import and
export tables, TLS callbacks, overlay, Authenticode presence, CLR header.
Input is assumed hostile: every read is bounds-checked, counts are capped, and
damage never raises past parse_pe() — it is recorded in PEInfo.warnings instead.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from .utils import shannon_entropy

MAX_SECTIONS     = 96
MAX_IMPORT_DLLS  = 256
MAX_IMPORT_FUNCS = 8000
MAX_EXPORTS      = 2000
MAX_TLS_CALLBACKS = 16

# Section characteristics
SCN_EXEC  = 0x20000000
SCN_READ  = 0x40000000
SCN_WRITE = 0x80000000
SCN_CODE  = 0x00000020

MACHINES = {
    0x14C: 'x86', 0x8664: 'x86-64', 0x1C0: 'ARM', 0x1C4: 'ARMv7 (Thumb-2)',
    0xAA64: 'ARM64', 0x200: 'IA-64', 0x5064: 'RISC-V 64',
}
SUBSYSTEMS = {
    1: 'Native (driver)', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console',
    7: 'POSIX console', 9: 'Windows CE', 10: 'EFI application', 11: 'EFI boot driver',
    12: 'EFI runtime driver', 14: 'Xbox', 16: 'Windows boot application',
}
DLL_CHARACTERISTICS = [
    (0x0020, 'high-entropy ASLR'), (0x0040, 'ASLR'), (0x0100, 'DEP/NX'),
    (0x0400, 'no SEH'), (0x4000, 'CFG'),
]


@dataclass
class Section:
    name:    str
    vsize:   int
    vaddr:   int
    rsize:   int
    rptr:    int
    flags:   int
    entropy: float
    md5:     str

    @property
    def executable(self) -> bool:
        return bool(self.flags & (SCN_EXEC | SCN_CODE))

    @property
    def perms(self) -> str:
        return (
            ('r' if self.flags & SCN_READ else '-')
            + ('w' if self.flags & SCN_WRITE else '-')
            + ('x' if self.flags & SCN_EXEC else '-')
        )


@dataclass
class PEInfo:
    machine:        int
    is64:           bool
    timestamp:      int
    characteristics: int
    subsystem:      int
    dll_chars:      int
    entry_rva:      int
    image_base:     int
    size_of_image:  int
    sections:       list[Section]
    dirs:           list[tuple[int, int]]
    imports:        dict[str, list[str]] = field(default_factory=dict)
    exports:        list[str]            = field(default_factory=list)
    tls_callbacks:  int                  = 0
    overlay_offset: int | None           = None
    overlay_size:   int                  = 0
    cert_offset:    int                  = 0
    cert_size:      int                  = 0
    clr:            bool                 = False
    warnings:       list[str]            = field(default_factory=list)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())

    def section_for_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.rsize):
                return s
        return None

    def imphash(self) -> str:
        """MD5 over 'dll.function' pairs (same recipe as pefile; ordinals are 'ordN')."""
        parts: list[str] = []
        for dll, funcs in self.imports.items():
            base = dll.lower()
            for ext in ('.dll', '.ocx', '.sys'):
                if base.endswith(ext):
                    base = base[:-len(ext)]
                    break
            for f in funcs:
                name = f'ord{f[1:]}' if f.startswith('#') else f.lower()
                parts.append(f'{base}.{name}')
        return hashlib.md5(','.join(parts).encode()).hexdigest() if parts else ''


class _Reader:
    """Bounds-checked little-endian reads over the raw file bytes."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def u16(self, off: int) -> int:
        if off < 0 or off + 2 > len(self.data):
            raise ValueError(f'read outside file at 0x{off:X}')
        return struct.unpack_from('<H', self.data, off)[0]

    def u32(self, off: int) -> int:
        if off < 0 or off + 4 > len(self.data):
            raise ValueError(f'read outside file at 0x{off:X}')
        return struct.unpack_from('<I', self.data, off)[0]

    def u64(self, off: int) -> int:
        if off < 0 or off + 8 > len(self.data):
            raise ValueError(f'read outside file at 0x{off:X}')
        return struct.unpack_from('<Q', self.data, off)[0]

    def cstr(self, off: int, limit: int = 256) -> str:
        if off < 0 or off >= len(self.data):
            raise ValueError(f'string outside file at 0x{off:X}')
        end = self.data.find(b'\x00', off, off + limit)
        end = off + limit if end == -1 else end
        return self.data[off:end].decode('latin-1')


def parse_pe(data: bytes) -> PEInfo | None:
    """Return PEInfo, or None when data is not a PE at all. Partial damage → warnings."""
    if len(data) < 0x40 or data[:2] != b'MZ':
        return None
    r = _Reader(data)
    try:
        e_lfanew = r.u32(0x3C)
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return None
        machine, nsec, timestamp, _sym, _nsym, optsize, chars = struct.unpack_from(
            '<HHIIIHH', data, e_lfanew + 4)
        opt   = e_lfanew + 24
        magic = r.u16(opt)
        if magic == 0x10B:
            is64, dd_off, base_off, nrva_off = False, opt + 96, opt + 28, opt + 92
            image_base = r.u32(base_off)
        elif magic == 0x20B:
            is64, dd_off, base_off, nrva_off = True, opt + 112, opt + 24, opt + 108
            image_base = r.u64(base_off)
        else:
            return None
        info = PEInfo(
            machine=machine, is64=is64, timestamp=timestamp, characteristics=chars,
            subsystem=r.u16(opt + 68), dll_chars=r.u16(opt + 70),
            entry_rva=r.u32(opt + 16), image_base=image_base,
            size_of_image=r.u32(opt + 56), sections=[], dirs=[],
        )
        for i in range(min(r.u32(nrva_off), 16)):
            if dd_off + 8 * (i + 1) > opt + optsize or dd_off + 8 * (i + 1) > len(data):
                break
            info.dirs.append((r.u32(dd_off + 8 * i), r.u32(dd_off + 8 * i + 4)))
    except (ValueError, struct.error):
        return None

    _read_sections(data, r, info, e_lfanew + 24 + optsize, nsec)
    for step in (_read_imports, _read_exports, _read_tls):
        try:
            step(data, r, info)
        except (ValueError, struct.error) as e:
            info.warnings.append(f'{step.__name__.removeprefix("_read_")}: {e}')
    _find_overlay(data, info)
    info.clr = len(info.dirs) > 14 and info.dirs[14][0] != 0 and info.dirs[14][1] != 0
    return info


def _read_sections(data: bytes, r: _Reader, info: PEInfo, table: int, nsec: int) -> None:
    if nsec > MAX_SECTIONS:
        info.warnings.append(f'{nsec} sections declared; only the first {MAX_SECTIONS} are read')
    for i in range(min(nsec, MAX_SECTIONS)):
        off = table + 40 * i
        if off + 40 > len(data):
            info.warnings.append('section table is truncated')
            break
        name = data[off:off + 8].rstrip(b'\x00').decode('latin-1')
        vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, off + 8)
        flags = struct.unpack_from('<I', data, off + 36)[0]
        raw = data[rptr:rptr + rsize] if rsize else b''
        if rsize and rptr + rsize > len(data):
            info.warnings.append(f'section {name or i} raw data extends past end of file')
        info.sections.append(Section(
            name=name, vsize=vsize, vaddr=vaddr, rsize=rsize, rptr=rptr, flags=flags,
            entropy=shannon_entropy(raw) if raw else 0.0,
            md5=hashlib.md5(raw).hexdigest() if raw else '',
        ))


def _rva_to_off(info: PEInfo, rva: int) -> int | None:
    for s in info.sections:
        if s.rsize and s.vaddr <= rva < s.vaddr + max(s.vsize, s.rsize):
            return rva - s.vaddr + s.rptr
    return rva if rva < 0x400 else None          # header area


def _read_imports(data: bytes, r: _Reader, info: PEInfo) -> None:
    if len(info.dirs) < 2 or not info.dirs[1][0]:
        return
    desc = _rva_to_off(info, info.dirs[1][0])
    if desc is None:
        raise ValueError('import directory RVA is not inside any section')
    width, ord_flag = (8, 1 << 63) if info.is64 else (4, 1 << 31)
    total = 0
    for i in range(MAX_IMPORT_DLLS):
        base = desc + 20 * i
        original, _ts, _fwd, name_rva, first = struct.unpack_from('<IIIII', data, base) \
            if base + 20 <= len(data) else (0, 0, 0, 0, 0)
        if not name_rva and not first:
            break
        name_off = _rva_to_off(info, name_rva)
        if name_off is None:
            raise ValueError('import DLL name RVA is not inside any section')
        dll   = r.cstr(name_off)
        table = _rva_to_off(info, original or first)
        funcs: list[str] = []
        if table is not None:
            for j in range(4096):
                if total >= MAX_IMPORT_FUNCS:
                    info.warnings.append('import list truncated')
                    break
                off   = table + width * j
                entry = r.u64(off) if info.is64 else r.u32(off)
                if entry == 0:
                    break
                if entry & ord_flag:
                    funcs.append(f'#{entry & 0xFFFF}')
                else:
                    hn = _rva_to_off(info, entry & 0x7FFFFFFF)
                    funcs.append(r.cstr(hn + 2) if hn is not None else '?')
                total += 1
        info.imports.setdefault(dll, []).extend(funcs)


def _read_exports(data: bytes, r: _Reader, info: PEInfo) -> None:
    if not info.dirs or not info.dirs[0][0]:
        return
    off = _rva_to_off(info, info.dirs[0][0])
    if off is None:
        raise ValueError('export directory RVA is not inside any section')
    count     = min(r.u32(off + 24), MAX_EXPORTS)
    names_off = _rva_to_off(info, r.u32(off + 32))
    if names_off is None:
        return
    for i in range(count):
        name_off = _rva_to_off(info, r.u32(names_off + 4 * i))
        if name_off is not None:
            info.exports.append(r.cstr(name_off))


def _read_tls(data: bytes, r: _Reader, info: PEInfo) -> None:
    if len(info.dirs) < 10 or not info.dirs[9][0]:
        return
    off = _rva_to_off(info, info.dirs[9][0])
    if off is None:
        return
    callbacks_va = r.u64(off + 24) if info.is64 else r.u32(off + 12)
    if not callbacks_va:
        return
    arr = _rva_to_off(info, callbacks_va - info.image_base)
    if arr is None:
        return
    width = 8 if info.is64 else 4
    for i in range(MAX_TLS_CALLBACKS):
        va = r.u64(arr + width * i) if info.is64 else r.u32(arr + width * i)
        if va == 0:
            break
        info.tls_callbacks += 1


def _find_overlay(data: bytes, info: PEInfo) -> None:
    """Bytes after the last section's raw data. An Authenticode blob is not counted as overlay."""
    ends = [s.rptr + s.rsize for s in info.sections if s.rsize]
    if not ends:
        return
    end = max(ends)
    if len(info.dirs) > 4 and info.dirs[4][0] and info.dirs[4][1]:
        info.cert_offset, info.cert_size = info.dirs[4]
    stop = info.cert_offset if info.cert_offset >= end else len(data)
    if stop > end:
        info.overlay_offset = end
        info.overlay_size   = stop - end

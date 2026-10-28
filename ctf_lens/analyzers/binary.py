"""
Executable file analyzer: ELF, PE (EXE/DLL), Java CLASS.
Entry point: analyze_executable(data, result)
Note: result._strings_cache must be populated by analyze() before calling this.
"""

import struct

from ..config import INTERESTING_KEYWORDS, MIN_STRING_LEN_EXEC
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, flag_is_clean
from .pe import analyze_pe


def analyze_executable(data: bytes, result: AnalysisResult) -> None:
    """Analyze binary: extract interesting strings, dispatch ELF/PE specific checks."""
    strings = result._strings_cache  # guaranteed populated by core.analyze()

    result.findings.append(Finding(
        title       = f'Strings in binary ({len(strings)})',
        severity    = 'INFO',
        description = f'Extracted strings longer than {MIN_STRING_LEN_EXEC} characters.',
        technique   = 'Binary Analysis',
    ))

    interesting: list[str] = []
    for s in strings:
        if looks_like_flag(s) and flag_is_clean(s):
            result.findings.append(Finding(
                title       = '🚩 Flag in binary!',
                severity    = 'HIGH',
                description = 'String matches a flag pattern.',
                data        = s,
                technique   = 'Binary Analysis',
            ))
        elif any(kw in s.lower() for kw in INTERESTING_KEYWORDS):
            interesting.append(s)

    if interesting:
        result.findings.append(Finding(
            title       = f'Interesting strings ({len(interesting)})',
            severity    = 'MEDIUM',
            description = 'Strings containing keywords:',
            data        = '\n'.join(interesting[:20]),
            technique   = 'Binary Analysis',
        ))

    if result.filetype == 'ELF':
        _analyze_elf(data, result)
    elif result.filetype == 'EXE':
        analyze_pe(data, result)


def _analyze_elf(data: bytes, result: AnalysisResult) -> None:
    if len(data) < 64:
        return

    elf_class = data[4]
    ei_data   = data[5]
    e_machine = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 18)[0]

    arch_map = {
        0x03: 'x86', 0x3E: 'x86-64', 0x28: 'ARM', 0xB7: 'AArch64',
        0x08: 'MIPS', 0x14: 'PowerPC', 0x02: 'SPARC',
    }
    arch   = arch_map.get(e_machine, f'unknown (0x{e_machine:04X})')
    bits   = '64-bit' if elf_class == 2 else '32-bit'
    endian = 'little-endian' if ei_data == 1 else 'big-endian'

    result.findings.append(Finding(
        title       = f'ELF binary: {bits} {arch} {endian}',
        severity    = 'INFO',
        description = 'For analysis: objdump, readelf, gdb, ghidra, radare2.',
        technique   = 'ELF Analysis',
    ))

    # Use the cached strings (already lowercased set) to avoid .lower() on 512 MB
    elf_strings_lower = {s.lower() for s in result._strings_cache}
    if b'.ctf' in data or any('flag' in s or 'ctf' in s for s in elf_strings_lower):
        result.findings.append(Finding(
            title       = 'Suspicious ELF sections',
            severity    = 'HIGH',
            description = "ELF contains sections or data named 'flag' or 'ctf'.",
            technique   = 'ELF Analysis',
        ))

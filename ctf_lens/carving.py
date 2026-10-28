"""
Embedded-file carving with structural validation.

Replaces the old "does this 2-byte magic occur anywhere" check, which fired on
random/compressed data (MZ, 0x1f8b) and on every ZIP member header.
"""

from __future__ import annotations

from .config import (
    EMBEDDED_SIGNATURES, MIN_EMBEDDED_OFFSET, MAX_CARVE_PER_TYPE, SELF_NESTING_TYPES,
)
from .models import Finding, AnalysisResult
from .signatures import validate


def find_embedded(data: bytes, result: AnalysisResult) -> None:
    for sig, name in EMBEDDED_SIGNATURES:
        if name == result.filetype and name in SELF_NESTING_TYPES:
            continue
        offset = MIN_EMBEDDED_OFFSET
        found  = 0
        while found < MAX_CARVE_PER_TYPE:
            pos = data.find(sig, offset)
            if pos == -1:
                break
            offset = pos + len(sig)
            if pos + len(sig) + 16 > len(data):
                continue
            if not validate(name, data, pos):
                continue
            result.findings.append(Finding(
                title       = f'Embedded {name} file',
                severity    = 'HIGH',
                description = (
                    f'Valid {name} header found at offset {pos}. '
                    'A file is hidden inside this file — classic CTF technique.'
                ),
                data        = f'Offset: {pos} bytes (0x{pos:X})',
                technique   = 'File Carving',
                hint        = 'Re-run with --extract DIR to save it.',
                offset      = pos,
            ))
            result.carved.append((name, pos))
            found += 1
        if found == MAX_CARVE_PER_TYPE:
            result.findings.append(Finding(
                title       = f'Embedded {name}: showing first {MAX_CARVE_PER_TYPE} occurrences',
                severity    = 'INFO',
                description = f'Limit reached — there may be more {name} files.',
                technique   = 'File Carving',
            ))

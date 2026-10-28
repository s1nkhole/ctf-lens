"""
--extract DIR: write carved files, trailing data and decoded binary layers to disk.
Names are generated here (never taken from file contents), so nothing can escape DIR.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import AnalysisResult
from .signatures import estimate_end, extension_for


def _slug(text: str, limit: int = 40) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', text).strip('_')[:limit] or 'file'


def save_artifacts(data: bytes, result: AnalysisResult, outdir: str) -> list[str]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    base    = _slug(Path(result.filepath).stem)
    written: list[str] = []

    for kind, pos in result.carved:
        if kind in ('TRAILING', 'OVERLAY'):
            end, ext, label = len(data), 'bin', kind.lower()
        else:
            end, ext, label = estimate_end(kind, data, pos), extension_for(kind), kind.lower()
        path = out / f'{base}_{label}_0x{pos:x}.{ext}'
        path.write_bytes(data[pos:end])
        written.append(str(path))

    for i, (chain, blob) in enumerate(result.layers, 1):
        path = out / f'{base}_layer{i}_{_slug(chain)}.bin'
        path.write_bytes(blob)
        written.append(str(path))

    return written

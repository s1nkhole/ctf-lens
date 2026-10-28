"""
LSB steganography analysis for images.
Separated from audio LSB so each analyzer owns its own bit-extraction logic.
"""

import re
import string
from .._lsb_common import lsb_entropy, lsb_bits_to_bytes
from ..config import (
    LSB_ENTROPY_THRESHOLD, LSB_ENTROPY_EMPTY,
)
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, detect_filetype
from ..registry import register_flag


def extract_lsb_text(lsb_bits, result: AnalysisResult, source: str) -> None:
    """
    Extract text from LSB bits and add a finding.
    source — human-readable label ('channel R', 'audio samples', etc.)
    """
    sample_bytes = lsb_bits_to_bytes(lsb_bits)
    if not sample_bytes:
        return

    try:
        text     = sample_bytes.decode('utf-8', errors='ignore')
        readable = ''.join(c for c in text if c in string.printable)
        if len(readable) >= 5:
            if looks_like_flag(readable):
                register_flag(
                    readable, result,
                    source=f'LSB [{source}]',
                    hint='Extract fully: zsteg image.png  or  stegsolve → Extract LSB',
                )
            else:
                result.decoded.append(Finding(
                    title       = 'LSB data',
                    severity    = 'INFO',
                    description = f'Text extracted from LSB [{source}]:',
                    data        = readable[:200],
                    technique   = 'LSB Steganography',
                ))
    except Exception:
        pass

    # Show hex only if there is anything non-zero
    if any(b != 0 for b in sample_bytes):
        result.decoded.append(Finding(
            title       = f'LSB hex [{source}]',
            severity    = 'INFO',
            description = 'First bytes from LSB (hex):',
            data        = sample_bytes.hex(),
            technique   = 'LSB Steganography',
        ))


def analyze_lsb_image(arr, mode: str, result: AnalysisResult, deep: bool = False) -> None:
    """
    Per-channel LSB analysis for an image numpy array.
    Logic:
      entropy < LSB_ENTROPY_EMPTY  → uniform channel (solid colour) — NOT stego
      entropy < LSB_ENTROPY_THRESHOLD → bits are non-random — STEGO suspect
      entropy ≈ 1.0                → random bits — normal for a real photo
    """
    import numpy as np

    channel_map: dict[str, list[tuple[int, str]]] = {
        'RGB':  [(0, 'R'), (1, 'G'), (2, 'B')],
        'RGBA': [(0, 'R'), (1, 'G'), (2, 'B'), (3, 'A')],
        'L':    [(0, 'L')],
    }
    channels    = channel_map.get(mode, [(0, 'CH0')])
    stego_found = False

    for ch_idx, ch_name in channels:
        lsb_bits = (arr & 1).flatten() if mode == 'L' else (arr[:, :, ch_idx] & 1).flatten()
        entropy  = lsb_entropy(lsb_bits)

        if entropy < LSB_ENTROPY_EMPTY:
            result.findings.append(Finding(
                title       = f'LSB channel {ch_name} — uniform',
                severity    = 'INFO',
                description = (
                    f'LSB entropy of channel {ch_name}: {entropy:.3f}. '
                    'All pixels are the same colour; no steganography.'
                ),
                technique   = 'LSB Steganography',
            ))
        elif entropy < LSB_ENTROPY_THRESHOLD:
            stego_found = True
            result.findings.append(Finding(
                title       = f'⚠️ LSB stego suspect — channel {ch_name}',
                severity    = 'HIGH',
                description = (
                    f'LSB entropy of channel {ch_name}: {entropy:.3f} (normal ≈ 1.0). '
                    'Non-random bits — indicates LSB steganography.'
                ),
                hint        = (
                    'Use stegsolve (Java), zsteg (Ruby: gem install zsteg), '
                    'or online: stylesuxx.github.io/steganography'
                ),
                technique   = 'LSB Steganography',
            ))
            extract_lsb_text(lsb_bits, result, f'channel {ch_name}')

    # Bit-plane analysis only when no LSB stego was found
    if not stego_found and mode in ('RGB', 'RGBA'):
        for bit in (1, 2):
            plane_bits = (arr[:, :, 0] >> bit & 1).flatten()
            plane_ent  = lsb_entropy(plane_bits)
            if LSB_ENTROPY_EMPTY < plane_ent < LSB_ENTROPY_THRESHOLD:
                result.findings.append(Finding(
                    title       = f'⚠️ Suspicious bit-plane {bit} of channel R',
                    severity    = 'MEDIUM',
                    description = (
                        f'Bit-plane {bit} entropy of channel R: {plane_ent:.3f}. '
                        'Data may be hidden beyond the LSB.'
                    ),
                    hint        = 'Try stegsolve → Bit Plane Browser for visualisation.',
                    technique   = 'LSB Steganography',
                ))

    # Independent of the entropy verdict above: short messages hide in noisy channels.
    bruteforce_lsb(arr, mode, result, deep=deep)


# ── Brute-force extraction ────────────────────────────────────────────────────
# Entropy alone cannot find a SHORT message in an otherwise noisy channel
# (a 32-byte flag in a 200x100 photo leaves the LSB entropy at 0.9999), so the
# detector above misses it. Instead we try the common embedding layouts and score
# what falls out: a readable run, a flag, or a file signature at the start.

_BF_BITS         = 32_768          # bits examined per candidate (4 KiB)
_BF_BIG_BITS     = 8 * 1024 * 1024 # bits kept when a hidden file is confirmed (1 MiB)
_RE_PRINTABLE_RUN = re.compile(rb'[\t\n\r\x20-\x7e]{6,}')
_BF_FILE_TYPES   = frozenset({
    'PNG', 'JPEG', 'GIF', 'ZIP', 'GZIP', 'BZIP2', 'XZ', '7ZIP', 'RAR', 'PDF',
    'ELF', 'EXE', 'SQLITE',
})


def _bf_bits(arr, idx: list[int], plane: int, order: str, nbits: int):
    """First nbits of the chosen bit-plane, reading pixels row- or column-major."""
    import numpy as np
    h, w, _ = arr.shape
    per_pixel = len(idx)
    if order == 'rows':
        rows = min(h, -(-nbits // (w * per_pixel)))
        sub  = arr[:rows][:, :, idx]
    else:
        cols = min(w, -(-nbits // (h * per_pixel)))
        sub  = arr[:, :cols][:, :, idx].transpose(1, 0, 2)
    return ((sub >> plane) & 1).astype(np.uint8).reshape(-1)[:nbits]


def _bf_bytes(bits, bitorder: str) -> bytes:
    import numpy as np
    n = (len(bits) // 8) * 8
    if n == 0:
        return b''
    return np.packbits(bits[:n], bitorder='big' if bitorder == 'msb' else 'little').tobytes()


def _readable_text(blob: bytes) -> str | None:
    """Leading human-readable message in blob (plain, or 4-byte big-endian length prefix)."""
    m = _RE_PRINTABLE_RUN.match(blob)
    if m and len(set(m.group(0))) >= 5:
        return m.group(0).decode('ascii')
    if len(blob) > 10:
        length = int.from_bytes(blob[:4], 'big')
        body   = blob[4:4 + length]
        if 6 <= length <= len(blob) - 4 and body and all(
            32 <= b < 127 or b in (9, 10, 13) for b in body
        ) and len(set(body)) >= 5:
            return body.decode('ascii')
    return None


def bruteforce_lsb(arr, mode: str, result: AnalysisResult, deep: bool = False) -> None:
    """Try channel subsets x bit-planes x scan order x bit order; report what decodes."""
    import numpy as np

    if mode not in ('RGB', 'RGBA', 'L'):
        return
    if arr.ndim == 2:
        arr = arr[:, :, None]
    if arr.shape[0] == 0 or arr.shape[1] == 0:
        return
    arr = arr.astype(np.uint8, copy=False)

    names  = {'L': ['L'], 'RGB': ['R', 'G', 'B'], 'RGBA': ['R', 'G', 'B', 'A']}[mode]
    combos: list[tuple[str, list[int]]] = [(n, [i]) for i, n in enumerate(names)]
    if len(names) >= 3:
        combos += [('RGB', [0, 1, 2]), ('BGR', [2, 1, 0])]
    if len(names) == 4:
        combos += [('RGBA', [0, 1, 2, 3]), ('ABGR', [3, 2, 1, 0])]

    planes     = (0, 1) if deep else (0,)
    texts_seen: set[str] = set()
    reported   = 0

    for name, idx in combos:
        for plane in planes:
            for order in ('rows', 'cols'):
                bits = _bf_bits(arr, idx, plane, order, _BF_BITS)
                for bitorder in ('msb', 'lsb'):
                    blob  = _bf_bytes(bits, bitorder)
                    label = f'{name} bit {plane}, {order}, {bitorder}-first'

                    ftype, _cat = detect_filetype(blob[:64]) if len(blob) >= 16 else ('UNKNOWN', '')
                    if ftype in _BF_FILE_TYPES:
                        big = _bf_bytes(_bf_bits(arr, idx, plane, order, _BF_BIG_BITS), bitorder)
                        result.findings.append(Finding(
                            title       = f'File hidden in LSB ({ftype})',
                            severity    = 'HIGH',
                            description = f'A {ftype} signature decodes from LSB [{label}].',
                            hint        = 'Re-run with --extract DIR to save the decoded bytes.',
                            technique   = 'LSB Steganography',
                        ))
                        result.layers.append((f'LSB {label} → {ftype}', big))
                        continue

                    text = _readable_text(blob)
                    if not text or text in texts_seen:
                        continue
                    texts_seen.add(text)
                    if looks_like_flag(text):
                        register_flag(
                            text, result, source=f'LSB [{label}]',
                            hint='Same extraction: zsteg -a image.png  or  stegsolve → Data Extract',
                        )
                    elif reported < 3:
                        reported += 1
                        result.decoded.append(Finding(
                            title       = f'LSB text [{label}]',
                            severity    = 'INFO',
                            description = 'Readable text decoded from LSB bits:',
                            data        = text[:200],
                            technique   = 'LSB Steganography',
                        ))

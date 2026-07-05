"""
LSB steganography analysis for images.
Separated from audio LSB so each analyzer owns its own bit-extraction logic.
"""

import string
from .._lsb_common import lsb_entropy, lsb_bits_to_bytes
from ..config import (
    LSB_ENTROPY_THRESHOLD, LSB_ENTROPY_EMPTY,
)
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag
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


def analyze_lsb_image(arr, mode: str, result: AnalysisResult) -> None:
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

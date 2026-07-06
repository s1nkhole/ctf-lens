"""
Audio file analyzer: WAV, MP3, FLAC.
Each format owns its own LSB extraction logic (audio samples ≠ image pixels).
Entry point: analyze_audio(data, result)
"""

import struct

from ..config import (
    WAV_STANDARD_CHUNKS, LSB_ENTROPY_THRESHOLD,
)
from .._lsb_common import lsb_entropy, lsb_bits_to_bytes
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, safe_decode, extract_strings, flag_is_clean
from ..registry import register_flag

import string as _string


# ── Entry point ───────────────────────────────────────────────────────────────

def analyze_audio(data: bytes, result: AnalysisResult) -> None:
    """Dispatch to format-specific audio analyzer."""
    try:
        if result.filetype == 'WAV':
            _analyze_wav(data, result)
        elif result.filetype == 'MP3':
            _analyze_mp3(data, result)
        elif result.filetype == 'FLAC':
            _analyze_flac(data, result)
    except Exception as e:
        result.findings.append(Finding(
            title       = 'Audio analysis error',
            severity    = 'INFO',
            description = str(e),
        ))


# ── WAV ───────────────────────────────────────────────────────────────────────

def _analyze_wav(data: bytes, result: AnalysisResult) -> None:
    """WAV: header params, LSB on samples, non-standard RIFF chunks."""
    if len(data) < 44:
        return

    try:
        channels    = struct.unpack_from('<H', data, 22)[0]
        sample_rate = struct.unpack_from('<I', data, 24)[0]
        bit_depth   = struct.unpack_from('<H', data, 34)[0]
    except struct.error:
        return

    result.findings.append(Finding(
        title       = 'WAV parameters',
        severity    = 'INFO',
        description = f'Channels: {channels}, sample rate: {sample_rate} Hz, bit depth: {bit_depth}',
        technique   = 'Audio Analysis',
    ))

    data_offset = _find_riff_chunk(data, b'data')
    if data_offset is not None and bit_depth in (8, 16):
        audio_bytes = data[data_offset + 8:]
        if len(audio_bytes) >= 100:
            _analyze_wav_lsb(audio_bytes, bit_depth, result)

    _scan_riff_chunks(data, result)


def _analyze_wav_lsb(audio_bytes: bytes, bit_depth: int, result: AnalysisResult) -> None:
    """LSB analysis on audio samples. Owns its own bit-extraction (samples ≠ pixels)."""
    try:
        import numpy as np

        dtype    = np.int16 if bit_depth == 16 else np.uint8
        samples  = np.frombuffer(audio_bytes[:min(len(audio_bytes), 200_000)], dtype=dtype)
        lsb_bits = samples & 1
        lsb_ent  = lsb_entropy(lsb_bits)

        if lsb_ent < LSB_ENTROPY_THRESHOLD:
            result.findings.append(Finding(
                title       = '⚠️ LSB stego suspect in audio',
                severity    = 'HIGH',
                description = (
                    f'LSB entropy of audio samples: {lsb_ent:.3f} (normal ≈ 1.0). '
                    'CTF challenges often hide data in audio LSB.'
                ),
                technique   = 'LSB Steganography',
            ))
            _extract_audio_lsb_text(lsb_bits, result)
        else:
            result.findings.append(Finding(
                title       = 'Audio LSB — normal',
                severity    = 'INFO',
                description = f'LSB entropy: {lsb_ent:.3f}',
                technique   = 'LSB Steganography',
            ))

    except ImportError:
        result.findings.append(Finding(
            title       = 'numpy not installed',
            severity    = 'INFO',
            description = 'For audio LSB analysis: pip install numpy',
            technique   = 'LSB Steganography',
        ))


def _extract_audio_lsb_text(lsb_bits, result: AnalysisResult) -> None:
    """Extract text from audio LSB bits and add a finding."""
    sample_bytes = lsb_bits_to_bytes(lsb_bits)
    if not sample_bytes:
        return

    try:
        text     = sample_bytes.decode('utf-8', errors='ignore')
        readable = ''.join(c for c in text if c in _string.printable)
        if len(readable) >= 5:
            if looks_like_flag(readable) and flag_is_clean(readable):
                register_flag(
                    readable, result,
                    source='LSB [audio samples]',
                    hint='Extract fully with Audacity or a custom script reading sample LSBs.',
                )
            else:
                result.decoded.append(Finding(
                    title       = 'Audio LSB data',
                    severity    = 'INFO',
                    description = 'Text extracted from audio sample LSBs:',
                    data        = readable[:200],
                    technique   = 'LSB Steganography',
                ))
    except Exception:
        pass

    if any(b != 0 for b in sample_bytes):
        result.decoded.append(Finding(
            title       = 'Audio LSB hex',
            severity    = 'INFO',
            description = 'First bytes from audio LSB (hex):',
            data        = sample_bytes.hex(),
            technique   = 'LSB Steganography',
        ))


def _find_riff_chunk(data: bytes, chunk_id: bytes) -> int | None:
    """
    Locate a RIFF chunk by ID via correct chunk-tree traversal (not .find()).
    data.find(b'data') gives false positives on ASCII strings in metadata.
    """
    pos = 12
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        try:
            clen = struct.unpack_from('<I', data, pos + 4)[0]
        except struct.error:
            break
        if cid == chunk_id:
            return pos
        if pos + 8 + clen > len(data):
            break
        if clen == 0:
            pos += 8
            continue
        pos += 8 + clen + (clen & 1)
    return None


def _scan_riff_chunks(data: bytes, result: AnalysisResult) -> None:
    """Report non-standard RIFF chunks (potential hiding spots)."""
    from ..config import WAV_SCAN_LIMIT
    pos = 12
    while pos + 8 <= min(len(data), WAV_SCAN_LIMIT):
        try:
            chunk_id  = data[pos:pos + 4].decode('ascii', errors='replace')
            chunk_len = struct.unpack_from('<I', data, pos + 4)[0]
            if pos + 8 + chunk_len > len(data):
                break
            if chunk_id not in WAV_STANDARD_CHUNKS:
                chunk_data = data[pos + 8: pos + 8 + min(chunk_len, 200)]
                result.findings.append(Finding(
                    title       = f"Non-standard WAV chunk: '{chunk_id}'",
                    severity    = 'HIGH',
                    description = f"Chunk '{chunk_id}' ({chunk_len} bytes) — may hide data.",
                    data        = f'First bytes: {chunk_data.hex()}',
                    technique   = 'Audio Chunks',
                ))
            pos += 8 + chunk_len + (chunk_len & 1)
            if chunk_len == 0:
                break
        except Exception:
            break


# ── MP3 ───────────────────────────────────────────────────────────────────────

# Bitrate table at module level — not recreated on every call
_MP3_BITRATE_TABLE = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]


def _analyze_mp3(data: bytes, result: AnalysisResult) -> None:
    """MP3: ID3 tags, trailing data after last frame."""
    if data[:3] == b'ID3':
        try:
            raw_size = struct.unpack_from('>I', data, 6)[0]
            id3_size = (
                ((raw_size >> 24) & 0x7F) << 21 |
                ((raw_size >> 16) & 0x7F) << 14 |
                ((raw_size >> 8)  & 0x7F) << 7  |
                ((raw_size)       & 0x7F)
            )
            tag_end     = 10 + id3_size
            id3_payload = data[10:tag_end]
            id3_text    = safe_decode(id3_payload)

            result.findings.append(Finding(
                title       = 'ID3 tags found',
                severity    = 'MEDIUM',
                description = (
                    f'MP3 contains ID3v2 tags ({id3_size} bytes). '
                    'Check Comment, UserText, Picture (APIC) for hidden data.'
                ),
                technique   = 'Audio Tags',
            ))

            if looks_like_flag(id3_text) and flag_is_clean(id3_text):
                result.findings.append(Finding(
                    title       = '🚩 Flag in ID3 tags!',
                    severity    = 'HIGH',
                    description = 'ID3 tags contain a string matching a flag pattern.',
                    data        = id3_text[:300],
                    technique   = 'Audio Tags',
                ))
        except Exception:
            result.findings.append(Finding(
                title       = 'ID3 tags found',
                severity    = 'MEDIUM',
                description = 'MP3 contains ID3 tags. Check Comment and Picture fields.',
                technique   = 'Audio Tags',
            ))

    # Trailing data: scan all sync words forward, take maximum frame_end
    mp3_sync_patterns = [b'\xff\xfb', b'\xff\xfa', b'\xff\xe3', b'\xff\xe2']
    last_frame_end    = -1

    for sync in mp3_sync_patterns:
        search_start = 0
        while True:
            pos = data.find(sync, search_start)
            if pos < 0 or pos + 4 > len(data):
                break
            search_start = pos + 1
            try:
                hdr         = struct.unpack_from('>I', data, pos)[0]
                bitrate_idx = (hdr >> 12) & 0xF
                sr_idx      = (hdr >> 10) & 0x3
                padding     = (hdr >> 9)  & 0x1
                bitrate     = _MP3_BITRATE_TABLE[bitrate_idx] * 1000
                sample_rate = [44100, 48000, 32000, 0][sr_idx]
                if bitrate > 0 and sample_rate > 0:
                    frame_size = 144 * bitrate // sample_rate + padding
                    frame_end  = pos + frame_size
                    if frame_end > last_frame_end:
                        last_frame_end = frame_end
            except Exception:
                continue

    if last_frame_end > 0 and last_frame_end < len(data):
        trailing_size = len(data) - last_frame_end
        has_id3v1     = len(data) >= 128 and data[-128:-125] == b'TAG'
        if trailing_size > 128 and not (has_id3v1 and trailing_size <= 130):
            result.findings.append(Finding(
                title       = 'Data after MP3 end',
                severity    = 'HIGH',
                description = (
                    f'{trailing_size} bytes found after the last MP3 frame. '
                    'Classic location for a hidden file.'
                ),
                data        = (
                    f'Start offset: {last_frame_end} (0x{last_frame_end:X}), '
                    f'first bytes: {data[last_frame_end:last_frame_end + 16].hex()}'
                ),
                technique   = 'File Carving',
            ))


# ── FLAC ──────────────────────────────────────────────────────────────────────

def _analyze_flac(data: bytes, result: AnalysisResult) -> None:
    """Basic FLAC analysis: scan metadata strings for flags."""
    result.findings.append(Finding(
        title       = 'FLAC file',
        severity    = 'INFO',
        description = (
            'FLAC contains metadata blocks: VORBIS_COMMENT (tags), PICTURE (cover art). '
            'Check tags for hidden data.'
        ),
        technique   = 'Audio Analysis',
    ))
    strings = extract_strings(data[:65536])
    for s in strings:
        if looks_like_flag(s) and flag_is_clean(s):
            register_flag(s, result, source='FLAC metadata')

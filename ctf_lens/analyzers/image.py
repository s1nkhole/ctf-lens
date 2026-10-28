"""
Image file analyzer: EXIF, PNG chunks, LSB steganography, JPEG DCT.
Entry point: analyze_image(data, result)
"""

import io
import struct
import zlib

from ..config import (
    PNG_STANDARD_CHUNKS, INTERESTING_KEYWORDS, JPEG_STANDALONE,
    MAX_DECOMPRESS_SIZE,
)
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, safe_decode, extract_strings, flag_is_clean, detect_filetype
from ..registry import register_flag
from .lsb_image import analyze_lsb_image


def analyze_image(data: bytes, result: AnalysisResult) -> None:
    """Dispatch image analysis. Structural parsers need no third-party packages."""
    # Pure-stdlib parsers run FIRST and independently of Pillow: a deliberately
    # corrupted PNG (the classic "fix the header" challenge) makes Pillow raise,
    # and that must not take the chunk/CRC analysis down with it.
    if result.filetype == 'PNG':
        _analyze_png_chunks(data, result)
    elif result.filetype == 'JPEG':
        _analyze_jpeg_dct(data, result)

    try:
        from PIL import Image
        import numpy as np

        img             = Image.open(io.BytesIO(data))
        width, height   = img.size
        mode            = img.mode

        result.findings.append(Finding(
            title       = 'Image parameters',
            severity    = 'INFO',
            description = f'Size: {width}×{height} px, mode: {mode}, format: {img.format}',
            technique   = 'Image Analysis',
        ))

        _analyze_exif(img, result)

        # Anomalous file size check (BMP/TIFF only — PNG/JPEG compress pixel data)
        expected = width * height * len(img.getbands())
        if len(data) > expected * 1.5 and result.filetype in ('BMP', 'TIFF'):
            result.findings.append(Finding(
                title       = 'File larger than expected',
                severity    = 'MEDIUM',
                description = (
                    f'Expected: {expected:,} bytes, actual: {len(data):,} bytes. '
                    'Hidden data may follow the pixel payload.'
                ),
                technique   = 'File Carving',
            ))

        if mode in ('RGB', 'RGBA', 'L'):
            arr = np.array(img)
            analyze_lsb_image(arr, mode, result, deep=bool(result._options.get('deep')))

    except ImportError:
        result.findings.append(Finding(
            title       = 'Pillow/numpy not installed',
            severity    = 'INFO',
            description = 'For pixel-level analysis (LSB, EXIF): pip install Pillow numpy',
        ))
    except Exception as e:
        result.findings.append(Finding(
            title       = 'Image decoder error',
            severity    = 'INFO',
            description = (
                f'Pillow could not decode the image ({e}). '
                'Structural checks above still apply; the file may be intentionally damaged.'
            ),
        ))


def _analyze_exif(img, result: AnalysisResult) -> None:
    """Extract and scan EXIF metadata for interesting fields and flags."""
    try:
        from PIL.ExifTags import TAGS
        exif_raw = img._getexif() if hasattr(img, '_getexif') else None
        if not exif_raw:
            return

        exif_data: dict[str, str] = {
            str(TAGS.get(tag_id, tag_id)): str(value)[:200]
            for tag_id, value in exif_raw.items()
        }

        _INTERESTING_EXIF = {
            'comment', 'description', 'author', 'software',
            'gps', 'user', 'copyright', 'artist', 'imagedescription',
        }
        interesting = {
            k: v for k, v in exif_data.items()
            if any(kw in k.lower() for kw in _INTERESTING_EXIF)
        }

        if interesting:
            exif_text = '\n'.join(f'{k}: {v}' for k, v in interesting.items())
            is_flag   = looks_like_flag(exif_text)
            result.findings.append(Finding(
                title       = '🚩 Flag in EXIF!' if is_flag else 'Interesting EXIF fields',
                severity    = 'HIGH' if is_flag else 'MEDIUM',
                description = 'EXIF fields with potentially useful data.',
                data        = exif_text,
                technique   = 'EXIF Analysis',
            ))
        else:
            result.findings.append(Finding(
                title       = 'EXIF metadata',
                severity    = 'INFO',
                description = f'Found {len(exif_data)} fields.',
                data        = '\n'.join(f'{k}: {v}' for k, v in list(exif_data.items())[:5]),
                technique   = 'EXIF Analysis',
            ))
    except Exception:
        pass


def _recover_ihdr_dimensions(chunk_data: bytes, stored_crc: int) -> list[tuple[int, int]]:
    """
    IHDR CRC does not match → try every single-field change of width or height
    that makes it match. This is the standard CTF "PNG with wrong dimensions" fix.
    """
    width, height = struct.unpack('>II', chunk_data[:8])
    rest          = chunk_data[8:]
    found: list[tuple[int, int]] = []
    for new_h in range(1, 1 << 16):
        if new_h != height and zlib.crc32(b'IHDR' + struct.pack('>II', width, new_h) + rest) == stored_crc:
            found.append((width, new_h))
    for new_w in range(1, 1 << 16):
        if new_w != width and zlib.crc32(b'IHDR' + struct.pack('>II', new_w, height) + rest) == stored_crc:
            found.append((new_w, height))
    return found


def _analyze_png_chunks(data: bytes, result: AnalysisResult) -> None:
    """Parse the PNG chunk tree: CRCs, text chunks, non-standard chunks, data after IEND."""
    pos       = 8
    saw_iend  = False
    broken    = False
    bad_crc: dict[str, int] = {}

    while pos + 12 <= len(data):
        try:
            chunk_len  = struct.unpack('>I', data[pos:pos + 4])[0]
            type_bytes = data[pos + 4:pos + 8]
            chunk_type = type_bytes.decode('ascii', errors='replace')

            if pos + 12 + chunk_len > len(data):
                broken = True
                result.findings.append(Finding(
                    title       = 'Corrupted PNG structure',
                    severity    = 'MEDIUM',
                    description = (
                        f"Chunk '{chunk_type}' at position {pos} extends past EOF. "
                        'File may be intentionally corrupted.'
                    ),
                    technique   = 'PNG Analysis',
                    offset      = pos,
                ))
                break

            chunk_data = data[pos + 8: pos + 8 + chunk_len]
            stored_crc = struct.unpack('>I', data[pos + 8 + chunk_len: pos + 12 + chunk_len])[0]
            if zlib.crc32(type_bytes + chunk_data) & 0xFFFFFFFF != stored_crc:
                if chunk_type == 'IHDR' and chunk_len == 13:
                    w, h = struct.unpack('>II', chunk_data[:8])
                    fixes = _recover_ihdr_dimensions(chunk_data, stored_crc)
                    if fixes:
                        fw, fh = fixes[0]
                        desc = (
                            f'IHDR CRC does not match the stored size {w}×{h}. '
                            f'The CRC is valid for {fw}×{fh} — the dimensions were tampered with '
                            '(often to crop part of the image away).'
                        )
                        hint = (
                            f'Patch IHDR to {fw}×{fh}: width = bytes 16–19, height = bytes 20–23 '
                            '(big-endian), then reopen the image.'
                        )
                    else:
                        desc = (
                            f'IHDR CRC does not match (stored size {w}×{h}) and no single '
                            'width/height change fixes it — other IHDR fields may be damaged.'
                        )
                        hint = 'Compare IHDR fields (bit depth, colour type) against the pixel data.'
                    result.findings.append(Finding(
                        title       = 'PNG IHDR CRC mismatch',
                        severity    = 'HIGH',
                        description = desc,
                        hint        = hint,
                        technique   = 'PNG Analysis',
                        offset      = pos,
                    ))
                else:
                    bad_crc[chunk_type] = bad_crc.get(chunk_type, 0) + 1

            if chunk_type == 'tEXt' and chunk_len < 50_000:
                text    = chunk_data.decode('latin-1', errors='replace')
                is_flag = looks_like_flag(text)
                result.findings.append(Finding(
                    title       = '🚩 Flag in PNG tEXt!' if is_flag else 'PNG tEXt chunk',
                    severity    = 'HIGH' if is_flag else 'MEDIUM',
                    description = 'Text chunk — popular place for hidden data.',
                    data        = text[:500],
                    technique   = 'PNG Chunks',
                    offset      = pos,
                ))

            elif chunk_type == 'iTXt' and chunk_len < 50_000:
                # Structure: keyword\x00 + compression_flag(1) + compression_method(1)
                #            + language_tag\x00 + translated_keyword\x00 + text
                try:
                    null1   = chunk_data.index(b'\x00')
                    keyword = chunk_data[:null1].decode('latin-1', errors='replace')
                    compressed = chunk_data[null1 + 1] == 1
                    rest    = chunk_data[null1 + 3:]          # skip 2 compression bytes
                    null2   = rest.index(b'\x00')
                    rest    = rest[null2 + 1:]
                    null3   = rest.index(b'\x00')
                    body    = rest[null3 + 1:]
                    if compressed:
                        body = zlib.decompressobj().decompress(body, MAX_DECOMPRESS_SIZE)
                    text    = body.decode('utf-8', errors='replace')
                    is_flag = looks_like_flag(text)
                    result.findings.append(Finding(
                        title       = '🚩 Flag in PNG iTXt!' if is_flag else f"PNG iTXt chunk '{keyword}'",
                        severity    = 'HIGH' if is_flag else 'MEDIUM',
                        description = 'International text chunk.',
                        data        = text[:500],
                        technique   = 'PNG Chunks',
                        offset      = pos,
                    ))
                except Exception:
                    pass

            elif chunk_type == 'zTXt' and chunk_len < 50_000:
                try:
                    null_pos     = chunk_data.index(b'\x00')
                    keyword      = chunk_data[:null_pos].decode('latin-1', errors='replace')
                    compressed   = chunk_data[null_pos + 2:]
                    dec_obj      = zlib.decompressobj()
                    decompressed = dec_obj.decompress(compressed, MAX_DECOMPRESS_SIZE)
                    text         = decompressed.decode('utf-8', errors='replace')
                    is_flag      = looks_like_flag(text)
                    result.findings.append(Finding(
                        title       = '🚩 Flag in PNG zTXt!' if is_flag else f"PNG zTXt chunk '{keyword}'",
                        severity    = 'HIGH' if is_flag else 'MEDIUM',
                        description = 'Compressed text chunk.',
                        data        = text[:500],
                        technique   = 'PNG Chunks',
                        offset      = pos,
                    ))
                except Exception:
                    pass

            elif chunk_type not in PNG_STANDARD_CHUNKS:
                result.findings.append(Finding(
                    title       = f"Non-standard PNG chunk: '{chunk_type}'",
                    severity    = 'HIGH',
                    description = (
                        f"Chunk '{chunk_type}' ({chunk_len} bytes) at position {pos}. "
                        'Non-standard chunks are often used to hide data.'
                    ),
                    data        = f'First bytes: {chunk_data[:20].hex()}',
                    technique   = 'PNG Chunks',
                    offset      = pos,
                ))

            pos += 12 + chunk_len
            if chunk_type == 'IEND':
                saw_iend = True
                break
        except Exception:
            broken = True
            break

    if bad_crc:
        listing = ', '.join(f'{k}×{v}' if v > 1 else k for k, v in sorted(bad_crc.items()))
        result.findings.append(Finding(
            title       = 'PNG chunk CRC mismatch',
            severity    = 'MEDIUM',
            description = (
                f'CRC check failed for: {listing}. '
                'The image was edited by hand or the data was patched after encoding.'
            ),
            technique   = 'PNG Analysis',
        ))

    if saw_iend and pos < len(data):
        trailing = data[pos:]
        kind, _  = detect_filetype(trailing[:64]) if len(trailing) >= 4 else ('UNKNOWN', '')
        preview  = ''.join(chr(b) if 32 <= b < 127 else '.' for b in trailing[:60])
        result.findings.append(Finding(
            title       = 'Data after PNG IEND',
            severity    = 'HIGH',
            description = (
                f'{len(trailing):,} bytes follow the IEND chunk'
                + (f' and look like a {kind} file' if kind not in ('UNKNOWN', 'TEXT') else '')
                + '. Classic polyglot / appended-payload trick.'
            ),
            data        = f'Offset: {pos} (0x{pos:X})\nASCII: {preview}',
            hint        = 'Re-run with --extract DIR to save the trailing bytes.',
            technique   = 'File Carving',
            offset      = pos,
        ))
        result.carved.append(('TRAILING', pos))
        for text in extract_strings(trailing):
            if looks_like_flag(text) and flag_is_clean(text):
                register_flag(text, result, source=f'data after PNG IEND (offset {pos})')
    elif not saw_iend and not broken:
        result.findings.append(Finding(
            title       = 'PNG has no IEND chunk',
            severity    = 'MEDIUM',
            description = 'The file ends without an IEND chunk — truncated or hand-edited.',
            technique   = 'PNG Analysis',
        ))


def _analyze_jpeg_dct(data: bytes, result: AnalysisResult) -> None:
    """Parse JPEG marker stream: COM comments, APP metadata, trailing data."""
    pos            = 2
    max_iterations = 50_000
    iterations     = 0

    while pos < len(data) - 2 and iterations < max_iterations:
        iterations += 1
        if data[pos] != 0xFF:
            pos += 1
            continue

        marker_byte = data[pos + 1]
        if marker_byte == 0xFF:
            pos += 1
            continue

        if marker_byte in JPEG_STANDALONE:
            pos += 2
            continue

        if pos + 4 > len(data):
            break
        marker_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        if marker_len < 2:
            break

        if marker_byte == 0xFE:   # COM marker
            comment_data = data[pos + 4: pos + 2 + marker_len]
            comment_text = safe_decode(comment_data)
            is_flag      = looks_like_flag(comment_text)
            result.findings.append(Finding(
                title       = '🚩 Flag in JPEG comment!' if is_flag else 'JPEG comment',
                severity    = 'HIGH' if is_flag else 'MEDIUM',
                description = 'JPEG COM marker contains text.',
                data        = comment_text[:300],
                technique   = 'JPEG Analysis',
            ))

        elif 0xE1 <= marker_byte <= 0xEF:   # APP1–APP15
            app_data = data[pos + 4: pos + 2 + marker_len]
            app_text = safe_decode(app_data)
            if any(kw in app_text.lower() for kw in INTERESTING_KEYWORDS):
                result.findings.append(Finding(
                    title       = f'JPEG APP{marker_byte - 0xE0} metadata',
                    severity    = 'MEDIUM',
                    description = 'APP marker contains interesting data.',
                    data        = app_text[:200],
                    technique   = 'JPEG Analysis',
                ))

        pos += 2 + marker_len

    # Trailing data after EOI
    eoi_pos = data.rfind(b'\xff\xd9')
    if eoi_pos > 0 and eoi_pos < len(data) - 2:
        trailing = data[eoi_pos + 2:]
        if len(trailing) > 4:
            result.findings.append(Finding(
                title       = 'Data after JPEG end',
                severity    = 'HIGH',
                description = (
                    f'{len(trailing)} bytes found after EOI marker. '
                    'Classic location for a hidden file.'
                ),
                data        = f'First bytes: {trailing[:20].hex()}',
                technique   = 'File Carving',
                offset      = eoi_pos + 2,
            ))
            result.carved.append(('TRAILING', eoi_pos + 2))

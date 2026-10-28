"""
PDF analyzer: JavaScript/launch actions, embedded files, flags in raw bytes AND
inside Flate-compressed streams.
Entry point: analyze_pdf(data, result)
"""

from __future__ import annotations

import re
import zlib

from ..config import FLAG_PATTERNS
from ..models import Finding, AnalysisResult
from ..utils import safe_decode, flag_is_clean
from ..registry import register_flag

_MAX_STREAMS         = 5_000
_MAX_STREAM_OUT      = 8 * 1024 * 1024
_MAX_TOTAL_OUT       = 64 * 1024 * 1024
_RE_PDF_STRING       = re.compile(rb'\(((?:\\.|[^\\()])*)\)', re.DOTALL)

# name → (severity, explanation)
_ACTIONS = {
    b'/OpenAction': ('MEDIUM', 'runs an action when the document is opened'),
    b'/Launch':     ('HIGH',   'can launch an external program'),
    b'/AA':         ('MEDIUM', 'additional-actions dictionary (triggered by events)'),
    b'/SubmitForm': ('MEDIUM', 'submits form data to a URL'),
    b'/RichMedia':  ('MEDIUM', 'embeds Flash/3D/media content'),
    b'/XFA':        ('MEDIUM', 'XFA forms (scriptable, frequently abused)'),
    b'/Encrypt':    ('MEDIUM', 'document is encrypted — stream contents may be unreadable'),
}


def _iter_streams(data: bytes):
    """Yield (index, raw_stream_bytes) for every `stream ... endstream` pair."""
    pos, n = 0, 0
    while n < _MAX_STREAMS:
        s = data.find(b'stream', pos)
        if s == -1:
            return
        if data[max(0, s - 3):s] == b'end':          # that was 'endstream'
            pos = s + 6
            continue
        start = s + 6
        if data[start:start + 2] == b'\r\n':
            start += 2
        elif data[start:start + 1] in (b'\n', b'\r'):
            start += 1
        end = data.find(b'endstream', start)
        if end == -1:
            return
        yield n, data[start:end]
        pos, n = end + 9, n + 1


def _inflate(raw: bytes) -> bytes | None:
    for candidate in (raw, raw.rstrip(b'\r\n')):
        try:
            return zlib.decompressobj().decompress(candidate, _MAX_STREAM_OUT)
        except zlib.error:
            continue
    return None


def _scan_text(text: str, result: AnalysisResult, source: str) -> None:
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            context = text[max(0, m.start() - 10): m.end() + 10]
            if flag_is_clean(context):
                register_flag(m.group(0), result, source=source)


def analyze_pdf(data: bytes, result: AnalysisResult) -> None:
    result.findings.append(Finding(
        title       = 'PDF file',
        severity    = 'INFO',
        description = 'For deep analysis: pdfextract, pdfcrack, pdf-parser.py.',
        technique   = 'PDF Analysis',
    ))

    if b'/JavaScript' in data or b'/JS' in data:
        result.findings.append(Finding(
            title       = 'PDF contains JavaScript',
            severity    = 'HIGH',
            description = 'PDF includes JavaScript — may contain a flag or exploit.',
            technique   = 'PDF Analysis',
        ))

    if b'/EmbeddedFile' in data:
        result.findings.append(Finding(
            title       = 'Embedded files in PDF',
            severity    = 'HIGH',
            description = 'PDF contains /EmbeddedFile objects — files hidden inside.',
            technique   = 'PDF Analysis',
        ))

    for key, (severity, why) in _ACTIONS.items():
        if key in data:
            result.findings.append(Finding(
                title       = f'PDF {key.decode()} present',
                severity    = severity,
                description = f'{key.decode()} {why}.',
                technique   = 'PDF Analysis',
            ))

    # Raw bytes (uncompressed objects, metadata, comments)
    _scan_text(safe_decode(data), result, 'PDF content')

    # Compressed streams: this is where most real PDF text lives
    total_out, inflated, scanned = 0, 0, 0
    for idx, raw in _iter_streams(data):
        scanned += 1
        out = _inflate(raw)
        if out is None:
            continue
        inflated  += 1
        total_out += len(out)
        text = out.decode('latin-1')
        _scan_text(text, result, f'PDF stream #{idx} (Flate)')
        # Text-showing operators split words: [(fl)-12(ag{x})] TJ → join the pieces.
        joined = b''.join(_RE_PDF_STRING.findall(out)).decode('latin-1')
        if joined and joined != text:
            _scan_text(joined, result, f'PDF stream #{idx} text operators')
        if b'/JavaScript' in out or b'app.alert' in out:
            result.findings.append(Finding(
                title       = f'JavaScript inside PDF stream #{idx}',
                severity    = 'HIGH',
                description = 'A compressed stream contains JavaScript.',
                data        = text[:300],
                technique   = 'PDF Analysis',
            ))
        if total_out > _MAX_TOTAL_OUT:
            break

    if scanned:
        result.findings.append(Finding(
            title       = f'PDF streams: {scanned} found, {inflated} inflated',
            severity    = 'INFO',
            description = 'Flate-compressed streams were decompressed and searched for flags.',
            technique   = 'PDF Analysis',
        ))

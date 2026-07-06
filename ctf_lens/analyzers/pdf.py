"""
PDF analyzer: JavaScript detection, embedded files, flag search.
Entry point: analyze_pdf(data, result)
"""

from ..config import FLAG_PATTERNS
from ..models import Finding, AnalysisResult
from ..utils import safe_decode, flag_is_clean
from ..registry import register_flag


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

    raw_text = safe_decode(data)
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(raw_text):
            # PDF raw bytes decode to a large, mostly-binary blob (streams,
            # object tables, etc.), so guard against junk-adjacent false
            # positives the same way every other analyzer does, and dedup
            # via register_flag instead of appending a raw Finding directly.
            context = raw_text[max(0, m.start() - 10): m.end() + 10]
            if flag_is_clean(context):
                register_flag(m.group(0), result, source='PDF content')

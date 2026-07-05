"""
PDF analyzer: JavaScript detection, embedded files, flag search.
Entry point: analyze_pdf(data, result)
"""

from ..config import FLAG_PATTERNS
from ..models import Finding, AnalysisResult
from ..utils import safe_decode


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
            result.findings.append(Finding(
                title       = '🚩 Flag in PDF!',
                severity    = 'HIGH',
                description = 'Flag found in PDF content.',
                data        = m.group(0),
                technique   = 'PDF Analysis',
            ))

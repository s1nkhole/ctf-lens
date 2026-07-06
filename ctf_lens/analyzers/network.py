"""
Network capture analyzer: PCAP/PCAPNG.
Entry point: analyze_network(data, result)
"""

from ..config import FLAG_PATTERNS
from ..models import Finding, AnalysisResult
from ..utils import safe_decode, flag_is_clean
from ..registry import register_flag


def analyze_network(data: bytes, result: AnalysisResult) -> None:
    result.findings.append(Finding(
        title       = 'PCAP file',
        severity    = 'INFO',
        description = 'Network capture file. Full analysis: Wireshark, tshark, scapy.',
        technique   = 'Network Analysis',
    ))

    # The whole capture decodes to one large, mostly-binary blob, so a flag
    # pattern can match anywhere in the noise. Guard with flag_is_clean (like
    # every other analyzer does for raw byte extraction) and dedup via
    # register_flag instead of just checking looks_like_flag on the entire
    # file and reporting the first 500 chars regardless of where it matched.
    text_content = safe_decode(data)
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text_content):
            context = text_content[max(0, m.start() - 10): m.end() + 10]
            if flag_is_clean(context):
                register_flag(m.group(0), result, source='PCAP payload')

    http_patterns = [b'HTTP/1.', b'HTTP/2', b'GET /', b'POST /', b'Host: ']
    found_http    = [p.decode() for p in http_patterns if p in data]
    if found_http:
        result.findings.append(Finding(
            title       = 'HTTP traffic in PCAP',
            severity    = 'MEDIUM',
            description = (
                f'HTTP markers found: {", ".join(found_http)}. '
                'Use Wireshark: Follow → TCP Stream to reconstruct.'
            ),
            technique   = 'Network Analysis',
        ))

    cred_patterns = [b'password=', b'passwd=', b'Authorization: Basic ', b'login=']
    found_creds   = [p.decode() for p in cred_patterns if p in data]
    if found_creds:
        result.findings.append(Finding(
            title       = 'Possible credentials in traffic',
            severity    = 'HIGH',
            description = f'Patterns found: {", ".join(found_creds)}',
            technique   = 'Network Analysis',
        ))

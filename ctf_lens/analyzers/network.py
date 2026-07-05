"""
Network capture analyzer: PCAP/PCAPNG.
Entry point: analyze_network(data, result)
"""

from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, safe_decode


def analyze_network(data: bytes, result: AnalysisResult) -> None:
    result.findings.append(Finding(
        title       = 'PCAP file',
        severity    = 'INFO',
        description = 'Network capture file. Full analysis: Wireshark, tshark, scapy.',
        technique   = 'Network Analysis',
    ))

    text_content = safe_decode(data)
    if looks_like_flag(text_content):
        result.findings.append(Finding(
            title       = '🚩 Flag in PCAP payload!',
            severity    = 'HIGH',
            description = 'Flag found in network traffic.',
            data        = text_content[:500],
            technique   = 'Network Analysis',
        ))

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

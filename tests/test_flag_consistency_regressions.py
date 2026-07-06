"""
Regression tests for the flag_is_clean() consistency fixes.

Before the fix:
  - core.py's _find_b64 / _find_hex registered a flag from decoded base64/hex
    content without checking flag_is_clean(), unlike _find_rot13 and
    _find_flags_in_strings which already did.
  - analyzers/pdf.py and analyzers/network.py decoded the *entire* raw file
    to text and searched the whole noisy blob for a flag pattern with no
    junk-adjacency guard at all, and without deduping through register_flag()
    — so the same flag could be reported multiple times.

These tests lock in the fixed behaviour.
"""
from ctf_lens.models import AnalysisResult
from ctf_lens.analyzers.pdf import analyze_pdf
from ctf_lens.analyzers.network import analyze_network
from ctf_lens.core import _find_b64, _find_hex


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        filepath="test", filesize=0, filetype="TEST", filecategory="test",
        md5="", sha256="", entropy=0.0,
    )


def test_pdf_flag_is_deduplicated():
    # The same flag string appears twice in the raw PDF bytes (e.g. once in
    # an object dictionary and once in a stream) — it must only be reported once.
    data = b"%PDF-1.4\nflag{pdf_example} ... flag{pdf_example} ...\n%%EOF"
    result = _empty_result()
    analyze_pdf(data, result)
    flag_findings = [f for f in result.findings if f.title == '\U0001f6a9 Flag found!']
    assert len(flag_findings) == 1
    assert flag_findings[0].data == "flag{pdf_example}"


def test_pdf_flag_surrounded_by_binary_junk_is_rejected():
    # A flag-shaped byte sequence sitting inside genuine binary noise
    # (e.g. a compressed stream) should not be reported as a real flag.
    data = b"%PDF-1.4\n" + b"\x01\x02\x03" + b"flag{junk}" + b"\x04\x05\x06" + b"\n%%EOF"
    result = _empty_result()
    analyze_pdf(data, result)
    flag_findings = [f for f in result.findings if f.title == '\U0001f6a9 Flag found!']
    assert flag_findings == []


def test_pcap_flag_is_deduplicated():
    data = b"flag{pcap_example} some traffic flag{pcap_example} more traffic"
    result = _empty_result()
    analyze_network(data, result)
    flag_findings = [f for f in result.findings if f.title == '\U0001f6a9 Flag found!']
    assert len(flag_findings) == 1
    assert flag_findings[0].data == "flag{pcap_example}"


def test_find_b64_rejects_junk_adjacent_decoded_flag():
    # A base64 blob that decodes to a flag surrounded by binary junk should
    # be rejected by flag_is_clean, same as ROT13/Atbash already are.
    import base64
    noisy_flag = "\x01\x02" + "flag{b64_junk}" + "\x03\x04"
    encoded = base64.b64encode(noisy_flag.encode("latin-1")).decode()
    result = _empty_result()
    _find_b64([encoded], result)
    assert result.findings == []


def test_find_hex_accepts_clean_decoded_flag():
    encoded = b"flag{hex_clean_example}".hex()
    result = _empty_result()
    _find_hex([encoded], result)
    flag_findings = [f for f in result.findings if f.title == '\U0001f6a9 Flag found!']
    assert len(flag_findings) == 1
    assert flag_findings[0].data == "flag{hex_clean_example}"

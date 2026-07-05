"""
Text file analyzer: whitespace stego, Caesar, Atbash, Vigenère hint.
Entry point: analyze_text(data, result)
"""

import re
import string
from collections import Counter

from ..config import (
    CAESAR_TABLES, CAESAR_COMMON_WORDS,
    MAX_CAESAR_WORDS, MAX_CAESAR_TOTAL_WORDS, MIN_WHITESPACE_RATIO,
    RE_WORD_4PLUS,
)
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, safe_decode, flag_is_clean
from ..registry import register_flag


def analyze_text(data: bytes, result: AnalysisResult) -> None:
    text  = safe_decode(data)
    lines = text.splitlines()

    result.findings.append(Finding(
        title       = 'Text file',
        severity    = 'INFO',
        description = f'Lines: {len(lines)}, characters: {len(text)}',
        technique   = 'Text Analysis',
    ))

    _analyze_whitespace_stego(lines, result)
    _analyze_null_bytes(text, result)
    _analyze_caesar(text, result)
    _analyze_atbash(text, result)
    _analyze_vigenere_hint(text, result)


def _analyze_whitespace_stego(lines: list[str], result: AnalysisResult) -> None:
    """
    Whitespace steganography: decode data from trailing spaces/tabs.
    Only trailing whitespace is encoded (not all spaces inside a line).
    """
    if not lines:
        return
    trailing_lines = [i for i, line in enumerate(lines) if line.endswith((' ', '\t'))]
    if len(trailing_lines) / len(lines) < MIN_WHITESPACE_RATIO:
        return

    result.findings.append(Finding(
        title       = '⚠️ Whitespace steganography',
        severity    = 'HIGH',
        description = (
            f'{len(trailing_lines)} of {len(lines)} lines have trailing spaces/tabs. '
            'Decoding: space=0, tab=1.'
        ),
        technique   = 'Whitespace Steganography',
    ))

    bits: list[int] = []
    for line in lines:
        stripped       = line.rstrip(' \t')
        trailing_chars = line[len(stripped):]
        for char in trailing_chars:
            if char == ' ':
                bits.append(0)
            elif char == '\t':
                bits.append(1)

    if len(bits) < 8:
        return

    decoded_bytes = bytearray(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits) - 7, 8)
    )
    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
    readable     = ''.join(c for c in decoded_text if c in string.printable)

    if readable:
        is_flag = looks_like_flag(readable)
        result.decoded.append(Finding(
            title       = '🚩 Flag from whitespace!' if is_flag else 'Whitespace decoded',
            severity    = 'HIGH' if is_flag else 'INFO',
            description = 'Data from trailing spaces/tabs:',
            data        = readable[:300],
            technique   = 'Whitespace Steganography',
        ))


def _analyze_null_bytes(text: str, result: AnalysisResult) -> None:
    null_count = text.count('\x00')
    if null_count > 5:
        result.findings.append(Finding(
            title       = f'Null bytes in text ({null_count})',
            severity    = 'MEDIUM',
            description = 'Null bytes in a text file — possible steganography or binary data.',
            technique   = 'Text Analysis',
        ))


def _analyze_caesar(text: str, result: AnalysisResult) -> None:
    """
    Test all 25 Caesar shifts (ROT1–ROT25).
    Applied to the full text (not individual words) so flag{...} survives.
    break intentionally removed — finds ALL valid shifts.
    """
    words = RE_WORD_4PLUS.findall(text)
    if not words or len(words) > MAX_CAESAR_TOTAL_WORDS:
        return

    sample_text = text[:MAX_CAESAR_WORDS * 10]

    for shift in range(1, 26):
        table         = CAESAR_TABLES[shift - 1]
        shifted       = sample_text.translate(table)
        shifted_set   = {w.lower() for w in RE_WORD_4PLUS.findall(shifted)}
        has_common    = len(shifted_set & CAESAR_COMMON_WORDS) >= 2
        is_flag       = looks_like_flag(shifted)

        if has_common or is_flag:
            result.findings.append(Finding(
                title       = f'🚩 Flag — Caesar shift {shift}!' if is_flag else f'Caesar shift {shift}',
                severity    = 'HIGH' if is_flag else 'MEDIUM',
                description = f'Shift {shift} {"reveals a flag" if is_flag else "gives readable text"}.',
                data        = shifted[:300],
                technique   = 'Caesar Cipher',
            ))


def _analyze_atbash(text: str, result: AnalysisResult) -> None:
    """Atbash cipher (A↔Z). Applied to full text to preserve flag{...} structure."""
    if not text.strip():
        return

    atbash_table = str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1],
    )
    sample  = text[:MAX_CAESAR_WORDS * 10]
    decoded = sample.translate(atbash_table)

    decoded_words = {w.lower() for w in RE_WORD_4PLUS.findall(decoded)}
    has_common    = len(decoded_words & CAESAR_COMMON_WORDS) >= 2
    is_flag       = looks_like_flag(decoded) and flag_is_clean(decoded)

    if has_common or is_flag:
        if is_flag:
            register_flag(
                decoded, result,
                source='Atbash cipher (A↔Z)',
                hint=(
                    "Decrypt: python3 -c \"import string; "
                    "t=str.maketrans(string.ascii_letters,"
                    "string.ascii_uppercase[::-1]+string.ascii_lowercase[::-1]);"
                    "print(open('file').read().translate(t))\""
                ),
            )
        else:
            result.findings.append(Finding(
                title       = 'Atbash cipher',
                severity    = 'MEDIUM',
                description = 'Atbash (A↔Z) gives readable text.',
                data        = decoded[:300],
                hint        = 'Try decrypting the whole file with Atbash.',
                technique   = 'Atbash Cipher',
            ))


def _analyze_vigenere_hint(text: str, result: AnalysisResult) -> None:
    """
    Check for Vigenère cipher via Index of Coincidence.
    Full cracking requires knowing the key length — here we give a hint.
    """
    letters_only = re.sub(r'[^a-zA-Z]', '', text).lower()
    if len(letters_only) < 100:
        return

    freq = Counter(letters_only)
    n    = len(letters_only)
    ic   = sum(c * (c - 1) for c in freq.values()) / (n * (n - 1))

    if ic < 0.05:
        result.findings.append(Finding(
            title       = '⚠️ Possible Vigenère cipher',
            severity    = 'MEDIUM',
            description = (
                f'Index of Coincidence: {ic:.4f} '
                '(English ≈ 0.065, random ≈ 0.038). '
                'Low IC indicates a polyalphabetic cipher (Vigenère, Beaufort, etc.).'
            ),
            technique   = 'Vigenere Analysis',
        ))

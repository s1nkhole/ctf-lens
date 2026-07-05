"""
General analysis (runs on every file type) and the main analyze() orchestrator.
Specialized analyzers are called from here via a category dispatcher.
"""

from __future__ import annotations

from typing import Callable

from .config import (
    ENTROPY_VERY_HIGH, ENTROPY_HIGH, ENTROPY_VERY_LOW,
    HIGH_ENTROPY_NORMAL_CATEGORIES, EMBEDDED_SIGNATURES, MIN_EMBEDDED_OFFSET,
    MAX_URLS_DISPLAY, INTERESTING_KEYWORDS, KEYWORD_SCAN_LIMIT,
    RE_B64, RE_HEX, RE_URL,
    MAX_ROT_STRINGS, XOR_KEY_RANGE, XOR_SAMPLE_SIZE,
    MIN_STRING_LEN, MIN_STRING_LEN_EXEC,
    MAX_FILE_SIZE, MAX_FILE_SIZE_MB,
)
from .models import SEVERITY_ORDER
from .models import Finding, AnalysisResult
from .utils import (
    shannon_entropy, detect_filetype, compute_hashes,
    extract_strings, looks_like_flag, flag_is_clean,
    safe_decode, validate_path,
)
from .decoders import (
    try_decode_base64, try_decode_hex, try_rot13,
    try_decode_xor, score_xor_result,
    try_decode_url_encoding, try_decode_html_entities,
    try_decode_binary_string, try_decode_morse,
)

from .registry import register_flag


# ── Entropy finding ───────────────────────────────────────────────────────────

def _analyze_entropy(result: AnalysisResult) -> None:
    e        = result.entropy
    category = result.filecategory

    if e > ENTROPY_VERY_HIGH:
        if category in HIGH_ENTROPY_NORMAL_CATEGORIES:
            result.findings.append(Finding(
                title       = f'High entropy ({e:.2f}/8.0) — normal for {result.filetype}',
                severity    = 'INFO',
                description = (
                    f'{result.filetype} uses built-in compression/encoding, '
                    'so high entropy is expected and is not a sign of encryption.'
                ),
                technique   = 'Entropy Analysis',
            ))
        else:
            result.findings.append(Finding(
                title       = f'Very high entropy ({e:.2f}/8.0)',
                severity    = 'HIGH',
                description = 'Indicates encryption, compression, or packed data. '
                              'In CTF this often means XOR, AES, or a nested archive.',
                hint        = 'Try --xor to brute-force XOR keys, '
                              'or binwalk to search for embedded files.',
                technique   = 'Entropy Analysis',
            ))
    elif e > ENTROPY_HIGH:
        if category not in HIGH_ENTROPY_NORMAL_CATEGORIES:
            result.findings.append(Finding(
                title       = f'High entropy ({e:.2f}/8.0)',
                severity    = 'MEDIUM',
                description = 'File may contain compressed or encoded data.',
                hint        = 'Try --xor or check for embedded archives.',
                technique   = 'Entropy Analysis',
            ))
    elif e < ENTROPY_VERY_LOW and result.filesize > 100:
        result.findings.append(Finding(
            title       = f'Very low entropy ({e:.2f}/8.0)',
            severity    = 'MEDIUM',
            description = (
                'Very few unique bytes. Possible simple cipher: '
                'single-byte XOR, Caesar, or repeating pattern.'
            ),
            hint        = 'Run with --xor to auto-brute-force XOR keys.',
            technique   = 'Entropy Analysis',
        ))


# ── Individual finders ────────────────────────────────────────────────────────

def _find_flags_in_strings(strings: list[str], result: AnalysisResult) -> None:
    for s in strings:
        if looks_like_flag(s) and flag_is_clean(s):
            register_flag(s, result, source='direct file content')


def _find_b64(strings: list[str], result: AnalysisResult) -> None:
    seen: set[str] = set()
    for s in strings:
        for m in RE_B64.finditer(s):
            candidate = m.group(0)
            if candidate in seen:
                continue
            seen.add(candidate)
            decoded = try_decode_base64(candidate)
            if not decoded:
                continue
            if looks_like_flag(decoded):
                register_flag(decoded, result, source=f'base64: {candidate[:60]}')
            else:
                result.decoded.append(Finding(
                    title       = 'Base64 decoded',
                    severity    = 'INFO',
                    description = f'Source string: {candidate[:40]}…',
                    data        = decoded[:200],
                    technique   = 'Base64 Encoding',
                ))


def _find_hex(strings: list[str], result: AnalysisResult) -> None:
    seen: set[str] = set()
    for s in strings:
        for m in RE_HEX.finditer(s):
            candidate = m.group(0)
            if candidate in seen:
                continue
            seen.add(candidate)
            decoded = try_decode_hex(candidate)
            if not decoded:
                continue
            if looks_like_flag(decoded):
                register_flag(decoded, result, source=f'hex: {candidate[:40]}')
            else:
                result.decoded.append(Finding(
                    title       = 'Hex decoded',
                    severity    = 'INFO',
                    description = f'Hex string: {candidate[:40]}',
                    data        = decoded[:200],
                    technique   = 'Hex Encoding',
                ))


def _find_rot13(strings: list[str], result: AnalysisResult, limit: int = MAX_ROT_STRINGS) -> None:
    ascii_strings = [s for s in strings if len(s) > 10 and s.isascii()]
    for s in ascii_strings[:limit]:
        rot = try_rot13(s)
        if rot and looks_like_flag(rot) and flag_is_clean(rot):
            register_flag(
                rot, result,
                source=f'ROT13 of: {s[:60]}',
                hint=(
                    'Decode whole file: '
                    "python3 -c \"import codecs; "
                    "print(codecs.decode(open('file').read(),'rot13'))\""
                ),
            )


def _find_embedded_files(data: bytes, result: AnalysisResult) -> None:
    MAX_PER_TYPE = 5
    for sig, name in EMBEDDED_SIGNATURES:
        offset      = MIN_EMBEDDED_OFFSET
        found_count = 0
        while found_count < MAX_PER_TYPE:
            pos = data.find(sig, offset)
            if pos == -1:
                break
            if pos + len(sig) + 16 <= len(data):
                result.findings.append(Finding(
                    title       = f'Embedded {name} file',
                    severity    = 'HIGH',
                    description = (
                        f'{name} magic bytes found at offset {pos}. '
                        'A file is hidden inside this file — classic CTF technique.'
                    ),
                    data        = f'Offset: {pos} bytes (0x{pos:X})',
                    technique   = 'File Carving',
                ))
                found_count += 1
            offset = pos + len(sig)
        if found_count == MAX_PER_TYPE:
            result.findings.append(Finding(
                title       = f'Embedded {name}: showing first {MAX_PER_TYPE} occurrences',
                severity    = 'INFO',
                description = f'>{MAX_PER_TYPE} {name} magic bytes found — possibly synthetic file.',
                technique   = 'File Carving',
            ))


def _find_urls(strings: list[str], result: AnalysisResult) -> None:
    urls: list[str] = []
    seen: set[str]  = set()
    for s in strings:
        for m in RE_URL.finditer(s):
            url = m.group(0)
            if url not in seen:
                seen.add(url)
                urls.append(url)
    if urls:
        result.findings.append(Finding(
            title       = f'URLs found ({len(urls)})',
            severity    = 'MEDIUM',
            description = 'Links may point to the next challenge step.',
            data        = '\n'.join(urls[:MAX_URLS_DISPLAY]),
            technique   = 'URL Extraction',
        ))


def _find_keywords(data: bytes, result: AnalysisResult) -> None:
    sample       = data[:KEYWORD_SCAN_LIMIT]
    sample_lower = sample.lower()
    found = [kw for kw in INTERESTING_KEYWORDS if kw.encode() in sample_lower]
    if found:
        result.findings.append(Finding(
            title       = 'Interesting keywords',
            severity    = 'MEDIUM',
            description = f'Found: {", ".join(found)}',
            technique   = 'Keyword Search',
        ))


def _add_decoded_finding(
    result: AnalysisResult,
    decoded: str,
    source_str: str,
    title_flag: str,
    title_normal: str,
    description_flag: str,
    description_normal: str,
    technique: str,
) -> None:
    is_flag = looks_like_flag(decoded)
    target  = result.findings if is_flag else result.decoded
    target.append(Finding(
        title       = title_flag if is_flag else title_normal,
        severity    = 'HIGH' if is_flag else 'INFO',
        description = description_flag if is_flag else description_normal,
        data        = decoded[:200],
        technique   = technique,
    ))


def _find_extra_encodings(strings: list[str], result: AnalysisResult, limit: int = 200) -> None:
    """URL-encoding, HTML entities, binary code, Morse code."""
    decoders = [
        (try_decode_url_encoding,  '🚩 Flag in URL encoding!',  'URL decoded',
         'URL encoding contains flag',                          lambda s: f'Source: {s[:60]}',
         'URL Encoding'),
        (try_decode_html_entities, '🚩 Flag in HTML entities!', 'HTML decoded',
         'HTML entities contain flag',                          lambda s: f'Source: {s[:60]}',
         'HTML Entities'),
        (try_decode_binary_string, '🚩 Flag in binary code!',   'Binary string decoded',
         'Binary code contains flag',                           lambda s: f'Binary: {s[:60]}…',
         'Binary Encoding'),
        (try_decode_morse,         '🚩 Flag in Morse code!',    'Morse code decoded',
         'Morse code contains flag',                            lambda s: f'Morse: {s[:60]}',
         'Morse Code'),
    ]
    for s in strings[:limit]:
        for decoder, t_flag, t_norm, d_flag, d_norm_fn, technique in decoders:
            decoded = decoder(s)
            if decoded:
                _add_decoded_finding(
                    result, decoded, s,
                    t_flag, t_norm, d_flag, d_norm_fn(s), technique,
                )


# ── XOR brute-force ───────────────────────────────────────────────────────────

def analyze_xor_bruteforce(data: bytes, result: AnalysisResult) -> None:
    """
    Try all single-byte XOR keys 0x01–0xFF.
    Only runs when --xor flag is passed (slow on large files).
    """
    sample     = data[:XOR_SAMPLE_SIZE]
    candidates: list[tuple[float, int, str]] = []
    flag_keys:  set[int] = set()

    for key in XOR_KEY_RANGE:
        decrypted = try_decode_xor(sample, key)
        score     = score_xor_result(decrypted)
        if score > 0.7:
            preview     = safe_decode(decrypted[:80])
            sample_text = safe_decode(decrypted)
            candidates.append((score, key, preview))
            if looks_like_flag(sample_text):
                flag_keys.add(key)
                full_decrypted = try_decode_xor(data, key)
                full_text      = safe_decode(full_decrypted)
                result.findings.append(Finding(
                    title       = f'🚩 Flag at XOR key=0x{key:02X}!',
                    severity    = 'HIGH',
                    description = f'XOR with key 0x{key:02X} reveals the flag.',
                    data        = full_text[:300],
                    technique   = 'XOR Cipher',
                ))

    candidates.sort(reverse=True)
    for score, key, preview in candidates[:3]:
        if key not in flag_keys:
            result.decoded.append(Finding(
                title       = f'XOR key=0x{key:02X} (score={score:.0%})',
                severity    = 'MEDIUM',
                description = 'XOR decryption result contains readable text:',
                data        = preview[:200],
                technique   = 'XOR Cipher',
            ))


# ── General analysis (runs on every file) ────────────────────────────────────

def analyze_general(
    data: bytes,
    strings: list[str],
    result: AnalysisResult,
    deep: bool = False,
) -> None:
    """
    Universal analysis applied to every file regardless of type.
    strings is passed explicitly — no hidden dependency on call order.
    """
    _analyze_entropy(result)
    _find_flags_in_strings(strings, result)
    _find_b64(strings, result)
    _find_hex(strings, result)
    _find_rot13(strings, result, limit=200 if deep else MAX_ROT_STRINGS)
    _find_extra_encodings(strings, result, limit=500 if deep else 200)
    _find_embedded_files(data, result)
    _find_urls(strings, result)
    _find_keywords(data, result)


# ── Main orchestrator ─────────────────────────────────────────────────────────

def analyze(
    filepath: str,
    deep: bool = False,
    xor_bruteforce: bool = False,
) -> AnalysisResult:
    """
    Read a file, detect its type, and run all applicable analyzers.
    deep=True enables additional checks (slower).
    xor_bruteforce=True brute-forces XOR keys 0x01–0xFF.
    """
    from .output import print_status  # local import to avoid circular dependency

    path = validate_path(filepath)

    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        print_status(
            f'[yellow]File too large: {file_size / 1024**2:.1f} MB '
            f'(limit {MAX_FILE_SIZE_MB} MB). Reading first {MAX_FILE_SIZE_MB} MB.[/yellow]'
        )
        with path.open('rb') as fh:
            data = fh.read(MAX_FILE_SIZE)
    else:
        data = path.read_bytes()

    filetype, category = detect_filetype(data)
    md5, sha256        = compute_hashes(data)
    entropy            = shannon_entropy(data)

    result = AnalysisResult(
        filepath     = str(path),
        filesize     = len(data),
        filetype     = filetype,
        filecategory = category,
        md5          = md5,
        sha256       = sha256,
        entropy      = entropy,
    )

    # Cache strings once — reused by all analyzers
    min_len = MIN_STRING_LEN_EXEC if category == 'executable' else MIN_STRING_LEN
    strings = extract_strings(data, min_len=min_len)
    result._strings_cache = strings

    # General analysis — always runs
    analyze_general(data, strings, result, deep=deep)

    # Optional XOR brute-force
    if xor_bruteforce:
        analyze_xor_bruteforce(data, result)

    # Specialized analysis dispatched by file category
    # Imported here (not at module level) to break the circular import:
    # core → analyzers → registry  (analyzers never import core directly)
    from . import analyzers as _az
    dispatcher: dict[str, Callable[[bytes, AnalysisResult], None]] = {
        'image':      _az.image.analyze_image,
        'audio':      _az.audio.analyze_audio,
        'archive':    _az.archive.analyze_archive,
        'text':       _az.text.analyze_text,
        'executable': _az.binary.analyze_executable,
        'java':       _az.binary.analyze_executable,
        'network':    _az.network.analyze_network,
    }
    if category in dispatcher:
        dispatcher[category](data, result)
    elif filetype == 'PDF':
        _az.pdf.analyze_pdf(data, result)

    # Sort: HIGH first, then MEDIUM, LOW, INFO; stable within each group
    result.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

    return result

"""
Archive analyzer: ZIP, GZIP, BZIP2.
Entry point: analyze_archive(data, result)
"""

import io
import os
import time
import zipfile
import zlib
import gzip
import bz2

from ..config import (
    MAX_DECOMPRESS_SIZE, MAX_ZIP_FILES_INSPECT,
    CTF_ZIP_PASSWORDS, ZIP_WORDLIST_MAX, ZIP_WORDLIST_SECONDS,
)
from ..models import Finding, AnalysisResult
from ..utils import looks_like_flag, safe_decode
from ..registry import register_flag


def analyze_archive(data: bytes, result: AnalysisResult) -> None:
    if result.filetype == 'ZIP':
        _analyze_zip(data, result)
    elif result.filetype == 'GZIP':
        _analyze_gzip(data, result)
    elif result.filetype == 'BZIP2':
        _analyze_bzip2(data, result)


def _try_password(zf: zipfile.ZipFile, info: zipfile.ZipInfo, pwd: bytes) -> bool:
    """ZipCrypto has a 1-byte check (1/256 false positives), so confirm via the CRC."""
    try:
        zf.read(info, pwd=pwd)
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, ValueError):
        return False


def _candidate_passwords(result: AnalysisResult, comment: str):
    seen: set[str] = set()

    def fresh(pw: str):
        if pw and pw not in seen:
            seen.add(pw)
            return True
        return False

    stem = os.path.splitext(os.path.basename(result.filepath))[0]
    extras = [stem, stem.lower(), *comment.split()[:20]]
    for pw in (*CTF_ZIP_PASSWORDS, *extras):
        if fresh(pw):
            yield pw

    wordlist = result._options.get('wordlist')
    if wordlist:
        deadline = time.monotonic() + ZIP_WORDLIST_SECONDS
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as fh:
            for i, line in enumerate(fh):
                if i >= ZIP_WORDLIST_MAX or time.monotonic() > deadline:
                    break
                pw = line.rstrip('\r\n')
                if fresh(pw):
                    yield pw


def _crack_zip(zf: zipfile.ZipFile, encrypted: list[zipfile.ZipInfo], result: AnalysisResult) -> str | None:
    """Try common CTF passwords (plus --wordlist). Returns the password or None."""
    classic = [i for i in encrypted if i.compress_type != 99 and i.file_size <= 50 * 1024 * 1024]
    if not classic:
        if any(i.compress_type == 99 for i in encrypted):
            result.findings.append(Finding(
                title       = 'ZIP uses AES encryption',
                severity    = 'MEDIUM',
                description = 'AES-encrypted entries cannot be tested with the standard library.',
                hint        = 'zip2john archive.zip > hash; john hash --wordlist=rockyou.txt',
                technique   = 'Archive Analysis',
            ))
        return None
    target  = min(classic, key=lambda i: i.file_size)
    comment = safe_decode(zf.comment) if zf.comment else ''
    tried   = 0
    for pw in _candidate_passwords(result, comment):
        tried += 1
        if _try_password(zf, target, pw.encode('utf-8', errors='ignore')):
            zf.setpassword(pw.encode('utf-8', errors='ignore'))
            result.findings.append(Finding(
                title       = f'🔓 ZIP password cracked: {pw}',
                severity    = 'HIGH',
                description = f'Password found after {tried} guesses; contents were read with it.',
                data        = pw,
                hint        = f"unzip -P '{pw}' archive.zip",
                technique   = 'Archive Analysis',
            ))
            return pw
    result.findings.append(Finding(
        title       = 'ZIP password not in built-in list',
        severity    = 'INFO',
        description = f'Tried {tried} common passwords. Supply --wordlist FILE for more.',
        hint        = 'zip2john archive.zip > hash; john hash --wordlist=rockyou.txt',
        technique   = 'Archive Analysis',
    ))
    return None


def _analyze_zip(data: bytes, result: AnalysisResult) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()

            result.findings.append(Finding(
                title       = f'ZIP contains {len(names)} file(s)',
                severity    = 'INFO',
                description = '\n'.join(names[:30]),
                technique   = 'Archive Analysis',
            ))

            ZIP_ENCRYPT_BIT = 0x1
            encrypted = [i for i in zf.infolist() if i.flag_bits & ZIP_ENCRYPT_BIT]
            if encrypted:
                result.findings.append(Finding(
                    title       = f'Password-protected files in ZIP ({len(encrypted)})',
                    severity    = 'HIGH',
                    description = (
                        'Files are password-protected. Common CTF passwords: '
                        'password, 123456, flag, ctf, or check other challenge files.'
                    ),
                    data        = '\n'.join(e.filename for e in encrypted[:10]),
                    technique   = 'Archive Analysis',
                ))
                _crack_zip(zf, encrypted, result)

            if zf.comment:
                comment = safe_decode(zf.comment)
                is_flag = looks_like_flag(comment)
                if is_flag:
                    register_flag(
                        comment, result,
                        source='ZIP archive comment',
                        hint='View comment: unzip -z archive.zip',
                    )
                else:
                    result.findings.append(Finding(
                        title       = 'ZIP comment',
                        severity    = 'MEDIUM',
                        description = 'ZIP file has a comment.',
                        data        = comment[:500],
                        technique   = 'Archive Analysis',
                    ))

            for name in names[:MAX_ZIP_FILES_INSPECT]:
                try:
                    info = zf.getinfo(name)
                    if info.file_size > MAX_DECOMPRESS_SIZE:
                        result.findings.append(Finding(
                            title       = f"Potential ZIP bomb: '{name}'",
                            severity    = 'HIGH',
                            description = (
                                f"'{name}' declares size {info.file_size:,} bytes "
                                f'(>{MAX_DECOMPRESS_SIZE // 1024**2} MB) — skipping.'
                            ),
                            technique   = 'Archive Analysis',
                        ))
                        continue
                    content      = zf.read(name)
                    content_text = safe_decode(content)
                    if looks_like_flag(content_text):
                        register_flag(
                            content_text, result,
                            source=f"file '{name}' inside ZIP",
                            hint='Extract: unzip archive.zip -d folder/',
                        )
                    elif len(content) > 4 and content[:4] == b'PK\x03\x04' and len(content) < 10_000_000:
                        result.findings.append(Finding(
                            title       = f"Nested ZIP: '{name}'",
                            severity    = 'MEDIUM',
                            description = f"'{name}' is itself a ZIP archive.",
                            technique   = 'Archive Analysis',
                        ))
                except Exception:
                    continue

    except zipfile.BadZipFile:
        result.findings.append(Finding(
            title       = 'Corrupted ZIP',
            severity    = 'MEDIUM',
            description = (
                'File has ZIP magic bytes but is not a valid ZIP. '
                'May be intentionally corrupted (CTF trick) or another ZIP-based format.'
            ),
            technique   = 'Archive Analysis',
        ))


def _analyze_gzip(data: bytes, result: AnalysisResult) -> None:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            decompressed = gz.read(MAX_DECOMPRESS_SIZE + 1)

        if len(decompressed) > MAX_DECOMPRESS_SIZE:
            result.findings.append(Finding(
                title       = 'GZIP bomb or very large file',
                severity    = 'HIGH',
                description = f'Decompressed size exceeds {MAX_DECOMPRESS_SIZE // 1024**2} MB.',
                technique   = 'Archive Analysis',
            ))
            decompressed = decompressed[:MAX_DECOMPRESS_SIZE]

        result.findings.append(Finding(
            title       = 'GZIP decompressed successfully',
            severity    = 'INFO',
            description = f'Decompressed size: {len(decompressed):,} bytes',
            technique   = 'Archive Analysis',
        ))

        content_text = safe_decode(decompressed)
        if looks_like_flag(content_text):
            register_flag(content_text, result, source='GZIP decompressed content')

    except Exception as e:
        result.findings.append(Finding(
            title       = 'GZIP decompression error',
            severity    = 'MEDIUM',
            description = str(e),
            technique   = 'Archive Analysis',
        ))


def _analyze_bzip2(data: bytes, result: AnalysisResult) -> None:
    """
    BZIP2 with bomb protection via incremental read.
    bz2.decompress(data) reads everything without a size limit — OOM risk.
    bz2.BZ2File.read(limit) stops at the limit, same as GzipFile.
    """
    try:
        with bz2.BZ2File(io.BytesIO(data)) as bz:
            decompressed = bz.read(MAX_DECOMPRESS_SIZE + 1)

        if len(decompressed) > MAX_DECOMPRESS_SIZE:
            result.findings.append(Finding(
                title       = 'BZIP2 bomb or very large file',
                severity    = 'HIGH',
                description = f'Decompressed size exceeds {MAX_DECOMPRESS_SIZE // 1024**2} MB.',
                technique   = 'Archive Analysis',
            ))
            decompressed = decompressed[:MAX_DECOMPRESS_SIZE]

        result.findings.append(Finding(
            title       = 'BZIP2 decompressed successfully',
            severity    = 'INFO',
            description = f'Size: {len(decompressed):,} bytes',
            technique   = 'Archive Analysis',
        ))
        content_text = safe_decode(decompressed)
        if looks_like_flag(content_text):
            register_flag(content_text, result, source='BZIP2 decompressed content')
    except Exception as e:
        result.findings.append(Finding(
            title       = 'BZIP2 decompression error',
            severity    = 'MEDIUM',
            description = str(e),
            technique   = 'Archive Analysis',
        ))

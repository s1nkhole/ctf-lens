"""
All thresholds, limits, and compile-time constants in one place.
To tune behaviour, only this file needs to change.
"""

import re
import string
from typing import Optional
from pathlib import Path

# ── File size limits ──────────────────────────────────────────────────────────
MAX_FILE_SIZE           = 512 * 1024 * 1024
MAX_FILE_SIZE_MB        = MAX_FILE_SIZE // (1024 * 1024)
MAX_DECOMPRESS_SIZE     = 256 * 1024 * 1024

# ── Entropy thresholds ────────────────────────────────────────────────────────
ENTROPY_VERY_HIGH       = 7.5
ENTROPY_HIGH            = 6.5
ENTROPY_VERY_LOW        = 1.5

# ── LSB steganography ─────────────────────────────────────────────────────────
LSB_ENTROPY_THRESHOLD   = 0.95
LSB_ENTROPY_EMPTY       = 0.01
LSB_SAMPLE_BITS         = 4_000
LSB_ENTROPY_SAMPLE      = 10_000

# ── String extraction ─────────────────────────────────────────────────────────
MIN_STRING_LEN          = 6
MIN_STRING_LEN_EXEC     = 8
MIN_B64_LEN             = 20
MIN_HEX_LEN             = 16
MIN_DECODED_LEN         = 3

# ── Analysis limits ───────────────────────────────────────────────────────────
MAX_ROT_STRINGS         = 50
MAX_CAESAR_WORDS        = 500
MAX_CAESAR_TOTAL_WORDS  = 1000
MAX_ZIP_FILES_INSPECT   = 20
MAX_URLS_DISPLAY        = 10
MIN_WHITESPACE_RATIO    = 0.3
MAX_DISPLAY_LINES       = 10
MAX_DECODED_DISPLAY     = 8
MIN_EMBEDDED_OFFSET     = 512
WAV_SCAN_LIMIT          = 10_000

# ── XOR brute-force ───────────────────────────────────────────────────────────
XOR_KEY_RANGE           = range(0x01, 0x100)
XOR_SAMPLE_SIZE         = 4096

# ── Multi-layer decoding (peel) ───────────────────────────────────────────────
PEEL_MAX_DEPTH          = 4          # max chain length: base64 → hex → rot13 → ...
PEEL_MAX_NODES          = 1500       # hard budget of decoded candidates per file
PEEL_MAX_BLOB           = 256 * 1024 # largest root blob fed to the peel engine
PEEL_MAX_SECONDS        = 5.0
PEEL_MAX_TOKENS         = 300
PEEL_MAX_OUTPUT         = 16 * 1024 * 1024

# ── Repeating-key XOR ─────────────────────────────────────────────────────────
XOR_MAX_KEY_LEN         = 40
XOR_MIN_DATA            = 40

# ── ZIP password guessing (stdlib ZipCrypto only) ─────────────────────────────
ZIP_WORDLIST_MAX        = 1_000_000
ZIP_WORDLIST_SECONDS    = 20.0
CTF_ZIP_PASSWORDS: tuple[str, ...] = (
    'password', 'Password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd',
    '123456', '12345678', '123456789', '1234', '12345', '000000', '111111',
    'admin', 'root', 'toor', 'letmein', 'qwerty', 'secret', 'changeme',
    'flag', 'ctf', 'CTF', 'flag123', 'ctf2024', 'ctf2025', 'ctf2026',
    'infected', 'malware', 'virus', 'sample', 'hunter2', 'iloveyou',
    'welcome', 'login', 'test', 'guest', 'default', 'pass', 'zip', 'unzip',
    'hack', 'hacker', 'hackme', 'challenge', 'picoctf', 'hackthebox', 'tryhackme',
)

# ── Keyword dictionary (single source of truth) ───────────────────────────────
INTERESTING_KEYWORDS: tuple[str, ...] = (
    'password', 'passwd', 'secret', 'key', 'flag', 'token',
    'admin', 'root', 'hack', 'auth', 'cred', 'private',
)

# ── Base64 charset ────────────────────────────────────────────────────────────
B64_CHARS: frozenset[str] = frozenset(string.ascii_letters + string.digits + '+/=')

# ── Path restriction (security) ───────────────────────────────────────────────
# Empty = no restriction (CLI mode). Set when embedding in an API.
ALLOWED_BASE_PATH: Optional[Path] = None

# ── Known CTF flag prefixes ───────────────────────────────────────────────────
CTF_KNOWN_PREFIXES: str = '|'.join([
    'flag', 'ctf', 'HTB', 'picoCTF', 'THM', 'DUCTF', 'STANDCON',
    'INCTF', 'BCACTF', 'UIUCTF', 'DCTF', 'RCTF', 'ASIS', 'BCTF',
    'CSAW', 'DEFCON', 'HSCTF', 'LACTF', 'MAPNA', 'NAHAMCON', 'PBCTF',
    'SEKAI', 'SHCTF', 'WECTF', 'WOLV', 'XMAS', 'ZER0PTS', 'ROOT',
])

# ── Compiled regexes (once at import time) ────────────────────────────────────
RE_PRINTABLE_STRINGS      = re.compile(rb'[ -~]{' + str(MIN_STRING_LEN).encode() + rb',}')
RE_PRINTABLE_STRINGS_EXEC = re.compile(rb'[ -~]{' + str(MIN_STRING_LEN_EXEC).encode() + rb',}')
RE_B64   = re.compile(r'[A-Za-z0-9+/]{' + str(MIN_B64_LEN) + r',}={0,2}')
RE_HEX   = re.compile(r'(?:0x)?[0-9a-fA-F]{' + str(MIN_HEX_LEN) + r',}')
RE_URL   = re.compile(r'https?://[^\s"\'<>]{5,}')
RE_WORD_4PLUS = re.compile(r'[a-zA-Z]{4,}')
RE_WORD_3PLUS = re.compile(r'[a-z]{3,}')

FLAG_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [rf'(?:{CTF_KNOWN_PREFIXES})\{{[^}}]+\}}']
]

# ── Magic bytes: file type detection ─────────────────────────────────────────
MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b'\x89PNG\r\n\x1a\n',   'PNG',    'image'),
    (b'\xff\xd8\xff',        'JPEG',   'image'),
    (b'GIF87a',              'GIF',    'image'),
    (b'GIF89a',              'GIF',    'image'),
    (b'BM',                  'BMP',    'image'),
    (b'II*\x00',             'TIFF',   'image'),
    (b'MM\x00*',             'TIFF',   'image'),
    (b'RIFF',                'RIFF',   'unknown'),
    (b'ID3',                 'MP3',    'audio'),
    (b'\xff\xfb',            'MP3',    'audio'),
    (b'\xff\xfa',            'MP3',    'audio'),
    (b'\xff\xe3',            'MP3',    'audio'),
    (b'fLaC',                'FLAC',   'audio'),
    (b'OggS',                'OGG',    'audio'),
    (b'PK\x03\x04',          'ZIP',    'archive'),
    (b'PK\x05\x06',          'ZIP',    'archive'),
    (b'\x1f\x8b',            'GZIP',   'archive'),
    (b'BZh',                 'BZIP2',  'archive'),
    (b'\xfd7zXZ\x00',        'XZ',     'archive'),
    (b"7z\xbc\xaf'\x1c",    '7ZIP',   'archive'),
    (b'Rar!\x1a\x07',        'RAR',    'archive'),
    (b'%PDF',                'PDF',    'document'),
    (b'\xd0\xcf\x11\xe0',   'DOC',    'document'),
    (b'MZ',                  'EXE',    'executable'),
    (b'\x7fELF',             'ELF',    'executable'),
    (b'\xca\xfe\xba\xbe',   '_CAFEBABE', 'unknown'),
    (b'\xd4\xc3\xb2\xa1',   'PCAP',   'network'),
    (b'\xa1\xb2\xc3\xd4',   'PCAP',   'network'),
    (b'\x0a\x0d\x0d\x0a',   'PCAPNG', 'network'),
    (b'-----BEGIN',          'PEM',    'crypto'),
    (b'\x30\x82',            'DER',    'crypto'),
    (b'SQLite format 3',     'SQLITE', 'database'),
    (b'\x89HDF',             'HDF5',   'data'),
]

EMBEDDED_SIGNATURES: list[tuple[bytes, str]] = [
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\xff\xd8\xff',      'JPEG'),
    (b'PK\x03\x04',        'ZIP'),
    (b'\x1f\x8b',          'GZIP'),
    (b'%PDF',              'PDF'),
    (b'\x7fELF',           'ELF'),
    (b'MZ',                'EXE'),
    (b'BZh',               'BZIP2'),
    (b"7z\xbc\xaf'\x1c",  '7ZIP'),
]

# Types that legitimately contain copies of their own signature (ZIP members,
# JPEG thumbnails, PDF revisions) — never report them as "embedded" in themselves.
SELF_NESTING_TYPES: frozenset[str] = frozenset({'ZIP', 'JPEG', 'PDF'})
MAX_CARVE_PER_TYPE      = 5

# ── Known safe chunk names ────────────────────────────────────────────────────
PNG_STANDARD_CHUNKS: frozenset[str] = frozenset({
    'IHDR', 'IDAT', 'IEND', 'PLTE', 'tEXt', 'iTXt', 'zTXt',
    'bKGD', 'cHRM', 'gAMA', 'hIST', 'pHYs', 'sBIT', 'sRGB',
    'tIME', 'tRNS', 'eXIf',
})

WAV_STANDARD_CHUNKS: frozenset[str] = frozenset({
    'fmt ', 'data', 'LIST', 'INFO', 'JUNK', 'PAD ', 'fact',
})

# ── Common English words used to score cipher results ────────────────────────
CAESAR_COMMON_WORDS: frozenset[str] = frozenset({
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can',
    'flag', 'key', 'this', 'that', 'with', 'have', 'from', 'they',
})

# ── Pre-computed Caesar shift tables (shifts 1–25) ────────────────────────────
import string as _string
CAESAR_TABLES: tuple[dict, ...] = tuple(
    str.maketrans(
        _string.ascii_uppercase + _string.ascii_lowercase,
        _string.ascii_uppercase[s:] + _string.ascii_uppercase[:s] +
        _string.ascii_lowercase[s:] + _string.ascii_lowercase[:s],
    )
    for s in range(1, 26)
)

# ── Morse code table ──────────────────────────────────────────────────────────
MORSE: dict[str, str] = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
}

# ── Keyword scan limit ────────────────────────────────────────────────────────
KEYWORD_SCAN_LIMIT = 65_536

# ── JPEG standalone markers (no length field) ─────────────────────────────────
JPEG_STANDALONE: frozenset[int] = frozenset({
    0xD8, 0xD9, 0x01,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
})

# ── Categories where high entropy is expected (not a cipher indicator) ────────
HIGH_ENTROPY_NORMAL_CATEGORIES: frozenset[str] = frozenset({
    'audio', 'image', 'archive',
})

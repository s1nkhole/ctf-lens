#!/usr/bin/env python3
"""
Использование: python ctf_lens.py <файл> [опции]

Опции:
  --deep     Глубокий анализ (медленнее, больше проверок)
  --xor      Перебор XOR-ключей (0x01–0xFF)
  --version  Версия
  -h/--help  Справка
"""

__version__ = "0.3.0"

# ─── Стандартная библиотека ───────────────────────────────────────────────────
import sys
import os
import re
import math
import struct
import base64
import binascii
import zipfile
import gzip
import zlib
import hashlib
import string
import io
import argparse
import bz2
import html as _html
from urllib.parse import unquote as _url_unquote
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Callable, Literal

# ─── Опциональные зависимости ─────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    print("[!] rich не установлен: pip install rich  — вывод будет упрощённым")

console = Console() if _RICH_AVAILABLE else None


# ═════════════════════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ — все пороги и лимиты в одном месте
# ═════════════════════════════════════════════════════════════════════════════

MAX_FILE_SIZE           = 512 * 1024 * 1024
MAX_FILE_SIZE_MB        = MAX_FILE_SIZE // (1024 * 1024)
MAX_DECOMPRESS_SIZE     = 256 * 1024 * 1024

ENTROPY_VERY_HIGH       = 7.5
ENTROPY_HIGH            = 6.5
ENTROPY_VERY_LOW        = 1.5

LSB_ENTROPY_THRESHOLD   = 0.95
LSB_ENTROPY_EMPTY       = 0.01
LSB_SAMPLE_BITS         = 4_000
LSB_ENTROPY_SAMPLE      = 10_000

MIN_STRING_LEN          = 6
MIN_STRING_LEN_EXEC     = 8
MIN_B64_LEN             = 20
MIN_HEX_LEN             = 16
MIN_DECODED_LEN         = 3

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

# XOR-перебор
XOR_KEY_RANGE           = range(0x01, 0x100)
XOR_SAMPLE_SIZE         = 4096

# ─── Единый словарь ключевых слов (устраняет дублирование) ───────────────────
_INTERESTING_KEYWORDS: tuple[str, ...] = (
    'password', 'passwd', 'secret', 'key', 'flag', 'token',
    'admin', 'root', 'hack', 'auth', 'cred', 'private',
)

# ─── Константы для base64 ─────────────────────────────────────────────────────
_B64_CHARS: frozenset[str] = frozenset(string.ascii_letters + string.digits + '+/=')

# ─── Разрешённые пути (безопасность) ─────────────────────────────────────────
# Пустое значение = без ограничений (CLI-режим). Заполняется при встраивании в API.
ALLOWED_BASE_PATH: Optional[Path] = None


# ═════════════════════════════════════════════════════════════════════════════
# РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ — компилируются один раз при импорте
# ═════════════════════════════════════════════════════════════════════════════

_RE_PRINTABLE_STRINGS = re.compile(  # ASCII строки для общего анализа
    rb'[ -~]{' + str(MIN_STRING_LEN).encode() + rb',}'
)
_RE_PRINTABLE_STRINGS_EXEC = re.compile(  # для бинарников — длиннее = меньше мусора
    rb'[ -~]{' + str(MIN_STRING_LEN_EXEC).encode() + rb',}'
)
_RE_B64 = re.compile(
    r'[A-Za-z0-9+/]{' + str(MIN_B64_LEN) + r',}={0,2}'
)
_RE_HEX = re.compile(
    r'(?:0x)?[0-9a-fA-F]{' + str(MIN_HEX_LEN) + r',}'
)
_RE_URL = re.compile(
    r'https?://[^\s"\'<>]{5,}'
)
_RE_WORD_4PLUS = re.compile(r'[a-zA-Z]{4,}')
_RE_WORD_3PLUS = re.compile(r'[a-z]{3,}')

# Известные CTF платформы и форматы флагов.
# Намеренно НЕ используем широкий [A-Z]{2,8}{...} —
# он матчит ROT13/Атбаш-зашифрованные версии флагов (gcvpbPGS{} = picoCTF в ROT13).
_CTF_KNOWN_PREFIXES: str = '|'.join([
    'flag', 'ctf', 'HTB', 'picoCTF', 'THM', 'DUCTF', 'STANDCON',
    'INCTF', 'BCACTF', 'UIUCTF', 'DCTF', 'RCTF', 'ASIS', 'BCTF',
    'CSAW', 'DEFCON', 'HSCTF', 'LACTF', 'MAPNA', 'NAHAMCON', 'PBCTF',
    'SEKAI', 'SHCTF', 'WECTF', 'WOLV', 'XMAS', 'ZER0PTS', 'ROOT',
])

_FLAG_PATTERNS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    rf'(?:{_CTF_KNOWN_PREFIXES})\{{[^}}]+\}}',
]]


# ═════════════════════════════════════════════════════════════════════════════
# MAGIC BYTES — определение типа файла
# ═════════════════════════════════════════════════════════════════════════════

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    # Картинки
    (b'\x89PNG\r\n\x1a\n',   'PNG',    'image'),
    (b'\xff\xd8\xff',        'JPEG',   'image'),
    (b'GIF87a',              'GIF',    'image'),
    (b'GIF89a',              'GIF',    'image'),
    (b'BM',                  'BMP',    'image'),
    (b'II*\x00',             'TIFF',   'image'),
    (b'MM\x00*',             'TIFF',   'image'),
    (b'RIFF',                'RIFF',   'unknown'),
    # Аудио
    (b'ID3',                 'MP3',    'audio'),
    (b'\xff\xfb',            'MP3',    'audio'),
    (b'\xff\xfa',            'MP3',    'audio'),
    (b'\xff\xe3',            'MP3',    'audio'),
    (b'fLaC',                'FLAC',   'audio'),
    (b'OggS',                'OGG',    'audio'),
    # Архивы
    (b'PK\x03\x04',          'ZIP',    'archive'),
    (b'PK\x05\x06',          'ZIP',    'archive'),
    (b'\x1f\x8b',            'GZIP',   'archive'),
    (b'BZh',                 'BZIP2',  'archive'),
    (b'\xfd7zXZ\x00',        'XZ',     'archive'),
    (b'7z\xbc\xaf\'\x1c',   '7ZIP',   'archive'),
    (b'Rar!\x1a\x07',        'RAR',    'archive'),
    # Документы
    (b'%PDF',                'PDF',    'document'),
    (b'\xd0\xcf\x11\xe0',   'DOC',    'document'),
    # Исполняемые
    (b'MZ',                  'EXE',    'executable'),
    (b'\x7fELF',             'ELF',    'executable'),
    # MACHO и CLASS различаются по major version (байты 6–7)
    # Обрабатываются в detect_filetype отдельно
    (b'\xca\xfe\xba\xbe',   '_CAFEBABE', 'unknown'),
    # Сеть
    (b'\xd4\xc3\xb2\xa1',   'PCAP',   'network'),
    (b'\xa1\xb2\xc3\xd4',   'PCAP',   'network'),
    (b'\x0a\x0d\x0d\x0a',   'PCAPNG', 'network'),
    # Прочее
    (b'-----BEGIN',          'PEM',    'crypto'),
    (b'\x30\x82',            'DER',    'crypto'),
    (b'SQLite format 3',     'SQLITE', 'database'),
    (b'\x89HDF',             'HDF5',   'data'),
]

# Magic bytes встроенных файлов для карвинга
_EMBEDDED_SIGNATURES: list[tuple[bytes, str]] = [
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\xff\xd8\xff',      'JPEG'),
    (b'PK\x03\x04',        'ZIP'),
    (b'\x1f\x8b',          'GZIP'),
    (b'%PDF',              'PDF'),
    (b'\x7fELF',           'ELF'),
    (b'MZ',                'EXE'),
    (b'BZh',               'BZIP2'),
    (b'7z\xbc\xaf',        '7ZIP'),
]

# Стандартные PNG chunks — не считаются подозрительными
_PNG_STANDARD_CHUNKS: frozenset[str] = frozenset({
    'IHDR', 'IDAT', 'IEND', 'PLTE', 'tEXt', 'iTXt', 'zTXt',
    'bKGD', 'cHRM', 'gAMA', 'hIST', 'pHYs', 'sBIT', 'sRGB',
    'tIME', 'tRNS', 'eXIf',
})

# Стандартные WAV/RIFF chunks
_WAV_STANDARD_CHUNKS: frozenset[str] = frozenset({
    'fmt ', 'data', 'LIST', 'INFO', 'JUNK', 'PAD ', 'fact',
})

# Общеизвестные слова для оценки Caesar/ROT13 результата
_CAESAR_COMMON_WORDS: frozenset[str] = frozenset({
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can',
    'flag', 'key', 'this', 'that', 'with', 'have', 'from', 'they',
})


# ═════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    title:       str
    description: str
    severity:    Literal['HIGH', 'MEDIUM', 'LOW', 'INFO'] = "INFO"
    data:        str = ""
    technique:   str = ""
    hint:        str = ""


@dataclass
class AnalysisResult:
    filepath:        str
    filesize:        int
    filetype:        str
    filecategory:    str
    md5:             str
    sha256:          str
    entropy:         float
    findings:        list[Finding] = field(default_factory=list)
    decoded:         list[Finding] = field(default_factory=list)
    # Кэш извлечённых строк — вычисляется один раз, переиспользуется всеми анализаторами
    _strings_cache:  list[str]    = field(default_factory=list, repr=False)
    # Множество уже найденных флагов — предотвращает дублирование одного флага из разных источников
    _seen_flags:     set[str]     = field(default_factory=set, repr=False)


SEVERITY_COLOR: dict[str, str] = {
    'HIGH':   'red',
    'MEDIUM': 'yellow',
    'LOW':    'cyan',
    'INFO':   'dim white',
}
SEVERITY_ICON: dict[str, str] = {
    'HIGH':   '🔴',
    'MEDIUM': '🟡',
    'LOW':    '🔵',
    'INFO':   '⚪',
}
_SEVERITY_ORDER: dict[str, int] = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}


# ═════════════════════════════════════════════════════════════════════════════
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ═════════════════════════════════════════════════════════════════════════════

def shannon_entropy(data: bytes) -> float:
    """Считает энтропию Шеннона (бит/байт) для последовательности байт."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


def detect_filetype(data: bytes) -> tuple[str, str]:
    """
    Определяет тип файла по magic bytes.
    Особые случаи:
      RIFF  → уточняется по байтам 8–12 (WAVE/WEBP/...)
      CAFEBABE → Java CLASS или Mach-O, различаются по major version
    """
    if len(data) < 4:
        return 'UNKNOWN', 'unknown'

    # Специальный случай: CAFEBABE — MACHO vs Java CLASS
    if data[:4] == b'\xca\xfe\xba\xbe':
        if len(data) >= 8:
            major = struct.unpack('>H', data[6:8])[0]
            # Java 1.1=45 .. Java 23=67; Mach-O fat binary имеет другие значения
            if 44 <= major <= 100:
                return 'CLASS', 'java'
        return 'MACHO', 'executable'

    for magic, ftype, category in MAGIC_SIGNATURES:
        if not data.startswith(magic):
            continue

        if ftype == '_CAFEBABE':
            continue

        # RIFF: уточняем subtype по байтам 8–12
        if ftype == 'RIFF' and len(data) > 12:
            subtype = data[8:12]
            if subtype == b'WAVE':
                return 'WAV', 'audio'
            elif subtype == b'WEBP':
                return 'WEBP', 'image'
            elif subtype == b'AVI ':
                return 'AVI', 'video'
            else:
                return 'RIFF', 'unknown'

        return ftype, category

    # Текст: пробуем декодировать начало файла
    sample = data[:512]
    for enc in ('utf-8', 'utf-16', 'latin-1'):
        try:
            decoded = sample.decode(enc)
            # Проверяем что большинство символов — печатаемые
            printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
            if printable_ratio > 0.85:
                return 'TEXT', 'text'
        except (UnicodeDecodeError, ValueError):
            continue

    return 'UNKNOWN', 'unknown'


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """
    Извлекает читаемые ASCII строки через скомпилированный re.findall.
    В 50–100x быстрее побайтового цикла на Python.
    """
    if min_len == MIN_STRING_LEN:
        pattern = _RE_PRINTABLE_STRINGS
    elif min_len == MIN_STRING_LEN_EXEC:
        pattern = _RE_PRINTABLE_STRINGS_EXEC
    else:
        # Произвольный min_len — компилируем на месте (редкий путь)
        pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')

    return [m.group(0).decode('ascii', errors='replace') for m in pattern.finditer(data)]


def looks_like_flag(s: str) -> bool:
    """Проверяет, похожа ли строка на CTF флаг по известным паттернам."""
    for pattern in _FLAG_PATTERNS:
        if pattern.search(s):
            return True
    return False


def compute_hashes(data: bytes) -> tuple[str, str]:
    """Возвращает (md5_hex, sha256_hex) для переданных байт."""
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def safe_decode(data: bytes, encodings=('utf-8', 'latin-1')) -> str:
    """Пробует декодировать байты в строку через список кодировок."""
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return data.decode('latin-1', errors='replace')


def _validate_path(filepath: str) -> Path:
    """
    Валидирует путь к файлу.
    При ALLOWED_BASE_PATH — проверяет что файл не выходит за её пределы (path traversal).
    """
    path = Path(filepath).resolve()
    if ALLOWED_BASE_PATH is not None:
        try:
            path.relative_to(ALLOWED_BASE_PATH)
        except ValueError:
            raise PermissionError(
                f"Доступ запрещён: файл '{path}' выходит за пределы '{ALLOWED_BASE_PATH}'"
            )
    if not path.exists():
        raise FileNotFoundError(f"Файл не найден: {filepath}")
    if not path.is_file():
        raise ValueError(f"Не является файлом: {filepath}")
    return path


# ═════════════════════════════════════════════════════════════════════════════
# ДЕКОДИРОВАНИЕ — функции возвращают Optional[str], не добавляют в result
# ═════════════════════════════════════════════════════════════════════════════

def try_decode_base64(s: str) -> Optional[str]:
    """
    Декодирует base64 строку.
    Формула паддинга: (4 - n%4) % 4 корректно обрабатывает все случаи
    включая n%4==0 (паддинг не нужен).
    raw декодируется один раз и переиспользуется для текстового и бинарного вывода.
    """
    s = s.strip().replace(' ', '').replace('\n', '')
    if len(s) < MIN_B64_LEN:
        return None
    if not all(c in _B64_CHARS for c in s):
        return None
    try:
        stripped = s.rstrip('=')
        if len(stripped) % 4 == 1:
            return None
        padding = (4 - len(stripped) % 4) % 4
        raw = base64.b64decode(stripped + '=' * padding)
    except Exception:
        return None

    # Пробуем прочитать как текст
    for enc in ('utf-8', 'latin-1'):
        try:
            text = raw.decode(enc)
            if len(text) >= MIN_DECODED_LEN and any(c in string.printable for c in text[:20]):
                return text
        except (UnicodeDecodeError, ValueError):
            continue

    # Текст не получился — возвращаем hex бинарных данных (повторный b64decode НЕ нужен)
    if len(raw) >= MIN_DECODED_LEN:
        return f"[binary] {raw.hex()[:80]}"
    return None


def try_decode_hex(s: str) -> Optional[str]:
    """Декодирует hex строку в текст или возвращает hex-представление."""
    s = s.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    if len(s) < MIN_HEX_LEN or len(s) % 2 != 0:
        return None
    if not all(c in string.hexdigits for c in s):
        return None
    try:
        raw = bytes.fromhex(s)
        try:
            text = raw.decode('utf-8')
            if len(text) >= MIN_DECODED_LEN and any(c in string.printable for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        # Бинарные данные — показываем hex (уже есть) + ASCII preview
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:40])
        return f"[binary] {printable}"
    except Exception:
        return None


def try_rot13(s: str) -> Optional[str]:
    """Применяет ROT13 и возвращает результат если он содержит читаемые слова."""
    if not s.isascii():
        return None
    result = s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
    ))
    # Считаем минимум 2 слова длиной 3+ символа
    if result != s and len(_RE_WORD_3PLUS.findall(result)) >= 2:
        return result
    return None


def _flag_is_clean(text: str) -> bool:
    """
    Проверяет что найденный флаг не окружён мусором.
    Проблема: ROT13/Атбаш находят 'flag{...}' внутри строки вроде
    'file.txtpicoCTF{flag}PK\\x03\\x04' — паттерн есть, но это мусор из ZIP-структуры.
    Правила:
      — до/после флага нет непечатаемых символов (бинарный мусор)
      — флаг занимает >40% длины строки ИЛИ строка короткая (<80 символов)
    """
    for pat in _FLAG_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        flag     = m.group(0)
        ratio    = len(flag) / max(len(text), 1)
        prefix   = text[:m.start()]
        suffix   = text[m.end():]
        has_junk = any(c not in string.printable for c in prefix[-10:] + suffix[:10])
        if has_junk:
            return False
        if ratio > 0.4 or len(text) < 80:
            return True
    return False


def try_decode_xor(data: bytes, key: int) -> bytes:
    """
    Применяет XOR с однобайтовым ключом ко всем байтам.
    bytes(map(...)) быстрее generator expression: map — C-функция без overhead интерпретатора,
    не создаёт промежуточный list в отличие от list comprehension.
    """
    return bytes(map(key.__xor__, data))


def score_xor_result(data: bytes) -> float:
    """
    Оценивает насколько результат XOR похож на читаемый текст (0.0–1.0).
    Считает долю печатаемых ASCII символов в выборке.
    """
    if not data:
        return 0.0
    sample = data[:XOR_SAMPLE_SIZE]
    printable_count = sum(
        32 <= b < 127 or b in (9, 10, 13)
        for b in sample
    )
    return printable_count / len(sample)


def try_decode_url_encoding(s: str) -> Optional[str]:
    """Декодирует URL-encoded строку (%XX)."""
    if '%' not in s:
        return None
    try:
        decoded = _url_unquote(s)
        if decoded != s and len(decoded) >= MIN_DECODED_LEN:
            return decoded
    except Exception:
        pass
    return None


def try_decode_html_entities(s: str) -> Optional[str]:
    """Декодирует HTML entities (&#...; и &amp; и т.д.)."""
    if '&' not in s:
        return None
    try:
        decoded = _html.unescape(s)
        if decoded != s and len(decoded) >= MIN_DECODED_LEN:
            return decoded
    except Exception:
        pass
    return None


def try_decode_binary_string(s: str) -> Optional[str]:
    """Декодирует строку из 0 и 1 (бинарное представление ASCII)."""
    clean = s.replace(' ', '').replace('\n', '')
    if not all(c in '01' for c in clean):
        return None
    if len(clean) < 8 or len(clean) % 8 != 0:
        return None
    try:
        result = ''
        for i in range(0, len(clean), 8):
            byte = int(clean[i:i+8], 2)
            if byte == 0:
                break
            result += chr(byte)
        if len(result) >= MIN_DECODED_LEN and result.isprintable():
            return result
    except Exception:
        pass
    return None


_MORSE: dict[str, str] = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
}


def try_decode_morse(s: str) -> Optional[str]:
    """Декодирует строку азбуки Морзе (. и -)."""
    clean = s.strip()
    # Валидируем: только точки, тире, пробелы, слэши
    if not re.fullmatch(r'[.\- /]+', clean):
        return None
    # Слова разделены ' / ', символы — пробелами
    words = clean.split(' / ')
    result_parts = []
    for word in words:
        chars = word.split(' ')
        decoded_word = ''
        for char in chars:
            if char in _MORSE:
                decoded_word += _MORSE[char]
            elif char:
                return None
        result_parts.append(decoded_word)
    result = ' '.join(result_parts)
    if len(result) >= MIN_DECODED_LEN:
        return result
    return None


# ═════════════════════════════════════════════════════════════════════════════
# LSB — общие функции (используются для изображений и аудио)
# ═════════════════════════════════════════════════════════════════════════════

def _lsb_entropy(lsb_bits) -> float:
    """
    Считает энтропию LSB-последовательности.
    Принимает numpy array или list из 0/1 значений.
    Конвертирует через bytearray — корректно работает с numpy int-типами.
    Возвращает 1.0 для пустого входа — нейтральное значение выше порога,
    чтобы не триггерить ложное HIGH «подозрение на LSB стего».
    """
    sample = lsb_bits[:LSB_ENTROPY_SAMPLE]
    if len(sample) == 0:
        return 1.0
    # bytearray(iterable) принимает любой итерируемый int — включая numpy int16
    return shannon_entropy(bytes(bytearray(int(b) for b in sample)))


def _lsb_bits_to_bytes(lsb_bits) -> bytes:
    """
    Конвертирует LSB-биты в байты (MSB first).
    Принимает numpy array или list из 0/1 значений.
    """
    sample = lsb_bits[:LSB_SAMPLE_BITS]
    if len(sample) < 8:
        return b''
    result = bytearray()
    for i in range(0, len(sample) - 7, 8):
        byte_val = 0
        for bit_pos in range(8):
            byte_val = (byte_val << 1) | int(sample[i + bit_pos])
        result.append(byte_val)
    return bytes(result)


def _extract_lsb_text(lsb_bits, result: AnalysisResult, source: str) -> None:
    """
    Извлекает текст из LSB-битов и добавляет находку в result.
    source — откуда биты ('изображение', 'аудио', 'канал R' и т.п.)
    """
    sample_bytes = _lsb_bits_to_bytes(lsb_bits)
    if not sample_bytes:
        return

    # Пробуем читать как текст
    try:
        text = sample_bytes.decode('utf-8', errors='ignore')
        readable = ''.join(c for c in text if c in string.printable)
        if len(readable) >= 5:
            if looks_like_flag(readable):
                _register_flag(readable, result, source=f"LSB [{source}]",
                               hint="Извлеки полностью: zsteg image.png  или  stegsolve → Extract LSB")
            else:
                result.decoded.append(Finding(
                    title       = 'LSB данные',
                    severity    = 'INFO',
                    description = f"Текст извлечённый из LSB [{source}]:",
                    data        = readable[:200],
                    technique   = 'LSB Steganography',
                ))
    except Exception:
        pass

    # Показываем hex только если там есть что-то кроме нулей
    # Сплошные нули = пустой канал, показывать нечего
    if any(b != 0 for b in sample_bytes):
        result.decoded.append(Finding(
            title       = f"LSB hex [{source}]",
            severity    = "INFO",
            description = "Первые байты из LSB (hex):",
            data        = sample_bytes.hex(),
            technique   = 'LSB Steganography',
        ))


# ═════════════════════════════════════════════════════════════════════════════
# ОБЩИЙ АНАЛИЗ — применяется ко всем типам файлов
# ═════════════════════════════════════════════════════════════════════════════

# Форматы где высокая энтропия — норма, а не признак шифрования
_HIGH_ENTROPY_NORMAL_CATEGORIES: frozenset[str] = frozenset({
    'audio',
    'image',
    'archive',
})


def _analyze_entropy(result: AnalysisResult) -> None:
    """
    Добавляет находку об энтропии.
    Для аудио/изображений/архивов высокая энтропия — норма формата,
    поэтому severity ниже и текст другой.
    """
    e        = result.entropy
    category = result.filecategory

    if e > ENTROPY_VERY_HIGH:
        if category in _HIGH_ENTROPY_NORMAL_CATEGORIES:
            # Для этих форматов высокая энтропия ожидаема — только INFO, не HIGH
            result.findings.append(Finding(
                title       = f"Высокая энтропия ({e:.2f}/8.0) — норма для {result.filetype}",
                severity    = "INFO",
                description = (
                    f"{result.filetype} использует встроенное сжатие/кодирование, "
                    "поэтому высокая энтропия ожидаема и не является признаком шифрования."
                ),
                technique   = 'Entropy Analysis',
            ))
        else:
            result.findings.append(Finding(
                title       = f"Очень высокая энтропия ({e:.2f}/8.0)",
                severity    = "HIGH",
                description = (
                    "Признак шифрования, сжатия или упакованных данных. "
                    "В CTF это часто означает XOR-шифрование, AES, или вложенный архив."
                ),
                hint        = "Попробуй --xor для перебора XOR-ключей, "
                              "или binwalk для поиска вложенных файлов.",
                technique   = 'Entropy Analysis',
            ))
    elif e > ENTROPY_HIGH:
        if category not in _HIGH_ENTROPY_NORMAL_CATEGORIES:
            result.findings.append(Finding(
                title       = f"Высокая энтропия ({e:.2f}/8.0)",
                severity    = "MEDIUM",
                description = "Файл может содержать сжатые или закодированные данные.",
                hint        = "Попробуй --xor или проверь на вложенные архивы.",
                technique   = 'Entropy Analysis',
            ))
    elif e < ENTROPY_VERY_LOW and result.filesize > 100:
        result.findings.append(Finding(
            title       = f"Очень низкая энтропия ({e:.2f}/8.0)",
            severity    = "MEDIUM",
            description = (
                "Файл содержит очень мало уникальных байт. "
                "Возможен простой шифр: XOR с одним ключом, Caesar, или повторяющиеся данные."
            ),
            hint        = "Запусти с флагом --xor для автоматического перебора XOR-ключей.",
            technique   = 'Entropy Analysis',
        ))


def _register_flag(flag: str, result: AnalysisResult, source: str, hint: str = "") -> bool:
    """
    Регистрирует найденный флаг в result.
    Возвращает True если флаг новый, False если уже был найден ранее.
    Единая точка добавления флагов — исключает дубли из разных источников
    (общий поиск строк, ROT13, base64, ZIP содержимое и т.д.).
    """
    # Нормализуем для сравнения: убираем мусор вокруг флага
    for pat in _FLAG_PATTERNS:
        m = pat.search(flag)
        if m:
            clean_flag = m.group(0)
            if clean_flag in result._seen_flags:
                return False
            result._seen_flags.add(clean_flag)
            result.findings.append(Finding(
                title       = "🚩 Флаг найден!",
                severity    = "HIGH",
                description = f"Источник: {source}",
                data        = clean_flag,
                hint        = hint,
                technique   = 'Flag Pattern',
            ))
            return True
    return False


def _find_flags_in_strings(strings: list[str], result: AnalysisResult) -> None:
    """
    Ищет CTF флаги напрямую в строках файла.
    _flag_is_clean исключает широкий паттерн [A-Z]{2,8}{...} от срабатывания
    на ROT13-закодированных флагах (например gcvpbPGS{...} = picoCTF{...} в ROT13).
    """
    for s in strings:
        if looks_like_flag(s) and _flag_is_clean(s):
            _register_flag(s, result, source="прямое содержимое файла")


def _find_b64(strings: list[str], result: AnalysisResult) -> None:
    """Ищет и декодирует base64 фрагменты в строках."""
    seen: set[str] = set()
    for s in strings:
        for m in _RE_B64.finditer(s):
            candidate = m.group(0)
            if candidate in seen:
                continue
            seen.add(candidate)
            decoded = try_decode_base64(candidate)
            if not decoded:
                continue
            if looks_like_flag(decoded):
                _register_flag(decoded, result, source=f"base64: {candidate[:60]}")
            else:
                result.decoded.append(Finding(
                    title       = "Base64 декодировано",
                    severity    = "INFO",
                    description = f"Исходная строка: {candidate[:40]}…",
                    data        = decoded[:200],
                    technique   = 'Base64 Encoding',
                ))


def _find_hex(strings: list[str], result: AnalysisResult) -> None:
    """Ищет и декодирует hex фрагменты в строках."""
    seen: set[str] = set()
    for s in strings:
        for m in _RE_HEX.finditer(s):
            candidate = m.group(0)
            if candidate in seen:
                continue
            seen.add(candidate)
            decoded = try_decode_hex(candidate)
            if not decoded:
                continue
            if looks_like_flag(decoded):
                _register_flag(decoded, result, source=f"hex: {candidate[:40]}")
            else:
                result.decoded.append(Finding(
                    title       = "Hex декодировано",
                    severity    = "INFO",
                    description = f"Hex строка: {candidate[:40]}",
                    data        = decoded[:200],
                    technique   = 'Hex Encoding',
                ))


def _find_rot13(strings: list[str], result: AnalysisResult, limit: int = MAX_ROT_STRINGS) -> None:
    """Проверяет ASCII строки на ROT13. Сообщает только о флагах без мусора."""
    ascii_strings = [s for s in strings if len(s) > 10 and s.isascii()]
    for s in ascii_strings[:limit]:
        rot = try_rot13(s)
        if rot and looks_like_flag(rot) and _flag_is_clean(rot):
            _register_flag(rot, result, source=f"ROT13 от: {s[:60]}",
                           hint="Декодируй весь файл: "
                                "python3 -c \"import codecs; "
                                "print(codecs.decode(open('file').read(),'rot13'))\"")


def _find_embedded_files(data: bytes, result: AnalysisResult) -> None:
    """
    Карвинг: ищет magic bytes встроенных файлов.
    Поиск начинается с MIN_EMBEDDED_OFFSET чтобы не ложно сработать на
    magic bytes самого файла.
    Лимит MAX_EMBEDDED_PER_TYPE вхождений на тип — защита от DoS на
    синтетических файлах с повторяющимися magic bytes.
    """
    MAX_EMBEDDED_PER_TYPE = 5

    for sig, name in _EMBEDDED_SIGNATURES:
        # Ищем все вхождения, не только первое
        offset = MIN_EMBEDDED_OFFSET
        found_count = 0
        while found_count < MAX_EMBEDDED_PER_TYPE:
            pos = data.find(sig, offset)
            if pos == -1:
                break
            # Проверяем что это не просто случайное совпадение —
            # рядом должно быть достаточно данных
            if pos + len(sig) + 16 <= len(data):
                result.findings.append(Finding(
                    title       = f"Встроенный {name} файл",
                    severity    = "HIGH",
                    description = (
                        f"Найдены magic bytes {name} на смещении {pos}. "
                        "Внутри файла спрятан другой файл — классический CTF приём."
                    ),
                    data        = f"Смещение: {pos} байт (0x{pos:X})",
                    technique   = 'File Carving',
                ))
                found_count += 1
            offset = pos + len(sig)
        if found_count == MAX_EMBEDDED_PER_TYPE:
            result.findings.append(Finding(
                title       = f"Встроенный {name}: показаны первые {MAX_EMBEDDED_PER_TYPE} вхождений",
                severity    = "INFO",
                description = f"Найдено >{MAX_EMBEDDED_PER_TYPE} magic bytes {name} — возможно синтетический файл.",
                technique   = 'File Carving',
            ))


def _find_urls(strings: list[str], result: AnalysisResult) -> None:
    """Собирает URL-адреса из строк файла."""
    urls: list[str] = []
    seen: set[str] = set()
    for s in strings:
        for m in _RE_URL.finditer(s):
            url = m.group(0)
            if url not in seen:
                seen.add(url)
                urls.append(url)
    if urls:
        result.findings.append(Finding(
            title       = f"URL адреса ({len(urls)} шт.)",
            severity    = "MEDIUM",
            description = "Ссылки могут указывать на следующий шаг задачи.",
            data        = '\n'.join(urls[:MAX_URLS_DISPLAY]),
            technique   = 'URL Extraction',
        ))


_KEYWORD_SCAN_LIMIT = 65_536


def _find_keywords(data: bytes, result: AnalysisResult) -> None:
    """
    Ищет чувствительные ключевые слова из единого словаря _INTERESTING_KEYWORDS.
    Сканируем только первые 64 КБ: сканирование ограничено, поэтому
    создание строчной копии sample (64 КБ) безопасно и даёт полный
    case-insensitive поиск (lowercase, UPPERCASE, Title case и т.п.).
    """
    sample       = data[:_KEYWORD_SCAN_LIMIT]
    sample_lower = sample.lower()
    found = [
        kw for kw in _INTERESTING_KEYWORDS
        if kw.encode() in sample_lower
    ]
    if found:
        result.findings.append(Finding(
            title       = "Интересные ключевые слова",
            severity    = "MEDIUM",
            description = f"Найдены слова: {', '.join(found)}",
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
        severity    = "HIGH" if is_flag else "INFO",
        description = description_flag if is_flag else description_normal,
        data        = decoded[:200],
        technique   = technique,
    ))


def _find_extra_encodings(strings: list[str], result: AnalysisResult, limit: int = 200) -> None:
    """
    Проверяет строки на дополнительные виды кодирования:
    URL-encoding, HTML entities, бинарный код, азбука Морзе.
    """
    decoders = [
        (try_decode_url_encoding,   "🚩 Флаг в URL encoding!", "URL-декодировано",
         "URL encoding содержит флаг",                           lambda s: f"Исходная строка: {s[:60]}",
         'URL Encoding'),
        (try_decode_html_entities,  "🚩 Флаг в HTML entities!", "HTML-декодировано",
         "HTML entities содержат флаг",                          lambda s: f"Исходная строка: {s[:60]}",
         'HTML Entities'),
        (try_decode_binary_string,  "🚩 Флаг в бинарном коде!", "Бинарная строка декодирована",
         "Бинарный код содержит флаг",                           lambda s: f"Бинарный код: {s[:60]}…",
         'Binary Encoding'),
        (try_decode_morse,          "🚩 Флаг в азбуке Морзе!", "Азбука Морзе декодирована",
         "Морзе код содержит флаг",                              lambda s: f"Морзе код: {s[:60]}",
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


def analyze_xor_bruteforce(data: bytes, result: AnalysisResult) -> None:
    """
    Перебирает XOR-ключи 0x01–0xFF и ищет ключи при которых
    результат содержит читаемый текст или флаг.
    Запускается только при --xor флаге (медленно для больших файлов).
    """
    best_score  = 0.0
    candidates: list[tuple[float, int, str]] = []
    flag_keys:  set[int] = set()

    sample = data[:XOR_SAMPLE_SIZE]

    for key in XOR_KEY_RANGE:
        decrypted = try_decode_xor(sample, key)
        score     = score_xor_result(decrypted)
        if score > 0.7:
            preview       = safe_decode(decrypted[:80])
            sample_text   = safe_decode(decrypted)
            candidates.append((score, key, preview))
            if looks_like_flag(sample_text):
                flag_keys.add(key)
                full_decrypted = try_decode_xor(data, key)
                full_text      = safe_decode(full_decrypted)
                result.findings.append(Finding(
                    title       = f"🚩 Флаг при XOR ключ=0x{key:02X}!",
                    severity    = "HIGH",
                    description = f"XOR с ключом 0x{key:02X} даёт флаг.",
                    data        = full_text[:300],
                    technique   = 'XOR Cipher',
                ))

    # Show top-3 candidates that did not already produce a flag finding
    candidates.sort(reverse=True)
    for score, key, preview in candidates[:3]:
        if key not in flag_keys:
            result.decoded.append(Finding(
                title       = f"XOR ключ=0x{key:02X} (score={score:.0%})",
                severity    = "MEDIUM",
                description = "Результат XOR-дешифровки содержит читаемый текст:",
                data        = preview[:200],
                technique   = 'XOR Cipher',
            ))


def analyze_general(data: bytes, strings: list[str], result: AnalysisResult, deep: bool = False) -> None:
    """
    Общий анализ для любого файла.
    strings передаётся явно — нет скрытой зависимости от порядка вызовов
    и не нужна защитная проверка кэша внутри функции.
    Кэш result._strings_cache заполняется в analyze() до вызова этой функции.
    deep=True increases scan limits for ROT13 and extra encodings.
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


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ ИЗОБРАЖЕНИЙ
# ═════════════════════════════════════════════════════════════════════════════

def analyze_image(data: bytes, result: AnalysisResult) -> None:
    """Анализ изображений: EXIF, PNG chunks, LSB стеганография."""
    try:
        from PIL import Image
        import numpy as np

        img = Image.open(io.BytesIO(data))
        width, height = img.size
        mode = img.mode

        result.findings.append(Finding(
            title       = "Параметры изображения",
            severity    = "INFO",
            description = f"Размер: {width}×{height} пикселей, режим: {mode}, формат: {img.format}",
            technique   = 'Image Analysis',
        ))

        # ── EXIF метаданные ───────────────────────────────────────────────
        _analyze_exif(img, result)

        # ── PNG chunks ────────────────────────────────────────────────────
        if result.filetype == 'PNG':
            _analyze_png_chunks(data, result)

        # ── Аномальный размер файла ───────────────────────────────────────
        expected = width * height * len(img.getbands())
        if len(data) > expected * 1.5 and result.filetype in ('BMP', 'TIFF'):
            result.findings.append(Finding(
                title       = "Файл больше ожидаемого",
                severity    = "MEDIUM",
                description = (
                    f"Ожидаемый размер: {expected:,} байт, реальный: {len(data):,} байт. "
                    "После пиксельных данных могут быть спрятанные данные."
                ),
                technique   = 'File Carving',
            ))

        # ── LSB стеганография ─────────────────────────────────────────────
        if mode in ('RGB', 'RGBA', 'L'):
            arr = np.array(img)
            _analyze_lsb_image(arr, mode, result)

        # ── DCT стеганография (JPEG) ──────────────────────────────────────
        if result.filetype == 'JPEG':
            _analyze_jpeg_dct(data, result)

    except ImportError:
        result.findings.append(Finding(
            title       = "Pillow/numpy не установлены",
            severity    = "INFO",
            description = "Для анализа изображений: pip install Pillow numpy",
        ))
    except Exception as e:
        result.findings.append(Finding(
            title       = "Ошибка анализа изображения",
            severity    = "INFO",
            description = str(e),
        ))


def _analyze_exif(img, result: AnalysisResult) -> None:
    """Извлекает и анализирует EXIF метаданные."""
    try:
        from PIL.ExifTags import TAGS
        exif_raw = img._getexif() if hasattr(img, '_getexif') else None
        if not exif_raw:
            return

        exif_data: dict[str, str] = {
            str(TAGS.get(tag_id, tag_id)): str(value)[:200]
            for tag_id, value in exif_raw.items()
        }

        _INTERESTING_EXIF = {'comment', 'description', 'author', 'software',
                              'gps', 'user', 'copyright', 'artist', 'imagedescription'}
        interesting = {
            k: v for k, v in exif_data.items()
            if any(kw in k.lower() for kw in _INTERESTING_EXIF)
        }

        if interesting:
            exif_text = '\n'.join(f"{k}: {v}" for k, v in interesting.items())
            is_flag   = looks_like_flag(exif_text)
            result.findings.append(Finding(
                title       = "🚩 Флаг в EXIF!" if is_flag else "Интересные EXIF поля",
                severity    = "HIGH" if is_flag else "MEDIUM",
                description = "Найдены EXIF поля с потенциально полезными данными.",
                data        = exif_text,
                technique   = 'EXIF Analysis',
            ))
        else:
            result.findings.append(Finding(
                title       = "EXIF метаданные",
                severity    = "INFO",
                description = f"Найдено {len(exif_data)} полей.",
                data        = '\n'.join(f"{k}: {v}" for k, v in list(exif_data.items())[:5]),
                technique   = 'EXIF Analysis',
            ))
    except Exception:
        pass


def _analyze_png_chunks(data: bytes, result: AnalysisResult) -> None:
    """Парсит PNG chunk tree, ищет нестандартные и tEXt/iTXt/zTXt chunks."""
    pos = 8
    while pos + 12 <= len(data):
        try:
            chunk_len  = struct.unpack('>I', data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8].decode('ascii', errors='replace')

            # Защита: chunk не должен выходить за пределы файла
            if pos + 12 + chunk_len > len(data):
                result.findings.append(Finding(
                    title       = "Повреждённая структура PNG",
                    severity    = "MEDIUM",
                    description = f"Chunk '{chunk_type}' на позиции {pos} выходит за пределы файла. "
                                  "Файл может быть намеренно повреждён.",
                    technique   = 'PNG Analysis',
                ))
                break

            chunk_data = data[pos + 8: pos + 8 + chunk_len]

            if chunk_type == 'tEXt' and chunk_len < 50_000:
                text = chunk_data.decode('latin-1', errors='replace')
                is_flag = looks_like_flag(text)
                result.findings.append(Finding(
                    title       = "🚩 Флаг в PNG tEXt!" if is_flag else "PNG tEXt chunk",
                    severity    = "HIGH" if is_flag else "MEDIUM",
                    description = "Текстовый chunk PNG — популярное место для скрытых данных.",
                    data        = text[:500],
                    technique   = 'PNG Chunks',
                ))

            elif chunk_type == 'iTXt' and chunk_len < 50_000:
                # Структура iTXt: keyword\x00 + compression_flag(1) + compression_method(1)
                #                  + language_tag\x00 + translated_keyword\x00 + text
                # language_tag и translated_keyword — переменной длины, каждый заканчивается \x00.
                # Фиксированный сдвиг +4 давал мусор при непустом language_tag — ищем 3 нуля.
                try:
                    # 1-й \x00: конец keyword
                    null1 = chunk_data.index(b'\x00')
                    keyword = chunk_data[:null1].decode('latin-1', errors='replace')
                    # пропускаем compression_flag(1) + compression_method(1) = 2 байта
                    rest = chunk_data[null1 + 3:]
                    # 2-й \x00: конец language_tag (может быть пустым → сразу \x00)
                    null2 = rest.index(b'\x00')
                    rest = rest[null2 + 1:]
                    # 3-й \x00: конец translated_keyword (может быть пустым)
                    null3 = rest.index(b'\x00')
                    text  = rest[null3 + 1:].decode('utf-8', errors='replace')
                    is_flag = looks_like_flag(text)
                    result.findings.append(Finding(
                        title       = "🚩 Флаг в PNG iTXt!" if is_flag else f"PNG iTXt chunk '{keyword}'",
                        severity    = "HIGH" if is_flag else "MEDIUM",
                        description = "Международный текстовый chunk PNG.",
                        data        = text[:500],
                        technique   = 'PNG Chunks',
                    ))
                except Exception:
                    pass

            elif chunk_type == 'zTXt' and chunk_len < 50_000:
                # zTXt — сжатый текст, декомпрессируем
                try:
                    null_pos    = chunk_data.index(b'\x00')
                    keyword     = chunk_data[:null_pos].decode('latin-1', errors='replace')
                    compressed  = chunk_data[null_pos + 2:]
                    dec_obj = zlib.decompressobj()
                    decompressed = dec_obj.decompress(compressed, MAX_DECOMPRESS_SIZE)
                    text = decompressed.decode('utf-8', errors='replace')
                    is_flag = looks_like_flag(text)
                    result.findings.append(Finding(
                        title       = "🚩 Флаг в PNG zTXt!" if is_flag else f"PNG zTXt chunk '{keyword}'",
                        severity    = "HIGH" if is_flag else "MEDIUM",
                        description = "Сжатый текстовый chunk PNG.",
                        data        = text[:500],
                        technique   = 'PNG Chunks',
                    ))
                except Exception:
                    pass

            elif chunk_type not in _PNG_STANDARD_CHUNKS:
                result.findings.append(Finding(
                    title       = f"Нестандартный PNG chunk: '{chunk_type}'",
                    severity    = "HIGH",
                    description = (
                        f"Chunk '{chunk_type}' размером {chunk_len} байт на позиции {pos}. "
                        "Нестандартные chunks часто используются для скрытия данных."
                    ),
                    data        = f"Первые байты: {chunk_data[:20].hex()}",
                    technique   = 'PNG Chunks',
                ))

            pos += 12 + chunk_len
        except Exception:
            break


def _analyze_lsb_image(arr, mode: str, result: AnalysisResult) -> None:
    """
    LSB-анализ изображения. Проверяет каждый канал отдельно.
    Логика:
      entropy < LSB_ENTROPY_EMPTY (≈0)  → канал однородный (одного цвета) — НЕ стего
      entropy < LSB_ENTROPY_THRESHOLD   → биты неслучайны, но не нулевые — СТЕГО
      entropy ≈ 1.0                     → биты случайны — норма для реального изображения
    """
    import numpy as np

    channel_map: dict[str, list[tuple[int, str]]] = {
        'RGB':  [(0, 'R'), (1, 'G'), (2, 'B')],
        'RGBA': [(0, 'R'), (1, 'G'), (2, 'B'), (3, 'A')],
        'L':    [(0, 'L')],
    }
    channels = channel_map.get(mode, [(0, 'CH0')])

    stego_found = False

    for ch_idx, ch_name in channels:
        if mode == 'L':
            lsb_bits = (arr & 1).flatten()
        else:
            lsb_bits = (arr[:, :, ch_idx] & 1).flatten()

        entropy = _lsb_entropy(lsb_bits)

        if entropy < LSB_ENTROPY_EMPTY:
            # Все биты одинаковы → однородный цвет → это НЕ признак стего
            # Просто инфо-сообщение, не шум HIGH
            result.findings.append(Finding(
                title       = f"LSB канал {ch_name} — однородный",
                severity    = "INFO",
                description = (
                    f"Энтропия LSB канала {ch_name}: {entropy:.3f}. "
                    "Все пиксели одного цвета, стеганографии нет."
                ),
                technique   = 'LSB Steganography',
            ))
        elif entropy < LSB_ENTROPY_THRESHOLD:
            # Биты не случайны и не нулевые — реальный признак стего
            stego_found = True
            result.findings.append(Finding(
                title       = f"⚠️ Подозрение на LSB стего — канал {ch_name}",
                severity    = "HIGH",
                description = (
                    f"Энтропия LSB канала {ch_name}: {entropy:.3f} (норма ≈1.0). "
                    "Биты неслучайны — признак LSB стеганографии."
                ),
                hint        = "Используй stegsolve (Java), zsteg (Ruby: gem install zsteg) "
                              "или онлайн: stylesuxx.github.io/steganography",
                technique   = 'LSB Steganography',
            ))
            _extract_lsb_text(lsb_bits, result, f"канал {ch_name}")
        else:
            # Норма — не показываем чтобы не засорять вывод
            pass

    # Bit-plane анализ только если стего не нашли в LSB
    # (если нашли — bit-plane даст дублирующую информацию)
    if not stego_found and mode in ('RGB', 'RGBA'):
        for bit in (1, 2):
            plane_bits = (arr[:, :, 0] >> bit & 1).flatten()
            plane_ent  = _lsb_entropy(plane_bits)
            if LSB_ENTROPY_EMPTY < plane_ent < LSB_ENTROPY_THRESHOLD:
                result.findings.append(Finding(
                    title       = f"⚠️ Подозрительный bit-plane {bit} канала R",
                    severity    = "MEDIUM",
                    description = (
                        f"Энтропия бит-плана {bit} канала R: {plane_ent:.3f}. "
                        "Данные могут быть спрятаны не только в LSB."
                    ),
                    hint        = "Попробуй stegsolve → Bit Plane Browser для визуализации.",
                    technique   = 'LSB Steganography',
                ))


_JPEG_STANDALONE: frozenset[int] = frozenset({
    0xD8, 0xD9, 0x01,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
})


def _analyze_jpeg_dct(data: bytes, result: AnalysisResult) -> None:

    pos = 2
    max_iterations = 50_000
    iterations = 0
    while pos < len(data) - 2 and iterations < max_iterations:
        iterations += 1
        if data[pos] != 0xFF:
            pos += 1
            continue

        # Пропускаем fill bytes (0xFF 0xFF ... перед маркером)
        marker_byte = data[pos + 1]
        if marker_byte == 0xFF:
            pos += 1
            continue

        # Standalone маркеры: нет поля длины — сразу переходим на следующий байт
        if marker_byte in _JPEG_STANDALONE:
            pos += 2
            continue

        # Остальные маркеры: 2 байта маркер + 2 байта длина (включает себя)
        if pos + 4 > len(data):
            break
        marker_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        if marker_len < 2:
            break

        if marker_byte == 0xFE:
            comment_data = data[pos + 4: pos + 2 + marker_len]
            comment_text = safe_decode(comment_data)
            is_flag = looks_like_flag(comment_text)
            result.findings.append(Finding(
                title       = "🚩 Флаг в JPEG COM!" if is_flag else "JPEG комментарий",
                severity    = "HIGH" if is_flag else "MEDIUM",
                description = "JPEG COM маркер содержит текст.",
                data        = comment_text[:300],
                technique   = 'JPEG Analysis',
            ))

        elif 0xE1 <= marker_byte <= 0xEF:
            app_data = data[pos + 4: pos + 2 + marker_len]
            app_text = safe_decode(app_data)
            if any(kw in app_text.lower() for kw in _INTERESTING_KEYWORDS):
                result.findings.append(Finding(
                    title       = f"JPEG APP{marker_byte - 0xE0} метаданные",
                    severity    = "MEDIUM",
                    description = "APP маркер содержит интересные данные.",
                    data        = app_text[:200],
                    technique   = 'JPEG Analysis',
                ))

        pos += 2 + marker_len

    eoi_pos = data.rfind(b'\xff\xd9')

    if eoi_pos > 0 and eoi_pos < len(data) - 2:
        trailing = data[eoi_pos + 2:]
        if len(trailing) > 4:
            result.findings.append(Finding(
                title       = "Данные после конца JPEG",
                severity    = "HIGH",
                description = (
                    f"Найдено {len(trailing)} байт после EOI маркера (конец JPEG). "
                    "Классическое место для скрытого файла."
                ),
                data        = f"Первые байты: {trailing[:20].hex()}",
                technique   = 'File Carving',
            ))


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ АУДИО
# ═════════════════════════════════════════════════════════════════════════════

def analyze_audio(data: bytes, result: AnalysisResult) -> None:
    """Анализ аудио файлов: WAV, MP3, FLAC, OGG."""
    try:
        if result.filetype == 'WAV':
            _analyze_wav(data, result)
        elif result.filetype == 'MP3':
            _analyze_mp3(data, result)
        elif result.filetype == 'FLAC':
            _analyze_flac(data, result)
    except Exception as e:
        result.findings.append(Finding(
            title       = "Ошибка анализа аудио",
            severity    = "INFO",
            description = str(e),
        ))


def _analyze_wav(data: bytes, result: AnalysisResult) -> None:
    """Анализ WAV: заголовок, LSB на сэмплах, нестандартные chunks."""
    if len(data) < 44:
        return

    try:
        channels    = struct.unpack_from('<H', data, 22)[0]
        sample_rate = struct.unpack_from('<I', data, 24)[0]
        bit_depth   = struct.unpack_from('<H', data, 34)[0]
    except struct.error:
        return

    result.findings.append(Finding(
        title       = "Параметры WAV",
        severity    = "INFO",
        description = f"Каналов: {channels}, частота: {sample_rate} Гц, глубина: {bit_depth} бит",
        technique   = 'Audio Analysis',
    ))

    data_offset = _find_riff_chunk(data, b'data')
    if data_offset is not None and bit_depth in (8, 16):
        audio_bytes = data[data_offset + 8:]
        if len(audio_bytes) >= 100:
            try:
                import numpy as np
                dtype    = np.int16 if bit_depth == 16 else np.uint8
                samples  = np.frombuffer(audio_bytes[:min(len(audio_bytes), 200_000)], dtype=dtype)
                lsb_bits = (samples & 1)
                lsb_ent  = _lsb_entropy(lsb_bits)

                if lsb_ent < LSB_ENTROPY_THRESHOLD:
                    result.findings.append(Finding(
                        title       = "⚠️ Подозрение на LSB стего в аудио",
                        severity    = "HIGH",
                        description = (
                            f"Энтропия LSB аудио-сэмплов: {lsb_ent:.3f} (норма ≈1.0). "
                            "В CTF часто прячут данные в LSB аудио."
                        ),
                        technique   = 'LSB Steganography',
                    ))
                    _extract_lsb_text(lsb_bits, result, "аудио-сэмплы")
                else:
                    result.findings.append(Finding(
                        title       = "LSB аудио — норма",
                        severity    = "INFO",
                        description = f"Энтропия LSB: {lsb_ent:.3f}",
                        technique   = 'LSB Steganography',
                    ))
            except ImportError:
                result.findings.append(Finding(
                    title       = "numpy не установлен",
                    severity    = "INFO",
                    description = "Для LSB-анализа аудио: pip install numpy",
                    technique   = 'LSB Steganography',
                ))

    # Нестандартные RIFF chunks
    pos = 12
    while pos + 8 <= min(len(data), WAV_SCAN_LIMIT):
        try:
            chunk_id  = data[pos:pos + 4].decode('ascii', errors='replace')
            chunk_len = struct.unpack_from('<I', data, pos + 4)[0]

            # Защита от chunk_len = 0xFFFFFFFF (повреждённый файл)
            if pos + 8 + chunk_len > len(data):
                break

            if chunk_id not in _WAV_STANDARD_CHUNKS:
                chunk_data = data[pos + 8: pos + 8 + min(chunk_len, 200)]
                result.findings.append(Finding(
                    title       = f"Нестандартный WAV chunk: '{chunk_id}'",
                    severity    = "HIGH",
                    description = f"Chunk '{chunk_id}' размером {chunk_len} байт — может скрывать данные.",
                    data        = f"Первые байты: {chunk_data.hex()}",
                    technique   = 'Audio Chunks',
                ))

            pos += 8 + chunk_len + (chunk_len & 1)
            if chunk_len == 0:
                break
        except Exception:
            break


def _find_riff_chunk(data: bytes, chunk_id: bytes) -> Optional[int]:
    """
    Ищет RIFF chunk по ID через корректный обход chunk tree (не через .find()).
    data.find(b'data') давал ложные срабатывания на ASCII строках в метаданных.
    """
    pos = 12
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        try:
            clen = struct.unpack_from('<I', data, pos + 4)[0]
        except struct.error:
            break
        if cid == chunk_id:
            return pos
        if pos + 8 + clen > len(data):
            break
        if clen == 0:
            pos += 8
            continue
        pos += 8 + clen + (clen & 1)
    return None


def _analyze_mp3(data: bytes, result: AnalysisResult) -> None:
    """Анализ MP3: ID3 теги, данные после конца файла."""
    if data[:3] == b'ID3':
        # Парсим ID3v2 заголовок для получения размера тегов
        try:
            # ID3v2 size: 4 байта с 7-битными значениями (synchsafe integer)
            raw_size = struct.unpack_from('>I', data, 6)[0]
            id3_size = (
                ((raw_size >> 24) & 0x7F) << 21 |
                ((raw_size >> 16) & 0x7F) << 14 |
                ((raw_size >> 8)  & 0x7F) << 7  |
                ((raw_size)       & 0x7F)
            )
            tag_end = 10 + id3_size

            result.findings.append(Finding(
                title       = "ID3 теги найдены",
                severity    = "MEDIUM",
                description = (
                    f"MP3 содержит ID3v2 теги ({id3_size} байт). "
                    "Проверь поля Comment, UserText, Picture (APIC) на скрытые данные."
                ),
                technique   = 'Audio Tags',
            ))

            # Ищем интересное в ID3 payload
            id3_payload = data[10:tag_end]
            id3_text    = safe_decode(id3_payload)
            if looks_like_flag(id3_text):
                result.findings.append(Finding(
                    title       = "🚩 Флаг в ID3 тегах!",
                    severity    = "HIGH",
                    description = "ID3 теги содержат строку похожую на флаг.",
                    data        = id3_text[:300],
                    technique   = 'Audio Tags',
                ))
        except Exception:
            result.findings.append(Finding(
                title       = "ID3 теги найдены",
                severity    = "MEDIUM",
                description = "MP3 содержит ID3 теги. Проверь Comment и Picture поля.",
                technique   = 'Audio Tags',
            ))

    # Поиск данных после конца MP3.
    # Проблема rfind: последний sync word находится внутри последнего фрейма,
    # а не после него — фрейм ещё продолжается на 144–1440 байт.
    # Условие last_frame < len(data) - 1000 давало ложные HIGH на любом нормальном MP3.
    # Исправление: парсим размер фрейма из заголовка чтобы знать где фрейм заканчивается.
    # rfind находит ПОСЛЕДНЕЕ вхождение sync-слова, которое может быть внутри ID3-тегов
    # или метаданных — ложное совпадение сдвигает last_frame_end в неверное место.
    # Исправление: сканируем весь файл вперёд и берём максимальный валидный frame_end.
    _MP3_BITRATE_TABLE = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0
    ]
    mp3_sync_patterns = [b'\xff\xfb', b'\xff\xfa', b'\xff\xe3', b'\xff\xe2']
    last_frame_end = -1

    for sync in mp3_sync_patterns:
        search_start = 0
        while True:
            pos = data.find(sync, search_start)
            if pos < 0 or pos + 4 > len(data):
                break
            search_start = pos + 1
            try:
                hdr         = struct.unpack_from('>I', data, pos)[0]
                bitrate_idx = (hdr >> 12) & 0xF
                sr_idx      = (hdr >> 10) & 0x3
                padding     = (hdr >> 9)  & 0x1

                bitrate     = _MP3_BITRATE_TABLE[bitrate_idx] * 1000
                sample_rates = [44100, 48000, 32000, 0]
                sample_rate  = sample_rates[sr_idx]

                if bitrate > 0 and sample_rate > 0:
                    # Размер фрейма MPEG1 Layer3: 144 * bitrate / sample_rate + padding
                    frame_size = 144 * bitrate // sample_rate + padding
                    frame_end  = pos + frame_size
                    if frame_end > last_frame_end:
                        last_frame_end = frame_end
            except Exception:
                continue

    if last_frame_end > 0 and last_frame_end < len(data):
        trailing_size = len(data) - last_frame_end
        has_id3v1 = len(data) >= 128 and data[-128:-125] == b'TAG'
        if trailing_size > 128 and not (has_id3v1 and trailing_size <= 130):
            result.findings.append(Finding(
                title       = "Данные после конца MP3",
                severity    = "HIGH",
                description = (
                    f"Найдено {trailing_size} байт после последнего MP3 фрейма. "
                    "Классическое место для скрытого файла."
                ),
                data        = (
                    f"Начало trailing: {last_frame_end} (0x{last_frame_end:X}), "
                    f"первые байты: {data[last_frame_end:last_frame_end + 16].hex()}"
                ),
                technique   = 'File Carving',
            ))


def _analyze_flac(data: bytes, result: AnalysisResult) -> None:
    """Базовый анализ FLAC: поиск VORBIS_COMMENT и PICTURE блоков."""
    result.findings.append(Finding(
        title       = "FLAC файл",
        severity    = "INFO",
        description = "FLAC содержит metadata блоки: VORBIS_COMMENT (теги), PICTURE (обложка). "
                      "Проверь теги на скрытые данные.",
        technique   = 'Audio Analysis',
    ))
    # Ищем строки с ключевыми словами в метаданных
    strings = extract_strings(data[:65536])
    for s in strings:
        if looks_like_flag(s):
            _register_flag(s, result, source="FLAC метаданные")


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ АРХИВОВ
# ═════════════════════════════════════════════════════════════════════════════

def analyze_archive(data: bytes, result: AnalysisResult) -> None:
    """Анализ архивов: ZIP, GZIP, BZIP2."""
    if result.filetype == 'ZIP':
        _analyze_zip(data, result)
    elif result.filetype == 'GZIP':
        _analyze_gzip(data, result)
    elif result.filetype == 'BZIP2':
        _analyze_bzip2(data, result)


def _analyze_zip(data: bytes, result: AnalysisResult) -> None:
    """Анализ ZIP: содержимое, шифрование, комментарий, вложенные файлы."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()

            result.findings.append(Finding(
                title       = f"ZIP содержит {len(names)} файл(ов)",
                severity    = "INFO",
                description = '\n'.join(names[:30]),
                technique   = 'Archive Analysis',
            ))

            # Зашифрованные файлы — flag_bits & 0x1 (bit 0 по PKWARE APPNOTE 4.4.4)
            ZIP_ENCRYPT_BIT = 0x1
            encrypted = [i for i in zf.infolist() if i.flag_bits & ZIP_ENCRYPT_BIT]
            if encrypted:
                result.findings.append(Finding(
                    title       = f"Зашифрованные файлы в ZIP ({len(encrypted)} шт.)",
                    severity    = "HIGH",
                    description = (
                        "Файлы защищены паролем. Типичные CTF пароли: "
                        "password, 123456, flag, ctf, или пароль в других файлах задачи."
                    ),
                    data        = '\n'.join(e.filename for e in encrypted[:10]),
                    technique   = 'Archive Analysis',
                ))

            # Комментарий архива
            if zf.comment:
                comment = safe_decode(zf.comment)
                is_flag = looks_like_flag(comment)
                if is_flag:
                    _register_flag(comment, result, source="комментарий ZIP архива",
                                   hint="Посмотри комментарий: unzip -z archive.zip")
                else:
                    result.findings.append(Finding(
                        title       = "Комментарий ZIP",
                        severity    = "MEDIUM",
                        description = "ZIP файл содержит комментарий.",
                        data        = comment[:500],
                        technique   = 'Archive Analysis',
                    ))

            # Проверяем содержимое файлов
            for name in names[:MAX_ZIP_FILES_INSPECT]:
                try:
                    info = zf.getinfo(name)
                    # ZIP bomb guard: file_size is declared in central directory
                    # and can be arbitrarily large without actual data
                    if info.file_size > MAX_DECOMPRESS_SIZE:
                        result.findings.append(Finding(
                            title       = f"Потенциальная ZIP-бомба: '{name}'",
                            severity    = "HIGH",
                            description = (
                                f"Файл '{name}' декларирует размер {info.file_size:,} байт "
                                f"(>{MAX_DECOMPRESS_SIZE // 1024**2} МБ) — пропускаем."
                            ),
                            technique   = 'Archive Analysis',
                        ))
                        continue
                    content = zf.read(name)
                    content_text = safe_decode(content)
                    if looks_like_flag(content_text):
                        _register_flag(content_text, result,
                                       source=f"файл '{name}' внутри ZIP",
                                       hint="Распакуй: unzip archive.zip -d папка/")
                    elif len(content) > 4 and content[:4] == b'PK\x03\x04' and len(content) < 10_000_000:
                        result.findings.append(Finding(
                            title       = f"Вложенный ZIP: '{name}'",
                            severity    = "MEDIUM",
                            description = f"Файл '{name}' внутри архива сам является ZIP архивом.",
                            technique   = 'Archive Analysis',
                        ))
                except Exception:
                    continue

    except zipfile.BadZipFile:
        result.findings.append(Finding(
            title       = "Повреждённый ZIP",
            severity    = "MEDIUM",
            description = (
                "Файл имеет ZIP magic bytes но не является корректным ZIP. "
                "Возможно намеренно повреждён (CTF-приём) или это другой формат на основе ZIP."
            ),
            technique   = 'Archive Analysis',
        ))


def _analyze_gzip(data: bytes, result: AnalysisResult) -> None:
    """Анализ GZIP с защитой от ZIP-бомб."""
    try:
        # Читаем с ограничением размера через GzipFile.read(max_size)
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            decompressed = gz.read(MAX_DECOMPRESS_SIZE + 1)

        if len(decompressed) > MAX_DECOMPRESS_SIZE:
            result.findings.append(Finding(
                title       = "GZIP-бомба или очень большой файл",
                severity    = "HIGH",
                description = f"Распакованный размер превышает {MAX_DECOMPRESS_SIZE // 1024**2} МБ.",
                technique   = 'Archive Analysis',
            ))
            decompressed = decompressed[:MAX_DECOMPRESS_SIZE]

        result.findings.append(Finding(
            title       = "GZIP успешно распакован",
            severity    = "INFO",
            description = f"Распакованный размер: {len(decompressed):,} байт",
            technique   = 'Archive Analysis',
        ))

        content_text = safe_decode(decompressed)
        if looks_like_flag(content_text):
            result.findings.append(Finding(
                title       = "🚩 Флаг в GZIP!",
                severity    = "HIGH",
                description = "Распакованные данные содержат флаг.",
                data        = content_text[:300],
                technique   = 'Archive Analysis',
            ))

    except Exception as e:
        result.findings.append(Finding(
            title       = "Ошибка распаковки GZIP",
            severity    = "MEDIUM",
            description = str(e),
            technique   = 'Archive Analysis',
        ))


def _analyze_bzip2(data: bytes, result: AnalysisResult) -> None:
    """
    Анализ BZIP2 с защитой от бомб через инкрементальное чтение.
    bz2.decompress(data) — читает всё целиком без лимита, OOM-уязвимость.
    bz2.BZ2File.read(limit) — останавливается по достижении лимита как GzipFile.
    bz2 импортирован на уровне модуля.
    """
    try:
        with bz2.BZ2File(io.BytesIO(data)) as bz:
            decompressed = bz.read(MAX_DECOMPRESS_SIZE + 1)

        if len(decompressed) > MAX_DECOMPRESS_SIZE:
            result.findings.append(Finding(
                title       = "BZIP2-бомба или очень большой файл",
                severity    = "HIGH",
                description = (
                    f"Распакованный размер превышает {MAX_DECOMPRESS_SIZE // 1024**2} МБ. "
                    "Чтение ограничено."
                ),
                technique   = 'Archive Analysis',
            ))
            decompressed = decompressed[:MAX_DECOMPRESS_SIZE]

        result.findings.append(Finding(
            title       = "BZIP2 успешно распакован",
            severity    = "INFO",
            description = f"Размер: {len(decompressed):,} байт",
            technique   = 'Archive Analysis',
        ))
        content_text = safe_decode(decompressed)
        if looks_like_flag(content_text):
            result.findings.append(Finding(
                title       = "🚩 Флаг в BZIP2!",
                severity    = "HIGH",
                description = "Распакованные данные содержат флаг.",
                data        = content_text[:300],
                technique   = 'Archive Analysis',
            ))
    except Exception as e:
        result.findings.append(Finding(
            title       = "Ошибка распаковки BZIP2",
            severity    = "MEDIUM",
            description = str(e),
            technique   = 'Archive Analysis',
        ))


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ ТЕКСТА
# ═════════════════════════════════════════════════════════════════════════════

# Все 25 Caesar-таблиц предвычислены при импорте модуля (сдвиги 1–25).
# tuple вместо мутабельного dict — иммутабелен, не накапливает state между вызовами,
# индексируется как _CAESAR_TABLES[shift - 1] (shift=1 → index=0).
_CAESAR_TABLES: tuple[dict, ...] = tuple(
    str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[s:] + string.ascii_uppercase[:s] +
        string.ascii_lowercase[s:] + string.ascii_lowercase[:s],
    )
    for s in range(1, 26)
)


def analyze_text(data: bytes, result: AnalysisResult) -> None:
    """Анализ текстовых файлов: whitespace стего, null байты, Caesar."""
    text  = safe_decode(data)
    lines = text.splitlines()

    result.findings.append(Finding(
        title       = "Текстовый файл",
        severity    = "INFO",
        description = f"Строк: {len(lines)}, символов: {len(text)}",
        technique   = 'Text Analysis',
    ))

    _analyze_whitespace_stego(lines, result)
    _analyze_null_bytes(text, result)
    _analyze_caesar(text, result)
    _analyze_atbash(text, result)
    _analyze_vigenere_hint(text, result)


def _analyze_whitespace_stego(lines: list[str], result: AnalysisResult) -> None:
    """
    Whitespace стеганография: декодирует данные из trailing пробелов/табов.
    Исправление: кодируются только trailing whitespace (хвост строки),
    а не все пробелы внутри строки.
    """
    if not lines:
        return
    trailing_lines = [i for i, line in enumerate(lines) if line.endswith((' ', '\t'))]
    if len(trailing_lines) / len(lines) < MIN_WHITESPACE_RATIO:
        return

    result.findings.append(Finding(
        title       = "⚠️ Whitespace стеганография",
        severity    = "HIGH",
        description = (
            f"{len(trailing_lines)} строк из {len(lines)} имеют trailing пробелы/табы. "
            "Декодирование: пробел=0, таб=1."
        ),
        technique   = 'Whitespace Steganography',
    ))

    # Извлекаем ТОЛЬКО trailing whitespace каждой строки
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

    # Собираем байты из битов (MSB first)
    decoded_bytes = bytearray(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits) - 7, 8)
    )
    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
    readable = ''.join(c for c in decoded_text if c in string.printable)

    if readable:
        is_flag = looks_like_flag(readable)
        result.decoded.append(Finding(
            title       = "🚩 Флаг из whitespace!" if is_flag else "Whitespace декодировано",
            severity    = "HIGH" if is_flag else "INFO",
            description = "Данные из trailing пробелов/табов:",
            data        = readable[:300],
            technique   = 'Whitespace Steganography',
        ))


def _analyze_null_bytes(text: str, result: AnalysisResult) -> None:
    """Обнаружение нулевых байт в тексте — признак бинарного или скрытого контента."""
    null_count = text.count('\x00')
    if null_count > 5:
        result.findings.append(Finding(
            title       = f"Нулевые байты в тексте ({null_count} шт.)",
            severity    = "MEDIUM",
            description = "Нулевые байты в текстовом файле — возможно стеганография или бинарные данные.",
            technique   = 'Text Analysis',
        ))


def _analyze_caesar(text: str, result: AnalysisResult) -> None:
    """
    Проверяет все 25 сдвигов Caesar (ROT1–ROT25).
    Исправления vs оригинал:
      1. break удалён — ищем ВСЕ валидные сдвиги, не только первый
      2. len(words) > MAX_CAESAR_TOTAL_WORDS (> вместо >=)
      3. translate-таблицы предвычислены при импорте в _CAESAR_TABLES (иммутабельный tuple)
    """
    words = _RE_WORD_4PLUS.findall(text)
    if not words or len(words) > MAX_CAESAR_TOTAL_WORDS:
        return

    # Применяем ко всему тексту — скобки и спецсимволы сохраняются (как в _analyze_atbash),
    # иначе 'picoCTF{...}' разрушается при сборке из отдельных слов.
    sample_text = text[:MAX_CAESAR_WORDS * 10]

    for shift in range(1, 26):
        table = _CAESAR_TABLES[shift - 1]

        shifted_sample = sample_text.translate(table)
        shifted_set    = {w.lower() for w in _RE_WORD_4PLUS.findall(shifted_sample)}

        has_common = len(shifted_set & _CAESAR_COMMON_WORDS) >= 2
        is_flag    = looks_like_flag(shifted_sample)

        if has_common or is_flag:
            result.findings.append(Finding(
                title       = f"🚩 Флаг Caesar сдвиг {shift}!" if is_flag else f"Caesar сдвиг {shift}",
                severity    = "HIGH" if is_flag else "MEDIUM",
                description = f"Сдвиг на {shift} {'даёт флаг' if is_flag else 'даёт читаемый текст'}.",
                data        = shifted_sample[:300],
                technique   = 'Caesar Cipher',
            ))
            # break НАМЕРЕННО УДАЛЁН — продолжаем искать все валидные сдвиги


def _analyze_atbash(text: str, result: AnalysisResult) -> None:
    """
    Шифр Атбаш: A↔Z, B↔Y и т.д.
    Популярен в CTF наряду с Caesar.
    Важно: применяем ко всему тексту (включая скобки), не только к словам —
    иначе паттерн 'flag{...}' разрушается при сборке из words.
    """
    if not text.strip():
        return

    atbash_table = str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1],
    )

    # Применяем ко всему тексту — скобки и спецсимволы сохраняются
    sample  = text[:MAX_CAESAR_WORDS * 10]
    decoded = sample.translate(atbash_table)

    decoded_words = {w.lower() for w in _RE_WORD_4PLUS.findall(decoded)}
    has_common    = len(decoded_words & _CAESAR_COMMON_WORDS) >= 2
    is_flag       = looks_like_flag(decoded) and _flag_is_clean(decoded)

    if has_common or is_flag:
        if is_flag:
            _register_flag(decoded, result, source="шифр Атбаш (A↔Z)",
                           hint="Расшифруй: python3 -c \"import string; "
                                "t=str.maketrans(string.ascii_letters,"
                                "string.ascii_uppercase[::-1]+string.ascii_lowercase[::-1]);"
                                "print(open('file').read().translate(t))\"")
        else:
            result.findings.append(Finding(
                title       = "Шифр Атбаш",
                severity    = "MEDIUM",
                description = "Шифр Атбаш (A↔Z) даёт читаемый текст.",
                data        = decoded[:300],
                hint        = "Попробуй расшифровать весь файл через Атбаш.",
                technique   = 'Atbash Cipher',
            ))


def _analyze_vigenere_hint(text: str, result: AnalysisResult) -> None:
    """
    Проверяет признаки шифра Виженера (индекс совпадений).
    Полный взлом требует знания длины ключа — здесь даём подсказку.
    """
    letters_only = re.sub(r'[^a-zA-Z]', '', text).lower()
    if len(letters_only) < 100:
        return

    # Индекс совпадений (Index of Coincidence)
    # Для английского текста ≈ 0.065, для случайного ≈ 0.038
    freq = Counter(letters_only)
    n    = len(letters_only)
    ic   = sum(c * (c - 1) for c in freq.values()) / (n * (n - 1))

    if ic < 0.05:
        result.findings.append(Finding(
            title       = "⚠️ Возможен шифр Виженера",
            severity    = "MEDIUM",
            description = (
                f"Индекс совпадений: {ic:.4f} (норма для EN ≈ 0.065, случайный ≈ 0.038). "
                "Низкий IC указывает на полиалфавитный шифр (Виженер, Beaufort и т.п.)."
            ),
            technique   = 'Vigenere Analysis',
        ))


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ БИНАРНИКОВ
# ═════════════════════════════════════════════════════════════════════════════

def analyze_executable(data: bytes, result: AnalysisResult) -> None:
    """Анализ исполняемых файлов: ELF, EXE, CLASS."""
    # _strings_cache гарантированно заполнен в analyze() до вызова этой функции.
    # Прямой вызов analyze_executable() минуя analyze() не поддерживается.
    strings = result._strings_cache

    result.findings.append(Finding(
        title       = f"Строки в бинарнике ({len(strings)} шт.)",
        severity    = "INFO",
        description = f"Извлечены строки длиннее {MIN_STRING_LEN_EXEC} символов.",
        technique   = 'Binary Analysis',
    ))

    interesting: list[str] = []
    for s in strings:
        if looks_like_flag(s):
            result.findings.append(Finding(
                title       = "🚩 Флаг в бинарнике!",
                severity    = "HIGH",
                description = "Найдена строка соответствующая паттерну флага.",
                data        = s,
                technique   = 'Binary Analysis',
            ))
        elif any(kw in s.lower() for kw in _INTERESTING_KEYWORDS):
            interesting.append(s)

    if interesting:
        result.findings.append(Finding(
            title       = f"Интересные строки ({len(interesting)} шт.)",
            severity    = "MEDIUM",
            description = "Строки содержащие ключевые слова:",
            data        = '\n'.join(interesting[:20]),
            technique   = 'Binary Analysis',
        ))

    # ELF-специфичный анализ
    if result.filetype == 'ELF':
        _analyze_elf(data, result)

    # PE-специфичный анализ
    elif result.filetype == 'EXE':
        _analyze_pe(data, result)


def _analyze_elf(data: bytes, result: AnalysisResult) -> None:
    """ELF: разрядность, архитектура, подозрительные секции."""
    if len(data) < 64:
        return

    elf_class = data[4]
    ei_data   = data[5]
    e_machine = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 18)[0]

    arch_map = {
        0x03: 'x86', 0x3E: 'x86-64', 0x28: 'ARM', 0xB7: 'AArch64',
        0x08: 'MIPS', 0x14: 'PowerPC', 0x02: 'SPARC',
    }
    arch = arch_map.get(e_machine, f'unknown (0x{e_machine:04X})')
    bits = '64-bit' if elf_class == 2 else '32-bit'
    endian = 'little-endian' if ei_data == 1 else 'big-endian'

    result.findings.append(Finding(
        title       = f"ELF бинарник: {bits} {arch} {endian}",
        severity    = "INFO",
        description = "Для анализа: objdump, readelf, gdb, ghidra, radare2.",
        technique   = 'ELF Analysis',
    ))

    # Ищем строку .note. и другие нестандартные секции.
    # data.lower() на 512 МБ создаёт вторую копию в памяти — используем уже
    # извлечённые строки из кэша (result._strings_cache заполнен в analyze()).
    elf_strings_lower = {s.lower() for s in result._strings_cache}
    if b'.ctf' in data or any('flag' in s or 'ctf' in s for s in elf_strings_lower):
        result.findings.append(Finding(
            title       = "Подозрительные ELF секции",
            severity    = "HIGH",
            description = "ELF содержит секции или данные с именами 'flag' или 'ctf'.",
            technique   = 'ELF Analysis',
        ))


def _analyze_pe(data: bytes, result: AnalysisResult) -> None:
    """PE (EXE/DLL): базовая информация."""
    try:
        # Находим PE header через e_lfanew (смещение в MZ заголовке)
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 6 > len(data):
            return
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return

        machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
        pe_arch = {0x14C: 'x86', 0x8664: 'x86-64', 0x1C0: 'ARM', 0xAA64: 'AArch64'}.get(machine, f'0x{machine:04X}')

        result.findings.append(Finding(
            title       = f"PE бинарник (Windows) — {pe_arch}",
            severity    = "INFO",
            description = "Для анализа: strings, PEStudio, x64dbg, Ghidra, IDA.",
            technique   = 'PE Analysis',
        ))
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ СЕТИ (PCAP)
# ═════════════════════════════════════════════════════════════════════════════

def analyze_network(data: bytes, result: AnalysisResult) -> None:
    """
    Базовый анализ PCAP файлов без внешних зависимостей.
    Ищет флаги и ключевые слова в payload пакетов.
    """
    result.findings.append(Finding(
        title       = "PCAP файл",
        severity    = "INFO",
        description = "Файл захвата сетевого трафика. Полный анализ: Wireshark, tshark, scapy.",
        technique   = 'Network Analysis',
    ))

    # Ищем флаги и интересное прямо в payload
    text_content = safe_decode(data)
    if looks_like_flag(text_content):
        result.findings.append(Finding(
            title       = "🚩 Флаг в PCAP payload!",
            severity    = "HIGH",
            description = "Найден флаг в сетевом трафике.",
            data        = text_content[:500],
            technique   = 'Network Analysis',
        ))

    # Ищем HTTP запросы/ответы
    http_patterns = [b'HTTP/1.', b'HTTP/2', b'GET /', b'POST /', b'Host: ']
    found_http = [p.decode() for p in http_patterns if p in data]
    if found_http:
        result.findings.append(Finding(
            title       = "HTTP трафик в PCAP",
            severity    = "MEDIUM",
            description = f"Найдены HTTP маркеры: {', '.join(found_http)}. "
                          "Используй Wireshark: Follow → TCP Stream для восстановления.",
            technique   = 'Network Analysis',
        ))

    # Ищем credentials
    cred_patterns = [b'password=', b'passwd=', b'Authorization: Basic ', b'login=']
    found_creds = [p.decode() for p in cred_patterns if p in data]
    if found_creds:
        result.findings.append(Finding(
            title       = "Возможные учётные данные в трафике",
            severity    = "HIGH",
            description = f"Найдены паттерны: {', '.join(found_creds)}",
            technique   = 'Network Analysis',
        ))


# ═════════════════════════════════════════════════════════════════════════════
# ГЛАВНЫЙ АНАЛИЗАТОР
# ═════════════════════════════════════════════════════════════════════════════

def analyze(filepath: str, deep: bool = False, xor_bruteforce: bool = False) -> AnalysisResult:
    """
    Читает файл, определяет тип, запускает анализаторы.
    deep=True — дополнительные проверки (медленнее).
    xor_bruteforce=True — перебор XOR ключей 0x01–0xFF.
    """
    path = _validate_path(filepath)

    # ── Чтение с лимитом размера ──────────────────────────────────────────
    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        _print(
            f"[yellow]Файл слишком большой: {file_size / 1024**2:.1f} МБ "
            f"(лимит {MAX_FILE_SIZE_MB} МБ). Читаю первые {MAX_FILE_SIZE_MB} МБ.[/yellow]"
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

    # ── Кэшируем строки один раз ──────────────────────────────────────────
    min_len = MIN_STRING_LEN_EXEC if category == 'executable' else MIN_STRING_LEN
    strings = extract_strings(data, min_len=min_len)
    result._strings_cache = strings

    # ── Общий анализ — всегда ─────────────────────────────────────────────
    analyze_general(data, strings, result, deep=deep)

    # ── XOR перебор — по запросу ──────────────────────────────────────────
    if xor_bruteforce:
        analyze_xor_bruteforce(data, result)

    # ── Специализированный анализ по типу файла ───────────────────────────
    dispatcher: dict[str, Callable[[bytes, AnalysisResult], None]] = {
        'image':      analyze_image,
        'audio':      analyze_audio,
        'archive':    analyze_archive,
        'text':       analyze_text,
        'executable': analyze_executable,
        'java':       analyze_executable,
        'network':    analyze_network,
    }
    if category in dispatcher:
        dispatcher[category](data, result)
    elif filetype == 'PDF':
        _analyze_pdf(data, result)

    # ── Сортируем: HIGH первыми, внутри группы — по порядку добавления ────
    result.findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 4))

    return result


def _analyze_pdf(data: bytes, result: AnalysisResult) -> None:
    """Базовый анализ PDF: поиск встроенных объектов и флагов."""
    result.findings.append(Finding(
        title       = "PDF файл",
        severity    = "INFO",
        description = "Для глубокого анализа: pdfextract, pdfcrack, pdf-parser.py.",
        technique   = 'PDF Analysis',
    ))
    # Ищем JavaScript (потенциально опасное содержимое в CTF)
    if b'/JavaScript' in data or b'/JS' in data:
        result.findings.append(Finding(
            title       = "PDF содержит JavaScript",
            severity    = "HIGH",
            description = "PDF включает JavaScript код — может содержать флаг или эксплойт.",
            technique   = 'PDF Analysis',
        ))
    # Ищем встроенные файлы
    if b'/EmbeddedFile' in data:
        result.findings.append(Finding(
            title       = "Встроенные файлы в PDF",
            severity    = "HIGH",
            description = "PDF содержит /EmbeddedFile объекты — файлы спрятаны внутри.",
            technique   = 'PDF Analysis',
        ))
    # Флаги в raw тексте
    raw_text = safe_decode(data)
    for pat in _FLAG_PATTERNS:
        for m in pat.finditer(raw_text):
            result.findings.append(Finding(
                title       = "🚩 Флаг в PDF!",
                severity    = "HIGH",
                description = "Найден флаг в PDF содержимом.",
                data        = m.group(0),
                technique   = 'PDF Analysis',
            ))


# ═════════════════════════════════════════════════════════════════════════════
# ВЫВОД
# ═════════════════════════════════════════════════════════════════════════════

def _print(msg: str) -> None:
    """Вспомогательная функция: rich.print если доступен, иначе обычный print."""
    if _RICH_AVAILABLE and console:
        console.print(msg)
    else:
        # Убираем rich-теги для plain-вывода
        clean = re.sub(r'\[/?[a-z_ ]+\]', '', msg)
        print(clean)


def print_results(result: AnalysisResult) -> None:
    """Выводит результаты анализа в структурированном виде."""
    if not _RICH_AVAILABLE:
        _print_plain(result)
        return

    console.print()
    console.rule(f"[bold cyan]ctf-lens v{__version__}[/bold cyan]")

    # ── Шапка с информацией о файле ───────────────────────────────────────
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("", style="dim", width=12)
    t.add_column("")
    t.add_row("Файл",     result.filepath)
    t.add_row("Тип",      f"[bold]{result.filetype}[/bold] ({result.filecategory})")
    t.add_row("Размер",   f"{result.filesize:,} байт ({result.filesize / 1024:.1f} КБ)")
    t.add_row("Энтропия", f"{result.entropy:.3f} / 8.0")
    t.add_row("MD5",      result.md5)
    t.add_row("SHA256",   result.sha256[:48] + "…")
    console.print(t)

    # ── Сводка ────────────────────────────────────────────────────────────
    highs   = [f for f in result.findings if f.severity == 'HIGH']
    mediums = [f for f in result.findings if f.severity == 'MEDIUM']
    infos   = [f for f in result.findings if f.severity in ('LOW', 'INFO')]

    summary = (
        f"[bold red]🔴 Критичных: {len(highs)}[/bold red]  "
        f"[bold yellow]🟡 Средних: {len(mediums)}[/bold yellow]  "
        f"[dim]⚪ Инфо: {len(infos)}[/dim]"
    )
    console.print(Panel(summary, box=box.ROUNDED))

    if not result.findings:
        console.print("[dim]Ничего подозрительного не найдено.[/dim]")
        return

    # ── Находки ───────────────────────────────────────────────────────────
    for finding in result.findings:
        color = SEVERITY_COLOR[finding.severity]
        icon  = SEVERITY_ICON[finding.severity]
        tech  = f"  [dim italic]{finding.technique}[/dim italic]" if finding.technique else ""

        console.print(f"\n{icon} [{color}][bold]{finding.title}[/bold][/{color}]{tech}")
        console.print(f"   {finding.description}")
        if finding.data:
            for line in finding.data.splitlines()[:MAX_DISPLAY_LINES]:
                console.print(f"   [dim]{line}[/dim]")
            remaining = len(finding.data.splitlines()) - MAX_DISPLAY_LINES
            if remaining > 0:
                console.print(f"   [dim]… ещё {remaining} строк[/dim]")
        if finding.hint:
            console.print(f"   [green]💡 {finding.hint}[/green]")

    # ── Декодированные данные ─────────────────────────────────────────────
    if result.decoded:
        console.print()
        console.rule("[bold]Автоматически декодировано[/bold]")
        for d in result.decoded:
            icon  = "🚩" if d.severity == "HIGH" else "•"
            tech  = f"  [dim italic]{d.technique}[/dim italic]" if d.technique else ""
            console.print(f"\n{icon} [cyan][bold]{d.title}[/bold][/cyan]{tech}")
            console.print(f"   {d.description}")
            if d.data:
                for line in d.data.splitlines()[:MAX_DECODED_DISPLAY]:
                    console.print(f"   [dim]{line}[/dim]")
            if d.hint:
                console.print(f"   [green]💡 {d.hint}[/green]")

    console.print()


def _print_plain(result: AnalysisResult) -> None:
    """Упрощённый вывод без rich."""
    print(f"\n{'='*60}")
    print(f"ctf-lens v{__version__}")
    print(f"{'='*60}")
    print(f"Файл:     {result.filepath}")
    print(f"Тип:      {result.filetype} ({result.filecategory})")
    print(f"Размер:   {result.filesize:,} байт")
    print(f"Энтропия: {result.entropy:.3f} / 8.0")
    print(f"MD5:      {result.md5}")
    print(f"SHA256:   {result.sha256[:48]}…")
    print()

    for finding in result.findings:
        print(f"[{finding.severity}] {finding.title}")
        print(f"  {finding.description}")
        if finding.data:
            for line in finding.data.splitlines()[:MAX_DISPLAY_LINES]:
                print(f"  {line}")
        if finding.hint:
            print(f"  💡 {finding.hint}")
        print()

    if result.decoded:
        print("\n--- Декодировано ---")
        for d in result.decoded:
            print(f"[{d.severity}] {d.title}")
            print(f"  {d.description}")
            if d.data:
                for line in d.data.splitlines()[:MAX_DECODED_DISPLAY]:
                    print(f"  {line}")
            if d.hint:
                print(f"  💡 {d.hint}")
            print()


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog        = 'ctf-lens',
        description = f'ctf-lens v{__version__} — анализатор файлов для CTF',
        add_help    = True,
    )
    parser.add_argument('filepath',          help='Путь к анализируемому файлу')
    parser.add_argument('--deep',   action='store_true', help='Глубокий анализ (медленнее)')
    parser.add_argument('--xor',    action='store_true', help='Перебор XOR ключей 0x01–0xFF')
    parser.add_argument('--version', action='version', version=f'ctf-lens {__version__}')

    args = parser.parse_args()

    _print(f"[dim]Анализирую: {args.filepath}[/dim]")
    if args.xor:
        _print(f"[dim]XOR перебор включён (ключи 0x01–0xFF)[/dim]")

    try:
        result = analyze(
            args.filepath,
            deep          = args.deep,
            xor_bruteforce = args.xor,
        )
        print_results(result)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        _print(f"[red]Ошибка: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        _print("\n[yellow]Прервано.[/yellow]")
        sys.exit(0)
    except Exception as e:
        _print(f"[red]Неожиданная ошибка: {e}[/red]")
        raise


if __name__ == '__main__':
    main()

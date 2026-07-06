"""Unit tests for ctf_lens.utils."""
import pytest

from ctf_lens.utils import (
    shannon_entropy, detect_filetype, extract_strings,
    looks_like_flag, flag_is_clean, compute_hashes, safe_decode,
)


# ── Entropy ───────────────────────────────────────────────────────────────────

def test_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_uniform_byte_is_zero():
    assert shannon_entropy(b"\x00" * 100) == 0.0


def test_entropy_random_is_high():
    import os
    assert shannon_entropy(os.urandom(4096)) > 7.5


# ── File type detection ───────────────────────────────────────────────────────

def test_detect_png():
    assert detect_filetype(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20) == ("PNG", "image")


def test_detect_riff_wave():
    data = b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 8
    assert detect_filetype(data) == ("WAV", "audio")


def test_detect_riff_webp():
    data = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 8
    assert detect_filetype(data) == ("WEBP", "image")


def test_detect_too_short_is_unknown():
    assert detect_filetype(b"\x01\x02") == ("UNKNOWN", "unknown")


def test_detect_plain_text():
    ftype, category = detect_filetype(b"just some plain ASCII text" * 5)
    assert (ftype, category) == ("TEXT", "text")


def test_detect_java_class_vs_macho():
    # Java 1.1 (major=45) should be CLASS; a bogus high major falls back to MACHO.
    class_data = b"\xca\xfe\xba\xbe\x00\x00\x00\x2d" + b"\x00" * 8
    assert detect_filetype(class_data) == ("CLASS", "java")

    macho_data = b"\xca\xfe\xba\xbe\x00\x00\x03\xe8" + b"\x00" * 8
    assert detect_filetype(macho_data) == ("MACHO", "executable")


# ── String extraction ─────────────────────────────────────────────────────────

def test_extract_strings_basic():
    data = b"\x00\x00hello world\x00\x00\x01hi\x00test1234"
    strings = extract_strings(data, min_len=4)
    assert "hello world" in strings
    assert "test1234" in strings
    assert "hi" not in strings  # shorter than min_len


def test_extract_strings_empty_data():
    assert extract_strings(b"", min_len=4) == []


# ── Flag detection ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "flag{simple_example}",
    "HTB{hack_the_box_example}",
    "picoCTF{pico_example}",
    "prefix text flag{embedded_in_sentence} suffix text",
])
def test_looks_like_flag_matches(text):
    assert looks_like_flag(text) is True


@pytest.mark.parametrize("text", [
    "no flag here at all",
    "flag without braces",
    "",
])
def test_looks_like_flag_no_match(text):
    assert looks_like_flag(text) is False


def test_flag_is_clean_accepts_isolated_flag():
    assert flag_is_clean("flag{clean_and_isolated}") is True


def test_flag_is_clean_rejects_binary_adjacent_junk():
    # Non-printable bytes immediately touching the flag should reject it —
    # this mirrors ZIP/ROT13 false-positive scenarios from the docstring.
    noisy = "file.txt" + "flag{noisy_example}" + "PK\x03\x04"
    assert flag_is_clean(noisy) is False


def test_flag_is_clean_short_string_with_clean_padding():
    assert flag_is_clean("prefix flag{short_clean} suffix") is True


def test_flag_is_clean_no_flag_present():
    assert flag_is_clean("nothing interesting here") is False


# ── Hashing / decoding helpers ─────────────────────────────────────────────────

def test_compute_hashes_known_values():
    md5, sha256 = compute_hashes(b"hello")
    assert md5 == "5d41402abc4b2a76b9719d911017c592"
    assert sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_safe_decode_utf8():
    assert safe_decode("héllo".encode("utf-8")) == "héllo"


def test_safe_decode_falls_back_to_latin1_replace():
    # An invalid UTF-8/latin-1 sequence should never raise — always returns a str.
    result = safe_decode(b"\xff\xfe\x00\x01")
    assert isinstance(result, str)

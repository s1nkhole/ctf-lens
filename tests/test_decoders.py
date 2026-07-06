"""Unit tests for ctf_lens.decoders — pure encode/decode helpers."""
import base64

from ctf_lens.decoders import (
    try_decode_base64, try_decode_hex, try_rot13,
    try_decode_xor, score_xor_result,
    try_decode_url_encoding, try_decode_html_entities,
    try_decode_binary_string, try_decode_morse,
)


# ── Base64 ────────────────────────────────────────────────────────────────────

def test_decode_base64_roundtrip():
    encoded = base64.b64encode(b"flag{base64_roundtrip_example}").decode()
    assert try_decode_base64(encoded) == "flag{base64_roundtrip_example}"


def test_decode_base64_too_short_rejected():
    # MIN_B64_LEN is 20; anything shorter must be rejected regardless of validity.
    assert try_decode_base64(base64.b64encode(b"hi").decode()) is None


def test_decode_base64_invalid_chars_rejected():
    assert try_decode_base64("not-valid-base64-!!!@@@###$$$") is None


def test_decode_base64_odd_padding_rejected():
    # A base64 body of length % 4 == 1 (after stripping '=') is never valid.
    assert try_decode_base64("A" * 21) is None


# ── Hex ───────────────────────────────────────────────────────────────────────

def test_decode_hex_roundtrip():
    encoded = b"flag{hex_roundtrip_example}".hex()
    assert try_decode_hex(encoded) == "flag{hex_roundtrip_example}"


def test_decode_hex_odd_length_rejected():
    assert try_decode_hex("abc") is None


def test_decode_hex_too_short_rejected():
    # MIN_HEX_LEN is 16
    assert try_decode_hex("abcd") is None


def test_decode_hex_non_hex_chars_rejected():
    assert try_decode_hex("zzzzzzzzzzzzzzzz") is None


def test_decode_hex_strips_0x_prefix():
    encoded = "0x" + b"flag{hex_0x_example}".hex()
    assert try_decode_hex(encoded) == "flag{hex_0x_example}"


# ── ROT13 ─────────────────────────────────────────────────────────────────────

def test_rot13_roundtrip_readable_text():
    # try_rot13 requires >=2 words of 3+ letters to accept the result.
    plain = "the quick brown fox jumps"
    rotated = plain.translate(str.maketrans(
        'abcdefghijklmnopqrstuvwxyz',
        'nopqrstuvwxyzabcdefghijklm',
    ))
    assert try_rot13(rotated) == plain


def test_rot13_rejects_gibberish():
    # ROT13 of random noise won't produce 2+ readable 3-letter words.
    assert try_rot13("xkq7 zz1 ##2") is None


def test_rot13_rejects_non_ascii():
    assert try_rot13("привет мир") is None


# ── XOR ───────────────────────────────────────────────────────────────────────

def test_xor_roundtrip():
    data = b"flag{xor_example}"
    key = 0x42
    encrypted = try_decode_xor(data, key)
    assert encrypted != data
    assert try_decode_xor(encrypted, key) == data


def test_score_xor_result_all_printable():
    assert score_xor_result(b"hello world") == 1.0


def test_score_xor_result_empty():
    assert score_xor_result(b"") == 0.0


def test_score_xor_result_binary_garbage():
    garbage = bytes(range(0, 20))  # mostly non-printable control bytes
    assert score_xor_result(garbage) < 0.5


# ── URL encoding ──────────────────────────────────────────────────────────────

def test_decode_url_encoding():
    assert try_decode_url_encoding("flag%7Burl_encoded%7D") == "flag{url_encoded}"


def test_decode_url_encoding_no_percent_returns_none():
    assert try_decode_url_encoding("plain text, no encoding here") is None


# ── HTML entities ─────────────────────────────────────────────────────────────

def test_decode_html_entities():
    assert try_decode_html_entities("flag&#123;html_entity&#125;") == "flag{html_entity}"


def test_decode_html_entities_no_ampersand_returns_none():
    assert try_decode_html_entities("nothing to decode here") is None


# ── Binary string ─────────────────────────────────────────────────────────────

def test_decode_binary_string():
    text = "hey"
    bits = ' '.join(format(ord(c), '08b') for c in text)
    assert try_decode_binary_string(bits) == "hey"


def test_decode_binary_string_rejects_non_binary():
    assert try_decode_binary_string("this is not binary") is None


def test_decode_binary_string_rejects_bad_length():
    assert try_decode_binary_string("0101") is None  # not a multiple of 8


# ── Morse code ────────────────────────────────────────────────────────────────

def test_decode_morse():
    # "SOS" in Morse: S = ..., O = ---, S = ...
    assert try_decode_morse("... --- ...") == "SOS"


def test_decode_morse_rejects_non_morse():
    assert try_decode_morse("this is plain text") is None

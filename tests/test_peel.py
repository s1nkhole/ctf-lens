"""Multi-layer decoding: chains of encodings, with strict noise control."""
import base64
import bz2
import codecs
import gzip
import zlib

from ctf_lens import analyze
from helpers import build_png

FLAG = b'flag{peel_test_value}'


def _run(tmp_path, blob, **kw):
    p = tmp_path / 'chain.txt'
    p.write_bytes(blob)
    return analyze(str(p), **kw)


def _b64(b):
    return base64.b64encode(b)


def test_base64_of_hex(tmp_path):
    result = _run(tmp_path, _b64(FLAG.hex().encode()))
    assert result.flags() == [FLAG.decode()]
    assert any('base64 → hex' in f.description for f in result.findings)


def test_hex_of_base64_of_zlib(tmp_path):
    assert FLAG.decode() in _run(tmp_path, _b64(zlib.compress(FLAG)).hex().encode()).flags()


def test_rot13_of_base64(tmp_path):
    assert FLAG.decode() in _run(tmp_path, codecs.encode(_b64(FLAG).decode(), 'rot13').encode()).flags()


def test_base64_of_gzip_and_bzip2(tmp_path):
    assert FLAG.decode() in _run(tmp_path, _b64(gzip.compress(FLAG))).flags()
    assert FLAG.decode() in _run(tmp_path, _b64(bz2.compress(FLAG))).flags()


def test_base32_base85_ascii85_base58(tmp_path):
    for enc in (base64.b32encode, base64.b85encode, base64.a85encode):
        assert FLAG.decode() in _run(tmp_path, enc(FLAG)).flags(), enc.__name__
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n, out = int.from_bytes(FLAG, 'big'), ''
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    assert FLAG.decode() in _run(tmp_path, out.encode()).flags()


def test_flag_inside_larger_text_file_with_a_token(tmp_path):
    text = b'Intro line.\nHere is the token: ' + _b64(FLAG.hex().encode()) + b'\nBye.\n'
    assert FLAG.decode() in _run(tmp_path, text).flags()


def test_depth_zero_disables_chains(tmp_path):
    assert _run(tmp_path, _b64(FLAG.hex().encode()), peel_depth=0).flags() == []


def test_plain_english_produces_no_findings_from_peel(tmp_path):
    text = (b'The committee met on Tuesday to discuss the proposal. After a long debate the members '
            b'agreed to postpone the vote until the following week, pending further review.')
    result = _run(tmp_path, text)
    assert result.flags() == []
    assert not any(d.title.startswith('Decoded (') for d in result.decoded)


def test_readable_non_flag_result_is_shown(tmp_path):
    result = _run(tmp_path, _b64(b'73337233743333'))
    assert any(d.description == 'Chain: base64 → hex' and d.data == 's3r3t33' for d in result.decoded)


def test_hex_string_is_not_double_reported_as_base64_garbage(example):
    result = analyze(example('example_hex.txt'))
    assert not any(d.title == 'Base64 decoded' for d in result.decoded)


def test_decoded_binary_layer_is_extracted(tmp_path):
    png = build_png(8, 8)
    result = _run(tmp_path, _b64(gzip.compress(png)), extract_dir=str(tmp_path / 'out'))
    assert any(f.title == 'Decoded layer is a PNG file' for f in result.findings)
    layers = [p for p in result.extracted if 'layer' in p]
    assert layers and open(layers[0], 'rb').read() == png

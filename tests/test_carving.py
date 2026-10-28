"""Carving and file-type detection must be driven by structure, not bare magic bytes."""
import gzip
import io
import random
import zipfile

from ctf_lens import analyze
from ctf_lens.utils import detect_filetype
from helpers import build_png, build_pe_stub


def _junk(n, seed=0):
    return b'\x00' * 16 + random.Random(seed).randbytes(n)


def _write(tmp_path, data, name='blob.bin'):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _embedded(result):
    return [f for f in result.findings if f.title.startswith('Embedded') and f.severity == 'HIGH']


def test_random_data_has_no_embedded_files(tmp_path):
    for seed in range(3):
        result = analyze(_write(tmp_path, _junk(2_000_000, seed), f'r{seed}.bin'))
        assert _embedded(result) == []


def test_real_png_inside_blob_is_found_at_exact_offset(tmp_path):
    png  = build_png(24, 24)
    data = _junk(1024 - 16, 1) + png + _junk(500, 2)
    result = analyze(_write(tmp_path, data))
    hits = [f for f in _embedded(result) if 'PNG' in f.title]
    assert [f.offset for f in hits] == [1024]


def test_valid_pe_is_found_and_fake_mz_is_not(tmp_path):
    good = analyze(_write(tmp_path, _junk(2000, 3) + build_pe_stub() + _junk(300, 4), 'good.bin'))
    assert any('EXE' in f.title for f in _embedded(good))
    fake = analyze(_write(tmp_path, _junk(2000, 3) + b'MZ' + b'A' * 200, 'fake.bin'))
    assert not any('EXE' in f.title for f in _embedded(fake))


def test_multi_member_zip_is_not_reported_as_embedded_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        for i in range(4):
            zf.writestr(f'f{i}.bin', random.Random(i).randbytes(400))
    result = analyze(_write(tmp_path, buf.getvalue(), 'multi.zip'))
    assert not any('Embedded ZIP' in f.title for f in result.findings)


def test_extract_writes_the_carved_file_byte_for_byte(tmp_path):
    png  = build_png(24, 24)
    data = _junk(1000, 5) + png + _junk(300, 6)
    out  = tmp_path / 'out'
    result = analyze(_write(tmp_path, data), extract_dir=str(out))
    saved = [p for p in result.extracted if p.endswith('.png')]
    assert saved and open(saved[0], 'rb').read() == png


def test_text_starting_with_bm_or_mz_is_text():
    assert detect_filetype(b'BMW is a car brand and this is plain text\n')[0] == 'TEXT'
    assert detect_filetype(b'MZ-2024 quarterly report: all numbers are fine\n')[0] == 'TEXT'


def test_real_bmp_pe_and_gzip_are_still_detected():
    bmp = b'BM' + (58).to_bytes(4, 'little') + b'\x00' * 4 + (54).to_bytes(4, 'little') \
        + (40).to_bytes(4, 'little') + (1).to_bytes(4, 'little') * 2 + b'\x01\x00\x18\x00' + b'\x00' * 28
    assert detect_filetype(bmp) == ('BMP', 'image')
    assert detect_filetype(build_pe_stub()) == ('EXE', 'executable')
    assert detect_filetype(gzip.compress(b'hello world' * 10)) == ('GZIP', 'archive')


def test_bad_gzip_and_mp3_headers_are_rejected():
    assert detect_filetype(b'\x1f\x8b\x00' + b'\x01' * 40)[0] != 'GZIP'
    assert detect_filetype(b'\xff\xfb\xf0\x00' + b'\x00' * 40)[0] != 'MP3'
    assert detect_filetype(b'\xff\xfb\x90\x00' + b'\x00' * 40)[0] == 'MP3'

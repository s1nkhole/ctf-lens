"""PNG structure: CRC checks, tampered IHDR recovery, data after IEND — all without Pillow."""
import struct

from ctf_lens import analyze
from helpers import build_png, png_chunk


def _write(tmp_path, data, name='t.png'):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _titles(result):
    return [f.title for f in result.findings]


def test_clean_png_has_no_alarming_findings(tmp_path):
    result = analyze(_write(tmp_path, build_png(32, 20)))
    assert [f for f in result.findings if f.severity in ('HIGH', 'MEDIUM')] == []


def test_tampered_height_is_detected_and_true_size_reported(tmp_path):
    png = bytearray(build_png(40, 30))
    png[20:24] = struct.pack('>I', 12)                      # height 30 → 12, CRC left stale
    result = analyze(_write(tmp_path, bytes(png)))
    hit = next(f for f in result.findings if f.title == 'PNG IHDR CRC mismatch')
    assert hit.severity == 'HIGH'
    assert '40×30' in hit.description and '40×12' in hit.description


def test_tampered_width_is_detected_and_true_size_reported(tmp_path):
    png = bytearray(build_png(40, 30))
    png[16:20] = struct.pack('>I', 99)
    hit = next(f for f in analyze(_write(tmp_path, bytes(png))).findings if f.title == 'PNG IHDR CRC mismatch')
    assert '40×30' in hit.description


def test_data_after_iend_is_reported_with_offset_and_flag(tmp_path):
    png  = build_png(16, 16)
    data = png + b'\nsome note flag{after_the_end_marker}\n'
    result = analyze(_write(tmp_path, data))
    hit = next(f for f in result.findings if f.title == 'Data after PNG IEND')
    assert hit.offset == len(png)
    assert 'flag{after_the_end_marker}' in result.flags()
    assert 'Corrupted PNG structure' not in _titles(result)


def test_appended_zip_is_identified_by_type(tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('a.txt', 'x' * 50)
    result = analyze(_write(tmp_path, build_png(16, 16) + buf.getvalue()))
    hit = next(f for f in result.findings if f.title == 'Data after PNG IEND')
    assert 'ZIP' in hit.description


def test_nonstandard_chunk_with_valid_crc_is_reported_without_crc_error(tmp_path):
    result = analyze(_write(tmp_path, build_png(16, 16, extra_chunks=((b'hidD', b'secret bytes here'),))))
    assert "Non-standard PNG chunk: 'hidD'" in _titles(result)
    assert 'PNG chunk CRC mismatch' not in _titles(result)


def test_corrupted_idat_crc_is_reported(tmp_path):
    png = bytearray(build_png(16, 16))
    idat = png.find(b'IDAT')
    png[idat + 10] ^= 0xFF
    assert 'PNG chunk CRC mismatch' in _titles(analyze(_write(tmp_path, bytes(png))))


def test_text_chunk_flag_still_found(tmp_path):
    result = analyze(_write(tmp_path, build_png(16, 16, extra_chunks=((b'tEXt', b'Comment\x00flag{in_text_chunk}'),))))
    assert 'flag{in_text_chunk}' in result.flags()

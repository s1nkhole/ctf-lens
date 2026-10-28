"""PDF: flags inside Flate-compressed streams (where real PDF text lives)."""
from ctf_lens import analyze
from helpers import build_pdf


def _write(tmp_path, data):
    p = tmp_path / 't.pdf'
    p.write_bytes(data)
    return str(p)


def test_flag_in_flate_stream_is_found(tmp_path):
    pdf = build_pdf([b'BT /F1 12 Tf (flag{hidden_in_flate_stream}) Tj ET'])
    result = analyze(_write(tmp_path, pdf))
    assert 'flag{hidden_in_flate_stream}' in result.flags()
    assert any(f.title.startswith('PDF streams: 1 found, 1 inflated') for f in result.findings)


def test_flag_split_by_kerning_operators_is_reassembled(tmp_path):
    pdf = build_pdf([b'BT [(fl)-12(ag{kerned_)8(flag_in_pdf})] TJ ET'])
    assert 'flag{kerned_flag_in_pdf}' in analyze(_write(tmp_path, pdf)).flags()


def test_clean_pdf_has_no_flag(tmp_path):
    pdf = build_pdf([b'BT /F1 12 Tf (Quarterly report, nothing to see) Tj ET'])
    assert analyze(_write(tmp_path, pdf)).flags() == []


def test_javascript_in_compressed_stream_and_launch_action(tmp_path):
    pdf = build_pdf([b'app.alert("hi"); this.exportDataObject({});'], extra_objects=b'<< /Type /Action /S /Launch >>\n')
    titles = [f.title for f in analyze(_write(tmp_path, pdf)).findings]
    assert any(t.startswith('JavaScript inside PDF stream') for t in titles)
    assert 'PDF /Launch present' in titles

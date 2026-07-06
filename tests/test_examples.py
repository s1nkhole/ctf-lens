"""
Integration tests: run the real analyze() pipeline against the fixture files
shipped in examples/, and assert the expected flag is actually surfaced.
"""
import pytest

from ctf_lens import analyze


def _all_flag_data(result):
    """Collect the `data` field of every registered '🚩 Flag found!' finding."""
    return [f.data for f in result.findings if f.title == '🚩 Flag found!']


def test_plaintext_flag_found(example):
    result = analyze(example("example_text.txt"))
    assert "flag{this_is_a_plaintext_flag_example}" in _all_flag_data(result)


def test_base64_flag_decoded_and_found(example):
    result = analyze(example("example_base64.txt"))
    assert "flag{base64_encoded_flag_example}" in _all_flag_data(result)


def test_hex_flag_decoded_and_found(example):
    result = analyze(example("example_hex.txt"))
    assert "flag{hex_encoded_flag_example}" in _all_flag_data(result)


def test_archive_flag_found_in_nested_file(example):
    result = analyze(example("example_archive.zip"))
    assert "flag{zip_archive_hidden_flag_example}" in _all_flag_data(result)


def test_polyglot_flag_found_after_eof(example):
    result = analyze(example("example_polyglot.png"))
    assert "flag{appended_after_eof_example}" in _all_flag_data(result)


def test_analyze_result_has_expected_metadata(example):
    result = analyze(example("example_text.txt"))
    assert result.filetype == "TEXT"
    assert result.filecategory == "text"
    assert len(result.md5) == 32
    assert len(result.sha256) == 64
    assert result.entropy >= 0.0


def test_analyze_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(str(tmp_path / "does_not_exist.png"))

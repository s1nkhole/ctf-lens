"""Unit tests for ctf_lens.registry.register_flag — the single dedup entry point."""
from ctf_lens.models import AnalysisResult
from ctf_lens.registry import register_flag


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        filepath="test", filesize=0, filetype="TEXT", filecategory="text",
        md5="", sha256="", entropy=0.0,
    )


def test_register_flag_new_flag_returns_true():
    result = _empty_result()
    assert register_flag("flag{new}", result, source="test") is True
    assert len(result.findings) == 1
    assert result.findings[0].data == "flag{new}"


def test_register_flag_duplicate_returns_false():
    result = _empty_result()
    register_flag("flag{dup}", result, source="source A")
    added_again = register_flag("flag{dup}", result, source="source B")
    assert added_again is False
    assert len(result.findings) == 1  # only registered once


def test_register_flag_no_pattern_match_returns_false():
    result = _empty_result()
    assert register_flag("not a flag at all", result, source="test") is False
    assert len(result.findings) == 0


def test_register_flag_extracts_clean_flag_from_noisy_string():
    # register_flag should extract just the matched flag pattern, not the
    # surrounding noise, when given e.g. "junk...flag{x}...junk".
    result = _empty_result()
    register_flag("garbage_before_flag{extracted}garbage_after", result, source="test")
    assert result.findings[0].data == "flag{extracted}"

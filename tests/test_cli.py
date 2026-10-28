"""CLI contract: JSON on stdout, status on stderr, exit codes, custom flag format."""
import json
import subprocess
import sys
from pathlib import Path

from ctf_lens import analyze
from ctf_lens.config import FLAG_PATTERNS

ROOT = Path(__file__).resolve().parent.parent


def _run(*args):
    return subprocess.run([sys.executable, '-m', 'ctf_lens', *args], cwd=ROOT, capture_output=True, text=True)


def _file(tmp_path, content, name='t.txt'):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return str(p)


def test_json_output_is_clean_and_complete(example):
    r = _run(example('example_text.txt'), '--json')
    assert r.returncode == 0 and r.stderr == ''
    data = json.loads(r.stdout)
    assert data['flags'] == ['flag{this_is_a_plaintext_flag_example}']
    assert {'file', 'size', 'type', 'md5', 'sha256', 'findings', 'decoded'} <= set(data)


def test_quiet_prints_only_flags(example):
    r = _run(example('example_text.txt'), '-q')
    assert r.stdout.strip() == 'flag{this_is_a_plaintext_flag_example}' and r.stderr == ''


def test_exit_code_is_opt_in(example, tmp_path):
    assert _run(example('example_text.txt'), '-q').returncode == 0
    assert _run(example('example_text.txt'), '-q', '--exit-code').returncode == 10
    assert _run(_file(tmp_path, 'nothing interesting in here at all'), '-q', '--exit-code').returncode == 0


def test_errors_go_to_stderr_with_status_1(tmp_path):
    r = _run(str(tmp_path / 'missing.bin'))
    assert r.returncode == 1 and r.stdout == '' and 'not found' in r.stderr.lower()
    bad = _run(_file(tmp_path, 'x'), '--flag-format', '(')
    assert bad.returncode == 1 and 'Invalid flag format' in bad.stderr


def test_custom_flag_format(tmp_path):
    path = _file(tmp_path, 'prize: EVT2026{custom_flag_value}\n')
    plain = analyze(path)
    assert plain.flags() == []
    assert any(f.title.startswith('Flag-shaped strings') for f in plain.findings)
    assert analyze(path, flag_format=r'EVT2026\{[^}]+\}').flags() == ['EVT2026{custom_flag_value}']
    assert _run(path, '-q', '--flag-format', r'EVT2026\{[^}]+\}').stdout.strip() == 'EVT2026{custom_flag_value}'


def test_custom_flag_format_does_not_leak_between_calls(tmp_path):
    before = len(FLAG_PATTERNS)
    analyze(_file(tmp_path, 'EVT2026{custom_flag_value}'), flag_format=r'EVT2026\{[^}]+\}')
    assert len(FLAG_PATTERNS) == before


def test_utf16_strings_are_searched(tmp_path):
    le = b'\x00' * 700 + 'flag{wide_string_le}'.encode('utf-16-le') + b'\x00' * 40
    be = b'\x00' * 700 + 'flag{wide_string_be}'.encode('utf-16-be') + b'\x00' * 40
    assert 'flag{wide_string_le}' in analyze(_file(tmp_path, le, 'le.bin')).flags()
    assert 'flag{wide_string_be}' in analyze(_file(tmp_path, be, 'be.bin')).flags()


def test_flag_with_unknown_longer_prefix_is_not_presented_silently_truncated(tmp_path):
    result = analyze(_file(tmp_path, 'prize: MYCTF{abc_def_ghi}'))
    hit = next(f for f in result.findings if f.title == '🚩 Flag found!')
    assert hit.data == 'CTF{abc_def_ghi}'                 # pattern behaviour unchanged
    assert "'MY'" in hit.hint and '--flag-format' in hit.hint
    clean = next(f for f in analyze(_file(tmp_path, 'prize: picoCTF{abc_def_ghi}', 'ok.txt')).findings
                 if f.title == '🚩 Flag found!')
    assert clean.hint == ''                               # no warning when the prefix is whole

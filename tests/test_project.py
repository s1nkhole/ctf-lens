"""Repository hygiene checks that keep metadata from drifting apart."""
import re
from pathlib import Path

from ctf_lens import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_version_matches_pyproject():
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / 'pyproject.toml').read_text(), re.M)
    assert m and m.group(1) == __version__


def test_gitignore_has_no_bom_and_ignores_pycache():
    raw = (ROOT / '.gitignore').read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf')
    assert b'__pycache__/' in raw

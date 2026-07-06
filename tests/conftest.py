"""Shared pytest fixtures."""
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def examples_dir() -> Path:
    """Path to the examples/ directory shipped with the repo."""
    return EXAMPLES_DIR


@pytest.fixture
def example(examples_dir):
    """Return a helper that resolves a filename inside examples/ to a full path string."""
    def _resolve(name: str) -> str:
        path = examples_dir / name
        assert path.exists(), f"Fixture file missing: {path}"
        return str(path)
    return _resolve

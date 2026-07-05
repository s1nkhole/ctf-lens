"""
ctf-lens — static analysis tool for CTF challenge files.

Public API:
    from ctf_lens import analyze, AnalysisResult, Finding
    result = analyze('challenge.png')
"""

from .core import analyze
from .models import AnalysisResult, Finding
from .output import __version__

__all__ = ['analyze', 'AnalysisResult', 'Finding', '__version__']

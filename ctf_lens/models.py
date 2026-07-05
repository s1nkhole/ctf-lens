"""
Core data structures: Finding, AnalysisResult, and severity display constants.
"""

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Finding:
    title:       str
    description: str
    severity:    Literal['HIGH', 'MEDIUM', 'LOW', 'INFO'] = 'INFO'
    data:        str = ''
    technique:   str = ''
    hint:        str = ''


@dataclass
class AnalysisResult:
    filepath:        str
    filesize:        int
    filetype:        str
    filecategory:    str
    md5:             str
    sha256:          str
    entropy:         float
    findings:        list[Finding] = field(default_factory=list)
    decoded:         list[Finding] = field(default_factory=list)
    # String cache — computed once in analyze(), reused by all analyzers
    _strings_cache:  list[str]    = field(default_factory=list, repr=False)
    # Deduplication set — prevents the same flag appearing from multiple sources
    _seen_flags:     set[str]     = field(default_factory=set, repr=False)


SEVERITY_COLOR: dict[str, str] = {
    'HIGH':   'red',
    'MEDIUM': 'yellow',
    'LOW':    'cyan',
    'INFO':   'dim white',
}

SEVERITY_ICON: dict[str, str] = {
    'HIGH':   '🔴',
    'MEDIUM': '🟡',
    'LOW':    '🔵',
    'INFO':   '⚪',
}

SEVERITY_ORDER: dict[str, int] = {
    'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3,
}

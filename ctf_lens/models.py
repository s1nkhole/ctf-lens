"""
Core data structures: Finding, AnalysisResult, and severity display constants.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Literal

from .config import FLAG_PATTERNS


@dataclass
class Finding:
    title:       str
    description: str
    severity:    Literal['HIGH', 'MEDIUM', 'LOW', 'INFO'] = 'INFO'
    data:        str = ''
    technique:   str = ''
    hint:        str = ''
    offset:      int | None = None   # byte offset inside the file, when meaningful


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
    # Run options passed down to analyzers (wordlist path, ...)
    _options:        dict[str, Any] = field(default_factory=dict, repr=False)
    # Embedded/trailing regions found: (kind, offset). Saved by --extract.
    carved:          list[tuple[str, int]]   = field(default_factory=list, repr=False)
    # Decoded binary layers worth saving: (chain description, bytes).
    layers:          list[tuple[str, bytes]] = field(default_factory=list, repr=False)
    # Paths written by --extract
    extracted:       list[str]    = field(default_factory=list)
    # Indicators of compromise by type: {'domain': [...], 'ipv4': [...], ...}
    iocs:            dict[str, list[str]] = field(default_factory=dict)
    # Structured per-format details for --json (e.g. details['pe'])
    details:         dict[str, Any] = field(default_factory=dict)

    def flags(self) -> list[str]:
        """Every distinct flag string found, in discovery order (HIGH findings first)."""
        out: list[str] = []
        for f in [*self.findings, *self.decoded]:
            if '🚩' not in f.title or not f.data:
                continue
            text = f.data
            for pat in FLAG_PATTERNS:
                m = pat.search(text)
                if m:
                    text = m.group(0)
                    break
            else:
                text = text.strip()
            if text and text not in out:
                out.append(text)
        return out

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable view of the result (no private caches)."""
        return {
            'file':      self.filepath,
            'size':      self.filesize,
            'type':      self.filetype,
            'category':  self.filecategory,
            'md5':       self.md5,
            'sha256':    self.sha256,
            'entropy':   round(self.entropy, 4),
            'flags':     self.flags(),
            'findings':  [asdict(f) for f in self.findings],
            'decoded':   [asdict(f) for f in self.decoded],
            'extracted': list(self.extracted),
            'iocs':      {k: list(v) for k, v in self.iocs.items()},
            'details':   self.details,
        }


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

"""
Flag registration — isolated to break the circular import between core and analyzers.
core.py imports analyzers; analyzers need register_flag → put it here, import from both sides.
"""

import re

from .config import FLAG_PATTERNS
from .models import Finding, AnalysisResult


def register_flag(flag: str, result: AnalysisResult, source: str, hint: str = '') -> bool:
    """
    Register a found flag into result.
    Returns True if the flag is new, False if already seen.
    Single entry point — prevents duplicates when the same flag is found via
    direct strings, base64, ROT13, ZIP content, EXIF, LSB, etc.
    """
    for pat in FLAG_PATTERNS:
        m = pat.search(flag)
        if m:
            clean_flag = m.group(0)
            if clean_flag in result._seen_flags:
                return False
            result._seen_flags.add(clean_flag)
            # A letter/digit glued in front of the matched prefix usually means the event
            # uses a longer prefix we do not know (MYCTF{..} matches as CTF{..}). Say so
            # instead of silently presenting a truncated flag as the answer.
            glued = re.search(r'[A-Za-z0-9_]+$', flag[:m.start()])
            if glued:
                hint = (
                    f"{hint}  ⚠ Directly preceded by {glued.group(0)[-12:]!r}: the real prefix may be "
                    "longer. Check the challenge text, or pass --flag-format 'FULLPREFIX\\{[^}]+\\}'."
                ).strip()
            result.findings.append(Finding(
                title       = '🚩 Flag found!',
                severity    = 'HIGH',
                description = f'Source: {source}',
                data        = clean_flag,
                hint        = hint,
                technique   = 'Flag Pattern',
            ))
            return True
    return False

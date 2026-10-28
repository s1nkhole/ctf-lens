"""
PE triage analyzer: layout anomalies, packer indicators, import behaviour,
overlay, TLS callbacks, timestamps. Parsing lives in ctf_lens.pe.

Everything reported here is a *hint* for a human analyst — an imported API or a
high-entropy section does not prove behaviour. Descriptions say so where it matters.
Entry point: analyze_pe(data, result)
"""

from __future__ import annotations

import datetime as _dt

from ..models import Finding, AnalysisResult
from ..pe import (
    parse_pe, PEInfo, MACHINES, SUBSYSTEMS, DLL_CHARACTERISTICS, SCN_EXEC, SCN_WRITE,
)
from ..utils import detect_filetype, shannon_entropy

HIGH_ENTROPY       = 7.2     # bits/byte: compressed or encrypted data
MIN_SECTION_BYTES  = 512     # ignore entropy of tiny sections
FEW_IMPORTS        = 6
LARGE_OVERLAY      = 4096
EARLIEST_PLAUSIBLE = _dt.datetime(1993, 1, 1, tzinfo=_dt.timezone.utc)

# Section names left behind by common packers/protectors (lower-case).
PACKER_SECTIONS = {
    'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack',
    '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack', '.themida': 'Themida',
    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
    '.mpress1': 'MPRESS', '.mpress2': 'MPRESS', '.petite': 'Petite', 'pec1': 'PECompact',
    'pec2': 'PECompact', '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
    '.rlpack': 'RLPack', '.packed': 'generic packer',
}

# (title, ATT&CK id, severity, minimum distinct APIs, must include one of, APIs).
# Names are lower-case without the A/W suffix. ATT&CK ids are indicative only.
API_GROUPS: list[tuple[str, str, str, int, frozenset[str], frozenset[str]]] = [
    ('process injection', 'T1055', 'MEDIUM', 3, frozenset({'writeprocessmemory', 'ntwritevirtualmemory'}),
     frozenset({'virtualallocex', 'writeprocessmemory', 'createremotethread', 'createremotethreadex',
                'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'ntmapviewofsection',
                'rtlcreateuserthread', 'ntwritevirtualmemory'})),
    ('process hollowing pattern', 'T1055.012', 'HIGH', 4,
     frozenset({'ntunmapviewofsection', 'zwunmapviewofsection'}),
     frozenset({'ntunmapviewofsection', 'zwunmapviewofsection', 'setthreadcontext',
                'writeprocessmemory', 'resumethread', 'virtualallocex'})),
    ('anti-debugging', 'T1622', 'MEDIUM', 1, frozenset(),
     frozenset({'checkremotedebuggerpresent', 'ntsetinformationthread', 'zwsetinformationthread'})),
    ('keylogging', 'T1056.001', 'MEDIUM', 2, frozenset({'setwindowshook', 'setwindowshookex'}),
     frozenset({'setwindowshookex', 'getasynckeystate', 'getkeyboardstate', 'registerrawinputdevices',
                'getrawinputdata'})),
    ('HTTP client', 'T1071.001', 'INFO', 2, frozenset(),
     frozenset({'internetopen', 'internetconnect', 'internetopenurl', 'httpopenrequest', 'httpsendrequest',
                'internetreadfile', 'winhttpopen', 'winhttpconnect', 'winhttpsendrequest',
                'winhttpreceiveresponse', 'winhttpreaddata'})),
    ('download to disk', 'T1105', 'MEDIUM', 1, frozenset(),
     frozenset({'urldownloadtofile', 'urldownloadtocachefile'})),
    ('raw sockets', 'T1095', 'INFO', 4, frozenset(),
     frozenset({'wsastartup', 'socket', 'connect', 'send', 'recv', 'wsasocket', 'bind', 'listen',
                'accept', 'gethostbyname', 'getaddrinfo'})),
    ('service installation', 'T1543.003', 'MEDIUM', 2, frozenset({'createservice'}),
     frozenset({'createservice', 'startservice', 'openscmanager', 'changeserviceconfig'})),
    ('token/privilege manipulation', 'T1134', 'INFO', 3, frozenset(),
     frozenset({'adjusttokenprivileges', 'openprocesstoken', 'lookupprivilegevalue', 'duplicatetokenex',
                'impersonateloggedonuser', 'setthreadtoken'})),
    ('cryptography', '', 'INFO', 3, frozenset(),
     frozenset({'cryptencrypt', 'cryptdecrypt', 'cryptgenkey', 'cryptderivekey', 'cryptacquirecontext',
                'cryptimportkey', 'bcryptencrypt', 'bcryptgeneratesymmetrickey', 'cryptgenrandom'})),
]
_KNOWN_APIS = frozenset().union(*(g[5] for g in API_GROUPS), *(g[4] for g in API_GROUPS))


def _canon(name: str) -> str:
    """CreateProcessW → createprocess, but only when the stripped form is a name we know."""
    n = name.lower()
    if n in _KNOWN_APIS:
        return n
    if n[-1:] in ('a', 'w') and n[:-1] in _KNOWN_APIS:
        return n[:-1]
    return n


def _flags_text(flags: int) -> str:
    return ''.join(c if flags & b else '-' for c, b in (('r', 0x40000000), ('w', SCN_WRITE), ('x', SCN_EXEC)))


def _when(ts: int) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)


def analyze_pe(data: bytes, result: AnalysisResult) -> None:
    info = parse_pe(data)
    if info is None:
        result.findings.append(Finding(
            title       = 'PE header is damaged',
            severity    = 'MEDIUM',
            description = 'The file starts like a PE but the headers cannot be parsed '
                          '(truncated or tampered). Compare e_lfanew and the optional header with a hex editor.',
            technique   = 'PE Analysis',
        ))
        return

    _summary(info, result)
    _record_details(info, result)
    _layout_checks(info, result)
    _import_checks(info, result)
    _overlay_checks(data, info, result)

    for w in info.warnings:
        result.findings.append(Finding(
            title       = 'PE parsing warning',
            severity    = 'MEDIUM',
            description = f'{w} — structure is damaged or deliberately malformed.',
            technique   = 'PE Analysis',
        ))


# ── reporting ────────────────────────────────────────────────────────────────

def _kind(info: PEInfo) -> str:
    if info.subsystem == 1:
        return 'driver (native subsystem)'
    return 'DLL' if info.is_dll else 'EXE'


def _summary(info: PEInfo, result: AnalysisResult) -> None:
    arch   = MACHINES.get(info.machine, f'machine 0x{info.machine:04X}')
    bits   = 'PE32+' if info.is64 else 'PE32'
    subsys = SUBSYSTEMS.get(info.subsystem, f'subsystem {info.subsystem}')
    mitig  = ', '.join(n for bit, n in DLL_CHARACTERISTICS if info.dll_chars & bit) or 'none'
    rows   = ['name       vsize   rsize  entropy perm md5']
    for s in info.sections[:8]:
        rows.append(f'{s.name[:8]:<9} {s.vsize:>6x} {s.rsize:>7x} {s.entropy:>7.2f} {_flags_text(s.flags)}  {s.md5[:8]}')
    if len(info.sections) > 8:
        rows.append(f'… {len(info.sections) - 8} more sections')
    signed = 'Authenticode blob present (NOT verified)' if info.cert_size else 'no Authenticode signature'
    result.findings.append(Finding(
        title       = f'PE {_kind(info)}: {arch}, {bits}, {subsys}',
        severity    = 'INFO',
        description = (
            f'Compiled {_when(info.timestamp):%Y-%m-%d %H:%M} UTC (header field, trivially forged). '
            f'Mitigations: {mitig}. {signed}.'
            + (' Managed (.NET) assembly.' if info.clr else '')
        ),
        data        = '\n'.join(rows),
        technique   = 'PE Analysis',
    ))
    if info.clr:
        result.findings.append(Finding(
            title       = '.NET assembly',
            severity    = 'INFO',
            description = 'CLR header present: the native import table is just a stub (mscoree). '
                          'Decompile with dnSpy/ILSpy instead of reading imports.',
            technique   = 'PE Analysis',
        ))


def _record_details(info: PEInfo, result: AnalysisResult) -> None:
    entry = info.section_for_rva(info.entry_rva) if info.entry_rva else None
    result.details['pe'] = {
        'machine':      MACHINES.get(info.machine, hex(info.machine)),
        'format':       'PE32+' if info.is64 else 'PE32',
        'kind':         _kind(info),
        'subsystem':    SUBSYSTEMS.get(info.subsystem, str(info.subsystem)),
        'timestamp':    _when(info.timestamp).isoformat(),
        'entry_rva':    info.entry_rva,
        'entry_section': entry.name if entry else None,
        'image_base':   info.image_base,
        'sections': [
            {'name': s.name, 'virtual_size': s.vsize, 'virtual_address': s.vaddr, 'raw_size': s.rsize,
             'raw_offset': s.rptr, 'entropy': round(s.entropy, 3), 'perms': _flags_text(s.flags), 'md5': s.md5}
            for s in info.sections
        ],
        'imports':      info.imports,
        'imphash':      info.imphash(),
        'exports':      info.exports,
        'tls_callbacks': info.tls_callbacks,
        'overlay':      {'offset': info.overlay_offset, 'size': info.overlay_size},
        'signed':       bool(info.cert_size),
        'dotnet':       info.clr,
    }


def _layout_checks(info: PEInfo, result: AnalysisResult) -> None:
    def add(title: str, severity: str, description: str, data: str = '') -> None:
        result.findings.append(Finding(title=title, severity=severity, description=description,
                                       data=data, technique='PE Analysis'))

    # Timestamp
    ts = _when(info.timestamp)
    if info.timestamp == 0:
        add('Compile timestamp is zero', 'INFO',
            'Zeroed by the linker (reproducible builds) or wiped on purpose.')
    elif ts > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1):
        add('Compile timestamp is in the future', 'MEDIUM',
            f'Header says {ts:%Y-%m-%d} — forged, or a deterministic-build hash instead of a time.')
    elif ts < EARLIEST_PLAUSIBLE:
        add('Compile timestamp predates Windows NT', 'MEDIUM', f'Header says {ts:%Y-%m-%d}: not a real build time.')

    # Packers: section names
    packers = {PACKER_SECTIONS[s.name.lower()] for s in info.sections if s.name.lower() in PACKER_SECTIONS}
    for p in sorted(packers):
        names = ', '.join(s.name for s in info.sections if PACKER_SECTIONS.get(s.name.lower()) == p)
        add(f'Packer indicator: {p}', 'HIGH',
            f'Section names ({names}) are typical for {p}. The real code is unpacked at runtime — '
            'analyse the unpacked process or dump, not this file.')

    # Entropy
    for s in info.sections:
        if s.rsize >= MIN_SECTION_BYTES and s.entropy >= HIGH_ENTROPY:
            if s.executable:
                add(f"High-entropy code section '{s.name}' ({s.entropy:.2f})", 'HIGH',
                    'Executable section looks compressed or encrypted — likely packed.')
            else:
                add(f"High-entropy section '{s.name}' ({s.entropy:.2f})", 'INFO' if s.name == '.rsrc' else 'MEDIUM',
                    'Compressed/encrypted payload, or compressed resources.')

    # Section flags
    for s in info.sections:
        if s.flags & SCN_EXEC and s.flags & SCN_WRITE:
            add(f"Writable + executable section '{s.name}'", 'MEDIUM',
                'Self-modifying code or an unpacker stub; normal compilers do not emit W+X sections.')
        if s.executable and s.rsize == 0 and s.vsize >= 0x1000:
            add(f"Executable section '{s.name}' is empty on disk", 'MEDIUM',
                f'Virtual size 0x{s.vsize:X} but no raw data: filled at runtime (classic unpacker layout).')

    # Entry point
    if info.entry_rva:
        sec = info.section_for_rva(info.entry_rva)
        if sec is None:
            add('Entry point is outside every section', 'MEDIUM',
                f'AddressOfEntryPoint 0x{info.entry_rva:X} maps to no section (header trick or damaged file).')
        else:
            if not sec.executable:
                add(f"Entry point in non-executable section '{sec.name}'", 'MEDIUM',
                    'Execution starts in a section not marked executable.')
            if len(info.sections) > 1 and sec is info.sections[-1] and not info.clr:
                add(f"Entry point in the last section '{sec.name}'", 'MEDIUM',
                    'Common for packers and file infectors that append their stub.')

    # TLS
    if info.tls_callbacks:
        add(f'TLS callbacks ({info.tls_callbacks})', 'MEDIUM',
            'Code that runs BEFORE the entry point — a debugger that breaks at the entry point misses it. '
            'Used for anti-debugging and early unpacking, but also by legitimate runtimes.')


def _import_checks(info: PEInfo, result: AnalysisResult) -> None:
    total = info.import_count
    if total:
        lines = [f'imphash: {info.imphash()}']
        lines += [f'{dll}: {len(f)}' for dll, f in list(info.imports.items())[:8]]
        if len(info.imports) > 8:
            lines.append(f'… {len(info.imports) - 8} more DLLs')
        result.findings.append(Finding(
            title       = f'Imports: {total} functions from {len(info.imports)} DLLs',
            severity    = 'INFO',
            description = 'Import hash (MD5 of dll.function list) clusters samples built from the same code. '
                          'Ordinal imports are hashed as ordN, which can differ from other tools for ws2_32/oleaut32.',
            data        = '\n'.join(lines),
            technique   = 'PE Imports',
        ))
    if 0 < total <= FEW_IMPORTS and not info.clr:
        result.findings.append(Finding(
            title       = f'Very few imports ({total})',
            severity    = 'MEDIUM',
            description = 'A real program imports dozens of functions. A near-empty table means packing '
                          'or dynamic API resolution (LoadLibrary/GetProcAddress, API hashing).',
            data        = '\n'.join(f for fs in info.imports.values() for f in fs),
            technique   = 'PE Imports',
        ))
    elif total == 0 and not info.clr and not info.is_dll and info.sections:
        result.findings.append(Finding(
            title       = 'No import table',
            severity    = 'MEDIUM',
            description = 'An executable with no imports resolves everything itself (shellcode-like, packed, '
                          'or a hand-built binary).',
            technique   = 'PE Imports',
        ))

    present = {_canon(f) for fs in info.imports.values() for f in fs}
    for title, attack, severity, minimum, required, apis in API_GROUPS:
        hit = sorted(present & apis)
        if len(hit) < minimum or (required and not (present & required)):
            continue
        tag = f' ({attack})' if attack else ''
        result.findings.append(Finding(
            title       = f'Imports suggest: {title}{tag}',
            severity    = severity,
            description = 'The import table contains APIs typical for this behaviour. An imported API is a '
                          'hint, not proof — check the code that calls them.',
            data        = ', '.join(hit),
            technique   = 'PE Imports',
        ))

    if info.is_dll and info.exports:
        result.findings.append(Finding(
            title       = f'Exports ({len(info.exports)})',
            severity    = 'INFO',
            description = 'Exported function names:',
            data        = '\n'.join(info.exports[:10]) + (f'\n… {len(info.exports) - 10} more' if len(info.exports) > 10 else ''),
            technique   = 'PE Analysis',
        ))


def _overlay_checks(data: bytes, info: PEInfo, result: AnalysisResult) -> None:
    if not info.overlay_offset or info.overlay_size <= 0:
        return
    blob = data[info.overlay_offset:info.overlay_offset + info.overlay_size]
    kind, _cat = detect_filetype(blob[:64]) if len(blob) >= 4 else ('UNKNOWN', '')
    ent  = shannon_entropy(blob[:1 << 20])
    result.carved.append(('OVERLAY', info.overlay_offset))
    if kind not in ('UNKNOWN', 'TEXT'):
        title, severity, extra = f'Overlay contains a {kind} file', 'HIGH', ' Self-extractor, installer or dropper payload.'
    elif info.overlay_size >= LARGE_OVERLAY:
        title, severity, extra = f'Overlay: {info.overlay_size:,} bytes', 'MEDIUM', ' Appended data is not loaded by Windows; droppers and installers keep payloads here.'
    else:
        title, severity, extra = f'Overlay: {info.overlay_size} bytes', 'INFO', ''
    result.findings.append(Finding(
        title       = title,
        severity    = severity,
        description = f'{info.overlay_size:,} bytes after the last section (entropy {ent:.2f}/8).{extra}',
        data        = f'Offset: {info.overlay_offset} (0x{info.overlay_offset:X})',
        hint        = 'Re-run with --extract DIR to save it.',
        technique   = 'PE Analysis',
        offset      = info.overlay_offset,
    ))

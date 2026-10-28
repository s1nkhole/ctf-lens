"""PE parsing and triage: structure, packer/anomaly heuristics, API groups, robustness against damage."""
import hashlib
import json
import random
import subprocess
import sys
from pathlib import Path

from ctf_lens import analyze
from ctf_lens.pe import parse_pe
from helpers import build_pe

ROOT = Path(__file__).resolve().parent.parent
CODE = {'name': '.text', 'data': b'\x55\x8b\xec' + bytes(range(32, 120)) * 6, 'flags': 0x60000020}
DATA = {'name': '.data', 'data': b'hello world, plain data section. ' * 20, 'flags': 0xC0000040}


def _analyze(tmp_path, data, name='s.exe', **kw):
    p = tmp_path / name
    p.write_bytes(data)
    return analyze(str(p), **kw)


def _titles(result):
    return [f.title for f in result.findings]


def _alarms(result):
    return [f.title for f in result.findings if f.severity in ('HIGH', 'MEDIUM') and f.technique.startswith('PE')]


# ── parser ───────────────────────────────────────────────────────────────────

def test_parser_reads_pe32_and_pe32plus():
    for is64 in (True, False):
        pe = parse_pe(build_pe(is64=is64))
        assert pe.is64 is is64
        assert [s.name for s in pe.sections] == ['.text', '.data', '.idata']
        assert pe.imports['KERNEL32.dll'][:2] == ['ExitProcess', 'GetLastError']
        assert pe.import_count == 10 and pe.warnings == []


def test_parser_reads_exports_tls_overlay_ordinals():
    pe = parse_pe(build_pe(dll=True, tls_callbacks=3, export_names=['Alpha', 'Beta'], overlay=b'X' * 100))
    assert pe.is_dll and pe.exports == ['Alpha', 'Beta'] and pe.tls_callbacks == 3
    assert pe.overlay_size == 100
    ords = parse_pe(build_pe(is64=False, imports={'WS2_32.dll': ['#115', 'send']}))
    assert ords.imports['WS2_32.dll'] == ['#115', 'send']


def test_certificate_is_not_counted_as_overlay():
    pe = parse_pe(build_pe(cert=b'\x30' * 300))
    assert pe.cert_size == 300 and pe.overlay_size == 0


def test_imphash_recipe():
    pe = parse_pe(build_pe(imports={'KERNEL32.dll': ['ExitProcess', 'GetLastError'], 'WS2_32.dll': ['#115']}))
    expected = 'kernel32.exitprocess,kernel32.getlasterror,ws2_32.ord115'
    assert pe.imphash() == hashlib.md5(expected.encode()).hexdigest()


def test_non_pe_returns_none():
    assert parse_pe(b'MZ' + b'\x00' * 200) is None
    assert parse_pe(b'not a pe at all') is None


def test_damaged_files_never_raise():
    good = build_pe(tls_callbacks=1, export_names=['A', 'B'], overlay=b'tail')
    for cut in range(0, len(good), 37):                  # truncation at many offsets
        parse_pe(good[:cut])
    rng = random.Random(1234)
    for _ in range(300):                                  # random corruption
        blob = bytearray(good)
        for _ in range(rng.randint(1, 12)):
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        parse_pe(bytes(blob))


def test_damaged_files_never_raise_through_the_full_pipeline(tmp_path):
    good = build_pe(tls_callbacks=1)
    rng = random.Random(99)
    for i in range(25):
        blob = bytearray(good)
        for _ in range(8):
            blob[rng.randrange(0, 0x300)] = rng.randrange(256)       # hammer the headers
        _analyze(tmp_path, bytes(blob), f'f{i}.exe')


# ── no false alarms ──────────────────────────────────────────────────────────

def test_ordinary_executable_raises_no_alarms(tmp_path):
    for is64 in (True, False):
        assert _alarms(_analyze(tmp_path, build_pe(is64=is64))) == []


def test_crt_style_imports_are_not_flagged(tmp_path):
    imports = {'KERNEL32.dll': ['IsDebuggerPresent', 'OutputDebugStringW', 'GetProcAddress', 'LoadLibraryA',
                                'CreateProcessW', 'VirtualAlloc', 'GetCurrentProcess', 'ExitProcess',
                                'NtQueryInformationProcess']}
    assert _alarms(_analyze(tmp_path, build_pe(imports=imports))) == []


def test_dotnet_assembly_with_one_import_is_not_called_packed(tmp_path):
    result = _analyze(tmp_path, build_pe(is64=False, clr=True, imports={'mscoree.dll': ['_CorExeMain']}))
    assert '.NET assembly' in _titles(result)
    assert not any(t.startswith('Very few imports') for t in _titles(result))


# ── detections ───────────────────────────────────────────────────────────────

def test_upx_like_layout_is_reported(tmp_path):
    rnd = random.Random(5).randbytes(3000)
    secs = [
        {'name': 'UPX0', 'data': b'', 'vsize': 0x10000, 'flags': 0xE0000080},
        {'name': 'UPX1', 'data': rnd, 'flags': 0xE0000040},
    ]
    result = _analyze(tmp_path, build_pe(sections=secs, imports={'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress']},
                                         entry_section=1))
    titles = _titles(result)
    assert 'Packer indicator: UPX' in titles
    assert any(t.startswith("High-entropy code section 'UPX1'") for t in titles)
    assert any(t.startswith("Writable + executable section") for t in titles)
    assert any(t.startswith("Executable section 'UPX0' is empty on disk") for t in titles)
    assert any(t.startswith('Very few imports (2)') for t in titles)


def test_entry_point_in_last_section(tmp_path):
    secs = [CODE, DATA, {'name': '.stub', 'data': b'\x90' * 600, 'flags': 0x60000020}]
    # imports={} so the builder adds no .idata after the stub: '.stub' really is the last section
    assert any(t.startswith("Entry point in the last section '.stub'")
               for t in _titles(_analyze(tmp_path, build_pe(sections=secs, entry_section=2, imports={}))))


def test_entry_point_in_non_executable_section(tmp_path):
    assert any(t.startswith("Entry point in non-executable section '.data'")
               for t in _titles(_analyze(tmp_path, build_pe(sections=[CODE, DATA], entry_section=1))))


def test_tls_callbacks_reported(tmp_path):
    assert 'TLS callbacks (2)' in _titles(_analyze(tmp_path, build_pe(tls_callbacks=2)))


def test_timestamps(tmp_path):
    assert 'Compile timestamp is in the future' in _titles(_analyze(tmp_path, build_pe(timestamp=4_102_444_800)))
    assert 'Compile timestamp is zero' in _titles(_analyze(tmp_path, build_pe(timestamp=0)))
    assert 'Compile timestamp predates Windows NT' in _titles(_analyze(tmp_path, build_pe(timestamp=86_400 * 365)))
    assert not any('timestamp' in t for t in _titles(_analyze(tmp_path, build_pe(timestamp=1_700_000_000))))


def test_api_groups_with_a_w_suffix_normalisation(tmp_path):
    inj = {'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ExitProcess']}
    f = next(f for f in _analyze(tmp_path, build_pe(imports=inj)).findings if 'process injection' in f.title)
    assert f.severity == 'MEDIUM' and '(T1055)' in f.title and 'writeprocessmemory' in f.data
    hollow = {'ntdll.dll': ['NtUnmapViewOfSection'], 'KERNEL32.dll': ['SetThreadContext', 'WriteProcessMemory', 'ResumeThread']}
    h = next(f for f in _analyze(tmp_path, build_pe(imports=hollow), 'h.exe').findings if 'hollowing' in f.title)
    assert h.severity == 'HIGH' and 'T1055.012' in h.title
    w = {'KERNEL32.dll': ['CreateServiceW', 'StartServiceA', 'OpenSCManagerW'], 'URLMON.dll': ['URLDownloadToFileW']}
    titles = _titles(_analyze(tmp_path, build_pe(imports=w), 'w.exe'))
    assert any('service installation' in t for t in titles) and any('download to disk' in t for t in titles)


def test_anti_debug_needs_a_strong_api(tmp_path):
    strong = {'KERNEL32.dll': ['CheckRemoteDebuggerPresent', 'ExitProcess']}
    assert any('anti-debugging' in t for t in _titles(_analyze(tmp_path, build_pe(imports=strong))))


def test_overlay_with_embedded_file_is_high_and_extractable(tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('payload.txt', 'secret ' * 40)
    payload = buf.getvalue()
    result = _analyze(tmp_path, build_pe(overlay=payload), extract_dir=str(tmp_path / 'out'))
    hit = next(f for f in result.findings if f.title == 'Overlay contains a ZIP file')
    assert hit.severity == 'HIGH' and hit.offset is not None
    saved = [p for p in result.extracted if 'overlay' in p]
    assert saved and Path(saved[0]).read_bytes() == payload
    assert not any(f.hint.startswith('Re-run with --extract') for f in result.findings)   # hint is retired once saved


def test_large_plain_overlay_is_medium_and_signature_alone_is_not_overlay(tmp_path):
    big = _analyze(tmp_path, build_pe(overlay=b'ABCD' * 2000))
    assert next(f for f in big.findings if f.title.startswith('Overlay:')).severity == 'MEDIUM'
    signed = _analyze(tmp_path, build_pe(cert=b'\x30' * 300), 'signed.exe')
    assert not any(t.startswith('Overlay') for t in _titles(signed))
    assert signed.details['pe']['signed'] is True


def test_exports_listed_for_dll(tmp_path):
    result = _analyze(tmp_path, build_pe(dll=True, export_names=['Alpha', 'Beta']), 'x.dll')
    exp = next(f for f in result.findings if f.title.startswith('Exports'))
    assert 'Alpha' in exp.data and 'PE DLL' in ' '.join(_titles(result))


# ── structured output ────────────────────────────────────────────────────────

def test_details_in_json_output(tmp_path):
    p = tmp_path / 'j.exe'
    p.write_bytes(build_pe(overlay=b'zz' * 10))
    r = subprocess.run([sys.executable, '-m', 'ctf_lens', str(p), '--json'], cwd=ROOT, capture_output=True, text=True)
    pe = json.loads(r.stdout)['details']['pe']
    assert pe['format'] == 'PE32+' and pe['imports']['KERNEL32.dll'][0] == 'ExitProcess'
    assert len(pe['imphash']) == 32 and pe['sections'][0]['name'] == '.text' and pe['overlay']['size'] == 20

"""IOC extraction: validated indicators, and silence on ordinary content."""
import json
import random
import subprocess
import sys
from pathlib import Path

from ctf_lens import analyze
from ctf_lens.ioc import extract_iocs, valid_btc_base58, valid_btc_bech32
from helpers import build_pe

ROOT = Path(__file__).resolve().parent.parent


def _file(tmp_path, content, name='t.txt'):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return str(p)


def test_bitcoin_validators_against_published_vectors():
    assert valid_btc_base58('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')            # genesis block address
    assert valid_btc_base58('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')
    assert not valid_btc_base58('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb')        # one character changed
    assert valid_btc_bech32('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')    # BIP173
    assert not valid_btc_bech32('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5')
    assert valid_btc_bech32('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0')   # BIP350 (bech32m)
    assert not valid_btc_bech32('bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4')  # bech32 checksum on a v1 address


def test_each_indicator_type_is_found():
    token = '123456789:AA' + 'x' * 33
    onion = 'a' * 16 + '.onion'
    found, _ = extract_iocs([
        'beacon to evil-c2.ru and 185.220.101.4', 'mail ops@evil-c2.ru',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater',
        r'C:\Users\alice\source\repos\Implant\x64\Release\Implant.pdb',
        r'%APPDATA%\Roaming\svc\update.exe', 'pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        f'http {onion}', token, 'https://discord.com/api/webhooks/123456/abc-DEF_ghi',
    ])
    assert 'evil-c2.ru' in found['domain'] and 'discord.com' in found['domain'] and found['ipv4'] == ['185.220.101.4']
    assert not any(d.endswith('.onion') for d in found['domain'])        # .onion has its own indicator type
    assert found['email'] == ['ops@evil-c2.ru'] and found['bitcoin'] == ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']
    assert found['onion'] == [onion] and found['telegram_token'] == [token]
    assert found['pdb_path'] == [r'C:\Users\alice\source\repos\Implant\x64\Release\Implant.pdb']
    assert found['registry_key'][0].endswith(r'\Run\Updater') and found['webhook']
    assert found['suspicious_path'] == [r'%APPDATA%\Roaming\svc\update.exe']


def test_ordinary_content_produces_no_indicators():
    found, suppressed = extract_iocs([
        'kernel32.dll', 'config.txt', 'setup.py', 'readme.md', 'index.html', 'app.js', 'style.css', 'libc.so.6',
        'version 1.2.3.4.5', 'build 10.0.19041.1', 'addr 10.0.0.1 192.168.1.5 127.0.0.1', 'ver 01.02.03.04',
        'schemas.microsoft.com', 'www.w3.org', 'crl.digicert.com', 'support@microsoft.com',
        'not a wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb', 'The quick brown fox, e.g. i.e. etc.',
        'OiI98.gR', 'yrMO.Pk', 'rx.ai', 'bcd1.ua',                       # shapes that random bytes produce
    ])
    assert found == {} and suppressed == 2        # microsoft.com + digicert.com; w3.org is dropped earlier (short label)


def test_random_data_produces_no_indicators(tmp_path):
    for seed in (3, 6, 7, 24):          # seeds that produced 'rx.ai'-style matches before the filters existed
        result = analyze(_file(tmp_path, random.Random(seed).randbytes(2_000_000), f'r{seed}.bin'))
        assert result.iocs == {} and not any(f.technique == 'IOC Extraction' for f in result.findings)


def test_domain_extraction_alone_is_quiet_on_random_strings():
    from ctf_lens.utils import extract_strings
    noisy = sum(bool(extract_iocs(extract_strings(random.Random(5000 + i).randbytes(2_000_000), min_len=4))[0])
                for i in range(30))
    assert noisy <= 1                    # measured 1/200 with the shipped filters; the gate above removes most of it


def test_domain_case_and_length_rules():
    found, _ = extract_iocs(['Example-corp.com', 'EVIL-C2.RU', 'login.ru', 'abcde.pw', 'ab.com'])
    assert found['domain'] == ['example-corp.com', 'evil-c2.ru', 'login.ru', 'abcde.pw']


def test_utf16_strings_are_covered(tmp_path):
    data = b'\x00' * 100 + 'http://beacon.evil-c2.ru/gate.php'.encode('utf-16-le') + b'\x00' * 50
    assert 'beacon.evil-c2.ru' in analyze(_file(tmp_path, data, 'w.bin')).iocs['domain']


def test_persistence_keys_are_called_out_in_a_pe(tmp_path):
    strings = rb'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' + b'\x00' + b'cmd.exe /c evil-c2.ru'
    pe = build_pe(sections=[
        {'name': '.text', 'data': b'\x55\x8b\xec' + bytes(range(32, 120)) * 6, 'flags': 0x60000020},
        {'name': '.data', 'data': strings.ljust(600, b'\x00'), 'flags': 0xC0000040}])
    result = analyze(_file(tmp_path, pe, 's.exe'))
    hit = next(f for f in result.findings if f.title.startswith('Persistence-related registry keys'))
    assert hit.severity == 'MEDIUM' and 'T1547.001' in hit.data
    assert 'evil-c2.ru' in result.iocs['domain']


def test_iocs_flag_and_json(tmp_path):
    path = _file(tmp_path, 'C2 at evil-c2.ru / 185.220.101.4 and flag{x_y_z_1}')
    r = subprocess.run([sys.executable, '-m', 'ctf_lens', path, '--iocs'], cwd=ROOT, capture_output=True, text=True)
    assert r.stdout.splitlines() == ['domain\tevil-c2.ru', 'ipv4\t185.220.101.4'] and r.stderr == ''
    j = subprocess.run([sys.executable, '-m', 'ctf_lens', path, '--json'], cwd=ROOT, capture_output=True, text=True)
    assert json.loads(j.stdout)['iocs']['ipv4'] == ['185.220.101.4']

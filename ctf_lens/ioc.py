"""
Indicator-of-compromise (IOC) extraction from the strings of a file.

Precision over recall: each indicator class has a validator so that ordinary files stay quiet.
  * domains      only under a curated TLD list (so 'kernel32.dll', 'config.txt', 'setup.py' do not match)
                 and not under well-known benign domains (reported as a suppressed count)
  * IPv4         globally routable only, no version-number lookalikes (1.2.3.4.5), no leading zeros
  * Bitcoin      Base58Check / Bech32 checksum verified
  * the rest     (registry keys, PDB paths, .onion, bot tokens, webhooks) have distinctive shapes

URLs are reported by the general URL finder, not here.
Entry point: report_iocs(strings, result)
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from .models import Finding, AnalysisResult

MAX_TEXT      = 32 * 1024 * 1024
MAX_PER_TYPE  = 500
# Shortest registrable label (the part before the TLD). Random bytes produce 'rx.ai'-style matches
# at a steady rate (measured: every 2 MB of random data without these limits), so short labels are
# ignored — more strictly under two-letter country TLDs, which are the most numerous.
MIN_LABEL     = 4
MIN_LABEL_CC  = 5
SHOW          = 25

_TLDS = (
    'com net org info biz xyz top site online shop store club live tech app dev io ai me tv cloud link '
    'click work support services finance ru cn su ua by kz ir kp de fr uk nl it es jp kr br tr tw hk sg '
    'au ca us eu ch se no fi dk cz ro bg gr hu pt ar mx za ng vn ph pk bd il ae sa eg tk ga cf gq pw ws'
).split()
_TLD_RE = '|'.join(sorted(_TLDS, key=len, reverse=True))

# Domains that appear in countless legitimate binaries (certificates, XML namespaces, update URLs).
BENIGN_DOMAINS = frozenset({
    'microsoft.com', 'windows.com', 'windowsupdate.com', 'w3.org', 'openxmlformats.org', 'xmlsoap.org',
    'digicert.com', 'verisign.com', 'sectigo.com', 'globalsign.com', 'entrust.net', 'symcb.com',
    'symcd.com', 'mozilla.org', 'apache.org', 'python.org', 'openssl.org', 'gnu.org',
    'example.com', 'example.org', 'example.net',
})

_DOMAIN = re.compile(
    r'(?<![A-Za-z0-9_@.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:' + _TLD_RE + r')(?![A-Za-z0-9\-])',
    re.IGNORECASE)
_IPV4    = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)')
_EMAIL   = re.compile(r'(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+(?:' + _TLD_RE + r')(?![A-Za-z0-9\-])',
                      re.IGNORECASE)
_REGKEY  = re.compile(r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)'
                      r'\\[^\x00-\x1f"\'<>|]{3,200}')
_PDB     = re.compile(r'[A-Za-z]:\\[^\x00-\x1f"<>|*?]{3,260}?\.pdb', re.IGNORECASE)
_PATH    = re.compile(r'(?:%(?:APPDATA|TEMP|TMP|LOCALAPPDATA|PROGRAMDATA|USERPROFILE|PUBLIC)%'
                      r'|[A-Za-z]:\\(?:Users\\[^\\\r\n]+\\AppData|ProgramData|Windows\\Temp|Users\\Public))'
                      r'\\[^\x00-\x1f"<>|*?]{1,200}', re.IGNORECASE)
_BTC_B58 = re.compile(r'(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])')
_BTC_BECH = re.compile(r'(?<![A-Za-z0-9])bc1[02-9ac-hj-np-z]{11,71}(?![A-Za-z0-9])')
_ONION   = re.compile(r'(?<![a-z2-7])(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion(?![a-z0-9])')
_TGTOKEN = re.compile(r'(?<![\d:])\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])')
_WEBHOOK = re.compile(r'https://(?:(?:discord|discordapp)\.com/api/webhooks/\d+/[\w\-]+|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)')

# registry persistence locations → (ATT&CK id, name); indicative only
_PERSISTENCE = [
    ('\\currentversion\\runonce', 'T1547.001', 'Run/RunOnce key'),
    ('\\currentversion\\run', 'T1547.001', 'Run key'),
    ('\\policies\\explorer\\run', 'T1547.001', 'Policies\\Explorer\\Run'),
    ('\\winlogon\\shell', 'T1547.004', 'Winlogon Shell'),
    ('\\winlogon\\userinit', 'T1547.004', 'Winlogon Userinit'),
    ('\\image file execution options', 'T1546.012', 'Image File Execution Options'),
    ('appinit_dlls', 'T1546.010', 'AppInit_DLLs'),
]

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def valid_btc_base58(addr: str) -> bool:
    """Base58Check: 25 bytes = version(1) + hash160(20) + checksum(4); version 0x00 or 0x05."""
    n = 0
    for c in addr:
        n = n * 58 + _B58.index(c)
    try:
        raw = n.to_bytes(25, 'big')
    except OverflowError:
        return False
    pad = len(addr) - len(addr.lstrip('1'))
    if raw[:pad] != b'\x00' * pad or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_polymod(values: list[int]) -> int:
    gen, chk = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3), 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def valid_btc_bech32(addr: str) -> bool:
    """Bech32 (BIP173, witness v0) or Bech32m (BIP350, v1+) checksum for hrp 'bc'."""
    if addr != addr.lower() or not addr.startswith('bc1'):
        return False
    try:
        data = [_BECH.index(c) for c in addr[3:]]
    except ValueError:
        return False
    if len(data) < 7:
        return False
    const = _bech32_polymod([3, 3, 0, 2, 3] + data)          # hrp 'bc' expanded
    witness_version = data[0]
    return const == (1 if witness_version == 0 else 0x2BC830A3)


def _benign(domain: str) -> bool:
    """True when domain or any parent domain is on the benign list (O(labels), not O(list))."""
    parts = domain.split('.')
    return any('.'.join(parts[i:]) in BENIGN_DOMAINS for i in range(len(parts) - 1))


def _consistent_case(name: str) -> bool:
    """All lower, all upper, or only the first letter capitalised — how real names are written."""
    return name == name.lower() or name == name.upper() or name == name[0].upper() + name[1:].lower()


def _unique(items) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
        if len(seen) >= MAX_PER_TYPE:
            break
    return list(seen)


def extract_iocs(strings: list[str]) -> tuple[dict[str, list[str]], int]:
    """Return ({type: [values]}, number of suppressed benign domains)."""
    text = '\n'.join(strings)[:MAX_TEXT]
    found: dict[str, list[str]] = {}
    suppressed = 0

    def put(kind: str, values) -> None:
        values = _unique(values)
        if values:
            found[kind] = values

    # domains — each distinct match is judged once (repetitive files can contain millions of matches)
    domains: list[str] = []
    seen_raw: set[str] = set()
    for m in _DOMAIN.finditer(text):
        raw = m.group(0)
        if raw in seen_raw:
            continue
        seen_raw.add(raw)
        if not _consistent_case(raw):
            continue                                         # 'OiI98.gR' is noise, 'Example.com' is not
        d = raw.lower()
        labels = d.split('.')
        if len(labels[-2]) < (MIN_LABEL_CC if len(labels[-1]) == 2 else MIN_LABEL) or d.replace('.', '').isdigit():
            continue
        if _benign(d):
            suppressed += 1
            continue
        if d not in domains:
            domains.append(d)
        if len(domains) >= MAX_PER_TYPE:
            break
    put('domain', domains)

    # IPv4
    ips: list[str] = []
    for m in _IPV4.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue                                         # octet > 255 or leading zeros
        if ip.is_global:
            ips.append(str(ip))
    put('ipv4', ips)

    if '@' in text:
        emails: dict[str, None] = {}
        for m in _EMAIL.finditer(text):
            addr = m.group(0).lower()
            if addr not in emails and not _benign(addr.rsplit('@', 1)[1]):
                emails[addr] = None
                if len(emails) >= MAX_PER_TYPE:
                    break
        put('email', emails)
    if 'HK' in text:
        put('registry_key', (m.group(0).rstrip('.,;)') for m in _REGKEY.finditer(text)))
    if '.pdb' in text.lower():
        put('pdb_path', (m.group(0) for m in _PDB.finditer(text)))
    if '%' in text or '\\' in text:
        put('suspicious_path', (m.group(0).rstrip('.,;)') for m in _PATH.finditer(text)))
    put('bitcoin', [a for a in (m.group(0) for m in _BTC_B58.finditer(text)) if valid_btc_base58(a)]
        + [a for a in (m.group(0) for m in _BTC_BECH.finditer(text)) if valid_btc_bech32(a)])
    if '.onion' in text:
        put('onion', (m.group(0) for m in _ONION.finditer(text)))
    if ':AA' in text:
        put('telegram_token', (m.group(0) for m in _TGTOKEN.finditer(text)))
    if 'webhook' in text or 'hooks.slack' in text:
        put('webhook', (m.group(0) for m in _WEBHOOK.finditer(text)))
    return found, suppressed


# (title, severity, description) per IOC type
_REPORT = {
    'domain':         ('Domains', 'INFO', 'Candidate network indicators (benign look-alikes filtered).'),
    'ipv4':           ('IPv4 addresses', 'INFO', 'Globally routable addresses found in strings.'),
    'email':          ('E-mail addresses', 'INFO', 'Contact, C2 or exfiltration addresses.'),
    'registry_key':   ('Registry keys', 'INFO', 'Registry paths referenced by the file.'),
    'pdb_path':       ('PDB paths', 'INFO', 'Debug-symbol paths often leak the build machine, user name and project.'),
    'suspicious_path': ('Suspicious file paths', 'INFO', 'User-writable locations used for dropped files and persistence.'),
    'bitcoin':        ('Bitcoin addresses', 'MEDIUM', 'Checksum-valid wallet addresses: ransom note, miner or stealer payout.'),
    'onion':          ('Tor hidden services', 'MEDIUM', '.onion addresses: C2 or ransom portal.'),
    'telegram_token': ('Telegram bot tokens', 'MEDIUM', 'Hard-coded bot token: command channel or exfiltration endpoint.'),
    'webhook':        ('Chat webhooks', 'MEDIUM', 'Discord/Slack webhook URLs are a common exfiltration endpoint.'),
}


def report_iocs(strings: list[str], result: AnalysisResult) -> None:
    found, suppressed = extract_iocs(strings)
    result.iocs = found
    for kind, (title, severity, description) in _REPORT.items():
        values = found.get(kind)
        if not values:
            continue
        extra = ''
        if kind == 'domain' and suppressed:
            extra = f' {suppressed} matches under well-known benign domains were hidden.'
        more = f'\n… {len(values) - SHOW} more (see --json / --iocs)' if len(values) > SHOW else ''
        result.findings.append(Finding(
            title       = f'IOC: {title} ({len(values)})',
            severity    = severity,
            description = description + extra,
            data        = '\n'.join(values[:SHOW]) + more,
            technique   = 'IOC Extraction',
        ))

    keys = found.get('registry_key', [])
    hits: dict[str, tuple[str, str]] = {}
    for key in keys:
        low = key.lower()
        for needle, attack, name in _PERSISTENCE:
            if needle in low:
                hits[key] = (attack, name)
                break
    if hits:
        result.findings.append(Finding(
            title       = f'Persistence-related registry keys ({len(hits)})',
            severity    = 'MEDIUM',
            description = 'Keys commonly written to survive reboot. A reference is a hint, not proof of a write.',
            data        = '\n'.join(f'{name} ({attack}): {key}' for key, (attack, name) in list(hits.items())[:SHOW]),
            technique   = 'IOC Extraction',
        ))

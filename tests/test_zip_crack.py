"""Encrypted ZIPs: built-in CTF passwords, --wordlist, and honest reporting when it fails."""
import zipfile

from ctf_lens import analyze
from helpers import build_zipcrypto_zip


def _zip(tmp_path, password, name='secret.zip'):
    data = build_zipcrypto_zip('flag.txt', b'flag{zip_password_cracked}', password)
    p = tmp_path / name
    p.write_bytes(data)
    assert zipfile.ZipFile(p).read('flag.txt', pwd=password.encode()) == b'flag{zip_password_cracked}'   # helper sanity
    return str(p)


def test_common_password_is_cracked_and_contents_read(tmp_path):
    result = analyze(_zip(tmp_path, 'infected'))
    assert 'flag{zip_password_cracked}' in result.flags()
    assert any(f.title == '🔓 ZIP password cracked: infected' for f in result.findings)


def test_archive_name_is_tried_as_a_password(tmp_path):
    assert 'flag{zip_password_cracked}' in analyze(_zip(tmp_path, 'challenge7', name='challenge7.zip')).flags()


def test_unknown_password_is_reported_honestly_then_found_with_wordlist(tmp_path):
    path = _zip(tmp_path, 'x9!zq-unusual')
    miss = analyze(path)
    assert miss.flags() == []
    assert any(f.title == 'ZIP password not in built-in list' for f in miss.findings)
    wl = tmp_path / 'words.txt'
    wl.write_text('alpha\nbeta\nx9!zq-unusual\ngamma\n')
    hit = analyze(path, wordlist=str(wl))
    assert 'flag{zip_password_cracked}' in hit.flags()


def test_missing_wordlist_is_a_clear_error(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        analyze(_zip(tmp_path, 'infected'), wordlist=str(tmp_path / 'nope.txt'))

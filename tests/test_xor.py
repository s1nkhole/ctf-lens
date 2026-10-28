"""XOR attacks: repeating key (statistical) and known-plaintext (flag prefix) recovery."""
import random

from ctf_lens import analyze

ENGLISH = (b'It was a bright cold day in April, and the clocks were striking thirteen. Winston Smith, '
           b'his chin nuzzled into his breast in an effort to escape the vile wind, slipped quickly '
           b'through the glass doors of Victory Mansions, though not quickly enough to prevent a swirl '
           b'of gritty dust from entering along with him. ')


def _xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _write(tmp_path, data):
    p = tmp_path / 'x.bin'
    p.write_bytes(data)
    return str(p)


def test_repeating_key_xor_flag_in_the_middle(tmp_path):
    plain = ENGLISH * 2 + b'the flag is flag{repeating_xor_recovered} ok. ' + ENGLISH
    result = analyze(_write(tmp_path, _xor(plain, b'secret')), xor_bruteforce=True)
    assert 'flag{repeating_xor_recovered}' in result.flags()


def test_repeating_key_without_flag_reports_readable_text(tmp_path):
    result = analyze(_write(tmp_path, _xor(ENGLISH * 3, b'k3y!')), xor_bruteforce=True)
    assert any(d.title.startswith('Repeating-key XOR') and 'Winston' in d.data for d in result.decoded)


def test_known_plaintext_recovers_short_data_with_short_key(tmp_path):
    cipher = _xor(b'flag{short_one}', b'ab')                 # too short for statistics
    result = analyze(_write(tmp_path, cipher), xor_bruteforce=True)
    assert 'flag{short_one}' in result.flags()


def test_single_byte_xor_still_works(tmp_path):
    assert 'flag{one_byte_key}' in analyze(_write(tmp_path, _xor(b'flag{one_byte_key} and more text here', b'\x5a')),
                                           xor_bruteforce=True).flags()


def test_random_data_with_xor_enabled_finds_nothing(tmp_path):
    result = analyze(_write(tmp_path, random.Random(7).randbytes(20_000)), xor_bruteforce=True)
    assert result.flags() == []
    assert not any(d.title.startswith('Repeating-key XOR') for d in result.decoded)


def test_xor_is_off_by_default(tmp_path):
    assert analyze(_write(tmp_path, _xor(b'flag{short_one}', b'ab'))).flags() == []

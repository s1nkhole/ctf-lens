"""LSB steganography: the entropy test cannot see short messages, extraction must not depend on it."""
import pytest

np   = pytest.importorskip('numpy')
Image = pytest.importorskip('PIL.Image')

from ctf_lens import analyze
from helpers import build_png


def _noise(w=120, h=80, seed=1):
    return np.random.RandomState(seed).randint(0, 256, (h, w, 3), dtype=np.uint8)


def _bits(payload: bytes, bitorder: str):
    return np.unpackbits(np.frombuffer(payload, dtype=np.uint8), bitorder='big' if bitorder == 'msb' else 'little')


def _embed(arr, payload, channels, order='rows', bitorder='msb'):
    """Write payload bits into the LSB of the chosen channels, pixel by pixel."""
    bits = _bits(payload, bitorder)
    work = arr.copy() if order == 'rows' else np.ascontiguousarray(arr.transpose(1, 0, 2))
    flat = work.reshape(-1, 3)                      # a view (work is contiguous), pixels in scan order
    i = 0
    for px in range(len(flat)):
        for ch in channels:
            if i >= len(bits):
                return work if order == 'rows' else np.ascontiguousarray(work.transpose(1, 0, 2))
            flat[px, ch] = (flat[px, ch] & 0xFE) | bits[i]
            i += 1
    return work if order == 'rows' else np.ascontiguousarray(work.transpose(1, 0, 2))


def _save(arr, tmp_path, name='img.png'):
    path = tmp_path / name
    Image.fromarray(arr, 'RGB').save(path)
    return str(path)


def test_shipped_example_flag_is_found(example):
    result = analyze(example('example_lsb.png'))
    assert 'flag{lsb_steganography_example}' in result.flags()


def test_short_message_in_noisy_channel_is_found_in_blue(tmp_path):
    img = _embed(_noise(), b'flag{blue_channel_message}\x00', channels=[2])
    assert 'flag{blue_channel_message}' in analyze(_save(img, tmp_path)).flags()


def test_lsb_first_bit_order(tmp_path):
    img = _embed(_noise(seed=2), b'flag{lsb_first_order}\x00', channels=[0], bitorder='lsb')
    assert 'flag{lsb_first_order}' in analyze(_save(img, tmp_path)).flags()


def test_column_major_scan_order(tmp_path):
    img = _embed(_noise(seed=3), b'flag{column_major_scan}\x00', channels=[1], order='cols')
    assert 'flag{column_major_scan}' in analyze(_save(img, tmp_path)).flags()


def test_interleaved_rgb(tmp_path):
    img = _embed(_noise(seed=4), b'flag{interleaved_rgb_bits}\x00', channels=[0, 1, 2])
    assert 'flag{interleaved_rgb_bits}' in analyze(_save(img, tmp_path)).flags()


def test_hidden_file_in_lsb_is_reported_and_extractable(tmp_path):
    payload = build_png(8, 8)
    img     = _embed(_noise(w=200, h=100, seed=5), payload, channels=[0])
    result  = analyze(_save(img, tmp_path), extract_dir=str(tmp_path / 'out'))
    assert any(f.title == 'File hidden in LSB (PNG)' for f in result.findings)
    saved = [p for p in result.extracted if 'layer' in p]
    assert saved and open(saved[0], 'rb').read()[:len(payload)] == payload


@pytest.mark.parametrize('seed', [10, 11, 12, 13])
def test_plain_noise_image_gives_no_lsb_noise(tmp_path, seed):
    """False-positive guard: random pixels must not yield 'LSB text', flags or hidden files."""
    result = analyze(_save(_noise(seed=seed), tmp_path))
    assert result.flags() == []
    assert not any(d.title.startswith('LSB text') for d in result.decoded)
    assert not any(f.title.startswith('File hidden in LSB') for f in result.findings)

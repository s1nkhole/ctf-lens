"""
Shared low-level LSB helpers (entropy + bit-to-byte conversion).
Used by analyzers/lsb_image.py and analyzers/audio.py independently.
No AnalysisResult mutations here — pure functions only.
"""

from .config import LSB_ENTROPY_SAMPLE, LSB_SAMPLE_BITS
from .utils import shannon_entropy


def lsb_entropy(lsb_bits) -> float:
    """
    Compute entropy of an LSB bit sequence.
    Accepts numpy array or list of 0/1 values.
    Converts via bytearray — correctly handles numpy int types.
    Returns 1.0 for empty input (neutral value above threshold —
    avoids triggering a false HIGH 'LSB stego suspect').
    """
    sample = lsb_bits[:LSB_ENTROPY_SAMPLE]
    if len(sample) == 0:
        return 1.0
    # bytearray(iterable) accepts any iterable of ints including numpy int16
    return shannon_entropy(bytes(bytearray(int(b) for b in sample)))


def lsb_bits_to_bytes(lsb_bits) -> bytes:
    """
    Convert LSB bits to bytes (MSB first).
    Accepts numpy array or list of 0/1 values.
    """
    sample = lsb_bits[:LSB_SAMPLE_BITS]
    if len(sample) < 8:
        return b''
    result = bytearray()
    for i in range(0, len(sample) - 7, 8):
        byte_val = 0
        for bit_pos in range(8):
            byte_val = (byte_val << 1) | int(sample[i + bit_pos])
        result.append(byte_val)
    return bytes(result)

"""AES-ECB over the ``cryptography`` library.

The ZTE ONT factory-mode protocol uses AES-192 in ECB mode with **zero**
padding: the plaintext is padded with NUL bytes to the block size, and a full
block is appended even when the input is already aligned. Unpadding strips
every trailing NUL.

That padding is deliberately not PKCS#7, which is what ``cryptography`` and most
other libraries implement. It is what the ONT firmware expects, so it is
implemented here rather than delegated. Note the round trip is therefore lossy
for data ending in NUL -- ``unpad(encrypt(x))`` cannot recover such an ``x``.
That matches the reference implementation, and no protocol message we send ends
in a NUL.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["BLOCK_SIZE", "KEY_SIZES", "pad", "unpad", "encrypt", "decrypt"]

BLOCK_SIZE = 16
KEY_SIZES = (16, 24, 32)  # AES-128, AES-192, AES-256


def pad(data: bytes) -> bytes:
    """Zero-pad to the block size, always appending at least one block."""
    return data + b"\x00" * (BLOCK_SIZE - len(data) % BLOCK_SIZE)


def unpad(data: bytes) -> bytes:
    """Strip every trailing NUL byte."""
    return data.rstrip(b"\x00")


def _cipher(key: bytes) -> Cipher:
    if len(key) not in KEY_SIZES:
        raise ValueError(
            f"key must be 16, 24, or 32 bytes (AES-128/192/256), got {len(key)}"
        )
    # ECB needs no IV; the ONT protocol does not use one.
    return Cipher(algorithms.AES(key), modes.ECB())


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB encrypt with zero padding."""
    encryptor = _cipher(key).encryptor()
    return encryptor.update(pad(plaintext)) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-ECB decrypt.

    The input must already be unpadded to a whole number of blocks -- this
    layer does no padding removal, so a partial block is a bug rather than
    something to guess at.
    """
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError(
            f"ciphertext must be a multiple of {BLOCK_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )
    decryptor = _cipher(key).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
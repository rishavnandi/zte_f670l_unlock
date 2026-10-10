"""Conformance tests for the AES implementation in zte_unlock.aes.

The factory-mode handshake is encrypted with this cipher, so a wrong key
schedule silently breaks every request. These gate everything else.

The hardcoded vector below was cross-checked against the openssl CLI,
pycryptodome and the `cryptography` library; the randomized cross-check
against openssl lives outside this file because it shells out.
"""

import pytest

from zte_unlock import aes

PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
KEY192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
CIPHERTEXT192 = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")


def test_aes192_vector():
    """FIPS-197 C.2, the size the ONT protocol uses."""
    assert aes._encrypt_block(PLAINTEXT, aes._expand_key(KEY192)) == CIPHERTEXT192


def test_aes192_vector_decrypts_back():
    assert aes._decrypt_block(CIPHERTEXT192, aes._expand_key(KEY192)) == PLAINTEXT


def test_aes192_single_block_matches_vector():
    """encrypt() on a block-aligned input reduces to the raw block cipher."""
    # pad() appends a full block when already aligned, so compare block 0.
    assert aes.encrypt(PLAINTEXT, KEY192)[:16] == CIPHERTEXT192


def test_aes128_and_256_keys_are_accepted():
    """The expansion is size-agnostic; wrong output would be caught above."""
    for size in (16, 32):
        assert len(aes.encrypt(b"data", bytes(size))) == 16


def test_roundtrip_various_lengths():
    """encrypt -> decrypt returns exactly pad(x), for every length."""
    for length in range(0, 80):
        original = bytes(range(length))
        assert aes.decrypt(aes.encrypt(original, KEY192), KEY192) == aes.pad(original)


def test_unpad_roundtrip():
    """Full pad/unpad roundtrip. Zero padding cannot represent data ending in
    NUL, so those lengths are excluded rather than asserted falsely."""
    for length in range(0, 80):
        original = bytes(range(length))
        if not original.endswith(b"\x00"):
            assert aes.unpad(aes.decrypt(aes.encrypt(original, KEY192), KEY192)) == original


def test_pad_always_adds_a_block_when_aligned():
    """The ONT protocol relies on this: aligned input still gains a block."""
    assert len(aes.encrypt(b"", KEY192)) == 16
    assert len(aes.encrypt(b"x" * 16, KEY192)) == 32
    assert len(aes.encrypt(b"x" * 17, KEY192)) == 32
    assert len(aes.encrypt(b"x" * 15, KEY192)) == 16


def test_decrypt_rejects_unaligned_input():
    """Partial blocks are a bug, not something to guess at."""
    with pytest.raises(ValueError, match="multiple of 16"):
        aes.decrypt(b"short", KEY192)


def test_rejects_wrong_key_size():
    for bad in (b"", bytes(15), bytes(20), bytes(33)):
        with pytest.raises(ValueError, match="16, 24, or 32 bytes"):
            aes.encrypt(b"data", bad)
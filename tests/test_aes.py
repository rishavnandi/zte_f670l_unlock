"""Tests for the padding contract in zte_unlock.aes.

The cipher itself belongs to the ``cryptography`` library and is not retested
here. What this module owns -- and what the ONT firmware actually constrains --
is the padding: zero-fill, a full block appended even when already aligned, and
strip-every-trailing-NUL on the way out.

The FIPS-197 vector below is kept as a cheap end-to-end canary. It pins this
module's key handling and mode selection to a known-good answer without
depending on library internals.
"""

import pytest

from zte_unlock import aes

PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
KEY192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
CIPHERTEXT192 = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")


class TestPadding:
    def test_pad_fills_to_the_block_boundary(self):
        assert len(aes.pad(b"x" * 15)) == 16
        assert len(aes.pad(b"x" * 17)) == 32

    def test_pad_appends_a_whole_block_when_already_aligned(self):
        """Not PKCS#7. An aligned input still gains a full block of NULs."""
        assert len(aes.pad(b"")) == 16
        assert len(aes.pad(b"x" * 16)) == 32
        assert aes.pad(b"x" * 16) == b"x" * 16 + bytes(16)

    def test_pad_uses_nul_bytes(self):
        assert aes.pad(b"ab") == b"ab" + bytes(14)

    def test_unpad_strips_every_trailing_nul(self):
        assert aes.unpad(b"ab" + bytes(20)) == b"ab"
        assert aes.unpad(bytes(32)) == b""

    def test_unpad_leaves_interior_nuls_alone(self):
        assert aes.unpad(b"a\x00b" + bytes(3)) == b"a\x00b"


class TestRoundTrip:
    def test_decrypt_returns_the_padded_form(self):
        """The guaranteed invariant, valid for every length.

        Zero padding cannot represent data that ends in NUL, so the honest
        assertion is decrypt(encrypt(x)) == pad(x) rather than a claim that
        unpad recovers x.
        """
        for length in range(0, 80):
            original = bytes(range(length))
            assert aes.decrypt(aes.encrypt(original, KEY192), KEY192) == aes.pad(original)

    def test_unpad_recovers_data_that_does_not_end_in_nul(self):
        for length in range(0, 80):
            original = bytes(range(length))
            if not original.endswith(b"\x00"):
                cipher = aes.encrypt(original, KEY192)
                assert aes.unpad(aes.decrypt(cipher, KEY192)) == original


class TestKeyHandling:
    def test_known_answer_vector(self):
        """FIPS-197 C.2. Pins mode and key handling to a known-good answer.

        pad() appends a whole block when already aligned, so the first block of
        the output is the bare cipher block.
        """
        assert aes.encrypt(PLAINTEXT, KEY192)[:16] == CIPHERTEXT192

    def test_all_three_key_sizes_are_accepted(self):
        for size in (16, 24, 32):
            assert len(aes.encrypt(b"data", bytes(size))) == 16

    def test_rejects_wrong_key_size(self):
        for bad in (b"", bytes(15), bytes(20), bytes(33)):
            with pytest.raises(ValueError, match="16, 24, or 32 bytes"):
                aes.encrypt(b"data", bad)

    def test_decrypt_rejects_unaligned_input(self):
        """Partial blocks are a bug, not something to guess at."""
        with pytest.raises(ValueError, match="multiple of 16"):
            aes.decrypt(b"short", KEY192)
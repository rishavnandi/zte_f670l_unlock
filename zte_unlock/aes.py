"""Minimal AES in ECB mode, implemented from FIPS-197 with no dependencies.

The ZTE ONT factory-mode interface uses AES-192-ECB with a per-session key.
There is no AES in the Python standard library, so it is implemented here
rather than taking a dependency. AES-128 and AES-256 keys are accepted too;
the key expansion is the same for all three, only the word count differs.

Verified against `openssl enc -aes-{128,192,256}-ecb`, pycryptodome and
`cryptography` over random keys and plaintexts; see tests/test_aes.py.

Note on zero padding: the ONT expects the plaintext zero-padded to the block
size, and a full extra block is appended even when the input is already
block-aligned. Trimming strips every trailing NUL. See pad() / unpad().
"""

from __future__ import annotations

BLOCK_SIZE = 16
KEY_SIZE = 24  # what the ONT protocol uses; 16- and 32-byte keys also work

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

# Rcon[i] == x**i in GF(2**8); only the first ten are ever indexed.
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)

# Key size in words -> number of rounds (FIPS-197 section 5).
_ROUNDS = {4: 10, 6: 12, 8: 14}


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES polynomial."""
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _expand_key(key: bytes) -> list[list[int]]:
    """Expand the key into rounds+1 round keys of 16 bytes each.

    The expanded key is one flat run of 4*(rounds+1) words, and round key r is
    words 4r..4r+3 -- for every key size, including AES-192. That is what makes
    AES-192 the odd one out: with nk=6 its six key words straddle the round
    boundaries, so round key 0 is only the first four of them and rounds 1..12
    re-read the tail of the key material. It is *not* 4 words starting at nk.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"key must be 16, 24, or 32 bytes (AES-128/192/256), got {len(key)}"
        )
    nk = len(key) // 4
    rounds = _ROUNDS[nk]

    words = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [_SBOX[b] for b in temp]          # SubWord
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]          # AES-256 only
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])

    return [[b for word in words[4 * r:4 * r + 4] for b in word]
            for r in range(rounds + 1)]


def _add_round_key(state: list[int], round_key: list[int]) -> None:
    for i in range(BLOCK_SIZE):
        state[i] ^= round_key[i]


def _shift_rows(state: list[int]) -> list[int]:
    """Rotate row r left by r positions.

    The state is column-major: the byte at (row r, column c) lives at flat
    index r + 4c, so a row is strided across the block rather than contiguous.
    Rotating row r left by r means:
        new[r + 4c] = old[r + 4((c + r) % 4)]
    """
    out = [0] * BLOCK_SIZE
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = state[row + 4 * ((col + row) % 4)]
    return out


def _inv_shift_rows(state: list[int]) -> list[int]:
    """Inverse of _shift_rows: rotate row r right by r positions."""
    out = [0] * BLOCK_SIZE
    for row in range(4):
        for col in range(4):
            out[row + 4 * ((col + row) % 4)] = state[row + 4 * col]
    return out


def _mix_columns(state: list[int]) -> list[int]:
    """Multiply each column by the fixed AES polynomial matrix."""
    out = [0] * BLOCK_SIZE
    for col in range(4):
        a0, a1, a2, a3 = state[col * 4:col * 4 + 4]
        out[col * 4 + 0] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        out[col * 4 + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        out[col * 4 + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        out[col * 4 + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)
    return out


def _inv_mix_columns(state: list[int]) -> list[int]:
    """Inverse of _mix_columns."""
    out = [0] * BLOCK_SIZE
    for col in range(4):
        a0, a1, a2, a3 = state[col * 4:col * 4 + 4]
        out[col * 4 + 0] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        out[col * 4 + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        out[col * 4 + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        out[col * 4 + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    return out


def _encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = list(block)
    rounds = len(round_keys) - 1
    _add_round_key(state, round_keys[0])

    for rnd in range(1, rounds + 1):
        state = [_SBOX[b] for b in state]
        state = _shift_rows(state)

        # MixColumns is skipped in the final round.
        if rnd != rounds:
            state = _mix_columns(state)

        _add_round_key(state, round_keys[rnd])

    return bytes(state)


def _decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = list(block)
    rounds = len(round_keys) - 1
    _add_round_key(state, round_keys[rounds])

    for rnd in range(rounds - 1, -1, -1):
        state = _inv_shift_rows(state)
        state = [_INV_SBOX[b] for b in state]
        _add_round_key(state, round_keys[rnd])

        # InvMixColumns is skipped in the last round (rnd 0).
        if rnd != 0:
            state = _inv_mix_columns(state)

    return bytes(state)


def pad(data: bytes) -> bytes:
    """Zero-pad to the block size, always appending at least one byte."""
    return data + b"\x00" * (BLOCK_SIZE - len(data) % BLOCK_SIZE)


def unpad(data: bytes) -> bytes:
    """Strip every trailing NUL byte."""
    return data.rstrip(b"\x00")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB encrypt, zero-padded."""
    round_keys = _expand_key(key)
    padded = pad(plaintext)
    return b"".join(
        _encrypt_block(padded[i:i + BLOCK_SIZE], round_keys)
        for i in range(0, len(padded), BLOCK_SIZE)
    )


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-ECB decrypt. Input length must be a multiple of the block size."""
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError(
            f"ciphertext must be a multiple of {BLOCK_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )
    round_keys = _expand_key(key)
    return b"".join(
        _decrypt_block(ciphertext[i:i + BLOCK_SIZE], round_keys)
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    )


# Inverse S-box, built once at import by inverting the table above.
_INV_SBOX = bytes(
    next(i for i, s in enumerate(_SBOX) if s == b) for b in range(256)
)
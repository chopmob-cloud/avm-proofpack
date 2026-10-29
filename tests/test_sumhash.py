"""Tests for the experimental pure-stdlib Algorand Sumhash512 primitive.

Validates ``avm_proofpack.consensus.sumhash`` against authentic go-sumhash
known-answer vectors (see ``tests/sumhash_kat/README.md`` for provenance): the
computed digest must match each vendored expected digest byte-for-byte, plus
basic property checks (determinism, 64-byte output length, avalanche sanity,
fail-closed behavior).
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from avm_proofpack.consensus import sumhash as _sumhash
from avm_proofpack.consensus.sumhash import (
    BLOCK_SIZE,
    DIGEST_SIZE,
    MATRIX_SEED,
    Sumhash512,
    SumhashError,
    sumhash512,
)

_KAT_PATH = pathlib.Path(__file__).parent / "sumhash_kat" / "sumhash512_kat.json"
_KAT = json.loads(_KAT_PATH.read_text(encoding="utf-8"))


def _shake(seed: str, length: int) -> bytes:
    return hashlib.shake_256(seed.encode("utf-8")).digest(length)


# --- string testVector cases (go-sumhash sumhash512_test.go) -----------------
_STRING_VECTORS = [
    (v["input_utf8"], bytes.fromhex(v["expected_hex"]))
    for v in _KAT["string_vectors"]
]
_STRING_IDS = [f"str[{i}]" for i in range(len(_STRING_VECTORS))]


def test_kat_file_present_and_shaped():
    assert _STRING_VECTORS, "expected string KAT vectors"
    assert _KAT["shake_vectors"], "expected SHAKE-derived KAT vectors"
    for _inp, expected in _STRING_VECTORS:
        assert len(expected) == DIGEST_SIZE


@pytest.mark.parametrize("text,expected", _STRING_VECTORS, ids=_STRING_IDS)
def test_string_vectors_match(text, expected):
    data = text.encode("utf-8")
    assert sumhash512(data) == expected
    # incremental hasher agrees with the one-shot helper
    assert Sumhash512(data).digest() == expected


def test_string_vectors_streamed_byte_by_byte():
    """Feeding one byte at a time must produce the identical digest."""
    for text, expected in _STRING_VECTORS:
        data = text.encode("utf-8")
        h = Sumhash512()
        for byte in data:
            h.update(bytes([byte]))
        assert h.digest() == expected


def test_shake_vectors_match():
    """Large multi-block (unsalted) and salted cases from go-sumhash."""
    for vec in _KAT["shake_vectors"]:
        data = _shake(vec["input_shake256_seed_utf8"], vec["input_length_bytes"])
        expected = bytes.fromhex(vec["expected_hex"])
        if vec.get("salt") is None and "salt_shake256_seed_utf8" not in vec:
            assert sumhash512(data) == expected
        else:
            salt = _shake(vec["salt_shake256_seed_utf8"], vec["salt_length_bytes"])
            assert sumhash512(data, salt=salt) == expected


# --- property / contract checks ---------------------------------------------
def test_constants():
    assert DIGEST_SIZE == 64
    assert BLOCK_SIZE == 64
    assert MATRIX_SEED == b"Algorand"
    assert Sumhash512.digest_size == 64
    assert Sumhash512.block_size == 64


def test_output_is_always_64_bytes():
    for n in (0, 1, 63, 64, 65, 127, 128, 200, 1000):
        assert len(sumhash512(b"\x5a" * n)) == DIGEST_SIZE


def test_determinism():
    data = b"the same bytes hashed twice" * 40
    assert sumhash512(data) == sumhash512(data)


def test_digest_does_not_consume_state():
    h = Sumhash512(b"prefix")
    first = h.digest()
    second = h.digest()
    assert first == second
    # can keep writing after digest()
    h.update(b"more")
    assert h.digest() != first
    assert h.digest() == sumhash512(b"prefixmore")


def test_copy_is_independent():
    h = Sumhash512(b"abc")
    clone = h.copy()
    clone.update(b"def")
    assert h.digest() == sumhash512(b"abc")
    assert clone.digest() == sumhash512(b"abcdef")


def test_hexdigest_matches_digest():
    data = b"hex please"
    assert sumhash512(data).hex() == Sumhash512(data).hexdigest()


def test_block_boundary_chunking_agrees():
    """Splitting an input across arbitrary chunk sizes yields one digest."""
    data = _shake("chunking", 500)
    reference = sumhash512(data)
    for step in (1, 7, 63, 64, 65, 128, 333):
        h = Sumhash512()
        for i in range(0, len(data), step):
            h.update(data[i : i + step])
        assert h.digest() == reference


def test_avalanche_single_bit_flip():
    base = b"avalanche baseline message for sumhash512" * 3
    d0 = sumhash512(base)
    flipped = bytearray(base)
    flipped[0] ^= 0x01
    d1 = sumhash512(bytes(flipped))
    assert d0 != d1
    # a single input-bit flip should disturb roughly half the output bits
    diff_bits = sum((a ^ b).bit_count() for a, b in zip(d0, d1))
    assert 128 < diff_bits < 384  # 512-bit digest; expect ~256


def test_empty_matches_helper_and_class():
    assert sumhash512(b"") == Sumhash512().digest()


# --- fail-closed contract ----------------------------------------------------
def test_non_bytes_input_raises_typeerror():
    with pytest.raises(TypeError):
        sumhash512("not bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Sumhash512().update(123)  # type: ignore[arg-type]


def test_bad_salt_length_raises():
    with pytest.raises(SumhashError):
        sumhash512(b"x", salt=b"too short")
    with pytest.raises(SumhashError):
        Sumhash512(salt=b"\x00" * 63)


def test_salt_none_is_unsalted_default():
    data = b"salt default"
    assert sumhash512(data) == sumhash512(data, salt=None)


def test_bytearray_and_memoryview_accepted():
    data = b"bytes-like inputs"
    expected = sumhash512(data)
    assert sumhash512(bytearray(data)) == expected
    assert sumhash512(memoryview(data)) == expected


def test_sumhash_error_is_valueerror():
    assert issubclass(SumhashError, ValueError)


def test_import_is_stdlib_only():
    # sanity: module exposes the documented surface
    assert hasattr(_sumhash, "sumhash512")
    assert hasattr(_sumhash, "Sumhash512")

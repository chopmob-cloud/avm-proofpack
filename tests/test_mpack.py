"""Codec unit tests: canonical byte-exactness at every boundary."""

import pytest

from avm_proofpack import mpack


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (0x7F, b"\x7f"),
        (0x80, b"\xcc\x80"),
        (0xFF, b"\xcc\xff"),
        (0x100, b"\xcd\x01\x00"),
        (0xFFFF, b"\xcd\xff\xff"),
        (0x10000, b"\xce\x00\x01\x00\x00"),
        (0xFFFFFFFF, b"\xce\xff\xff\xff\xff"),
        (0x100000000, b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00"),
        (2**64 - 1, b"\xcf" + b"\xff" * 8),
        (-1, b"\xff"),
        (-32, b"\xe0"),
        (-33, b"\xd0\xdf"),
        (-128, b"\xd0\x80"),
        (-129, b"\xd1\xff\x7f"),
        (-(2**63), b"\xd3\x80" + b"\x00" * 7),
        (True, b"\xc3"),
        (False, b"\xc2"),
        (None, b"\xc0"),
        ("", b"\xa0"),
        ("a", b"\xa1a"),
        ("a" * 31, b"\xbf" + b"a" * 31),
        ("a" * 32, b"\xd9\x20" + b"a" * 32),
        (b"", b"\xc4\x00"),
        (b"\x00\x01", b"\xc4\x02\x00\x01"),
        ([], b"\x90"),
        ([1, "x"], b"\x92\x01\xa1x"),
        ({}, b"\x80"),
    ],
)
def test_scalar_encodings(value, encoded):
    assert mpack.encode_canonical(value) == encoded
    assert mpack.decode(encoded) == value


def test_int_out_of_uint64_range_rejected():
    with pytest.raises(mpack.EncodeError):
        mpack.encode_canonical(2**64)
    with pytest.raises(mpack.EncodeError):
        mpack.encode_canonical(-(2**63) - 1)


def test_map_keys_sorted_by_utf8_bytes():
    # Plain string sort, not encoded-bytes sort: "gh" must precede "r"
    # despite fixstr length prefixes ordering differently.
    encoded = mpack.encode_canonical({"r": 1, "gh": 2, "tc": 3, "0": 4})
    assert encoded == b"\x84\xa10\x04\xa2gh\x02\xa1r\x01\xa2tc\x03"


def test_int_map_keys_sorted_numerically():
    encoded = mpack.encode_canonical({2: "b", 0: "a", 1: "c"})
    assert encoded == b"\x83\x00\xa1a\x01\xa1c\x02\xa1b"
    assert mpack.decode(encoded) == {0: "a", 1: "c", 2: "b"}


def test_mixed_key_types_rejected():
    with pytest.raises(mpack.EncodeError):
        mpack.encode_canonical({"a": 1, 2: 3})


def test_float_rejected_on_encode():
    with pytest.raises(mpack.EncodeError):
        mpack.encode_canonical(1.0)


def test_float_rejected_on_decode():
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\xcb" + b"\x00" * 8)  # float64
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\xca" + b"\x00" * 4)  # float32


def test_ext_rejected_on_decode():
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\xd4\x01\x00")  # fixext1


def test_trailing_bytes_rejected():
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\x01\x02")


def test_truncated_input_rejected():
    for blob in (b"", b"\xc4\x05ab", b"\xcd\x01", b"\x81\xa1a"):
        with pytest.raises(mpack.DecodeError):
            mpack.decode(blob)


def test_duplicate_map_key_rejected():
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\x82\xa1a\x01\xa1a\x02")


def test_non_utf8_str_round_trips_exactly():
    # TEAL state values and logs are Go strings holding arbitrary bytes,
    # transported in the msgpack str family. The codec must reproduce the
    # exact wire bytes while keeping str distinct from bin.
    wire = b"\x81\xa2lg\x91\xa3\x9a\xff\x00"
    decoded = mpack.decode(wire)
    assert isinstance(decoded["lg"][0], str)
    assert mpack.encode_canonical(decoded) == wire


def test_str_and_bin_are_distinct_types():
    assert mpack.encode_canonical("ab") == b"\xa2ab"
    assert mpack.encode_canonical(b"ab") == b"\xc4\x02ab"
    assert mpack.decode(b"\xa2ab") == "ab"
    assert mpack.decode(b"\xc4\x02ab") == b"ab"


def test_bool_map_key_rejected_on_decode():
    with pytest.raises(mpack.DecodeError):
        mpack.decode(b"\x81\xc3\x01")


def test_deep_nesting_rejected_typed():
    # A crafted deeply nested blob must produce DecodeError, never
    # RecursionError: the decoder is a hostile-input surface.
    blob = b"\x91" * 200 + b"\x01"
    with pytest.raises(mpack.DecodeError):
        mpack.decode(blob)
    deep = 1
    for _ in range(200):
        deep = [deep]
    with pytest.raises(mpack.EncodeError):
        mpack.encode_canonical(deep)


def test_nesting_within_limit_accepted():
    blob = b"\x91" * 60 + b"\x01"
    assert mpack.encode_canonical(mpack.decode(blob)) == blob


def test_nested_round_trip():
    obj = {
        "outer": [{"k": b"\x00" * 32, "n": 2**40}, [1, -1, "s"], None, True],
        "z": {0: {"deep": b"bytes"}},
    }
    assert mpack.decode(mpack.encode_canonical(obj)) == obj

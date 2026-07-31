"""Canonical msgpack codec for Algorand-encoded objects.

Algorand encodes every consensus object with go-codec in canonical mode:
map keys are strings sorted by their UTF-8 bytes, integers use the shortest
possible representation, byte strings use the bin family, and zero-valued
fields are omitted ("omitempty") by the *encoder of the object* (this codec
does not decide omission; callers construct maps containing exactly the
fields to be encoded).

Only the msgpack subset that appears in Algorand block encodings is
supported: nil, bool, int/uint, str, bin, array, map. Float and ext types
are rejected outright, a canonical Algorand object never contains them, so
encountering one is evidence of corruption, and silently accepting it would
widen the attack surface of a verification preimage.

Correctness contract: for any object decoded from a canonically encoded
Algorand blob, ``encode_canonical(decode(blob)) == blob``. The test suite
enforces this round-trip byte equality against live mainnet blocks.
"""

from __future__ import annotations

__all__ = ["DecodeError", "EncodeError", "decode", "encode_canonical"]

_UINT64_MAX = 2**64 - 1
_INT64_MIN = -(2**63)

# Deepest container nesting accepted. Real Algorand objects nest a handful of
# levels; the cap turns a crafted deep-nesting blob into a typed DecodeError
# instead of an interpreter RecursionError.
_MAX_DEPTH = 64


class DecodeError(ValueError):
    """Raised when input is not valid canonical-subset msgpack."""


class EncodeError(ValueError):
    """Raised when an object cannot be canonically encoded."""


def decode(data: bytes) -> object:
    """Decode a single msgpack object, requiring full input consumption."""
    obj, offset = _decode_at(data, 0, 0)
    if offset != len(data):
        raise DecodeError(
            f"trailing bytes after msgpack object: consumed {offset} of {len(data)}"
        )
    return obj


def _take(data: bytes, offset: int, n: int) -> bytes:
    end = offset + n
    if end > len(data):
        raise DecodeError(f"truncated input: need {n} bytes at offset {offset}")
    return data[offset:end]


def _decode_at(data: bytes, offset: int, depth: int) -> tuple[object, int]:
    if depth > _MAX_DEPTH:
        raise DecodeError(f"nesting exceeds maximum depth {_MAX_DEPTH}")
    if offset >= len(data):
        raise DecodeError(f"truncated input at offset {offset}")
    b = data[offset]
    offset += 1

    if b <= 0x7F:  # positive fixint
        return b, offset
    if b >= 0xE0:  # negative fixint
        return b - 0x100, offset
    if 0x80 <= b <= 0x8F:  # fixmap
        return _decode_map(data, offset, b & 0x0F, depth)
    if 0x90 <= b <= 0x9F:  # fixarray
        return _decode_array(data, offset, b & 0x0F, depth)
    if 0xA0 <= b <= 0xBF:  # fixstr
        return _decode_str(data, offset, b & 0x1F)

    if b == 0xC0:
        return None, offset
    if b == 0xC2:
        return False, offset
    if b == 0xC3:
        return True, offset

    if b == 0xC4:  # bin8
        n = _take(data, offset, 1)[0]
        return bytes(_take(data, offset + 1, n)), offset + 1 + n
    if b == 0xC5:  # bin16
        n = int.from_bytes(_take(data, offset, 2), "big")
        return bytes(_take(data, offset + 2, n)), offset + 2 + n
    if b == 0xC6:  # bin32
        n = int.from_bytes(_take(data, offset, 4), "big")
        return bytes(_take(data, offset + 4, n)), offset + 4 + n

    if b == 0xCC:
        return _take(data, offset, 1)[0], offset + 1
    if b == 0xCD:
        return int.from_bytes(_take(data, offset, 2), "big"), offset + 2
    if b == 0xCE:
        return int.from_bytes(_take(data, offset, 4), "big"), offset + 4
    if b == 0xCF:
        return int.from_bytes(_take(data, offset, 8), "big"), offset + 8

    if b == 0xD0:
        return int.from_bytes(_take(data, offset, 1), "big", signed=True), offset + 1
    if b == 0xD1:
        return int.from_bytes(_take(data, offset, 2), "big", signed=True), offset + 2
    if b == 0xD2:
        return int.from_bytes(_take(data, offset, 4), "big", signed=True), offset + 4
    if b == 0xD3:
        return int.from_bytes(_take(data, offset, 8), "big", signed=True), offset + 8

    if b == 0xD9:  # str8
        n = _take(data, offset, 1)[0]
        return _decode_str(data, offset + 1, n)
    if b == 0xDA:  # str16
        n = int.from_bytes(_take(data, offset, 2), "big")
        return _decode_str(data, offset + 2, n)
    if b == 0xDB:  # str32
        n = int.from_bytes(_take(data, offset, 4), "big")
        return _decode_str(data, offset + 4, n)

    if b == 0xDC:  # array16
        n = int.from_bytes(_take(data, offset, 2), "big")
        return _decode_array(data, offset + 2, n, depth)
    if b == 0xDD:  # array32
        n = int.from_bytes(_take(data, offset, 4), "big")
        return _decode_array(data, offset + 4, n, depth)

    if b == 0xDE:  # map16
        n = int.from_bytes(_take(data, offset, 2), "big")
        return _decode_map(data, offset + 2, n, depth)
    if b == 0xDF:  # map32
        n = int.from_bytes(_take(data, offset, 4), "big")
        return _decode_map(data, offset + 4, n, depth)

    raise DecodeError(f"unsupported msgpack type byte 0x{b:02x} at offset {offset - 1}")


def _decode_str(data: bytes, offset: int, n: int) -> tuple[str, int]:
    # go-codec encodes Go strings with the msgpack str family, and Go strings
    # are arbitrary byte containers: TEAL state values ("tb"), application
    # logs ("lg"), and similar fields routinely hold non-UTF-8 bytes.
    # surrogateescape preserves those bytes losslessly so the encoder can
    # reproduce the wire bytes exactly, keeping the str/bin type distinction.
    raw = _take(data, offset, n)
    return raw.decode("utf-8", errors="surrogateescape"), offset + n


def _decode_array(data: bytes, offset: int, n: int, depth: int) -> tuple[list, int]:
    items = []
    for _ in range(n):
        item, offset = _decode_at(data, offset, depth + 1)
        items.append(item)
    return items, offset


def _decode_map(data: bytes, offset: int, n: int, depth: int) -> tuple[dict, int]:
    # Algorand maps carry str keys (struct codec tags) or int keys (e.g. the
    # block header's state proof tracking map, keyed by StateProofType).
    out: dict = {}
    for _ in range(n):
        key, offset = _decode_at(data, offset, depth + 1)
        if not isinstance(key, (str, int)) or isinstance(key, bool):
            raise DecodeError(
                f"map key must be str or int, got {type(key).__name__} "
                f"at offset {offset}"
            )
        # Keys must be uniformly str or uniformly int, matching what
        # encode_canonical accepts. Without this the decoder's output domain
        # would be wider than the encoder's input domain, and a hostile blob
        # could drive an EncodeError out of a decode-then-encode path.
        if out and isinstance(key, str) != isinstance(next(iter(out)), str):
            raise DecodeError("map keys must be uniformly str or uniformly int")
        if key in out:
            raise DecodeError(f"duplicate map key {key!r}")
        value, offset = _decode_at(data, offset, depth + 1)
        out[key] = value
    return out, offset


def encode_canonical(obj: object) -> bytes:
    """Encode ``obj`` as canonical msgpack (go-codec canonical mode)."""
    # A single growing bytearray, not a list of small bytes objects: the
    # latter costs ~98 bytes of peak allocation per encoded scalar, which
    # turns a large hostile input into a memory amplification attack.
    out = bytearray()
    _encode_into(obj, out, 0)
    return bytes(out)


def _encode_into(obj: object, parts: bytearray, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise EncodeError(f"nesting exceeds maximum depth {_MAX_DEPTH}")
    # bool must be tested before int: bool is a subclass of int in Python.
    if obj is None:
        parts.extend(b"\xc0")
    elif isinstance(obj, bool):
        parts.extend(b"\xc3" if obj else b"\xc2")
    elif isinstance(obj, int):
        _encode_int(obj, parts)
    elif isinstance(obj, bytes):
        _encode_bin(obj, parts)
    elif isinstance(obj, bytearray):
        _encode_bin(bytes(obj), parts)
    elif isinstance(obj, str):
        _encode_str(obj, parts)
    elif isinstance(obj, list):
        n = len(obj)
        if n <= 0x0F:
            parts.extend(bytes([0x90 | n]))
        elif n <= 0xFFFF:
            parts.extend(b"\xdc" + n.to_bytes(2, "big"))
        elif n <= 0xFFFFFFFF:
            parts.extend(b"\xdd" + n.to_bytes(4, "big"))
        else:
            raise EncodeError("array too long")
        for item in obj:
            _encode_into(item, parts, depth + 1)
    elif isinstance(obj, dict):
        keys = list(obj.keys())
        all_str = all(isinstance(k, str) for k in keys)
        all_int = all(
            isinstance(k, int) and not isinstance(k, bool) for k in keys
        )
        if not (all_str or all_int):
            raise EncodeError("map keys must be uniformly str or uniformly int")
        # Canonical order: str keys sort by UTF-8 bytes (go-codec sorts
        # struct codec tags as plain strings); int keys sort numerically,
        # which coincides with encoded-byte order for canonical uints.
        if all_str:
            keys.sort(key=lambda k: k.encode("utf-8", errors="surrogateescape"))
        else:
            keys.sort()
        n = len(keys)
        if n <= 0x0F:
            parts.extend(bytes([0x80 | n]))
        elif n <= 0xFFFF:
            parts.extend(b"\xde" + n.to_bytes(2, "big"))
        elif n <= 0xFFFFFFFF:
            parts.extend(b"\xdf" + n.to_bytes(4, "big"))
        else:
            raise EncodeError("map too large")
        for key in keys:
            if isinstance(key, str):
                _encode_str(key, parts)
            else:
                _encode_int(key, parts)
            _encode_into(obj[key], parts, depth + 1)
    elif isinstance(obj, float):
        raise EncodeError(
            "float is not permitted in canonical Algorand encodings"
        )
    else:
        raise EncodeError(f"cannot canonically encode {type(obj).__name__}")


def _encode_int(value: int, parts: bytearray) -> None:
    if value >= 0:
        if value <= 0x7F:
            parts.extend(bytes([value]))
        elif value <= 0xFF:
            parts.extend(b"\xcc" + bytes([value]))
        elif value <= 0xFFFF:
            parts.extend(b"\xcd" + value.to_bytes(2, "big"))
        elif value <= 0xFFFFFFFF:
            parts.extend(b"\xce" + value.to_bytes(4, "big"))
        elif value <= _UINT64_MAX:
            parts.extend(b"\xcf" + value.to_bytes(8, "big"))
        else:
            raise EncodeError(f"integer {value} exceeds uint64")
    else:
        if value >= -0x20:
            parts.extend((value + 0x100).to_bytes(1, "big"))
        elif value >= -0x80:
            parts.extend(b"\xd0" + value.to_bytes(1, "big", signed=True))
        elif value >= -0x8000:
            parts.extend(b"\xd1" + value.to_bytes(2, "big", signed=True))
        elif value >= -0x80000000:
            parts.extend(b"\xd2" + value.to_bytes(4, "big", signed=True))
        elif value >= _INT64_MIN:
            parts.extend(b"\xd3" + value.to_bytes(8, "big", signed=True))
        else:
            raise EncodeError(f"integer {value} below int64")


def _encode_bin(value: bytes, parts: bytearray) -> None:
    n = len(value)
    if n <= 0xFF:
        parts.extend(b"\xc4" + bytes([n]))
    elif n <= 0xFFFF:
        parts.extend(b"\xc5" + n.to_bytes(2, "big"))
    elif n <= 0xFFFFFFFF:
        parts.extend(b"\xc6" + n.to_bytes(4, "big"))
    else:
        raise EncodeError("bin too long")
    parts.extend(value)


def _encode_str(value: str, parts: bytearray) -> None:
    # Mirror of _decode_str: surrogateescape restores the original bytes of
    # non-UTF-8 content decoded from the wire.
    raw = value.encode("utf-8", errors="surrogateescape")
    n = len(raw)
    if n <= 0x1F:
        parts.extend(bytes([0xA0 | n]))
    elif n <= 0xFF:
        parts.extend(b"\xd9" + bytes([n]))
    elif n <= 0xFFFF:
        parts.extend(b"\xda" + n.to_bytes(2, "big"))
    elif n <= 0xFFFFFFFF:
        parts.extend(b"\xdb" + n.to_bytes(4, "big"))
    else:
        raise EncodeError("str too long")
    parts.extend(raw)

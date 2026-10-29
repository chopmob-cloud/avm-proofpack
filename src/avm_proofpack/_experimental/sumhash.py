"""Experimental, pure-stdlib Algorand Sumhash512 hash primitive.

This module is an EXPERIMENTAL foundation layer, a sibling to
:mod:`avm_proofpack._experimental.falcon` and
:mod:`avm_proofpack._experimental.stateproof`. It is **not wired into**
``verify_bundle`` and changes no existing behavior. Importing it has no side
effects (the ~64 KiB matrix and its lookup table are built lazily, on the first
hash, then cached).

Why this exists
---------------
The next trust tier (removing node trust from a state proof) must verify the
state proof's Merkle-tree membership of each revealed ephemeral key under the
participant key commitment. Algorand state-proof trees use **Sumhash512**, not
SHA-256: a reveal's ``prf.hsh`` type is ``1`` (= Sumhash) with 64-byte nodes
(see :mod:`avm_proofpack._experimental.stateproof`). The repo's ``merkle.py``
is SHA-256 / 32-byte and cannot verify those trees. This module supplies the
raw Sumhash512 primitive (message bytes -> 64-byte digest) that the deferred
membership check (step A2) will build on. It is KAT-validated against
go-sumhash's own test vectors (see below).

What this module IS (and is NOT)
--------------------------------
It IS the *raw* Sumhash512 primitive, byte-for-byte identical to
``github.com/algorand/go-sumhash`` ``New512``/``Sum512``. It is NOT the
domain-separated Merkle leaf/node hashing (Algorand's ``HashRep`` /
``crypto/merklearray`` prepends a HashID such as the ``"KP"`` ephemeral-key
leaf domain and encodes node structure); that wrapping belongs to the
membership step (A2) and is deliberately out of scope here. Verifying a hash
alone removes no node trust.

The exact construction (confirmed against go-sumhash source)
-----------------------------------------------------------
Subset-sum compression over a fixed matrix ``A``, in a Merkle-Damgard wrapper.

* **Matrix** ``A`` -- ``n = 8`` rows by ``m = 1024`` columns of ``uint64``,
  expanded from the ASCII seed ``b"Algorand"`` via SHAKE256
  (``compress.go`` ``RandomMatrixFromSeed`` + ``sumhash512.go``
  ``RandomMatrixFromSeed([]byte("Algorand"), 8, 1024)``). The XOF absorbs, all
  little-endian: ``uint16(64) || uint16(n=8) || uint16(m=1024) || b"Algorand"``,
  then is squeezed for ``n*m`` 8-byte little-endian ``uint64`` words in
  row-major order (row ``i`` outer, column ``j`` inner).
* **Compression** ``A.Compress`` (``compress.go``): input ``msg`` is
  ``InputLen = m/8 = 128`` bytes; output ``dst`` is ``OutputLen = n*8 = 64``
  bytes. For each row ``i``, ``dst[8i:8i+8] = LE(sum over set input bits j of
  A[i][j]) mod 2^64``. Bit ``k`` of input byte ``msg[b]`` selects column
  ``8*b + k`` (little-endian bit order within each byte).
* **Merkle-Damgard** (``sumhash.go``): block size ``B = InputLen - OutputLen =
  64`` bytes; IV = 64 zero bytes; the per-block compression input is
  ``chain(64 bytes) || (block XOR salt)(64 bytes)``. Finalization
  (``checkSum``): append ``0x01`` then zero bytes to reach ``P = B - 16 = 48``
  bytes mod ``B``, then a 128-bit little-endian bit-length (low 64 bits =
  ``len*8``, high 64 bits = 0). Digest size 64 bytes.
* **Salt**: ``New512(nil)`` is unsalted -- this is the mode Algorand uses
  (``go-algorand`` ``crypto.Sumhash512`` / ``HashFactory{HashType: Sumhash}``).
  Optional 64-byte salt is supported for construction parity (``Reset``
  prepends a zero block, and each block is XORed with the salt).

Correctness validation
----------------------
Validated in ``tests/test_sumhash.py`` against the known-answer vectors vendored
in ``tests/sumhash_kat/`` (see its ``README`` for provenance). Those vectors
are copied byte-for-byte from go-sumhash's own ``sumhash512_test.go``
``testVector`` table and streaming-input tests: the empty string, single-block
strings, a multi-block quotation, and a 6000-byte (~94-block) SHAKE256-derived
input, plus the salted 6000-byte case. This implementation reproduces every
expected digest exactly.

Fail-closed contract
--------------------
Non-bytes input raises :class:`TypeError`. A wrong-length salt, an input long
enough to overflow the length counter, or any internal state inconsistency
raises :class:`SumhashError`. There is no code path that returns a
wrong-length or partially-computed digest.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = [
    "BLOCK_SIZE",
    "DIGEST_SIZE",
    "MATRIX_COLS",
    "MATRIX_ROWS",
    "MATRIX_SEED",
    "Sumhash512",
    "SumhashError",
    "sumhash512",
]

# --- Sumhash512 parameters (see module docstring for go-sumhash sources) -----
DIGEST_SIZE = 64  # go-sumhash Sumhash512DigestSize; == OutputLen (n*8)
BLOCK_SIZE = 64  # go-sumhash Sumhash512DigestBlockSize; == InputLen - OutputLen
MATRIX_SEED = b"Algorand"  # sumhash512.go RandomMatrixFromSeed seed
MATRIX_ROWS = 8  # n
MATRIX_COLS = 1024  # m

_OUTPUT_LEN = MATRIX_ROWS * 8  # 64 bytes of uint64 words
_INPUT_LEN = MATRIX_COLS // 8  # 128 bytes = chain(64) || block(64)
_MASK64 = (1 << 64) - 1
_LENGTH_FIELD = 16  # 128-bit little-endian bit-length appended at finalization
_PAD_TARGET = BLOCK_SIZE - _LENGTH_FIELD  # P = 48
# go-sumhash Write() overflow guard: refuses at (1<<61) total bytes.
_MAX_INPUT_BYTES = 1 << 61

assert _INPUT_LEN == _OUTPUT_LEN + BLOCK_SIZE  # matrix shape sanity


class SumhashError(ValueError):
    """Raised when a Sumhash512 input or internal state is malformed.

    Subclasses :class:`ValueError`, so existing ``except ValueError`` handlers
    still catch it. A malformed input is always a rejection, never a silently
    wrong digest.
    """


def _require_bytes(name: str, value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like, got {type(value).__name__}")
    return bytes(value)


# --- Matrix / lookup-table expansion (lazy, cached) --------------------------
# ``_LOOKUP[i][b]`` is a 256-entry table: for row ``i`` and input-byte position
# ``b`` (0..127), entry ``v`` is the subset sum (mod 2^64) of the eight matrix
# columns ``A[i][8b .. 8b+7]`` selected by the set bits of ``v``. This is the
# ``LookupTable`` optimization from go-sumhash's ``compress.go``; it produces a
# digest identical to the naive per-bit ``Matrix.Compress``.
_LOOKUP: list[list[list[int]]] | None = None


def _expand_matrix() -> list[list[int]]:
    """Expand the fixed Sumhash512 matrix ``A`` (8 x 1024 uint64) from the seed.

    Mirrors go-sumhash ``RandomMatrixFromSeed(b"Algorand", 8, 1024)``: absorb
    ``LE16(64) || LE16(8) || LE16(1024) || b"Algorand"`` into SHAKE256, then
    squeeze ``8*1024`` little-endian ``uint64`` words in row-major order.
    """
    xof = hashlib.shake_256()
    xof.update(
        struct.pack("<H", 64)
        + struct.pack("<H", MATRIX_ROWS)
        + struct.pack("<H", MATRIX_COLS)
        + MATRIX_SEED
    )
    word_count = MATRIX_ROWS * MATRIX_COLS
    raw = xof.digest(word_count * 8)
    if len(raw) != word_count * 8:
        raise SumhashError("matrix expansion produced a short SHAKE256 stream")
    words = struct.unpack(f"<{word_count}Q", raw)
    return [
        list(words[i * MATRIX_COLS : (i + 1) * MATRIX_COLS])
        for i in range(MATRIX_ROWS)
    ]


def _build_lookup() -> list[list[list[int]]]:
    matrix = _expand_matrix()
    lookup: list[list[list[int]]] = []
    for row in matrix:
        row_tables: list[list[int]] = []
        for b in range(_INPUT_LEN):
            cols = row[8 * b : 8 * b + 8]
            table = [0] * 256
            for value in range(1, 256):
                # value with its lowest set bit cleared: reuse its precomputed
                # sum and add just the column for that bit (fast, exact).
                low = value & -value
                bit = low.bit_length() - 1
                table[value] = (table[value ^ low] + cols[bit]) & _MASK64
            row_tables.append(table)
        lookup.append(row_tables)
    return lookup


def _lookup() -> list[list[list[int]]]:
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = _build_lookup()
    return _LOOKUP


def _compress(chain: bytes, block: bytes) -> bytearray:
    """Compress ``chain(64) || block(64)`` -> new 64-byte chaining value.

    ``block`` is already salt-processed by the caller. Fail-closed on any
    size deviation (would indicate corrupted internal state).
    """
    if len(chain) != _OUTPUT_LEN or len(block) != BLOCK_SIZE:
        raise SumhashError("internal: compression input has wrong size")
    msg = chain + block  # _INPUT_LEN (128) bytes
    lookup = _lookup()
    out = bytearray(_OUTPUT_LEN)
    for i in range(MATRIX_ROWS):
        tables = lookup[i]
        x = 0
        for b in range(_INPUT_LEN):
            x += tables[b][msg[b]]
        struct.pack_into("<Q", out, 8 * i, x & _MASK64)
    return out


class Sumhash512:
    """Incremental Algorand Sumhash512 hasher (pure stdlib).

    Mirrors ``hashlib``-style hashers: :meth:`update` absorbs bytes,
    :meth:`digest`/:meth:`hexdigest` produce the 64-byte result without
    consuming the object (state is snapshotted, matching go-sumhash's
    ``Sum``). :attr:`digest_size` and :attr:`block_size` are both 64.

    ``salt`` is optional; when ``None`` (the default, and the mode Algorand
    uses) the hash is unsalted. A non-``None`` salt must be exactly
    :data:`BLOCK_SIZE` (64) bytes, or :class:`SumhashError` is raised.
    """

    digest_size = DIGEST_SIZE
    block_size = BLOCK_SIZE

    __slots__ = ("_buffer", "_chain", "_length", "_salt")

    def __init__(self, data: bytes = b"", *, salt: bytes | None = None) -> None:
        if salt is not None:
            salt = _require_bytes("salt", salt)
            if len(salt) != BLOCK_SIZE:
                raise SumhashError(
                    f"salt must be {BLOCK_SIZE} bytes, got {len(salt)}"
                )
        self._salt = salt
        self._chain = bytearray(_OUTPUT_LEN)  # all-zeros IV
        self._buffer = bytearray()
        self._length = 0  # total input bytes absorbed (incl. salt block)
        if salt is not None:
            # go-sumhash Reset(): a leading zero block prepends the salt.
            self.update(bytes(BLOCK_SIZE))
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        """Absorb ``data``. Raises :class:`TypeError` for non-bytes input."""
        data = _require_bytes("data", data)
        if not data:
            return
        if len(data) >= _MAX_INPUT_BYTES - self._length:
            raise SumhashError("input length overflows the Sumhash512 counter")
        self._length += len(data)
        buffer = self._buffer
        buffer += data
        full = len(buffer) - (len(buffer) % BLOCK_SIZE)
        if full:
            self._absorb_blocks(buffer[:full])
            del buffer[:full]

    def _absorb_blocks(self, data: bytes) -> None:
        salt = self._salt
        chain = self._chain
        for off in range(0, len(data), BLOCK_SIZE):
            block = data[off : off + BLOCK_SIZE]
            if salt is not None:
                block = bytes(a ^ b for a, b in zip(block, salt))
            chain = _compress(chain, block)
        self._chain = chain

    def copy(self) -> Sumhash512:
        """Return an independent snapshot of this hasher's state."""
        clone = Sumhash512.__new__(Sumhash512)
        clone._salt = self._salt
        clone._chain = bytearray(self._chain)
        clone._buffer = bytearray(self._buffer)
        clone._length = self._length
        return clone

    def digest(self) -> bytes:
        """Return the 64-byte digest without consuming this hasher."""
        clone = self.copy()
        clone._finalize()
        if len(clone._chain) != DIGEST_SIZE:
            raise SumhashError("internal: digest is not 64 bytes")
        return bytes(clone._chain)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def _finalize(self) -> None:
        length = self._length
        bit_length = length << 3
        remainder = length % BLOCK_SIZE
        if remainder < _PAD_TARGET:
            pad_len = _PAD_TARGET - remainder
        else:
            pad_len = BLOCK_SIZE + _PAD_TARGET - remainder
        # 0x01 marker then zero bytes (bits are read little-endian).
        self.update(b"\x01" + b"\x00" * (pad_len - 1))
        # 128-bit little-endian bit length: low 64 bits then a zero high word.
        self.update(struct.pack("<Q", bit_length) + b"\x00" * 8)
        if self._buffer:
            raise SumhashError("internal: buffer not drained after finalization")


def sumhash512(data: bytes, *, salt: bytes | None = None) -> bytes:
    """Compute the Algorand Sumhash512 digest of ``data`` (returns 64 bytes).

    One-shot convenience over :class:`Sumhash512`. ``salt`` defaults to
    ``None`` (unsalted, the mode Algorand uses); a non-``None`` salt must be
    64 bytes. Raises :class:`TypeError` for non-bytes input and
    :class:`SumhashError` for a malformed salt or an over-length input.
    """
    return Sumhash512(data, salt=salt).digest()

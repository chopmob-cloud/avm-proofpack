"""Experimental, verify-only Falcon-1024 signature primitive (pure stdlib).

This module is an EXPERIMENTAL foundation layer. It is **not yet wired into**
``verify_bundle`` and it changes no existing behavior. Importing it has no
side effects. It exists so that a future tier can begin to remove node trust
by verifying the Falcon-1024 signatures inside Algorand/Voi state proofs.

What this module IS
-------------------
A correct, KAT-validated, fail-closed Falcon-1024 signature *verifier*, using
only the Python standard library at runtime (``hashlib`` provides SHAKE256;
no numpy, no third-party crypto). It verifies the "compressed" signature
format, which is the format go-algorand emits and consumes via its cgo Falcon
binding (``github.com/algorand/falcon``). Two header variants are accepted:

* ``0x3a`` -- standard salted Falcon-1024 compressed signature
  (``header || salt[40] || comp(s2)``), i.e. header byte ``0x30 | logn`` with
  ``logn = 10``.
* ``0xba`` -- deterministic "det1024" compressed signature
  (``header || salt_version || comp(s2)``), i.e. ``0x3a | 0x80``. The 40-byte
  salt is reconstructed from the one-byte salt version exactly as
  go-algorand's ``falcon_det1024`` does. This is the variant used by Algorand
  state proofs / go-algorand's ``crypto/falcon``.

What this module is NOT
-----------------------
* It is NOT keygen or signing (no NTRU sampler, no FFT lattice work).
* It does NOT decode the CT ("constant-time", header ``0x5a`` / ``0xda``)
  signature format; those are rejected.
* It is NOT, by itself, a state-proof verifier. Verifying a Falcon signature
  proves only "this message was signed by the holder of this Falcon key". It
  does NOT verify the state proof's reveals, Merkle-tree membership, signed
  weight thresholds, or the voters-commitment anchoring to a trusted round.
  Those are deliberately out of scope here and remain future work. Using this
  primitive alone does NOT remove node trust.

Parameters (Falcon-1024), and their sources
--------------------------------------------
* ``n = 1024``, ``q = 12289`` -- Falcon spec (falcon-sign.info), and
  go-algorand C reference ``common.py`` (``q = 12*1024 + 1``).
* Acceptance bound on the squared l2-norm ``||(s1, s2)||^2``:
  ``BETA_SQ = 70265242``. This is ``l2bound[logn=10]`` in the Falcon C
  reference ``common.c`` and ``sig_bound`` for n=1024 in the reference Python
  implementation (tprest/falcon.py). NOTE: ``34034726`` is the *Falcon-512*
  bound (``l2bound[9]``), not Falcon-1024.
* HashToPoint: SHAKE256 over ``salt || message``, read 2 bytes big-endian per
  candidate, accept if ``< 61445`` (= ``5 * q``) and reduce mod ``q``, until
  ``n`` coefficients are collected. This matches ``hash_to_point_vartime`` in
  the C reference, which is the function ``falcon_verify`` uses for the
  compressed format; it is output-identical to the constant-time
  ``hash_to_point_ct`` used by the det1024 signer.
* Public key: 1-byte header ``0x00 | logn`` (= ``0x0a``) followed by ``h``
  encoded as 1024 big-endian 14-bit coefficients (``modq_decode``).
* Signature ``s2``: Golomb-style compressed encoding (``comp_decode``): per
  coefficient, 1 sign bit, 7 low bits, then a unary-coded high part.

Correctness validation
-----------------------
Validated against known-answer tests in ``tests/falcon_kat/`` whose
(public key, message, signature) triples were produced by compiling the exact
go-algorand Falcon C reference and were asserted byte-identical to the
official ``FALCON_DET1024_KAT`` vectors vendored in that reference's test
suite. See ``tests/falcon_kat/README.md`` for full provenance. The test suite
proves valid triples ACCEPT and that tampered signatures, wrong messages, and
wrong keys REJECT.

Fail-closed contract
--------------------
``falcon1024_verify`` returns ``True`` only for a fully valid signature. It
raises :class:`FalconError` for structurally malformed input (wrong lengths,
unknown header byte, out-of-range coefficients, invalid encodings, trailing
bytes) and returns ``False`` for a well-formed signature that does not verify
(norm bound exceeded / hash-to-point mismatch). It never returns ``True`` on
doubt. :func:`falcon1024_accepts` is a convenience wrapper that treats every
rejection (raise or ``False``) uniformly as ``False``.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "FalconError",
    "N",
    "Q",
    "BETA_SQ",
    "PUBLIC_KEY_SIZE",
    "SALT_LEN",
    "HEADER_STANDARD_COMPRESSED",
    "HEADER_DET_COMPRESSED",
    "falcon1024_verify",
    "falcon1024_accepts",
]

# --- Falcon-1024 parameters (see module docstring for sources) --------------
LOGN = 10
N = 1 << LOGN  # 1024
Q = 12289  # 12 * 1024 + 1
BETA_SQ = 70265242  # l2bound[10]; squared-norm acceptance bound (inclusive)

_MODQ_PAYLOAD_LEN = (N * 14 + 7) >> 3  # 1792 bytes of 14-bit coefficients
PUBLIC_KEY_SIZE = 1 + _MODQ_PAYLOAD_LEN  # 1793
PUBKEY_HEADER = 0x00 | LOGN  # 0x0a

SALT_LEN = 40
HEADER_STANDARD_COMPRESSED = 0x30 | LOGN  # 0x3a
HEADER_DET_COMPRESSED = HEADER_STANDARD_COMPRESSED | 0x80  # 0xba

_HASH_REJECT = 5 * Q  # 61445
_MAX_ABS_S2 = 2047  # comp_decode coefficient range is -2047..+2047

# Deterministic-mode fixed salt "rest" bytes: C array
# `falcon_det1024_salt_rest[38] = {"FALCON_DET"}` -> "FALCON_DET" + 28 NULs.
_DET_SALT_REST = b"FALCON_DET" + b"\x00" * 28
assert len(_DET_SALT_REST) == 38


class FalconError(ValueError):
    """Raised when a Falcon-1024 input is structurally malformed.

    A malformed public key or signature is a rejection, never an acceptance.
    (Subclasses ``ValueError`` so existing ``except ValueError`` handlers in
    callers still catch it.)
    """


def _det_salt(salt_version: int) -> bytes:
    """Reconstruct the 40-byte det1024 salt for a given salt version.

    Mirrors ``falcon_det1024_write_salt``: ``[version, logn] + rest[38]``.
    """
    return bytes((salt_version & 0xFF, LOGN)) + _DET_SALT_REST


def _decode_pubkey(public_key: bytes) -> list[int]:
    """Decode a Falcon-1024 public key to its 1024 h-coefficients in [0, q).

    Faithful to the C reference ``modq_decode`` (14-bit big-endian bitstream):
    every coefficient must be < q, and the unused bits of the final byte must
    be zero. Raises :class:`FalconError` on any deviation.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise FalconError(
            f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    if public_key[0] != PUBKEY_HEADER:
        raise FalconError(
            f"public key header must be {PUBKEY_HEADER:#04x}, got {public_key[0]:#04x}"
        )
    buf = public_key[1:]
    h = [0] * N
    acc = 0
    acc_len = 0
    u = 0
    pos = 0
    while u < N:
        acc = (acc << 8) | buf[pos]
        pos += 1
        acc_len += 8
        if acc_len >= 14:
            acc_len -= 14
            w = (acc >> acc_len) & 0x3FFF
            if w >= Q:
                raise FalconError("public key coefficient out of range (>= q)")
            h[u] = w
            u += 1
    if acc & ((1 << acc_len) - 1):
        raise FalconError("public key has non-zero trailing bits")
    if pos != _MODQ_PAYLOAD_LEN:
        raise FalconError("public key payload length mismatch")
    return h


def _comp_decode(buf: bytes) -> list[int]:
    """Decode a compressed s2 polynomial (1024 signed coefficients).

    Faithful to the C reference ``comp_decode``: 1 sign bit + 7 low bits + a
    unary-coded high part per coefficient; rejects "negative zero", any
    absolute value > 2047, truncation, and non-zero trailing bits. Requires
    the encoding to consume ``buf`` exactly (the exact-consumption check that
    ``falcon_verify`` applies to compressed signatures). Raises
    :class:`FalconError` on any deviation.
    """
    n_in = len(buf)
    x = [0] * N
    acc = 0
    acc_len = 0
    v = 0
    for u in range(N):
        if v >= n_in:
            raise FalconError("compressed signature truncated")
        acc = (acc << 8) | buf[v]
        v += 1
        b = acc >> acc_len
        s = b & 128
        m = b & 127
        while True:
            if acc_len == 0:
                if v >= n_in:
                    raise FalconError("compressed signature truncated (unary)")
                acc = (acc << 8) | buf[v]
                v += 1
                acc_len = 8
            acc_len -= 1
            if (acc >> acc_len) & 1:
                break
            m += 128
            if m > _MAX_ABS_S2:
                raise FalconError("compressed signature coefficient out of range")
        if s and m == 0:
            raise FalconError("compressed signature encodes negative zero")
        x[u] = -m if s else m
    if acc & ((1 << acc_len) - 1):
        raise FalconError("compressed signature has non-zero trailing bits")
    if v != n_in:
        raise FalconError("compressed signature has trailing bytes")
    return x


def _hash_to_point(salt: bytes, message: bytes) -> list[int]:
    """HashToPoint: SHAKE256(salt || message) -> 1024 coefficients in [0, q).

    2 bytes big-endian per candidate, reject if >= 5*q, else reduce mod q.
    Output-identical to the C reference ``hash_to_point_vartime`` that
    ``falcon_verify`` uses for compressed signatures.
    """
    xof = hashlib.shake_256(salt + message)
    # Oversample generously; the acceptance probability per 2-byte draw is
    # ~0.9376, so 3*N draws (6*N bytes) overshoots N with overwhelming margin.
    length = 6 * N
    while True:
        stream = xof.digest(length)
        out: list[int] = []
        i = 0
        limit = len(stream) - 1
        while i < limit and len(out) < N:
            w = (stream[i] << 8) | stream[i + 1]
            i += 2
            if w < _HASH_REJECT:
                out.append(w % Q)
        if len(out) == N:
            return out
        length *= 2  # pragma: no cover - astronomically unlikely


def _mul_negacyclic_modq(a: list[int], b: list[int]) -> list[int]:
    """Multiply two degree-<n polynomials in Z_q[x] / (x^n + 1).

    Both inputs must have coefficients in [0, q). Uses exact big-integer
    (Kronecker-substitution) convolution with 64-bit slots -- every full
    convolution coefficient is < n*(q-1)^2 < 2^38, so slots never overlap --
    then folds x^n = -1. Result coefficients are in [0, q).
    """
    slot = 8  # bytes (64 bits) per coefficient slot
    ba = bytearray(N * slot)
    bb = bytearray(N * slot)
    for i in range(N):
        ba[i * slot : i * slot + slot] = a[i].to_bytes(slot, "little")
        bb[i * slot : i * slot + slot] = b[i].to_bytes(slot, "little")
    prod = int.from_bytes(ba, "little") * int.from_bytes(bb, "little")
    pb = prod.to_bytes(2 * N * slot, "little")
    out = [0] * N
    for i in range(N):
        lo = int.from_bytes(pb[i * slot : (i + 1) * slot], "little")
        hi = int.from_bytes(pb[(i + N) * slot : (i + N + 1) * slot], "little")
        out[i] = (lo - hi) % Q
    return out


def _split_signature(signature: bytes) -> tuple[bytes, bytes]:
    """Return (salt, compressed_s2) for a compressed Falcon-1024 signature.

    Dispatches on the header byte: ``0xba`` (det1024) reconstructs the salt
    from a one-byte salt version; ``0x3a`` (standard) reads the embedded
    40-byte salt. Raises :class:`FalconError` on any other header or on a
    signature too short to hold the required fields.
    """
    if len(signature) < 2:
        raise FalconError("signature too short")
    header = signature[0]
    if header == HEADER_DET_COMPRESSED:
        salt = _det_salt(signature[1])
        enc_s2 = signature[2:]
    elif header == HEADER_STANDARD_COMPRESSED:
        if len(signature) < 1 + SALT_LEN:
            raise FalconError("standard signature too short for salt")
        salt = signature[1 : 1 + SALT_LEN]
        enc_s2 = signature[1 + SALT_LEN :]
    else:
        raise FalconError(
            f"unsupported signature header {header:#04x} "
            f"(want {HEADER_STANDARD_COMPRESSED:#04x} or "
            f"{HEADER_DET_COMPRESSED:#04x}; CT format is not supported)"
        )
    if not enc_s2:
        raise FalconError("signature has no compressed payload")
    return salt, enc_s2


def _require_bytes(name: str, val: object) -> bytes:
    if not isinstance(val, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like, got {type(val).__name__}")
    return bytes(val)


def _signature_squared_norm(
    public_key: bytes, message: bytes, signature: bytes
) -> int:
    """Recover ``(s1, s2)`` and return the squared l2-norm ``||(s1, s2)||^2``.

    This is the quantity Falcon compares against :data:`BETA_SQ`. It decodes
    the public key and signature, reconstructs ``s1 = c - s2*h`` (centered),
    and sums the squares of both halves. Raises :class:`FalconError` on any
    structural malformation. Kept private; used by :func:`falcon1024_verify`
    and by the test suite's boundary checks.
    """
    h = _decode_pubkey(public_key)
    salt, enc_s2 = _split_signature(signature)
    s2 = _comp_decode(enc_s2)
    c = _hash_to_point(salt, message)

    # s1 = c - s2 * h  (mod x^n + 1, mod q), then centered into (-q/2, q/2].
    s2_modq = [coef % Q for coef in s2]
    s2h = _mul_negacyclic_modq(h, s2_modq)
    half = Q >> 1
    sqnorm = 0
    for i in range(N):
        s1 = (c[i] - s2h[i]) % Q
        if s1 > half:
            s1 -= Q
        sqnorm += s1 * s1 + s2[i] * s2[i]
    return sqnorm


def falcon1024_verify(
    public_key: bytes, message: bytes, signature: bytes
) -> bool:
    """Verify a compressed Falcon-1024 signature. Fail-closed.

    Returns ``True`` iff ``signature`` is a structurally valid compressed
    Falcon-1024 signature of ``message`` under ``public_key`` and its squared
    l2-norm is within :data:`BETA_SQ`.

    Raises :class:`FalconError` for structurally malformed input (wrong
    length, unknown header, out-of-range coefficient, bad encoding, trailing
    bytes). Returns ``False`` for a well-formed signature that does not verify
    (norm bound exceeded or hash-to-point mismatch). Never returns ``True`` on
    doubt. Raises :class:`TypeError` if an argument is not bytes-like.
    """
    public_key = _require_bytes("public_key", public_key)
    message = _require_bytes("message", message)
    signature = _require_bytes("signature", signature)
    return _signature_squared_norm(public_key, message, signature) <= BETA_SQ


def falcon1024_accepts(
    public_key: bytes, message: bytes, signature: bytes
) -> bool:
    """Like :func:`falcon1024_verify`, but treats every rejection as ``False``.

    Structural malformation (which :func:`falcon1024_verify` reports by
    raising :class:`FalconError`) is folded into a plain ``False``. Wrong
    argument types still raise :class:`TypeError`. Useful when the caller only
    cares whether a signature is valid and not *why* it failed.
    """
    try:
        return falcon1024_verify(public_key, message, signature)
    except FalconError:
        return False

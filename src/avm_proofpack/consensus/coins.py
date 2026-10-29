"""State Proof coin selection (A4); not a trust root on its own.

Wire rules follow go-algorand 853f03d6e85a1af1b0d93113df2a94371fb56213,
crypto/stateproof/{coinGenerator,verifier,const}.go and protocol/hash.go.
Independent Python implementation; no upstream code is incorporated.
The signing participants commitment and logarithmic proven weight are verifier
inputs, NOT automatically the message's next-interval fields: the caller must
supply the trusted values (``TrustedVoters`` / a ``ChainAnchor``). As of 0.4.x
this module is shipped and ``verify_bundle`` calls it, together with the
membership and weight checks, to reach the stake-attested tier.
"""
from __future__ import annotations

import hashlib
import struct

MAX_REVEALS = 640
_UINT64_MAX = (1 << 64) - 1


class CoinSelectionError(ValueError):
    """Malformed or resource-exhausting coin-selection input."""


def _uint64(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= _UINT64_MAX:
        raise CoinSelectionError(f"{name} must be a {'positive ' if positive else ''}uint64")
    return value


def _bytes(name: str, value: object, size: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CoinSelectionError(f"{name} must be bytes-like")
    if len(value) != size:
        raise CoinSelectionError(f"{name} must be {size} bytes")
    raw = bytes(value)
    if len(raw) != size:
        raise CoinSelectionError(f"{name} must be {size} bytes")
    return raw


def coin_seed(*, participants_commitment: bytes, ln_proven_weight: int,
              signature_commitment: bytes, signed_weight: int,
              message_hash: bytes) -> bytes:
    """Version-0, 180-byte Fiat-Shamir preimage including the spc domain.

    The single 0x00 after the "spc" tag is CONSENSUS-CRITICAL: upstream hashes
    protocol.StateProofCoin("spc") followed by the coin-choice seed bytes, whose
    first field is the version byte (VersionForCoinGenerator == 0,
    coinGenerator.go:32,76). It is NOT a stray pad byte. "Correcting" the tag to
    a 4-byte "spc\\x00" literal with a different value, or dropping the version
    byte, silently forks the coin stream and would accept/reject different
    positions than the chain does. The 180-byte total is confirmed by the real
    mainnet fixtures in tests/coin_kat/.
    """

    part = _bytes("participants_commitment", participants_commitment, 64)
    sig = _bytes("signature_commitment", signature_commitment, 64)
    msg = _bytes("message_hash", message_hash, 32)
    ln = _uint64("ln_proven_weight", ln_proven_weight)
    weight = _uint64("signed_weight", signed_weight, positive=True)
    return b"spc\x00" + part + struct.pack("<Q", ln) + sig + struct.pack("<Q", weight) + msg


def generate_coins(*, participants_commitment: bytes, ln_proven_weight: int,
                   signature_commitment: bytes, signed_weight: int,
                   message_hash: bytes, count: int) -> tuple[int, ...]:
    """Generate bounded coins in [0, signed_weight) with unbiased rejection.

    hashlib SHAKE digest(n) returns a PREFIX, not the next n bytes. Cache a
    growing prefix and advance an explicit offset so rejection consumes bytes.
    At most 40960 draws are allowed. Exhaustion rejects rather than returning
    a partial result; this local resource policy is stricter than upstream.
    The draw budget is belt-and-braces, not reachable policy: the worst case
    measured for 640 coins at weight 2^63+1 is ~1292 draws, roughly 31x headroom.
    """
    seed = coin_seed(participants_commitment=participants_commitment,
                     ln_proven_weight=ln_proven_weight,
                     signature_commitment=signature_commitment,
                     signed_weight=signed_weight, message_hash=message_hash)
    if type(count) is not int or not 0 <= count <= MAX_REVEALS:
        raise CoinSelectionError(f"count must be in [0, {MAX_REVEALS}]")
    threshold = (1 << 64) // signed_weight * signed_weight
    xof = hashlib.shake_256(seed)
    limit = MAX_REVEALS * 64 * 8
    stream = b""
    offset = 0
    result: list[int] = []
    while len(result) < count:
        if offset == len(stream):
            if offset == limit:
                raise CoinSelectionError("rejection sampling draw budget exhausted")
            stream = xof.digest(min(limit, max(512, len(stream) * 2)))
        value = struct.unpack_from("<Q", stream, offset)[0]
        offset += 8
        if value < threshold:
            result.append(value % signed_weight)
    return tuple(result)


def coin_selection_result(state_proof: object, *, participants_commitment: bytes,
                          ln_proven_weight: int, signature_commitment: bytes,
                          message_hash: bytes) -> bool:
    """Verify selected positions, coin ranges, reveal coverage and bounds. Fail-closed."""
    try:
        if not isinstance(state_proof, dict):
            return False
        positions = state_proof.get("pr")
        reveals = state_proof.get("r")
        if type(positions) is not list or not isinstance(reveals, dict):
            return False
        # Selected positions MAY repeat: len(pr) legitimately exceeds len(r),
        # because a participant's weight can be hit by several coins. Only the
        # coverage direction (every reveal is selected) is an invariant.
        if not 0 < len(positions) <= MAX_REVEALS:
            return False
        parsed = []
        for position in positions:
            if type(position) is not int or not 0 <= position <= _UINT64_MAX:
                return False
            reveal = reveals.get(position)
            if not isinstance(reveal, dict):
                return False
            slot, part = reveal.get("s"), reveal.get("p")
            if not isinstance(slot, dict) or not isinstance(part, dict):
                return False
            running, weight = slot.get("l", 0), part.get("w")
            if type(running) is not int or type(weight) is not int:
                return False
            # `0 <= running <= _UINT64_MAX - weight` already bounds weight to
            # uint64 (a larger weight makes the upper bound negative), so a
            # separate `weight <= _UINT64_MAX` clause would be dead code.
            #
            # `0 < weight` is a REDUNDANT EARLY-OUT, not a load-bearing check:
            # a non-positive weight makes the final range test
            # `start <= coin and coin - start < weight` unsatisfiable, so no
            # input's verdict changes if this clause is removed. It is kept as
            # defence-in-depth and cannot be pinned non-vacuously by a test.
            #
            # NOTE this local bound is deliberately STRICTER than upstream:
            # go-algorand evaluates `L <= coin && coin < L+Weight` in uint64 and
            # wraps on overflow, whereas this module rejects any
            # running+weight > 2^64-1. Unreachable for valid proofs (a real
            # proof has L+Weight <= SignedWeight), so there is no fork risk --
            # do not "relax for consistency".
            if not 0 < weight or not 0 <= running <= _UINT64_MAX - weight:
                return False
            parsed.append((position, running, weight))
        # Reveal keys must be real ints: a hand-built proof could key True, which
        # aliases position 1 (True == 1). mpack.decode already rejects bool keys,
        # but this is free defence-in-depth.
        if not all(type(k) is int for k in reveals):
            return False
        if {p for p, _r, _w in parsed} != set(reveals):
            return False
        if _bytes("SigCommit", state_proof.get("c"), 64) != _bytes(
            "signature_commitment", signature_commitment, 64
        ):
            return False
        signed_weight = _uint64("SignedWeight", state_proof.get("w"), positive=True)
        coins = generate_coins(
            participants_commitment=participants_commitment, ln_proven_weight=ln_proven_weight,
            signature_commitment=signature_commitment, signed_weight=signed_weight,
            message_hash=message_hash, count=len(parsed))
        return all(start <= coin and coin - start < weight
                   for coin, (_p, start, weight) in zip(coins, parsed))
    except (CoinSelectionError, TypeError, ValueError):
        return False

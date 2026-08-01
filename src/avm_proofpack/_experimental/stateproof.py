"""Experimental state-proof reveal reconstruction (Falcon message preimage).

This module is an EXPERIMENTAL foundation layer, a sibling to
:mod:`avm_proofpack._experimental.falcon`. It is **not wired into**
``verify_bundle`` and
changes no existing behavior. Importing it has no side effects. It exists so a
future tier can begin to remove node trust by verifying the Falcon-1024
signatures inside Algorand/Voi state proofs against the state-proof *message*.

What this module solves
-----------------------
The Falcon primitive can already verify a signature *given the exact message
bytes*. The missing piece was: **what message does a state-proof reveal's
Falcon signature actually sign?** This module answers that, reconstructs the
message from fields already carried in a bundle, and (via the test suite)
proves that a real captured reveal VERIFIES with
:func:`avm_proofpack._experimental.falcon.falcon1024_verify`.

The preimage, derived from primary source
-----------------------------------------
Each reveal (``crypto/stateproof.StateProof.Reveals[pos]``) carries a
``merklesignature.Signature`` whose Falcon signature is verified over the raw
bytes of the state-proof **message hash** (``crypto/stateproof/verifier.go``
``Verifier.Verify`` -> ``r.Part.PK.VerifyBytes(round, data[:], &sig)`` ->
``crypto/merklesignature`` ``Verifier.VerifyBytes`` ->
``sig.VerifyingKey.VerifyBytes(msg, sig.Signature)``; no re-hash in between --
Falcon's own ``hash_to_point(salt || msg)`` is the only hashing).

That ``data`` is a 32-byte ``MessageHash``, computed from the
``stateproofmsg.Message`` as (``data/stateproofmsg/message.go``
``Message.IntoStateProofMessageHash`` + ``Message.ToBeHashed``, and
``crypto.GenericHashObj`` in ``crypto/util.go``):

    MessageHash = SHA256( "spm" || canonical_msgpack(Message) )

* ``"spm"`` is ``protocol.StateProofMessage`` (``protocol/hash.go``).
* The hash is SHA-256 (``stateproofmsg`` hashes the message with
  ``crypto.Sha256``), producing the 32-byte ``MessageHash``.
* ``Message`` is a canonical (go-codec, omitempty) msgpack map with str codec
  tags, hashed in sorted-key order (``"P","b","f","l","v"``):

  | tag | field                  | type   |
  |-----|------------------------|--------|
  | ``b`` | BlockHeadersCommitment | []byte |
  | ``v`` | VotersCommitment       | []byte |
  | ``P`` | LnProvenWeight         | uint64 |
  | ``f`` | FirstAttestedRound     | uint64 |
  | ``l`` | LastAttestedRound      | uint64 |

Every one of these five fields is already carried in a proofpack bundle's
``state_proof_message`` section, so a bundle is self-sufficient to rebuild the
message with no network access.

Validation
----------
``tests/test_stateproof.py`` reconstructs this preimage from each real fixture
and verifies real captured reveals with the KAT-validated Falcon verifier.
Every reveal in every fixture (148 real mainnet Falcon signatures across
Algorand-pay, Algorand-appl and Voi-appl) verifies; a one-bit tamper of the
message hash makes them all reject. That real-data success is the correctness
proof for the preimage.

What this module is NOT (still node-trusting)
---------------------------------------------
Verifying a reveal's Falcon signature proves only "the holder of this ephemeral
Falcon key signed this state-proof message". It does **not** yet prove:

* that the ephemeral key is committed under the participant's key commitment
  (``Participant.PK`` / ``merklesignature.Commitment``): that is a merkle
  membership proof over an **Algorand Sumhash512** tree (the reveal's
  ``prf.hsh`` type is ``1`` = Sumhash, 64-byte nodes; leaf domain ``"KP"``,
  ``crypto/merklesignature`` ``CommittablePublicKey``; index derived as
  ``round - (round % KeyLifetime)`` with ``KeyLifetime`` = ``PK.lf``).
  Sumhash512 is not implemented in this repo yet -- see
  :data:`EPHEMERAL_KEY_LEAF_DOMAIN` and :func:`ephemeral_key_first_round`,
  which capture the confirmed spec for that next pass.
* aggregation of all reveals, the signed-weight/threshold check, the
  coin-based reveal-position selection, or the voters-commitment anchoring to
  a trusted round.

Those are deliberately out of scope here and remain future work. Using this
primitive alone does NOT remove node trust.
"""

from __future__ import annotations

import hashlib
from typing import NamedTuple

from .. import mpack
from .falcon import PUBLIC_KEY_SIZE, falcon1024_accepts, falcon1024_verify

__all__ = [
    "StateProofError",
    "STATE_PROOF_MESSAGE_HASHID",
    "EPHEMERAL_KEY_LEAF_DOMAIN",
    "RevealSignatureCount",
    "state_proof_message_hash",
    "reveal_falcon_inputs",
    "iter_reveals",
    "verify_reveal_signature",
    "count_reveal_signatures",
    "ephemeral_key_first_round",
]

#: ``protocol.StateProofMessage`` (``protocol/hash.go``): the HashID prefix on
#: the state-proof message preimage.
STATE_PROOF_MESSAGE_HASHID = b"spm"

#: ``merklesignature.KeysInMSS`` (``crypto/merklesignature``): the HashID for a
#: committable ephemeral public key (merkle leaf of the participant key tree).
#: Recorded for the deferred ephemeral-key membership pass; the tree hash is
#: Algorand Sumhash512, which this repo does not implement yet.
EPHEMERAL_KEY_LEAF_DOMAIN = b"KP"

_SHA256_SIZE = 32
_VOTERS_COMMITMENT_SIZE = 64  # merklesignature root == Sumhash512 digest size


class StateProofError(ValueError):
    """Raised when a state proof or its message fields are malformed.

    Subclasses :class:`ValueError`, so existing ``except ValueError`` handlers
    still catch it. A malformed input is always a rejection, never a silent
    acceptance.
    """


def _require_uint(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StateProofError(f"{name} must be a non-negative integer")
    return value


def _require_bytes(name: str, value: object, exact_len: int | None = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise StateProofError(f"{name} must be bytes-like")
    raw = bytes(value)
    if exact_len is not None and len(raw) != exact_len:
        raise StateProofError(f"{name} must be {exact_len} bytes, got {len(raw)}")
    return raw


def state_proof_message_hash(
    *,
    block_headers_commitment: bytes,
    voters_commitment: bytes,
    ln_proven_weight: int,
    first_attested_round: int,
    last_attested_round: int,
) -> bytes:
    """Reconstruct the 32-byte state-proof ``MessageHash``.

    This is the exact byte string each reveal's Falcon signature is verified
    over (see module docstring for the go-algorand derivation):

        SHA256( "spm" || canonical_msgpack(Message) )

    where ``Message`` is the go-codec canonical, omitempty msgpack map with str
    codec tags ``b`` (block-headers commitment), ``v`` (voters commitment),
    ``P`` (ln proven weight), ``f`` (first attested round), ``l`` (last
    attested round). All five arguments are carried verbatim in a bundle's
    ``state_proof_message`` section.

    Fields are validated fail-closed. ``omitempty`` is honored faithfully: a
    zero-valued uint or empty byte field is omitted from the encoded map, so
    the preimage matches what go-codec would have produced. Raises
    :class:`StateProofError` on any malformed field.
    """
    bhc = _require_bytes(
        "block_headers_commitment", block_headers_commitment, _SHA256_SIZE
    )
    vc = _require_bytes(
        "voters_commitment", voters_commitment, _VOTERS_COMMITMENT_SIZE
    )
    ln = _require_uint("ln_proven_weight", ln_proven_weight)
    first = _require_uint("first_attested_round", first_attested_round)
    last = _require_uint("last_attested_round", last_attested_round)
    if first > last:
        raise StateProofError(
            f"attested interval is inverted: first {first} > last {last}"
        )

    # go-codec omitempty: omit any field equal to its zero value. Real state
    # proofs populate all five, but honoring omitempty keeps the preimage
    # byte-identical to go-codec for any input.
    message: dict[str, object] = {}
    if bhc:
        message["b"] = bhc
    if vc:
        message["v"] = vc
    if ln:
        message["P"] = ln
    if first:
        message["f"] = first
    if last:
        message["l"] = last

    preimage = STATE_PROOF_MESSAGE_HASHID + mpack.encode_canonical(message)
    return hashlib.sha256(preimage).digest()


def reveal_falcon_inputs(reveal: object) -> tuple[bytes, bytes]:
    """Extract ``(falcon_public_key, falcon_signature)`` from one reveal.

    A reveal is ``crypto/stateproof.Reveal``:
    ``{"p": Participant, "s": SigSlot}``. The SigSlot's ``"s"`` is a
    ``merklesignature.Signature`` carrying the ephemeral Falcon verifying key
    (``vkey.k``, 1793 bytes) and the Falcon signature (``sig``). Raises
    :class:`StateProofError` if the structure is not as expected.
    """
    if not isinstance(reveal, dict):
        raise StateProofError("reveal must be a map")
    sig_slot = reveal.get("s")
    if not isinstance(sig_slot, dict):
        raise StateProofError("reveal has no SigSlot ('s')")
    signature = sig_slot.get("s")
    if not isinstance(signature, dict):
        raise StateProofError("SigSlot has no merklesignature ('s')")
    falcon_sig = signature.get("sig")
    if not isinstance(falcon_sig, (bytes, bytearray, memoryview)):
        raise StateProofError("merklesignature has no Falcon signature ('sig')")
    vkey = signature.get("vkey")
    if not isinstance(vkey, dict):
        raise StateProofError("merklesignature has no verifying key ('vkey')")
    public_key = vkey.get("k")
    public_key = _require_bytes("verifying key ('vkey.k')", public_key, PUBLIC_KEY_SIZE)
    return public_key, bytes(falcon_sig)


def iter_reveals(state_proof: object):
    """Yield ``(position, reveal)`` pairs from a decoded state proof, sorted.

    ``state_proof`` is the decoded ``crypto/stateproof.StateProof`` map; its
    ``"r"`` field is the sparse ``position -> Reveal`` map. Positions are
    yielded in ascending numeric order for determinism. Raises
    :class:`StateProofError` if there is no reveals map.
    """
    if not isinstance(state_proof, dict):
        raise StateProofError("state proof must be a map")
    reveals = state_proof.get("r")
    if not isinstance(reveals, dict):
        raise StateProofError("state proof has no reveals map ('r')")
    for position in sorted(reveals):
        yield position, reveals[position]


def verify_reveal_signature(reveal: object, message_hash: bytes) -> bool:
    """Verify one reveal's Falcon signature over ``message_hash``. Fail-closed.

    ``message_hash`` is the 32-byte value from :func:`state_proof_message_hash`.
    Returns ``True`` iff the reveal's Falcon signature is a structurally valid
    compressed Falcon-1024 signature of ``message_hash`` under the reveal's
    ephemeral verifying key. Structural malformation (bad key/signature
    encoding) folds to ``False`` via :func:`falcon1024_accepts`; a malformed
    reveal *structure* still raises :class:`StateProofError`.

    This proves only that the holder of the ephemeral Falcon key signed the
    state-proof message. It does NOT prove that key is committed under the
    participant's key commitment (see module docstring).
    """
    _require_bytes("message_hash", message_hash, _SHA256_SIZE)
    public_key, signature = reveal_falcon_inputs(reveal)
    return falcon1024_accepts(public_key, message_hash, signature)


class RevealSignatureCount(NamedTuple):
    """How many reveals carried a valid Falcon signature over the message.

    Unpacks as the 2-tuple ``(verified, total)``. ``is_trust_root`` is a
    property that is ALWAYS ``False`` at this layer: it exists so a future
    caller cannot mistake a full ``verified == total`` count for an attested
    state proof. Any code that gates on attestation must read ``is_trust_root``
    and will get the honest answer until the deferred membership / signed-weight
    / coin-selection / voters-anchoring checks are implemented. Because it is a
    property, not a field, no caller can construct this type with it set true.
    """

    verified: int
    total: int

    @property
    def is_trust_root(self) -> bool:
        return False


def count_reveal_signatures(
    state_proof: object,
    *,
    block_headers_commitment: bytes,
    voters_commitment: bytes,
    ln_proven_weight: int,
    first_attested_round: int,
    last_attested_round: int,
) -> RevealSignatureCount:
    """Count reveals whose Falcon signature matches the reconstructed message.

    Convenience wrapper: rebuilds the message hash from the supplied
    ``state_proof_message`` fields (all carried in a bundle) and Falcon-verifies
    every reveal. Returns a :class:`RevealSignatureCount`.

    IMPORTANT: this is a COUNT, not a verdict. A full ``verified == total``
    result does NOT establish the state proof as a trust root, which is why the
    function is named ``count_*`` and the result's ``is_trust_root`` is always
    ``False``. It proves each revealed ephemeral key signed the message, but not
    key-commitment membership, signed-weight thresholds, coin-based position
    selection, or voters-commitment anchoring. Those remain future work; do not
    treat this as node-trust removal.
    """
    message_hash = state_proof_message_hash(
        block_headers_commitment=block_headers_commitment,
        voters_commitment=voters_commitment,
        ln_proven_weight=ln_proven_weight,
        first_attested_round=first_attested_round,
        last_attested_round=last_attested_round,
    )
    verified = 0
    total = 0
    for _position, reveal in iter_reveals(state_proof):
        total += 1
        if verify_reveal_signature(reveal, message_hash):
            verified += 1
    return RevealSignatureCount(verified=verified, total=total)


def ephemeral_key_first_round(round_number: int, key_lifetime: int) -> int:
    """First round of the key-lifetime window containing ``round_number``.

    ``crypto/merklesignature`` ``Verifier.FirstRoundInKeyLifetime``:
    ``round - (round % KeyLifetime)``. This is the ``Round`` field of the
    ``CommittablePublicKey`` merkle leaf whose membership the deferred
    ephemeral-key pass must prove (leaf domain :data:`EPHEMERAL_KEY_LEAF_DOMAIN`,
    over an Algorand Sumhash512 tree). ``KeyLifetime`` is the reveal's
    ``Participant.PK.lf``. Provided now because it is pure arithmetic and
    testable; the surrounding membership check awaits a Sumhash512
    implementation. Raises :class:`StateProofError` if ``key_lifetime`` is not
    a positive integer.
    """
    round_number = _require_uint("round_number", round_number)
    if not isinstance(key_lifetime, int) or isinstance(key_lifetime, bool) or key_lifetime <= 0:
        raise StateProofError("key_lifetime must be a positive integer")
    return round_number - (round_number % key_lifetime)

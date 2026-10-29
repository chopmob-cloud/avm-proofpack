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
Falcon key signed this state-proof message".

Step A2 -- ephemeral-key membership -- is now IMPLEMENTED (see
:mod:`avm_proofpack._experimental.merklesig` and :func:`verify_reveal` /
:func:`verify_ephemeral_key_membership` below). Combined, they prove "the holder
of an ephemeral key *committed under this participant's key commitment* signed
the state-proof message": the ephemeral key's Sumhash512 vector-commitment
membership proof (``prf``, ``hsh`` type ``1`` = Sumhash, 64-byte nodes; leaf
domain ``"KP"``, ``crypto/merklesignature`` ``CommittablePublicKey``; leaf round
``round - (round % KeyLifetime)`` with ``KeyLifetime`` = ``PK.lf``) is verified
up to ``Participant.PK.cmt``.

It still does **not** prove, and so still does NOT remove node trust:

* the per-participant weights and the aggregate signed-weight/threshold check
  (step A3);
* the coin-based reveal-position selection (step A4);
* the voters-commitment anchoring to a trusted round (step A5).

Those are deliberately out of scope here and remain future work. Using these
primitives alone does NOT remove node trust.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import NamedTuple

from .. import mpack
from .falcon import (
    PUBLIC_KEY_SIZE,
    falcon1024_accepts,
    signature_ct_representation,
)
from .merklesig import (
    NODE_SIZE,
    MerkleSigError,
    committable_public_key_leaf,
    sumhash_multiproof_root,
    verify_sumhash_multiproof,
    verify_sumhash_vector_commitment,
)
from .sumhash import sumhash512

__all__ = [
    "EPHEMERAL_KEY_LEAF_DOMAIN",
    "LN2_INT_APPROXIMATION",
    "MAX_ENCODED_TREE_DEPTH",
    "PARTICIPANT_LEAF_DOMAIN",
    "SIG_SLOT_LEAF_DOMAIN",
    "STATE_PROOF_MESSAGE_HASHID",
    "STRENGTH_TARGET_DEFAULT",
    "WEIGHT_PRECISION_BITS",
    "RevealMembershipInputs",
    "RevealSignatureCount",
    "StateProofError",
    "StateProofRevealsResult",
    "accumulate_revealed_weight",
    "approx_proven_weight",
    "compute_participant_tree_root",
    "compute_signature_tree_root",
    "count_reveal_signatures",
    "ephemeral_key_first_round",
    "iter_reveals",
    "participant_leaf",
    "reveal_falcon_inputs",
    "reveal_membership_inputs",
    "sig_slot_leaf",
    "signed_weight_meets_threshold",
    "state_proof_message_hash",
    "verify_all_reveals",
    "verify_ephemeral_key_membership",
    "verify_participant_tree_membership",
    "verify_reveal",
    "verify_reveal_signature",
    "verify_signature_tree_membership",
    "verify_signed_weight_threshold",
]

#: ``protocol.StateProofMessage`` (``protocol/hash.go``): the HashID prefix on
#: the state-proof message preimage.
STATE_PROOF_MESSAGE_HASHID = b"spm"

#: ``merklesignature.KeysInMSS`` (``crypto/merklesignature``): the HashID for a
#: committable ephemeral public key (merkle leaf of the participant key tree).
#: Recorded for the deferred ephemeral-key membership pass; the tree hash is
#: Algorand Sumhash512, which this repo does not implement yet.
EPHEMERAL_KEY_LEAF_DOMAIN = b"KP"

#: ``protocol.StateProofSig`` (``protocol/hash.go``): HashID of a signature-tree
#: leaf. The leaf hashes ``committableSignatureSlot.ToBeHashed`` (go-algorand
#: ``crypto/stateproof/structs.go``): ``LE64(L) || Signature.fixed`` under this
#: domain, with the Sumhash512 tree hash.
SIG_SLOT_LEAF_DOMAIN = b"sps"

#: ``protocol.StateProofPart`` (``protocol/hash.go``): HashID of a
#: participant-tree leaf. The leaf hashes ``basics.Participant.ToBeHashed``:
#: ``LE64(Weight) || PK.GetFixedLengthHashableRepresentation`` where the PK
#: (``merklesignature.Verifier``) fixed representation is
#: ``LE64(KeyLifetime) || Commitment[64]``.
PARTICIPANT_LEAF_DOMAIN = b"spp"

#: ``crypto/merklearray`` ``MaxEncodedTreeDepth``: the fixed number of digest
#: slots a ``SingleLeafProof.GetFixedLengthHashableRepresentation`` pads to
#: (leading zero digests + the real path), so the sig-tree leaf is fixed length.
MAX_ENCODED_TREE_DEPTH = 16

#: ``crypto/stateproof`` ``precisionBits``: fixed-point precision (in bits) of
#: the log-domain weight arithmetic.
WEIGHT_PRECISION_BITS = 16

#: ``crypto/stateproof`` ``ln2IntApproximation`` = ceil(ln(2) * 2**16) = 45427.
LN2_INT_APPROXIMATION = 45427

#: Consensus ``StateProofStrengthTarget`` (256 on Algorand mainnet; empirically
#: 256 on Voi mainnet). The security parameter the signed-weight threshold is
#: verified against. Overridable for other networks.
STRENGTH_TARGET_DEFAULT = 256

_SHA256_SIZE = 32
_VOTERS_COMMITMENT_SIZE = 64  # merklesignature root == Sumhash512 digest size
_CRYPTO_PRIMITIVES_ID = 0  # merklesignature CryptoPrimitivesID (uint16 LE, = 0)


def _le16(value: int) -> bytes:
    return struct.pack("<H", value)


def _le64(value: int) -> bytes:
    return struct.pack("<Q", value)


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


class RevealMembershipInputs(NamedTuple):
    """The fields needed to verify one reveal's key-commitment membership.

    Extracted from a decoded ``crypto/stateproof.Reveal``:

    * ``verifying_key`` -- the ephemeral 1793-byte Falcon public key
      (``s.s.vkey.k``), the same key its Falcon signature is verified under.
    * ``index`` -- the leaf's position in the key tree (``s.s.idx``,
      ``VectorCommitmentIndex``).
    * ``tree_depth`` -- the merklearray proof depth (``s.s.prf.td``).
    * ``path`` -- the bottom-up sibling digests (``s.s.prf.pth``), each 64
      bytes.
    * ``key_commitment`` -- the participant's key-tree root
      (``p.p.cmt``, 64 bytes).
    * ``key_lifetime`` -- ``Participant.PK.lf`` (``p.p.lf``), the key-lifetime
      window used to derive the leaf's round.
    """

    verifying_key: bytes
    index: int
    tree_depth: int
    path: list
    key_commitment: bytes
    key_lifetime: int


def reveal_membership_inputs(reveal: object) -> RevealMembershipInputs:
    """Extract the key-commitment membership fields from one reveal.

    A reveal is ``crypto/stateproof.Reveal`` ``{"p": Participant, "s": SigSlot}``.
    The membership proof lives in the SigSlot's ``merklesignature.Signature``
    (``idx``, ``prf.td``, ``prf.pth``, and the ephemeral ``vkey.k``); the tree
    root and key lifetime live in the Participant's ``PK`` (``cmt``, ``lf``).
    Also asserts the proof's hash type is Sumhash (``prf.hsh.t == 1``), because
    this verifier only implements the Sumhash512 tree. Raises
    :class:`StateProofError` if the structure is not as expected.
    """
    if not isinstance(reveal, dict):
        raise StateProofError("reveal must be a map")

    participant = reveal.get("p")
    if not isinstance(participant, dict):
        raise StateProofError("reveal has no Participant ('p')")
    pk = participant.get("p")
    if not isinstance(pk, dict):
        raise StateProofError("Participant has no PK ('p')")
    key_commitment = _require_bytes(
        "key commitment ('p.p.cmt')", pk.get("cmt"), _VOTERS_COMMITMENT_SIZE
    )
    key_lifetime = pk.get("lf")
    if not isinstance(key_lifetime, int) or isinstance(key_lifetime, bool) or key_lifetime <= 0:
        raise StateProofError("Participant PK has no positive key lifetime ('p.p.lf')")

    sig_slot = reveal.get("s")
    if not isinstance(sig_slot, dict):
        raise StateProofError("reveal has no SigSlot ('s')")
    signature = sig_slot.get("s")
    if not isinstance(signature, dict):
        raise StateProofError("SigSlot has no merklesignature ('s')")
    vkey = signature.get("vkey")
    if not isinstance(vkey, dict):
        raise StateProofError("merklesignature has no verifying key ('vkey')")
    verifying_key = _require_bytes(
        "verifying key ('vkey.k')", vkey.get("k"), PUBLIC_KEY_SIZE
    )

    index = signature.get("idx")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise StateProofError("merklesignature has no valid index ('idx')")

    proof = signature.get("prf")
    if not isinstance(proof, dict):
        raise StateProofError("merklesignature has no proof ('prf')")
    # Only the Sumhash512 tree (hash type 1) is implemented; reject anything
    # else fail-closed rather than silently verifying under the wrong hash.
    hsh = proof.get("hsh")
    hash_type = hsh.get("t") if isinstance(hsh, dict) else None
    if hash_type != 1:
        raise StateProofError(
            f"proof hash type is {hash_type!r}, expected 1 (Sumhash); "
            "only the Sumhash512 key tree is supported"
        )
    tree_depth = proof.get("td")
    if not isinstance(tree_depth, int) or isinstance(tree_depth, bool) or tree_depth < 0:
        raise StateProofError("proof has no valid tree depth ('prf.td')")
    path = proof.get("pth")
    if not isinstance(path, list):
        raise StateProofError("proof has no sibling path ('prf.pth')")

    return RevealMembershipInputs(
        verifying_key=verifying_key,
        index=index,
        tree_depth=tree_depth,
        path=path,
        key_commitment=key_commitment,
        key_lifetime=key_lifetime,
    )


def verify_ephemeral_key_membership(reveal: object, signed_round: int) -> bool:
    """Verify one reveal's ephemeral key is committed under the participant's key
    commitment. Fail-closed.

    Reconstructs the ``merklesignature`` leaf for the reveal's ephemeral Falcon
    key at ``round = FirstRoundInKeyLifetime(signed_round)`` and checks its
    Sumhash512 vector-commitment membership proof (``prf``) up to the
    participant's key commitment (``cmt``). ``signed_round`` is the state-proof
    round -- i.e. the message's ``LastAttestedRound`` -- matching
    ``crypto/merklesignature`` ``Verifier.VerifyBytes``.

    Returns ``True`` iff the proof authenticates the key at its declared index
    under ``cmt``; returns ``False`` on a root mismatch; folds structural
    malformation of the membership fields (:class:`MerkleSigError`) to ``False``.
    A malformed reveal *structure* still raises :class:`StateProofError`.

    This proves the ephemeral key is committed under THIS participant's key
    commitment. It does NOT by itself remove node trust (participant weights,
    signed-weight threshold, coin-based position selection, and
    voters-commitment anchoring remain future work).
    """
    signed_round = _require_uint("signed_round", signed_round)
    inputs = reveal_membership_inputs(reveal)
    try:
        leaf_round = ephemeral_key_first_round(signed_round, inputs.key_lifetime)
        leaf = committable_public_key_leaf(inputs.verifying_key, leaf_round)
        return verify_sumhash_vector_commitment(
            leaf,
            inputs.index,
            inputs.tree_depth,
            inputs.path,
            inputs.key_commitment,
        )
    except MerkleSigError:
        return False


def verify_reveal(reveal: object, message_hash: bytes, signed_round: int) -> bool:
    """Complete single-reveal check: Falcon signature AND key membership. Fail-closed.

    Returns ``True`` iff BOTH hold for ``reveal``:

    1. its ephemeral Falcon key signed the 32-byte state-proof ``message_hash``
       (:func:`verify_reveal_signature`), and
    2. that same ephemeral key is committed under the participant's key
       commitment at ``round = FirstRoundInKeyLifetime(signed_round)``
       (:func:`verify_ephemeral_key_membership`).

    Together these prove: *the holder of an ephemeral key committed under this
    participant's key commitment signed the state-proof message.* Both use the
    identical ephemeral key (``vkey.k``), so a tamper of the key, the signature,
    the message, the round, or the proof path fails at least one check and the
    whole reveal is rejected.

    ``message_hash`` is the 32-byte value from :func:`state_proof_message_hash`;
    ``signed_round`` is the state-proof round (the message's
    ``LastAttestedRound``). Returns ``False`` on any verification failure; a
    malformed reveal *structure* still raises :class:`StateProofError`.

    IMPORTANT: a passing ``verify_reveal`` still does NOT establish the state
    proof as a trust root. It is a per-reveal check only; the participant
    weights, the aggregate signed-weight/threshold, the coin-based
    reveal-position selection, and the voters-commitment anchoring to a trusted
    round are all still pending (steps A3-A5). Using this alone does NOT remove
    node trust.
    """
    if not verify_reveal_signature(reveal, message_hash):
        return False
    return verify_ephemeral_key_membership(reveal, signed_round)


# ---------------------------------------------------------------------------
# A3 -- sig-tree / participant-tree membership and the signed-weight threshold.
#
# WHAT A3 ADDS. A2 proves, per reveal, "the holder of an ephemeral key committed
# under this participant's key commitment signed the state-proof message". A3
# proves two batch facts about the *set* of reveals:
#   (a) every revealed SigSlot is a member of the state proof's signature tree
#       (SigProofs -> root SigCommit, self-contained in the state proof); and
#   (b) every revealed Participant is a member of the participants tree
#       (PartProofs -> root = the voters commitment); and
#   (c) the declared aggregate SignedWeight clears the log-domain proven-weight
#       threshold that go-algorand's verifier checks.
#
# WHAT A3 STILL IS NOT (do not mistake this for the trust root):
#   * COIN SELECTION (A4) is NOT implemented. A3 verifies membership of the
#     reveals it is *given*; it does NOT verify that those are the positions the
#     verifier's coins actually select. Without A4 an attacker can choose which
#     positions to reveal, so A3 alone does not bind the signed weight to the
#     revealed signers -- it is not the trust root.
#   * VOTERS-COMMITMENT ANCHORING (A5) is NOT implemented. Participant membership
#     is checked against a voters commitment that this layer TRUSTS; it does not
#     anchor that commitment to a trusted round. IMPORTANT: the state-proof
#     message's VotersCommitment commits to the voters of the *next* interval,
#     not the signers of *this* proof. The signers' voters commitment lives in an
#     earlier block header (round LastAttestedRound - StateProofInterval) that a
#     single bundle does not carry. So verifying participant membership against
#     message.VotersCommitment only succeeds when the voter set is unchanged
#     across the interval; A5 must supply the correct anchored commitment.
# ---------------------------------------------------------------------------


def _single_leaf_proof_fixed_representation(proof: object) -> bytes:
    """Fixed-length serialization of a ``merklearray.SingleLeafProof``.

    Matches ``SingleLeafProof.GetFixedLengthHashableRepresentation``
    (``crypto/merklearray/proof.go``): one ``TreeDepth`` byte, then
    ``MaxEncodedTreeDepth - len(Path)`` leading 64-byte zero digests, then the
    real bottom-up path digests. Only the Sumhash512 tree (``hsh.t == 1``,
    64-byte nodes) is supported. Raises :class:`StateProofError` fail-closed on
    any malformation.
    """
    if not isinstance(proof, dict):
        raise StateProofError("signature proof ('prf') must be a map")
    hsh = proof.get("hsh")
    hash_type = hsh.get("t") if isinstance(hsh, dict) else None
    if hash_type != 1:
        raise StateProofError(
            f"proof hash type is {hash_type!r}, expected 1 (Sumhash)"
        )
    tree_depth = proof.get("td")
    if (
        not isinstance(tree_depth, int)
        or isinstance(tree_depth, bool)
        or not 0 <= tree_depth <= 0xFF
    ):
        raise StateProofError("proof has no valid tree depth ('prf.td')")
    path = proof.get("pth")
    if not isinstance(path, list):
        raise StateProofError("proof has no sibling path ('prf.pth')")
    if len(path) > MAX_ENCODED_TREE_DEPTH:
        raise StateProofError(
            f"proof path has {len(path)} digests, exceeds "
            f"MaxEncodedTreeDepth {MAX_ENCODED_TREE_DEPTH}"
        )
    digests = [_require_bytes(f"prf.pth[{i}]", d, NODE_SIZE) for i, d in enumerate(path)]
    zero = b"\x00" * NODE_SIZE
    out = bytearray()
    out.append(tree_depth)
    out.extend(zero * (MAX_ENCODED_TREE_DEPTH - len(digests)))
    for digest in digests:
        out.extend(digest)
    return bytes(out)


def sig_slot_leaf(reveal: object) -> bytes:
    """Reconstruct the 64-byte signature-tree leaf for one reveal. Fail-closed.

    The leaf is ``Sumhash512(committableSignatureSlot.ToBeHashed)``
    (``crypto/stateproof/structs.go`` ``buildCommittableSignature`` +
    ``committableSignatureSlot.ToBeHashed``):

        Sumhash512( "sps" || LE64(L) || Signature.fixed )

    where ``L`` is the SigSlot's ``l`` (0 when omitted) and ``Signature.fixed``
    is ``merklesignature.Signature.GetFixedLengthHashableRepresentation``
    (``crypto/merklesignature``):

        LE16(0) || Falcon_CT(1538) || VerifyingKey(1793) ||
            LE64(VectorCommitmentIndex) || SingleLeafProof.fixed

    ``Falcon_CT`` is the compressed signature re-encoded to the fixed-length CT
    format (:func:`avm_proofpack._experimental.falcon.signature_ct_representation`),
    ``VerifyingKey`` is the raw 1793-byte ephemeral public key, and the trailing
    proof is the ephemeral key's membership proof serialized fixed-length. Every
    field is validated; raises :class:`StateProofError` on any malformation.
    """
    if not isinstance(reveal, dict):
        raise StateProofError("reveal must be a map")
    sig_slot = reveal.get("s")
    if not isinstance(sig_slot, dict):
        raise StateProofError("reveal has no SigSlot ('s')")
    running_weight = sig_slot.get("l", 0)
    running_weight = _require_uint("SigSlot L ('s.l')", running_weight)
    signature = sig_slot.get("s")
    if not isinstance(signature, dict):
        raise StateProofError("SigSlot has no merklesignature ('s.s')")

    falcon_sig = signature.get("sig")
    falcon_sig = _require_bytes("Falcon signature ('s.s.sig')", falcon_sig)
    vkey = signature.get("vkey")
    if not isinstance(vkey, dict):
        raise StateProofError("merklesignature has no verifying key ('vkey')")
    public_key = _require_bytes("verifying key ('vkey.k')", vkey.get("k"), PUBLIC_KEY_SIZE)
    index = signature.get("idx")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index > 0xFFFFFFFFFFFFFFFF:
        raise StateProofError("merklesignature has no valid index ('idx')")

    try:
        ct = signature_ct_representation(falcon_sig)
    except ValueError as exc:  # FalconError subclasses ValueError
        raise StateProofError(f"Falcon signature not CT-convertible: {exc}") from exc

    proof_fixed = _single_leaf_proof_fixed_representation(signature.get("prf"))
    signature_fixed = (
        _le16(_CRYPTO_PRIMITIVES_ID)
        + ct
        + public_key
        + _le64(index)
        + proof_fixed
    )
    preimage = SIG_SLOT_LEAF_DOMAIN + _le64(running_weight) + signature_fixed
    return sumhash512(preimage)


def participant_leaf(reveal: object) -> bytes:
    """Reconstruct the 64-byte participants-tree leaf for one reveal. Fail-closed.

    The leaf is ``Sumhash512(basics.Participant.ToBeHashed)``:

        Sumhash512( "spp" || LE64(Weight) || LE64(KeyLifetime) || Commitment[64] )

    ``LE64(KeyLifetime) || Commitment`` is the participant PK
    (``merklesignature.Verifier``) ``GetFixedLengthHashableRepresentation``.
    Raises :class:`StateProofError` on any malformation.
    """
    if not isinstance(reveal, dict):
        raise StateProofError("reveal must be a map")
    participant = reveal.get("p")
    if not isinstance(participant, dict):
        raise StateProofError("reveal has no Participant ('p')")
    weight = _require_uint("participant weight ('p.w')", participant.get("w"))
    pk = participant.get("p")
    if not isinstance(pk, dict):
        raise StateProofError("Participant has no PK ('p.p')")
    commitment = _require_bytes("key commitment ('p.p.cmt')", pk.get("cmt"), _VOTERS_COMMITMENT_SIZE)
    key_lifetime = _require_uint("key lifetime ('p.p.lf')", pk.get("lf"))
    preimage = (
        PARTICIPANT_LEAF_DOMAIN
        + _le64(weight)
        + _le64(key_lifetime)
        + commitment
    )
    return sumhash512(preimage)


def _proof_fields(state_proof: object, key: str) -> tuple[list, int]:
    """Return ``(path, tree_depth)`` for a state-proof merklearray proof.

    ``key`` is ``"S"`` (SigProofs) or ``"P"`` (PartProofs). Validates the proof
    is a Sumhash tree (``hsh.t == 1``). Raises :class:`StateProofError`.
    """
    if not isinstance(state_proof, dict):
        raise StateProofError("state proof must be a map")
    proof = state_proof.get(key)
    if not isinstance(proof, dict):
        raise StateProofError(f"state proof has no merklearray proof ({key!r})")
    hsh = proof.get("hsh")
    hash_type = hsh.get("t") if isinstance(hsh, dict) else None
    if hash_type != 1:
        raise StateProofError(
            f"proof {key!r} hash type is {hash_type!r}, expected 1 (Sumhash)"
        )
    tree_depth = proof.get("td")
    if not isinstance(tree_depth, int) or isinstance(tree_depth, bool) or tree_depth < 0:
        raise StateProofError(f"proof {key!r} has no valid tree depth ('td')")
    path = proof.get("pth")
    if not isinstance(path, list):
        raise StateProofError(f"proof {key!r} has no sibling path ('pth')")
    return path, tree_depth


def compute_signature_tree_root(state_proof: object) -> bytes:
    """Reconstruct the signature-tree root from the reveals' SigSlots.

    Builds each revealed position's :func:`sig_slot_leaf` and verifies the
    multi-element ``SigProofs`` (go-algorand ``VerifyVectorCommitment``),
    returning the reconstructed 64-byte root. This root must equal the state
    proof's ``SigCommit`` (``c``). Raises :class:`StateProofError` /
    :class:`MerkleSigError` on malformed input.
    """
    path, tree_depth = _proof_fields(state_proof, "S")
    leaves = {pos: sig_slot_leaf(reveal) for pos, reveal in iter_reveals(state_proof)}
    return sumhash_multiproof_root(leaves, path, tree_depth)


def compute_participant_tree_root(state_proof: object) -> bytes:
    """Reconstruct the participants-tree root from the reveals' Participants.

    Builds each revealed position's :func:`participant_leaf` and verifies the
    multi-element ``PartProofs``, returning the reconstructed 64-byte root. This
    is the voters commitment the revealed signers are co-members of. See the A5
    note above: it equals the message's ``VotersCommitment`` only when the voter
    set is unchanged across the interval. Raises on malformed input.
    """
    path, tree_depth = _proof_fields(state_proof, "P")
    leaves = {pos: participant_leaf(reveal) for pos, reveal in iter_reveals(state_proof)}
    return sumhash_multiproof_root(leaves, path, tree_depth)


def verify_signature_tree_membership(state_proof: object) -> bool:
    """Verify every revealed SigSlot is a member of the signature tree. Fail-closed.

    Returns ``True`` iff the reveals' ``SigProofs`` reconstruct exactly the state
    proof's ``SigCommit`` (``c``). This is fully self-contained in the state
    proof. A mismatch or any structural malformation folds to ``False``.
    """
    if not isinstance(state_proof, dict):
        return False
    try:
        sig_commit = _require_bytes("SigCommit ('c')", state_proof.get("c"), NODE_SIZE)
        path, tree_depth = _proof_fields(state_proof, "S")
        leaves = {pos: sig_slot_leaf(reveal) for pos, reveal in iter_reveals(state_proof)}
    except StateProofError:
        return False
    return verify_sumhash_multiproof(sig_commit, leaves, path, tree_depth)


def verify_participant_tree_membership(
    state_proof: object, participants_commitment: bytes
) -> bool:
    """Verify every revealed Participant is a member of the participants tree.

    Returns ``True`` iff the reveals' ``PartProofs`` reconstruct exactly
    ``participants_commitment`` (the voters commitment the reveals should be
    members of). Fail-closed: a mismatch or malformation folds to ``False``.

    ``participants_commitment`` MUST be the voters commitment of the round this
    proof attests (see the A5 note above); passing the message's
    ``VotersCommitment`` is correct only when the voter set is unchanged across
    the interval, and this layer does not (and cannot, from a single bundle)
    anchor that commitment to a trusted round.
    """
    commitment = _require_bytes(
        "participants_commitment", participants_commitment, NODE_SIZE
    )
    try:
        path, tree_depth = _proof_fields(state_proof, "P")
        leaves = {pos: participant_leaf(reveal) for pos, reveal in iter_reveals(state_proof)}
    except StateProofError:
        return False
    return verify_sumhash_multiproof(commitment, leaves, path, tree_depth)


def accumulate_revealed_weight(state_proof: object) -> int:
    """Sum the participant weights across the revealed positions.

    IMPORTANT: this is the aggregate weight of the *revealed* signers only, a
    small sampled subset. It is deliberately NOT equal to the state proof's
    declared ``SignedWeight`` (``w``), which is the total weight of all signers.
    On the real fixtures this sum is strictly less than ``SignedWeight``. The
    signed-weight threshold (:func:`signed_weight_meets_threshold`) checks the
    *declared* ``SignedWeight``; the declared value is what A4 coin-selection
    binds to the reveals. This function is provided for inspection, not as the
    threshold input. Raises :class:`StateProofError` on malformed input.
    """
    return sum(_require_uint("participant weight ('p.w')",
                             (reveal.get("p") or {}).get("w") if isinstance(reveal, dict) else None)
               for _pos, reveal in iter_reveals(state_proof))


def _weight_subexpressions(signed_weight: int) -> tuple[int, int, int]:
    """The (y, x, w) sub-expressions of go-algorand ``getSubExpressions``.

    With ``d = floor(log2(signedWeight)) = bit_length-1`` and
    ``b = WEIGHT_PRECISION_BITS``:

        y = signedWeight**2 + 2**(d+2) * signedWeight + 2**(2d)
        x = 3 * 2**b * (signedWeight**2 - 2**(2d))
        w = d * (ln2IntApproximation - 1)

    Computed with Python big integers (exact, no overflow), matching the go
    ``*big.Int`` arithmetic exactly.
    """
    d = signed_weight.bit_length() - 1
    sw2 = signed_weight * signed_weight
    y = sw2 + (signed_weight << (d + 2)) + (1 << (2 * d))
    x = 3 * (1 << WEIGHT_PRECISION_BITS) * (sw2 - (1 << (2 * d)))
    w = d * (LN2_INT_APPROXIMATION - 1)
    return y, x, w


def signed_weight_meets_threshold(
    signed_weight: int,
    ln_proven_weight: int,
    num_reveals: int,
    strength_target: int = STRENGTH_TARGET_DEFAULT,
) -> bool:
    """The exact go-algorand ``verifyWeights`` inequality. Fail-closed.

    Returns ``True`` iff, with ``T = ln2IntApproximation`` and ``(y, x, w)`` from
    :func:`_weight_subexpressions`:

        num_reveals * (x + w * y)  >=  (strength_target * T + num_reveals * P) * y

    where ``P = ln_proven_weight`` (the message's ``LnProvenWeight``, i.e.
    ``ceil(ln(provenWeight) * 2**16)``). This is the real, log-domain
    proven-weight check the verifier runs -- there is no separate scalar
    ``signedWeight >= provenWeight`` test; the inequality above encodes it.
    ``num_reveals`` is the number of coins, ``len(PositionsToReveal)`` (NOT the
    number of distinct reveals). Returns ``False`` on a zero signed weight or any
    non-integer / negative input. Never returns ``True`` on doubt.
    """
    for name, value in (
        ("signed_weight", signed_weight),
        ("ln_proven_weight", ln_proven_weight),
        ("num_reveals", num_reveals),
        ("strength_target", strength_target),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return False
    if signed_weight == 0:
        return False
    y, x, w = _weight_subexpressions(signed_weight)
    lhs = num_reveals * (x + w * y)
    rhs = (strength_target * LN2_INT_APPROXIMATION + num_reveals * ln_proven_weight) * y
    return lhs >= rhs


def _message_ln_proven_weight(message: object) -> int:
    """Extract ``LnProvenWeight`` from a message mapping or accept it directly."""
    if isinstance(message, int) and not isinstance(message, bool):
        return message
    if isinstance(message, dict):
        for key in ("ln_proven_weight", "P", "LnProvenWeight"):
            if key in message:
                return _require_uint("ln_proven_weight", message[key])
    raise StateProofError("message has no ln_proven_weight")


def verify_signed_weight_threshold(
    state_proof: object,
    message: object,
    *,
    strength_target: int = STRENGTH_TARGET_DEFAULT,
) -> bool:
    """Verify a state proof's declared SignedWeight clears the threshold. Fail-closed.

    Pulls the declared ``SignedWeight`` (``w``) and the coin count
    ``len(PositionsToReveal)`` (``pr``) from ``state_proof`` and the
    ``LnProvenWeight`` from ``message`` (a mapping with ``ln_proven_weight`` /
    ``P``, or the integer itself), then applies
    :func:`signed_weight_meets_threshold`. Returns ``False`` on any structural
    malformation.

    This is the genuine verifier check, but on its own it is NOT the trust root:
    without A4 coin-selection the declared ``SignedWeight`` is not yet bound to
    the revealed signers.
    """
    if not isinstance(state_proof, dict):
        return False
    signed_weight = state_proof.get("w", 0)
    positions = state_proof.get("pr")
    if not isinstance(positions, list):
        return False
    try:
        ln_proven_weight = _message_ln_proven_weight(message)
    except StateProofError:
        return False
    return signed_weight_meets_threshold(
        signed_weight, ln_proven_weight, len(positions), strength_target
    )


def approx_proven_weight(ln_proven_weight: int) -> int:
    """A floating-point estimate of ``provenWeight`` from ``LnProvenWeight``.

    ``LnProvenWeight = ceil(ln(provenWeight) * 2**precisionBits)``, so
    ``provenWeight ~= exp(LnProvenWeight / 2**precisionBits)``. This inversion is
    LOSSY and is provided only for human-readable reporting; it is NEVER used in
    the actual threshold check, which stays entirely in the exact integer log
    domain (:func:`signed_weight_meets_threshold`). Returns a rounded integer.
    """
    ln_proven_weight = _require_uint("ln_proven_weight", ln_proven_weight)
    return round(math.exp(ln_proven_weight / (1 << WEIGHT_PRECISION_BITS)))


class StateProofRevealsResult(NamedTuple):
    """Structured result of the combined A2+A3 checks over all reveals.

    Every boolean is a genuine verification outcome; ``is_trust_root`` is always
    ``False`` (a property, so it cannot be constructed true) because A4
    coin-selection and A5 voters anchoring are still pending. A caller that
    treats ``all_checks_ok`` as attestation would be wrong -- read
    ``is_trust_root``.
    """

    reveal_count: int
    num_reveals: int
    signed_weight: int
    ln_proven_weight: int
    approx_proven_weight: int
    revealed_weight: int
    all_reveals_ok: bool          # per reveal: Falcon signature AND ephemeral-key membership
    sig_tree_ok: bool             # batch: all SigSlots members of SigCommit
    part_tree_ok: bool            # batch: all Participants members of participants_commitment
    weight_threshold_ok: bool     # declared SignedWeight clears the proven-weight threshold

    @property
    def all_checks_ok(self) -> bool:
        return (
            self.all_reveals_ok
            and self.sig_tree_ok
            and self.part_tree_ok
            and self.weight_threshold_ok
        )

    @property
    def is_trust_root(self) -> bool:
        return False


def verify_all_reveals(
    state_proof: object,
    *,
    block_headers_commitment: bytes,
    voters_commitment: bytes,
    ln_proven_weight: int,
    first_attested_round: int,
    last_attested_round: int,
    participants_commitment: bytes | None = None,
    strength_target: int = STRENGTH_TARGET_DEFAULT,
) -> StateProofRevealsResult:
    """Run the combined A2+A3 checks over every reveal and the weight threshold.

    For each reveal: the Falcon signature over the reconstructed state-proof
    message hash AND the ephemeral key's membership under the participant's key
    commitment (A2, :func:`verify_reveal`). As batch facts (A3): all revealed
    SigSlots are members of ``SigCommit`` (:func:`verify_signature_tree_membership`);
    all revealed Participants are members of ``participants_commitment``
    (:func:`verify_participant_tree_membership`, defaulting to
    ``voters_commitment``); and the declared ``SignedWeight`` clears the
    proven-weight threshold (:func:`signed_weight_meets_threshold`).

    Returns a :class:`StateProofRevealsResult`. IMPORTANT: even when every field
    is ``True`` this is NOT node-trust removal. ``is_trust_root`` is always
    ``False`` -- A4 coin-selection (which positions must be revealed) and A5
    voters-commitment anchoring are still pending, and the participant check
    trusts ``participants_commitment`` (which for a bare bundle may not even be
    the correct signing voters commitment; see the A5 note above).
    """
    message_hash = state_proof_message_hash(
        block_headers_commitment=block_headers_commitment,
        voters_commitment=voters_commitment,
        ln_proven_weight=ln_proven_weight,
        first_attested_round=first_attested_round,
        last_attested_round=last_attested_round,
    )
    signed_round = _require_uint("last_attested_round", last_attested_round)

    reveal_count = 0
    all_reveals_ok = True
    for _pos, reveal in iter_reveals(state_proof):
        reveal_count += 1
        if not verify_reveal(reveal, message_hash, signed_round):
            all_reveals_ok = False

    part_root = participants_commitment
    if part_root is None:
        part_root = voters_commitment

    sig_tree_ok = verify_signature_tree_membership(state_proof)
    part_tree_ok = verify_participant_tree_membership(state_proof, part_root)

    signed_weight = state_proof.get("w", 0) if isinstance(state_proof, dict) else 0
    positions = state_proof.get("pr") if isinstance(state_proof, dict) else None
    num_reveals = len(positions) if isinstance(positions, list) else 0
    weight_threshold_ok = signed_weight_meets_threshold(
        signed_weight, ln_proven_weight, num_reveals, strength_target
    )

    try:
        revealed_weight = accumulate_revealed_weight(state_proof)
    except StateProofError:
        revealed_weight = 0

    return StateProofRevealsResult(
        reveal_count=reveal_count,
        num_reveals=num_reveals,
        signed_weight=signed_weight if isinstance(signed_weight, int) else 0,
        ln_proven_weight=ln_proven_weight,
        approx_proven_weight=approx_proven_weight(ln_proven_weight),
        revealed_weight=revealed_weight,
        all_reveals_ok=all_reveals_ok and reveal_count > 0,
        sig_tree_ok=sig_tree_ok,
        part_tree_ok=part_tree_ok,
        weight_threshold_ok=weight_threshold_ok,
    )

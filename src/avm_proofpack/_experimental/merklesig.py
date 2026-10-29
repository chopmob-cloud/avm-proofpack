"""Experimental Sumhash512 key-commitment membership (merklesignature tree).

This module is an EXPERIMENTAL foundation layer, a sibling to
:mod:`avm_proofpack._experimental.falcon`,
:mod:`avm_proofpack._experimental.sumhash` and
:mod:`avm_proofpack._experimental.stateproof`. It is **not wired into**
``verify_bundle`` and changes no existing behavior. Importing it has no side
effects.

What this module solves (trust-root step A2)
--------------------------------------------
:mod:`.stateproof` already proves "the holder of an ephemeral Falcon key signed
the state-proof message". The missing piece it flagged as deferred was: **is
that ephemeral key actually committed under the participant's key commitment?**
That is a Merkle-membership proof over Algorand's ``merklesignature`` key tree,
which -- unlike the SHA-256 vector commitment in :mod:`avm_proofpack.merkle` --
uses **Sumhash512** nodes. This module supplies exactly that check.

The construction, from primary source (go-algorand)
---------------------------------------------------
* **Leaf.** ``crypto/merklesignature/committablePublicKeys.go``
  ``CommittablePublicKey.ToBeHashed`` returns HashID ``protocol.KeysInMSS``
  (= ``"KP"``, ``protocol/hash.go``) and the byte string

      LE16(CryptoPrimitivesID=0) || LE64(Round) || VerifyingKey

  where ``VerifyingKey`` is ``FalconVerifier.GetFixedLengthHashableRepresentation``
  (``crypto/falconWrapper.go``), i.e. the raw 1793-byte Falcon public key
  (the reveal's ``vkey.k``). ``CryptoPrimitivesID`` is ``uint16(0)``
  (``crypto/merklesignature/const.go``). The leaf *node* value is
  ``crypto.GenericHashObj(Sumhash, leaf)`` = ``Sumhash512("KP" || bytes)``.
* **Round.** ``Verifier.VerifyBytes`` (``crypto/merklesignature/``
  ``merkleSignatureScheme.go``) sets ``Round = FirstRoundInKeyLifetime(round)``
  ``= round - (round % KeyLifetime)`` (``KeyLifetime`` = the reveal's
  ``Participant.PK.lf``, 256 in fixtures). ``round`` is the state-proof round,
  i.e. the message's ``LastAttestedRound``.
* **Internal node.** ``crypto/merklearray/layer.go`` hashes a pair as
  ``Sumhash512("MA" || left || right)`` (HashID ``protocol.MerkleArrayNode`` =
  ``"MA"``), each child a fixed 64-byte digest; a missing child is 64 zero
  bytes. No length prefixes.
* **Index.** The key tree is a *vector commitment*
  (``BuildVectorCommitmentTree``); element index ``i`` sits at the
  bit-reversed position across ``tree_depth`` bits
  (``crypto/merklearray/vectorCommitmentArray.go``
  ``merkleTreeToVectorCommitmentIndex``: ``bits.Reverse64(i) >> (64-pathLen)``),
  identical to :mod:`avm_proofpack.merkle`'s convention but over Sumhash512.
* **Root.** must equal the participant's key commitment
  (``Participant.PK.cmt``, 64 bytes).

Real-data validation
--------------------
``tests/test_stateproof_membership.py`` reconstructs the leaf and verifies the
reveal's ``prf`` path to ``cmt`` for real captured reveals in every fixture
(Algorand-pay, Algorand-appl, Voi-appl). That success on real mainnet data is
the correctness proof for the encoding above.

What this is NOT
----------------
Membership proves the ephemeral key is committed under *this participant's* key
commitment. It still does NOT establish the state proof as a trust root: the
per-participant weights, the signed-weight/threshold check, the coin-based
reveal-position selection, and the voters-commitment anchoring to a trusted
round (steps A3-A5) are all still pending. Using this alone does NOT remove
node trust.
"""

from __future__ import annotations

import hmac
import struct

from .sumhash import DIGEST_SIZE, sumhash512

__all__ = [
    "CRYPTO_PRIMITIVES_ID",
    "KEYS_IN_MSS_DOMAIN",
    "MERKLE_ARRAY_NODE_DOMAIN",
    "NODE_SIZE",
    "MerkleSigError",
    "committable_public_key_hashrep",
    "committable_public_key_leaf",
    "sumhash_multiproof_root",
    "verify_sumhash_multiproof",
    "verify_sumhash_vector_commitment",
]

#: ``protocol.KeysInMSS`` (``protocol/hash.go``): HashID for a committable
#: ephemeral public key (the merklesignature key-tree leaf).
KEYS_IN_MSS_DOMAIN = b"KP"

#: ``protocol.MerkleArrayNode`` (``protocol/hash.go``): HashID for an internal
#: merklearray node.
MERKLE_ARRAY_NODE_DOMAIN = b"MA"

#: ``crypto/merklesignature/const.go`` ``CryptoPrimitivesID = uint16(0)``: the
#: 2-byte little-endian scheme id prefixed inside the leaf's hashable bytes.
CRYPTO_PRIMITIVES_ID = 0

#: merklesignature tree node/root size == Sumhash512 digest size.
NODE_SIZE = DIGEST_SIZE  # 64

# Raw 1793-byte Falcon-1024 public key length; imported lazily to avoid a hard
# import cycle is unnecessary (falcon has no back-dependency), but we keep the
# literal here so this module needs only sumhash at import time.
_FALCON_PUBLIC_KEY_SIZE = 1793


class MerkleSigError(ValueError):
    """Raised when a key-commitment membership input is malformed.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    still catch it. A malformed input is always a rejection, never a silent
    acceptance.
    """


def _require_uint(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MerkleSigError(f"{name} must be a non-negative integer")
    return value


def _require_bytes(name: str, value: object, exact_len: int | None = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise MerkleSigError(f"{name} must be bytes-like")
    raw = bytes(value)
    if exact_len is not None and len(raw) != exact_len:
        raise MerkleSigError(f"{name} must be {exact_len} bytes, got {len(raw)}")
    return raw


def _bit_reverse(index: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


def committable_public_key_hashrep(verifying_key: bytes, round_number: int) -> bytes:
    """Return the merklesignature leaf's hashable byte string (pre-hash).

    This is exactly ``CommittablePublicKey.ToBeHashed``'s output, WITH its
    ``"KP"`` HashID prefix prepended (the ``crypto.GenericHashObj`` preimage):

        "KP" || LE16(CryptoPrimitivesID=0) || LE64(round) || verifying_key

    ``verifying_key`` is the raw 1793-byte Falcon-1024 public key (the reveal's
    ``vkey.k``). Raises :class:`MerkleSigError` on a malformed field. This is a
    preimage, not a digest; :func:`committable_public_key_leaf` hashes it.
    """
    vk = _require_bytes(
        "verifying_key", verifying_key, _FALCON_PUBLIC_KEY_SIZE
    )
    rnd = _require_uint("round_number", round_number)
    if rnd > 0xFFFFFFFFFFFFFFFF:
        raise MerkleSigError("round_number exceeds uint64")
    return (
        KEYS_IN_MSS_DOMAIN
        + struct.pack("<H", CRYPTO_PRIMITIVES_ID)
        + struct.pack("<Q", rnd)
        + vk
    )


def committable_public_key_leaf(verifying_key: bytes, round_number: int) -> bytes:
    """Return the 64-byte Sumhash512 leaf-node value for an ephemeral key.

    Leaf node = ``Sumhash512(committable_public_key_hashrep(vk, round))`` --
    the value that enters the merklearray proof at the leaf position. Fail-
    closed: raises :class:`MerkleSigError` for a malformed key or round.
    """
    leaf = sumhash512(committable_public_key_hashrep(verifying_key, round_number))
    if len(leaf) != NODE_SIZE:  # pragma: no cover - sumhash512 is fixed-width
        raise MerkleSigError("internal: leaf hash is not 64 bytes")
    return leaf


def verify_sumhash_vector_commitment(
    leaf_hash: bytes,
    index: int,
    tree_depth: int,
    path: object,
    root: bytes,
) -> bool:
    """Verify a single-leaf Sumhash512 vector-commitment membership proof.

    Walks ``leaf_hash`` at element ``index`` up ``tree_depth`` levels using the
    bottom-up ``path`` sibling digests, hashing each parent as
    ``Sumhash512("MA" || left || right)`` (left/right chosen by the
    bit-reversed vector-commitment position), and returns whether the computed
    root equals ``root`` (the participant's ``cmt``).

    ``path`` may be a sequence of 64-byte digests (the reveal's ``prf.pth``) or
    a single concatenated ``tree_depth * 64`` byte string. Returns ``False`` on
    a root mismatch; raises :class:`MerkleSigError` for structurally invalid
    input so callers can distinguish "proof disagrees" from "proof malformed".
    Never returns ``True`` on doubt.
    """
    leaf_hash = _require_bytes("leaf_hash", leaf_hash, NODE_SIZE)
    root = _require_bytes("root", root, NODE_SIZE)
    if not isinstance(tree_depth, int) or isinstance(tree_depth, bool):
        raise MerkleSigError("tree_depth must be an integer")
    if not 0 <= tree_depth <= 64:
        raise MerkleSigError(f"tree depth {tree_depth} out of range [0, 64]")

    siblings = _normalize_path(path, tree_depth)
    index = _require_uint("index", index)
    if index >= (1 << tree_depth):
        raise MerkleSigError(
            f"index {index} out of range for tree depth {tree_depth}"
        )

    position = _bit_reverse(index, tree_depth)
    node = leaf_hash
    for level in range(tree_depth):
        sibling = siblings[level]
        if position & 1:
            node = sumhash512(MERKLE_ARRAY_NODE_DOMAIN + sibling + node)
        else:
            node = sumhash512(MERKLE_ARRAY_NODE_DOMAIN + node + sibling)
        position >>= 1

    return hmac.compare_digest(node, root)


def _normalize_path(path: object, tree_depth: int) -> list[bytes]:
    """Coerce ``path`` to a list of exactly ``tree_depth`` 64-byte siblings.

    Accepts a list/tuple of 64-byte digests or a single concatenated byte
    string of length ``tree_depth * 64``. Raises :class:`MerkleSigError` on any
    length/type deviation.
    """
    if isinstance(path, (bytes, bytearray, memoryview)):
        raw = bytes(path)
        if len(raw) != tree_depth * NODE_SIZE:
            raise MerkleSigError(
                f"concatenated path length {len(raw)} does not match tree depth "
                f"{tree_depth} (expected {tree_depth * NODE_SIZE} bytes)"
            )
        return [raw[i * NODE_SIZE : (i + 1) * NODE_SIZE] for i in range(tree_depth)]
    if isinstance(path, (list, tuple)):
        if len(path) != tree_depth:
            raise MerkleSigError(
                f"path has {len(path)} siblings but tree depth is {tree_depth}"
            )
        return [_require_bytes(f"path[{i}]", s, NODE_SIZE) for i, s in enumerate(path)]
    raise MerkleSigError("path must be a byte string or a sequence of digests")


def _coerce_digest_list(path: object) -> list[bytes]:
    """Coerce a proof ``Path`` to a list of 64-byte digests (any count).

    Accepts a list/tuple of 64-byte digests or a single concatenated byte
    string whose length is a multiple of 64. Unlike :func:`_normalize_path`
    (single-leaf, exactly ``tree_depth`` siblings) a multi-element proof's Path
    length is variable, so no count is enforced here. Raises
    :class:`MerkleSigError` on any type/length deviation.
    """
    if isinstance(path, (bytes, bytearray, memoryview)):
        raw = bytes(path)
        if len(raw) % NODE_SIZE != 0:
            raise MerkleSigError(
                f"concatenated path length {len(raw)} is not a multiple of "
                f"{NODE_SIZE}"
            )
        return [raw[i * NODE_SIZE : (i + 1) * NODE_SIZE] for i in range(len(raw) // NODE_SIZE)]
    if isinstance(path, (list, tuple)):
        return [_require_bytes(f"path[{i}]", s, NODE_SIZE) for i, s in enumerate(path)]
    raise MerkleSigError("path must be a byte string or a sequence of digests")


def sumhash_multiproof_root(
    leaves_by_position: object,
    path: object,
    tree_depth: int,
) -> bytes:
    """Reconstruct the root of a multi-element Sumhash512 vector commitment.

    Implements go-algorand ``crypto/merklearray`` ``VerifyVectorCommitment`` ->
    ``Verify`` for a *set* of leaves. ``VerifyVectorCommitment`` first maps every
    element index ``i`` to its vector-commitment position
    ``bits.Reverse64(i) >> (64-treeDepth)`` (``convertIndexes``); ``Verify`` then
    hashes each element, builds the sorted first partial layer
    (``buildFirstPartialLayer``) and walks up ``treeDepth`` levels
    (``partialLayer.up``). At each level, ascending by position, a node's sibling
    is taken from the adjacent revealed node when present, otherwise consumed
    FIFO from the proof ``Path`` (``siblings.get`` with a nil tree); the parent
    is ``Sumhash512("MA" || left || right)`` with left/right chosen by position
    parity. Returns the single reconstructed 64-byte root.

    ``leaves_by_position`` is a mapping ``element_index -> 64-byte leaf hash``
    (the leaves already hashed with their own domain, e.g. ``sps``/``spp``).
    Fail-closed: raises :class:`MerkleSigError` if the proof is structurally
    malformed, if positions are out of range or collide, if the Path is
    exhausted early, or if hints remain unconsumed (an over-long Path). Callers
    compare the returned root against the expected commitment with a
    constant-time equality.
    """
    if not isinstance(tree_depth, int) or isinstance(tree_depth, bool):
        raise MerkleSigError("tree_depth must be an integer")
    if not 0 <= tree_depth <= 64:
        raise MerkleSigError(f"tree depth {tree_depth} out of range [0, 64]")
    if not isinstance(leaves_by_position, dict) or not leaves_by_position:
        raise MerkleSigError("leaves_by_position must be a non-empty mapping")

    hints = _coerce_digest_list(path)
    capacity = 1 << tree_depth
    layer: list[list] = []
    for position, leaf in leaves_by_position.items():
        pos = _require_uint("position", position)
        if pos >= capacity:
            raise MerkleSigError(
                f"position {pos} out of range for tree depth {tree_depth}"
            )
        vc_pos = _bit_reverse(pos, tree_depth)
        layer.append([vc_pos, _require_bytes("leaf", leaf, NODE_SIZE)])
    layer.sort(key=lambda item: item[0])
    for i in range(1, len(layer)):
        if layer[i][0] == layer[i - 1][0]:
            raise MerkleSigError("duplicate leaf position")

    hint_index = 0
    for _level in range(tree_depth):
        parents: list[list] = []
        i = 0
        while i < len(layer):
            pos, node = layer[i]
            sibling_pos = pos ^ 1
            if i + 1 < len(layer) and layer[i + 1][0] == sibling_pos:
                sibling = layer[i + 1][1]
                i += 2
            else:
                if hint_index >= len(hints):
                    raise MerkleSigError("proof path exhausted before the root")
                sibling = hints[hint_index]
                hint_index += 1
                i += 1
            if pos & 1:
                parent = sumhash512(MERKLE_ARRAY_NODE_DOMAIN + sibling + node)
            else:
                parent = sumhash512(MERKLE_ARRAY_NODE_DOMAIN + node + sibling)
            parents.append([pos >> 1, parent])
        layer = parents

    if hint_index != len(hints):
        raise MerkleSigError("proof path has unconsumed sibling hints")
    if len(layer) != 1 or layer[0][0] != 0:
        raise MerkleSigError("proof did not reduce to a single root")
    return layer[0][1]


def verify_sumhash_multiproof(
    root: bytes,
    leaves_by_position: object,
    path: object,
    tree_depth: int,
) -> bool:
    """Verify a multi-element Sumhash512 vector-commitment proof. Fail-closed.

    Returns ``True`` iff :func:`sumhash_multiproof_root` reconstructs exactly
    ``root`` from ``leaves_by_position`` and ``path``. A root mismatch returns
    ``False``; a structurally malformed proof (:class:`MerkleSigError`) also
    folds to ``False``. Never returns ``True`` on doubt.
    """
    expected = _require_bytes("root", root, NODE_SIZE)
    try:
        computed = sumhash_multiproof_root(leaves_by_position, path, tree_depth)
    except MerkleSigError:
        return False
    return hmac.compare_digest(computed, expected)

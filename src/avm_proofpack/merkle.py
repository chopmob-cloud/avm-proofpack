"""Vector commitment (Merkle) proof verification, go-algorand semantics.

Algorand's SHA-256 transaction commitment and the state proof block-headers
commitment are *vector commitments*: Merkle trees over a power-of-two array
in which element index ``i`` is stored at the bit-reversed position of ``i``
across ``tree_depth`` bits (go-algorand
``crypto/merklearray/vectorCommitmentArray.go``,
``merkleTreeToVectorCommitmentIndex``:
``bits.Reverse64(index) >> (64 - pathLen)``). Positions beyond the array
length hold the fixed bottom leaf ``sha256("MB")``.

An internal node is ``sha256("MA" || left || right)`` with no length
prefixes (``crypto/merklearray/layer.go``); a missing child is 32 zero
bytes. Single-leaf proofs, as served by algod's proof endpoints via
``GetConcatenatedProof``, are the authentication path's sibling hashes
ordered bottom-up, 32 bytes each.
"""

from __future__ import annotations

import hmac

from .hashes import DOMAIN_MERKLE_ARRAY_NODE, sha256

__all__ = ["ProofError", "verify_vector_commitment"]

_DIGEST_SIZE = 32


class ProofError(ValueError):
    """Raised when a proof is structurally invalid (distinct from a mismatch)."""


def _bit_reverse(index: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


def verify_vector_commitment(
    leaf_hash: bytes,
    index: int,
    tree_depth: int,
    proof: bytes,
    root: bytes,
) -> bool:
    """Return whether ``leaf_hash`` at element ``index`` proves up to ``root``.

    ``proof`` is the concatenated bottom-up sibling path. Returns False on a
    root mismatch; raises :class:`ProofError` for structurally invalid input
    so callers can distinguish "proof disagrees" from "proof malformed".
    """
    if len(leaf_hash) != _DIGEST_SIZE:
        raise ProofError(f"leaf hash must be {_DIGEST_SIZE} bytes, got {len(leaf_hash)}")
    if len(root) != _DIGEST_SIZE:
        raise ProofError(f"root must be {_DIGEST_SIZE} bytes, got {len(root)}")
    if not 0 <= tree_depth <= 64:
        raise ProofError(f"tree depth {tree_depth} out of range [0, 64]")
    if len(proof) != tree_depth * _DIGEST_SIZE:
        raise ProofError(
            f"proof length {len(proof)} does not match tree depth {tree_depth} "
            f"(expected {tree_depth * _DIGEST_SIZE} bytes)"
        )
    if index < 0 or index >= (1 << tree_depth):
        raise ProofError(f"index {index} out of range for tree depth {tree_depth}")

    position = _bit_reverse(index, tree_depth)
    node = leaf_hash
    for level in range(tree_depth):
        sibling = proof[level * _DIGEST_SIZE : (level + 1) * _DIGEST_SIZE]
        if position & 1:
            node = sha256(DOMAIN_MERKLE_ARRAY_NODE + sibling + node)
        else:
            node = sha256(DOMAIN_MERKLE_ARRAY_NODE + node + sibling)
        position >>= 1

    return hmac.compare_digest(node, root)

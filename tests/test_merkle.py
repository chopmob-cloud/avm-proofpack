"""Vector commitment verification against hand-computed trees."""

import pytest

from avm_proofpack.hashes import (
    DOMAIN_MERKLE_ARRAY_NODE,
    DOMAIN_VC_BOTTOM_LEAF,
    sha256,
)
from avm_proofpack.merkle import ProofError, verify_vector_commitment


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(DOMAIN_MERKLE_ARRAY_NODE + left + right)


BOTTOM = sha256(DOMAIN_VC_BOTTOM_LEAF)


def _leaves(n: int) -> list[bytes]:
    return [sha256(b"leaf-%d" % i) for i in range(n)]


def _bit_reverse(index: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


def _build_vc(leaves: list[bytes], depth: int) -> tuple[bytes, list[list[bytes]]]:
    """Build a vector commitment: leaves placed at bit-reversed positions,
    padded with the MB bottom leaf; return (root, levels bottom-up)."""
    size = 1 << depth
    bottom = [BOTTOM] * size
    for i, leaf in enumerate(leaves):
        bottom[_bit_reverse(i, depth)] = leaf
    levels = [bottom]
    current = bottom
    while len(current) > 1:
        current = [
            _node(current[i], current[i + 1]) for i in range(0, len(current), 2)
        ]
        levels.append(current)
    return current[0], levels


def _proof_for(index: int, depth: int, levels: list[list[bytes]]) -> bytes:
    position = _bit_reverse(index, depth)
    path = b""
    for level in range(depth):
        path += levels[level][position ^ 1]
        position >>= 1
    return path


@pytest.mark.parametrize("leaf_count,depth", [(1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (256, 8)])
def test_all_leaves_prove(leaf_count, depth):
    leaves = _leaves(leaf_count)
    root, levels = _build_vc(leaves, depth)
    for index, leaf in enumerate(leaves):
        proof = _proof_for(index, depth, levels)
        assert verify_vector_commitment(leaf, index, depth, proof, root)


def test_wrong_root_fails():
    leaves = _leaves(4)
    root, levels = _build_vc(leaves, 2)
    proof = _proof_for(1, 2, levels)
    assert not verify_vector_commitment(leaves[1], 1, 2, proof, sha256(b"not-root"))


def test_wrong_index_fails():
    leaves = _leaves(4)
    root, levels = _build_vc(leaves, 2)
    proof = _proof_for(1, 2, levels)
    assert not verify_vector_commitment(leaves[1], 2, 2, proof, root)


def test_tampered_proof_fails():
    leaves = _leaves(4)
    root, levels = _build_vc(leaves, 2)
    proof = bytearray(_proof_for(1, 2, levels))
    proof[0] ^= 0x01
    assert not verify_vector_commitment(leaves[1], 1, 2, bytes(proof), root)


def test_structural_errors_raise():
    leaves = _leaves(2)
    root, levels = _build_vc(leaves, 1)
    proof = _proof_for(0, 1, levels)
    with pytest.raises(ProofError):
        verify_vector_commitment(leaves[0][:-1], 0, 1, proof, root)  # short leaf
    with pytest.raises(ProofError):
        verify_vector_commitment(leaves[0], 0, 1, proof[:-1], root)  # short proof
    with pytest.raises(ProofError):
        verify_vector_commitment(leaves[0], 0, 2, proof, root)  # depth mismatch
    with pytest.raises(ProofError):
        verify_vector_commitment(leaves[0], 2, 1, proof, root)  # index >= 2**depth
    with pytest.raises(ProofError):
        verify_vector_commitment(leaves[0], 0, 65, b"\x00" * (65 * 32), root)


def test_depth_zero_single_element():
    leaves = _leaves(1)
    root, _ = _build_vc(leaves, 0)
    assert root == leaves[0]
    assert verify_vector_commitment(leaves[0], 0, 0, b"", root)
    assert not verify_vector_commitment(sha256(b"other"), 0, 0, b"", root)

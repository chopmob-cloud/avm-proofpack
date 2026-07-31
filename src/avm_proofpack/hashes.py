"""Hash primitives and domain separators used by Algorand consensus objects.

Every hashed Algorand object is domain-separated: the preimage is the ASCII
HashID prefix immediately followed by the object's canonical encoding
(go-algorand ``crypto/util.go`` ``HashRep``). The constants below are taken
verbatim from go-algorand ``protocol/hash.go``.
"""

from __future__ import annotations

import base64
import hashlib

__all__ = [
    "DOMAIN_BLOCK_HEADER",
    "DOMAIN_LIGHT_BLOCK_HEADER",
    "DOMAIN_MERKLE_ARRAY_NODE",
    "DOMAIN_SIGNED_TXN_IN_BLOCK",
    "DOMAIN_TRANSACTION",
    "DOMAIN_TXN_MERKLE_LEAF",
    "DOMAIN_VC_BOTTOM_LEAF",
    "sha256",
    "sha512_256",
    "txid_to_bytes",
    "txid_from_bytes",
]

DOMAIN_BLOCK_HEADER = b"BH"  # protocol.BlockHeader
DOMAIN_LIGHT_BLOCK_HEADER = b"B256"  # protocol.BlockHeader256
DOMAIN_MERKLE_ARRAY_NODE = b"MA"  # protocol.MerkleArrayNode
DOMAIN_SIGNED_TXN_IN_BLOCK = b"STIB"  # protocol.SignedTxnInBlock
DOMAIN_TRANSACTION = b"TX"  # protocol.Transaction
DOMAIN_TXN_MERKLE_LEAF = b"TL"  # protocol.TxnMerkleLeaf
DOMAIN_VC_BOTTOM_LEAF = b"MB"  # protocol.MerkleVectorCommitmentBottomLeaf


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512_256(data: bytes) -> bytes:
    return hashlib.new("sha512_256", data).digest()


def txid_to_bytes(txid: str) -> bytes:
    """Decode a 52-character base32 transaction id to its 32-byte digest."""
    if len(txid) != 52:
        raise ValueError(f"transaction id must be 52 base32 characters, got {len(txid)}")
    try:
        raw = base64.b32decode(txid + "====")
    except Exception as exc:
        raise ValueError(f"invalid base32 transaction id: {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"decoded transaction id is {len(raw)} bytes, expected 32")
    return raw


def txid_from_bytes(digest: bytes) -> str:
    """Encode a 32-byte digest as the canonical 52-character base32 txid."""
    if len(digest) != 32:
        raise ValueError(f"transaction id digest must be 32 bytes, got {len(digest)}")
    return base64.b32encode(digest).decode("ascii").rstrip("=")

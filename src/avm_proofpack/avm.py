"""AVM (Algorand/Voi) consensus object reconstruction.

Everything here rebuilds hashes from canonical bytes captured out of a real
block, so an offline verifier recomputes every link itself rather than
trusting values quoted by a node.

Sources (go-algorand):
- ``data/bookkeeping/block.go`` ``DecodeSignedTxn``: genesis restoration.
- ``data/bookkeeping/txn_merkle.go``: SHA-256 transaction leaf =
  ``sha256("TL" || sha256("TX"||txn) || sha256("STIB"||stib))``.
- ``data/bookkeeping/lightBlockHeader.go``: LightBlockHeader codec tags
  ``0`` (seed), ``1`` (block hash), ``r``, ``gh``, ``tc``; HashID ``B256``.
- ``config/consensus.go`` ``StateProofBlockHashInLightHeader`` (v39+): the
  light header carries the block hash; before v39 it carried the seed.
"""

from __future__ import annotations

from . import mpack
from .hashes import (
    DOMAIN_BLOCK_HEADER,
    DOMAIN_LIGHT_BLOCK_HEADER,
    DOMAIN_SIGNED_TXN_IN_BLOCK,
    DOMAIN_TRANSACTION,
    sha256,
    sha512_256,
)

__all__ = [
    "ReconstructionError",
    "block_hash",
    "light_block_header_leaf",
    "stib_hash_sha256",
    "transaction_from_stib",
    "txn_hashes",
]


class ReconstructionError(ValueError):
    """Raised when block data cannot be reconstructed coherently."""


def transaction_from_stib(stib: dict, block_header: dict) -> dict:
    """Rebuild the standalone Transaction map from a SignedTxnInBlock.

    Blocks store transactions with genesis fields stripped
    (``EncodeSignedTxn``); the transaction id is computed over the restored
    form (``DecodeSignedTxn``):

    - ``gen`` (GenesisID) is restored iff the stib's ``hgi`` flag is set.
    - ``gh`` (GenesisHash) is restored when the stib's ``hgh`` flag is set,
      and unconditionally under ``RequireGenesisHash``. Every protocol
      version that produces a SHA-256 transaction commitment (consensus
      v34+) has ``RequireGenesisHash`` true, and this library only ever
      handles such rounds, so restoration is unconditional here.
    """
    signed_txn = stib.get("txn")
    if not isinstance(signed_txn, dict):
        raise ReconstructionError("stib has no 'txn' map")

    txn = dict(signed_txn)

    if stib.get("hgi"):
        genesis_id = block_header.get("gen")
        if not isinstance(genesis_id, str):
            raise ReconstructionError("stib sets hgi but block header has no 'gen'")
        txn["gen"] = genesis_id

    genesis_hash = block_header.get("gh")
    if not isinstance(genesis_hash, bytes) or len(genesis_hash) != 32:
        raise ReconstructionError("block header 'gh' missing or not 32 bytes")
    if "gh" in txn and txn["gh"] != genesis_hash:
        raise ReconstructionError(
            "stib transaction carries a genesis hash different from the block's"
        )
    txn["gh"] = genesis_hash

    return txn


def txn_hashes(txn: dict) -> tuple[bytes, bytes]:
    """Return (sha512_256 txid digest, sha256 txid digest) for a Transaction.

    The familiar base32 transaction id displays the SHA-512/256 digest; the
    SHA-256 transaction commitment's leaves use the SHA-256 digest of the
    same ``"TX" || canonical(txn)`` preimage (``Txid.IDSha256``).
    """
    preimage = DOMAIN_TRANSACTION + mpack.encode_canonical(txn)
    return sha512_256(preimage), sha256(preimage)


def stib_hash_sha256(stib_bytes: bytes) -> bytes:
    """SHA-256 hash of a canonical SignedTxnInBlock (``HashSHA256``)."""
    return sha256(DOMAIN_SIGNED_TXN_IN_BLOCK + stib_bytes)


def block_hash(block_header_bytes: bytes) -> bytes:
    """The block hash: ``sha512_256("BH" || canonical(header))``."""
    return sha512_256(DOMAIN_BLOCK_HEADER + block_header_bytes)


def light_block_header_leaf(
    round_number: int,
    genesis_hash: bytes,
    txn_commitment_sha256: bytes,
    *,
    block_hash_digest: bytes | None = None,
    seed: bytes | None = None,
) -> bytes:
    """Leaf hash of a LightBlockHeader in the block-headers commitment.

    Exactly one of ``block_hash_digest`` (consensus v39+,
    ``StateProofBlockHashInLightHeader``) or ``seed`` (pre-v39) must be
    given. Fields are canonically encoded under their codec tags with
    zero values omitted (``omitempty``), then hashed as
    ``sha256("B256" || encoding)``.
    """
    if (block_hash_digest is None) == (seed is None):
        raise ReconstructionError(
            "exactly one of block_hash_digest or seed must be provided"
        )
    variant_key, variant_value = (
        ("1", block_hash_digest) if block_hash_digest is not None else ("0", seed)
    )
    assert variant_value is not None
    if len(variant_value) != 32:
        raise ReconstructionError(
            f"light header field '{variant_key}' must be 32 bytes, "
            f"got {len(variant_value)}"
        )
    if len(genesis_hash) != 32:
        raise ReconstructionError("genesis hash must be 32 bytes")
    if len(txn_commitment_sha256) != 32:
        raise ReconstructionError("sha256 txn commitment must be 32 bytes")
    if round_number <= 0:
        raise ReconstructionError(f"round must be positive, got {round_number}")

    light_header: dict[str, object] = {
        variant_key: variant_value,
        "gh": genesis_hash,
        "r": round_number,
        "tc": txn_commitment_sha256,
    }
    # omitempty: an all-zero variant value would be omitted by go-codec. A
    # zero block hash or zero seed cannot occur in a real chain; reject
    # rather than silently encode a preimage go-algorand would never emit.
    if variant_value == b"\x00" * 32:
        raise ReconstructionError(f"light header field '{variant_key}' is all zero")

    return sha256(DOMAIN_LIGHT_BLOCK_HEADER + mpack.encode_canonical(light_header))

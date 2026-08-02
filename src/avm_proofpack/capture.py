"""Capture a proofpack bundle from an algod node, with hard integrity gates.

Capture is the only networked step, and it distrusts its own source: every
value the node reports is recomputed from canonical bytes before the bundle
is written, and the finished bundle must pass full offline verification
before it is returned. A bundle that exists, verifies.

Gates, in order:

1. Codec fidelity: the fetched block round-trips byte-identically through
   this library's msgpack codec, proving the codec is faithful for the
   exact bytes the evidence depends on.
2. Stib hash: the canonical stib re-hashes to the node's reported stibhash.
3. Transaction identity: the restored transaction hashes to the caller's
   txid.
4. Block linkage: the derived block hash equals the next block's ``prev``.
5. Full offline verification of the assembled bundle.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from . import mpack
from .avm import (
    ReconstructionError,
    block_hash,
    stib_hash_sha256,
    transaction_from_stib,
    txn_hashes,
)
from .bundle import (
    FORMAT_NAME,
    FORMAT_VERSION,
    VARIANT_BLOCK_HASH,
    VARIANT_SEED,
    Bundle,
)
from .client import NodeClient, NodeNotFound
from .hashes import txid_from_bytes, txid_to_bytes
from .verify import VerificationError, verify_bundle

__all__ = ["CaptureError", "NotYetProvable", "capture"]


class CaptureError(RuntimeError):
    """Capture failed an integrity gate or the node returned unusable data."""


class NotYetProvable(CaptureError):
    """No state proof covers the round yet; retry after the interval closes."""


def _b64field(data: dict, key: str, context: str) -> bytes:
    value = data.get(key)
    if not isinstance(value, str):
        raise CaptureError(f"{context}: missing field {key!r}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise CaptureError(f"{context}: field {key!r} is not base64: {exc}") from exc


def _uintfield(data: dict, key: str, context: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CaptureError(f"{context}: missing or invalid integer field {key!r}")
    return value


def capture(node_url: str, txid: str, round_number: int, *, timeout: float = 30.0,
           opener=None, validator=None) -> dict:
    """Capture and return a verified bundle dict for ``txid`` in ``round_number``."""
    # Validate before either value is interpolated into a URL path.
    txid_to_bytes(txid)  # raises ValueError unless 52-char base32 of 32 bytes
    if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number <= 0:
        raise CaptureError(f"round must be a positive integer, got {round_number!r}")

    client = NodeClient(node_url, timeout=timeout, opener=opener, validator=validator)

    # State proof covering the round (404 with a specific message until the
    # interval is attested, surfaced as NotYetProvable for callers to poll).
    try:
        state_proof_response = client.get_json(f"/v2/stateproofs/{round_number}")
    except NodeNotFound as exc:
        raise NotYetProvable(
            f"no state proof covers round {round_number} yet: {exc}"
        ) from exc
    message = state_proof_response.get("Message")
    if not isinstance(message, dict):
        raise CaptureError("state proof response has no Message object")
    first_attested = _uintfield(message, "FirstAttestedRound", "state proof message")
    last_attested = _uintfield(message, "LastAttestedRound", "state proof message")
    if not first_attested <= round_number <= last_attested:
        raise CaptureError(
            f"node returned state proof for interval [{first_attested}, "
            f"{last_attested}], which does not cover round {round_number}"
        )
    headers_commitment = _b64field(
        message, "BlockHeadersCommitment", "state proof message"
    )
    voters_commitment = _b64field(message, "VotersCommitment", "state proof message")
    ln_proven_weight = _uintfield(message, "LnProvenWeight", "state proof message")
    state_proof_b64 = state_proof_response.get("StateProof")
    if not isinstance(state_proof_b64, str):
        raise CaptureError("state proof response has no StateProof field")
    try:
        base64.b64decode(state_proof_b64, validate=True)
    except Exception as exc:
        raise CaptureError(f"node's StateProof field is not valid base64: {exc}") from exc

    # Transaction proof (SHA-256 tree) and light block header proof.
    txn_proof_response = client.get_json(
        f"/v2/blocks/{round_number}/transactions/{txid}/proof"
        "?hashtype=sha256&format=json"
    )
    if txn_proof_response.get("hashtype") != "sha256":
        raise CaptureError(
            f"node returned hashtype {txn_proof_response.get('hashtype')!r}, "
            "expected sha256"
        )
    txn_index = _uintfield(txn_proof_response, "idx", "transaction proof")
    txn_depth = _uintfield(txn_proof_response, "treedepth", "transaction proof")
    txn_proof_bytes = _b64field(txn_proof_response, "proof", "transaction proof")
    reported_stibhash = _b64field(txn_proof_response, "stibhash", "transaction proof")

    light_proof_response = client.get_json(
        f"/v2/blocks/{round_number}/lightheader/proof"
    )
    light_depth = _uintfield(light_proof_response, "treedepth", "light header proof")
    light_proof_bytes = _b64field(light_proof_response, "proof", "light header proof")

    # The block itself, in canonical msgpack.
    block_response_bytes = client.get_bytes(
        f"/v2/blocks/{round_number}?format=msgpack"
    )
    try:
        decoded_response = mpack.decode(block_response_bytes)
        # Gate 1: codec fidelity over the entire response.
        reencoded = mpack.encode_canonical(decoded_response)
    except (mpack.DecodeError, mpack.EncodeError) as exc:
        raise CaptureError(f"node returned undecodable block msgpack: {exc}") from exc
    if reencoded != block_response_bytes:
        raise CaptureError(
            "codec fidelity gate failed: block response does not round-trip "
            "byte-identically; refusing to build evidence with this codec"
        )
    if not isinstance(decoded_response, dict):
        raise CaptureError("block response is not a map")
    block = decoded_response.get("block")
    if not isinstance(block, dict):
        raise CaptureError("block response has no 'block' map")
    header = {key: value for key, value in block.items() if key != "txns"}
    payset = block.get("txns", [])
    if not isinstance(payset, list):
        raise CaptureError("block payset is not an array")
    if txn_index >= len(payset):
        raise CaptureError(
            f"transaction proof idx {txn_index} out of range for payset of "
            f"{len(payset)}"
        )
    stib = payset[txn_index]
    if not isinstance(stib, dict):
        raise CaptureError(f"payset entry {txn_index} is not a map")

    try:
        stib_bytes = mpack.encode_canonical(stib)
        header_bytes = mpack.encode_canonical(header)
    except mpack.EncodeError as exc:
        raise CaptureError(f"node block is not canonically encodable: {exc}") from exc

    # Gate 2: our canonical stib hashes to the node's reported stibhash.
    if stib_hash_sha256(stib_bytes) != reported_stibhash:
        raise CaptureError(
            "stib hash gate failed: canonical re-encoding does not reproduce "
            "the node's stibhash"
        )

    # Gate 3: the restored transaction is the one the caller asked about.
    try:
        txn = transaction_from_stib(stib, header)
        txid_512, _ = txn_hashes(txn)
    except (ReconstructionError, mpack.EncodeError) as exc:
        raise CaptureError(f"could not reconstruct transaction: {exc}") from exc
    derived_txid = txid_from_bytes(txid_512)
    if derived_txid != txid:
        raise CaptureError(
            f"transaction identity gate failed: payset entry {txn_index} is "
            f"{derived_txid}, not {txid}"
        )

    # Gate 4: derived block hash must be the next block's prev pointer.
    next_block_bytes = client.get_bytes(
        f"/v2/blocks/{round_number + 1}?format=msgpack"
    )
    try:
        next_decoded = mpack.decode(next_block_bytes)
    except mpack.DecodeError as exc:
        raise CaptureError(f"node returned undecodable next block: {exc}") from exc
    if not isinstance(next_decoded, dict) or not isinstance(
        next_decoded.get("block"), dict
    ):
        raise CaptureError("next block response is malformed")
    next_prev = next_decoded["block"].get("prev")
    derived_block_hash = block_hash(header_bytes)
    if next_prev != derived_block_hash:
        raise CaptureError(
            "block linkage gate failed: derived block hash does not match the "
            "next block's prev pointer"
        )

    genesis_hash = header.get("gh")
    genesis_id = header.get("gen")
    if not isinstance(genesis_hash, bytes) or not isinstance(genesis_id, str):
        raise CaptureError("block header lacks genesis hash or genesis id")

    bundle_dict = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "chain": {
            "genesis_id": genesis_id,
            "genesis_hash_b64": base64.b64encode(genesis_hash).decode("ascii"),
        },
        "transaction": {"txid": txid, "round": round_number},
        "block_header_msgpack_b64": base64.b64encode(header_bytes).decode("ascii"),
        "stib_msgpack_b64": base64.b64encode(stib_bytes).decode("ascii"),
        "txn_proof": {
            "index": txn_index,
            "tree_depth": txn_depth,
            "proof_b64": base64.b64encode(txn_proof_bytes).decode("ascii"),
        },
        "light_header_proof": {
            "tree_depth": light_depth,
            "proof_b64": base64.b64encode(light_proof_bytes).decode("ascii"),
        },
        "state_proof_message": {
            "block_headers_commitment_b64": base64.b64encode(
                headers_commitment
            ).decode("ascii"),
            "first_attested_round": first_attested,
            "last_attested_round": last_attested,
            "ln_proven_weight": ln_proven_weight,
            "voters_commitment_b64": base64.b64encode(voters_commitment).decode(
                "ascii"
            ),
        },
        "state_proof_msgpack_b64": state_proof_b64,
        "meta": {
            "light_header_variant": VARIANT_BLOCK_HASH,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_node": node_url,
        },
    }

    # Gate 5: the assembled bundle must verify offline before it is returned.
    # The light header variant is block_hash on every consensus version from
    # v39 on; if verification fails there on an older-protocol chain, retry
    # once with the seed variant and record whichever the commitment confirms.
    try:
        verify_bundle(Bundle.from_dict(bundle_dict))
    except VerificationError as exc:
        if exc.check not in ("light-header", "light-header-proof"):
            raise  # a non-variant failure must surface as itself
        bundle_dict["meta"]["light_header_variant"] = VARIANT_SEED
        verify_bundle(Bundle.from_dict(bundle_dict))  # raises to caller if wrong

    return bundle_dict

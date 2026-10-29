"""Proofpack bundle format: a self-contained, offline-verifiable evidence file.

A bundle carries everything needed to re-derive the chain of commitments for
one transaction, from raw canonical bytes up to the state proof message,
with no network access and no values taken on trust from the capturing
node. See SPEC.md for the format definition.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["BundleError", "Bundle", "FORMAT_NAME", "FORMAT_VERSION"]

FORMAT_NAME = "avm-proofpack"
FORMAT_VERSION = 1

VARIANT_BLOCK_HASH = "block_hash"
VARIANT_SEED = "seed"


class BundleError(ValueError):
    """Raised when a bundle file is structurally invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BundleError(message)


# Per-field decoded-size ceilings. Real values sit far below these; the caps
# bound worst-case allocation from a hostile bundle whose file-size check was
# bypassed (e.g. constructed via from_dict rather than load).
_MAX_FIELD_BYTES = 2 * 1024 * 1024


def _b64(data: dict, key: str, *, expect_len: int | None = None,
         max_len: int = _MAX_FIELD_BYTES) -> bytes:
    value = data.get(key)
    _require(isinstance(value, str), f"missing or non-string field: {key}")
    _require(len(value) <= max_len * 4 // 3 + 4, f"field {key} is too large")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise BundleError(f"field {key} is not valid base64: {exc}") from exc
    if expect_len is not None:
        _require(len(raw) == expect_len, f"field {key} must be {expect_len} bytes")
    _require(len(raw) <= max_len, f"field {key} exceeds {max_len} bytes")
    return raw


def _uint(data: dict, key: str) -> int:
    value = data.get(key)
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
             f"missing or invalid non-negative integer field: {key}")
    return value


@dataclass(frozen=True)
class Bundle:
    """Validated, decoded view of a proofpack bundle."""

    genesis_id: str
    genesis_hash: bytes
    txid: str
    round: int
    block_header_bytes: bytes
    stib_bytes: bytes
    txn_proof_index: int
    txn_proof_depth: int
    txn_proof: bytes
    light_header_proof_depth: int
    light_header_proof: bytes
    block_headers_commitment: bytes
    first_attested_round: int
    last_attested_round: int
    ln_proven_weight: int
    voters_commitment: bytes
    state_proof_bytes: bytes
    light_header_variant: str
    captured_at: str
    source_node: str
    #: The full StateProof (reveals, signature weight, signature). Optional: bundles
    #: captured before 2026-10-29 carry only the message, and a bundle without this
    #: can never reach the stake-attested tier.
    state_proof_proof_bytes: bytes | None = None
    #: The PREVIOUS interval's message, whose VotersCommitment and LnProvenWeight
    #: authenticate this proof's signing set and weight bound. Never the message
    #: carried in this bundle, which is authored by the proof builder.
    previous_message: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Bundle":
        _require(isinstance(data, dict), "bundle must be a JSON object")
        _require(data.get("format") == FORMAT_NAME,
                 f"format must be {FORMAT_NAME!r}, got {data.get('format')!r}")
        _require(data.get("version") == FORMAT_VERSION,
                 f"unsupported bundle version {data.get('version')!r}")

        chain = data.get("chain")
        _require(isinstance(chain, dict), "missing chain section")
        genesis_id = chain.get("genesis_id")
        _require(isinstance(genesis_id, str) and genesis_id != "",
                 "chain.genesis_id must be a non-empty string")

        transaction = data.get("transaction")
        _require(isinstance(transaction, dict), "missing transaction section")
        txid = transaction.get("txid")
        _require(isinstance(txid, str) and len(txid) == 52,
                 "transaction.txid must be a 52-character base32 string")

        txn_proof = data.get("txn_proof")
        _require(isinstance(txn_proof, dict), "missing txn_proof section")
        light_proof = data.get("light_header_proof")
        _require(isinstance(light_proof, dict), "missing light_header_proof section")
        message = data.get("state_proof_message")
        _require(isinstance(message, dict), "missing state_proof_message section")
        meta = data.get("meta")
        _require(isinstance(meta, dict), "missing meta section")
        variant = meta.get("light_header_variant")
        _require(variant in (VARIANT_BLOCK_HASH, VARIANT_SEED),
                 "meta.light_header_variant must be 'block_hash' or 'seed'")
        captured_at = meta.get("captured_at")
        _require(isinstance(captured_at, str), "meta.captured_at must be a string")
        source_node = meta.get("source_node")
        _require(isinstance(source_node, str), "meta.source_node must be a string")

        first = _uint(message, "first_attested_round")
        last = _uint(message, "last_attested_round")
        round_number = _uint(transaction, "round")
        _require(first <= last, "state proof interval is inverted")
        _require(first <= round_number <= last,
                 f"round {round_number} outside attested interval [{first}, {last}]")

        return cls(
            genesis_id=genesis_id,
            genesis_hash=_b64(chain, "genesis_hash_b64", expect_len=32),
            txid=txid,
            round=round_number,
            block_header_bytes=_b64(data, "block_header_msgpack_b64"),
            stib_bytes=_b64(data, "stib_msgpack_b64"),
            txn_proof_index=_uint(txn_proof, "index"),
            txn_proof_depth=_uint(txn_proof, "tree_depth"),
            txn_proof=_b64(txn_proof, "proof_b64"),
            light_header_proof_depth=_uint(light_proof, "tree_depth"),
            light_header_proof=_b64(light_proof, "proof_b64"),
            block_headers_commitment=_b64(message, "block_headers_commitment_b64",
                                          expect_len=32),
            first_attested_round=first,
            last_attested_round=last,
            ln_proven_weight=_uint(message, "ln_proven_weight"),
            # VotersCommitment is a 64-byte vector-commitment root (the
            # commitment hash is 64 bytes, not the 32 of block hashes).
            voters_commitment=_b64(message, "voters_commitment_b64", expect_len=64),
            state_proof_bytes=_b64(data, "state_proof_msgpack_b64"),
            state_proof_proof_bytes=(
                _b64(data, "state_proof_b64") if "state_proof_b64" in data else None
            ),
            previous_message=(
                data.get("previous_state_proof_message")
                if isinstance(data.get("previous_state_proof_message"), dict)
                else None
            ),
            light_header_variant=variant,
            captured_at=captured_at,
            source_node=source_node,
        )

    #: Refuse bundle files larger than this. A real bundle is a few KB; the
    #: cap turns a hostile multi-megabyte upload into a cheap rejection
    #: before any parsing or canonical re-encoding allocates against it.
    MAX_FILE_BYTES = 4 * 1024 * 1024

    @classmethod
    def load(cls, path: str | Path) -> "Bundle":
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise BundleError(f"cannot read bundle file {path}: {exc}") from exc
        if len(raw) > cls.MAX_FILE_BYTES:
            raise BundleError(
                f"bundle file {path} is {len(raw)} bytes, exceeding the "
                f"{cls.MAX_FILE_BYTES}-byte limit"
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError(f"bundle file {path} is not valid UTF-8: {exc}") from exc
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise BundleError(f"bundle file {path} is not valid JSON: {exc}") from exc
        return cls.from_dict(data)


def dump_bundle(data: dict, path: str | Path) -> None:
    """Write a bundle dict to ``path`` as stable, human-diffable JSON."""
    Bundle.from_dict(data)  # refuse to write anything that does not validate
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

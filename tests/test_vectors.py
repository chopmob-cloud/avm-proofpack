"""Self-validating harness for the cross-implementation conformance vectors.

The vectors under ``vectors/`` are the normative test set an independent
implementation (a future JS or Go verifier) runs to prove byte-for-byte
agreement with this reference. This harness proves the vectors themselves
still agree with the library, guarding against silent drift:

- every ``vectors/positive/*.json`` bundle verifies, and every expected
  derived value it records (hashes, roots, leaves, rounds, trust root, the
  ordered check list, and the full PaymentFacts) matches what the library
  computes right now;
- every ``vectors/negative/*.json`` mutation, applied through the same
  declarative op DSL an independent verifier would reimplement, fails closed
  with exactly the recorded error type and (for a VerificationError) the
  recorded ``check`` step.

The mutation DSL below is a byte-for-byte copy of ``vectors/generate.py``'s
``apply_mutation``; it is deliberately duplicated so the harness re-derives
each negative outcome independently of the generator.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from avm_proofpack import mpack
from avm_proofpack.avm import (
    block_hash,
    light_block_header_leaf,
    stib_hash_sha256,
    transaction_from_stib,
    txn_hashes,
)
from avm_proofpack.bundle import Bundle, BundleError
from avm_proofpack.extract import extract_payment
from avm_proofpack.hashes import DOMAIN_TXN_MERKLE_LEAF, sha256
from avm_proofpack.verify import VerificationError, verify_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors"
POSITIVE = sorted((VECTORS_DIR / "positive").glob("*.json"))
NEGATIVE = sorted((VECTORS_DIR / "negative").glob("*.json"))
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

SCHEMA = "avm-proofpack-conformance/v1"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve(vector_path: Path, rel: str) -> Path:
    return (vector_path.parent / rel).resolve()


def _fixture_dict(name: str) -> dict:
    return _load_json(FIXTURES_DIR / f"{name}.json")


# -- mutation DSL (mirror of vectors/generate.py:apply_mutation) -------------

def _get_parent(data: dict, path: str) -> tuple[dict, str]:
    parts = path.split(".")
    node = data
    for part in parts[:-1]:
        node = node[part]
    return node, parts[-1]


def apply_mutation(data: dict, ops: list[dict]) -> dict:
    out = copy.deepcopy(data)
    for op in ops:
        kind = op["op"]
        if kind == "set":
            parent, key = _get_parent(out, op["path"])
            parent[key] = op["value"]
        elif kind == "add_int":
            parent, key = _get_parent(out, op["path"])
            parent[key] = parent[key] + op["delta"]
        elif kind == "flip_b64_bit":
            parent, key = _get_parent(out, op["path"])
            raw = bytearray(base64.b64decode(parent[key]))
            raw[op["byte_offset"] % len(raw)] ^= op.get("xor", 0x01)
            parent[key] = base64.b64encode(bytes(raw)).decode("ascii")
        elif kind == "truncate_b64_tail":
            parent, key = _get_parent(out, op["path"])
            raw = base64.b64decode(parent[key])
            parent[key] = base64.b64encode(
                raw[: len(raw) - op["drop_bytes"]]
            ).decode("ascii")
        elif kind == "copy_from":
            src = _fixture_dict(op["from_fixture"])
            src_parent, src_key = _get_parent(src, op["from_path"])
            dst_parent, dst_key = _get_parent(out, op["path"])
            dst_parent[dst_key] = copy.deepcopy(src_parent[src_key])
        else:
            raise ValueError(f"unknown mutation op {kind!r}")
    return out


# -- derived intermediate leaves (mirror of verify.py, via library calls) ----

def _derived_leaves(bundle: Bundle) -> tuple[str, str]:
    header = mpack.decode(bundle.block_header_bytes)
    stib = mpack.decode(bundle.stib_bytes)
    txn = transaction_from_stib(stib, header)
    _, txid_256 = txn_hashes(txn)
    stib_hash = stib_hash_sha256(bundle.stib_bytes)
    txn_leaf = sha256(DOMAIN_TXN_MERKLE_LEAF + txid_256 + stib_hash)
    txn_commitment = header["txn256"]
    if bundle.light_header_variant == "block_hash":
        light_leaf = light_block_header_leaf(
            bundle.round, bundle.genesis_hash, txn_commitment,
            block_hash_digest=block_hash(bundle.block_header_bytes),
        )
    else:
        light_leaf = light_block_header_leaf(
            bundle.round, bundle.genesis_hash, txn_commitment,
            seed=header["seed"],
        )
    return txn_leaf.hex(), light_leaf.hex()


# -- positive vectors --------------------------------------------------------

@pytest.mark.parametrize("path", POSITIVE, ids=[p.stem for p in POSITIVE])
def test_positive_vector(path):
    vec = _load_json(path)
    assert vec["schema"] == SCHEMA
    assert vec["kind"] == "positive"
    exp = vec["expected"]

    bundle = Bundle.load(_resolve(path, vec["bundle_path"]))
    report = verify_bundle(bundle)

    assert exp["verifies"] is True
    assert exp["trust_root"] == report.trust_root == "unattested"
    assert exp["txid"] == report.txid
    assert exp["round"] == report.round
    assert exp["genesis_id"] == report.genesis_id
    assert exp["first_attested_round"] == report.first_attested_round
    assert exp["last_attested_round"] == report.last_attested_round
    assert exp["light_header_variant"] == report.light_header_variant
    assert exp["checks"] == list(report.checks)

    assert exp["genesis_hash_hex"] == base64.b64decode(report.genesis_hash_b64).hex()
    assert exp["block_hash_hex"] == base64.b64decode(report.block_hash_b64).hex()
    assert (
        exp["txn_commitment_root_hex"]
        == base64.b64decode(report.txn_commitment_b64).hex()
    )
    assert (
        exp["block_headers_commitment_root_hex"]
        == base64.b64decode(report.block_headers_commitment_b64).hex()
    )

    txn_leaf_hex, light_leaf_hex = _derived_leaves(bundle)
    assert exp["txn_leaf_hash_hex"] == txn_leaf_hex
    assert exp["light_header_leaf_hash_hex"] == light_leaf_hex

    assert exp["payment_facts"] == extract_payment(bundle, report=report).as_dict()


# -- negative vectors --------------------------------------------------------

@pytest.mark.parametrize("path", NEGATIVE, ids=[p.stem for p in NEGATIVE])
def test_negative_vector(path):
    vec = _load_json(path)
    assert vec["schema"] == SCHEMA
    assert vec["kind"] == "negative"
    exp = vec["expected"]
    assert exp["verifies"] is False

    base = _load_json(_resolve(path, vec["base_bundle_path"]))
    mutated = apply_mutation(base, vec["mutation"])

    kwargs = {}
    opts = vec.get("verify_options", {})
    if "expected_genesis_hash_hex" in opts:
        kwargs["expected_genesis_hash"] = bytes.fromhex(opts["expected_genesis_hash_hex"])

    if exp["error_type"] == "BundleError":
        # Fails fail-closed at schema validation, before any verify step.
        with pytest.raises(BundleError):
            verify_bundle(Bundle.from_dict(mutated), **kwargs)
        return

    assert exp["error_type"] == "VerificationError"
    bundle = Bundle.from_dict(mutated)  # must parse; the failure is in verify
    with pytest.raises(VerificationError) as excinfo:
        verify_bundle(bundle, **kwargs)
    assert excinfo.value.check == exp["failed_check"]


def test_vector_set_is_present():
    assert len(POSITIVE) == 3, "expected one positive vector per fixture"
    assert len(NEGATIVE) >= 12, "expected the canonical negative tamper set"

"""Deterministic generator for settlement_evidence_binding_v1.

The raw-Bundle conformance set (../positive, ../negative) proves the on-chain
anchor. THIS set proves the layer above it: how a captured bundle is *bound* to
a round-bearing settlement attestation as portable, offline-verifiable evidence,
exactly as the gateway emits it (gateway/app/services/settlement_evidence_service.py,
gateway/app/routers/receipt_verify.py).

The binding record (ChainBinding + SettlementEvidence) carries:

    scheme                = "avm-proofpack/1"
    settled_payment_ref   = "sha256:" + SHA-256(f"{tenant_id}:{tx_id}:{network}")
    round                 = the confirmed round of the settling txn
    chain_genesis_id      = the bundle's chain identity
    bundle_sha256         = SHA-256( dump_bundle(bundle) )      <-- NOT JCS
    attestation_content_hash / attestation_settlement_round

Load-bearing rules a conformant verifier MUST enforce (see verify_binding.py):

  R1  bundle_sha256 == SHA-256 of dump_bundle's bytes:
        json.dumps(bundle, indent=2, sort_keys=True) + "\n"
      This is deliberately NOT the RFC 8785 JCS compact form the rest of the
      substrate uses, so a downloaded .proofpack.json verifies with plain
      `sha256sum`. A verifier that assumes JCS here computes a different digest
      and MUST reject -- shipped as the canary (seb-v1-r05).
  R2  settled_payment_ref recomputes from (tenant_id, tx_id, network).
  R3  round == bundle.round == attestation_settlement_round  (the L2 join:
      a bundle for a different round cannot back this attestation).
  R4  chain_genesis_id == bundle.genesis_id (chain-identity pin).
  R5  the bundle itself verifies under avm_proofpack.verify_bundle (the anchor
      is real, not just well-shaped).

Run:  python generate.py   (writes settlement_evidence_binding_v1.json)
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src"))

from avm_proofpack.bundle import Bundle  # noqa: E402

# The attestation content_hash is computed with the same JCS the corpus uses, so
# this vector's attestation digest is byte-identical to a settlement_attestation_v1
# record carrying settlement_round == the bundle's round.
from algovoi_substrate import canonicalize  # noqa: E402

FIXTURE_REL = "../../tests/fixtures/algorand-mainnet-pay.json"
FIXTURE_ABS = os.path.normpath(os.path.join(HERE, FIXTURE_REL))
OUTPUT = os.path.join(HERE, "settlement_evidence_binding_v1.json")

# Fixed evidence-side inputs (deterministic; no clock, no randomness).
TENANT_ID = "11111111-1111-4111-8111-111111111111"
NETWORK = "algorand"
CANON_VERSION = "jcs-rfc8785-v1"


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def dump_bundle_canon_bytes(bundle: dict) -> bytes:
    """The exact bytes avm_proofpack.dump_bundle writes (indent=2, sort_keys)."""
    return (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")


def jcs_compact_bytes(bundle: dict) -> bytes:
    """The WRONG canon for a proofpack bundle: RFC 8785-style compact form."""
    return json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")


def settled_payment_ref(tenant_id: str, tx_id: str, network: str) -> str:
    return "sha256:" + sha256_hex(f"{tenant_id}:{tx_id}:{network}".encode("utf-8"))


def attestation_content_hash(settlement_round: int, settlement_chain: str) -> str:
    body = {
        "canon_version": CANON_VERSION,
        "jurisdiction_flags": ["UK", "EU"],
        "settled_payment_ref": "sha256:" + "a" * 64,
        "settlement_amount": {"amount_minor": "1000000", "asset_id": "USDC"},
        "settlement_chain": settlement_chain,
        "settlement_provider_did": "did:web:algovoi.co.uk",
        "settlement_result": "SETTLED",
        "settlement_round": settlement_round,
        "settlement_timestamp_ms": 1721030000000,
    }
    canon = canonicalize(body)
    cb = canon.encode("utf-8") if isinstance(canon, str) else canon
    return "sha256:" + sha256_hex(cb)


def main() -> None:
    bundle = json.load(open(FIXTURE_ABS, encoding="utf-8"))
    b = Bundle.from_dict(bundle)  # must validate
    round_ = b.round
    genesis_id = b.genesis_id

    good_bundle_sha256 = sha256_hex(dump_bundle_canon_bytes(bundle))
    jcs_wrong_sha256 = sha256_hex(jcs_compact_bytes(bundle))
    assert good_bundle_sha256 != jcs_wrong_sha256

    tx_id = bundle["transaction"]["txid"]
    ref = settled_payment_ref(TENANT_ID, tx_id, NETWORK)
    att = attestation_content_hash(round_, NETWORK)

    def binding(**over):
        rec = {
            "scheme": "avm-proofpack/1",
            "settled_payment_ref": ref,
            "settled_payment_ref_preimage": {
                "tenant_id": TENANT_ID, "tx_id": tx_id, "network": NETWORK,
            },
            "network": NETWORK,
            "round": round_,
            "chain_genesis_id": genesis_id,
            "bundle_sha256": good_bundle_sha256,
            "bundle_path": FIXTURE_REL,
            "attestation_content_hash": att,
            "attestation_settlement_round": round_,
        }
        rec.update(over)
        return rec

    vectors = [
        {
            "vector_id": "seb-v1-001",
            "kind": "positive",
            "expectation": "accept",
            "description": (
                "Reference settlement-evidence binding: a captured avm-proofpack "
                "bundle bound to a round-bearing settlement attestation. "
                "bundle_sha256 is SHA-256 of dump_bundle's indent-2/sort_keys "
                "bytes; settled_payment_ref recomputes from (tenant, tx, network); "
                "round == bundle.round == attestation_settlement_round; "
                "chain_genesis_id == bundle.genesis_id; the bundle verifies."
            ),
            "binding": binding(),
        },
        {
            "vector_id": "seb-v1-r05",
            "kind": "canary",
            "expectation": "reject",
            "reject_rule": "R1_bundle_sha256_dump_canon_not_jcs",
            "description": (
                "NON-JCS CANARY. bundle_sha256 is set to the RFC 8785 JCS/compact "
                "hash of the bundle. A verifier that (wrongly) assumes JCS for the "
                "proofpack bundle would accept this; a conformant verifier "
                "recomputes over dump_bundle's indent-2/sort_keys bytes and MUST "
                "reject. This is the whole point of documenting the off-canon digest."
            ),
            "wrong_jcs_bundle_sha256": jcs_wrong_sha256,
            "binding": binding(bundle_sha256=jcs_wrong_sha256),
        },
        {
            "vector_id": "seb-v1-r01",
            "kind": "negative",
            "expectation": "reject",
            "reject_rule": "R1_bundle_sha256_recompute",
            "description": "Fabricated bundle_sha256 (all-f) does not recompute over the bundle bytes.",
            "binding": binding(bundle_sha256="f" * 64),
        },
        {
            "vector_id": "seb-v1-r02",
            "kind": "negative",
            "expectation": "reject",
            "reject_rule": "R3_round_join",
            "description": (
                "Round-join break: the evidence round (and bundle) is for a "
                "different round than the attestation's settlement_round. A bundle "
                "cannot back an attestation for a round it does not attest."
            ),
            "binding": binding(attestation_settlement_round=round_ + 1),
        },
        {
            "vector_id": "seb-v1-r03",
            "kind": "negative",
            "expectation": "reject",
            "reject_rule": "R2_settled_payment_ref_recompute",
            "description": (
                "settled_payment_ref does not recompute from (tenant, tx, network) "
                "-- evidence cannot be re-pointed to another charge."
            ),
            "binding": binding(
                settled_payment_ref="sha256:" + "0" * 64,
            ),
        },
        {
            "vector_id": "seb-v1-r04",
            "kind": "negative",
            "expectation": "reject",
            "reject_rule": "R4_chain_identity_pin",
            "description": (
                "chain_genesis_id does not match the bundle's genesis id "
                "(chain-identity pin): evidence from one chain cannot back a "
                "settlement claimed on another."
            ),
            "binding": binding(chain_genesis_id="testnet-v1.0"),
        },
    ]

    out = {
        "schema": "avm-proofpack-settlement-evidence-binding/v1",
        "artefact_id": "settlement-evidence-binding-conformance-v1",
        "published_at": "2026-08-02T00:00:00Z",
        "canon_note": (
            "bundle_sha256 = SHA-256( json.dumps(bundle, indent=2, sort_keys=True) "
            "+ '\\n' ) -- the bytes avm_proofpack.dump_bundle writes. This is NOT "
            "RFC 8785 JCS; it is chosen so a downloaded .proofpack.json verifies "
            "with plain sha256sum. attestation_content_hash IS JCS (RFC 8785), the "
            "same as settlement_attestation_v1. The two canons deliberately differ; "
            "see seb-v1-r05 (canary)."
        ),
        "load_bearing_rules": {
            "R1": "bundle_sha256 == SHA-256(dump_bundle bytes); NOT JCS.",
            "R2": "settled_payment_ref == 'sha256:'+SHA-256(f'{tenant_id}:{tx_id}:{network}').",
            "R3": "round == bundle.round == attestation_settlement_round (L2 join).",
            "R4": "chain_genesis_id == bundle.genesis_id (chain-identity pin).",
            "R5": "bundle verifies under avm_proofpack.verify_bundle (real anchor).",
        },
        "composes_with": {
            "raw_bundle_set": "../positive, ../negative (the on-chain anchor + its 17 tamper negatives)",
            "settlement_attestation": (
                "algovoi-jcs-conformance-vectors settlement_attestation_v1 "
                "(round-bearing vector settlement-attestation-v1-009) and "
                "settlement_action_binding_v1 (sab-v1-007)"
            ),
        },
        "vectors": vectors,
    }

    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {len(vectors)} vectors -> {OUTPUT}")
    print(f"  bundle round={round_} genesis_id={genesis_id}")
    print(f"  bundle_sha256 (dump canon) = {good_bundle_sha256}")
    print(f"  jcs-wrong    (canary)      = {jcs_wrong_sha256}")
    print(f"  settled_payment_ref        = {ref}")
    print(f"  attestation_content_hash   = {att}")


if __name__ == "__main__":
    main()

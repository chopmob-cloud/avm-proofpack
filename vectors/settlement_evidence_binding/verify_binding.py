"""settlement_evidence_binding_v1 runner.

Reimplements the five binding rules (R1-R5) from the written contract and runs
them against every vector: positive/canary vectors must ACCEPT/REJECT exactly as
declared. Recompute-not-readback throughout: every published digest is
recomputed from source (the bundle file, the ref preimage), never trusted.

Usage:  python verify_binding.py
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
from avm_proofpack.verify import VerificationError, verify_bundle  # noqa: E402

VECTORS = os.path.join(HERE, "settlement_evidence_binding_v1.json")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _dump_bundle_bytes(bundle: dict) -> bytes:
    return (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")


class BindingReject(Exception):
    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule


def verify_binding(rec: dict) -> None:
    """Raise BindingReject on the first broken rule; return None if all hold."""
    bundle_path = os.path.normpath(os.path.join(HERE, rec["bundle_path"]))
    bundle = json.load(open(bundle_path, encoding="utf-8"))
    b = Bundle.from_dict(bundle)

    # R1: bundle_sha256 is the dump_bundle (indent=2, sort_keys) digest, NOT JCS.
    recomputed = _sha(_dump_bundle_bytes(bundle))
    if rec["bundle_sha256"] != recomputed:
        raise BindingReject("R1", f"bundle_sha256 {rec['bundle_sha256'][:16]}.. != dump-canon {recomputed[:16]}..")

    # R2: settled_payment_ref recomputes from (tenant_id, tx_id, network).
    pre = rec["settled_payment_ref_preimage"]
    expect_ref = "sha256:" + _sha(f"{pre['tenant_id']}:{pre['tx_id']}:{pre['network']}".encode("utf-8"))
    if rec["settled_payment_ref"] != expect_ref:
        raise BindingReject("R2", "settled_payment_ref does not recompute from its preimage")

    # R3: round == bundle.round == attestation_settlement_round (the L2 join).
    if not (rec["round"] == b.round == rec["attestation_settlement_round"]):
        raise BindingReject(
            "R3",
            f"round join broken: evidence={rec['round']} bundle={b.round} "
            f"attestation={rec['attestation_settlement_round']}",
        )

    # R4: chain_genesis_id == bundle.genesis_id (chain-identity pin).
    if rec["chain_genesis_id"] != b.genesis_id:
        raise BindingReject("R4", f"chain_genesis_id {rec['chain_genesis_id']} != bundle {b.genesis_id}")

    # R5: the bundle actually verifies (the anchor is real, not just well-shaped).
    try:
        verify_bundle(b)
    except VerificationError as exc:
        raise BindingReject("R5", f"bundle failed verification: {exc}") from exc


def main() -> int:
    data = json.load(open(VECTORS, encoding="utf-8"))
    failures: list[str] = []
    print("settlement_evidence_binding_v1 runner")
    print(f"schema: {data['schema']}  vectors: {len(data['vectors'])}")
    print()
    for v in data["vectors"]:
        vid = v["vector_id"]
        want = v["expectation"]  # accept | reject
        try:
            verify_binding(v["binding"])
            got = "accept"
            detail = ""
        except BindingReject as exc:
            got = "reject"
            detail = exc.rule
        ok = got == want
        if not ok:
            failures.append(f"{vid}: expected {want}, got {got}")
        mark = "PASS" if ok else "FAIL"
        rr = v.get("reject_rule", "")
        note = f"({detail})" if detail else (f"[{rr}]" if rr else "")
        print(f"  {vid}: {mark}  {v['kind']:8} -> {got:6} {note}")
    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: {len(data['vectors'])} binding vectors (R1-R5 reimplemented from the contract).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

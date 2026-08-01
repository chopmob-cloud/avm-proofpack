"""Adversarial validation of avm-proofpack against real mainnet bundles.

Threat model: the bundle is entirely attacker-controlled. Every attack below is
something a malicious facilitator/capturer would try; each MUST fail closed.
Exit non-zero if any expected-refusal actually succeeds.

Usage:
    python scripts/adversarial_secval.py [ALGORAND_BUNDLE.json VOI_BUNDLE.json]

With no arguments it runs against the repository's real-captured fixtures.
"""
import base64
import copy
import json
import pathlib
import sys

from avm_proofpack import Bundle, verify_bundle
from avm_proofpack.verify import VerificationError
from avm_proofpack.extract import extract_payment, matches_reference, ExtractionError, decode_address, encode_address
from avm_proofpack import chains

_FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
if len(sys.argv) >= 3:
    ALG, VOI = sys.argv[1], sys.argv[2]
else:
    ALG = str(_FIXTURES / "algorand-mainnet-pay.json")
    VOI = str(_FIXTURES / "voi-mainnet-appl.json")

fails = []
def expect_refuse(name, fn):
    """fn must raise; if it returns, that's a security failure."""
    try:
        fn()
        print(f"  [SECURITY FAIL] {name}: attack SUCCEEDED (should have been refused)")
        fails.append(name)
    except Exception as e:
        print(f"  [ok] {name}: refused -> {type(e).__name__}")

def expect_ok(name, fn):
    try:
        fn()
        print(f"  [ok] {name}")
    except Exception as e:
        print(f"  [FAIL] {name}: legitimate op raised {type(e).__name__}: {e}")
        fails.append(name)

alg = Bundle.load(ALG)
voi = Bundle.load(VOI)
alg_dict = json.load(open(ALG))

print("== baseline ==")
expect_ok("real Algorand bundle verifies", lambda: verify_bundle(alg))
expect_ok("real Voi bundle verifies", lambda: verify_bundle(voi))

print("== forgery: mutate payment bytes (the whole point) ==")
def flip_stib():
    d = copy.deepcopy(alg_dict)
    raw = bytearray(base64.b64decode(d["stib_msgpack_b64"]))
    raw[len(raw)//2] ^= 0x01  # flip one bit in the signed-txn-in-block
    d["stib_msgpack_b64"] = base64.b64encode(bytes(raw)).decode()
    verify_bundle(Bundle.from_dict(d))
expect_refuse("1-bit flip in stib bytes rejected", flip_stib)

def forged_txid():
    d = copy.deepcopy(alg_dict)
    d["transaction"]["txid"] = "A" * 52  # claim a different txid
    verify_bundle(Bundle.from_dict(d))
expect_refuse("substituted txid rejected", forged_txid)

def forged_round():
    d = copy.deepcopy(alg_dict)
    d["transaction"]["round"] += 1
    verify_bundle(Bundle.from_dict(d))
expect_refuse("altered round rejected", forged_round)

def forged_proof():
    d = copy.deepcopy(alg_dict)
    raw = bytearray(base64.b64decode(d["txn_proof"]["proof_b64"]))
    if raw:
        raw[0] ^= 0xFF
    d["txn_proof"]["proof_b64"] = base64.b64encode(bytes(raw)).decode()
    verify_bundle(Bundle.from_dict(d))
expect_refuse("tampered merkle proof rejected", forged_proof)

def forged_commitment():
    d = copy.deepcopy(alg_dict)
    raw = bytearray(base64.b64decode(d["state_proof_message"]["block_headers_commitment_b64"]))
    raw[0] ^= 0xFF
    d["state_proof_message"]["block_headers_commitment_b64"] = base64.b64encode(bytes(raw)).decode()
    verify_bundle(Bundle.from_dict(d))
expect_refuse("tampered state-proof commitment rejected", forged_commitment)

print("== extract gate: report for bundle A must not unlock bundle B ==")
rep_voi = verify_bundle(voi)
rep_alg = verify_bundle(alg)
expect_refuse("extract(Algorand, report=Voi's) refused", lambda: extract_payment(alg, report=rep_voi))
expect_refuse("extract(Voi, report=Algorand's) refused", lambda: extract_payment(voi, report=rep_alg))
expect_ok("extract(Algorand, its own report) works", lambda: extract_payment(alg, report=rep_alg))

print("== extract must not emit forged facts from an unverifiable bundle ==")
def extract_tampered():
    d = copy.deepcopy(alg_dict)
    raw = bytearray(base64.b64decode(d["stib_msgpack_b64"]))
    raw[len(raw)//2] ^= 0x01
    d["stib_msgpack_b64"] = base64.b64encode(bytes(raw)).decode()
    return extract_payment(Bundle.from_dict(d))  # default: verifies internally
expect_refuse("extract on tampered bundle refused (no forged amount)", extract_tampered)

print("== cross-chain confusion ==")
alg_gh = base64.b64decode(alg_dict["chain"]["genesis_hash_b64"])
voi_gh = voi.genesis_hash
expect_refuse("Voi bundle pinned to Algorand genesis rejected",
              lambda: verify_bundle(voi, expected_genesis_hash=alg_gh))
expect_ok("Voi bundle pinned to correct genesis ok",
          lambda: verify_bundle(voi, expected_genesis_hash=voi_gh))

print("== chain registry integrity ==")
expect_ok("algorand-mainnet registry hash matches real bundle",
          lambda: (_ for _ in ()).throw(AssertionError("mismatch")) if chains.get_chain("algorand-mainnet").genesis_hash != alg_gh else None)
expect_ok("voi-mainnet registry hash matches real bundle",
          lambda: (_ for _ in ()).throw(AssertionError("mismatch")) if chains.get_chain("voi-mainnet").genesis_hash != voi_gh else None)

print("== matches_reference (privacy loop) ==")
import hashlib
facts = extract_payment(alg)
tenant, network = "acme", "algorand-mainnet"
good = hashlib.sha256(f"{tenant}:{facts.txid}:{network}".encode()).hexdigest()
bad = hashlib.sha256(f"attacker:{facts.txid}:{network}".encode()).hexdigest()
expect_ok("matches_reference true for correct preimage",
          lambda: (_ for _ in ()).throw(AssertionError) if not matches_reference(alg, good, template="{tenant}:{txid}:{network}", tenant=tenant, network=network) else None)
expect_ok("matches_reference false for wrong preimage",
          lambda: (_ for _ in ()).throw(AssertionError) if matches_reference(alg, bad, template="{tenant}:{txid}:{network}", tenant=tenant, network=network) else None)
expect_refuse("matches_reference raises on malformed ref (not silent False)",
              lambda: matches_reference(alg, "not-hex", template="{txid}"))
expect_refuse("matches_reference rejects caller overriding {txid}",
              lambda: matches_reference(alg, good, template="{txid}", txid="attacker"))

print("== address checksum ==")
expect_refuse("address with corrupted checksum rejected",
              lambda: decode_address(facts.sender[:-1] + ("A" if facts.sender[-1] != "A" else "B")))
expect_ok("address round-trips", lambda: decode_address(encode_address(decode_address(facts.sender))))

print()
if fails:
    print(f"RESULT: {len(fails)} SECURITY FAILURE(S): {fails}")
    sys.exit(1)
print("RESULT: all adversarial checks passed (every forgery/confusion attempt failed closed)")

"""Fixture verification and the tamper suite.

The fixtures are real bundles captured from Algorand and Voi mainnet. Every
fixture must verify offline; every systematic mutation of a fixture must
fail closed with a precise error. A tamper test that passes verification is
a security defect in the library, not in the test.
"""

import base64
import copy
import json
from pathlib import Path

import pytest

from avm_proofpack.bundle import Bundle, BundleError
from avm_proofpack.verify import VerificationError, verify_bundle

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))
FIXTURE_IDS = [path.stem for path in FIXTURES]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _flip_b64_byte(encoded: str, offset: int = 0) -> str:
    raw = bytearray(base64.b64decode(encoded))
    raw[offset % len(raw)] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_fixture_verifies_offline(path):
    report = verify_bundle(Bundle.load(path))
    assert report.checks == (
        "canonical-form",
        "block-header",
        "transaction-id",
        "txn-commitment-membership",
        "block-headers-commitment-membership",
        "state-proof-present",
    )
    assert report.trust_root == "unattested"


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_chain_pinning(path):
    data = _load(path)
    genesis = base64.b64decode(data["chain"]["genesis_hash_b64"])
    verify_bundle(Bundle.from_dict(data), expected_genesis_hash=genesis)
    with pytest.raises(VerificationError) as excinfo:
        verify_bundle(
            Bundle.from_dict(data), expected_genesis_hash=b"\x00" * 32
        )
    assert excinfo.value.check == "chain-identity"


def _tamper_cases():
    def stib_byte(data):
        data["stib_msgpack_b64"] = _flip_b64_byte(data["stib_msgpack_b64"], 5)

    def header_byte(data):
        data["block_header_msgpack_b64"] = _flip_b64_byte(
            data["block_header_msgpack_b64"], 5
        )

    def claimed_txid(data):
        txid = data["transaction"]["txid"]
        replacement = "A" if txid[0] != "A" else "B"
        data["transaction"]["txid"] = replacement + txid[1:]

    def claimed_round(data):
        data["transaction"]["round"] += 1

    def txn_proof_byte(data):
        # A single-transaction block legitimately has a depth-0 tree with an
        # empty proof (root == leaf); the mutation is then inapplicable.
        if not data["txn_proof"]["proof_b64"]:
            pytest.skip("empty txn proof (depth-0 tree): nothing to flip")
        data["txn_proof"]["proof_b64"] = _flip_b64_byte(
            data["txn_proof"]["proof_b64"]
        )

    def txn_proof_index(data):
        data["txn_proof"]["index"] += 1

    def txn_proof_truncated(data):
        if not data["txn_proof"]["proof_b64"]:
            pytest.skip("empty txn proof (depth-0 tree): nothing to truncate")
        raw = base64.b64decode(data["txn_proof"]["proof_b64"])
        data["txn_proof"]["proof_b64"] = base64.b64encode(raw[:-32]).decode()

    def light_proof_byte(data):
        data["light_header_proof"]["proof_b64"] = _flip_b64_byte(
            data["light_header_proof"]["proof_b64"]
        )

    def headers_commitment(data):
        data["state_proof_message"]["block_headers_commitment_b64"] = _flip_b64_byte(
            data["state_proof_message"]["block_headers_commitment_b64"]
        )

    def interval_shift(data):
        data["state_proof_message"]["first_attested_round"] += 1
        data["state_proof_message"]["last_attested_round"] += 1

    def genesis_hash(data):
        data["chain"]["genesis_hash_b64"] = _flip_b64_byte(
            data["chain"]["genesis_hash_b64"]
        )

    def variant_flip(data):
        data["meta"]["light_header_variant"] = "seed"

    return {
        "stib-byte-flip": stib_byte,
        "header-byte-flip": header_byte,
        "claimed-txid": claimed_txid,
        "claimed-round": claimed_round,
        "txn-proof-byte-flip": txn_proof_byte,
        "txn-proof-index": txn_proof_index,
        "txn-proof-truncated": txn_proof_truncated,
        "light-proof-byte-flip": light_proof_byte,
        "headers-commitment-flip": headers_commitment,
        "interval-shift": interval_shift,
        "genesis-hash-flip": genesis_hash,
        "variant-flip": variant_flip,
    }


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
@pytest.mark.parametrize("name,mutate", _tamper_cases().items(), ids=list(_tamper_cases()))
def test_tampered_bundle_fails(path, name, mutate):
    data = copy.deepcopy(_load(path))
    mutate(data)
    with pytest.raises((VerificationError, BundleError)):
        verify_bundle(Bundle.from_dict(data))


def test_transplanted_stib_fails():
    """A stib from a different transaction in the same block must not verify
    against another bundle's claimed txid (binding, not just membership)."""
    paths = {p.stem: p for p in FIXTURES}
    a = _load(paths["algorand-mainnet-appl"])
    b = _load(paths["algorand-mainnet-pay"])
    assert a["transaction"]["round"] == b["transaction"]["round"]
    tampered = copy.deepcopy(a)
    tampered["stib_msgpack_b64"] = b["stib_msgpack_b64"]
    tampered["txn_proof"] = b["txn_proof"]
    with pytest.raises(VerificationError) as excinfo:
        verify_bundle(Bundle.from_dict(tampered))
    assert excinfo.value.check == "transaction"


def test_cross_chain_transplant_fails():
    """A Voi state proof message must not vouch for an Algorand block."""
    paths = {p.stem: p for p in FIXTURES}
    algorand = _load(paths["algorand-mainnet-appl"])
    voi = _load(paths["voi-mainnet-appl"])
    tampered = copy.deepcopy(algorand)
    tampered["state_proof_message"] = voi["state_proof_message"]
    tampered["light_header_proof"] = voi["light_header_proof"]
    with pytest.raises((VerificationError, BundleError)):
        verify_bundle(Bundle.from_dict(tampered))


def test_bundle_schema_rejects_garbage():
    with pytest.raises(BundleError):
        Bundle.from_dict({})
    with pytest.raises(BundleError):
        Bundle.from_dict({"format": "avm-proofpack", "version": 99})
    data = _load(FIXTURES[0])
    data["txn_proof"]["proof_b64"] = "not base64!!"
    with pytest.raises(BundleError):
        Bundle.from_dict(data)

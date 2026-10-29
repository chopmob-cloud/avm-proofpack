"""Stake-attested tier: the fallback path, pinned.

The POSITIVE path (a bundle carrying a full state proof plus the previous
interval's message reaching trust_root == "stake_attested") is currently
verified only by the offline spike, because the fixture that exercises it is
834 KB. Until that fixture is committed, these tests pin the behaviour that
must hold for every existing bundle: with no proof material, the tier must
NOT be claimed.
"""
import json
import pathlib

import pytest

from avm_proofpack.bundle import Bundle
from avm_proofpack.verify import verify_bundle

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} not present")
    return json.loads(p.read_text(encoding="utf-8"))


def test_bundle_without_state_proof_stays_unattested():
    """A bundle carrying only the message must never claim stake_attested."""
    data = _load("algorand-mainnet-pay.json")
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


def test_missing_previous_message_cannot_reach_stake_attested():
    """Even WITH a proof, no previous-interval message means no tier.

    The previous message is the only source of the trusted signing set and
    weight bound; without it the tier has nothing to authenticate against.
    """
    data = _load("algorand-mainnet-pay.json")
    data["state_proof_proof_bytes"] = data.get("state_proof_msgpack_b64")
    data["previous_state_proof_message"] = None
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"


def test_hostile_previous_message_fails_closed():
    """A malformed previous message must fail closed, not raise."""
    data = _load("algorand-mainnet-pay.json")
    data["state_proof_b64"] = data.get("state_proof_msgpack_b64")
    data["previous_state_proof_message"] = {
        "ln_proven_weight": "not-an-int",
        "voters_commitment_b64": "!!!not-base64!!!",
        "block_headers_commitment_b64": "AA==",
        "first_attested_round": 0,
        "last_attested_round": 0,
    }
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"

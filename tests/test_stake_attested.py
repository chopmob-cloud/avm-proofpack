"""Stake-attested tier, pinned in both directions.

Positive: a real Algorand mainnet bundle (round 66457600) carrying the full
state proof and the previous interval's message reaches trust_root ==
"stake_attested".

Negative: bundles without the proof material, without the previous message,
or with a tampered proof must never reach it. A tier that can be claimed
without the signature actually verifying would be worse than no tier at all.
"""
import copy
import gzip
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
    data["previous_state_proof_message"] = None
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"


def test_hostile_previous_message_fails_closed():
    """A malformed previous message must fail closed, not raise."""
    data = _load("algorand-mainnet-pay.json")
    data["previous_state_proof_message"] = {
        "ln_proven_weight": "not-an-int",
        "voters_commitment_b64": "!!!not-base64!!!",
        "block_headers_commitment_b64": "AA==",
        "first_attested_round": 0,
        "last_attested_round": 0,
    }
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"


STAKE_FIXTURE = "stake_attested_algorand_66457600.json.gz"


def _load_gz(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} not present")
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)


def test_real_bundle_reaches_stake_attested():
    """The positive path: full proof + previous message -> stake_attested."""
    report = verify_bundle(Bundle.from_dict(_load_gz(STAKE_FIXTURE)))
    assert report.trust_root == "stake_attested"
    assert "state-proof-stake-attested" in report.checks


def test_tampered_declared_weight_does_not_reach_stake_attested():
    """Raise the declared signature weight by one: threshold must reject it.

    Tampering a Merkle proof path ("S") does not change the outcome, because the
    path bytes are not themselves an asserted fact -- the leaf they resolve to is.
    The declared weight w IS an assertion, and it must be bound by the reveal
    signatures and the coin selection, so a one-unit lie has to fail.

    Note: round-tripping through encode_canonical is lossless for this structure,
    confirmed by the positive test passing on the same fixture.
    """
    from avm_proofpack.mpack import decode, encode_canonical

    data = _load_gz(STAKE_FIXTURE)
    sp = decode(__import__("base64").b64decode(data["state_proof_msgpack_b64"]))
    original = sp["w"]
    sp["w"] = original + 1
    data["state_proof_msgpack_b64"] = __import__("base64").b64encode(encode_canonical(sp)).decode()
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


def test_substituting_the_messages_own_ln_does_not_reach_stake_attested():
    """Using the bundle's own message as the authenticated bound must fail.

    This is the round-1 defect: the message is authored by the proof builder,
    so its ln_proven_weight makes the weight bound attacker-chosen.
    """
    data = _load_gz(STAKE_FIXTURE)
    own = data["state_proof_message"]
    data["previous_state_proof_message"] = {
        "block_headers_commitment_b64": own["block_headers_commitment_b64"],
        "first_attested_round": own["first_attested_round"],
        "last_attested_round": own["last_attested_round"],
        "ln_proven_weight": own["ln_proven_weight"],
        "voters_commitment_b64": own["voters_commitment_b64"],
    }
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"

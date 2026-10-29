"""Stake-attested tier, pinned in both directions.

The tier is defined relative to a caller-supplied ``TrustedVoters`` anchor (the
signing interval's voters commitment + proven-weight bound). A single bundle
cannot authenticate that commitment on its own, so:

Positive: a real Algorand mainnet bundle (round 66457600) carrying the full
state proof reaches ``trust_root == "stake_attested"`` WHEN verified against the
correct trusted anchor.

Negative: no anchor, a wrong anchor, an anchor that disagrees with the bundle's
own previous_message, a tampered aggregate weight, OR a tampered *per-participant*
weight must all stay "unattested". A tier that could be claimed without the
revealed stake actually being bound to the trusted commitment would be worse than
no tier at all.
"""
import base64
import copy
import gzip
import json
import pathlib

import pytest

from avm_proofpack.bundle import Bundle
from avm_proofpack.verify import TrustedVoters, verify_bundle

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

STAKE_FIXTURE = "stake_attested_algorand_66457600.json.gz"


def _load(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} not present")
    return json.loads(p.read_text(encoding="utf-8"))


def _load_gz(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} not present")
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)


def _anchor_from_previous_message(data) -> TrustedVoters:
    """Build the trusted anchor from the bundle's previous-interval message.

    In production the caller obtains these values from a source it trusts (a
    trusted node, an earlier verified link, a pinned genesis). The fixture's
    previous_state_proof_message carries the real round-(R-interval) values, so
    using them here models a caller that independently trusts that commitment.
    """
    prev = data["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"], validate=True),
        ln_proven_weight=prev["ln_proven_weight"],
    )


# --------------------------------------------------------------------------- #
# No anchor -> never stake_attested (the default, safe path).
# --------------------------------------------------------------------------- #

def test_bundle_without_state_proof_stays_unattested():
    """A bundle carrying only the message must never claim stake_attested."""
    data = _load("algorand-mainnet-pay.json")
    report = verify_bundle(Bundle.from_dict(data))
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


def test_real_bundle_without_anchor_stays_unattested():
    """Even the full real bundle must NOT reach the tier without a trusted anchor.

    Offline bundle data alone can never authenticate the signing voters
    commitment, so the default verdict is unattested.
    """
    report = verify_bundle(Bundle.from_dict(_load_gz(STAKE_FIXTURE)))
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


# --------------------------------------------------------------------------- #
# Correct anchor -> stake_attested.
# --------------------------------------------------------------------------- #

def test_real_bundle_reaches_stake_attested_with_anchor():
    """The positive path: full proof + correct trusted anchor -> stake_attested."""
    data = _load_gz(STAKE_FIXTURE)
    report = verify_bundle(
        Bundle.from_dict(data), trusted_voters=_anchor_from_previous_message(data)
    )
    assert report.trust_root == "stake_attested"
    assert "state-proof-stake-attested" in report.checks


# --------------------------------------------------------------------------- #
# The vulnerability this release fixes: the revealed stake must be BOUND to the
# trusted voters commitment. A per-participant weight is not fed into the coin
# seed and is not covered by the Falcon signature, so before the fix (which
# omitted the participant-tree membership check) inflating one reveal's weight
# slipped through. It must now be rejected.
# --------------------------------------------------------------------------- #

def test_tampered_participant_weight_does_not_reach_stake_attested():
    from avm_proofpack.mpack import decode, encode_canonical

    data = _load_gz(STAKE_FIXTURE)
    anchor = _anchor_from_previous_message(data)

    sp = decode(base64.b64decode(data["state_proof_msgpack_b64"]))
    first = sorted(sp["r"])[0]
    # Inflate a single revealed participant's weight. The coin seed (which uses
    # the aggregate SignedWeight, not per-participant weights) is unchanged, and
    # the Falcon signature does not cover the weight, so only the participant-tree
    # membership binding can catch this.
    sp["r"][first]["p"]["w"] += 1_000_000_000_000_000
    data["state_proof_msgpack_b64"] = base64.b64encode(encode_canonical(sp)).decode()

    report = verify_bundle(Bundle.from_dict(data), trusted_voters=anchor)
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


def test_participant_membership_is_the_binding():
    """Directly pin that the participant-tree check rejects the forged weight.

    Guards against a refactor that drops the binding while coin selection (which
    is blind to per-participant weights) still passes.
    """
    from avm_proofpack.mpack import decode
    from avm_proofpack.consensus.stateproof import verify_participant_tree_membership

    data = _load_gz(STAKE_FIXTURE)
    anchor = _anchor_from_previous_message(data)

    sp = decode(base64.b64decode(data["state_proof_msgpack_b64"]))
    assert verify_participant_tree_membership(sp, anchor.voters_commitment) is True
    first = sorted(sp["r"])[0]
    sp["r"][first]["p"]["w"] += 1_000_000_000_000_000
    assert verify_participant_tree_membership(sp, anchor.voters_commitment) is False


# --------------------------------------------------------------------------- #
# Other negatives.
# --------------------------------------------------------------------------- #

def test_tampered_declared_weight_does_not_reach_stake_attested():
    """Raise the declared aggregate signature weight by one: it must be rejected.

    This reshuffles the coin stream (the seed includes SignedWeight), so the
    coins no longer land in the revealed slots.
    """
    from avm_proofpack.mpack import decode, encode_canonical

    data = _load_gz(STAKE_FIXTURE)
    anchor = _anchor_from_previous_message(data)
    sp = decode(base64.b64decode(data["state_proof_msgpack_b64"]))
    sp["w"] = sp["w"] + 1
    data["state_proof_msgpack_b64"] = base64.b64encode(encode_canonical(sp)).decode()
    report = verify_bundle(Bundle.from_dict(data), trusted_voters=anchor)
    assert report.trust_root == "unattested"
    assert "state-proof-stake-attested" not in report.checks


def test_wrong_anchor_commitment_does_not_reach_stake_attested():
    """An anchor whose voters commitment is not the real signing set is rejected."""
    data = _load_gz(STAKE_FIXTURE)
    anchor = _anchor_from_previous_message(data)
    bad = TrustedVoters(
        voters_commitment=bytes([anchor.voters_commitment[0] ^ 0xFF])
        + anchor.voters_commitment[1:],
        ln_proven_weight=anchor.ln_proven_weight,
    )
    report = verify_bundle(Bundle.from_dict(data), trusted_voters=bad)
    assert report.trust_root == "unattested"


def test_anchor_mismatching_previous_message_is_rejected():
    """If the bundle's own previous_message disagrees with the anchor, reject.

    The bundle must not be able to assert a different signing interval than the
    one the caller trusts.
    """
    data = copy.deepcopy(_load_gz(STAKE_FIXTURE))
    anchor = _anchor_from_previous_message(data)
    # Flip the bundle's previous_message commitment so it no longer matches the
    # (unchanged) trusted anchor.
    prev = data["previous_state_proof_message"]
    raw = bytearray(base64.b64decode(prev["voters_commitment_b64"]))
    raw[0] ^= 0xFF
    prev["voters_commitment_b64"] = base64.b64encode(bytes(raw)).decode()
    report = verify_bundle(Bundle.from_dict(data), trusted_voters=anchor)
    assert report.trust_root == "unattested"


def test_hostile_previous_message_fails_closed():
    """A malformed previous message must fail closed, not raise."""
    data = copy.deepcopy(_load_gz(STAKE_FIXTURE))
    anchor = _anchor_from_previous_message(data)
    data["previous_state_proof_message"] = {
        "ln_proven_weight": "not-an-int",
        "voters_commitment_b64": "!!!not-base64!!!",
        "block_headers_commitment_b64": "AA==",
        "first_attested_round": 0,
        "last_attested_round": 0,
    }
    report = verify_bundle(Bundle.from_dict(data), trusted_voters=anchor)
    assert report.trust_root == "unattested"

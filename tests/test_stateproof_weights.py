"""Real-data anchor for A3: sig-tree / participant-tree membership + signed weight.

These tests reconstruct, from real captured state proofs, the signature-tree and
participant-tree leaves and verify the multi-element merklearray proofs
(``SigProofs`` / ``PartProofs``) against their roots, then verify the exact
go-algorand signed-weight threshold. If the fixed-length leaf encodings (the
Falcon compressed->CT conversion, the participant/PK layout), the Sumhash512
``"MA"`` node hashing, the bit-reversed vector-commitment index, the multi-proof
sibling/hint traversal, or the log-domain weight arithmetic were wrong by a
single byte or bit, none of these would verify -- so their success on real
mainnet data is the correctness proof (see
``avm_proofpack._experimental.stateproof`` for the go-algorand derivation).

HONEST SCOPE. A3 is NOT the trust root:

* Signature-tree membership is fully self-contained (root = the state proof's
  ``SigCommit``) and verifies for every fixture.
* Participant-tree membership verifies the reveals are co-members of one
  participants tree. That tree's root equals the message's ``VotersCommitment``
  only when the voter set is unchanged across the interval (true for the Voi
  fixture, NOT for the Algorand-mainnet fixtures, whose message ``VotersCommitment``
  commits to the *next* interval's voters). The correct signing-voters commitment
  lives in an earlier block header a single bundle does not carry -- anchoring it
  is deferred to A5. These tests therefore verify participant membership against
  the *reconstructed* root and separately record where it does / does not equal
  the message ``VotersCommitment``.
* The signed-weight threshold uses the *declared* ``SignedWeight``; A4
  coin-selection (which binds it to the reveals) is not implemented here.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from avm_proofpack import mpack
from avm_proofpack._experimental.stateproof import (
    STRENGTH_TARGET_DEFAULT,
    StateProofError,
    accumulate_revealed_weight,
    approx_proven_weight,
    compute_participant_tree_root,
    compute_signature_tree_root,
    iter_reveals,
    participant_leaf,
    sig_slot_leaf,
    signed_weight_meets_threshold,
    verify_all_reveals,
    verify_participant_tree_membership,
    verify_signature_tree_membership,
    verify_signed_weight_threshold,
)

_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
_FIXTURES = [
    "algorand-mainnet-pay.json",
    "algorand-mainnet-appl.json",
    "voi-mainnet-appl.json",
]
# The message VotersCommitment equals the signing-voters commitment only when
# the voter set is stable across the interval. This holds for the Voi fixture.
_VC_MATCHES_MESSAGE = {
    "algorand-mainnet-pay.json": False,
    "algorand-mainnet-appl.json": False,
    "voi-mainnet-appl.json": True,
}


def _load(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


def _state_proof(bundle: dict) -> dict:
    sp = mpack.decode(base64.b64decode(bundle["state_proof_msgpack_b64"]))
    assert isinstance(sp, dict)
    return sp


def _msg(bundle: dict) -> dict:
    return bundle["state_proof_message"]


def _voters_commitment(bundle: dict) -> bytes:
    return base64.b64decode(_msg(bundle)["voters_commitment_b64"])


# --------------------------------------------------------------------------
# Headline: signature-tree membership (self-contained, root = SigCommit).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_signature_tree_membership_verifies(name):
    """Every revealed SigSlot is a member of the signature tree (root SigCommit)."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    assert verify_signature_tree_membership(sp) is True
    # The reconstructed root is exactly the state proof's SigCommit ('c').
    assert compute_signature_tree_root(sp) == sp["c"]


@pytest.mark.parametrize("name", _FIXTURES)
def test_signature_tree_covers_every_reveal(name):
    """The multiproof authenticates a leaf for every reveal position."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    positions = [pos for pos, _r in iter_reveals(sp)]
    assert len(positions) == len(sp["r"]) > 0
    # sig_slot_leaf must succeed (fixed-length CT conversion) for every reveal.
    for _pos, reveal in iter_reveals(sp):
        leaf = sig_slot_leaf(reveal)
        assert isinstance(leaf, bytes) and len(leaf) == 64


# --------------------------------------------------------------------------
# Headline: participant-tree membership (root = the voters commitment).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_participant_tree_reveals_are_comembers(name):
    """The reveals are co-members of one participants tree (reconstructed root)."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    root = compute_participant_tree_root(sp)  # deterministic; raises if malformed
    assert isinstance(root, bytes) and len(root) == 64
    # Membership against the reconstructed root holds for every fixture.
    assert verify_participant_tree_membership(sp, root) is True
    for _pos, reveal in iter_reveals(sp):
        leaf = participant_leaf(reveal)
        assert isinstance(leaf, bytes) and len(leaf) == 64


@pytest.mark.parametrize("name", _FIXTURES)
def test_participant_root_vs_message_voters_commitment(name):
    """Reconstructed participant root == message VotersCommitment iff voter set stable.

    True for Voi (stable voter set); False for Algorand-mainnet, whose message
    VotersCommitment commits to the *next* interval's voters. This documents the
    A5 anchoring gap, honestly, on real data.
    """
    bundle = _load(name)
    sp = _state_proof(bundle)
    matches = compute_participant_tree_root(sp) == _voters_commitment(bundle)
    assert matches is _VC_MATCHES_MESSAGE[name]
    # verify_participant_tree_membership against message VC agrees with `matches`.
    assert (
        verify_participant_tree_membership(sp, _voters_commitment(bundle)) is matches
    )


# --------------------------------------------------------------------------
# Signed-weight accumulation vs the declared SignedWeight (honest relationship).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_revealed_weight_is_a_strict_subset_of_signed_weight(name):
    """Sum of revealed weights is a strict subset < declared SignedWeight.

    The reveals are a sampled subset of the signers, so their weight sum does NOT
    equal the declared SignedWeight (``w``). The threshold check uses the
    declared value, not this sum.
    """
    bundle = _load(name)
    sp = _state_proof(bundle)
    revealed = accumulate_revealed_weight(sp)
    assert 0 < revealed < sp["w"]


# --------------------------------------------------------------------------
# Signed-weight threshold: the exact go-algorand verifyWeights inequality.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_signed_weight_threshold_holds(name):
    """The declared SignedWeight clears the proven-weight threshold (st=256)."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    assert verify_signed_weight_threshold(sp, _msg(bundle)) is True
    # And signed weight exceeds the (lossily) derived proven weight.
    assert sp["w"] > approx_proven_weight(_msg(bundle)["ln_proven_weight"])


@pytest.mark.parametrize("name", _FIXTURES)
def test_threshold_is_tight_at_the_real_signed_weight(name):
    """numReveals is minimal: dropping below a boundary signed weight fails.

    Binary-search the least signed weight that still clears the threshold; one
    unit below must fail, confirming the inequality is exact (not a loose
    approximation) and fail-closed.
    """
    bundle = _load(name)
    sp = _state_proof(bundle)
    ln = _msg(bundle)["ln_proven_weight"]
    nr = len(sp["pr"])
    real = sp["w"]
    assert signed_weight_meets_threshold(real, ln, nr, STRENGTH_TARGET_DEFAULT)

    lo, hi = 1, real
    while lo < hi:
        mid = (lo + hi) // 2
        if signed_weight_meets_threshold(mid, ln, nr, STRENGTH_TARGET_DEFAULT):
            hi = mid
        else:
            lo = mid + 1
    boundary = lo
    assert signed_weight_meets_threshold(boundary, ln, nr, STRENGTH_TARGET_DEFAULT)
    assert not signed_weight_meets_threshold(boundary - 1, ln, nr, STRENGTH_TARGET_DEFAULT)
    assert boundary <= real


def test_threshold_math_fail_closed():
    """verifyWeights rejects zero/negative/non-integer inputs fail-closed."""
    assert signed_weight_meets_threshold(0, 1, 1, 256) is False
    assert signed_weight_meets_threshold(-1, 1, 1, 256) is False
    assert signed_weight_meets_threshold(100, -1, 1, 256) is False
    assert signed_weight_meets_threshold(100, 1, 1, True) is False  # bool rejected
    assert signed_weight_meets_threshold(100, 1, 0, 256) in (True, False)


def test_higher_strength_target_requires_more_weight():
    """A large strength target makes the same signed weight fail (monotonic)."""
    bundle = _load("voi-mainnet-appl.json")
    sp = _state_proof(bundle)
    ln = _msg(bundle)["ln_proven_weight"]
    nr = len(sp["pr"])
    assert signed_weight_meets_threshold(sp["w"], ln, nr, 256) is True
    assert signed_weight_meets_threshold(sp["w"], ln, nr, 10_000_000) is False


# --------------------------------------------------------------------------
# Tamper cases: every mutation is rejected fail-closed.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_mutated_sig_proof_fails(name):
    """Flipping one bit of a SigProofs sibling breaks the root -> reject."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    sib = sp["S"]["pth"][0]
    sp["S"]["pth"][0] = bytes([sib[0] ^ 0x01]) + sib[1:]
    assert verify_signature_tree_membership(sp) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_mutated_part_proof_fails(name):
    """Flipping one bit of a PartProofs sibling breaks the root -> reject."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    good_root = compute_participant_tree_root(sp)
    sib = sp["P"]["pth"][0]
    sp["P"]["pth"][0] = bytes([sib[0] ^ 0x01]) + sib[1:]
    assert verify_participant_tree_membership(sp, good_root) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_mutated_sig_slot_weight_breaks_leaf(name):
    """Tampering a SigSlot's running-weight L changes its leaf -> reject."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    # Pick a reveal that carries an explicit L and bump it.
    for _pos, reveal in iter_reveals(sp):
        if "l" in reveal["s"]:
            reveal["s"]["l"] = reveal["s"]["l"] + 1
            break
    else:
        pytest.skip("fixture has no explicit SigSlot L to tamper")
    assert verify_signature_tree_membership(sp) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_mutated_participant_weight_breaks_leaf(name):
    """Tampering a participant's weight changes its leaf -> reject."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    root = compute_participant_tree_root(sp)
    _pos, reveal = next(iter_reveals(sp))
    reveal["p"]["w"] = reveal["p"]["w"] + 1
    assert verify_participant_tree_membership(sp, root) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_understated_signed_weight_fails_threshold(name):
    """A signed weight below the proven-weight bound fails the threshold."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    ln = _msg(bundle)["ln_proven_weight"]
    nr = len(sp["pr"])
    understated = sp["w"] // 2
    assert signed_weight_meets_threshold(understated, ln, nr, 256) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_overstated_proven_weight_fails_threshold(name):
    """Raising the proven weight (LnProvenWeight) above signed weight rejects."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    nr = len(sp["pr"])
    # Push ln proven weight far above ln(signed weight): must fail.
    huge_ln = _msg(bundle)["ln_proven_weight"] + 5 * (1 << 16)
    assert signed_weight_meets_threshold(sp["w"], huge_ln, nr, 256) is False


# --------------------------------------------------------------------------
# Combined A2+A3 convenience result.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_all_reveals_structured_result(name):
    """The combined result reports honest per-fixture truth; never a trust root."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    msg = _msg(bundle)
    res = verify_all_reveals(
        sp,
        block_headers_commitment=base64.b64decode(msg["block_headers_commitment_b64"]),
        voters_commitment=_voters_commitment(bundle),
        ln_proven_weight=msg["ln_proven_weight"],
        first_attested_round=msg["first_attested_round"],
        last_attested_round=msg["last_attested_round"],
    )
    assert res.reveal_count == len(sp["r"]) > 0
    assert res.num_reveals == len(sp["pr"])
    assert res.signed_weight == sp["w"]
    assert res.all_reveals_ok is True          # A2: Falcon + ephemeral membership
    assert res.sig_tree_ok is True             # A3: sig-tree membership
    assert res.weight_threshold_ok is True     # A3: signed-weight threshold
    # part_tree_ok (vs message VotersCommitment) follows the anchoring reality.
    assert res.part_tree_ok is _VC_MATCHES_MESSAGE[name]
    # Never a trust root, regardless of the other outcomes.
    assert res.is_trust_root is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_all_reveals_with_correct_root_all_true(name):
    """Given the correct participants commitment, every A2+A3 check passes."""
    bundle = _load(name)
    sp = _state_proof(bundle)
    msg = _msg(bundle)
    correct_root = compute_participant_tree_root(sp)
    res = verify_all_reveals(
        sp,
        block_headers_commitment=base64.b64decode(msg["block_headers_commitment_b64"]),
        voters_commitment=_voters_commitment(bundle),
        ln_proven_weight=msg["ln_proven_weight"],
        first_attested_round=msg["first_attested_round"],
        last_attested_round=msg["last_attested_round"],
        participants_commitment=correct_root,
    )
    assert res.all_checks_ok is True
    assert res.is_trust_root is False


# --------------------------------------------------------------------------
# Structural fail-closed contract.
# --------------------------------------------------------------------------


def test_leaf_builders_reject_malformed():
    with pytest.raises(StateProofError):
        sig_slot_leaf("not a dict")
    with pytest.raises(StateProofError):
        sig_slot_leaf({})
    with pytest.raises(StateProofError):
        participant_leaf({})
    with pytest.raises(StateProofError):
        participant_leaf({"p": {"w": 1}})  # no PK


def test_verify_functions_are_fail_closed_on_garbage():
    assert verify_signature_tree_membership({}) is False
    assert verify_participant_tree_membership({}, b"\x00" * 64) is False
    assert verify_signed_weight_threshold({}, {"ln_proven_weight": 1}) is False

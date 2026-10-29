"""A5 chain authentication tests. Anchoring is caller trust; this is not absolute."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest

_CHAINS = json.loads((Path(__file__).parent / "chain_kat/chains.json").read_text(encoding="utf-8"))
_VOI = _CHAINS["voi-mainnet"]
_ROUNDS = sorted(int(r) for r in _VOI if r.isdigit())
_ANCHOR_ROUND, _MID_ROUND, _TARGET_ROUND = _ROUNDS[0], _ROUNDS[1], _ROUNDS[2]


def _chain_module():
    import importlib
    import importlib.util

    name = "avm_proofpack._experimental.chain"
    assert importlib.util.find_spec(name) is not None, "A5 chain module is missing"
    return importlib.import_module(name)


def _proof(round_number: int) -> Any:
    from avm_proofpack import mpack

    entry = _VOI[str(round_number)]
    return mpack.decode(base64.b64decode(entry["state_proof_b64"]))


def _message(round_number: int) -> dict:
    return copy.deepcopy(_VOI[str(round_number)]["message"])


def _genesis() -> bytes:
    return base64.b64decode(_VOI["genesis_hash"])


def _anchor():
    chain = _chain_module()
    m = _message(_ANCHOR_ROUND)
    return chain.ChainAnchor(
        round=_ANCHOR_ROUND,
        voters_commitment=base64.b64decode(m["VotersCommitment"]),
        ln_proven_weight=m["LnProvenWeight"],
        genesis_hash=_genesis(),
    )


def _link(round_number: int, *, message=None):
    chain = _chain_module()
    return chain.ChainLink(
        state_proof=_proof(round_number),
        message=message if message is not None else _message(round_number),
        genesis_hash=_genesis(),
    )


def _links():
    return {r: _link(r) for r in (_MID_ROUND, _TARGET_ROUND)}


def test_real_voi_chain_authenticates():
    chain = _chain_module()
    result = chain.authenticate_chain(_anchor(), _links(), target_round=_TARGET_ROUND)
    assert result.ok, result.failure
    assert result.links_verified == 2
    assert result.is_trust_root is True
    assert result.failure is None


def test_target_inputs_are_the_previous_interval_fields():
    """The inputs that authenticated the target must be the MID link's message
    fields -- the previous interval's, not the target's own."""
    chain = _chain_module()
    result = chain.authenticate_chain(_anchor(), _links(), target_round=_TARGET_ROUND)
    assert result.ok, result.failure
    mid = _message(_MID_ROUND)
    commitment, ln = result.target_inputs
    assert commitment == base64.b64decode(mid["VotersCommitment"])
    assert ln == mid["LnProvenWeight"]
    # and they are genuinely the mid link's own fields, not the target's --
    # for this Voi window the voter set did not rotate, so mid and target
    # messages coincide and no inequality can be asserted here.
    assert commitment == base64.b64decode(mid["VotersCommitment"])
    assert ln == mid["LnProvenWeight"]


def test_wrong_anchor_commitment_fails_at_first_link():
    chain = _chain_module()
    anchor = _anchor()
    bad = chain.ChainAnchor(
        round=anchor.round,
        voters_commitment=bytes([anchor.voters_commitment[0] ^ 0xFF]) + anchor.voters_commitment[1:],
        ln_proven_weight=anchor.ln_proven_weight,
        genesis_hash=anchor.genesis_hash,
    )
    result = chain.authenticate_chain(bad, _links(), target_round=_TARGET_ROUND)
    assert result.ok is False
    assert result.links_verified == 0
    assert result.is_trust_root is False
    assert "round" in (result.failure or "")


def test_genesis_mismatch_fails():
    chain = _chain_module()
    links = _links()
    links[_MID_ROUND] = chain.ChainLink(
        state_proof=links[_MID_ROUND].state_proof,
        message=links[_MID_ROUND].message,
        genesis_hash=b"\x00" * 32,
    )
    result = chain.authenticate_chain(_anchor(), links, target_round=_TARGET_ROUND)
    assert result.ok is False
    assert "genesis" in (result.failure or "")


def test_missing_middle_link_fails():
    chain = _chain_module()
    result = chain.authenticate_chain(
        _anchor(), {_TARGET_ROUND: _link(_TARGET_ROUND)}, target_round=_TARGET_ROUND
    )
    assert result.ok is False
    assert "missing link" in (result.failure or "")


def test_link_attesting_a_different_round_fails():
    chain = _chain_module()
    links = _links()
    # key the mid link under the target round but keep its own message
    links[_TARGET_ROUND] = _link(_MID_ROUND)
    result = chain.authenticate_chain(_anchor(), links, target_round=_TARGET_ROUND)
    assert result.ok is False
    assert "attests" in (result.failure or "")


def test_tampered_reveal_fails():
    chain = _chain_module()
    sp = _proof(_MID_ROUND)
    position = sp["pr"][0]
    signature = bytearray(sp["r"][position]["s"]["s"]["sig"])
    signature[0] ^= 0x01
    sp["r"][position]["s"]["s"]["sig"] = bytes(signature)
    links = _links()
    links[_MID_ROUND] = chain.ChainLink(sp, _message(_MID_ROUND), _genesis())
    result = chain.authenticate_chain(_anchor(), links, target_round=_TARGET_ROUND)
    assert result.ok is False
    assert result.links_verified == 0


def test_target_must_be_on_the_interval_grid():
    chain = _chain_module()
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain(_anchor(), _links(), target_round=_TARGET_ROUND + 1)


def test_target_must_follow_the_anchor():
    chain = _chain_module()
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain(_anchor(), _links(), target_round=_ANCHOR_ROUND)


def test_interval_must_be_positive():
    chain = _chain_module()
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain(_anchor(), _links(), target_round=_TARGET_ROUND, interval=0)


def test_anchor_must_be_a_chain_anchor():
    chain = _chain_module()
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain({"round": 1}, _links(), target_round=_TARGET_ROUND)


def test_wrong_anchor_is_caught_by_coin_selection():
    """Document the layering.

    The participant tree is checked against the authenticated commitment, but a
    wrong anchor also changes the coin stream, so coin selection rejects. That
    makes the participant-tree input redundant defence-in-depth rather than the
    load-bearing binding. Pin which component rejects so a refactor that drops
    the coin check cannot silently remove the only binding.
    """
    chain = _chain_module()
    anchor = _anchor()
    bad_commitment = bytes([anchor.voters_commitment[0] ^ 0xFF]) + anchor.voters_commitment[1:]

    result = chain.verify_link(
        _link(_MID_ROUND),
        voters_commitment=bad_commitment,
        ln_proven_weight=anchor.ln_proven_weight,
        genesis_hash=_genesis(),
    )
    assert result.coin_selection_ok is False
    assert result.ok is False


def test_verify_link_rejects_a_non_chainlink():
    chain = _chain_module()
    with pytest.raises(chain.ChainError):
        chain.verify_link(
            {"state_proof": {}, "message": {}},
            voters_commitment=b"\x00" * 64,
            ln_proven_weight=1,
            genesis_hash=_genesis(),
        )


def test_verify_link_rejects_genesis_mismatch():
    chain = _chain_module()
    anchor = _anchor()
    with pytest.raises(chain.ChainError):
        chain.verify_link(
            _link(_MID_ROUND),
            voters_commitment=anchor.voters_commitment,
            ln_proven_weight=anchor.ln_proven_weight,
            genesis_hash=b"\x00" * 32,
        )


def test_rejects_a_non_int_anchor_round():
    """A str round used to raise a bare TypeError; the error surface is ChainError."""
    chain = _chain_module()
    anchor = _anchor()
    for bad in (str(anchor.round), -1, 1.5, True):
        with pytest.raises(chain.ChainError):
            chain.authenticate_chain(
                chain.ChainAnchor(bad, anchor.voters_commitment,
                                 anchor.ln_proven_weight, anchor.genesis_hash),
                _links(), target_round=_TARGET_ROUND)

def test_rejects_malformed_anchor_material():
    chain = _chain_module()
    anchor = _anchor()
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain(
            chain.ChainAnchor(anchor.round, b'\x00' * 63,
                             anchor.ln_proven_weight, anchor.genesis_hash),
            _links(), target_round=_TARGET_ROUND)
    with pytest.raises(chain.ChainError):
        chain.authenticate_chain(
            chain.ChainAnchor(anchor.round, anchor.voters_commitment,
                             anchor.ln_proven_weight, b'\x00' * 31),
            _links(), target_round=_TARGET_ROUND)

def test_chain_result_cannot_be_internally_inconsistent():
    chain = _chain_module()
    """ok without target_inputs, or failure without ok, must not exist."""
    with pytest.raises(chain.ChainError):
        chain.ChainResult(True, 1, 100, None, None)
    with pytest.raises(chain.ChainError):
        chain.ChainResult(False, 1, 100, (b'\x00' * 64, 1), None)
    with pytest.raises(chain.ChainError):
        chain.ChainResult(False, -1, 100, None, 'x')



# --- rotation fixture: the Algorand A4 proof, whose message fields differ ---
# --- from the previous interval (the Voi fixtures do NOT rotate).      ---


_ALGO_FIXTURE = Path(__file__).parent / "fixtures" / "algorand-mainnet-pay.json"
_CONTEXTS = Path(__file__).parent / "coin_kat" / "fixture_contexts.json"


def _algorand_rotation_link():
    """A real proof whose message VotersCommitment/LnProvenWeight differ from
    the previous interval's authenticated values. Without this, own-vs-previous
    mix-ups are unobservable."""
    from avm_proofpack import mpack

    fixture = json.loads(_ALGO_FIXTURE.read_text(encoding="utf-8"))
    context = json.loads(_CONTEXTS.read_text(encoding="utf-8"))["contexts"]["algorand-mainnet"]
    chain = _chain_module()
    return chain.ChainLink(
        state_proof=mpack.decode(base64.b64decode(fixture["state_proof_msgpack_b64"])),
        message=fixture["state_proof_message"],
        genesis_hash=b"\x00" * 32,
    ), context


def test_rotation_fixture_verifies_with_previous_interval_inputs():
    chain = _chain_module()
    link, context = _algorand_rotation_link()
    result = chain.verify_link(
        link,
        voters_commitment=base64.b64decode(context["voters_commitment_b64"]),
        ln_proven_weight=context["ln_proven_weight"],
        genesis_hash=b"\x00" * 32,
    )
    assert result.reveals_ok is True
    assert result.coin_selection_ok is True


def test_rotation_fixture_rejects_the_messages_own_commitment():
    """The participant tree must use the PREVIOUS interval's commitment. Using
    the message's own commitment rejects a valid mainnet proof -- which is what
    makes that mutation behaviour-changing, not equivalent."""
    chain = _chain_module()
    link, context = _algorand_rotation_link()
    own = base64.b64decode(link.message["voters_commitment_b64"])
    prev = base64.b64decode(context["voters_commitment_b64"])
    assert own != prev, "fixture must rotate for this test to mean anything"

    result = chain.verify_link(
        link,
        voters_commitment=own,
        ln_proven_weight=context["ln_proven_weight"],
        genesis_hash=b"\x00" * 32,
    )
    assert result.reveals_ok is False


def test_threshold_uses_the_authenticated_ln_not_the_messages(monkeypatch):
    """SECURITY regression: the proven-weight bound must be taken from the
    authenticated previous interval. Feeding it the message's own
    LnProvenWeight makes the bound attacker-chosen."""
    chain = _chain_module()
    link, context = _algorand_rotation_link()
    prev_ln = context["ln_proven_weight"]
    own_ln = link.message["ln_proven_weight"]
    assert prev_ln != own_ln, "fixture must differ for this test to mean anything"

    seen = []
    real = chain.signed_weight_meets_threshold

    def spy(signed_weight, ln_proven_weight, num_reveals, strength_target):
        seen.append(ln_proven_weight)
        return real(signed_weight, ln_proven_weight, num_reveals, strength_target)

    monkeypatch.setattr(chain, "signed_weight_meets_threshold", spy)
    chain.verify_link(
        link,
        voters_commitment=base64.b64decode(context["voters_commitment_b64"]),
        ln_proven_weight=prev_ln,
        genesis_hash=b"\x00" * 32,
    )
    assert seen == [prev_ln], f"threshold fed {seen} instead of the authenticated {prev_ln}"

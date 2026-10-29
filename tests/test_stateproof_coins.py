"""A4 differential tests. Coin selection is NOT consensus authentication."""
from __future__ import annotations

import copy
import importlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_VECTORS = json.loads((Path(__file__).parent / "coin_kat/coins_v0.json").read_text(encoding="utf-8"))


def _coins_module():
    name = "avm_proofpack._experimental.coins"
    assert importlib.util.find_spec(name) is not None, "A4 coin-selection module is missing"
    return importlib.import_module(name)


def _args(v):
    return {
        "participants_commitment": bytes.fromhex(v["participants_commitment_hex"]),
        "ln_proven_weight": v["ln_proven_weight"],
        "signature_commitment": bytes.fromhex(v["signature_commitment_hex"]),
        "signed_weight": v["signed_weight"],
        "message_hash": bytes.fromhex(v["message_hash_hex"]),
    }


def test_seed_matches_independent_go_vectors():
    coins = _coins_module()
    for v in _VECTORS:
        seed = coins.coin_seed(**_args(v))
        assert seed.hex() == v["seed_hex"]
        assert len(seed) == 180


@pytest.mark.parametrize("v", _VECTORS, ids=lambda v: v["name"])
def test_coins_match_independent_go_vectors(v):
    coins = _coins_module()
    assert hasattr(coins, "generate_coins"), "A4 SHAKE/rejection sampling is missing"
    assert list(coins.generate_coins(**_args(v), count=len(v["coins"]))) == v["coins"]


def _fixture(name) -> tuple[Any, dict]:
    import base64

    from avm_proofpack import mpack
    from avm_proofpack._experimental.stateproof import state_proof_message_hash
    b = json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
    m = b["state_proof_message"]
    contexts = json.loads((Path(__file__).parent / "coin_kat/fixture_contexts.json").read_text(encoding="utf-8"))["contexts"]
    context = contexts["voi-mainnet" if name.startswith("voi") else "algorand-mainnet"]
    msg_hash = state_proof_message_hash(
        block_headers_commitment=base64.b64decode(m["block_headers_commitment_b64"]),
        voters_commitment=base64.b64decode(m["voters_commitment_b64"]),
        ln_proven_weight=m["ln_proven_weight"],
        first_attested_round=m["first_attested_round"], last_attested_round=m["last_attested_round"],
    )
    return mpack.decode(base64.b64decode(b["state_proof_msgpack_b64"])), {
        "participants_commitment": base64.b64decode(context["voters_commitment_b64"]),
        "ln_proven_weight": context["ln_proven_weight"],
        "message_hash": msg_hash,
    }


@pytest.mark.parametrize("name", ["algorand-mainnet-pay", "algorand-mainnet-appl", "voi-mainnet-appl"])
def test_real_fixture_coin_selection(name):
    coins = _coins_module()
    sp, args = _fixture(name)
    assert len(sp["pr"]) > len(sp["r"]), "repeated selected positions must remain allowed"
    assert hasattr(coins, "coin_selection_result"), "A4 position/range verification is missing"
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is True


# --- tamper resistance: every mutation below must be REJECTED -------------


def _tampered(name="algorand-mainnet-pay"):
    sp, args = _fixture(name)
    return copy.deepcopy(sp), args


def _gen_args(sp, args):
    """generate_coins needs the proof's own signed weight and sig commitment."""
    return {**args, "signature_commitment": sp["c"], "signed_weight": sp["w"]}


def test_rejects_substituted_selected_position():
    coins = _coins_module()
    sp, args = _tampered()
    original = sp["pr"][0]
    sp["pr"][0] = next(p for p in sp["r"] if p != original)
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_range_shifted_above_its_coin():
    # A +/-1 shift is NOT detectable (ranges are ~1e13 wide); moving the whole
    # range clear of the coin is, and that is the property worth asserting.
    coins = _coins_module()
    sp, args = _tampered()
    sp["r"][sp["pr"][0]]["s"]["l"] += sp["r"][sp["pr"][0]]["p"]["w"]
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_range_shortened_below_its_coin():
    coins = _coins_module()
    sp, args = _tampered()
    position = sp["pr"][0]
    start = sp["r"][position]["s"]["l"]
    coin = coins.generate_coins(**_gen_args(sp, args), count=1)[0]
    assert coin > start, "fixture coin must sit above the range start for this case"
    sp["r"][position]["p"]["w"] = coin - start
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_wrong_signature_commitment():
    coins = _coins_module()
    sp, args = _tampered()
    assert coins.coin_selection_result(
        sp, signature_commitment=b"\x00" * 64, **args) is False


def test_rejects_tampered_signed_weight():
    coins = _coins_module()
    sp, args = _tampered()
    sp["w"] += 1
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_missing_reveal():
    coins = _coins_module()
    sp, args = _tampered()
    del sp["r"][sp["pr"][0]]
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_unselected_extra_reveal():
    coins = _coins_module()
    sp, args = _tampered()
    sp["r"][2**40] = sp["r"][sp["pr"][0]]
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_rejects_empty_and_malformed_proofs():
    coins = _coins_module()
    sp, args = _tampered()
    for bad in (None, {}, {"pr": [], "r": {}}, {"pr": "x", "r": {}},
                {"pr": [0], "r": {}}, {"pr": [True], "r": {0: sp["r"][sp["pr"][0]]}}):
        assert coins.coin_selection_result(bad, signature_commitment=b"\x00" * 64, **args) is False


def test_count_bounds_and_draw_budget():
    coins = _coins_module()
    sp, args = _tampered()
    with pytest.raises(coins.CoinSelectionError):
        coins.generate_coins(**_gen_args(sp, args), count=coins.MAX_REVEALS + 1)
    with pytest.raises(coins.CoinSelectionError):
        coins.generate_coins(**_gen_args(sp, args), count=-1)
    with pytest.raises(coins.CoinSelectionError):
        coins.generate_coins(**{**_gen_args(sp, args), "signed_weight": 0}, count=1)


def test_rejects_non_uint64_and_bool_inputs():
    coins = _coins_module()
    sp, args = _tampered()
    for bad in (True, 1.0, "1", -1, 2**64):
        with pytest.raises(coins.CoinSelectionError):
            coins.generate_coins(**{**_gen_args(sp, args), "ln_proven_weight": bad}, count=1)


# --- guards that were present but unpinned; each test below dies if its
# --- guard is deleted, which is the whole point of pinning it -------------


def test_rejects_complete_proof_with_no_positions():
    """Pins `0 < len(positions)`. Without it an empty proof passes vacuously:
    coverage holds (empty==empty), c matches, count=0 yields (), all() over
    nothing is True."""
    coins = _coins_module()
    sp, args = _tampered()
    empty = {"pr": [], "r": {}, "c": sp["c"], "w": sp["w"]}
    assert coins.coin_selection_result(empty, signature_commitment=sp["c"], **args) is False


def test_coin_count_is_pinned_to_selected_positions_not_reveals():
    """Pins `count=len(parsed)`. With len(reveals) the zip truncates at the
    reveal count and a bad tail position is silently never compared."""
    coins = _coins_module()
    sp, args = _tampered()
    base = list(sp["pr"])
    tail_coin = coins.generate_coins(**_gen_args(sp, args), count=len(base) + 1)[-1]
    bad = next(
        p for p in set(base)
        if not (sp["r"][p]["s"].get("l", 0) <= tail_coin
                and tail_coin - sp["r"][p]["s"].get("l", 0) < sp["r"][p]["p"]["w"])
    )
    sp["pr"] = base + [bad]
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_missing_log_defaults_to_zero():
    """Pins `slot.get("l", 0)`.

    Real mainnet reveals already omit "l" when Log==0 (the voi fixture does), so
    a missing key must mean 0. With signed_weight=1 every coin is exactly 0, so
    the range must be [0,1): a default of 1 would start the range at 1 and reject.
    """
    coins = _coins_module()
    sp, args = _tampered("voi-mainnet-appl")
    assert any("l" not in sp["r"][p]["s"] for p in sp["r"]), \
        "fixture should exercise an omitted log"

    synthetic = {
        "pr": [0],
        "r": {0: {"s": {}, "p": {"w": 1}}},
        "c": b"\x11" * 64,
        "w": 1,
    }
    assert coins.coin_selection_result(
        synthetic,
        participants_commitment=args["participants_commitment"],
        ln_proven_weight=args["ln_proven_weight"],
        signature_commitment=b"\x11" * 64,
        message_hash=args["message_hash"],
    ) is True


def test_pins_position_ceiling():
    """Pins the position uint64 ceiling.

    The reveal MUST exist under the oversized key, otherwise the lookup fails
    first and the ceiling is never reached (this test previously passed
    vacuously). With a matching reveal and weight 1, every coin is 0, so without
    the ceiling this proof is accepted.
    """
    coins = _coins_module()
    sp, args = _tampered()
    oversized = {
        "pr": [2**64],
        "r": {2**64: {"s": {}, "p": {"w": 1}}},
        "c": sp["c"],
        "w": 1,
    }
    assert coins.coin_selection_result(oversized, signature_commitment=sp["c"], **args) is False


def test_rejects_oversized_weight():
    """Pins the weight bound. A weight above uint64 makes `_UINT64_MAX - weight`
    negative, so the sum bound rejects it; without any weight bound the proof is
    accepted (coin 0 falls in [0, 2^64))."""
    coins = _coins_module()
    sp, args = _tampered()
    oversized = {
        "pr": [0],
        "r": {0: {"s": {}, "p": {"w": 2**64}}},
        "c": sp["c"],
        "w": 1,
    }
    assert coins.coin_selection_result(oversized, signature_commitment=sp["c"], **args) is False


def test_rejects_negative_range_start():
    """Pins `0 <= running`. A negative range start is outside the uint64 domain
    yet would otherwise accept coin 0 inside [-1, 1)."""
    coins = _coins_module()
    sp, args = _tampered()
    negative = {
        "pr": [0],
        "r": {0: {"s": {"l": -1}, "p": {"w": 2}}},
        "c": sp["c"],
        "w": 1,
    }
    assert coins.coin_selection_result(negative, signature_commitment=sp["c"], **args) is False


def test_coin_inputs_come_from_previous_interval_not_the_message():
    """Coin selection must use the PREVIOUS interval's voters commitment; the
    message itself carries the NEXT interval's commitment.

    A future "simplification" that wires the message's own fields in would
    silently change the coin stream.

    Only the Algorand fixture can discriminate: for Voi the prior interval's
    voters commitment and LnProvenWeight coincide with the message's own fields
    (no participant rotation between those intervals), so that fixture passes
    either way and is deliberately not asserted here.
    """
    import base64

    coins = _coins_module()
    name = "algorand-mainnet-pay"
    sp, args = _fixture(name)
    b = json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
    m = b["state_proof_message"]
    message_commitment = base64.b64decode(m["voters_commitment_b64"])

    # The two intervals genuinely differ, which is what makes this test bite.
    assert message_commitment != args["participants_commitment"]
    assert m["ln_proven_weight"] != args["ln_proven_weight"]

    message_values = {
        **args,
        "participants_commitment": message_commitment,
        "ln_proven_weight": m["ln_proven_weight"],
    }
    assert coins.coin_selection_result(
        sp, signature_commitment=sp["c"], **message_values) is False


def test_rejects_bool_reveal_keys():
    """Pins the int-key filter.

    True and 1 are the SAME dict key, so merely adding True corrupts an existing
    reveal and fails for the wrong reason. Here the reveal for position 1 is
    re-keyed to True with identical content: every content/range/coverage check
    still passes (set(reveals) == set(positions) because True == 1), so only the
    explicit int-key filter rejects it.
    """
    coins = _coins_module()
    sp, args = _tampered()
    assert 1 in sp["r"], "need position 1 so True aliases it"
    sp["r"] = {(True if k == 1 else k): v for k, v in sp["r"].items()}
    assert any(type(k) is not int for k in sp["r"])
    assert coins.coin_selection_result(sp, signature_commitment=sp["c"], **args) is False


def test_bytes_rejects_multibyte_memoryview():
    """Pins the post-`bytes()` length recheck: a memoryview of 64 two-byte
    elements has len()==64 but 128 bytes."""
    import array

    coins = _coins_module()
    multi = memoryview(array.array("H", [0] * 64))
    assert len(multi) == 64
    with pytest.raises(coins.CoinSelectionError):
        coins._bytes("commitment", multi, 64)


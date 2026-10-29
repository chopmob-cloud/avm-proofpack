"""Real-data regression anchor for ephemeral-key key-commitment membership (A2).

The headline tests reconstruct the ``merklesignature`` leaf for real captured
reveals and verify their Sumhash512 vector-commitment membership proof
(``prf``) up to the participant's key commitment (``Participant.PK.cmt``), for
EVERY fixture. If the leaf encoding, the ``"MA"`` node hashing, the bit-reversed
vector-commitment index, or the leaf round were wrong by a single byte, none of
these would verify -- so their success on real mainnet data is the correctness
proof for the encoding (see ``avm_proofpack.consensus.merklesig`` for the
go-algorand derivation).

These tests also exercise ``verify_reveal`` (Falcon signature AND membership,
the complete single-reveal check) and confirm every tamper -- key, round, proof
path, index, message -- is rejected fail-closed. They deliberately do NOT assert
weights, thresholds, coin-selection, or voters-commitment anchoring: this module
is not a trust root and is not wired into ``verify_bundle``.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from avm_proofpack import mpack
from avm_proofpack.consensus.merklesig import (
    CRYPTO_PRIMITIVES_ID,
    KEYS_IN_MSS_DOMAIN,
    MerkleSigError,
    committable_public_key_hashrep,
    committable_public_key_leaf,
    verify_sumhash_vector_commitment,
)
from avm_proofpack.consensus.stateproof import (
    StateProofError,
    ephemeral_key_first_round,
    iter_reveals,
    reveal_membership_inputs,
    state_proof_message_hash,
    verify_ephemeral_key_membership,
    verify_reveal,
)

_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
_FIXTURES = [
    "algorand-mainnet-pay.json",
    "algorand-mainnet-appl.json",
    "voi-mainnet-appl.json",
]


def _load(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


def _decoded_state_proof(bundle: dict) -> dict:
    sp = mpack.decode(base64.b64decode(bundle["state_proof_msgpack_b64"]))
    assert isinstance(sp, dict)
    return sp


def _signed_round(bundle: dict) -> int:
    # The state-proof round used to derive the ephemeral-key leaf is the
    # message's LastAttestedRound (crypto/merklesignature Verifier.VerifyBytes).
    return bundle["state_proof_message"]["last_attested_round"]


def _message_hash(bundle: dict) -> bytes:
    spm = bundle["state_proof_message"]
    return state_proof_message_hash(
        block_headers_commitment=base64.b64decode(spm["block_headers_commitment_b64"]),
        voters_commitment=base64.b64decode(spm["voters_commitment_b64"]),
        ln_proven_weight=spm["ln_proven_weight"],
        first_attested_round=spm["first_attested_round"],
        last_attested_round=spm["last_attested_round"],
    )


# --------------------------------------------------------------------------
# Headline: real captured reveals' ephemeral keys verify their membership.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_every_reveal_membership_verifies(name):
    """EVERY reveal in the fixture proves membership under its participant's cmt.

    This is the real-data proof of the leaf encoding + Sumhash512 node hashing
    + bit-reversed index: a wrong construction verifies zero reveals.
    """
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)

    total = 0
    for _pos, reveal in iter_reveals(state_proof):
        total += 1
        assert verify_ephemeral_key_membership(reveal, signed_round) is True, (
            f"{name}: reveal {_pos} failed key-commitment membership"
        )
    assert total > 0, "fixture has no reveals"


@pytest.mark.parametrize("name", _FIXTURES)
def test_membership_leaf_matches_documented_encoding(name):
    """The leaf is Sumhash512("KP" || LE16(0) || LE64(round) || vkey.k)."""
    import struct

    from avm_proofpack.consensus.sumhash import sumhash512

    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))
    inputs = reveal_membership_inputs(reveal)
    leaf_round = ephemeral_key_first_round(signed_round, inputs.key_lifetime)

    manual_hashrep = (
        KEYS_IN_MSS_DOMAIN
        + struct.pack("<H", CRYPTO_PRIMITIVES_ID)
        + struct.pack("<Q", leaf_round)
        + inputs.verifying_key
    )
    assert committable_public_key_hashrep(inputs.verifying_key, leaf_round) == manual_hashrep
    assert committable_public_key_leaf(inputs.verifying_key, leaf_round) == sumhash512(
        manual_hashrep
    )
    # And it authenticates directly through the low-level vector-commitment verifier.
    leaf = committable_public_key_leaf(inputs.verifying_key, leaf_round)
    assert verify_sumhash_vector_commitment(
        leaf, inputs.index, inputs.tree_depth, inputs.path, inputs.key_commitment
    ) is True


# --------------------------------------------------------------------------
# Complete single-reveal check: Falcon signature AND membership.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_reveal_passes_for_every_real_reveal(name):
    """verify_reveal (Falcon + membership) accepts every real reveal."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    message_hash = _message_hash(bundle)
    signed_round = _signed_round(bundle)
    for _pos, reveal in iter_reveals(state_proof):
        assert verify_reveal(reveal, message_hash, signed_round) is True, (
            f"{name}: reveal {_pos} failed the combined Falcon+membership check"
        )


# --------------------------------------------------------------------------
# Tamper cases: every mutation is rejected fail-closed.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_tampered_verifying_key_fails_membership(name):
    """Flipping one bit of the ephemeral key breaks the leaf -> membership fails."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    good_key = reveal["s"]["s"]["vkey"]["k"]
    reveal["s"]["s"]["vkey"]["k"] = bytes([good_key[0] ^ 0x01]) + good_key[1:]
    assert verify_ephemeral_key_membership(reveal, signed_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_wrong_round_fails_membership(name):
    """A round in a different key-lifetime window yields a different leaf -> fail."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    lf = reveal["p"]["p"]["lf"]
    # Shift into the previous key-lifetime window (a genuinely different leaf).
    wrong_round = signed_round - lf
    assert wrong_round >= 0
    assert ephemeral_key_first_round(wrong_round, lf) != ephemeral_key_first_round(
        signed_round, lf
    )
    assert verify_ephemeral_key_membership(reveal, wrong_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_mutated_proof_path_fails_membership(name):
    """Flipping one bit of a sibling in the path breaks the root -> fail."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    path = reveal["s"]["s"]["prf"]["pth"]
    sib0 = path[0]
    path[0] = bytes([sib0[0] ^ 0x01]) + sib0[1:]
    assert verify_ephemeral_key_membership(reveal, signed_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_wrong_index_fails_membership(name):
    """Changing the leaf index moves it to a position the path no longer proves."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    idx = reveal["s"]["s"]["idx"]
    reveal["s"]["s"]["idx"] = idx ^ 0x01
    assert verify_ephemeral_key_membership(reveal, signed_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_reveal_fails_on_membership_tamper(name):
    """verify_reveal rejects when only the membership proof is tampered."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    message_hash = _message_hash(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    # Falcon signature is untouched and valid; break only the proof path.
    path = reveal["s"]["s"]["prf"]["pth"]
    path[-1] = bytes([path[-1][0] ^ 0x01]) + path[-1][1:]
    assert verify_reveal(reveal, message_hash, signed_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_reveal_fails_on_falcon_tamper(name):
    """verify_reveal rejects when only the Falcon signature is tampered.

    Mutating the ephemeral key would break membership too; instead flip a bit of
    the Falcon *signature* so membership still passes but the signature check
    fails, proving verify_reveal enforces BOTH conditions.
    """
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    message_hash = _message_hash(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))

    # Membership alone still passes (key/path/index untouched).
    assert verify_ephemeral_key_membership(reveal, signed_round) is True
    good_sig = reveal["s"]["s"]["sig"]
    # Flip a payload bit (after the 2-byte det1024 header) to keep it structural.
    reveal["s"]["s"]["sig"] = good_sig[:2] + bytes([good_sig[2] ^ 0x01]) + good_sig[3:]
    assert verify_reveal(reveal, message_hash, signed_round) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_verify_reveal_fails_on_wrong_message(name):
    """verify_reveal rejects a valid reveal against a different message hash."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    good = _message_hash(bundle)
    tampered = bytes([good[0] ^ 0x01]) + good[1:]
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))
    assert verify_reveal(reveal, tampered, signed_round) is False


# --------------------------------------------------------------------------
# Structural validation / fail-closed contract.
# --------------------------------------------------------------------------


def test_reveal_membership_inputs_rejects_malformed():
    with pytest.raises(StateProofError):
        reveal_membership_inputs("not a dict")
    with pytest.raises(StateProofError):
        reveal_membership_inputs({})  # no participant
    with pytest.raises(StateProofError):
        # non-Sumhash proof hash type must be rejected fail-closed
        reveal_membership_inputs(
            {
                "p": {"p": {"cmt": b"\x00" * 64, "lf": 256}},
                "s": {
                    "s": {
                        "vkey": {"k": b"\x00" * 1793},
                        "idx": 0,
                        "prf": {"hsh": {"t": 0}, "td": 1, "pth": [b"\x00" * 64]},
                    }
                },
            }
        )


def test_committable_public_key_leaf_rejects_bad_inputs():
    with pytest.raises(MerkleSigError):
        committable_public_key_leaf(b"\x00" * 10, 256)  # wrong key length
    with pytest.raises(MerkleSigError):
        committable_public_key_leaf(b"\x00" * 1793, -1)  # negative round


def test_vector_commitment_rejects_structural_errors():
    good_leaf = b"\x11" * 64
    root = b"\x22" * 64
    with pytest.raises(MerkleSigError):
        verify_sumhash_vector_commitment(b"\x00" * 32, 0, 1, [b"\x00" * 64], root)
    with pytest.raises(MerkleSigError):
        # path length disagrees with tree depth
        verify_sumhash_vector_commitment(good_leaf, 0, 2, [b"\x00" * 64], root)
    with pytest.raises(MerkleSigError):
        # index out of range for depth
        verify_sumhash_vector_commitment(good_leaf, 4, 1, [b"\x00" * 64], root)


def test_vector_commitment_depth_zero_is_leaf_equals_root():
    """A depth-0 proof authenticates iff the leaf already equals the root."""
    leaf = committable_public_key_leaf(b"\x07" * 1793, 256)
    assert verify_sumhash_vector_commitment(leaf, 0, 0, [], leaf) is True
    assert verify_sumhash_vector_commitment(leaf, 0, 0, [], b"\x00" * 64) is False


def test_vector_commitment_accepts_concatenated_path():
    """A concatenated byte-string path verifies identically to a list path."""
    bundle = _load(_FIXTURES[0])
    state_proof = _decoded_state_proof(bundle)
    signed_round = _signed_round(bundle)
    _pos, reveal = next(iter_reveals(state_proof))
    inputs = reveal_membership_inputs(reveal)
    leaf_round = ephemeral_key_first_round(signed_round, inputs.key_lifetime)
    leaf = committable_public_key_leaf(inputs.verifying_key, leaf_round)

    concat = b"".join(inputs.path)
    assert verify_sumhash_vector_commitment(
        leaf, inputs.index, inputs.tree_depth, concat, inputs.key_commitment
    ) is True

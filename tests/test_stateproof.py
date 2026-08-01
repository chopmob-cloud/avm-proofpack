"""Tests for the experimental state-proof reveal reconstruction primitive.

The headline test is a REAL-DATA regression anchor: for each live-captured
fixture, this reconstructs the state-proof ``MessageHash`` from the bundle's
``state_proof_message`` fields and proves that real captured reveals verify
with the KAT-validated Falcon-1024 verifier. If the reconstructed preimage were
wrong by a single byte, none of these would verify -- so their success is the
correctness proof for the preimage formula
(``SHA256("spm" || canonical_msgpack(Message))``; see
``avm_proofpack._experimental.stateproof`` for the go-algorand derivation).

These tests exercise ONLY the Falcon-over-message layer. They deliberately do
not assert key-commitment membership, weights, or anchoring (out of scope; the
module is not a trust root and is not wired into ``verify_bundle``).
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from avm_proofpack import mpack
from avm_proofpack._experimental.falcon import (
    PUBLIC_KEY_SIZE,
    HEADER_DET_COMPRESSED,
    falcon1024_verify,
)
from avm_proofpack._experimental.stateproof import (
    EPHEMERAL_KEY_LEAF_DOMAIN,
    STATE_PROOF_MESSAGE_HASHID,
    RevealSignatureCount,
    StateProofError,
    count_reveal_signatures,
    ephemeral_key_first_round,
    iter_reveals,
    reveal_falcon_inputs,
    state_proof_message_hash,
    verify_reveal_signature,
)

_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
_FIXTURES = [
    "algorand-mainnet-pay.json",
    "algorand-mainnet-appl.json",
    "voi-mainnet-appl.json",
]


def _load(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


def _message_fields(bundle: dict) -> dict:
    spm = bundle["state_proof_message"]
    return {
        "block_headers_commitment": base64.b64decode(
            spm["block_headers_commitment_b64"]
        ),
        "voters_commitment": base64.b64decode(spm["voters_commitment_b64"]),
        "ln_proven_weight": spm["ln_proven_weight"],
        "first_attested_round": spm["first_attested_round"],
        "last_attested_round": spm["last_attested_round"],
    }


def _decoded_state_proof(bundle: dict) -> dict:
    sp = mpack.decode(base64.b64decode(bundle["state_proof_msgpack_b64"]))
    assert isinstance(sp, dict)
    return sp


# --------------------------------------------------------------------------
# Headline: real captured reveals verify (the preimage correctness proof).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FIXTURES)
def test_all_reveals_verify_against_reconstructed_message(name):
    """Every reveal's Falcon signature verifies over the rebuilt message.

    This is the real-data proof of the preimage formula: a wrong preimage
    would verify zero reveals.
    """
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    result = count_reveal_signatures(state_proof, **_message_fields(bundle))
    assert isinstance(result, RevealSignatureCount)
    assert result.total > 0, "fixture has no reveals"
    assert result.verified == result.total, (
        f"{name}: only {result.verified}/{result.total} reveals verified"
    )
    # A full signature count is NEVER an attestation at this experimental layer.
    assert result.is_trust_root is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_first_reveal_verifies_with_raw_falcon(name):
    """At least one real reveal verifies through the raw Falcon verifier.

    Uses ``falcon1024_verify`` directly (not the convenience wrapper) to keep
    this an unambiguous anchor tying real mainnet Falcon signatures to the
    reconstructed 32-byte message hash.
    """
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    message_hash = state_proof_message_hash(**_message_fields(bundle))
    assert len(message_hash) == 32

    _pos, first_reveal = next(iter_reveals(state_proof))
    public_key, signature = reveal_falcon_inputs(first_reveal)
    assert len(public_key) == PUBLIC_KEY_SIZE
    assert signature[0] == HEADER_DET_COMPRESSED  # 0xba: det1024 compressed
    assert falcon1024_verify(public_key, message_hash, signature) is True


@pytest.mark.parametrize("name", _FIXTURES)
def test_tampered_message_hash_rejects_every_reveal(name):
    """Flipping one bit of the message hash makes all reveals reject."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    good = state_proof_message_hash(**_message_fields(bundle))
    tampered = bytes([good[0] ^ 0x01]) + good[1:]
    for _pos, reveal in iter_reveals(state_proof):
        assert verify_reveal_signature(reveal, tampered) is False


@pytest.mark.parametrize("name", _FIXTURES)
def test_wrong_field_value_changes_message_hash(name):
    """Perturbing any message field yields a hash no reveal verifies under."""
    bundle = _load(name)
    state_proof = _decoded_state_proof(bundle)
    fields = _message_fields(bundle)
    perturbed = dict(fields)
    perturbed["last_attested_round"] = fields["last_attested_round"] + 1
    wrong = state_proof_message_hash(**perturbed)
    assert wrong != state_proof_message_hash(**fields)
    _pos, reveal = next(iter_reveals(state_proof))
    assert verify_reveal_signature(reveal, wrong) is False


# --------------------------------------------------------------------------
# Preimage construction unit tests.
# --------------------------------------------------------------------------


def test_message_hash_matches_manual_construction():
    """The hash equals SHA256("spm" || canonical_msgpack(sorted Message))."""
    import hashlib

    bhc = bytes(range(32))
    vc = bytes(range(64))
    ln, first, last = 2231545, 63604737, 63604992
    expected_map = {"P": ln, "b": bhc, "f": first, "l": last, "v": vc}
    expected = hashlib.sha256(
        STATE_PROOF_MESSAGE_HASHID + mpack.encode_canonical(expected_map)
    ).digest()
    got = state_proof_message_hash(
        block_headers_commitment=bhc,
        voters_commitment=vc,
        ln_proven_weight=ln,
        first_attested_round=first,
        last_attested_round=last,
    )
    assert got == expected


def test_message_hash_omitempty_drops_zero_uint():
    """A zero uint field is omitted (go-codec omitempty), changing the hash."""
    bhc = bytes(range(32))
    vc = bytes(range(64))
    with_zero = state_proof_message_hash(
        block_headers_commitment=bhc,
        voters_commitment=vc,
        ln_proven_weight=0,
        first_attested_round=1,
        last_attested_round=1,
    )
    # Manually build the map WITHOUT the "P" key, matching omitempty.
    import hashlib

    manual = hashlib.sha256(
        STATE_PROOF_MESSAGE_HASHID
        + mpack.encode_canonical({"b": bhc, "f": 1, "l": 1, "v": vc})
    ).digest()
    assert with_zero == manual


def test_message_hash_rejects_bad_lengths():
    with pytest.raises(StateProofError):
        state_proof_message_hash(
            block_headers_commitment=b"\x00" * 31,  # wrong length
            voters_commitment=b"\x00" * 64,
            ln_proven_weight=1,
            first_attested_round=1,
            last_attested_round=1,
        )
    with pytest.raises(StateProofError):
        state_proof_message_hash(
            block_headers_commitment=b"\x00" * 32,
            voters_commitment=b"\x00" * 32,  # must be 64
            ln_proven_weight=1,
            first_attested_round=1,
            last_attested_round=1,
        )


def test_message_hash_rejects_inverted_interval():
    with pytest.raises(StateProofError):
        state_proof_message_hash(
            block_headers_commitment=bytes(range(32)),
            voters_commitment=bytes(range(64)),
            ln_proven_weight=1,
            first_attested_round=10,
            last_attested_round=9,
        )


# --------------------------------------------------------------------------
# Reveal extraction and structural validation.
# --------------------------------------------------------------------------


def test_reveal_inputs_reject_malformed_structures():
    with pytest.raises(StateProofError):
        reveal_falcon_inputs("not a dict")
    with pytest.raises(StateProofError):
        reveal_falcon_inputs({})  # no SigSlot
    with pytest.raises(StateProofError):
        reveal_falcon_inputs({"s": {"s": {"vkey": {"k": b"x"}}}})  # no sig
    with pytest.raises(StateProofError):
        # vkey too short for a Falcon public key
        reveal_falcon_inputs({"s": {"s": {"sig": b"\xba\x00", "vkey": {"k": b"x"}}}})


def test_iter_reveals_requires_reveals_map():
    with pytest.raises(StateProofError):
        list(iter_reveals("not a dict"))
    with pytest.raises(StateProofError):
        list(iter_reveals({}))  # no 'r'


def test_verify_reveal_signature_requires_32_byte_hash():
    bundle = _load(_FIXTURES[0])
    state_proof = _decoded_state_proof(bundle)
    _pos, reveal = next(iter_reveals(state_proof))
    with pytest.raises(StateProofError):
        verify_reveal_signature(reveal, b"\x00" * 31)


# --------------------------------------------------------------------------
# Deferred ephemeral-key membership: confirmed spec fragments.
# --------------------------------------------------------------------------


def test_ephemeral_key_first_round():
    # crypto/merklesignature FirstRoundInKeyLifetime: round - round%lifetime
    assert ephemeral_key_first_round(63604900, 256) == 63604900 - (63604900 % 256)
    assert ephemeral_key_first_round(512, 256) == 512
    assert ephemeral_key_first_round(700, 256) == 512
    assert ephemeral_key_first_round(0, 256) == 0


def test_ephemeral_key_first_round_rejects_bad_lifetime():
    with pytest.raises(StateProofError):
        ephemeral_key_first_round(100, 0)
    with pytest.raises(StateProofError):
        ephemeral_key_first_round(100, -1)


def test_key_lifetime_present_in_fixture_participants():
    """The participant PK carries KeyLifetime ('lf') the deferred pass needs."""
    bundle = _load(_FIXTURES[0])
    state_proof = _decoded_state_proof(bundle)
    _pos, reveal = next(iter_reveals(state_proof))
    key_lifetime = reveal["p"]["p"]["lf"]
    assert isinstance(key_lifetime, int) and key_lifetime > 0
    # Sanity: the proof hash type is Sumhash (1), 64-byte nodes -> deferred.
    assert reveal["s"]["s"]["prf"]["hsh"]["t"] == 1
    assert EPHEMERAL_KEY_LEAF_DOMAIN == b"KP"

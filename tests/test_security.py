"""Regression tests for hardening fixes (see the security review).

Each test pins a specific defect the review found, so a regression cannot
reintroduce it silently.
"""

import base64
import copy
import json
from pathlib import Path

import pytest

from avm_proofpack import mpack
from avm_proofpack.bundle import Bundle, BundleError
from avm_proofpack.verify import VerificationError, verify_bundle

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))


def _load(name="algorand-mainnet-appl"):
    return json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text(
        encoding="utf-8"
    ))


# -- Finding 3: mixed-key maps must not escape as EncodeError ---------------

def test_decoder_rejects_mixed_key_map():
    # {"a": 1, 2: 3} — decoder must reject, so its output domain never
    # exceeds the encoder's input domain.
    blob = b"\x82\xa1a\x01\x02\x03"
    with pytest.raises(mpack.DecodeError):
        mpack.decode(blob)


def test_mixed_key_header_fails_typed_not_encodeerror():
    # {"rnd": 1, 1: nil}: a header the decoder now rejects outright.
    data = _load()
    data["block_header_msgpack_b64"] = base64.b64encode(
        b"\x82\xa3rnd\x01\x01\xc0"
    ).decode()
    with pytest.raises((VerificationError, BundleError)) as exc:
        verify_bundle(Bundle.from_dict(data))
    assert not isinstance(exc.value, mpack.EncodeError)


# -- Finding 4/5: hostile bundle size and malformed files -------------------

def test_oversized_field_rejected():
    data = _load()
    data["block_header_msgpack_b64"] = base64.b64encode(b"\x00" * (3 * 1024 * 1024)).decode()
    with pytest.raises(BundleError):
        Bundle.from_dict(data)


def test_load_rejects_oversized_file(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b'{"x":"' + b"a" * (5 * 1024 * 1024) + b'"}')
    with pytest.raises(BundleError):
        Bundle.load(big)


def test_load_rejects_non_utf8_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe garbage")
    with pytest.raises(BundleError):
        Bundle.load(bad)


def test_load_rejects_deeply_nested_json(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_bytes(b"[" * 200000)
    with pytest.raises(BundleError):
        Bundle.load(deep)


# -- Finding 1: state proof blob must be present and well-formed ------------

def test_junk_state_proof_rejected():
    data = _load()
    data["state_proof_msgpack_b64"] = base64.b64encode(b"not a state proof").decode()
    with pytest.raises(VerificationError) as exc:
        verify_bundle(Bundle.from_dict(data))
    assert exc.value.check == "state-proof-present"


def test_trust_root_is_unattested():
    report = verify_bundle(Bundle.from_dict(_load()))
    assert report.trust_root == "unattested"


# -- Finding 8: header must carry a matching genesis id ---------------------

def test_missing_gen_rejected():
    data = _load()
    header = mpack.decode(base64.b64decode(data["block_header_msgpack_b64"]))
    del header["gen"]
    data["block_header_msgpack_b64"] = base64.b64encode(
        mpack.encode_canonical(header)
    ).decode()
    with pytest.raises(VerificationError) as exc:
        verify_bundle(Bundle.from_dict(data))
    assert exc.value.check == "block-header"


# -- Finding 9: voters commitment length is pinned --------------------------

def test_voters_commitment_length_enforced():
    data = _load()
    data["state_proof_message"]["voters_commitment_b64"] = base64.b64encode(
        b"\x00" * 40
    ).decode()
    with pytest.raises(BundleError):
        Bundle.from_dict(data)

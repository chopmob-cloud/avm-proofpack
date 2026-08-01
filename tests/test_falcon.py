"""Tests for the experimental verify-only Falcon-1024 primitive.

Validates ``avm_proofpack._experimental.falcon`` against authentic Falcon-1024
deterministic (det1024) known-answer test vectors (see
``tests/falcon_kat/README.md`` for provenance): valid triples must ACCEPT,
and tampered signatures / wrong messages / wrong keys / malformed input must
REJECT (fail closed).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from avm_proofpack._experimental import falcon as _falcon
from avm_proofpack._experimental.falcon import (
    BETA_SQ,
    HEADER_DET_COMPRESSED,
    PUBLIC_KEY_SIZE,
    FalconError,
    falcon1024_accepts,
    falcon1024_verify,
)

_KAT_PATH = pathlib.Path(__file__).parent / "falcon_kat" / "falcon1024_det_kat.json"


def _load_vectors():
    doc = json.loads(_KAT_PATH.read_text())
    out = []
    for vec in doc["vectors"]:
        out.append(
            (
                vec["index"],
                bytes.fromhex(vec["public_key_hex"]),
                bytes.fromhex(vec["message_hex"]),
                bytes.fromhex(vec["signature_hex"]),
            )
        )
    return out


VECTORS = _load_vectors()
IDS = [f"idx={idx}" for idx, _, _, _ in VECTORS]


def test_kat_file_present_and_nonempty():
    assert VECTORS, "expected at least one KAT vector"
    # sanity on the vendored shapes
    for _idx, pk, _msg, sig in VECTORS:
        assert len(pk) == PUBLIC_KEY_SIZE
        assert sig[0] == HEADER_DET_COMPRESSED  # 0xba


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_kat_vectors_accept(idx, pk, msg, sig):
    assert falcon1024_verify(pk, msg, sig) is True
    assert falcon1024_accepts(pk, msg, sig) is True


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_kat_norm_within_bound(idx, pk, msg, sig):
    norm = _falcon._signature_squared_norm(pk, msg, sig)
    assert 0 < norm <= BETA_SQ


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_single_byte_signature_mutation_rejects(idx, pk, msg, sig):
    # Flip one bit at many positions across the compressed payload; every
    # mutation must reject (either FalconError -> False via accepts(), or a
    # norm/hash failure -> False).
    n = len(sig)
    positions = {2, 3, 5, 17, n // 3, n // 2, (2 * n) // 3, n - 2, n - 1}
    for pos in sorted(p for p in positions if 0 <= p < n):
        bad = bytearray(sig)
        bad[pos] ^= 0x01
        assert falcon1024_accepts(pk, msg, bytes(bad)) is False, f"pos={pos}"


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_wrong_message_rejects(idx, pk, msg, sig):
    if msg:
        wrong = bytearray(msg)
        wrong[0] ^= 0x01
        wrong = bytes(wrong)
    else:
        wrong = b"\x01"  # empty-message vector: any non-empty message is wrong
    assert falcon1024_accepts(pk, wrong, sig) is False
    # appending a byte is also a different message
    assert falcon1024_accepts(pk, msg + b"\x00", sig) is False


def test_wrong_public_key_rejects():
    assert len(VECTORS) >= 2, "need >=2 vectors to cross keys"
    for i in range(len(VECTORS)):
        j = (i + 1) % len(VECTORS)
        _, pk_i, _, _ = VECTORS[i]
        _, _, msg_j, sig_j = VECTORS[j]
        # sig_j/msg_j are valid under pk_j, not under pk_i
        assert falcon1024_accepts(pk_i, msg_j, sig_j) is False


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_public_key_payload_mutation_rejects(idx, pk, msg, sig):
    # Flip a bit in the coefficient payload (never the header byte).
    bad = bytearray(pk)
    bad[100] ^= 0x01
    assert falcon1024_accepts(bytes(bad), msg, sig) is False


# --- fail-closed / structural validation -----------------------------------


def test_non_bytes_arguments_raise_type_error():
    _idx, pk, msg, sig = VECTORS[0]
    with pytest.raises(TypeError):
        falcon1024_verify("not-bytes", msg, sig)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        falcon1024_verify(pk, 1234, sig)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        falcon1024_verify(pk, msg, None)  # type: ignore[arg-type]


def test_bad_public_key_length_raises():
    _idx, pk, msg, sig = VECTORS[0]
    with pytest.raises(FalconError):
        falcon1024_verify(pk[:-1], msg, sig)
    with pytest.raises(FalconError):
        falcon1024_verify(pk + b"\x00", msg, sig)


def test_bad_public_key_header_raises():
    _idx, pk, msg, sig = VECTORS[0]
    bad = bytearray(pk)
    bad[0] = 0x00  # not 0x0a
    with pytest.raises(FalconError):
        falcon1024_verify(bytes(bad), msg, sig)


def test_public_key_out_of_range_coefficient_raises():
    _idx, _pk, msg, sig = VECTORS[0]
    # header ok, payload all 0xff -> first 14-bit coefficient = 0x3fff >= q.
    bad = bytes([0x0A]) + b"\xff" * (PUBLIC_KEY_SIZE - 1)
    with pytest.raises(FalconError):
        falcon1024_verify(bad, msg, sig)


def test_signature_too_short_raises():
    _idx, pk, msg, _sig = VECTORS[0]
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, b"")
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, b"\xba")  # header only, missing everything


def test_unknown_signature_header_raises():
    _idx, pk, msg, sig = VECTORS[0]
    for header in (0x00, 0x3B, 0x5A, 0xDA, 0xFF):  # incl. CT headers 0x5a/0xda
        bad = bytearray(sig)
        bad[0] = header
        with pytest.raises(FalconError):
            falcon1024_verify(pk, msg, bytes(bad))


def test_standard_header_too_short_for_salt_raises():
    _idx, pk, msg, _sig = VECTORS[0]
    # standard compressed header (0x3a) but not enough bytes for the 40-byte salt
    bad = bytes([0x3A]) + b"\x00" * 10
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, bad)


def test_empty_compressed_payload_raises():
    _idx, pk, msg, _sig = VECTORS[0]
    # det header + salt version, but no compressed s2 payload
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, bytes([HEADER_DET_COMPRESSED, 0x00]))


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_trailing_bytes_after_signature_raise(idx, pk, msg, sig):
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, sig + b"\x00")
    with pytest.raises(FalconError):
        falcon1024_verify(pk, msg, sig + b"\x7f")


@pytest.mark.parametrize("idx,pk,msg,sig", VECTORS, ids=IDS)
def test_truncated_signature_rejects(idx, pk, msg, sig):
    # Dropping the last payload byte should never verify (and must not raise
    # anything other than FalconError).
    assert falcon1024_accepts(pk, msg, sig[:-1]) is False


# --- norm-bound boundary property ------------------------------------------


def test_norm_boundary_is_inclusive_and_just_over_rejects(monkeypatch):
    _idx, pk, msg, sig = VECTORS[0]
    norm = _falcon._signature_squared_norm(pk, msg, sig)

    # Bound exactly equal to the signature's norm: accept (bound is inclusive).
    monkeypatch.setattr(_falcon, "BETA_SQ", norm)
    assert falcon1024_verify(pk, msg, sig) is True

    # Bound one below the signature's norm: the norm is now "just over" -> reject.
    monkeypatch.setattr(_falcon, "BETA_SQ", norm - 1)
    assert falcon1024_verify(pk, msg, sig) is False


def test_real_bound_value():
    # Guard against a silent regression to the Falcon-512 bound (34034726).
    assert BETA_SQ == 70265242


# --- confirm the module is not wired into bundle verification ---------------


def test_module_is_isolated_and_not_wired():
    import importlib

    import avm_proofpack

    # importable as an internal experimental module, but NOT part of the
    # published package API (and excluded from the built distribution, see
    # pyproject [tool.setuptools.packages.find] exclude).
    falcon = importlib.import_module("avm_proofpack._experimental.falcon")
    assert hasattr(falcon, "falcon1024_verify")
    assert "falcon1024_verify" not in getattr(avm_proofpack, "__all__", [])
    assert not hasattr(avm_proofpack, "_falcon")  # the old top-level name is gone

    # verify.py may mention Falcon as a planned tier in comments, but it must
    # not import or call the primitive, nor reach the experimental package.
    from avm_proofpack import verify as verify_mod

    src = pathlib.Path(verify_mod.__file__).read_text()
    assert "_experimental" not in src
    assert "_falcon" not in src
    assert "falcon1024_verify" not in src
    assert "falcon1024_accepts" not in src

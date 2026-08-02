"""API-key authentication suite (design §9 / Phase 1 DoD).

Valid keys accept; unknown/missing keys reject; keys load from a file; and the
compare path is constant-time (hmac.compare_digest, every configured key
checked without short-circuit).
"""
from __future__ import annotations

import hmac

import pytest

from avm_proofpack_server.auth import ApiKeyAuth, AuthenticationError


def test_valid_key_accepts():
    auth = ApiKeyAuth(["secret-key-one", "secret-key-two"])
    auth.authenticate("secret-key-one")   # no raise
    auth.authenticate("secret-key-two")   # no raise


def test_unknown_key_rejected():
    auth = ApiKeyAuth(["secret-key-one"])
    with pytest.raises(AuthenticationError):
        auth.authenticate("wrong-key")


def test_missing_key_rejected():
    auth = ApiKeyAuth(["secret-key-one"])
    with pytest.raises(AuthenticationError):
        auth.authenticate(None)


def test_empty_string_rejected():
    auth = ApiKeyAuth(["secret-key-one"])
    with pytest.raises(AuthenticationError):
        auth.authenticate("")


def test_prefix_of_valid_key_rejected():
    # compare_digest is length-aware: a prefix must not authenticate.
    auth = ApiKeyAuth(["secret-key-one"])
    with pytest.raises(AuthenticationError):
        auth.authenticate("secret-key")


def test_at_least_one_key_required():
    with pytest.raises(ValueError):
        ApiKeyAuth([])


def test_keys_loaded_from_file(tmp_path):
    key_file = tmp_path / "keys.txt"
    key_file.write_text("key-alpha\n  key-beta  \n\n", encoding="utf-8")
    auth = ApiKeyAuth(key_file=str(key_file))
    auth.authenticate("key-alpha")
    auth.authenticate("key-beta")  # surrounding whitespace stripped
    with pytest.raises(AuthenticationError):
        auth.authenticate("key-gamma")


def test_constant_time_path_checks_every_key(monkeypatch):
    # No short-circuit: even when the FIRST key matches, every configured key is
    # compared, so runtime does not depend on which/where a key matches.
    auth = ApiKeyAuth(["k1", "k2", "k3"])
    calls = {"n": 0}
    real = hmac.compare_digest

    def counting(a, b):
        calls["n"] += 1
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", counting)
    auth.authenticate("k1")  # matches first key
    assert calls["n"] == 3   # still compared all three


def test_uses_compare_digest(monkeypatch):
    # Prove the compare goes through hmac.compare_digest, not ==.
    auth = ApiKeyAuth(["only-key"])
    used = {"flag": False}
    real = hmac.compare_digest

    def spy(a, b):
        used["flag"] = True
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    auth.authenticate("only-key")
    assert used["flag"] is True

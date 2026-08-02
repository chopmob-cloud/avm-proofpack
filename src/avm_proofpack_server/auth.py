"""Constant-time static API-key authentication."""
from __future__ import annotations
import hmac
from pathlib import Path

class AuthenticationError(PermissionError):
    pass

class ApiKeyAuth:
    def __init__(self, keys: list[str] | tuple[str, ...] = (), *, key_file: str | None = None):
        values = list(keys)
        if key_file:
            values.extend(line.strip() for line in Path(key_file).read_text(encoding="utf-8").splitlines() if line.strip())
        self._keys = tuple(value.encode("utf-8") for value in values)
        if not self._keys:
            raise ValueError("at least one API key is required")

    def authenticate(self, presented: str | None) -> None:
        if presented is None:
            raise AuthenticationError("authentication required")
        candidate = presented.encode("utf-8")
        # Compare against every key without short-circuiting: each comparison is
        # constant-time (hmac.compare_digest), and iterating the full set means
        # runtime does not depend on WHICH key matched or how early it appears.
        matched = False
        for key in self._keys:
            if hmac.compare_digest(candidate, key):
                matched = True
        if not matched:
            raise AuthenticationError("invalid API key")

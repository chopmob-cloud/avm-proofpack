"""Minimal algod REST client (stdlib only).

Deliberately tiny: two GET helpers with explicit timeouts and errors that
carry the URL and response excerpt. No retries here, callers decide their
own retry policy, and no third-party HTTP dependency, so the verification
path has no supply chain beyond CPython itself.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["NodeError", "NodeNotFound", "NodeClient"]

_MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # a full block + cert fits comfortably


class NodeError(RuntimeError):
    """A node request failed (network, HTTP status, or malformed body)."""


class NodeNotFound(NodeError):
    """The node answered 404 for the requested resource."""


class NodeClient:
    def __init__(self, base_url: str, *, timeout: float = 30.0, token: str = "",
                 opener: urllib.request.OpenerDirector | None = None,
                 validator: object | None = None) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"node URL must be http(s)://host[:port], got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = token
        self.opener = opener
        self.validator = validator

    def _get(self, path: str) -> bytes:
        url = self.base_url + path
        if self.validator is not None:
            self.validator(url)
        opener = self.opener or urllib.request
        headers = {"User-Agent": "avm-proofpack"}
        if self.token:
            headers["X-Algo-API-Token"] = self.token
        request = urllib.request.Request(url, headers=headers)
        try:
            with opener.urlopen(request, timeout=self.timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            excerpt = exc.read(512).decode("utf-8", errors="replace")
            if exc.code == 404:
                raise NodeNotFound(f"GET {url} -> 404: {excerpt}") from exc
            raise NodeError(f"GET {url} -> {exc.code}: {excerpt}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise NodeError(f"GET {url} failed: {exc}") from exc
        if len(body) > _MAX_RESPONSE_BYTES:
            raise NodeError(f"GET {url}: response exceeds {_MAX_RESPONSE_BYTES} bytes")
        return body

    def get_json(self, path: str) -> dict:
        body = self._get(path)
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NodeError(f"GET {path}: response is not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise NodeError(f"GET {path}: expected a JSON object")
        return decoded

    def get_bytes(self, path: str) -> bytes:
        return self._get(path)

"""Phase 0 DoD suite for the SSRF egress guard (design §9, S1).

Every case is stdlib-mocked; no real network call is made. `socket.getaddrinfo`
is monkeypatched so the "resolver" is fully under test control, and the pinned
connection classes are stubbed for the redirect / rebind cases.
"""
from __future__ import annotations

import socket

import pytest

from avm_proofpack_server import egress
from avm_proofpack_server.egress import (
    EgressBlocked,
    EgressPolicy,
    ResolvedTarget,
)

PUBLIC_IP = "93.184.216.34"  # example.com, a normal public address


def _fake_getaddrinfo(*ip_lists):
    """Build a getaddrinfo stub.

    Each positional arg is the list of IP strings to return on the Nth call;
    the last list repeats for any further calls. Records the call count on the
    returned function's ``.calls`` attribute.
    """
    state = {"n": 0}

    def fake(host, port, *args, **kwargs):
        idx = min(state["n"], len(ip_lists) - 1)
        state["n"] += 1
        result = []
        for ip in ip_lists[idx]:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
            result.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
        return result

    fake.calls = state
    return fake


def _patch_resolver(monkeypatch, *ip_lists):
    fake = _fake_getaddrinfo(*ip_lists)
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


# --------------------------------------------------------------------------
# Private / special ranges are refused (allow_http=True so the REASON for the
# refusal is genuinely the IP class, not the scheme).
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, resolved_ip",
    [
        ("http://metadata.example/latest/meta-data/", "169.254.169.254"),  # cloud metadata
        ("http://metadata.example/x", "::ffff:169.254.169.254"),           # IPv4-mapped IPv6 metadata
        ("http://loopback.example:8080/x", "127.0.0.1"),                   # loopback
        ("http://loopback6.example/x", "::1"),                             # IPv6 loopback
        ("http://rfc1918.example/x", "10.1.2.3"),                          # RFC1918 10/8
        ("http://rfc1918.example/x", "172.16.5.4"),                        # RFC1918 172.16/12
        ("http://rfc1918.example/x", "192.168.1.1"),                       # RFC1918 192.168/16
        ("http://linklocal.example/x", "169.254.10.10"),                   # link-local
        ("http://ula.example/x", "fd00::1"),                               # ULA fc00::/7
        ("http://ula.example/x", "fc00::abcd"),                            # ULA fc00::/7
        ("http://unspec.example/x", "0.0.0.0"),                            # unspecified v4
        ("http://unspec6.example/x", "::"),                                # unspecified v6
        ("http://mcast.example/x", "224.0.0.1"),                           # multicast
        ("http://reserved.example/x", "240.0.0.1"),                        # reserved
    ],
)
def test_refuses_non_public_targets(monkeypatch, url, resolved_ip):
    _patch_resolver(monkeypatch, [resolved_ip])
    policy = EgressPolicy(allow_http=True)
    with pytest.raises(EgressBlocked):
        policy.validate_and_pin(url)


def test_refuses_if_any_resolved_ip_is_private(monkeypatch):
    # Resolver returns a public AND a private IP; the presence of the private
    # one must fail the whole resolution closed.
    _patch_resolver(monkeypatch, [PUBLIC_IP, "10.0.0.9"])
    policy = EgressPolicy(allow_http=True)
    with pytest.raises(EgressBlocked):
        policy.validate_and_pin("http://mixed.example/x")


# --------------------------------------------------------------------------
# Redirect-follow bypass is blocked: a permitted node that 302s to metadata
# must NOT be followed.
# --------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status, headers=None):
        self.status = status
        self.reason = "x"
        self.headers = headers or {}

    def close(self):
        pass

    def read(self, *a):
        return b""


class _FakeConn:
    """Records the address it was pinned to; returns a canned response."""

    last = None

    def __init__(self, target, timeout):
        self.target = target
        self.sock = object()
        _FakeConn.last = self
        self._response = _FakeResponse(200)

    def set_response(self, response):
        self._response = response

    def request(self, method, path, body=None, headers=None):
        self.method = method
        self.path = path

    def getresponse(self):
        return self._response

    def close(self):
        self.sock = None


def test_redirect_to_metadata_is_refused(monkeypatch):
    # The permitted host resolves public, but answers 302 -> metadata.
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy(allow_http=True)

    def make_conn(target, timeout):
        conn = _FakeConn(target, timeout)
        conn.set_response(
            _FakeResponse(302, {"Location": "http://169.254.169.254/latest/"})
        )
        return conn

    monkeypatch.setattr(egress, "_PinnedHTTPConnection", make_conn)
    import urllib.request

    request = urllib.request.Request("http://permitted.example/x")
    with pytest.raises(EgressBlocked):
        policy.opener().urlopen(request)


# --------------------------------------------------------------------------
# DNS rebinding is defeated: resolve once, pin, connect to the validated IP;
# a resolver that flips to a private IP on the second call is never consulted
# again at connect time.
# --------------------------------------------------------------------------

def test_dns_rebind_pins_first_resolution(monkeypatch):
    fake = _patch_resolver(monkeypatch, [PUBLIC_IP], ["169.254.169.254"])
    policy = EgressPolicy(allow_http=True)

    monkeypatch.setattr(egress, "_PinnedHTTPConnection", _FakeConn)
    import urllib.request

    request = urllib.request.Request("http://rebind.example/x")
    response = policy.opener().urlopen(request)

    assert response.status == 200
    # The connection was pinned to the FIRST (public) resolution...
    assert _FakeConn.last.target.address == PUBLIC_IP
    # ...and DNS was consulted exactly once (no re-resolution at connect time,
    # so the flip to the private IP never took effect).
    assert fake.calls["n"] == 1


def test_resolve_returns_public_ip_only_once(monkeypatch):
    fake = _patch_resolver(monkeypatch, [PUBLIC_IP], ["10.0.0.1"])
    policy = EgressPolicy(allow_http=True)
    target = policy.validate_and_pin("http://rebind.example/x")
    assert target.address == PUBLIC_IP
    assert fake.calls["n"] == 1


# --------------------------------------------------------------------------
# A normal public algod hostname passes the guard.
# --------------------------------------------------------------------------

def test_public_host_passes(monkeypatch):
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy()  # https, no allowlist
    target = policy.validate_and_pin("https://mainnet-api.algonode.cloud/v2/status")
    assert isinstance(target, ResolvedTarget)
    assert target.address == PUBLIC_IP
    assert target.hostname == "mainnet-api.algonode.cloud"
    assert target.scheme == "https"
    assert target.port == 443


# --------------------------------------------------------------------------
# https-by-default, http opt-in.
# --------------------------------------------------------------------------

def test_http_refused_by_default(monkeypatch):
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy()  # allow_http defaults False
    with pytest.raises(EgressBlocked):
        policy.validate_and_pin("http://mainnet-api.algonode.cloud/v2/status")


def test_http_allowed_when_opted_in(monkeypatch):
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy(allow_http=True)
    target = policy.validate_and_pin("http://mainnet-api.algonode.cloud/v2/status")
    assert target.address == PUBLIC_IP
    assert target.scheme == "http"
    assert target.port == 80


# --------------------------------------------------------------------------
# Allowlist: only listed hosts pass, in addition to the private-range checks.
# --------------------------------------------------------------------------

def test_allowlist_blocks_unlisted_public_host(monkeypatch):
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy(allowlist={"mainnet-api.algonode.cloud"})
    with pytest.raises(EgressBlocked):
        policy.validate_and_pin("https://evil.example/x")


def test_allowlist_permits_listed_host(monkeypatch):
    _patch_resolver(monkeypatch, [PUBLIC_IP])
    policy = EgressPolicy(allowlist={"mainnet-api.algonode.cloud"})
    target = policy.validate_and_pin("https://mainnet-api.algonode.cloud/v2/status")
    assert target.address == PUBLIC_IP


def test_allowlisted_host_still_subject_to_private_range_check(monkeypatch):
    # Even an allowlisted host is refused if it resolves to a private IP
    # (allowlist is in ADDITION to, not instead of, the range checks).
    _patch_resolver(monkeypatch, ["127.0.0.1"])
    policy = EgressPolicy(allowlist={"mainnet-api.algonode.cloud"}, allow_http=True)
    with pytest.raises(EgressBlocked):
        policy.validate_and_pin("http://mainnet-api.algonode.cloud/v2/status")


# --------------------------------------------------------------------------
# Core NodeClient: default behaviour is unchanged (no opener/validator ->
# plain urllib.request path, byte-for-byte as before the hook was added).
# --------------------------------------------------------------------------

def test_nodeclient_defaults_are_none():
    from avm_proofpack.client import NodeClient

    client = NodeClient("https://node.example")
    assert client.opener is None
    assert client.validator is None


def test_nodeclient_default_uses_urllib(monkeypatch):
    import urllib.request
    from avm_proofpack import client as client_mod

    called = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"hello"

    def fake_urlopen(request, timeout=None):
        called["url"] = request.full_url
        called["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = client_mod.NodeClient("https://node.example")
    body = client.get_bytes("/v2/status")
    assert body == b"hello"
    # Default path went through urllib.request.urlopen (no injected opener).
    assert called["url"] == "https://node.example/v2/status"


def test_nodeclient_injected_opener_and_validator(monkeypatch):
    from avm_proofpack.client import NodeClient

    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"ok"

    class _Opener:
        def urlopen(self, request, timeout=None):
            seen["opener_url"] = request.full_url
            return _Resp()

    def validator(url):
        seen["validated"] = url

    client = NodeClient("https://node.example", opener=_Opener(), validator=validator)
    body = client.get_bytes("/v2/status")
    assert body == b"ok"
    # Injected opener was used and the validator was consulted first.
    assert seen["opener_url"] == "https://node.example/v2/status"
    assert seen["validated"] == "https://node.example/v2/status"

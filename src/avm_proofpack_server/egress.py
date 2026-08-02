"""SSRF egress control for outbound algod dials (design §9, S1).

The security keystone of the service layer. As a library the caller supplies
`node_url` and trusts their own node, so the URL is inside the trust boundary.
As a service an untrusted remote caller supplies `source_node` /
`corroboration_nodes` and **the server dials them** - those inputs are now
attacker-controlled, and error excerpts + response bodies flow back to the
caller, so this is a *read* SSRF, not blind.

This module is the single choke point every outbound dial must pass through.
It is stdlib-only (socket, ipaddress, ssl, http.client, urllib) so it never
poisons the zero-dependency verification core.

Policy enforced, all mandatory:

* Resolve the hostname and REJECT if ANY resolved IP is
  private / loopback / link-local / ULA / unspecified / multicast / reserved,
  for IPv4 AND IPv6, including IPv4-mapped IPv6 (e.g.
  ``::ffff:169.254.169.254``) which is unwrapped and re-checked against its
  embedded IPv4 (169.254.169.254 cloud metadata is caught in both forms).
* PIN the resolved IP: the TCP connection is made to the exact address that
  was validated; DNS is not consulted again at connect time, defeating DNS
  rebinding. The original hostname is preserved for the Host header and TLS
  SNI.
* DISABLE HTTP redirect following: a 3xx is refused, never auto-followed
  (urllib follows 3xx by default and does not re-validate the target, so a
  permitted node that 302s to 169.254.169.254 would otherwise bypass the
  guard).
* Optional config-driven ALLOWLIST of permitted hosts; when set only
  allowlisted hosts pass, in ADDITION to the private-range checks.
* HTTPS by default; plain HTTP is opt-in (``allow_http=True``) and the
  private-range checks still apply.

Public API:

* ``EgressPolicy(allowlist=..., allow_http=...)`` - the policy object.
* ``policy.validate_and_pin(url) -> ResolvedTarget`` - resolve, validate,
  return the pinned connection parameters (raises ``EgressBlocked``).
* ``policy.validate(url)`` - validate only (the ``validator`` hook shape
  ``avm_proofpack.client.NodeClient`` accepts).
* ``policy.opener()`` / ``guarded_opener(policy_or_config)`` - a
  urllib-compatible opener (the ``opener`` hook ``NodeClient`` accepts) that
  connects to the pinned IP and refuses redirects.
* ``EgressBlocked`` - the typed refusal exception.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class EgressBlocked(ValueError):
    """The destination is refused by the egress policy (SSRF guard)."""


# Back-compat alias: earlier drafts and sibling modules used EgressDenied.
EgressDenied = EgressBlocked


@dataclass(frozen=True)
class ResolvedTarget:
    """A validated, pinned connection target.

    ``address`` is the exact IP the guard validated; connect to it and to it
    only. ``hostname`` is the original name, preserved for Host header + SNI.
    """

    hostname: str
    port: int
    address: str
    scheme: str


def _reject_special(address: str) -> None:
    """Raise EgressBlocked if ``address`` is any non-public / special IP.

    Covers IPv4 and IPv6. IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is unwrapped
    and its embedded IPv4 is checked too, because the IPv6 wrapper's own
    ``is_*`` properties do not reliably reflect the mapped IPv4 across
    CPython 3.10-3.12.
    """
    ip = ipaddress.ip_address(address)
    candidates = [ip]
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    # Some IPv6 forms embed IPv4 differently (6to4 / teredo); unwrap those too.
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        candidates.append(sixtofour)
    teredo = getattr(ip, "teredo", None)
    if teredo is not None:
        # teredo returns (server, client); the client IP is the interesting one.
        candidates.extend(teredo)
    for candidate in candidates:
        if (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_unspecified
            or candidate.is_multicast
            or candidate.is_reserved
        ):
            raise EgressBlocked(
                f"destination {address} resolves to a non-public address "
                f"({candidate}); refused"
            )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose TCP peer is the already-validated address.

    We connect the socket to the pinned IP but wrap TLS with the original
    hostname as SNI, so certificate validation and virtual-host routing still
    work while DNS is never consulted a second time.
    """

    def __init__(self, target: ResolvedTarget, timeout: float):
        super().__init__(
            target.hostname, target.port, timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._target = target

    def connect(self) -> None:  # pragma: no cover - exercised via opener tests
        sock = socket.create_connection(
            (self._target.address, self._target.port), self.timeout
        )
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self._target.hostname
        )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP connection pinned to the validated address (opt-in only)."""

    def __init__(self, target: ResolvedTarget, timeout: float):
        super().__init__(target.address, target.port, timeout=timeout)
        self._target = target


class PinnedOpener:
    """urllib-compatible opener: validates + pins per call, refuses redirects.

    Shaped to drop into ``avm_proofpack.client.NodeClient(opener=...)``: it
    exposes ``urlopen(request, timeout=...)`` and returns an
    ``http.client.HTTPResponse`` (a context manager supporting ``.read(n)``),
    and raises ``urllib.error.HTTPError`` on >=400 exactly like urllib, so the
    core client's error handling is unchanged.
    """

    def __init__(self, policy: "EgressPolicy"):
        self.policy = policy

    def urlopen(self, request, timeout: float = 30.0):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        target = self.policy.validate_and_pin(url)
        parsed = urllib.parse.urlsplit(url)
        headers = dict(request.header_items()) if hasattr(request, "header_items") else {}
        # Preserve virtual-host routing while the socket goes to the pinned IP.
        headers["Host"] = parsed.netloc
        method = getattr(request, "get_method", lambda: None)()
        if method is None:
            method = "POST" if getattr(request, "data", None) else "GET"
        if target.scheme == "https":
            connection = _PinnedHTTPSConnection(target, timeout)
        else:
            connection = _PinnedHTTPConnection(target, timeout)
        try:
            path = urllib.parse.urlunsplit(
                ("", "", parsed.path or "/", parsed.query, "")
            )
            connection.request(
                method, path, body=getattr(request, "data", None), headers=headers
            )
            response = connection.getresponse()
            # Redirects are refused, never followed and never re-resolved.
            if 300 <= response.status < 400:
                response.close()
                raise EgressBlocked(
                    f"redirect ({response.status}) refused; redirects are disabled"
                )
            if response.status >= 400:
                raise urllib.error.HTTPError(
                    url, response.status, response.reason, response.headers, response
                )
            return response
        except EgressBlocked:
            connection.close()
            raise
        except Exception:
            if getattr(connection, "sock", None) is not None:
                connection.close()
            raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses instead of following (defence in depth).

    Used if a plain ``urllib`` opener is ever built; the primary path is
    :class:`PinnedOpener`, which also refuses 3xx.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EgressBlocked(f"redirect ({code}) refused; redirects are disabled")


class EgressPolicy:
    """Resolve-validate-pin policy for outbound algod dials.

    Parameters
    ----------
    allowlist:
        If non-empty, only these hostnames may be dialled (in addition to the
        private-range checks). Compared case-insensitively with any trailing
        dot stripped.
    allow_http:
        If ``False`` (default), plain ``http://`` is refused; ``https://`` is
        required. If ``True``, ``http://`` is permitted but the private-range
        checks still apply.
    """

    def __init__(
        self,
        *,
        allowlist: "set[str] | frozenset[str] | None" = None,
        allow_http: bool = False,
    ):
        self.allowlist = frozenset(h.lower().rstrip(".") for h in (allowlist or ()))
        self.allow_http = bool(allow_http)

    def validate_and_pin(self, url: str) -> ResolvedTarget:
        """Resolve, validate, and return the pinned connection target.

        Raises :class:`EgressBlocked` on any policy failure.
        """
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise EgressBlocked("only http(s) URLs are permitted")
        if parsed.scheme == "http" and not self.allow_http:
            raise EgressBlocked("plain http is disabled; use https (or opt in)")
        if not parsed.hostname:
            raise EgressBlocked("destination URL has no hostname")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise EgressBlocked("userinfo and URL fragments are not permitted")
        try:
            host = parsed.hostname.rstrip(".").lower()
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise EgressBlocked("invalid destination port") from exc

        if self.allowlist and host not in self.allowlist:
            raise EgressBlocked(f"host {host!r} is not on the egress allowlist")

        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise EgressBlocked(f"DNS resolution failed for {host!r}") from exc
        if not infos:
            raise EgressBlocked(f"DNS returned no addresses for {host!r}")

        # Validate EVERY resolved address; reject if any is non-public. Then
        # pin the first (we resolve exactly once here, so connect-time cannot
        # re-resolve to a different, private IP - DNS rebinding is defeated).
        addresses = []
        for info in infos:
            address = info[4][0]
            # Strip any IPv6 scope-id suffix (fe80::1%eth0) before parsing.
            address = address.split("%", 1)[0]
            _reject_special(address)
            addresses.append(address)
        return ResolvedTarget(host, port, addresses[0], parsed.scheme)

    def validate(self, url: str) -> None:
        """Validate the URL only (the NodeClient ``validator`` hook shape)."""
        self.validate_and_pin(url)

    def opener(self) -> PinnedOpener:
        """Return a urllib-compatible opener bound to this policy."""
        return PinnedOpener(self)


def guarded_opener(policy_or_config: object) -> PinnedOpener:
    """Build a :class:`PinnedOpener` from an :class:`EgressPolicy` or a config.

    Accepts an :class:`EgressPolicy` directly, or any config object exposing a
    ``node_allowlist`` iterable (e.g. ``ServerConfig``), from which a policy is
    constructed.
    """
    if isinstance(policy_or_config, EgressPolicy):
        return policy_or_config.opener()
    allowlist = getattr(policy_or_config, "node_allowlist", None)
    allow_http = bool(getattr(policy_or_config, "allow_http", False))
    return EgressPolicy(
        allowlist=set(allowlist) if allowlist else None, allow_http=allow_http
    ).opener()


__all__ = [
    "EgressBlocked",
    "EgressDenied",
    "EgressPolicy",
    "NoRedirect",
    "PinnedOpener",
    "ResolvedTarget",
    "guarded_opener",
]

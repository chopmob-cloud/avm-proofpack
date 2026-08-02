"""Shared test kit for the Phase 6 server suites (parity / security / integration).

Pure helper functions and constants consolidated here so ``test_parity.py`` and
``test_security.py`` drive BOTH transports the same way rather than each carrying
its own copy of the loopback gRPC harness, the in-process ASGI driver, and the
network mocks. This module is NOT a test module (leading underscore keeps pytest
from collecting it); it is imported by name from the sibling test files (pytest's
default prepend import mode puts ``tests/server`` on ``sys.path``).

The ``tls_files`` fixture lives in ``conftest.py`` and reuses ``make_tls_files``
below.

No live algod is ever dialled from here: ``mock_capture_network`` monkeypatches
the core ``capture`` / ``corroborate`` symbols the service imports, and the SSRF
helpers mock DNS + the socket dialer so the egress guard refuses non-public
targets without a socket ever opening.
"""
from __future__ import annotations

import base64
import contextlib
import datetime
import json
import ssl
from pathlib import Path

# --- fixture bundle (a real, offline-verifiable testnet/mainnet pay bundle) ---

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "algorand-mainnet-pay.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
FIXTURE_DICT = json.loads(FIXTURE_BYTES)
FIXTURE_B64 = base64.b64encode(FIXTURE_BYTES).decode("ascii")
# A real, well-formed txid so the core capture path reaches the egress guard
# (capture validates the txid before it ever builds a client).
FIXTURE_TXID = FIXTURE_DICT["transaction"]["txid"]
FIXTURE_ROUND = FIXTURE_DICT["transaction"]["round"]

VALID_KEY = "test-key-abc123"
AUTH = {"x-api-key": VALID_KEY}

ATTACKER_HOST = "attacker.example"
METADATA_IP = "169.254.169.254"


# --- service / app construction ------------------------------------------

def build_service(config=None, store=None, *, allow_http=False):
    from avm_proofpack_server.config import ServerConfig
    from avm_proofpack_server.egress import EgressPolicy
    from avm_proofpack_server.service import ProofpackService

    return ProofpackService(config or ServerConfig(),
                            egress=EgressPolicy(allow_http=allow_http), store=store)


def build_rest_app(config=None, store=None, *, auth=True, allow_http=False):
    from avm_proofpack_server.auth import ApiKeyAuth
    from avm_proofpack_server.rest_gateway import make_asgi_app

    api = ApiKeyAuth([VALID_KEY]) if auth else None
    return make_asgi_app(build_service(config, store, allow_http=allow_http), auth=api)


# --- TLS (throwaway self-signed cert; tests only) ------------------------

def make_tls_files(directory: Path):
    """Generate a throwaway self-signed cert/key pair; return (cert, key) paths."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = directory / "cert.pem"
    key_file = directory / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return str(cert_file), str(key_file)


def _client_ssl(cert_file: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cert_file)
    ctx.set_alpn_protocols(["h2"])
    return ctx


@contextlib.asynccontextmanager
async def running_grpc(svc, auth, tls_files):
    """Start a loopback TLS gRPC server; yield a connected ProofpackStub."""
    from grpclib.client import Channel

    from avm_proofpack_server.grpc_server import build_server_ssl_context, create_server
    from avm_proofpack_server.generated.avm_proofpack.v1 import ProofpackStub

    cert_file, key_file = tls_files
    server = create_server(svc, auth=auth)
    server_ctx = build_server_ssl_context(cert_file, key_file)
    await server.start("127.0.0.1", 0, ssl=server_ctx)
    port = server._server.sockets[0].getsockname()[1]
    channel = Channel("localhost", port, ssl=_client_ssl(cert_file))
    try:
        yield ProofpackStub(channel)
    finally:
        channel.close()
        server.close()
        await server.wait_closed()


# --- in-process ASGI driver ----------------------------------------------

async def call_rest(app, method, path, *, headers=None, json_body=None):
    """Drive the ASGI app once; return (status, headers, list-of-json-frames)."""
    body = b"" if json_body is None else json.dumps(json_body).encode("utf-8")
    scope = {
        "type": "http", "method": method, "path": path, "query_string": b"",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1"))
                    for k, v in (headers or {}).items()],
    }
    fed = {"done": False}

    async def receive():
        if fed["done"]:
            return {"type": "http.disconnect"}
        fed["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    events = []

    async def send(message):
        events.append(message)

    await app(scope, receive, send)
    start = next(e for e in events if e["type"] == "http.response.start")
    raw = b"".join(e.get("body", b"") for e in events if e["type"] == "http.response.body")
    frames = [json.loads(line) for line in raw.split(b"\n") if line.strip()]
    resp_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in start["headers"]}
    return start["status"], resp_headers, frames


# --- network mocks (no real dial ever) -----------------------------------

def mock_capture_network(monkeypatch, *, stamp_meta=False):
    """Make the core capture return the fixture and corroborate agree.

    When ``stamp_meta`` is True the fake reproduces capture's real meta-stamping
    (``meta.source_node = node_url`` and a fresh ``meta.captured_at``), so the
    volatile-meta behaviour that makes byte-identical capture impossible is
    faithfully present even though the underlying "algod data" is identical for
    every caller. Parity tests use this to prove the achievable invariant
    (bundle-minus-meta + report identical) rather than an unachievable one.
    """
    import copy as _copy

    from avm_proofpack_server import service as service_mod
    from avm_proofpack.verify import CorroborationReport, CorroborationResult

    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        d = _copy.deepcopy(FIXTURE_DICT)
        if stamp_meta:
            meta = dict(d.get("meta", {}))
            meta["source_node"] = node_url
            meta["captured_at"] = datetime.datetime.now(
                datetime.timezone.utc).isoformat(timespec="seconds")
            d["meta"] = meta
        return d

    monkeypatch.setattr(service_mod, "capture", fake_capture)
    monkeypatch.setattr(
        service_mod, "corroborate",
        lambda bundle, urls, **kw: CorroborationReport(
            tuple(CorroborationResult(u, "agree") for u in urls)))


def pin_dns_to_metadata(monkeypatch, host=ATTACKER_HOST, ip=METADATA_IP):
    """Resolve only ``host`` to ``ip`` (cloud-metadata / rebinding style).

    Every other host (notably the loopback client/server) is delegated to the
    real resolver so the transport still works; the fake is scoped to the attack.
    """
    from avm_proofpack_server import egress as egress_mod

    real_getaddrinfo = egress_mod.socket.getaddrinfo

    def fake_getaddrinfo(h, port, *a, **kw):
        if h == host:
            family = 10 if ":" in ip else 2  # AF_INET6 / AF_INET
            sockaddr = (ip, port, 0, 0) if family == 10 else (ip, port)
            return [(family, 1, 6, "", sockaddr)]
        return real_getaddrinfo(h, port, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "getaddrinfo", fake_getaddrinfo)


def spy_dials(monkeypatch):
    """Record every address socket.create_connection is asked to dial."""
    from avm_proofpack_server import egress as egress_mod

    dialled: list[str] = []
    real_create_connection = egress_mod.socket.create_connection

    def spy_create_connection(address, *a, **kw):
        dialled.append(address[0])
        return real_create_connection(address, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "create_connection", spy_create_connection)
    return dialled


# --- cross-transport report / fact normalisers ---------------------------
# A gRPC response carries betterproto message objects; a REST response carries
# JSON dicts. To compare them (and both against a direct library call) we reduce
# each to the SAME canonical dict shape.

def report_to_dict(report) -> dict:
    """Canonical report dict from a library VerificationReport OR a proto message.

    Both expose the same attribute names (the proto is a field-for-field mirror),
    so the REST gateway's ``_report_dict`` reads either one identically.
    """
    from avm_proofpack_server.rest_gateway import _report_dict

    return _report_dict(report)


def library_fact_dict(fact) -> dict:
    """Canonical fact dict from a library PaymentFacts (matches REST _fact_dict)."""
    from avm_proofpack_server.rest_gateway import _fact_dict

    return _fact_dict(fact)


def grpc_fact_dict(fact) -> dict:
    """Canonical fact dict from a proto PaymentFact message.

    Mirrors ``rest_gateway._fact_dict`` but reads the proto field names (the proto
    uses ``receiver_address`` where the library uses ``receiver``, and ``note`` is
    raw bytes rather than a base64 string).
    """
    return {
        "txn_type": fact.txn_type,
        "sender": fact.sender,
        "fee": fact.fee,
        "first_valid": fact.first_valid,
        "last_valid": fact.last_valid,
        "note": base64.b64encode(fact.note).decode("ascii") if fact.note else "",
        "group_b64": fact.group_b64 or "",
        "receiver_address": fact.receiver_address or "",
        "amount": fact.amount or 0,
        "close_remainder_to": fact.close_remainder_to or "",
        "asset_id": fact.asset_id or 0,
        "asset_close_to": fact.asset_close_to or "",
        "app_id": fact.app_id or 0,
        "limitations": list(fact.limitations),
    }

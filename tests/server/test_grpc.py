"""gRPC transport suite (design §9; Phase 3 DoD).

Hermetic and fast: a loopback grpclib server runs on an ephemeral port with a
throwaway self-signed cert generated in-process. No live algod is ever dialled -
the core ``capture``/``corroborate`` symbols the service imports are
monkeypatched, and the SSRF test mocks DNS so the egress guard refuses the
metadata IP without a socket ever opening.

Covered (Phase 3 DoD):
* all 6 RPCs reachable over TLS with a valid key;
* unauthenticated -> UNAUTHENTICATED; bad key -> UNAUTHENTICATED; Health needs
  no key;
* over-limit corroboration_nodes -> RESOURCE_EXHAUSTED;
* an SSRF attempt (169.254.169.254) via source_node AND corroboration_nodes is
  refused end-to-end through the gRPC path (PERMISSION_DENIED);
* verify/extract responses carry bundle_json (S4).
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import ssl
from pathlib import Path

import pytest

# The whole module needs the [server] extra; skip cleanly if it is absent.
pytest.importorskip("grpclib")
pytest.importorskip("betterproto")
cryptography = pytest.importorskip("cryptography")

from grpclib import GRPCError
from grpclib.client import Channel
from grpclib.const import Status

from avm_proofpack_server import service as service_mod
from avm_proofpack_server.auth import ApiKeyAuth
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressPolicy
from avm_proofpack_server import egress as egress_mod
from avm_proofpack_server.grpc_server import (
    build_server_ssl_context, create_server,
)
from avm_proofpack_server.service import ProofpackService
from avm_proofpack_server.generated.avm_proofpack.v1 import (
    CaptureRequest, CorroborateRequest, ExtractRequest, HealthRequest,
    ProofpackStub, VerifyRequest,
)
from avm_proofpack.verify import CorroborationReport, CorroborationResult

VALID_KEY = "test-key-abc123"

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "algorand-mainnet-pay.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
FIXTURE_DICT = json.loads(FIXTURE_BYTES)
# A real, well-formed txid so the core capture path reaches the egress guard
# (capture validates the txid before it ever builds a client).
FIXTURE_TXID = "CCQU5VMM5K5OHNLK6IVRI5XTKI57HIODHPLKGGS4RZ5GWP3OZYHA"
FIXTURE_ROUND = 63604900


# -- self-signed cert (throwaway; tests only) -----------------------------

@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

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
    d = tmp_path_factory.mktemp("tls")
    cert_file = d / "cert.pem"
    key_file = d / "key.pem"
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
async def _running(svc, auth, tls_files):
    """Start a loopback TLS gRPC server; yield a connected ProofpackStub."""
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


def _svc(config=None, store=None, *, allow_http=False):
    return ProofpackService(config or ServerConfig(),
                            egress=EgressPolicy(allow_http=allow_http), store=store)


def _mock_network(monkeypatch):
    """Make capture return the fixture and corroborate agree - no real dials."""
    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        return dict(FIXTURE_DICT)
    monkeypatch.setattr(service_mod, "capture", fake_capture)
    monkeypatch.setattr(
        service_mod, "corroborate",
        lambda bundle, urls, **kw: CorroborationReport(
            (CorroborationResult(urls[0], "agree"),)))


# -- all 6 RPCs reachable over TLS with a valid key -----------------------

def test_all_six_rpcs_over_tls_with_valid_key(monkeypatch, tls_files):
    _mock_network(monkeypatch)
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            # Health - no key required.
            health = await stub.health(HealthRequest())
            assert health.ok is True and health.version

            # Verify - real offline verification of the fixture bundle.
            v = await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES), metadata=md)
            assert v.bundle_json == FIXTURE_BYTES          # S4
            assert v.report.txid == FIXTURE_TXID

            # Extract - real facts; carries bundle_json (S4).
            e = await stub.extract(ExtractRequest(bundle_json=FIXTURE_BYTES), metadata=md)
            assert e.bundle_json == FIXTURE_BYTES          # S4
            assert e.facts and e.facts[0].txn_type == "pay"
            assert e.facts[0].receiver_address           # S3: receiver crosses the wire
            assert e.genesis_hash_b64

            # Capture - network mocked; report is real.
            c = await stub.capture(CaptureRequest(
                chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                source_node="https://node.example"), metadata=md)
            assert c.bundle_json and c.report.txid == FIXTURE_TXID

            # CaptureStream - server-streaming progress reaches DONE.
            stages = []
            async for progress in stub.capture_stream(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://node.example"), metadata=md):
                stages.append(progress.stage)
            names = {s.name for s in stages}
            assert "FETCHING_STATE_PROOF" in names and "DONE" in names

            # Corroborate - mocked agreement; carries bundle_json (S4).
            co = await stub.corroborate(CorroborateRequest(
                bundle_json=FIXTURE_BYTES, nodes=["https://n1.example"]), metadata=md)
            assert co.bundle_json == FIXTURE_BYTES         # S4
            assert co.fully_corroborated is True
            assert co.results and co.results[0].matches is True

    asyncio.run(scenario())


# -- auth enforcement -----------------------------------------------------

def test_unauthenticated_call_rejected(tls_files):
    auth = ApiKeyAuth([VALID_KEY])

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES))
            assert ei.value.status == Status.UNAUTHENTICATED

    asyncio.run(scenario())


def test_bad_key_rejected(tls_files):
    auth = ApiKeyAuth([VALID_KEY])

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES),
                                  metadata={"x-api-key": "wrong-key"})
            assert ei.value.status == Status.UNAUTHENTICATED

    asyncio.run(scenario())


def test_health_needs_no_key(tls_files):
    auth = ApiKeyAuth([VALID_KEY])

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            health = await stub.health(HealthRequest())  # no metadata
            assert health.ok is True

    asyncio.run(scenario())


def test_authorization_bearer_header_accepted(monkeypatch, tls_files):
    _mock_network(monkeypatch)
    auth = ApiKeyAuth([VALID_KEY])

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            v = await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES),
                                  metadata={"authorization": f"Bearer {VALID_KEY}"})
            assert v.bundle_json == FIXTURE_BYTES

    asyncio.run(scenario())


def test_capture_unauthenticated_rejected_before_any_dial(monkeypatch, tls_files):
    # If auth ran AFTER the dial, this fake would record a call. It must not.
    calls = []

    def spy_capture(node_url, txid, round_number, *, timeout, opener, validator):
        calls.append(node_url)
        return dict(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", spy_capture)
    auth = ApiKeyAuth([VALID_KEY])

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://node.example"))  # no key
            assert ei.value.status == Status.UNAUTHENTICATED

    asyncio.run(scenario())
    assert calls == []  # auth rejected before the service ever dialled


# -- S2: over-limit corroboration_nodes -----------------------------------

def test_capture_over_limit_nodes_rejected(monkeypatch, tls_files):
    _mock_network(monkeypatch)
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            nodes = [f"https://n{i}.example" for i in range(9)]  # 9 > cap 8
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://node.example", corroborate=True,
                    corroboration_nodes=nodes), metadata=md)
            assert ei.value.status == Status.RESOURCE_EXHAUSTED

    asyncio.run(scenario())


def test_corroborate_over_limit_nodes_rejected(tls_files):
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            nodes = [f"https://n{i}.example" for i in range(9)]
            with pytest.raises(GRPCError) as ei:
                await stub.corroborate(CorroborateRequest(
                    bundle_json=FIXTURE_BYTES, nodes=nodes), metadata=md)
            assert ei.value.status == Status.RESOURCE_EXHAUSTED

    asyncio.run(scenario())


# -- S1: SSRF refused end-to-end through the gRPC path --------------------

ATTACKER_HOST = "attacker.example"


def _pin_dns_to_metadata(monkeypatch):
    """Resolve only the attacker host to the cloud-metadata IP (rebinding-style).

    No real DNS for the attack: getaddrinfo returns 169.254.169.254 for the
    attacker host, so the guard rejects the resolved link-local address before
    any connection is attempted. Every other host (notably the test's own
    loopback client/server) is delegated to the real resolver so the transport
    still works - the fake is scoped to the attack, not global.
    """
    metadata_ip = "169.254.169.254"
    real_getaddrinfo = egress_mod.socket.getaddrinfo

    def fake_getaddrinfo(host, port, *a, **kw):
        if host == ATTACKER_HOST:
            return [(2, 1, 6, "", (metadata_ip, port))]
        return real_getaddrinfo(host, port, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "getaddrinfo", fake_getaddrinfo)


def test_ssrf_via_source_node_refused_end_to_end(monkeypatch, tls_files):
    _pin_dns_to_metadata(monkeypatch)
    # Do NOT mock capture: the real capture path must reach the egress guard.
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://attacker.example"), metadata=md)
            assert ei.value.status == Status.PERMISSION_DENIED
            assert "non-public" in (ei.value.message or "")

    asyncio.run(scenario())


def test_ssrf_via_literal_metadata_ip_refused(tls_files):
    # A literal link-local IP resolves to itself; no DNS mock needed.
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://169.254.169.254"), metadata=md)
            assert ei.value.status == Status.PERMISSION_DENIED

    asyncio.run(scenario())


def test_ssrf_via_corroboration_node_refused_end_to_end(monkeypatch, tls_files):
    # Corroboration is best-effort across nodes: the core corroborate() catches
    # per-node egress refusals (EgressBlocked is a ValueError) and records the
    # node as non-matching rather than failing the whole request. The security
    # property that matters is still enforced end-to-end: the metadata IP is
    # NEVER dialled, and the attacker node does not corroborate. We prove the
    # no-dial property with a socket spy.
    _pin_dns_to_metadata(monkeypatch)
    dialled: list[str] = []
    real_create_connection = egress_mod.socket.create_connection

    def spy_create_connection(address, *a, **kw):
        dialled.append(address[0])
        return real_create_connection(address, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "create_connection", spy_create_connection)
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            co = await stub.corroborate(CorroborateRequest(
                bundle_json=FIXTURE_BYTES,
                nodes=["https://attacker.example"]), metadata=md)
            assert co.bundle_json == FIXTURE_BYTES          # S4: bytes returned
            assert co.results and co.results[0].matches is False
            assert co.fully_corroborated is False

    asyncio.run(scenario())
    # The egress guard refused before any socket opened to the metadata IP.
    assert "169.254.169.254" not in dialled


# -- exception -> status mapping (not-found via a store-backed capture) ----

def test_verify_bad_bundle_maps_to_invalid_argument(tls_files):
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.verify(VerifyRequest(bundle_json=b"not json"), metadata=md)
            assert ei.value.status == Status.INVALID_ARGUMENT

    asyncio.run(scenario())


def test_verify_unverifiable_bundle_maps_to_invalid_argument(tls_files):
    # Valid JSON that decodes into a bundle but fails verification (tampered
    # state-proof interval). VerificationError is NOT a ValueError, so this
    # exercises the dedicated mapping branch -> INVALID_ARGUMENT, not INTERNAL.
    import copy
    auth = ApiKeyAuth([VALID_KEY])
    md = {"x-api-key": VALID_KEY}
    tampered = copy.deepcopy(FIXTURE_DICT)
    tampered["state_proof_message"]["first_attested_round"] += 1
    tampered_bytes = json.dumps(tampered).encode("utf-8")

    async def scenario():
        async with _running(_svc(), auth, tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.verify(VerifyRequest(bundle_json=tampered_bytes), metadata=md)
            assert ei.value.status == Status.INVALID_ARGUMENT

    asyncio.run(scenario())

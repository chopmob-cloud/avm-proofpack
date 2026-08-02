"""REST gateway suite (design §4 + §9; Phase 4 DoD).

Hermetic and fast: the ASGI app is driven in-process (construct scope / feed the
body via ``receive`` / capture ``send``) - the same way an ASGI test client
drives an app, with no socket, port, or thread. uvicorn is never started here;
the app object is pure stdlib and exercises the exact code path uvicorn would run
(``serve_rest`` only wraps this app). No live algod is ever dialled: the core
``capture`` / ``corroborate`` symbols the service imports are monkeypatched, and
the SSRF tests mock DNS so the egress guard refuses the metadata IP without a
socket ever opening.

Covered (Phase 4 DoD):
* every endpoint reachable; ``GET /v1/health`` needs no key;
* all other endpoints 401 without / with a bad key, BEFORE any dial;
* SSRF via source_node / corroboration_nodes refused end-to-end (403 / not
  dialled); the metadata IP is never connected to;
* over-limit corroboration_nodes -> 429;
* verify / extract responses carry bundle_json (base64) with the full S3
  PaymentFact field set;
* a consistent JSON error envelope with the mapped status;
* REST verify of the same bytes matches a direct library verify (parity).
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path

import pytest

# The gateway app itself is stdlib-only, but this suite exercises the wire
# mappers/service; skip cleanly if the core is somehow unavailable.
from avm_proofpack_server import service as service_mod
from avm_proofpack_server import egress as egress_mod
from avm_proofpack_server.auth import ApiKeyAuth
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressPolicy
from avm_proofpack_server.rest_gateway import make_asgi_app, _report_dict
from avm_proofpack_server.service import ProofpackService
from avm_proofpack.bundle import Bundle
from avm_proofpack.verify import (
    CorroborationReport, CorroborationResult, verify_bundle,
)

VALID_KEY = "test-key-abc123"

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "algorand-mainnet-pay.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
FIXTURE_DICT = json.loads(FIXTURE_BYTES)
FIXTURE_B64 = base64.b64encode(FIXTURE_BYTES).decode("ascii")
# A real, well-formed txid so the core capture path reaches the egress guard.
FIXTURE_TXID = "CCQU5VMM5K5OHNLK6IVRI5XTKI57HIODHPLKGGS4RZ5GWP3OZYHA"
FIXTURE_ROUND = 63604900

AUTH = {"x-api-key": VALID_KEY}


# -- in-process ASGI driver -----------------------------------------------

async def _call(app, method, path, *, headers=None, json_body=None):
    """Drive the ASGI app once; return (status, headers, list-of-json-frames).

    The body is joined then split on newlines and each non-empty line parsed as
    JSON, so a single JSON response yields one frame and an NDJSON stream yields
    one frame per progress line.
    """
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


def _svc(config=None, store=None, *, allow_http=False):
    return ProofpackService(config or ServerConfig(),
                            egress=EgressPolicy(allow_http=allow_http), store=store)


def _app(config=None, store=None, *, auth=True, allow_http=False):
    api = ApiKeyAuth([VALID_KEY]) if auth else None
    return make_asgi_app(_svc(config, store, allow_http=allow_http), auth=api)


def _mock_network(monkeypatch):
    """Make capture return the fixture and corroborate agree - no real dials."""
    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        return dict(FIXTURE_DICT)
    monkeypatch.setattr(service_mod, "capture", fake_capture)
    monkeypatch.setattr(
        service_mod, "corroborate",
        lambda bundle, urls, **kw: CorroborationReport(
            (CorroborationResult(urls[0], "agree"),)))


# -- every endpoint reachable with a valid key ----------------------------

def test_all_endpoints_reachable_with_valid_key(monkeypatch):
    _mock_network(monkeypatch)
    app = _app()

    async def scenario():
        # Health - no key required.
        status, _, frames = await _call(app, "GET", "/v1/health")
        assert status == 200 and frames[0]["ok"] is True and frames[0]["version"]

        # Verify - real offline verification of the fixture bundle.
        status, _, frames = await _call(
            app, "POST", "/v1/verify", headers=AUTH, json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        assert frames[0]["report"]["txid"] == FIXTURE_TXID

        # Extract - real facts; carries bundle_json (S4).
        status, _, frames = await _call(
            app, "POST", "/v1/extract", headers=AUTH, json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        assert frames[0]["facts"][0]["txn_type"] == "pay"
        assert frames[0]["genesis_hash_b64"]

        # Capture - network mocked; report is real.
        status, _, frames = await _call(
            app, "POST", "/v1/capture", headers=AUTH, json_body={
                "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
                "source_node": "https://node.example"})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"])                    # S4
        assert frames[0]["report"]["txid"] == FIXTURE_TXID

        # CaptureStream equivalent - NDJSON progress reaching DONE.
        status, resp_headers, frames = await _call(
            app, "POST", "/v1/capture/stream", headers=AUTH, json_body={
                "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
                "source_node": "https://node.example"})
        assert status == 200 and resp_headers["content-type"] == "application/x-ndjson"
        stages = [f["stage"] for f in frames]
        assert "FETCHING_STATE_PROOF" in stages and "DONE" in stages
        done = next(f for f in frames if f["stage"] == "DONE")
        assert base64.b64decode(done["result"]["bundle_json"])              # S4

        # Corroborate - mocked agreement; carries bundle_json (S4).
        status, _, frames = await _call(
            app, "POST", "/v1/corroborate", headers=AUTH, json_body={
                "bundle_json": FIXTURE_B64, "nodes": ["https://n1.example"]})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        assert frames[0]["fully_corroborated"] is True
        assert frames[0]["results"][0]["matches"] is True

    asyncio.run(scenario())


# -- auth enforcement -----------------------------------------------------

def test_health_needs_no_key():
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "GET", "/v1/health")
        assert status == 200 and frames[0]["ok"] is True

    asyncio.run(scenario())


@pytest.mark.parametrize("path,body", [
    ("/v1/verify", {"bundle_json": FIXTURE_B64}),
    ("/v1/extract", {"bundle_json": FIXTURE_B64}),
    ("/v1/corroborate", {"bundle_json": FIXTURE_B64, "nodes": []}),
    ("/v1/capture", {"chain": "algorand", "txid": FIXTURE_TXID,
                     "round": FIXTURE_ROUND, "source_node": "https://node.example"}),
    ("/v1/capture/stream", {"chain": "algorand", "txid": FIXTURE_TXID,
                            "round": FIXTURE_ROUND, "source_node": "https://node.example"}),
])
def test_endpoints_require_key(path, body):
    app = _app()

    async def scenario():
        # No key at all.
        status, _, frames = await _call(app, "POST", path, json_body=body)
        assert status == 401 and "error" in frames[0]
        # Bad key.
        status, _, frames = await _call(
            app, "POST", path, headers={"x-api-key": "wrong-key"}, json_body=body)
        assert status == 401 and "error" in frames[0]

    asyncio.run(scenario())


def test_authorization_bearer_header_accepted(monkeypatch):
    _mock_network(monkeypatch)
    app = _app()

    async def scenario():
        status, _, frames = await _call(
            app, "POST", "/v1/verify",
            headers={"authorization": f"Bearer {VALID_KEY}"},
            json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES

    asyncio.run(scenario())


def test_capture_unauthenticated_rejected_before_any_dial(monkeypatch):
    # If auth ran AFTER the dial this spy would record a call. It must not.
    calls = []

    def spy_capture(node_url, txid, round_number, *, timeout, opener, validator):
        calls.append(node_url)
        return dict(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", spy_capture)
    app = _app()

    async def scenario():
        # No key.
        status, _, _ = await _call(app, "POST", "/v1/capture", json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example"})
        assert status == 401
        # Bad key.
        status, _, _ = await _call(app, "POST", "/v1/capture",
                                   headers={"x-api-key": "nope"}, json_body={
                                       "chain": "algorand", "txid": FIXTURE_TXID,
                                       "round": FIXTURE_ROUND,
                                       "source_node": "https://node.example"})
        assert status == 401

    asyncio.run(scenario())
    assert calls == []  # auth rejected before the service ever dialled


# -- S1: SSRF refused end-to-end through the REST path ---------------------

ATTACKER_HOST = "attacker.example"


def _pin_dns_to_metadata(monkeypatch):
    """Resolve only the attacker host to the cloud-metadata IP (rebinding-style)."""
    metadata_ip = "169.254.169.254"
    real_getaddrinfo = egress_mod.socket.getaddrinfo

    def fake_getaddrinfo(host, port, *a, **kw):
        if host == ATTACKER_HOST:
            return [(2, 1, 6, "", (metadata_ip, port))]
        return real_getaddrinfo(host, port, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "getaddrinfo", fake_getaddrinfo)


def _spy_dials(monkeypatch):
    dialled: list[str] = []
    real_create_connection = egress_mod.socket.create_connection

    def spy_create_connection(address, *a, **kw):
        dialled.append(address[0])
        return real_create_connection(address, *a, **kw)

    monkeypatch.setattr(egress_mod.socket, "create_connection", spy_create_connection)
    return dialled


def test_ssrf_via_source_node_refused_end_to_end(monkeypatch):
    _pin_dns_to_metadata(monkeypatch)
    dialled = _spy_dials(monkeypatch)
    # Do NOT mock capture: the real capture path must reach the egress guard.
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": f"https://{ATTACKER_HOST}"})
        assert status == 403
        assert "non-public" in frames[0]["error"]["message"]

    asyncio.run(scenario())
    assert "169.254.169.254" not in dialled  # metadata IP never dialled


def test_ssrf_via_literal_metadata_ip_refused(monkeypatch):
    dialled = _spy_dials(monkeypatch)
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://169.254.169.254"})
        assert status == 403 and "error" in frames[0]

    asyncio.run(scenario())
    assert "169.254.169.254" not in dialled


def test_ssrf_via_corroboration_node_refused_end_to_end(monkeypatch):
    # Corroboration is best-effort: the core corroborate() catches per-node egress
    # refusals and records the node as non-matching rather than failing the whole
    # request. The security property that matters is still enforced end-to-end:
    # the metadata IP is NEVER dialled and the attacker node does not corroborate.
    _pin_dns_to_metadata(monkeypatch)
    dialled = _spy_dials(monkeypatch)
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/corroborate", headers=AUTH, json_body={
            "bundle_json": FIXTURE_B64, "nodes": [f"https://{ATTACKER_HOST}"]})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        assert frames[0]["results"][0]["matches"] is False
        assert frames[0]["fully_corroborated"] is False

    asyncio.run(scenario())
    assert "169.254.169.254" not in dialled  # metadata IP never dialled


# -- S2: over-limit corroboration_nodes -> 429 ----------------------------

def test_capture_over_limit_nodes_rejected(monkeypatch):
    _mock_network(monkeypatch)
    app = _app()
    nodes = [f"https://n{i}.example" for i in range(9)]  # 9 > cap 8

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example", "corroborate": True,
            "corroboration_nodes": nodes})
        assert status == 429 and "error" in frames[0]

    asyncio.run(scenario())


def test_corroborate_over_limit_nodes_rejected():
    app = _app()
    nodes = [f"https://n{i}.example" for i in range(9)]

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/corroborate", headers=AUTH,
                                        json_body={"bundle_json": FIXTURE_B64, "nodes": nodes})
        assert status == 429 and "error" in frames[0]

    asyncio.run(scenario())


# -- S3/S4: verify + extract carry bundle_json and the full PaymentFact ----

def test_verify_and_extract_carry_bundle_json_and_full_payment_fact():
    app = _app()

    async def scenario():
        # Verify: bundle_json is base64 that round-trips to the exact bytes (S4).
        status, _, frames = await _call(app, "POST", "/v1/verify", headers=AUTH,
                                        json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES

        # Extract: every S3 field crosses the wire (dropping any would let a
        # consumer over-credit a close-out / clawback / appl "payment").
        status, _, frames = await _call(app, "POST", "/v1/extract", headers=AUTH,
                                        json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        fact = frames[0]["facts"][0]
        for field_name in (
            "txn_type", "sender", "fee", "first_valid", "last_valid", "note",
            "group_b64", "receiver_address", "amount", "close_remainder_to",
            "asset_id", "asset_close_to", "app_id", "limitations",
        ):
            assert field_name in fact, f"S3 field {field_name} missing from PaymentFact"
        assert fact["txn_type"] == "pay"
        assert fact["receiver_address"]  # a pay txn surfaces a receiver

    asyncio.run(scenario())


# -- error envelope + status mapping --------------------------------------

def test_bad_bundle_returns_error_envelope_400():
    app = _app()

    async def scenario():
        # "not json" base64-encoded: decodes to bytes that are not a JSON object.
        bad = base64.b64encode(b"not json").decode("ascii")
        status, headers, frames = await _call(app, "POST", "/v1/verify", headers=AUTH,
                                              json_body={"bundle_json": bad})
        assert status == 400
        assert headers["content-type"] == "application/json"
        assert set(frames[0]) == {"error"}
        assert frames[0]["error"]["status"] == 400
        assert frames[0]["error"]["message"]

    asyncio.run(scenario())


def test_unverifiable_bundle_returns_400():
    # Valid JSON that decodes into a bundle but fails verification (tampered
    # state-proof interval). VerificationError is mapped to 400, not 500.
    tampered = copy.deepcopy(FIXTURE_DICT)
    tampered["state_proof_message"]["first_attested_round"] += 1
    tampered_b64 = base64.b64encode(json.dumps(tampered).encode("utf-8")).decode("ascii")
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/verify", headers=AUTH,
                                        json_body={"bundle_json": tampered_b64})
        assert status == 400 and frames[0]["error"]["status"] == 400

    asyncio.run(scenario())


def test_unknown_route_404():
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/nope", headers=AUTH, json_body={})
        assert status == 404 and "error" in frames[0]

    asyncio.run(scenario())


# -- parity: REST verify == direct library verify -------------------------

def test_rest_verify_matches_library_verify():
    """The REST report of a bundle equals a direct verify_bundle of the same bytes.

    The gRPC layer serialises the identical VerificationReport through the same
    field mapping (grpc_server._report_msg / rest_gateway._report_dict share the
    field set), so this same-service assertion covers the design's parity
    requirement for the report shape (full cross-transport harness is Phase 6).
    """
    expected = _report_dict(verify_bundle(Bundle.from_dict(copy.deepcopy(FIXTURE_DICT))))
    app = _app()

    async def scenario():
        status, _, frames = await _call(app, "POST", "/v1/verify", headers=AUTH,
                                        json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        assert frames[0]["report"] == expected

    asyncio.run(scenario())

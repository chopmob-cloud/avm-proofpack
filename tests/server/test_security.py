"""Server security-regression suite (design §9, S1-S5 + auth; Phase 6 DoD).

The single named gate for "does the service still uphold S1-S5". The individual
transport suites (test_grpc / test_rest / test_egress / test_storage /
test_scheduler) each assert pieces of this in their own context; THIS file is the
consolidated regression that exercises each control, through BOTH transports
where a transport is applicable, so a regression in any one is caught here even
if a transport suite is trimmed. It reuses the shared harness in ``_kit.py``.

Coverage map (case -> control -> transport(s)):

* S1 SSRF egress control
  - literal metadata IP (169.254.169.254) via source_node ....... gRPC + REST
  - IPv4-mapped IPv6 metadata (::ffff:169.254.169.254) .......... gRPC + REST
  - 302-redirect-to-metadata refused ........................... shared opener*
  - DNS-rebind host resolving to metadata ...................... gRPC + REST
  - corroboration_nodes pointing at metadata ................... gRPC + REST
  - the metadata IP is NEVER dialled in any of the above.
* S2 resource bounds / DoS
  - over-limit corroboration_nodes on capture .................. gRPC + REST
  - over-limit corroboration_nodes on corroborate ............. gRPC + REST
  - wait_seconds clamped ...................................... service + REST
  - global concurrency semaphore bounds concurrent captures ... service**
  - request deadline enforced ................................. service + REST + gRPC
* S4 the bundle is the sole trust anchor
  - verify / extract / capture / corroborate all carry bundle_json .. gRPC + REST
  - there is no verdict-only RPC/endpoint.
* S5 tenant IDOR (store/jobstore layer***)
  - cross-tenant bundle read -> not-found (never 403/existence leak)
  - owned-miss and unowned-miss are indistinguishable
  - source_node does not cross tenants on a shared content hash
  - cross-tenant scheduler-job read -> not-found
* auth
  - unauthenticated + bad-key rejected before any work on every RPC/endpoint
    except health .............................................. gRPC + REST

  * Both transports dial exclusively through ``service.egress.opener()``; the
    302-refusal is asserted at that shared choke point (triggering a real 302
    end-to-end needs a live upstream). If the opener refuses, both transports do.
  ** The two transports share ONE service instance and its semaphores; the bound
    is a service-layer property, asserted directly against the service.
  *** The v1 proto exposes no read-by-coordinate RPC (Capture/Verify/Extract/
    Corroborate/Health only), so a cross-tenant bundle/job read cannot be issued
    over a transport at all - the store and job-store ownership checks ARE the
    IDOR surface, and are the regression gate here.

Hermetic: no live algod. See ``_kit`` for the mocks.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import threading
import time

import pytest

pytest.importorskip("grpclib")
pytest.importorskip("betterproto")
pytest.importorskip("cryptography")

from grpclib import GRPCError
from grpclib.const import Status

from ._kit import (
    ATTACKER_HOST, AUTH, FIXTURE_B64, FIXTURE_BYTES, FIXTURE_DICT, FIXTURE_ROUND,
    FIXTURE_TXID, METADATA_IP, VALID_KEY, build_rest_app, build_service, call_rest,
    mock_capture_network, pin_dns_to_metadata, running_grpc, spy_dials,
)

from avm_proofpack_server import service as service_mod
from avm_proofpack_server.auth import ApiKeyAuth
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressBlocked, EgressPolicy
from avm_proofpack_server.generated.avm_proofpack.v1 import (
    CaptureRequest, CorroborateRequest, ExtractRequest, HealthRequest, VerifyRequest,
)

MD = {"x-api-key": VALID_KEY}


def _auth():
    return ApiKeyAuth([VALID_KEY])


# =========================================================================
# S1 - SSRF egress control
# =========================================================================

def test_s1_literal_metadata_ip_refused_grpc(monkeypatch, tls_files):
    dialled = spy_dials(monkeypatch)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node=f"https://{METADATA_IP}"), metadata=MD)
            assert ei.value.status == Status.PERMISSION_DENIED

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


def test_s1_literal_metadata_ip_refused_rest(monkeypatch):
    dialled = spy_dials(monkeypatch)
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": f"https://{METADATA_IP}"})
        assert status == 403 and "error" in frames[0]

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


def test_s1_ipv4_mapped_ipv6_metadata_refused_grpc(monkeypatch, tls_files):
    # A host that resolves to the IPv4-mapped form of the metadata IP; the guard
    # unwraps ::ffff:a.b.c.d and rejects the embedded link-local IPv4.
    pin_dns_to_metadata(monkeypatch, host="mapped.example", ip="::ffff:169.254.169.254")
    dialled = spy_dials(monkeypatch)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://mapped.example"), metadata=MD)
            assert ei.value.status == Status.PERMISSION_DENIED

    asyncio.run(scenario())
    assert METADATA_IP not in dialled and "::ffff:169.254.169.254" not in dialled


def test_s1_ipv4_mapped_ipv6_metadata_refused_rest(monkeypatch):
    pin_dns_to_metadata(monkeypatch, host="mapped.example", ip="::ffff:169.254.169.254")
    dialled = spy_dials(monkeypatch)
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://mapped.example"})
        assert status == 403 and "error" in frames[0]

    asyncio.run(scenario())
    assert METADATA_IP not in dialled and "::ffff:169.254.169.254" not in dialled


def test_s1_redirect_to_metadata_refused_at_shared_opener(monkeypatch):
    """A permitted node that 302s to metadata is refused; redirects are disabled.

    Both transports dial exclusively through ``service.egress.opener()`` (a
    PinnedOpener), so refusing the 302 at the opener refuses it for both. The
    permitted host resolves public but answers 302 -> metadata; urllib would
    follow it, the guard must not.
    """
    from avm_proofpack_server import egress as egress_mod

    # Permitted host resolves to a public IP...
    pin_dns_to_metadata(monkeypatch, host="permitted.example", ip="93.184.216.34")

    class _Resp:
        def __init__(self, status, headers):
            self.status, self.reason, self.headers = status, "x", headers

        def close(self):
            pass

    class _Conn:
        def __init__(self, target, timeout):
            self.sock = object()

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return _Resp(302, {"Location": f"http://{METADATA_IP}/latest/"})

        def close(self):
            self.sock = None

    monkeypatch.setattr(egress_mod, "_PinnedHTTPConnection", _Conn)
    import urllib.request

    policy = EgressPolicy(allow_http=True)
    # This is the exact opener the service threads into every capture/corroborate.
    with pytest.raises(EgressBlocked):
        policy.opener().urlopen(urllib.request.Request("http://permitted.example/x"))


def test_s1_dns_rebind_host_refused_grpc(monkeypatch, tls_files):
    # A hostname whose resolution yields the metadata IP is refused before any
    # connect (resolve-and-pin: the bad IP is caught at validate time).
    pin_dns_to_metadata(monkeypatch)  # attacker.example -> 169.254.169.254
    dialled = spy_dials(monkeypatch)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node=f"https://{ATTACKER_HOST}"), metadata=MD)
            assert ei.value.status == Status.PERMISSION_DENIED

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


def test_s1_dns_rebind_host_refused_rest(monkeypatch):
    pin_dns_to_metadata(monkeypatch)
    dialled = spy_dials(monkeypatch)
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": f"https://{ATTACKER_HOST}"})
        assert status == 403
        assert "non-public" in frames[0]["error"]["message"]

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


def test_s1_corroboration_node_metadata_never_dialled_grpc(monkeypatch, tls_files):
    # Corroboration is best-effort: a per-node egress refusal is recorded as a
    # non-match, the whole request still succeeds, and the metadata IP is never
    # dialled (the security property that matters).
    pin_dns_to_metadata(monkeypatch)
    dialled = spy_dials(monkeypatch)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            co = await stub.corroborate(CorroborateRequest(
                bundle_json=FIXTURE_BYTES, nodes=[f"https://{ATTACKER_HOST}"]), metadata=MD)
            assert co.bundle_json == FIXTURE_BYTES              # S4
            assert co.results and co.results[0].matches is False
            assert co.fully_corroborated is False

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


def test_s1_corroboration_node_metadata_never_dialled_rest(monkeypatch):
    pin_dns_to_metadata(monkeypatch)
    dialled = spy_dials(monkeypatch)
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/corroborate", headers=AUTH,
                                            json_body={"bundle_json": FIXTURE_B64,
                                                       "nodes": [f"https://{ATTACKER_HOST}"]})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"]) == FIXTURE_BYTES   # S4
        assert frames[0]["results"][0]["matches"] is False
        assert frames[0]["fully_corroborated"] is False

    asyncio.run(scenario())
    assert METADATA_IP not in dialled


# =========================================================================
# S2 - resource bounds / DoS
# =========================================================================

def test_s2_over_limit_nodes_capture_grpc(monkeypatch, tls_files):
    mock_capture_network(monkeypatch)
    nodes = [f"https://n{i}.example" for i in range(9)]  # 9 > cap 8

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://node.example", corroborate=True,
                    corroboration_nodes=nodes), metadata=MD)
            assert ei.value.status == Status.RESOURCE_EXHAUSTED

    asyncio.run(scenario())


def test_s2_over_limit_nodes_capture_rest(monkeypatch):
    mock_capture_network(monkeypatch)
    app = build_rest_app()
    nodes = [f"https://n{i}.example" for i in range(9)]

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example", "corroborate": True,
            "corroboration_nodes": nodes})
        assert status == 429 and "error" in frames[0]

    asyncio.run(scenario())


def test_s2_over_limit_nodes_corroborate_grpc(tls_files):
    nodes = [f"https://n{i}.example" for i in range(9)]

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.corroborate(CorroborateRequest(
                    bundle_json=FIXTURE_BYTES, nodes=nodes), metadata=MD)
            assert ei.value.status == Status.RESOURCE_EXHAUSTED

    asyncio.run(scenario())


def test_s2_over_limit_nodes_corroborate_rest():
    app = build_rest_app()
    nodes = [f"https://n{i}.example" for i in range(9)]

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/corroborate", headers=AUTH,
                                            json_body={"bundle_json": FIXTURE_B64, "nodes": nodes})
        assert status == 429 and "error" in frames[0]

    asyncio.run(scenario())


def test_s2_wait_seconds_clamped_config_and_transport(monkeypatch):
    # The clamp is the S2 control: a uint32 wait would allow a ~136-year hold.
    cfg = ServerConfig(max_wait_seconds=60)
    assert cfg.clamp_wait(2 ** 32 - 1) == 60
    assert cfg.clamp_wait(-5) == 0

    # And a request carrying an absurd wait_seconds still returns promptly - the
    # clamp is applied inside the service before any hold.
    mock_capture_network(monkeypatch)
    app = build_rest_app(cfg)

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example", "wait_seconds": 2 ** 31})
        assert status == 200
        assert base64.b64decode(frames[0]["bundle_json"])   # S4

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_s2_global_concurrency_semaphore_bounds_concurrent_captures(monkeypatch):
    # The two transports share ONE service and its semaphores; the bound is a
    # service-layer property. Distinct api keys so the GLOBAL cap (not per-key) is
    # the binding limit.
    cfg = ServerConfig(global_concurrency=3, per_key_concurrency=3, request_timeout=30.0)
    state = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        with lock:
            state["cur"] += 1
            state["max"] = max(state["max"], state["cur"])
        time.sleep(0.05)
        with lock:
            state["cur"] -= 1
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", fake_capture)
    svc = build_service(cfg)

    async def go():
        await asyncio.gather(*[
            svc.capture(api_key=f"key-{i}", chain="algorand", txid=FIXTURE_TXID,
                        round_number=FIXTURE_ROUND, source_node="https://n.example")
            for i in range(8)])

    asyncio.run(go())
    assert state["max"] <= 3            # never exceeded the global cap
    assert state["max"] >= 2            # genuinely concurrent (not serialised)


def test_s2_request_deadline_enforced_service(monkeypatch):
    cfg = ServerConfig(request_timeout=0.05)

    def slow_capture(node_url, txid, round_number, *, timeout, opener, validator):
        time.sleep(0.4)
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", slow_capture)
    svc = build_service(cfg)

    async def go():
        await svc.capture(api_key="k", chain="algorand", txid=FIXTURE_TXID,
                          round_number=FIXTURE_ROUND, source_node="https://n.example")

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(go())


def test_s2_request_deadline_enforced_rest(monkeypatch):
    cfg = ServerConfig(request_timeout=0.05)

    def slow_capture(node_url, txid, round_number, *, timeout, opener, validator):
        time.sleep(0.4)
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", slow_capture)
    app = build_rest_app(cfg)

    async def scenario():
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example"})
        assert status == 504  # deadline -> gateway timeout

    asyncio.run(scenario())


def test_s2_request_deadline_enforced_grpc(monkeypatch, tls_files):
    cfg = ServerConfig(request_timeout=0.05)

    def slow_capture(node_url, txid, round_number, *, timeout, opener, validator):
        time.sleep(0.4)
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", slow_capture)

    async def scenario():
        async with running_grpc(build_service(cfg), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(CaptureRequest(
                    chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                    source_node="https://node.example"), metadata=MD)
            assert ei.value.status == Status.DEADLINE_EXCEEDED

    asyncio.run(scenario())


# =========================================================================
# S4 - the bundle is the sole trust anchor (no verdict-without-bytes)
# =========================================================================

def test_s4_every_response_carries_bundle_json_grpc(monkeypatch, tls_files):
    mock_capture_network(monkeypatch)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            v = await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES), metadata=MD)
            assert v.bundle_json == FIXTURE_BYTES
            e = await stub.extract(ExtractRequest(bundle_json=FIXTURE_BYTES), metadata=MD)
            assert e.bundle_json == FIXTURE_BYTES
            c = await stub.capture(CaptureRequest(
                chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                source_node="https://node.example"), metadata=MD)
            assert c.bundle_json and len(c.bundle_json) > 0
            co = await stub.corroborate(CorroborateRequest(
                bundle_json=FIXTURE_BYTES, nodes=["https://n1.example"]), metadata=MD)
            assert co.bundle_json == FIXTURE_BYTES

    asyncio.run(scenario())


def test_s4_every_response_carries_bundle_json_rest(monkeypatch):
    mock_capture_network(monkeypatch)
    app = build_rest_app()

    async def one(path, body):
        status, _, frames = await call_rest(app, "POST", path, headers=AUTH, json_body=body)
        assert status == 200
        assert "bundle_json" in frames[0]
        assert base64.b64decode(frames[0]["bundle_json"])  # decodes to real bytes
        return frames[0]

    async def scenario():
        await one("/v1/verify", {"bundle_json": FIXTURE_B64})
        await one("/v1/extract", {"bundle_json": FIXTURE_B64})
        await one("/v1/capture", {"chain": "algorand", "txid": FIXTURE_TXID,
                                  "round": FIXTURE_ROUND, "source_node": "https://node.example"})
        await one("/v1/corroborate", {"bundle_json": FIXTURE_B64, "nodes": ["https://n1.example"]})

    asyncio.run(scenario())


def test_s4_no_verdict_only_response_type():
    # Structural guarantee: every response message that carries a verdict/report
    # also carries bundle_json - there is no verdict-only message in the proto.
    import dataclasses

    from avm_proofpack_server.generated.avm_proofpack.v1 import (
        CaptureResponse, CorroborateResponse, ExtractResponse, VerifyResponse,
    )

    for msg in (VerifyResponse, ExtractResponse, CaptureResponse, CorroborateResponse):
        fields = {f.name for f in dataclasses.fields(msg)}
        assert "bundle_json" in fields, f"{msg.__name__} must carry bundle_json (S4)"


# =========================================================================
# S5 - tenant IDOR (store + job-store layer; no read-by-coordinate RPC)
# =========================================================================

A, B = "tenant-a", "tenant-b"
BYTES_A = b'{"meta":{"source_node":"https://private-a.example"},"n":1}'
BYTES_B = b'{"meta":{"source_node":"https://private-b.example"},"n":2}'


def test_s5_cross_tenant_bundle_read_is_not_found(tmp_path):
    from avm_proofpack_server.storage import BundleNotFound, SqliteBundleStore

    store = SqliteBundleStore(tmp_path / "bundles.db")
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    # B guesses A's low-entropy coordinate: must be not-found, never a 403 that
    # would confirm the coordinate exists for another tenant.
    with pytest.raises(BundleNotFound):
        store.get(B, "algorand", 100, "TX1")


def test_s5_owned_and_unowned_misses_indistinguishable(tmp_path):
    from avm_proofpack_server.storage import BundleNotFound, SqliteBundleStore

    store = SqliteBundleStore(tmp_path / "bundles.db")
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    with pytest.raises(BundleNotFound) as unowned:
        store.get(B, "algorand", 100, "TX1")       # exists for A, not for B
    with pytest.raises(BundleNotFound) as absent:
        store.get(B, "algorand", 999, "NOPE")      # never stored at all
    assert (type(unowned.value), str(unowned.value)) == (type(absent.value), str(absent.value))


def test_s5_source_node_does_not_cross_tenants(tmp_path):
    from avm_proofpack_server.storage import SqliteBundleStore

    store = SqliteBundleStore(tmp_path / "bundles.db")
    store.put(A, "algorand", 100, "TX1", BYTES_A)  # carries private-a
    store.put(B, "algorand", 100, "TX1", BYTES_B)  # carries private-b, same coord
    got_a = store.get(A, "algorand", 100, "TX1")
    got_b = store.get(B, "algorand", 100, "TX1")
    assert b"private-a" in got_a and b"private-b" not in got_a
    assert b"private-b" in got_b and b"private-a" not in got_b


def test_s5_source_node_isolated_on_shared_content_hash(tmp_path):
    # Byte-identical bundles from two tenants collide on hash; the blob is kept
    # per tenant so one tenant's get can never return the other's stored object.
    from avm_proofpack_server.storage import BundleNotFound, SqliteBundleStore

    store = SqliteBundleStore(tmp_path / "bundles.db")
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    store.put(B, "algorand", 100, "TX1", BYTES_A)  # identical bytes -> same hash
    store.delete(A, "algorand", 100, "TX1")
    with pytest.raises(BundleNotFound):
        store.get(A, "algorand", 100, "TX1")
    assert store.get(B, "algorand", 100, "TX1") == BYTES_A  # B untouched by A's delete


def test_s5_cross_tenant_scheduler_job_read_is_not_found(tmp_path):
    from avm_proofpack_server.scheduler import (
        CaptureJob, InMemoryJobStore, JobNotFound, SqliteJobStore,
    )

    def job(tenant):
        return CaptureJob(tenant=tenant, chain="algorand", txid=FIXTURE_TXID,
                          round_number=FIXTURE_ROUND, source_node="https://n.example")

    for store in (InMemoryJobStore(), SqliteJobStore(tmp_path / "jobs.db")):
        jid = store.add(job("alice"))
        assert store.get("alice", jid).tenant == "alice"
        with pytest.raises(JobNotFound):        # cross-tenant read masked
            store.get("bob", jid)
        assert store.list("bob") == []          # bob addresses none of alice's jobs


# =========================================================================
# auth - unauthenticated / bad-key rejected before any work (health exempt)
# =========================================================================

_GRPC_RPCS = ("verify", "extract", "capture", "corroborate")


def _grpc_request(name):
    if name == "verify":
        return VerifyRequest(bundle_json=FIXTURE_BYTES)
    if name == "extract":
        return ExtractRequest(bundle_json=FIXTURE_BYTES)
    if name == "capture":
        return CaptureRequest(chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                              source_node="https://node.example")
    if name == "corroborate":
        return CorroborateRequest(bundle_json=FIXTURE_BYTES, nodes=["https://n1.example"])
    raise AssertionError(name)


@pytest.mark.parametrize("rpc", _GRPC_RPCS)
@pytest.mark.parametrize("md", [None, {"x-api-key": "wrong-key"}], ids=["no-key", "bad-key"])
def test_auth_grpc_rpcs_reject_before_work(rpc, md, tls_files):
    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            method = getattr(stub, rpc)
            with pytest.raises(GRPCError) as ei:
                await method(_grpc_request(rpc), metadata=md)
            assert ei.value.status == Status.UNAUTHENTICATED

    asyncio.run(scenario())


def test_auth_grpc_capture_unauthenticated_before_any_dial(monkeypatch, tls_files):
    calls = []

    def spy_capture(node_url, txid, round_number, *, timeout, opener, validator):
        calls.append(node_url)
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", spy_capture)

    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            with pytest.raises(GRPCError) as ei:
                await stub.capture(_grpc_request("capture"))  # no key
            assert ei.value.status == Status.UNAUTHENTICATED

    asyncio.run(scenario())
    assert calls == []  # rejected before the service ever dialled


def test_auth_grpc_health_exempt(tls_files):
    async def scenario():
        async with running_grpc(build_service(), _auth(), tls_files) as stub:
            health = await stub.health(HealthRequest())  # no metadata
            assert health.ok is True and health.version

    asyncio.run(scenario())


_REST_ENDPOINTS = [
    ("/v1/verify", {"bundle_json": FIXTURE_B64}),
    ("/v1/extract", {"bundle_json": FIXTURE_B64}),
    ("/v1/corroborate", {"bundle_json": FIXTURE_B64, "nodes": []}),
    ("/v1/capture", {"chain": "algorand", "txid": FIXTURE_TXID,
                     "round": FIXTURE_ROUND, "source_node": "https://node.example"}),
    ("/v1/capture/stream", {"chain": "algorand", "txid": FIXTURE_TXID,
                            "round": FIXTURE_ROUND, "source_node": "https://node.example"}),
]


@pytest.mark.parametrize("path,body", _REST_ENDPOINTS)
@pytest.mark.parametrize("headers", [None, {"x-api-key": "wrong-key"}], ids=["no-key", "bad-key"])
def test_auth_rest_endpoints_reject_before_work(path, body, headers):
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "POST", path, headers=headers, json_body=body)
        assert status == 401 and "error" in frames[0]

    asyncio.run(scenario())


def test_auth_rest_capture_unauthenticated_before_any_dial(monkeypatch):
    calls = []

    def spy_capture(node_url, txid, round_number, *, timeout, opener, validator):
        calls.append(node_url)
        return copy.deepcopy(FIXTURE_DICT)

    monkeypatch.setattr(service_mod, "capture", spy_capture)
    app = build_rest_app()

    async def scenario():
        status, _, _ = await call_rest(app, "POST", "/v1/capture", json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": "https://node.example"})
        assert status == 401

    asyncio.run(scenario())
    assert calls == []


def test_auth_rest_health_exempt():
    app = build_rest_app()

    async def scenario():
        status, _, frames = await call_rest(app, "GET", "/v1/health")
        assert status == 200 and frames[0]["ok"] is True

    asyncio.run(scenario())

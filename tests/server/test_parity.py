"""Cross-transport parity (design §3 "Tests/conformance/parity"; Phase 6 DoD).

Two transports, ONE service (design §4). This suite proves the two faces agree:
Verify and Extract of the SAME bundle bytes through gRPC and through REST produce
EQUAL reports/facts, and both equal a DIRECT library ``verify_bundle`` /
``extract_payment``. Capture parity is asserted at the achievable invariant.

Parity invariants asserted
---------------------------
* **Verify:** ``report`` (all 13 fields) is identical across gRPC, REST, and a
  direct ``verify_bundle`` of the same bytes; both transports echo the exact
  input bundle bytes (S4).
* **Extract:** the full S3 ``PaymentFact`` field set is identical across gRPC,
  REST, and a direct ``extract_payment``; ``genesis_hash_b64`` agrees; both
  transports echo the bytes (S4).
* **Capture:** everything EXCEPT the volatile ``meta`` block is identical across
  transports, and the ``report`` is identical. Byte-identical capture is NOT an
  achievable invariant: the real ``capture`` stamps ``meta.captured_at`` (wall
  clock) and ``meta.source_node`` (the caller's node URL) at capture time, so two
  captures of the SAME transaction differ in ``meta`` even against identical
  algod data. The test mocks algod IDENTICALLY for both transports (same fake
  responses) and reproduces that meta-stamping, then asserts the achievable
  invariant: identical bundle-minus-meta and identical report. It also asserts
  ``meta.source_node`` DID diverge between the transports, so the exclusion is
  demonstrably load-bearing rather than vacuous.

Hermetic: no live algod. gRPC runs on a loopback TLS server; REST is driven
in-process. Capture's network is mocked identically for both transports.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json

import pytest

pytest.importorskip("grpclib")
pytest.importorskip("betterproto")
pytest.importorskip("cryptography")

from ._kit import (
    AUTH, FIXTURE_BYTES, FIXTURE_B64, FIXTURE_DICT, FIXTURE_ROUND, FIXTURE_TXID,
    VALID_KEY, build_rest_app, build_service, call_rest, grpc_fact_dict,
    library_fact_dict, mock_capture_network, report_to_dict, running_grpc,
)

from avm_proofpack_server.auth import ApiKeyAuth
from avm_proofpack.bundle import Bundle
from avm_proofpack.extract import extract_payment
from avm_proofpack.verify import verify_bundle
from avm_proofpack_server.generated.avm_proofpack.v1 import (
    CaptureRequest, ExtractRequest, VerifyRequest,
)

MD = {"x-api-key": VALID_KEY}


# -- Verify parity: gRPC report == REST report == direct verify_bundle ----

def test_verify_report_parity_across_transports(tls_files):
    direct = report_to_dict(verify_bundle(Bundle.from_dict(copy.deepcopy(FIXTURE_DICT))))

    async def scenario():
        # gRPC
        async with running_grpc(build_service(), ApiKeyAuth([VALID_KEY]), tls_files) as stub:
            g = await stub.verify(VerifyRequest(bundle_json=FIXTURE_BYTES), metadata=MD)
        grpc_report = report_to_dict(g.report)
        grpc_bytes = g.bundle_json

        # REST
        app = build_rest_app()
        status, _, frames = await call_rest(
            app, "POST", "/v1/verify", headers=AUTH, json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        rest_report = frames[0]["report"]
        rest_bytes = base64.b64decode(frames[0]["bundle_json"])
        return grpc_report, grpc_bytes, rest_report, rest_bytes

    grpc_report, grpc_bytes, rest_report, rest_bytes = asyncio.run(scenario())

    # Reports are byte-for-byte equal across gRPC, REST, and the library.
    assert grpc_report == direct
    assert rest_report == direct
    assert grpc_report == rest_report
    # S4: both transports echo the exact input bundle bytes.
    assert grpc_bytes == FIXTURE_BYTES
    assert rest_bytes == FIXTURE_BYTES


# -- Extract parity: gRPC facts == REST facts == direct extract_payment ---

def test_extract_facts_parity_across_transports(tls_files):
    direct_facts = extract_payment(Bundle.from_dict(copy.deepcopy(FIXTURE_DICT)))
    direct_fact = library_fact_dict(direct_facts)
    direct_gh = direct_facts.genesis_hash_b64

    async def scenario():
        async with running_grpc(build_service(), ApiKeyAuth([VALID_KEY]), tls_files) as stub:
            g = await stub.extract(ExtractRequest(bundle_json=FIXTURE_BYTES), metadata=MD)
        grpc_facts = [grpc_fact_dict(f) for f in g.facts]
        grpc_gh = g.genesis_hash_b64
        grpc_bytes = g.bundle_json

        app = build_rest_app()
        status, _, frames = await call_rest(
            app, "POST", "/v1/extract", headers=AUTH, json_body={"bundle_json": FIXTURE_B64})
        assert status == 200
        return (grpc_facts, grpc_gh, grpc_bytes,
                frames[0]["facts"], frames[0]["genesis_hash_b64"],
                base64.b64decode(frames[0]["bundle_json"]))

    (grpc_facts, grpc_gh, grpc_bytes,
     rest_facts, rest_gh, rest_bytes) = asyncio.run(scenario())

    # Same number of facts, same full S3 field set and values, across both
    # transports and the direct library call.
    assert grpc_facts == [direct_fact]
    assert rest_facts == [direct_fact]
    assert grpc_facts == rest_facts
    # genesis_hash agrees across transports and matches the direct library value.
    assert grpc_gh == rest_gh == direct_gh
    # S4: both transports echo the exact input bundle bytes.
    assert grpc_bytes == FIXTURE_BYTES
    assert rest_bytes == FIXTURE_BYTES


# -- Capture parity: identical bundle-minus-meta and identical report ------

def test_capture_parity_excludes_volatile_meta(monkeypatch, tls_files):
    """Capture through gRPC and REST agrees on everything except volatile meta.

    Algod is mocked IDENTICALLY for both transports (same fake responses). The
    fake reproduces capture's real meta-stamping (source_node = the caller's node
    URL, captured_at = now), so meta genuinely diverges between the two requests
    exactly as it would in production. The achievable invariant is therefore
    "identical bundle-minus-meta + identical report", not "byte-identical bundle".
    """
    mock_capture_network(monkeypatch, stamp_meta=True)

    grpc_node = "https://grpc-node.example"
    rest_node = "https://rest-node.example"

    async def scenario():
        async with running_grpc(build_service(), ApiKeyAuth([VALID_KEY]), tls_files) as stub:
            g = await stub.capture(CaptureRequest(
                chain="algorand", txid=FIXTURE_TXID, round=FIXTURE_ROUND,
                source_node=grpc_node), metadata=MD)
        grpc_bundle = json.loads(g.bundle_json)
        grpc_report = report_to_dict(g.report)

        app = build_rest_app()
        status, _, frames = await call_rest(app, "POST", "/v1/capture", headers=AUTH, json_body={
            "chain": "algorand", "txid": FIXTURE_TXID, "round": FIXTURE_ROUND,
            "source_node": rest_node})
        assert status == 200
        rest_bundle = json.loads(base64.b64decode(frames[0]["bundle_json"]))
        rest_report = frames[0]["report"]
        return grpc_bundle, grpc_report, rest_bundle, rest_report

    grpc_bundle, grpc_report, rest_bundle, rest_report = asyncio.run(scenario())

    # The volatile meta DID diverge between transports (this is why we exclude
    # it) - the exclusion is load-bearing, not vacuous.
    assert grpc_bundle["meta"]["source_node"] == grpc_node
    assert rest_bundle["meta"]["source_node"] == rest_node
    assert grpc_bundle["meta"]["source_node"] != rest_bundle["meta"]["source_node"]

    # Achievable invariant: everything EXCEPT meta is byte-identical...
    grpc_no_meta = {k: v for k, v in grpc_bundle.items() if k != "meta"}
    rest_no_meta = {k: v for k, v in rest_bundle.items() if k != "meta"}
    assert grpc_no_meta == rest_no_meta
    # ...and the verification report is identical across transports.
    assert grpc_report == rest_report
    assert grpc_report["txid"] == FIXTURE_TXID

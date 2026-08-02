"""Live-testnet integration test (design §3 "Integration tests"; Phase 6 DoD).

Captures a KNOWN confirmed transaction from a REAL algod node through the service
path (so the egress guard, bounds, and verify-on-capture all run exactly as in
production), then verifies the resulting bundle OFFLINE - proving the round-trip
"a bundle that exists, verifies" holds against live chain data.

SKIPPED BY DEFAULT. It never runs during the normal suite: it is both marked
``network`` (so it can be selected with ``-m network``) AND skipped unless the
required environment variables are set, so a default ``pytest`` run - in CI or
locally - never touches the network.

How to run it against testnet
-----------------------------
Point it at any public algod REST endpoint and give it a confirmed txn whose
state-proof interval has already closed (i.e. old enough to be provable):

    AVM_PROOFPACK_TEST_NODE=https://testnet-api.algonode.cloud \
    AVM_PROOFPACK_TEST_TXID=<52-char base32 txid> \
    AVM_PROOFPACK_TEST_ROUND=<confirmed round> \
    PYTHONPATH=src python -m pytest tests/server/test_integration.py -m network -q

Optional env:
    AVM_PROOFPACK_TEST_CHAIN       chain id label for the store key (default: algorand)
    AVM_PROOFPACK_TEST_ALLOW_HTTP  set to 1 to permit a plain-http node URL
                                   (https is required otherwise; the egress guard
                                   still refuses any private/loopback/link-local
                                   resolved address regardless).

The node must be a PUBLIC host: the egress SSRF guard (S1) is active on this
path, so a loopback/RFC1918/link-local node URL is refused - as intended.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from avm_proofpack.bundle import Bundle
from avm_proofpack.extract import extract_payment
from avm_proofpack.verify import verify_bundle
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressPolicy
from avm_proofpack_server.service import ProofpackService

pytestmark = pytest.mark.network

_NODE = os.environ.get("AVM_PROOFPACK_TEST_NODE")
_TXID = os.environ.get("AVM_PROOFPACK_TEST_TXID")
_ROUND = os.environ.get("AVM_PROOFPACK_TEST_ROUND")
_CHAIN = os.environ.get("AVM_PROOFPACK_TEST_CHAIN", "algorand")
_ALLOW_HTTP = os.environ.get("AVM_PROOFPACK_TEST_ALLOW_HTTP", "0").strip().lower() in (
    "1", "true", "yes", "on")

_MISSING = [name for name, value in (
    ("AVM_PROOFPACK_TEST_NODE", _NODE),
    ("AVM_PROOFPACK_TEST_TXID", _TXID),
    ("AVM_PROOFPACK_TEST_ROUND", _ROUND),
) if not value]
_SKIP_REASON = (
    "live-testnet integration test: set "
    + ", ".join(_MISSING or ["AVM_PROOFPACK_TEST_*"])
    + " to run (see module docstring); skipped by default so the normal suite "
    "makes no network call"
)


@pytest.mark.skipif(bool(_MISSING), reason=_SKIP_REASON)
def test_capture_then_verify_offline_against_live_testnet():
    round_number = int(_ROUND)

    # Real dials, but through the SERVICE path: the egress SSRF guard is active,
    # so the node URL must resolve to a public address (a testnet node does).
    service = ProofpackService(
        ServerConfig(),
        egress=EgressPolicy(allow_http=_ALLOW_HTTP),
    )

    result = asyncio.run(service.capture(
        api_key="integration",
        chain=_CHAIN,
        txid=_TXID,
        round_number=round_number,
        source_node=_NODE,
    ))

    bundle_bytes = result["bundle_json"]
    assert isinstance(bundle_bytes, bytes) and bundle_bytes  # S4: bytes returned

    # ---- OFFLINE verification: no network, only the returned bytes ----
    bundle = Bundle.from_dict(json.loads(bundle_bytes))
    report = verify_bundle(bundle)               # raises VerificationError if invalid
    assert report.txid == _TXID
    assert report.round == round_number

    # The service's own (non-authoritative) report agrees with the offline one.
    assert result["report"].txid == _TXID
    assert result["report"].round == round_number

    # Payment facts are extractable offline from the verified bytes.
    facts = extract_payment(bundle)
    assert facts.txid == _TXID
    assert facts.round == round_number
    assert facts.sender  # a real transaction has a sender

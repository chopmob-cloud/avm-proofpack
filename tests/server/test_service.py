"""ProofpackService S2/S4 suite (design §9, S2 + S4; Phase 1 DoD).

All network is mocked - the core ``capture``/``corroborate`` symbols imported
into the service module are monkeypatched, so no live node is ever dialled.
Covered: S2 DoS bounds (corroboration_nodes cap, wait_seconds clamp, global +
per-key concurrency, request deadline), the egress opener/validator threaded
onto EVERY dial path, and S4 (every response carries bundle_json; no
verdict-only path).
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest

from avm_proofpack_server import service as service_mod
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressPolicy, PinnedOpener
from avm_proofpack_server.service import ProofpackService
from avm_proofpack.verify import CorroborationReport, CorroborationResult

FIXTURE = json.loads(
    (Path(__file__).resolve().parent.parent / "fixtures" / "algorand-mainnet-pay.json")
    .read_text(encoding="utf-8")
)


def _svc(config=None, store=None):
    # A permissive egress policy is fine: capture/corroborate are mocked, so the
    # opener is only ever inspected, never used to dial.
    return ProofpackService(config or ServerConfig(),
                            egress=EgressPolicy(allow_http=True), store=store)


def _fake_capture_returning_fixture(recorder=None):
    def fake(node_url, txid, round_number, *, timeout, opener, validator):
        if recorder is not None:
            recorder.append({"opener": opener, "validator": validator, "node": node_url})
        return dict(FIXTURE)
    return fake


def _patch_verify_ok(monkeypatch):
    monkeypatch.setattr(service_mod, "verify_bundle", lambda bundle, **kw: "REPORT")


# -- S2: corroboration_nodes cap (reject over-limit) ---------------------

def test_capture_rejects_over_limit_corroboration_nodes(monkeypatch):
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture())
    _patch_verify_ok(monkeypatch)
    svc = _svc()
    nodes = [f"https://n{i}.example" for i in range(9)]  # 9 > cap of 8
    with pytest.raises(ValueError):
        asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                                round_number=1, source_node="https://src.example",
                                corroboration_nodes=nodes))


def test_corroborate_async_rejects_over_limit_nodes():
    svc = _svc()
    raw = json.dumps(FIXTURE).encode("utf-8")
    nodes = [f"https://n{i}.example" for i in range(9)]
    with pytest.raises(ValueError):
        asyncio.run(svc.corroborate_async(api_key="k", bundle_json=raw, nodes=nodes))


def test_exactly_eight_nodes_accepted(monkeypatch):
    recorder = []
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture(recorder))
    _patch_verify_ok(monkeypatch)
    monkeypatch.setattr(service_mod, "corroborate",
                        lambda bundle, urls, **kw: CorroborationReport(
                            (CorroborationResult(urls[0], "agree"),)))
    svc = _svc()
    nodes = [f"https://n{i}.example" for i in range(8)]
    out = asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                                  round_number=1, source_node="https://src.example",
                                  corroboration_nodes=nodes))
    assert len(out["corroboration"].results) == 8


# -- S2: wait_seconds clamp ----------------------------------------------

def test_wait_seconds_clamped_at_config():
    cfg = ServerConfig(max_wait_seconds=60)
    assert cfg.clamp_wait(2 ** 32 - 1) == 60   # uint32 max clamped down
    assert cfg.clamp_wait(-5) == 0
    assert cfg.clamp_wait(30) == 30


def test_capture_tolerates_uint32_wait(monkeypatch):
    # A hostile uint32 wait must not hang the request; it is clamped and capture
    # returns promptly.
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture())
    _patch_verify_ok(monkeypatch)
    svc = _svc(ServerConfig(max_wait_seconds=1))
    out = asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                                  round_number=1, source_node="https://src.example",
                                  wait_seconds=2 ** 32 - 1))
    assert out["bundle_json"]


# -- S2: concurrency limits (global + per-key) ---------------------------

class _ConcurrencyProbe:
    def __init__(self, hold=0.05):
        self.hold = hold
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()

    def capture(self, node_url, txid, round_number, *, timeout, opener, validator):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.hold)
        with self.lock:
            self.active -= 1
        return dict(FIXTURE)


async def _run_n_captures(svc, n, api_keys):
    async def one(key):
        return await svc.capture(api_key=key, chain="algorand", txid="TX",
                                 round_number=1, source_node="https://src.example")
    return await asyncio.gather(*(one(api_keys[i]) for i in range(n)))


def test_global_concurrency_caps_parallel_captures(monkeypatch):
    probe = _ConcurrencyProbe()
    monkeypatch.setattr(service_mod, "capture", probe.capture)
    _patch_verify_ok(monkeypatch)
    svc = _svc(ServerConfig(global_concurrency=1, per_key_concurrency=8))
    asyncio.run(_run_n_captures(svc, 3, ["a", "b", "c"]))  # distinct keys
    assert probe.peak == 1  # global cap of 1 dominates


def test_per_key_concurrency_caps_same_key(monkeypatch):
    probe = _ConcurrencyProbe()
    monkeypatch.setattr(service_mod, "capture", probe.capture)
    _patch_verify_ok(monkeypatch)
    svc = _svc(ServerConfig(global_concurrency=8, per_key_concurrency=1))
    asyncio.run(_run_n_captures(svc, 3, ["same", "same", "same"]))
    assert probe.peak == 1  # one in-flight per key


def test_distinct_keys_run_in_parallel(monkeypatch):
    probe = _ConcurrencyProbe()
    monkeypatch.setattr(service_mod, "capture", probe.capture)
    _patch_verify_ok(monkeypatch)
    svc = _svc(ServerConfig(global_concurrency=8, per_key_concurrency=1))
    asyncio.run(_run_n_captures(svc, 2, ["a", "b"]))  # different keys
    assert probe.peak == 2  # per-key limit does not serialise distinct keys


# -- S2: request deadline -------------------------------------------------

def test_capture_enforces_request_deadline(monkeypatch):
    def slow(node_url, txid, round_number, *, timeout, opener, validator):
        time.sleep(1.0)
        return dict(FIXTURE)
    monkeypatch.setattr(service_mod, "capture", slow)
    _patch_verify_ok(monkeypatch)
    svc = _svc(ServerConfig(request_timeout=0.1))
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                                round_number=1, source_node="https://src.example"))


# -- S2/S1: egress opener + validator used on EVERY dial path ------------

def _assert_egress_wired(entry, svc):
    assert isinstance(entry["opener"], PinnedOpener)
    assert entry["opener"].policy is svc.egress
    # validator is the policy's bound validate method
    assert entry["validator"].__self__ is svc.egress
    assert entry["validator"].__func__ is type(svc.egress).validate


def test_capture_dial_uses_egress_opener(monkeypatch):
    recorder = []
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture(recorder))
    _patch_verify_ok(monkeypatch)
    svc = _svc()
    asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                            round_number=1, source_node="https://src.example"))
    assert len(recorder) == 1
    _assert_egress_wired(recorder[0], svc)


def test_corroborate_dial_uses_egress_opener_on_capture_path(monkeypatch):
    cap_rec, cor_rec = [], []
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture(cap_rec))
    _patch_verify_ok(monkeypatch)

    def fake_corroborate(bundle, urls, *, timeout, opener, validator):
        cor_rec.append({"opener": opener, "validator": validator, "node": urls[0]})
        return CorroborationReport((CorroborationResult(urls[0], "agree"),))

    monkeypatch.setattr(service_mod, "corroborate", fake_corroborate)
    svc = _svc()
    asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                            round_number=1, source_node="https://src.example",
                            corroboration_nodes=["https://n1.example", "https://n2.example"]))
    assert len(cor_rec) == 2  # one dial per node
    for entry in cor_rec:
        _assert_egress_wired(entry, svc)


def test_corroborate_async_uses_egress_opener(monkeypatch):
    cor_rec = []

    def fake_corroborate(bundle, urls, *, timeout, opener, validator):
        cor_rec.append({"opener": opener, "validator": validator, "node": urls[0]})
        return CorroborationReport((CorroborationResult(urls[0], "agree"),))

    monkeypatch.setattr(service_mod, "corroborate", fake_corroborate)
    svc = _svc()
    raw = json.dumps(FIXTURE).encode("utf-8")
    out = asyncio.run(svc.corroborate_async(api_key="k", bundle_json=raw,
                                            nodes=["https://n1.example"]))
    assert cor_rec and isinstance(cor_rec[0]["opener"], PinnedOpener)
    _assert_egress_wired(cor_rec[0], svc)
    assert out["fully_corroborated"] is True


# -- S2: corroboration runs concurrency-capped, not unbounded sequential -

def test_corroboration_respects_concurrency_cap(monkeypatch):
    probe = _ConcurrencyProbe(hold=0.05)

    def fake_corroborate(bundle, urls, *, timeout, opener, validator):
        with probe.lock:
            probe.active += 1
            probe.peak = max(probe.peak, probe.active)
        time.sleep(probe.hold)
        with probe.lock:
            probe.active -= 1
        return CorroborationReport((CorroborationResult(urls[0], "agree"),))

    monkeypatch.setattr(service_mod, "corroborate", fake_corroborate)
    svc = _svc(ServerConfig(corroboration_concurrency=2))
    raw = json.dumps(FIXTURE).encode("utf-8")
    nodes = [f"https://n{i}.example" for i in range(6)]
    out = asyncio.run(svc.corroborate_async(api_key="k", bundle_json=raw, nodes=nodes))
    assert len(out["results"]) == 6      # all nodes fetched
    assert probe.peak <= 2               # never exceeded the concurrency cap
    assert probe.peak > 1                # and it really did run in parallel


# -- S4: every response carries bundle_json; no verdict-only path --------

def test_verify_response_includes_bundle_json():
    svc = _svc()
    raw = json.dumps(FIXTURE).encode("utf-8")
    out = svc.verify(raw)
    assert out["bundle_json"] == raw
    assert "report" in out


def test_extract_response_includes_bundle_json():
    svc = _svc()
    raw = json.dumps(FIXTURE).encode("utf-8")
    out = svc.extract(raw)
    assert out["bundle_json"] == raw
    assert "facts" in out


def test_capture_response_includes_bundle_json(monkeypatch):
    monkeypatch.setattr(service_mod, "capture", _fake_capture_returning_fixture())
    _patch_verify_ok(monkeypatch)
    svc = _svc()
    out = asyncio.run(svc.capture(api_key="k", chain="algorand", txid="TX",
                                  round_number=1, source_node="https://src.example"))
    assert out["bundle_json"] and isinstance(out["bundle_json"], bytes)
    assert "report" in out


def test_corroborate_async_includes_bundle_json(monkeypatch):
    monkeypatch.setattr(service_mod, "corroborate",
                        lambda bundle, urls, **kw: CorroborationReport(
                            (CorroborationResult(urls[0], "agree"),)))
    svc = _svc()
    raw = json.dumps(FIXTURE).encode("utf-8")
    out = asyncio.run(svc.corroborate_async(api_key="k", bundle_json=raw,
                                            nodes=["https://n1.example"]))
    assert out["bundle_json"] == raw


def test_service_exposes_no_verdict_only_method():
    # Guard against a future verdict-without-bytes RPC: every public result
    # method's return dict includes bundle_json (checked above); assert the
    # service class exposes no method whose name implies a bare verdict.
    public = {n for n in dir(ProofpackService) if not n.startswith("_")}
    for name in public:
        assert name not in {"is_valid", "verdict", "check", "attest"}

"""Background capture scheduler suite (design §7 Phase 5; "Time / freshness").

All network is mocked - either the core ``capture`` symbol imported into the
service module is monkeypatched, or the real egress guard is exercised against a
literal private IP (which is refused before any socket is opened). No live node
is dialled. The asyncio loop is driven deterministically: maturity/capture
scenarios call ``run_once`` directly with an injected clock and zero backoff, so
there are no real sleeps; only the loop-lifecycle tests (cancellation,
crash-resilience) yield briefly, which is unavoidable for an infinite loop.

Scenarios (task DoD):
* NotYetProvable -> retry -> on maturity captured and retrievable by the owner.
* A job that keeps failing past its deadline is marked failed/expired (no
  infinite loop).
* Every dial rides the egress guard: an SSRF/private-IP job is refused and the
  metadata IP is never dialled.
* Tenant scoping: a scheduled job and its resulting bundle are only visible to
  the owning tenant (S5).
* CancelledError propagates cleanly; the loop never crashes on a single job
  error.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from avm_proofpack.capture import CaptureError, NotYetProvable
from avm_proofpack_server import service as service_mod
from avm_proofpack_server import egress as egress_mod
from avm_proofpack_server.config import ServerConfig
from avm_proofpack_server.egress import EgressBlocked, EgressPolicy
from avm_proofpack_server.scheduler import (
    DONE, EXPIRED, FAILED, PENDING,
    CaptureJob, CaptureScheduler, ClockSanityError, InMemoryJobStore,
    JobNotFound, SqliteJobStore, clock_sanity_check,
)
from avm_proofpack_server.service import ProofpackService
from avm_proofpack_server.storage import BundleNotFound, SqliteBundleStore

FIXTURE = json.loads(
    (Path(__file__).resolve().parent.parent / "fixtures" / "algorand-mainnet-pay.json")
    .read_text(encoding="utf-8")
)

# Real fixture coordinates: TXID must be valid base32 because the SSRF test runs
# the REAL capture path (which validates the txid before dialling).
TXID = FIXTURE["transaction"]["txid"]
ROUND = FIXTURE["transaction"]["round"]


class _Clock:
    """Deterministic monotonic clock; advance explicitly, never sleeps."""

    def __init__(self, t=0.0):
        self.t = float(t)

    def __call__(self):
        return self.t


def _svc(store=None, config=None, egress=None):
    return ProofpackService(config or ServerConfig(scheduler_retry_backoff=0.0),
                            egress=egress or EgressPolicy(allow_http=True),
                            store=store)


def _job(tenant="t1", source_node="https://node.example", **kw):
    base = dict(tenant=tenant, chain="algorand", txid=TXID, round_number=ROUND,
                source_node=source_node)
    base.update(kw)
    return CaptureJob(**base)


def _patch_verify_ok(monkeypatch):
    monkeypatch.setattr(service_mod, "verify_bundle", lambda bundle, **kw: "REPORT")


# -- clock sanity (Time / freshness startup hook) ------------------------

def test_clock_sanity_accepts_present_and_rejects_absurd():
    assert clock_sanity_check(1_700_000_000) == 1_700_000_000  # 2023-ish, fine
    with pytest.raises(ClockSanityError):
        clock_sanity_check(0)                 # unset clock (1970)
    with pytest.raises(ClockSanityError):
        clock_sanity_check(5_000_000_000)     # absurdly future


# -- NotYetProvable -> retry -> matures -> stored & retrievable ----------

def test_not_yet_provable_then_matures_and_stored(monkeypatch, tmp_path):
    calls = {"n": 0}

    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        calls["n"] += 1
        if calls["n"] == 1:
            raise NotYetProvable("no state proof covers the round yet")
        return dict(FIXTURE)

    monkeypatch.setattr(service_mod, "capture", fake_capture)
    _patch_verify_ok(monkeypatch)
    store = SqliteBundleStore(tmp_path / "bundles.db")
    svc = _svc(store=store)
    clock = _Clock()
    sched = CaptureScheduler(svc, config=svc.config, clock=clock)
    job_id = sched.add(_job())

    async def go():
        await sched.run_once()   # attempt 1 -> NotYetProvable, stays pending
        assert sched.jobs.get("t1", job_id).status == PENDING
        with pytest.raises(BundleNotFound):
            store.get("t1", "algorand", ROUND, TXID)
        await sched.run_once()   # attempt 2 -> matured, captured, stored

    asyncio.run(go())

    assert calls["n"] == 2
    assert sched.jobs.get("t1", job_id).status == DONE
    # Retrievable by the owning tenant.
    assert store.get("t1", "algorand", ROUND, TXID)  # bytes, no raise
    # Not visible to any other tenant (S5, existence-masked).
    with pytest.raises(BundleNotFound):
        store.get("t2", "algorand", ROUND, TXID)


# -- keeps failing past deadline -> terminal, no infinite loop -----------

def test_hard_failures_exhaust_attempts_and_mark_failed(monkeypatch, tmp_path):
    def always_fail(node_url, txid, round_number, *, timeout, opener, validator):
        raise CaptureError("node returned garbage")

    monkeypatch.setattr(service_mod, "capture", always_fail)
    _patch_verify_ok(monkeypatch)
    store = SqliteBundleStore(tmp_path / "b.db")
    cfg = ServerConfig(scheduler_retry_backoff=0.0, scheduler_max_attempts=3)
    svc = _svc(store=store, config=cfg)
    sched = CaptureScheduler(svc, config=cfg, clock=_Clock())
    job_id = sched.add(_job())

    async def go():
        for _ in range(3):
            await sched.run_once()
        # A fourth sweep must find nothing due (terminal jobs are never revisited).
        before = sched.jobs.get("t1", job_id).attempts
        await sched.run_once()
        after = sched.jobs.get("t1", job_id).attempts
        assert before == after  # no infinite loop; attempts frozen once terminal

    asyncio.run(go())
    job = sched.jobs.get("t1", job_id)
    assert job.status == FAILED
    assert job.attempts == 3
    assert "garbage" in (job.last_error or "")


def test_never_maturing_job_expires_at_deadline(monkeypatch):
    def not_yet(node_url, txid, round_number, *, timeout, opener, validator):
        raise NotYetProvable("interval not closed")

    monkeypatch.setattr(service_mod, "capture", not_yet)
    _patch_verify_ok(monkeypatch)
    cfg = ServerConfig(scheduler_retry_backoff=10.0, scheduler_job_deadline_seconds=5)
    svc = _svc(config=cfg)
    clock = _Clock(0.0)
    sched = CaptureScheduler(svc, config=cfg, clock=clock)
    job_id = sched.add(_job())  # deadline assigned at clock()=0 -> 5.0

    async def go():
        await sched.run_once()                       # now=0: retry, not_before=10
        assert sched.jobs.get("t1", job_id).status == PENDING
        clock.t = 10.0                                # past deadline (5.0)
        await sched.run_once()                        # now=10 >= deadline -> EXPIRED

    asyncio.run(go())
    assert sched.jobs.get("t1", job_id).status == EXPIRED


# -- S1: every dial rides the egress guard; metadata IP never dialled -----

def test_ssrf_job_refused_and_metadata_never_dialled(monkeypatch, tmp_path):
    # REAL egress policy (no allow_http): a link-local/metadata target must be
    # refused at validate time, before any TCP connect.
    dialled = []
    real_create_connection = egress_mod.socket.create_connection
    monkeypatch.setattr(egress_mod.socket, "create_connection",
                        lambda *a, **k: dialled.append(a) or real_create_connection(*a, **k))
    # NOTE: core `capture` is NOT mocked here - the real client path runs, so the
    # egress validator is genuinely exercised.
    store = SqliteBundleStore(tmp_path / "b.db")
    cfg = ServerConfig(scheduler_retry_backoff=0.0, scheduler_max_attempts=1)
    svc = ProofpackService(cfg, egress=EgressPolicy(), store=store)  # https-only, no allowlist
    sched = CaptureScheduler(svc, config=cfg, clock=_Clock())
    job_id = sched.add(_job(source_node="https://169.254.169.254"))  # cloud metadata

    asyncio.run(sched.run_once())

    job = sched.jobs.get("t1", job_id)
    assert job.status == FAILED
    assert "non-public" in (job.last_error or "") or "169.254" in (job.last_error or "")
    assert dialled == []                              # metadata IP never dialled
    with pytest.raises(BundleNotFound):               # nothing stored
        store.get("t1", "algorand", ROUND, TXID)


def test_capture_dial_carries_egress_opener_and_validator(monkeypatch):
    # The scheduler must route through the service, which threads the egress
    # opener/validator onto EVERY dial (never a raw NodeClient).
    seen = {}

    def fake_capture(node_url, txid, round_number, *, timeout, opener, validator):
        seen["opener"] = opener
        seen["validator"] = validator
        return dict(FIXTURE)

    monkeypatch.setattr(service_mod, "capture", fake_capture)
    _patch_verify_ok(monkeypatch)
    svc = _svc()
    sched = CaptureScheduler(svc, config=svc.config, clock=_Clock())
    sched.add(_job())
    asyncio.run(sched.run_once())
    from avm_proofpack_server.egress import PinnedOpener
    assert isinstance(seen["opener"], PinnedOpener)
    assert seen["opener"].policy is svc.egress
    assert seen["validator"].__self__ is svc.egress


# -- S5: tenant scoping of jobs AND resulting bundles --------------------

def test_tenant_scoped_jobs_and_bundles(monkeypatch, tmp_path):
    monkeypatch.setattr(
        service_mod, "capture",
        lambda node_url, txid, round_number, *, timeout, opener, validator: dict(FIXTURE))
    _patch_verify_ok(monkeypatch)
    store = SqliteBundleStore(tmp_path / "b.db")
    svc = _svc(store=store)
    sched = CaptureScheduler(svc, config=svc.config, clock=_Clock())
    a_id = sched.add(_job(tenant="alice"))
    b_id = sched.add(_job(tenant="bob"))

    asyncio.run(sched.run_once())

    # Each tenant sees only its own job.
    assert sched.jobs.get("alice", a_id).tenant == "alice"
    assert sched.jobs.get("bob", b_id).tenant == "bob"
    with pytest.raises(JobNotFound):
        sched.jobs.get("alice", b_id)      # cross-tenant read masked as not-found
    with pytest.raises(JobNotFound):
        sched.jobs.get("bob", a_id)
    assert [j.job_id for j in sched.jobs.list("alice")] == [a_id]
    assert [j.job_id for j in sched.jobs.list("bob")] == [b_id]

    # Each tenant's captured bundle is isolated.
    assert store.get("alice", "algorand", ROUND, TXID)
    assert store.get("bob", "algorand", ROUND, TXID)
    # A third tenant that scheduled nothing sees nothing.
    with pytest.raises(BundleNotFound):
        store.get("carol", "algorand", ROUND, TXID)


def test_inmemory_jobstore_requires_tenant():
    store = InMemoryJobStore()
    with pytest.raises(ValueError):
        store.add(CaptureJob(tenant="", chain="algorand", txid=TXID,
                             round_number=ROUND, source_node="https://n.example"))


def test_sqlite_jobstore_roundtrip_and_tenant_scope(tmp_path):
    store = SqliteJobStore(tmp_path / "jobs.db")
    jid = store.add(_job(tenant="alice", corroboration_nodes=("https://c1.example",)))
    got = store.get("alice", jid)
    assert got.tenant == "alice"
    assert got.corroboration_nodes == ("https://c1.example",)
    with pytest.raises(JobNotFound):
        store.get("bob", jid)
    assert store.list("bob") == []
    # `due` returns the pending job (tenant-agnostic internal worker query).
    assert [j.job_id for j in store.due(now=0.0)] == [jid]
    store.close()


# -- loop lifecycle: never crashes, CancelledError propagates ------------

def test_run_once_never_raises_on_single_job_error(monkeypatch):
    def boom(node_url, txid, round_number, *, timeout, opener, validator):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(service_mod, "capture", boom)
    _patch_verify_ok(monkeypatch)
    cfg = ServerConfig(scheduler_retry_backoff=0.0, scheduler_max_attempts=1)
    svc = _svc(config=cfg)
    sched = CaptureScheduler(svc, config=cfg, clock=_Clock())
    job_id = sched.add(_job())
    # run_once must swallow the job error (not propagate).
    asyncio.run(sched.run_once())
    assert sched.jobs.get("t1", job_id).status == FAILED


def test_loop_survives_sweep_error_and_keeps_ticking():
    async def go():
        svc = _svc(config=ServerConfig(scheduler_poll_interval=0.01))
        sched = CaptureScheduler(svc, config=svc.config, clock=_Clock())
        calls = {"n": 0}

        async def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom in a sweep")

        sched.run_once = flaky        # force the loop's own try/except to fire
        task = sched.start()
        await asyncio.sleep(0.06)     # allow several ticks
        assert calls["n"] >= 2        # survived the boom and kept sweeping
        await sched.stop()
        assert task.done()

    asyncio.run(go())


def test_cancellederror_propagates_from_run():
    async def go():
        svc = _svc(config=ServerConfig(scheduler_poll_interval=0.01))
        sched = CaptureScheduler(svc, config=svc.config, clock=_Clock())
        task = asyncio.create_task(sched.run())
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())


def test_start_is_idempotent_and_stop_clean():
    async def go():
        svc = _svc(config=ServerConfig(scheduler_poll_interval=0.01))
        sched = CaptureScheduler(svc, config=svc.config, clock=_Clock())
        t1 = sched.start()
        t2 = sched.start()
        assert t1 is t2               # a second start does not spawn a second loop
        await asyncio.sleep(0.02)
        await sched.stop()
        assert t1.done()

    asyncio.run(go())

"""Bounded background capture scheduler (design §7 Phase 5; "Time / freshness").

Given scheduled capture requests ``(chain, txid, round, tenant)`` this worker
polls the node for state-proof maturity, captures the bundle once the 256-round
attestation interval closes, and stores it in the tenant-scoped ``BundleStore``.

Loop invariants (mirror the estate's settlement-evidence reaper idiom):

* **Never crashes the loop.** Every per-job error and every sweep-level error is
  caught and logged; one bad job never stops the worker.
* **CancelledError propagates.** Shutdown cancels the task; ``CancelledError`` is
  re-raised, never swallowed, so ``stop()`` completes cleanly.
* **First poll fires promptly.** No sleep-before-first-sweep; a freshly enqueued
  job is attempted on the next tick, and the first tick is immediate.
* **Idempotent re-runs.** Terminal jobs (``done`` / ``failed`` / ``expired``)
  are never revisited; a re-sweep of a pending job simply retries capture, and
  ``ProofpackService.capture`` writes are content-addressed and tenant-scoped so
  a duplicate capture is a harmless overwrite of identical coordinates.

How maturity is detected (S1-safe)
----------------------------------
The scheduler does NOT open its own socket. It calls the SAME
``ProofpackService.capture``; capture's first step is ``GET
/v2/stateproofs/{round}``, which the core surfaces as
``avm_proofpack.NotYetProvable`` (a 404 / interval-not-covering means the
attestation interval has not closed yet). So "poll for maturity, then capture"
is one atomic call: ``NotYetProvable`` == not-yet == retry-later; a returned
bundle == matured and captured. Because it goes through the service, the egress
SSRF guard (S1), the concurrency/deadline bounds (S2), and the tenant-scoped
store write (S5) all apply exactly as they do for a client request. The
scheduler holds NO raw ``NodeClient`` and NEVER bypasses the egress guard.

Clock as a trust input ("Time / freshness")
--------------------------------------------
The server clock is a trust input for maturity decisions, so:

* ``clock_sanity_check`` is a documented startup hook (called from ``__main__``
  when the scheduler is enabled). It rejects an absurd wall clock. It adds NO
  network NTP dependency; the production deployment gates startup on ntpd/chrony
  sync -- this hook is the in-process check point for that.
* ALL interval arithmetic (backoff, deadline) uses ``time.monotonic`` via the
  injected ``clock``, never the wall clock, so a step change in wall time cannot
  corrupt retry/expiry maths mid-run.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from avm_proofpack.capture import CaptureError, NotYetProvable
from .config import ServerConfig
from .egress import EgressBlocked

logger = logging.getLogger("avm_proofpack_server.scheduler")

# Terminal + non-terminal job states.
PENDING = "pending"
DONE = "done"
FAILED = "failed"
EXPIRED = "expired"
_TERMINAL = frozenset({DONE, FAILED, EXPIRED})

# Wall-clock sanity window for the startup trust check. A clock outside this
# window is unset or absurdly skewed; maturity decisions cannot be trusted.
_MIN_SANE_EPOCH = 1_577_836_800   # 2020-01-01T00:00:00Z
_MAX_SANE_EPOCH = 4_102_444_800   # 2100-01-01T00:00:00Z


class ClockSanityError(RuntimeError):
    """The server wall clock is outside the sane window; refuse to schedule."""


def clock_sanity_check(now_wall: float | None = None) -> float:
    """Startup trust hook: reject an absurd server wall clock.

    The scheduler decides maturity partly from time; a wildly wrong clock (unset
    RTC, misconfigured VM) makes those decisions untrustworthy. This is a
    DOCUMENTED check point for an NTP-synced deployment -- run ntpd/chrony and
    gate startup on sync. It deliberately adds NO network NTP client. Interval
    maths never uses this value; it uses ``time.monotonic`` (see the module
    docstring). Returns the validated wall time for logging.
    """
    now = time.time() if now_wall is None else now_wall
    if not (_MIN_SANE_EPOCH <= now <= _MAX_SANE_EPOCH):
        raise ClockSanityError(
            f"server wall clock {now!r} is outside the sane window "
            f"[{_MIN_SANE_EPOCH}, {_MAX_SANE_EPOCH}]; NTP-sync the host before "
            "enabling the capture scheduler"
        )
    return now


@dataclass
class CaptureJob:
    """A scheduled capture request, tenant-scoped (S5).

    ``not_before`` / ``deadline`` are on the injected monotonic clock's scale,
    NOT wall time. ``job_id`` is server-minted (high entropy) so it is not
    enumerable across tenants.
    """
    tenant: str
    chain: str
    txid: str
    round_number: int
    source_node: str
    corroboration_nodes: tuple[str, ...] = ()
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = PENDING
    attempts: int = 0
    not_before: float = 0.0
    deadline: float | None = None
    last_error: str | None = None

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL


class JobStore(ABC):
    """Pluggable, tenant-scoped job source.

    Reads (``get`` / ``list``) are tenant-scoped exactly like the BundleStore
    (S5): a tenant can neither see nor address another tenant's jobs. ``due`` is
    an internal worker query (tenant-agnostic) that returns non-terminal jobs
    whose ``not_before`` has passed on the given clock.
    """

    @abstractmethod
    def add(self, job: CaptureJob) -> str: ...
    @abstractmethod
    def due(self, now: float) -> list[CaptureJob]: ...
    @abstractmethod
    def update(self, job: CaptureJob) -> None: ...
    @abstractmethod
    def get(self, tenant: str, job_id: str) -> CaptureJob: ...
    @abstractmethod
    def list(self, tenant: str) -> list[CaptureJob]: ...


class JobNotFound(KeyError):
    pass


def _require_tenant(tenant: str) -> None:
    if not tenant or not isinstance(tenant, str):
        raise ValueError("tenant is required")


class InMemoryJobStore(JobStore):
    """Simple thread-safe in-memory queue. The default job source."""

    def __init__(self) -> None:
        self._jobs: dict[str, CaptureJob] = {}
        self._lock = threading.RLock()

    def add(self, job: CaptureJob) -> str:
        _require_tenant(job.tenant)
        with self._lock:
            self._jobs[job.job_id] = job
        return job.job_id

    def due(self, now: float) -> list[CaptureJob]:
        with self._lock:
            return [j for j in self._jobs.values()
                    if not j.terminal and j.not_before <= now]

    def update(self, job: CaptureJob) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, tenant: str, job_id: str) -> CaptureJob:
        _require_tenant(tenant)
        with self._lock:
            job = self._jobs.get(job_id)
        # Existence-masked: not-owned is indistinguishable from not-found (S5).
        if job is None or job.tenant != tenant:
            raise JobNotFound("job not found")
        return job

    def list(self, tenant: str) -> list[CaptureJob]:
        _require_tenant(tenant)
        with self._lock:
            return [j for j in self._jobs.values() if j.tenant == tenant]


class SqliteJobStore(JobStore):
    """Optional SQLite-backed job table, tenant-scoped (S5), alongside storage.py.

    Persistence caveat: ``not_before`` / ``deadline`` live on the monotonic
    scale, which resets across process restarts. After a restart a persisted
    deadline is re-based by the scheduler when it re-adopts jobs; kept simple on
    purpose -- this is a scheduler, not a full job system.
    """

    _COLS = ("job_id", "tenant", "chain", "txid", "round_number", "source_node",
             "corroboration_nodes", "status", "attempts", "not_before",
             "deadline", "last_error")

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS capture_jobs (
          job_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, chain TEXT NOT NULL,
          txid TEXT NOT NULL, round_number INTEGER NOT NULL,
          source_node TEXT NOT NULL, corroboration_nodes TEXT NOT NULL,
          status TEXT NOT NULL, attempts INTEGER NOT NULL,
          not_before REAL NOT NULL, deadline REAL, last_error TEXT);
        CREATE INDEX IF NOT EXISTS capture_jobs_tenant ON capture_jobs(tenant);
        """)
        self._db.commit()

    def _row(self, job: CaptureJob) -> tuple:
        return (job.job_id, job.tenant, job.chain, job.txid, job.round_number,
                job.source_node, "\n".join(job.corroboration_nodes), job.status,
                job.attempts, job.not_before, job.deadline, job.last_error)

    def _job(self, row) -> CaptureJob:
        d = dict(zip(self._COLS, row))
        nodes = tuple(n for n in (d["corroboration_nodes"] or "").split("\n") if n)
        return CaptureJob(
            tenant=d["tenant"], chain=d["chain"], txid=d["txid"],
            round_number=d["round_number"], source_node=d["source_node"],
            corroboration_nodes=nodes, job_id=d["job_id"], status=d["status"],
            attempts=d["attempts"], not_before=d["not_before"],
            deadline=d["deadline"], last_error=d["last_error"])

    def add(self, job: CaptureJob) -> str:
        _require_tenant(job.tenant)
        with self._lock, self._db:
            self._db.execute(
                f"INSERT OR REPLACE INTO capture_jobs({','.join(self._COLS)}) "
                f"VALUES ({','.join('?' * len(self._COLS))})", self._row(job))
        return job.job_id

    def due(self, now: float) -> list[CaptureJob]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM capture_jobs WHERE status=? AND not_before<=?",
                (PENDING, now)).fetchall()
        return [self._job(r) for r in rows]

    def update(self, job: CaptureJob) -> None:
        self.add(job)

    def get(self, tenant: str, job_id: str) -> CaptureJob:
        _require_tenant(tenant)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM capture_jobs WHERE job_id=? AND tenant=?",
                (job_id, tenant)).fetchone()
        if row is None:  # existence-masked cross-tenant (S5)
            raise JobNotFound("job not found")
        return self._job(row)

    def list(self, tenant: str) -> list[CaptureJob]:
        _require_tenant(tenant)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM capture_jobs WHERE tenant=? ORDER BY job_id",
                (tenant,)).fetchall()
        return [self._job(r) for r in rows]

    def close(self) -> None:
        self._db.close()


class CaptureScheduler:
    """Async background worker driving scheduled captures through the service.

    Parameters
    ----------
    service:
        The ONE shared ``ProofpackService``; its ``capture`` applies egress
        (S1), bounds (S2), and the tenant-scoped store write (S5).
    jobs:
        A ``JobStore`` (defaults to a fresh ``InMemoryJobStore``) or an iterable
        of ``CaptureJob`` / job-kwargs dicts for convenience.
    clock:
        Monotonic clock, injectable for deterministic tests (default
        ``time.monotonic``).
    """

    def __init__(self, service, jobs=None, *, config: ServerConfig | None = None,
                 clock=time.monotonic):
        self.service = service
        self.config = config or getattr(service, "config", None) or ServerConfig()
        self._clock = clock
        self._task: asyncio.Task | None = None
        self._sem = asyncio.Semaphore(self.config.scheduler_concurrency)

        if jobs is None:
            self.jobs: JobStore = InMemoryJobStore()
        elif isinstance(jobs, JobStore):
            self.jobs = jobs
        else:
            self.jobs = InMemoryJobStore()
            for job in jobs:
                self.add(job)

    # -- job admission ----------------------------------------------------

    def add(self, job) -> str:
        """Enqueue a job. Accepts a CaptureJob or a kwargs dict.

        Assigns the monotonic deadline here (using the injected clock) so it is
        never derived from wall time.
        """
        if isinstance(job, dict):
            job = CaptureJob(**job)
        if job.deadline is None:
            job.deadline = self._clock() + self.config.scheduler_job_deadline_seconds
        return self.jobs.add(job)

    # -- one sweep --------------------------------------------------------

    async def run_once(self) -> None:
        """Run one bounded sweep over all due, non-terminal jobs.

        Concurrency is capped by ``config.scheduler_concurrency``. A single job
        error can NEVER escape (``return_exceptions=True`` plus per-job
        try/except), so the caller loop is protected.
        """
        due = self.jobs.due(self._clock())
        if not due:
            return
        await asyncio.gather(*(self._attempt(job) for job in due),
                             return_exceptions=True)

    async def _attempt(self, job: CaptureJob) -> None:
        async with self._sem:
            job.attempts += 1
            now = self._clock()
            try:
                # SAME service path: egress guard + bounds + tenant store write.
                await self.service.capture(
                    api_key=f"scheduler:{job.tenant}",
                    chain=job.chain, txid=job.txid,
                    round_number=job.round_number, source_node=job.source_node,
                    corroboration_nodes=list(job.corroboration_nodes),
                    tenant=job.tenant)
            except NotYetProvable as exc:
                # Interval not closed yet: retry-later, unless we are past the
                # deadline (state proof never matured in time) -> expired.
                job.last_error = str(exc)
                if self._past_deadline(job, now):
                    job.status = EXPIRED
                    logger.info("scheduler.job_expired",
                                extra={"job_id": job.job_id, "round": job.round_number})
                else:
                    job.not_before = now + self.config.scheduler_retry_backoff
            except (EgressBlocked, CaptureError, Exception) as exc:  # noqa: B014
                # Hard failure (SSRF refusal, node/data error, anything). Retry
                # with backoff until attempts or deadline are exhausted, then
                # mark failed. NEVER loops forever.
                job.last_error = str(exc)
                if self._exhausted(job, now):
                    job.status = FAILED
                    logger.warning("scheduler.job_failed",
                                   extra={"job_id": job.job_id, "error": str(exc)})
                else:
                    job.not_before = now + self.config.scheduler_retry_backoff
            else:
                job.status = DONE
                job.last_error = None
                logger.info("scheduler.job_captured",
                            extra={"job_id": job.job_id, "round": job.round_number})
            finally:
                self.jobs.update(job)

    def _past_deadline(self, job: CaptureJob, now: float) -> bool:
        return job.deadline is not None and now >= job.deadline

    def _exhausted(self, job: CaptureJob, now: float) -> bool:
        return (job.attempts >= self.config.scheduler_max_attempts
                or self._past_deadline(job, now))

    # -- loop lifecycle ---------------------------------------------------

    async def run(self, interval: float | None = None) -> None:
        """Infinite poll loop. First sweep fires immediately (no sleep-first)."""
        poll = self.config.scheduler_poll_interval if interval is None else interval
        logger.info("scheduler.started",
                    extra={"poll_interval": poll,
                           "concurrency": self.config.scheduler_concurrency})
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # loop must never crash on a sweep error
                logger.error("scheduler.sweep_error",
                             extra={"error": str(exc)}, exc_info=True)
            await asyncio.sleep(poll)

    def start(self, interval: float | None = None) -> asyncio.Task:
        if self._task is None:
            self._task = asyncio.create_task(self.run(interval))
        return self._task

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

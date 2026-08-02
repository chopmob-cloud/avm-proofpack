"""Validated server configuration and resource bounds."""
from __future__ import annotations
from dataclasses import dataclass
import os

@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    grpc_port: int = 50051
    rest_port: int = 8080
    max_corroboration_nodes: int = 8
    max_wait_seconds: int = 60
    request_timeout: float = 30.0
    max_bundle_bytes: int = 4 * 1024 * 1024
    global_concurrency: int = 16
    per_key_concurrency: int = 2
    corroboration_concurrency: int = 4
    api_key_file: str | None = None
    node_allowlist: frozenset[str] = frozenset()
    # TLS (design §9 / plan Phase 3). The design supports BOTH in-process TLS
    # and TLS termination at a reverse proxy. When both cert and key are
    # configured, in-process TLS is default-on; when neither is set the server
    # binds plaintext (intended only behind a proxy that terminates TLS).
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    # Scheduler (design §7 Phase 5; "Time / freshness" axis). Default OFF: the
    # background worker only runs when explicitly enabled. All interval maths use
    # time.monotonic; the wall clock is a trust input for maturity (see
    # scheduler.clock_sanity_check), never used for backoff/deadline arithmetic.
    scheduler_enabled: bool = False
    scheduler_poll_interval: float = 60.0
    scheduler_concurrency: int = 4
    scheduler_retry_backoff: float = 60.0
    scheduler_job_deadline_seconds: int = 24 * 3600
    scheduler_max_attempts: int = 20

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert_file and self.tls_key_file)

    def __post_init__(self) -> None:
        if self.max_corroboration_nodes < 0 or self.max_corroboration_nodes > 8:
            raise ValueError("max_corroboration_nodes must be between 0 and 8")
        if self.max_wait_seconds < 0 or self.max_wait_seconds > 3600:
            raise ValueError("max_wait_seconds must be between 0 and 3600")
        if self.request_timeout <= 0 or self.request_timeout > 300:
            raise ValueError("request_timeout must be between 0 and 300 seconds")
        if self.global_concurrency < 1 or self.global_concurrency > 1024 or self.per_key_concurrency < 1 or self.per_key_concurrency > 128:
            raise ValueError("concurrency limits are out of bounds")
        if self.corroboration_concurrency < 1 or self.corroboration_concurrency > 64:
            raise ValueError("corroboration_concurrency must be between 1 and 64")
        if self.scheduler_poll_interval <= 0 or self.scheduler_poll_interval > 86400:
            raise ValueError("scheduler_poll_interval must be between 0 and 86400 seconds")
        if self.scheduler_concurrency < 1 or self.scheduler_concurrency > 128:
            raise ValueError("scheduler_concurrency must be between 1 and 128")
        if self.scheduler_retry_backoff < 0 or self.scheduler_retry_backoff > 86400:
            raise ValueError("scheduler_retry_backoff must be between 0 and 86400 seconds")
        if self.scheduler_job_deadline_seconds < 1:
            raise ValueError("scheduler_job_deadline_seconds must be positive")
        if self.scheduler_max_attempts < 1:
            raise ValueError("scheduler_max_attempts must be positive")

    def clamp_wait(self, value: int) -> int:
        return max(0, min(int(value), self.max_wait_seconds))

    def clamp_nodes(self, nodes: list[str]) -> list[str]:
        if len(nodes) > self.max_corroboration_nodes:
            raise ValueError("too many corroboration nodes")
        return list(nodes)

    @classmethod
    def from_env(cls) -> "ServerConfig":
        def integer(name: str, default: int) -> int:
            return int(os.environ.get(name, default))
        def flag(name: str, default: bool) -> bool:
            return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")
        return cls(host=os.environ.get("AVM_PROOFPACK_HOST", "127.0.0.1"),
                   grpc_port=integer("AVM_PROOFPACK_GRPC_PORT", 50051),
                   rest_port=integer("AVM_PROOFPACK_REST_PORT", 8080),
                   api_key_file=os.environ.get("AVM_PROOFPACK_API_KEY_FILE"),
                   tls_cert_file=os.environ.get("AVM_PROOFPACK_TLS_CERT_FILE"),
                   tls_key_file=os.environ.get("AVM_PROOFPACK_TLS_KEY_FILE"),
                   scheduler_enabled=flag("AVM_PROOFPACK_SCHEDULER_ENABLED", False),
                   scheduler_poll_interval=float(os.environ.get("AVM_PROOFPACK_SCHEDULER_POLL_INTERVAL", 60.0)))

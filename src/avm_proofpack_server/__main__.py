"""Server entry point: launch the gRPC and/or REST transport from config.

Both transports wrap ONE :class:`ProofpackService`, so they are two faces of the
same implementation (design §4). Which transports run is config-driven via
``AVM_PROOFPACK_TRANSPORTS`` (comma-separated, default ``grpc,rest``). TLS is a
deployment concern handled inside each transport (default-on when a cert+key are
configured, otherwise plaintext intended only behind a TLS-terminating proxy).

Transport modules pull the ``[server]`` extra (grpclib / betterproto / uvicorn);
they are imported LAZILY, only for the transports actually selected, so a
deployment that runs just one transport need not import the other's deps.
"""
from __future__ import annotations

import asyncio
import os

from .auth import ApiKeyAuth
from .config import ServerConfig
from .service import ProofpackService


def _selected_transports() -> list[str]:
    raw = os.environ.get("AVM_PROOFPACK_TRANSPORTS", "grpc,rest")
    return [name.strip().lower() for name in raw.split(",") if name.strip()]


async def _run(service: ProofpackService, config: ServerConfig,
               auth: ApiKeyAuth | None, transports: list[str]) -> None:
    tasks = []
    if "grpc" in transports:
        from .grpc_server import serve as serve_grpc
        tasks.append(asyncio.create_task(serve_grpc(service, config, auth=auth)))
    if "rest" in transports:
        from .rest_gateway import serve_rest
        tasks.append(asyncio.create_task(serve_rest(service, config, auth=auth)))
    if not tasks:
        raise SystemExit(
            "no valid transports selected; set AVM_PROOFPACK_TRANSPORTS to "
            "'grpc', 'rest', or 'grpc,rest'")
    # Optional background capture scheduler (default OFF). Shares the ONE
    # ProofpackService, so every scheduled dial rides the same egress guard and
    # bounds. Imported lazily so a deployment that never schedules pays nothing.
    if config.scheduler_enabled:
        from .scheduler import CaptureScheduler, clock_sanity_check
        # The server clock is a trust input for maturity decisions; gate startup.
        clock_sanity_check()
        scheduler = CaptureScheduler(service, config=config)
        tasks.append(scheduler.start())
    await asyncio.gather(*tasks)


def main() -> None:
    config = ServerConfig.from_env()
    # ApiKeyAuth exposes ApiKeyAuth(key_file=...); there is no from_file() (that
    # was the pre-existing bug). No key file => auth is None, which the transports
    # treat as proxy/mTLS-terminated mode (auth enforced upstream).
    auth = ApiKeyAuth(key_file=config.api_key_file) if config.api_key_file else None
    service = ProofpackService(config)
    asyncio.run(_run(service, config, auth, _selected_transports()))


if __name__ == "__main__":
    main()

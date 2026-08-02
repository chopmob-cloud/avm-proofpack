"""grpclib transport for the transport-independent proofpack service.

This module is the gRPC face of :class:`ProofpackService`. It is a THIN
transport: every RPC deserialises the request, delegates to the service (which
owns the S1 egress guard, the S2 resource bounds, the S4 bundle-is-the-anchor
guarantee, and the S5 tenant scoping), and maps the service's typed exceptions
onto gRPC status codes. No verification, dialing, or storage logic lives here.

Transport-layer security posture (design §9):

* **Auth before work (closes the Phase-1 gap).** Every RPC except ``Health``
  requires a valid API key presented in request metadata (``x-api-key`` or
  ``authorization: Bearer <key>``), verified with the constant-time
  :class:`ApiKeyAuth`. The check runs BEFORE the request body is read and before
  any dial, so an unauthenticated or bad-key call is rejected with
  ``UNAUTHENTICATED`` without the server ever touching a caller-supplied node.
  The authenticated key is threaded into the service as the identity for the
  per-key concurrency semaphore (S2). ``Health`` is deliberately exempt so
  liveness probes need no credential.
* **S2 at the transport.** ``corroboration_nodes`` is length-checked against the
  config cap before any dial (``RESOURCE_EXHAUSTED`` on overflow); the service
  additionally clamps ``wait_seconds`` and enforces the request deadline and the
  global/per-key/corroboration concurrency semaphores.
* **S4.** There is no verdict-only RPC; every response echoes ``bundle_json``.
  This layer never synthesises a verdict of its own.

This module imports ``grpclib`` / ``betterproto`` / the generated stubs LAZILY,
so ``import avm_proofpack_server`` (and the stdlib-only egress/config pieces)
still works without the ``[server]`` extra installed. Loading this module's
transport entry points without the extra raises a clear
``install avm-proofpack[server]`` error rather than a bare ``ImportError``.
"""
from __future__ import annotations

import asyncio
from typing import Any

from .auth import ApiKeyAuth, AuthenticationError
from .egress import EgressBlocked
from .storage import BundleNotFound

# Core exceptions used only for status mapping. The core is stdlib-only and
# always importable; importing it here never pulls a third-party dependency.
# VerificationError is NOT a ValueError, so it needs its own mapping branch;
# ExtractionError IS a ValueError and is covered by that branch.
from avm_proofpack.verify import VerificationError


_AUTH_METADATA_KEYS = ("x-api-key", "authorization")


def _load_transport():
    """Import the [server]-extra transport bits, or fail with a clear message."""
    try:
        import grpclib  # noqa: F401
        from grpclib import GRPCError
        from grpclib.const import Status, Handler, Cardinality
        from .generated.avm_proofpack.v1 import (
            CaptureProgress, CaptureProgressStage, CaptureRequest, CaptureResponse,
            CorroborateRequest, CorroborateResponse, CorroborationResult,
            ExtractRequest, ExtractResponse, HealthRequest, HealthResponse,
            PaymentFact, ProofpackBase, VerificationReport, VerifyRequest,
            VerifyResponse,
        )
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "gRPC support requires the service extra; install avm-proofpack[server] "
            f"(original error: {exc})"
        ) from exc
    return {
        "GRPCError": GRPCError, "Status": Status, "Handler": Handler,
        "Cardinality": Cardinality, "CaptureProgress": CaptureProgress,
        "CaptureProgressStage": CaptureProgressStage, "CaptureRequest": CaptureRequest,
        "CaptureResponse": CaptureResponse, "CorroborateRequest": CorroborateRequest,
        "CorroborateResponse": CorroborateResponse, "CorroborationResult": CorroborationResult,
        "ExtractRequest": ExtractRequest, "ExtractResponse": ExtractResponse,
        "HealthRequest": HealthRequest, "HealthResponse": HealthResponse,
        "PaymentFact": PaymentFact, "ProofpackBase": ProofpackBase,
        "VerificationReport": VerificationReport, "VerifyRequest": VerifyRequest,
        "VerifyResponse": VerifyResponse,
    }


def _metadata_key(metadata) -> str | None:
    """Extract a presented API key from grpclib request metadata.

    Accepts ``x-api-key: <key>`` or ``authorization: Bearer <key>`` (the bare
    ``authorization`` value is also accepted). Returns ``None`` when absent so
    the auth layer can reject it uniformly.
    """
    for key, value in (metadata or {}).items() if hasattr(metadata, "items") else (metadata or ()):
        if str(key).lower() in _AUTH_METADATA_KEYS:
            value = value.decode() if isinstance(value, (bytes, bytearray)) else str(value)
            return value[len("Bearer "):] if value.startswith("Bearer ") else value
    return None


def _status_for(exc: Exception, Status):
    """Map a service/core exception to a gRPC status code (design §9)."""
    if isinstance(exc, AuthenticationError):
        return Status.UNAUTHENTICATED
    if isinstance(exc, EgressBlocked):
        # SSRF refusal: a caller-supplied node was rejected by the egress guard.
        return Status.PERMISSION_DENIED
    if isinstance(exc, BundleNotFound):
        return Status.NOT_FOUND
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return Status.DEADLINE_EXCEEDED
    if isinstance(exc, MemoryError):
        return Status.RESOURCE_EXHAUSTED
    if isinstance(exc, VerificationError):
        # A caller-supplied bundle that decodes but fails verification is a bad
        # argument, not a server-internal error.
        return Status.INVALID_ARGUMENT
    if isinstance(exc, ValueError):
        # The service raises ValueError for the S2 node-count overflow; surface
        # that as RESOURCE_EXHAUSTED. Every other ValueError (bad bundle bytes,
        # bad JSON, verification/extraction failures) is a bad argument.
        message = str(exc).lower()
        if "too many" in message and "node" in message:
            return Status.RESOURCE_EXHAUSTED
        return Status.INVALID_ARGUMENT
    return Status.INTERNAL


def make_service(service, auth: ApiKeyAuth | None = None):
    """Build the grpclib handler wrapping ``service``.

    ``auth`` gates every RPC except ``Health``. Passing ``auth=None`` disables
    the API-key check and is intended ONLY for deployments that authenticate at
    a trusted reverse proxy / via mTLS; the in-process default (see
    ``__main__``) always wires a real :class:`ApiKeyAuth`.
    """
    T = _load_transport()
    GRPCError, Status = T["GRPCError"], T["Status"]
    Handler, Cardinality = T["Handler"], T["Cardinality"]
    ProofpackBase = T["ProofpackBase"]
    (CaptureProgress, CaptureProgressStage, CaptureRequest, CaptureResponse,
     CorroborateRequest, CorroborateResponse, CorroborationResult, ExtractRequest,
     ExtractResponse, HealthRequest, HealthResponse, PaymentFact, VerificationReport,
     VerifyRequest, VerifyResponse) = (
        T["CaptureProgress"], T["CaptureProgressStage"], T["CaptureRequest"],
        T["CaptureResponse"], T["CorroborateRequest"], T["CorroborateResponse"],
        T["CorroborationResult"], T["ExtractRequest"], T["ExtractResponse"],
        T["HealthRequest"], T["HealthResponse"], T["PaymentFact"],
        T["VerificationReport"], T["VerifyRequest"], T["VerifyResponse"],
    )

    # -- wire mappers: core dataclasses -> generated proto messages --------
    # Explicit field-by-field mapping (not a generic asdict) because the core
    # field names diverge from the wire (core PaymentFacts.receiver ->
    # receiver_address; CorroborationResult.status -> matches) and dropping a
    # field would violate S3 full-fidelity.

    def _report_msg(report) -> Any:
        return VerificationReport(
            txid=report.txid, round=report.round, genesis_id=report.genesis_id,
            genesis_hash_b64=report.genesis_hash_b64,
            block_hash_b64=report.block_hash_b64,
            txn_commitment_b64=report.txn_commitment_b64,
            light_header_variant=report.light_header_variant,
            first_attested_round=report.first_attested_round,
            last_attested_round=report.last_attested_round,
            block_headers_commitment_b64=report.block_headers_commitment_b64,
            voters_commitment_b64=report.voters_commitment_b64,
            checks=list(report.checks), trust_root=report.trust_root,
        )

    def _fact_msg(fact) -> Any:
        return PaymentFact(
            txn_type=fact.txn_type, sender=fact.sender, fee=fact.fee,
            first_valid=fact.first_valid, last_valid=fact.last_valid,
            note=fact.note or b"", group_b64=fact.group_b64 or "",
            receiver_address=fact.receiver or "", amount=fact.amount or 0,
            close_remainder_to=fact.close_remainder_to or "",
            asset_id=fact.asset_id or 0, asset_close_to=fact.asset_close_to or "",
            app_id=fact.app_id or 0, limitations=list(fact.limitations),
        )

    def _corr_msg(result) -> Any:
        # Core CorroborationResult carries (node, status, detail). The wire
        # exposes a boolean `matches`; witnessed_commitment_b64 is not surfaced
        # by the core corroborate() path, so it is left empty.
        return CorroborationResult(
            node=result.node, matches=(result.status == "agree"),
            witnessed_commitment_b64="",
        )

    def _corr_list(report) -> list:
        return [_corr_msg(r) for r in report.results] if report is not None else []

    class HandlerImpl(ProofpackBase):
        def __init__(self):
            self._auth = auth
            self._service = service

        # -- auth (design §9; closes the Phase-1 gap) ---------------------
        def _authenticate(self, metadata) -> str | None:
            """Verify the presented key. Returns the key (identity) or raises.

            Runs before the request body is read and before any dial. When
            ``auth`` is disabled, the presented key (if any) is still returned so
            it can scope the per-key semaphore, but no rejection occurs.
            """
            presented = _metadata_key(metadata)
            if self._auth is None:
                return presented
            try:
                self._auth.authenticate(presented)
            except AuthenticationError as exc:
                raise GRPCError(Status.UNAUTHENTICATED, str(exc)) from exc
            return presented

        # -- unary RPC bodies (called with an already-authenticated key) ---
        async def _do_capture(self, request, api_key: str):
            # S2 at the transport: reject an over-limit node list before dialing.
            cfg = self._service.config
            if request.corroborate and len(request.corroboration_nodes) > cfg.max_corroboration_nodes:
                raise GRPCError(
                    Status.RESOURCE_EXHAUSTED,
                    f"too many corroboration nodes (max {cfg.max_corroboration_nodes})",
                )
            result = await self._service.capture(
                api_key=api_key, chain=request.chain, txid=request.txid,
                round_number=request.round, source_node=request.source_node,
                corroboration_nodes=list(request.corroboration_nodes) if request.corroborate else [],
                wait_seconds=request.wait_seconds, tenant=request.tenant or "default",
            )
            return CaptureResponse(
                bundle_json=result["bundle_json"],
                report=_report_msg(result["report"]),
                corroboration_results=_corr_list(result.get("corroboration")),
            )

        async def _do_verify(self, request):
            result = self._service.verify(
                request.bundle_json, request.expected_genesis_hash_b64 or None)
            return VerifyResponse(
                bundle_json=result["bundle_json"],
                report=_report_msg(result["report"]))

        async def _do_extract(self, request):
            result = self._service.extract(request.bundle_json)
            # The core extract_payment returns the single top-level fact; the
            # wire is `repeated` (a bundle could carry more), so normalise to a
            # list without dropping the object.
            facts = result["facts"]
            facts = list(facts) if isinstance(facts, (list, tuple)) else [facts]
            return ExtractResponse(
                bundle_json=result["bundle_json"],
                facts=[_fact_msg(f) for f in facts],
                genesis_hash_b64=facts[0].genesis_hash_b64 if facts else "",
            )

        async def _do_corroborate(self, request, api_key: str):
            cfg = self._service.config
            if len(request.nodes) > cfg.max_corroboration_nodes:
                raise GRPCError(
                    Status.RESOURCE_EXHAUSTED,
                    f"too many corroboration nodes (max {cfg.max_corroboration_nodes})",
                )
            result = await self._service.corroborate_async(
                api_key=api_key, bundle_json=request.bundle_json,
                nodes=list(request.nodes))
            return CorroborateResponse(
                bundle_json=result["bundle_json"],
                results=[_corr_msg(r) for r in result["results"]],
                fully_corroborated=result["fully_corroborated"],
            )

        # -- grpclib stream adapters --------------------------------------
        # Every unary RPC below authenticates first (Health, which does not, has
        # its own handler). ``needs_key`` says whether the body consumes the
        # authenticated key as the per-key semaphore identity (capture /
        # corroborate dial and are metered; verify / extract do neither).
        async def _unary(self, stream, body, *, needs_key: bool):
            try:
                api_key = self._authenticate(stream.metadata)
                request = await stream.recv_message()
                response = await (body(request, api_key) if needs_key else body(request))
                await stream.send_message(response)
            except GRPCError:
                raise
            except Exception as exc:  # noqa: BLE001 - map to a gRPC status
                raise GRPCError(_status_for(exc, Status), str(exc)) from exc

        async def _rpc_capture(self, stream):
            await self._unary(stream, self._do_capture, needs_key=True)

        async def _rpc_verify(self, stream):
            await self._unary(stream, self._do_verify, needs_key=False)

        async def _rpc_extract(self, stream):
            await self._unary(stream, self._do_extract, needs_key=False)

        async def _rpc_corroborate(self, stream):
            await self._unary(stream, self._do_corroborate, needs_key=True)

        async def _rpc_health(self, stream):
            # Health is EXEMPT from auth (liveness probes carry no credential).
            await stream.recv_message()
            await stream.send_message(HealthResponse(ok=True, version="0.2.0"))

        async def _rpc_capture_stream(self, stream):
            # Server-streaming progress. Auth first (before any dial); then run
            # the capture and emit the stage enum. Errors surface as a FAILED
            # stage followed by a GRPCError status.
            try:
                api_key = self._authenticate(stream.metadata)
                request = await stream.recv_message()
                cfg = self._service.config
                if request.corroborate and len(request.corroboration_nodes) > cfg.max_corroboration_nodes:
                    raise GRPCError(
                        Status.RESOURCE_EXHAUSTED,
                        f"too many corroboration nodes (max {cfg.max_corroboration_nodes})",
                    )
                await stream.send_message(CaptureProgress(
                    stage=CaptureProgressStage.FETCHING_STATE_PROOF,
                    message="capture started"))
                response = await self._do_capture(request, api_key)
                await stream.send_message(CaptureProgress(
                    stage=CaptureProgressStage.VERIFYING,
                    message="bundle fetched and verified"))
                if response.corroboration_results:
                    await stream.send_message(CaptureProgress(
                        stage=CaptureProgressStage.CORROBORATING,
                        message="corroboration complete"))
                await stream.send_message(CaptureProgress(
                    stage=CaptureProgressStage.DONE, message="capture complete"))
            except GRPCError as exc:
                # Emit a FAILED progress frame, then propagate the status.
                try:
                    await stream.send_message(CaptureProgress(
                        stage=CaptureProgressStage.FAILED, message=exc.message or "failed"))
                except Exception:  # noqa: BLE001 - stream may already be closing
                    pass
                raise
            except Exception as exc:  # noqa: BLE001
                try:
                    await stream.send_message(CaptureProgress(
                        stage=CaptureProgressStage.FAILED, message=str(exc)))
                except Exception:  # noqa: BLE001
                    pass
                raise GRPCError(_status_for(exc, Status), str(exc)) from exc

        def __mapping__(self):
            return {
                "/avm_proofpack.v1.Proofpack/Capture": Handler(
                    self._rpc_capture, Cardinality.UNARY_UNARY,
                    CaptureRequest, CaptureResponse),
                "/avm_proofpack.v1.Proofpack/CaptureStream": Handler(
                    self._rpc_capture_stream, Cardinality.UNARY_STREAM,
                    CaptureRequest, CaptureProgress),
                "/avm_proofpack.v1.Proofpack/Verify": Handler(
                    self._rpc_verify, Cardinality.UNARY_UNARY,
                    VerifyRequest, VerifyResponse),
                "/avm_proofpack.v1.Proofpack/Extract": Handler(
                    self._rpc_extract, Cardinality.UNARY_UNARY,
                    ExtractRequest, ExtractResponse),
                "/avm_proofpack.v1.Proofpack/Corroborate": Handler(
                    self._rpc_corroborate, Cardinality.UNARY_UNARY,
                    CorroborateRequest, CorroborateResponse),
                "/avm_proofpack.v1.Proofpack/Health": Handler(
                    self._rpc_health, Cardinality.UNARY_UNARY,
                    HealthRequest, HealthResponse),
            }

    return HandlerImpl()


def build_server_ssl_context(cert_file: str, key_file: str):
    """Build a server-side TLS context (ALPN h2) from cert/key paths.

    Kept out of ``make_service`` so TLS is a deployment concern: the design
    supports in-process TLS AND termination at a reverse proxy. Only stdlib
    ``ssl`` is used here (no third-party dependency).
    """
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.set_alpn_protocols(["h2"])
    return context


def create_server(service, *, auth: ApiKeyAuth | None = None):
    """Return a grpclib ``Server`` wrapping ``service`` (not yet started)."""
    try:
        from grpclib.server import Server
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "gRPC support requires the service extra; install avm-proofpack[server] "
            f"(original error: {exc})"
        ) from exc
    return Server([make_service(service, auth=auth)])


async def serve(service, config, *, auth: ApiKeyAuth | None = None):
    """Start the gRPC server per ``config`` and serve until cancelled.

    TLS is default-on when both cert and key are configured (``config.tls_enabled``);
    otherwise the server binds plaintext (intended only behind a TLS-terminating
    proxy).
    """
    server = create_server(service, auth=auth)
    ssl_context = (
        build_server_ssl_context(config.tls_cert_file, config.tls_key_file)
        if config.tls_enabled else None
    )
    await server.start(config.host, config.grpc_port, ssl=ssl_context)
    try:
        await server.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

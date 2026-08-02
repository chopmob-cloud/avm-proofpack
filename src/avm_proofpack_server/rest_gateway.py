"""Thin REST gateway (design §4): two transports, ONE service implementation.

The gateway deserialises JSON into the SAME :class:`ProofpackService` the gRPC
layer calls, and serialises the result back. No verification, bounds, egress or
storage logic lives here - it reuses the service, so REST and gRPC are two faces
of one implementation. The wire mappers below produce exactly the field set the
gRPC ``_report_msg`` / ``_fact_msg`` / ``_corr_msg`` mappers produce, so a
Verify/Extract of the same bundle bytes yields the same report over either
transport (design's parity requirement).

Security posture carried at the REST layer (design §9):

* **S1 (SSRF).** Every outbound dial goes through the service, which routes it
  through the injected egress opener/validator. The gateway never dials a
  caller URL itself; an :class:`EgressBlocked` refusal surfaces as ``403``.
* **S2 (bounds).** ``corroboration_nodes`` is length-checked before any dial
  (``429`` on overflow); the service additionally clamps ``wait_seconds`` and
  enforces the request deadline and global/per-key concurrency. The request
  body is size-capped (``413`` on overflow) before it is parsed.
* **S4 (bundle is the sole anchor).** Every verify/extract/capture/corroborate
  response echoes ``bundle_json`` (base64). There is no verdict-only path; the
  gateway never synthesises a verdict of its own.
* **S5 (tenant scope).** The ``tenant`` field is threaded straight into the
  service, which enforces ownership on every store method.

Auth (design §9): every endpoint except ``GET /v1/health`` requires a valid API
key in ``x-api-key`` or ``authorization: Bearer <key>``, verified with the
constant-time :class:`ApiKeyAuth`. The check runs BEFORE the request body is
read and BEFORE any dial, so an unauthenticated or bad-key call is rejected with
``401`` without the server ever touching a caller-supplied node.

HTTP lib: the ASGI protocol on stdlib, served by **uvicorn** (the HTTP dep
pinned in the ``[server]`` extra: ``uvicorn==0.30.6``). The ASGI *app* is pure
stdlib (``json`` / ``base64`` / ``asyncio``), so building and driving it needs
no third-party import; only *serving* it does, and uvicorn is imported LAZILY in
:func:`serve_rest` so ``import avm_proofpack_server.rest_gateway`` still works
without the extra, and tests can drive the app in-process with no server at all.
Running under a single uvicorn event loop means the service's asyncio primitives
(the global / per-key semaphores) bind to ONE loop - unlike a per-request
``asyncio.run()``, which would rebind them to a fresh loop on every call and
raise on the second capture.
"""
from __future__ import annotations

import asyncio
import base64
import json

from .auth import ApiKeyAuth, AuthenticationError
from .egress import EgressBlocked
from .health import health
from .storage import BundleNotFound

# Core exception used only for status mapping; the core is stdlib-only and always
# importable, so this never pulls a third-party dependency.
from avm_proofpack.verify import VerificationError

# Request body cap: the service caps the decoded bundle at ~4 MiB; base64 plus
# the JSON envelope inflate that, so allow generous headroom then refuse (413).
_MAX_REQUEST_BYTES = 8 * 1024 * 1024


class _HttpError(Exception):
    """A gateway-level failure carrying its own HTTP status (routing/limits)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# -- wire mappers: core dataclasses -> JSON dicts -------------------------
# Explicit field-by-field mapping (mirrors grpc_server's _report_msg /
# _fact_msg / _corr_msg). Field names match the proto snake_case; bytes are
# base64-encoded for JSON. Dropping a field would violate S3 full-fidelity.

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _report_dict(report) -> dict:
    return {
        "txid": report.txid,
        "round": report.round,
        "genesis_id": report.genesis_id,
        "genesis_hash_b64": report.genesis_hash_b64,
        "block_hash_b64": report.block_hash_b64,
        "txn_commitment_b64": report.txn_commitment_b64,
        "light_header_variant": report.light_header_variant,
        "first_attested_round": report.first_attested_round,
        "last_attested_round": report.last_attested_round,
        "block_headers_commitment_b64": report.block_headers_commitment_b64,
        "voters_commitment_b64": report.voters_commitment_b64,
        "checks": list(report.checks),
        "trust_root": report.trust_root,
    }


def _fact_dict(fact) -> dict:
    # Mirrors grpc_server._fact_msg: core PaymentFacts.receiver -> receiver_address;
    # note (raw bytes) -> base64 string; omitted uints -> 0; omitted strings -> "".
    return {
        "txn_type": fact.txn_type,
        "sender": fact.sender,
        "fee": fact.fee,
        "first_valid": fact.first_valid,
        "last_valid": fact.last_valid,
        "note": _b64(fact.note) if fact.note else "",
        "group_b64": fact.group_b64 or "",
        "receiver_address": fact.receiver or "",
        "amount": fact.amount or 0,
        "close_remainder_to": fact.close_remainder_to or "",
        "asset_id": fact.asset_id or 0,
        "asset_close_to": fact.asset_close_to or "",
        "app_id": fact.app_id or 0,
        "limitations": list(fact.limitations),
    }


def _corr_dict(result) -> dict:
    # Mirrors grpc_server._corr_msg: core status ("agree"/...) -> boolean matches;
    # witnessed_commitment_b64 is not surfaced by the core path, so it is empty.
    return {
        "node": result.node,
        "matches": result.status == "agree",
        "witnessed_commitment_b64": "",
    }


def _status_and_message(exc: Exception) -> tuple[int, str]:
    """Map a service/core exception to an HTTP status (design §9 semantics).

    auth -> 401, egress/SSRF refusal -> 403, not-found -> 404, over-limit -> 429,
    timeout -> 504, bad input / unverifiable -> 400, else -> 500. Internal
    errors return a generic message (no internal detail leaks).
    """
    if isinstance(exc, _HttpError):
        return exc.status, exc.message
    if isinstance(exc, AuthenticationError):
        return 401, str(exc)
    if isinstance(exc, EgressBlocked):
        # SSRF refusal: a caller-supplied node was rejected by the egress guard.
        return 403, str(exc)
    if isinstance(exc, BundleNotFound):
        return 404, str(exc)
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return 504, "request timed out"
    if isinstance(exc, MemoryError):
        return 429, "resource exhausted"
    if isinstance(exc, VerificationError):
        # A bundle that decodes but fails verification is a bad argument.
        return 400, str(exc)
    if isinstance(exc, ValueError):
        message = str(exc)
        low = message.lower()
        if "too many" in low and "node" in low:
            return 429, message
        return 400, message
    return 500, "internal server error"


# -- ASGI response helpers ------------------------------------------------

async def _send_json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _read_body(receive) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > _MAX_REQUEST_BYTES:
            raise _HttpError(413, "request body too large")
        chunks.append(chunk)
        if not message.get("more_body"):
            break
    return b"".join(chunks)


def _decode_bundle(body: dict) -> bytes:
    raw = body.get("bundle_json")
    if not isinstance(raw, str):
        raise ValueError("bundle_json (base64 string) is required")
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("bundle_json is not valid base64") from exc


def _require_str_list(value, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return value


class RestGateway:
    """ASGI application mapping ``/v1/`` HTTP+JSON onto a :class:`ProofpackService`."""

    def __init__(self, service, auth: ApiKeyAuth | None = None):
        self._service = service
        self._auth = auth

    # -- auth (before body read, before any dial) -------------------------
    def _authenticate(self, scope) -> str | None:
        presented = self._key_from_headers(scope.get("headers") or [])
        if self._auth is None:
            # Proxy-mode: auth disabled, but still thread the presented key as the
            # per-key semaphore identity. Intended only behind a trusted proxy.
            return presented
        self._auth.authenticate(presented)  # raises AuthenticationError -> 401
        return presented

    @staticmethod
    def _key_from_headers(headers) -> str | None:
        table = {}
        for key, value in headers:
            table[key.decode("latin-1").lower()] = value.decode("latin-1")
        if "x-api-key" in table:
            return table["x-api-key"]
        authz = table.get("authorization")
        if authz:
            return authz[len("Bearer "):] if authz.lower().startswith("bearer ") else authz
        return None

    async def _read_json(self, receive) -> dict:
        raw = await _read_body(receive)
        try:
            body = json.loads(raw or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body is not valid JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        return body

    # -- endpoint bodies --------------------------------------------------
    def _validate_capture_body(self, body: dict) -> None:
        for field_name in ("chain", "txid", "source_node"):
            if not isinstance(body.get(field_name), str) or not body.get(field_name):
                raise ValueError(f"{field_name} is required and must be a non-empty string")
        if not isinstance(body.get("round"), int) or isinstance(body.get("round"), bool):
            raise ValueError("round must be an integer")
        _require_str_list(body.get("corroboration_nodes"), "corroboration_nodes")

    async def _capture(self, body: dict, api_key) -> dict:
        self._validate_capture_body(body)
        cfg = self._service.config
        corroborate = bool(body.get("corroborate"))
        requested = _require_str_list(body.get("corroboration_nodes"), "corroboration_nodes")
        # S2 at the transport: reject an over-limit node list before any dial.
        if corroborate and len(requested) > cfg.max_corroboration_nodes:
            raise ValueError(
                f"too many corroboration nodes (max {cfg.max_corroboration_nodes})")
        result = await self._service.capture(
            api_key=api_key, chain=body["chain"], txid=body["txid"],
            round_number=body["round"], source_node=body["source_node"],
            corroboration_nodes=requested if corroborate else [],
            wait_seconds=body.get("wait_seconds", 0),
            tenant=body.get("tenant", "default"),
        )
        return {
            "bundle_json": _b64(result["bundle_json"]),         # S4
            "report": _report_dict(result["report"]),           # non-authoritative hint
            "corroboration_results": (
                [_corr_dict(r) for r in result["corroboration"].results]
                if result.get("corroboration") is not None else []
            ),
        }

    def _verify(self, body: dict) -> dict:
        result = self._service.verify(
            _decode_bundle(body), body.get("expected_genesis_hash_b64") or None)
        return {
            "bundle_json": _b64(result["bundle_json"]),         # S4
            "report": _report_dict(result["report"]),           # non-authoritative hint
        }

    def _extract(self, body: dict) -> dict:
        result = self._service.extract(_decode_bundle(body))
        facts = result["facts"]
        facts = list(facts) if isinstance(facts, (list, tuple)) else [facts]
        return {
            "bundle_json": _b64(result["bundle_json"]),         # S4
            "facts": [_fact_dict(f) for f in facts],
            "genesis_hash_b64": facts[0].genesis_hash_b64 if facts else "",
        }

    async def _corroborate(self, body: dict, api_key) -> dict:
        cfg = self._service.config
        bundle_json = _decode_bundle(body)
        nodes = _require_str_list(body.get("nodes"), "nodes")
        if len(nodes) > cfg.max_corroboration_nodes:
            raise ValueError(
                f"too many corroboration nodes (max {cfg.max_corroboration_nodes})")
        result = await self._service.corroborate_async(
            api_key=api_key, bundle_json=bundle_json, nodes=nodes)
        return {
            "bundle_json": _b64(result["bundle_json"]),         # S4
            "results": [_corr_dict(r) for r in result["results"]],
            "fully_corroborated": result["fully_corroborated"], # non-authoritative hint
        }

    # -- CaptureStream equivalent: NDJSON progress (chunked) --------------
    async def _capture_stream(self, receive, send, api_key) -> None:
        """Stream capture progress as newline-delimited JSON (application/x-ndjson).

        This is the REST equivalent of the gRPC server-streaming ``CaptureStream``.
        Auth and the S2 node-cap are enforced BEFORE the 200 stream is opened, so
        those failures still surface as proper status codes (401 / 429). Once the
        stream is open the capture runs and coarse-grained progress frames are
        emitted (mirroring the gRPC stage enum); the core fetch itself is atomic,
        so stages bracket it rather than tracking each algod GET. The final frame
        carries the full capture result; a failure after the stream opens is
        reported as a ``FAILED`` frame with the mapped status embedded.
        """
        body = await self._read_json(receive)
        self._validate_capture_body(body)
        cfg = self._service.config
        requested = _require_str_list(body.get("corroboration_nodes"), "corroboration_nodes")
        if bool(body.get("corroborate")) and len(requested) > cfg.max_corroboration_nodes:
            raise ValueError(
                f"too many corroboration nodes (max {cfg.max_corroboration_nodes})")

        await send({
            "type": "http.response.start", "status": 200,
            "headers": [(b"content-type", b"application/x-ndjson")],
        })

        async def frame(obj: dict) -> None:
            await send({
                "type": "http.response.body",
                "body": (json.dumps(obj) + "\n").encode("utf-8"),
                "more_body": True,
            })

        try:
            await frame({"stage": "FETCHING_STATE_PROOF", "message": "capture started"})
            result = await self._capture(body, api_key)
            await frame({"stage": "VERIFYING", "message": "bundle fetched and verified"})
            if result.get("corroboration_results"):
                await frame({"stage": "CORROBORATING", "message": "corroboration complete"})
            await frame({"stage": "DONE", "message": "capture complete", "result": result})
        except Exception as exc:  # noqa: BLE001 - report inside the open stream
            status, message = _status_and_message(exc)
            await frame({"stage": "FAILED", "error": {"message": message, "status": status}})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    # -- routing ----------------------------------------------------------
    async def _route(self, scope, receive, send) -> None:
        method, path = scope["method"], scope["path"]

        # Health is the only unauthenticated endpoint (liveness probes need no key).
        if path == "/v1/health":
            if method != "GET":
                raise _HttpError(404, "not found")
            await _send_json(send, 200, health())
            return

        # Everything else authenticates FIRST, before any body read or dial.
        api_key = self._authenticate(scope)
        if method != "POST":
            raise _HttpError(404, "not found")

        if path == "/v1/capture/stream":
            await self._capture_stream(receive, send, api_key)
            return

        body = await self._read_json(receive)
        if path == "/v1/capture":
            result = await self._capture(body, api_key)
        elif path == "/v1/verify":
            result = self._verify(body)
        elif path == "/v1/extract":
            result = self._extract(body)
        elif path == "/v1/corroborate":
            result = await self._corroborate(body, api_key)
        else:
            raise _HttpError(404, "not found")
        await _send_json(send, 200, result)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if scope["type"] != "http":
            return
        try:
            await self._route(scope, receive, send)
        except Exception as exc:  # noqa: BLE001 - map to a JSON error envelope
            status, message = _status_and_message(exc)
            await _send_json(send, status, {"error": {"message": message, "status": status}})


def make_asgi_app(service, auth: ApiKeyAuth | None = None) -> RestGateway:
    """Build the ASGI application wrapping ``service`` (stdlib-only; no uvicorn)."""
    return RestGateway(service, auth=auth)


async def serve_rest(service, config, *, auth: ApiKeyAuth | None = None) -> None:
    """Serve the REST gateway under uvicorn per ``config`` (imported lazily).

    TLS is default-on when both cert and key are configured (``config.tls_enabled``);
    otherwise the server binds plaintext (intended only behind a TLS-terminating
    proxy). uvicorn is imported here, not at module load, so importing this module
    without the ``[server]`` extra never hard-fails.
    """
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "REST support requires the service extra; install avm-proofpack[server] "
            f"(original error: {exc})"
        ) from exc
    app = make_asgi_app(service, auth=auth)
    options = dict(host=config.host, port=config.rest_port, log_level="warning", lifespan="on")
    if config.tls_enabled:
        options.update(ssl_certfile=config.tls_cert_file, ssl_keyfile=config.tls_key_file)
    server = uvicorn.Server(uvicorn.Config(app, **options))
    await server.serve()

# avm-proofpack service (gRPC + REST)

The service is the **optional** network face of avm-proofpack. It exposes the
same `capture` / `verify` / `extract` / `corroborate` operations the library and
CLI provide, over gRPC and a thin REST/JSON gateway, so non-Python consumers can
use them. It is **additive**: the verification core (`src/avm_proofpack/`) stays
zero-dependency and behaviourally unchanged, and the service is a separate
distribution shape activated by an extra.

> **Read [SECURITY](#security) before you deploy or rely on this.** The service's
> verdict is a non-authoritative hint; the bundle is the sole trust anchor and a
> consumer must re-verify it offline.

- [What it is](#what-it-is)
- [Install](#install)
- [Running it](#running-it)
  - [docker-compose](#docker-compose)
  - [python -m avm_proofpack_server](#python--m-avm_proofpack_server)
- [Configuration (environment variables)](#configuration-environment-variables)
- [TLS](#tls)
- [API-key authentication](#api-key-authentication)
- [Endpoints and RPCs](#endpoints-and-rpcs)
- [Streaming capture (NDJSON)](#streaming-capture-ndjson)
- [curl examples](#curl-examples)
- [Persistence](#persistence)
- [Integration test against a real node](#integration-test-against-a-real-node)
- [SECURITY](#security)

## What it is

Two transports, **one** implementation. A single `ProofpackService` owns all the
logic; the gRPC server (`grpclib`) and the REST gateway (a stdlib ASGI app served
by `uvicorn`) are thin faces over it, so a `Verify`/`Extract` of the same bundle
bytes yields the same report over either transport.

The service adds, over the CLI:

- gRPC for any language (single `.proto` contract, `protos/avm_proofpack/v1/`);
- REST/JSON over `/v1/` for curl/HTTP consumers;
- server-side capture (with the SSRF egress guard around every outbound dial);
- an optional background scheduler that captures a round once its state-proof
  interval matures;
- API-key auth, TLS, and per-key/global concurrency bounds.

What it deliberately does **not** add: any way to trust the server's verdict
without the bundle bytes (see [SECURITY](#security)).

## Install

The core install stays zero-dependency:

```bash
pip install avm-proofpack
```

The service needs the `[server]` extra, which pulls the transport runtime
(`grpclib`, `betterproto`, `uvicorn`):

```bash
pip install "avm-proofpack[server]"
```

Importing `avm_proofpack_server` without the extra still works for the
stdlib-only pieces (config, egress, health); only *serving* a transport requires
the extra, and attempting it without the extra fails with a clear
`install avm-proofpack[server]` message rather than a bare `ImportError`.

## Running it

### docker-compose

The repo ships a `Dockerfile` (multi-stage, `python:3.12-slim`, non-root, installs
`.[server]`, runs `python -m avm_proofpack_server`) and a `docker-compose.yml`.

```bash
# 1. Provide an API key file (one key per line), git-ignored.
#    It is bind-mounted as a compose file-secret and read by the container's
#    NON-ROOT `proofpack` user, so it must be readable by that user — a mode
#    0600 file owned by another uid makes the container crash-loop with
#    PermissionError on /run/secrets/api_key. Make it group/other-readable
#    (0644) or use a real secrets backend that mounts it 0444.
printf 'change-me-to-a-long-random-key\n' > api-key && chmod 644 api-key

# 2. (optional) Provide TLS material for in-process TLS:
mkdir -p certs
#   put server.crt and server.key in ./certs  (or unset the two TLS env vars
#   in docker-compose.yml to run plaintext behind a TLS-terminating proxy)

# 3. Bring it up:
docker compose up --build
```

REST is published on `localhost:8080`, gRPC on `localhost:50051`.

The server holds **no** node URL of its own: the algod endpoint is supplied per
request (`source_node` on capture, `nodes` on corroborate) and dialled through
the egress guard. Because that guard refuses private/loopback addresses, point
captures at an **external, public** node; a compose-internal algod sidecar is
refused as shipped (see the comment block in `docker-compose.yml`).

### python -m avm_proofpack_server

```bash
pip install "avm-proofpack[server]"

export AVM_PROOFPACK_HOST=0.0.0.0
export AVM_PROOFPACK_API_KEY_FILE=/etc/proofpack/api-key
export AVM_PROOFPACK_TLS_CERT_FILE=/etc/proofpack/server.crt
export AVM_PROOFPACK_TLS_KEY_FILE=/etc/proofpack/server.key
# export AVM_PROOFPACK_TRANSPORTS=rest        # run one transport only, if desired

python -m avm_proofpack_server
```

Both transports launch by default; set `AVM_PROOFPACK_TRANSPORTS` to `grpc`,
`rest`, or `grpc,rest`.

## Configuration (environment variables)

These are the environment variables the running server actually reads
(`src/avm_proofpack_server/config.py::ServerConfig.from_env` and
`__main__.py`). Names and defaults are exact.

| Env var | Field | Default | Meaning |
|---|---|---|---|
| `AVM_PROOFPACK_HOST` | `host` | `127.0.0.1` | Bind address for both transports. Use `0.0.0.0` in a container. |
| `AVM_PROOFPACK_GRPC_PORT` | `grpc_port` | `50051` | gRPC listen port. |
| `AVM_PROOFPACK_REST_PORT` | `rest_port` | `8080` | REST listen port. |
| `AVM_PROOFPACK_TRANSPORTS` | *(entry point)* | `grpc,rest` | Comma-separated transports to launch: `grpc`, `rest`, or both. Read in `__main__.py`, not `config.py`. |
| `AVM_PROOFPACK_API_KEY_FILE` | `api_key_file` | *(unset)* | Path to a file of API keys, one per line. **Unset disables the API-key check** (proxy/mTLS-terminated mode — auth is expected upstream). |
| `AVM_PROOFPACK_TLS_CERT_FILE` | `tls_cert_file` | *(unset)* | PEM certificate path. In-process TLS is on only when **both** cert and key are set. |
| `AVM_PROOFPACK_TLS_KEY_FILE` | `tls_key_file` | *(unset)* | PEM private-key path. |
| `AVM_PROOFPACK_SCHEDULER_ENABLED` | `scheduler_enabled` | `0` (off) | Enable the background capture scheduler. Truthy values: `1`, `true`, `yes`, `on`. |
| `AVM_PROOFPACK_SCHEDULER_POLL_INTERVAL` | `scheduler_poll_interval` | `60.0` | Scheduler poll interval in seconds (float). |

### Config knobs that are NOT environment-driven

`ServerConfig` carries more bounds, but `from_env()` does **not** read them, so
they take their code defaults unless the service is constructed programmatically.
They are listed here for accuracy; do not expect the env vars to exist:

| Field | Default | Purpose |
|---|---|---|
| `max_corroboration_nodes` | `8` | Cap on `corroboration_nodes` / `nodes` (S2). |
| `max_wait_seconds` | `60` | `wait_seconds` is clamped to this (S2). |
| `request_timeout` | `30.0` | Per-request dial/verify deadline (seconds). |
| `max_bundle_bytes` | `4 MiB` | Decoded-bundle size cap. |
| `global_concurrency` | `16` | Global concurrent-capture semaphore (S2). |
| `per_key_concurrency` | `2` | Per-API-key concurrent-capture semaphore (S2). |
| `corroboration_concurrency` | `4` | Concurrent corroboration dials per request (S2). |
| `node_allowlist` | *(empty)* | Optional egress host allowlist. **No env var reads it in this build**; the egress guard's private-range denial always applies regardless. |
| `scheduler_concurrency` | `4` | Concurrent scheduled captures. |
| `scheduler_retry_backoff` | `60.0` | Retry backoff (seconds, monotonic). |
| `scheduler_job_deadline_seconds` | `86400` | Per-job deadline. |
| `scheduler_max_attempts` | `20` | Per-job attempt cap. |

## TLS

The design supports **both** in-process TLS and TLS termination at a reverse
proxy:

- **In-process TLS** — set `AVM_PROOFPACK_TLS_CERT_FILE` and
  `AVM_PROOFPACK_TLS_KEY_FILE` to PEM paths. When **both** are present, TLS is
  default-on: REST is served by uvicorn with those files, and gRPC binds an
  stdlib `ssl` context (ALPN `h2`). Mount the cert/key as read-only volumes; do
  not bake them into the image.
- **Reverse-proxy termination** — leave both unset. The server binds plaintext,
  which is intended **only** behind a proxy (nginx/traefik) that terminates TLS
  and, ideally, also handles auth (see below).

## API-key authentication

Every endpoint **except health** requires a valid API key. Keys come from the
file named by `AVM_PROOFPACK_API_KEY_FILE`, one key per line; the check is
constant-time. Present the key one of two ways:

- REST header `x-api-key: <key>`, or `authorization: Bearer <key>`.
- gRPC metadata `x-api-key: <key>`, or `authorization: Bearer <key>`.

The check runs **before** the request body is read and **before** any outbound
dial, so an unauthenticated or bad-key call is rejected (REST `401`, gRPC
`UNAUTHENTICATED`) without the server ever touching a caller-supplied node. The
authenticated key also scopes the per-key concurrency semaphore.

If `AVM_PROOFPACK_API_KEY_FILE` is **unset**, the API-key check is disabled — a
mode intended only for deployments that authenticate at a trusted reverse proxy
or via mTLS. Do not expose an unauthenticated server directly.

Health (`GET /v1/health`, gRPC `Health`) is deliberately exempt so liveness
probes need no credential.

## Endpoints and RPCs

| gRPC RPC (`avm_proofpack.v1.Proofpack`) | REST | Auth | Notes |
|---|---|---|---|
| `Capture` | `POST /v1/capture` | yes | Fetch + verify + (optional) corroborate + optional store. |
| `CaptureStream` | `POST /v1/capture/stream` | yes | Progress stream; REST emits NDJSON (see below). |
| `Verify` | `POST /v1/verify` | yes | Verify supplied bundle bytes. |
| `Extract` | `POST /v1/extract` | yes | Extract payment facts from a verified bundle. |
| `Corroborate` | `POST /v1/corroborate` | yes | Compare the bundle's trust root against independent nodes. |
| `Health` | `GET /v1/health` | **no** | Liveness; returns `{ok, version}`. |

REST error shapes: `401` auth, `403` egress/SSRF refusal, `404` not-found (also
the mask for a cross-tenant read — no existence leak), `413` body too large,
`429` over-limit (too many nodes) / resource exhausted, `400` bad input or a
bundle that decodes but fails verification, `504` timeout, `500` internal (a
generic message; no internal detail leaks). The gRPC layer maps the same
failures onto `UNAUTHENTICATED` / `PERMISSION_DENIED` / `NOT_FOUND` /
`RESOURCE_EXHAUSTED` / `INVALID_ARGUMENT` / `DEADLINE_EXCEEDED` / `INTERNAL`.

Every capture/verify/extract/corroborate response echoes `bundle_json`
(base64 in REST/JSON, bytes in gRPC). There is no verdict-only path — see
[SECURITY](#security), S4.

## Streaming capture (NDJSON)

`POST /v1/capture/stream` is the REST equivalent of the gRPC server-streaming
`CaptureStream`. Auth and the node-count cap are enforced **before** the `200`
stream opens (so those still surface as proper status codes). Once open, the
response is `application/x-ndjson`: one JSON object per line, mirroring the gRPC
stage enum:

```
{"stage": "FETCHING_STATE_PROOF", "message": "capture started"}
{"stage": "VERIFYING", "message": "bundle fetched and verified"}
{"stage": "CORROBORATING", "message": "corroboration complete"}   # only if corroboration ran
{"stage": "DONE", "message": "capture complete", "result": { ...full capture result... }}
```

The core fetch is atomic, so stages bracket it rather than tracking each algod
GET. A failure after the stream opens is reported as a final
`{"stage": "FAILED", "error": {"message": ..., "status": ...}}` frame.

## curl examples

Health (no auth):

```bash
curl -s http://localhost:8080/v1/health
# {"ok": true, "version": "0.2.0"}
```

Verify a bundle. The REST body carries the bundle bytes as base64 in
`bundle_json`:

```bash
# Base64-encode a local bundle file, then POST it to /v1/verify.
BUNDLE_B64=$(base64 -w0 evidence.json)   # macOS: base64 -i evidence.json

curl -s https://localhost:8080/v1/verify \
  -H "x-api-key: $PROOFPACK_API_KEY" \
  -H "content-type: application/json" \
  -d "{\"bundle_json\": \"$BUNDLE_B64\", \"expected_genesis_hash_b64\": \"wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=\"}"
```

The response echoes `bundle_json` (base64) plus a non-authoritative `report`.
**Re-verify `bundle_json` offline** and reach your own verdict — do not trust the
`report` field (see [SECURITY](#security)).

Capture (server dials the caller-supplied public node through the egress guard):

```bash
curl -s https://localhost:8080/v1/capture \
  -H "x-api-key: $PROOFPACK_API_KEY" \
  -H "content-type: application/json" \
  -d '{
        "chain": "algorand",
        "txid": "KOERHNGJPLUUQK4WJ4YPY5OC3BOINDH2J4E6HM2RYARSJ5R3FAYA",
        "round": 63604900,
        "source_node": "https://testnet-api.algonode.cloud",
        "corroborate": false
      }'
```

(For a plaintext deployment behind a proxy, use `http://` and drop `-k`; the `-k`
you may need above is only because a self-signed dev cert is not in your trust
store — never use `-k` against production.)

## Persistence

Captured bundles are content-addressed and **tenant-scoped**
(`src/avm_proofpack_server/storage.py`, `SqliteBundleStore`), and the optional
scheduler can persist jobs in a `SqliteJobStore`. The store enforces ownership on
every method and masks not-owned coordinates as not-found (S5).

Note the shipped `python -m avm_proofpack_server` entry point constructs the
service with the default in-memory backend (`store=None`) — it does not wire a
SQLite store from an env var. A deployment that wants durable storage constructs
`ProofpackService(config, store=SqliteBundleStore(path))` programmatically. The
`docker-compose.yml` provisions a writable `/data` volume for that case.

## Integration test against a real node

`tests/server/test_integration.py` captures a known confirmed transaction from a
**real** algod node through the service path (egress guard, bounds, and
verify-on-capture all active), then verifies the resulting bundle offline. It is
**skipped by default** — the normal suite makes no network call — and runs only
when these env vars are set:

```bash
AVM_PROOFPACK_TEST_NODE=https://testnet-api.algonode.cloud \
AVM_PROOFPACK_TEST_TXID=<52-char base32 txid> \
AVM_PROOFPACK_TEST_ROUND=<confirmed round> \
PYTHONPATH=src python -m pytest tests/server/test_integration.py -m network -q
```

Optional: `AVM_PROOFPACK_TEST_CHAIN` (store-key label, default `algorand`) and
`AVM_PROOFPACK_TEST_ALLOW_HTTP=1` (permit a plain-http node URL). The node must
be a **public** host: the S1 egress guard is active on this path, so a
loopback/RFC1918/link-local URL is refused, as intended.

## SECURITY

The service inherits the library's trust model and adds a service-layer threat
surface. The controls below are gates, not nice-to-haves (design §9, S1–S6).

**The bundle is the sole trust anchor (S4).** `Verify`/`Corroborate` responses
(`report`, `fully_corroborated`) are **non-authoritative hints** for display and
triage only. A consumer MUST re-verify `bundle_json` offline with `verify_bundle`
and reach its own verdict. Trusting the server's verdict re-introduces the
trusted third party this format exists to remove — and a *signed* server verdict
would be worse, lending cryptographic confidence to an unverified answer. There
is deliberately no mode that returns a verdict without the bytes; every response
echoes `bundle_json`.

**SSRF egress guard (S1).** As a service, `source_node` / `corroboration_nodes`
are attacker-controlled and the server dials them. Every outbound dial goes
through `egress.py`, which: resolves the host and refuses any
private/loopback/link-local/ULA/unspecified/multicast/reserved address (IPv4 and
IPv6, including IPv4-mapped forms like `::ffff:169.254.169.254`); **pins** the
resolved IP for the connection to defeat DNS rebinding; and **refuses HTTP
redirects** (a permitted node that 302s to cloud metadata is blocked). An
optional host allowlist can further restrict targets. HTTPS is required unless
plain HTTP is explicitly opted in. A refusal surfaces as REST `403` / gRPC
`PERMISSION_DENIED`.

**Resource bounds / DoS (S2).** `corroboration_nodes` is capped
(`max_corroboration_nodes`, default 8) and rejected before any dial;
`wait_seconds` is clamped; captures are bounded by global and per-key
concurrency semaphores; corroboration fans out under a concurrency cap, not an
unbounded loop; each request has a deadline and a decoded-bundle size cap; the
REST body is size-capped (`413`) before parsing.

**Tenant isolation (S5).** The store is tenant-scoped and content-addressed.
Ownership is enforced on every method; a caller guessing another tenant's
`(chain, round, txid)` gets **not-found**, never `403`, so existence is not
leaked. `meta.source_node` (which may record a private algod URL) is kept
per-tenant so it can never be served across the tenant boundary through a shared
content hash.

**Stake-attested tier is NOT offered by the service
(S6).** The service's trust root remains the bundle's own state-proof
*message*: its `Verify` passes no trust anchor, so every service verdict is
`trust_root == "unattested"`, and `--corroborate` / `Corroborate` only reduces
that to "these independent nodes do not all collude". The stake-attested tier
(`src/avm_proofpack/consensus/`, reached by the library when a caller supplies a
`TrustedVoters` anchor) is deliberately NOT exposed by the service: the service
has no trusted anchor to offer on a caller's behalf, so it never returns a
"fully attested" verdict. A consumer that wants attestation must re-verify the
returned `bundle_json` offline with its own trusted anchor.
Release tooling MUST build the image/wheel from a clean checkout or sdist so the
experimental modules are never globbed into a distribution.

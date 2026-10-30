# Design: gRPC + REST service framework for avm-proofpack

**Date:** 2026-08-01 (security review revision)
**Status:** Draft design, not yet implemented. Section 9 (Security requirements) is a MANDATORY gate before implementation begins.
**Repo:** https://github.com/chopmob-cloud/avm-proofpack

---

## 1. Surface enumeration

### Source modules (12 files)

```
src/avm_proofpack/
  __init__.py
  avm.py          # AVM reconstruction: block_hash, stib_hash_sha256, transaction_from_stib, txn_hashes
  bundle.py       # Bundle serialisation/deserialisation
  capture.py      # Orchestrator: fetch → verify → bundle
  chains.py       # Chain registry (genesis hashes, CAIP-2 IDs)
  cli.py          # Typer CLI entrypoints
  client.py       # ~60-line stdlib urllib wrapper (5 REST GETs to algod)
  extract.py      # Payment-fact extraction from verified bundles
  hashes.py       # SHA-256/512-256 wrappers
  merkle.py       # Merkle proof verification (vector commitment)
  mpack.py        # msgpack decode via stdlib only
  verify.py       # End-to-end bundle verification
```

### Test files (9 files)

```
tests/
  test_bundles.py
  test_chains.py
  test_cli.py
  test_extract.py
  test_fuzz.py          # Fuzz harness for verify path
  test_merkle.py
  test_mpack.py
  test_security.py      # Security regression suite
  test_vectors.py       # Conformance-vector runner
  # experimental (untracked) trust-root tier, not in the published package:
  test_falcon.py        # Falcon-1024 verifier + negative KATs
  test_stateproof.py    # state-proof message reconstruction
```

### Fixtures & vectors

```
tests/fixtures/         # Real testnet data
vectors/                # Conformance vectors (README.md)
```

### The only network code today

`client.py` makes exactly 5 REST GETs to an algod node during capture:

| Endpoint | Purpose |
|---|---|
| `GET /v2/stateproofs/{round}` | State proof message (attestation root) |
| `GET /v2/blocks/{round}/transactions/{txid}/proof` | Tx Merkle proof + stib hash |
| `GET /v2/blocks/{round}/lightheader/proof` | Light header proof |
| `GET /v2/blocks/{round}?format=msgpack` | Block header + payset (canonical msgpack) |
| `GET /v2/blocks/{round+1}?format=msgpack` | Next block (prev-hash linkage gate) |

Corroboration re-calls `GET /v2/stateproofs/{round}` against independent nodes.

### Sibling/tier variants

None. Single-tier Apache-2.0 project. The "next edition" is additive — adding service interfaces without breaking the existing library's zero-dependency stream.

---

## 2. Delta map: what we gain

| Capability | Today | After |
|---|---|---|
| Non-Python consumers | Must shell-out to CLI | gRPC (any language) or REST (curl/http) |
| Batch capture (N txns across M rounds) | One at a time, sequential | Streaming gRPC, async REST |
| Persistent bundle store | Filesystem only | Pluggable backends (S3, SQLite, Postgres) |
| Scheduled capture ("capture round X when state proof matures") | Manual polling with `--wait` | Server-side scheduler |
| Corroboration-as-a-service | Client-side only | Server can corroborate on capture |
| Authenticated, metered access | None | API keys, rate limiting |
| Observability | None | Metrics, structured logging, health checks |

---

## 3. Axis-by-axis assessment

### Supply-chain / provenance

- **Today:** Zero runtime deps. `pip install avm-proofpack` pulls nothing but CPython stdlib. SBOM is trivial.
- **gRPC option:** `grpcio` is a ~20 MB C-extension wheel. `grpcio-tools` for codegen. Alternative: `grpclib` (pure-Python, async, ~200 KB) — lighter but less battle-tested.
- **REST option:** FastAPI pulls `starlette`, `pydantic`, `uvicorn` — ~15 transitive deps. Flask is fewer deps but sync-only. aiohttp is one C-extension.
- **Mitigation:** Keep the *verification path* zero-dependency by making the service a separate distribution (`avm-proofpack-server`) or an optional extra (`pip install avm-proofpack[server]`). The library core (`src/avm_proofpack/`) stays stdlib-only, entirely unchanged.

> **Design rule: do not let the service interface poison the verification supply chain.**

### Cryptography / PQC / key lifecycle

- **Today:** `hashlib` only (SHA-256, SHA-512/256). No keys. No signatures.
- **Service needs:** TLS (mandatory — no plaintext HTTP/gRPC for bundle capture). API key/token management. Potential mTLS for gRPC to algod.
- **Design:** TLS via `uvicorn` (REST) or `grpc.ssl_server_credentials()` (gRPC). API keys as `X-API-Key` header or gRPC `CallCredentials`. No custom crypto — delegate entirely to the transport. Key rotation via environment/config reload.
- **State-proof tier (future):** The planned Falcon signature verification (SPEC.md §6, `state_proof_msgpack_b64` carried but not consumed today) makes the service's trust-root story important. A server that verifies Falcon signatures itself can offer "fully attested" bundles, removing the corroboration requirement for clients.

### Identity / standards

- **Today:** CAIP-2 chain identifiers (`algorand:wGHE2Pwdvd7...`). Chain registry in `chains.py`.
- **Service identity:**
  - OpenAPI 3.1 spec for REST
  - Protobuf service definitions (with `buf` linting) for gRPC
- **Common semantics across both surfaces:**
  - `Capture(txid, round, chain) → bundle` (or async `CaptureStatus`)
  - `Verify(bundle_bytes) → VerificationReport`
  - `Extract(bundle_bytes) → PaymentFacts`
  - `Health() → status`
- **Interoperability:** A well-defined proto is the strongest interop story — Go, JS, Rust consumers generate clients trivially. REST with OpenAPI is second-strongest but more prone to drift.

### Time / freshness

- **Today:** `captured_at` ISO-8601 in bundle metadata. State proof interval bounds. `--wait` polling.
- **Service adds:** Server-side scheduling ("capture round 63605200 at maturity"), TTL on cached bundles, request deadlines. The server's clock becomes a trust input — must be NTP-synced, validated on startup.
- **Design:** `CaptureRequest` carries an optional `capture_after` timestamp (server waits until state proof interval closes). Responses carry a server-generated `served_at`. Cron-style scheduled capture is a separate concern (background worker).

### Persistence / migration / compatibility

- **Today:** JSON files. Format v1 (`SPEC.md`). Stable bundle schema.
- **Service needs:** Bundle storage backend. Options:
  - **SQLite** — simplest, matches project ethos, zero config
  - **S3-compatible** — for production, keyed by `{genesis_hash_hex}/{round}/{txid}.json`
  - **Postgres** — if rich querying is needed
- **Design:** Pluggable `BundleStore` abstract class with two initial implementations: `SqliteBundleStore` and `S3BundleStore`.
  - Content-addressable: the storage key is `sha256(bundle_bytes)` so bundles are deduplicated and immutable.
  - A separate index table maps `(chain, round, txid) → content_hash`.
- **Compatibility:** Bundle format v1 is frozen. When v2 arrives, the store carries both, and the service gates on `Accept: application/avm-proofpack+json; version=1`.

### Tests / conformance / parity

- **Today:** Conformance vectors (`vectors/`), fuzz tests (`test_fuzz.py`), security regression tests (`test_security.py`), network-marked fixture tests.
- **Service adds:**
  - **Integration tests** against a real algod (testnet) via docker-compose
  - **gRPC/REST parity tests** — the same capture/verify through both interfaces must produce byte-identical bundles and reports
  - **Load tests** — concurrent captures, large bundles, slow nodes
  - **The existing conformance vectors must pass through the service path** — `Capture` through gRPC, then `Verify` through REST, must produce the identical report as direct library calls

### Tier parity

No variants exist. N/A.

---

## 4. Architecture decision: gRPC-first, with a REST gateway

**Recommendation: gRPC-first, with a thin REST gateway.**

1. **gRPC gives the strongest interop.** A single `.proto` file is a machine-readable, type-safe contract. Go, Rust, JS, C#, Java consumers get native clients. No OpenAPI drift.

2. **REST is universal but loose.** Every language can do HTTP/JSON, but field names, error shapes, and auth schemes diverge across implementations. An OpenAPI spec helps but is not self-enforcing.

3. **gRPC-gateway pattern:** Define the service in protobuf. Generate:
   - gRPC server (Python)
   - gRPC clients (all languages)
   - REST gateway via a hand-written `/v1/` HTTP mapping that proxies to the same handler layer

4. **Pure-Python gRPC stack:** `grpclib` for the server (pure Python, async) with `protoc`-generated stubs that work with either `grpcio` or `grpclib` clients.

The REST gateway is thin — it deserialises JSON into the same request objects the gRPC handler uses, calls the same service layer, and serialises back. **Two transports, one service implementation.**

---

## 5. Service definition (protobuf sketch)

```protobuf
syntax = "proto3";

package avm_proofpack.v1;

service Proofpack {
  rpc Capture(CaptureRequest) returns (CaptureResponse);
  rpc CaptureStream(CaptureRequest) returns (stream CaptureProgress);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Extract(ExtractRequest) returns (ExtractResponse);
  rpc Corroborate(CorroborateRequest) returns (CorroborateResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

message CaptureRequest {
  string chain = 1;
  string txid = 2;
  uint64 round = 3;
  string source_node = 4;
  bool corroborate = 5;
  repeated string corroboration_nodes = 6;
  uint32 wait_seconds = 7;
}

message CaptureResponse {
  bytes bundle_json = 1;
  VerificationReport report = 2;
  repeated CorroborationResult corroboration_results = 3;
}

message CaptureProgress {
  enum Stage {
    FETCHING_STATE_PROOF = 0;
    FETCHING_TXN_PROOF = 1;
    FETCHING_BLOCK = 2;
    FETCHING_NEXT_BLOCK = 3;
    VERIFYING = 4;
    CORROBORATING = 5;
    DONE = 6;
    FAILED = 7;
  }
  Stage stage = 1;
  string message = 2;
}

message VerifyRequest {
  bytes bundle_json = 1;
  string expected_genesis_hash_b64 = 2;
  bool accept_unattested = 3;
}

message VerifyResponse {
  VerificationReport report = 1;
}

message VerificationReport {
  string txid = 1;
  uint64 round = 2;
  string genesis_id = 3;
  string genesis_hash_b64 = 4;
  string block_hash_b64 = 5;
  string txn_commitment_b64 = 6;
  string light_header_variant = 7;
  uint64 first_attested_round = 8;
  uint64 last_attested_round = 9;
  string block_headers_commitment_b64 = 10;
  string voters_commitment_b64 = 11;
  repeated string checks = 12;
  string trust_root = 13;
}

message ExtractRequest {
  bytes bundle_json = 1;
}

message ExtractResponse {
  repeated PaymentFact facts = 1;
  string genesis_hash_b64 = 2;
}

message PaymentFact {
  // Full parity with avm_proofpack.extract.PaymentFacts. The close-out,
  // clawback and appl caveats below are load-bearing: dropping them lets a
  // consumer over-credit a payment (see Section 9, S3). All fields the
  // library surfaces MUST cross the wire.
  string txn_type = 1;                 // pay | axfer | appl | other
  string sender = 2;
  uint64 fee = 3;
  uint64 first_valid = 4;
  uint64 last_valid = 5;
  bytes  note = 6;
  string group_b64 = 7;
  string receiver_address = 8;         // omitted-zero surfaces as the zero address
  uint64 amount = 9;
  string close_remainder_to = 10;      // set => sender's ENTIRE balance also moved (> amount)
  uint64 asset_id = 11;
  string asset_close_to = 12;          // set => sender's ENTIRE asset balance also moved
  uint64 app_id = 13;
  repeated string limitations = 14;    // e.g. appl inner-txn caveat, rekey, clawback
}

message CorroborateRequest {
  bytes bundle_json = 1;
  repeated string nodes = 2;
}

message CorroborateResponse {
  repeated CorroborationResult results = 1;
  bool fully_corroborated = 2;
}

message CorroborationResult {
  string node = 1;
  bool matches = 2;
  bytes witnessed_commitment_b64 = 3;
}

message HealthRequest {}
message HealthResponse {
  bool ok = 1;
  string version = 2;
}
```

---

## 6. Package structure (additive, not breaking)

```
src/
  avm_proofpack/              # UNCHANGED — zero-dependency core
    __init__.py
    avm.py
    bundle.py
    capture.py
    chains.py
    cli.py
    client.py
    extract.py
    hashes.py
    merkle.py
    mpack.py
    verify.py
  avm_proofpack_server/       # NEW — service layer
    __init__.py
    service.py                # ProofpackService: calls core, handles orchestration
    grpc_server.py            # gRPC server startup (grpclib)
    rest_gateway.py           # Thin HTTP/JSON mapping to same service layer
    storage.py                # BundleStore ABC + SqliteBundleStore + S3BundleStore
    scheduler.py              # Background capture-scheduler worker
    config.py                 # Env/file config, TLS certs, API keys
    health.py                 # Health-check logic

protos/
  avm_proofpack/
    v1/
      proofpack.proto

tests/
  test_grpc.py                # gRPC parity tests
  test_rest.py                # REST parity tests
  test_storage.py             # BundleStore tests
  test_service.py             # Service-layer unit tests
```

---

## 7. Build order

| Phase | What | Effort | Produces |
|---|---|---|---|
| **0. Proto spec** | Finalise `.proto`, run through `buf lint`, publish | 1 day | `protos/avm_proofpack/v1/proofpack.proto` |
| **1. Core service layer** | `ProofpackService` wrapping existing `capture`, `verify`, `extract` — pure logic, testable in-process | 2 days | `src/avm_proofpack_server/service.py` |
| **2. Storage** | `BundleStore` ABC + `SqliteBundleStore` implementation | 1 day | `src/avm_proofpack_server/storage.py` |
| **3. gRPC server** | `grpclib`-based server, generated stubs, TLS, API key auth | 2 days | `src/avm_proofpack_server/grpc_server.py` |
| **4. REST gateway** | Thin `/v1/` HTTP mapping to same `ProofpackService` | 1 day | `src/avm_proofpack_server/rest_gateway.py` |
| **5. Scheduler** | Background worker: poll for state proof maturity, capture, store | 1 day | `src/avm_proofpack_server/scheduler.py` |
| **6. Parity tests** | Same capture/verify through gRPC and REST → byte-identical | 2 days | `tests/test_grpc.py`, `tests/test_rest.py` |
| **7. Docker + docs** | Dockerfile, docker-compose (algod + proofpack-server), user docs | 1 day | `Dockerfile`, `docker-compose.yml`, `docs/service.md` |

**Total:** ~11 days of focused work to a production-ready first release.

---

## 8. Risks / open decisions

1. **`grpclib` vs `grpcio`.** `grpclib` is pure Python (simpler SBOM) but less widely deployed. `grpcio` is canonical but is a C extension. Start with `grpclib`; fall back to `grpcio` if performance or edge-case gaps appear.

2. **`betterproto` vs `protobuf`.** `betterproto` generates Pythonic dataclass-style messages; works well with `grpclib`. Google's `protobuf` is standard but heavier. `betterproto` aligns with the project's minimalism.

3. **Streaming capture is the right gRPC pattern.** A single capture can take 10–60s waiting for state proof maturity. Server-side streaming (`CaptureStream`) gives progress updates and keeps the connection alive. REST equivalent is chunked transfer — workable, less elegant.

4. **TLS termination:** Should the server terminate TLS itself, or should the design assume a reverse proxy (nginx/traefik)? The design should support both, but the default docker-compose should terminate at the server for simplicity.

5. **API key management:** File-based (simple) vs database-backed (scalable) vs pluggable (OAuth2 client credentials). Start with a static key file; add OAuth2 as an extension point.

6. **`avm-proofpack` repo vs separate repo for the server.** Colocating in the same repo is simpler, avoids version skew, and lets the server be an optional extra. A separate repo gives cleaner CI and release cycles. Recommend: same repo, different distribution.

---

## 9. Security requirements (MANDATORY before implementation)

Threat-model shift: today the caller supplies `node_url` and trusts their own
node, so `node_url` is *inside* the trust boundary. As a service, an untrusted
remote caller supplies `source_node` / `corroboration_nodes` and **the server
dials them** — those inputs become attacker-controlled. Every requirement below
follows from that flip and is a gate, not a nice-to-have. (Findings from the
2026-08-01 security validation; the shipped library core was found sound —
these apply to the *service layer* being added.)

### S1 — SSRF egress control (HIGH)
The server MUST NOT dial arbitrary caller-supplied URLs. `client.py`'s only
current guard is an `http(s)` scheme check, which still permits
`http://169.254.169.254/…` (cloud metadata), `http://127.0.0.1:<port>`,
RFC1918/link-local/ULA, and DNS-rebinding hosts. Error excerpts and 16 MiB
bodies are reflected back to the caller, so this is a *read* SSRF, not blind.
Required:
- An **allowlist of permitted algod endpoints** (config-driven), OR
  resolve-and-pin the hostname and **reject RFC1918 / loopback / link-local /
  ULA / unspecified** resolved IPs.
- **Disable HTTP redirect following** (`urllib` follows 3xx by default and does
  NOT re-validate the redirect target — a host allowlist alone is bypassable by
  a permitted node that 302s to `169.254.169.254`). Use a custom opener with a
  no-op redirect handler, or re-validate every hop.
- Pin DNS (resolve once, connect to that IP) to defeat rebinding.

### S2 — Resource bounds / DoS (HIGH→MED)
One request must not translate into unbounded server egress or held workers:
- Cap `corroboration_nodes` length (e.g. ≤ 8) and **clamp `wait_seconds`** to a
  small maximum; `uint32` today allows ~136 years.
- Bound **concurrent captures** globally and per API key; corroboration fetches
  must run with a concurrency limit, not an unbounded sequential loop.
- Keep the existing 16 MiB response cap and per-request timeout; add per-key
  rate limiting and a request deadline on `CaptureStream`.

### S3 — Full-fidelity `PaymentFact` (MED)
The wire `PaymentFact` MUST carry every field `extract.PaymentFacts` surfaces —
`close_remainder_to`, `asset_close_to`, `app_id`, and `limitations` — not just
`amount`/`receiver`. Dropping them lets a consumer credit `amount` while missing
that the sender's entire balance was swept via a close-out, or that an `appl`
"payment" is not proven at all by a v1 bundle. (Proto updated in §5.)

### S4 — The bundle is the sole trust anchor (MED)
`Verify`/`Corroborate` responses (`report`, `fully_corroborated`) are
**non-authoritative hints**. The service contract MUST state that a consumer
re-verifies `bundle_json` offline with `verify_bundle`; trusting the server's
verdict re-introduces the trusted third party this format exists to remove. A
*signed* server verdict would be worse — it lends cryptographic confidence to an
unverified answer. Never expose a mode that returns a verdict without the bytes.

### S5 — Tenant-scoped store, existence-masked (MED)
The content-addressable store (`sha256(bundle_bytes)`, index
`(chain, round, txid) → hash`) has no tenant scoping. Required:
- Scope the index by tenant; a caller MUST NOT read another tenant's bundle by
  guessing `(chain, round, txid)` (low-entropy, enumerable).
- Mask not-owned as **not-found**, never `403` (don't leak existence — that
  reveals which transactions a tenant is watching).
- Treat `meta.source_node` as sensitive: it records the capturing node URL
  verbatim (possibly a tenant's private algod), so it must not leak across
  tenants via a shared content-addressed object. Enforce the ownership check on
  **every** store method, not just `Get`.

### S6 — Consensus tier ships in the wheel; the server still does not use it

**Superseded by 0.4.1, on an explicit decision to promote.** The Falcon/state-proof code moved from
`src/avm_proofpack/_experimental/` to `src/avm_proofpack/consensus/` (commit `c6059f6`) and **ships in the
published wheel**; `verify_bundle` reaches `trust_root="stake_attested"` when the caller supplies a
`TrustedVoters` anchor (0.4.1, commit `c97dcc3`). This section previously stated the opposite, and was false
from the moment of promotion.

**Requirements that still hold** (all now implemented in `consensus/`, and exercised by the anchor path):

- a reveal-signature counter is a *count*, not a verdict (`count_reveal_signatures`,
  `is_trust_root=False`) — do not let `verified == total` gate a trust decision;
- attestation requires key-commitment membership, signed-weight threshold, coin-position selection and
  voters-commitment anchoring, and it is only as good as the anchor supplied.

**The service boundary stands, for a different reason.** `avm_proofpack_server` does not import
`consensus/`: the service is stateless and holds no trusted anchor, so anything it could say about
attestation would be unanchored. Attestation belongs to the caller.

**Former build-hygiene caveat — no longer applicable.** Wheels built from a dirty tree could previously
glob-include `_`-prefixed modules by accident. The modules are now published deliberately, and the
zero-dependency promise is pinned by an AST guard over `consensus/falcon.py` in `tests/test_falcon.py`.
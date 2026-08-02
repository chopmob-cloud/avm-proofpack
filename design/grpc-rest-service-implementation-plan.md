# Implementation plan: gRPC + REST service (Phase B)

**Status:** Planned, not started.
**Companion:** [grpc-rest-service-design.md](grpc-rest-service-design.md) — the
architecture and the mandatory security requirements (§9, S1–S6). This document
is the build plan: decisions locked, sequence, and definition of done.

The guiding constraint is unchanged: **the service is additive and must not
compromise the zero-dependency, offline-verifiable core.** The core
(`src/avm_proofpack/`) stays stdlib-only and behaviourally unchanged; the
service is a separate package activated by an extra.

---

## 1. Decisions locked

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | gRPC stack | **grpclib** (pure-Python, async) | SBOM minimalism; grpcio kept as a documented fallback if perf/edge gaps appear |
| 2 | Generated stubs | **betterproto** (pinned exact) | Pythonic, aligns with grpclib; it is beta, so pin an exact version |
| 3 | Distribution | Same repo, **`avm-proofpack[server]`** extra | Server code ships in the wheel; the extra pulls the runtime deps. Core install stays zero-dependency |
| 4 | TLS | In-process **and** reverse-proxy supported; default compose terminates at the server | Covers both deployment shapes without forcing a proxy |
| 5 | Auth | Static API-key file first (behind egress control); OAuth2 as an extension point | Simplest safe start; auth without egress control is the more dangerous gap |
| 6 | Home | Same repo, separate top-level package `avm_proofpack_server` | Avoids version skew; clean separation from the core |

---

## 2. Package layout

```
src/avm_proofpack_server/
  __init__.py
  egress.py        # S1 SSRF guard — the security keystone, built FIRST
  config.py        # caps, TLS certs, API keys, node allowlist
  auth.py          # API-key verification
  service.py       # ProofpackService: wraps core capture/verify/extract
  storage.py       # BundleStore ABC + SqliteBundleStore (+ S3BundleStore later)
  grpc_server.py   # grpclib server startup
  rest_gateway.py  # thin HTTP/JSON mapping onto the same service layer
  scheduler.py     # background capture-at-maturity worker
  health.py
protos/
  avm_proofpack/v1/proofpack.proto
tests/server/
  test_egress.py test_service.py test_storage.py
  test_grpc.py test_rest.py test_parity.py test_security.py test_integration.py
```

### One core change (small, non-breaking)
Parameterize `avm_proofpack.client.NodeClient` to accept an optional injected
opener/validator, so the server enforces egress policy **without forking**
`client.py`. Default behaviour (stdlib urllib, current semantics) is preserved
for library/CLI users. This is the only edit to the core.

### Packaging
```toml
[project.optional-dependencies]
server = ["grpclib==<pin>", "betterproto==<pin>", "<rest/http server pin>"]
```
`avm_proofpack_server` is included in `packages.find` (unlike `_experimental`,
which stays excluded). Without the extra installed, importing the server package
fails with a clear "install avm-proofpack[server]" message.

---

## 3. Build sequence (security-first; ~11–12 days)

Ordered so the security-critical primitives exist before anything can dial a
network. Each phase lists its definition of done (DoD).

### Phase 0 — Proto + egress guard (2 d)
- Finalize `proofpack.proto`: full-fidelity `PaymentFact` (S3), fix
  `CorroborationResult.witnessed_commitment_b64` type (`bytes` vs `_b64`
  string — pick one), `buf lint`, vendor generated stubs.
- Build `egress.py`: resolve host → reject RFC1918 / loopback / link-local /
  ULA / unspecified; **pin the resolved IP** for the connection; custom opener
  with **no redirect handler**; optional config allowlist.
- **DoD:** SSRF unit tests (169.254.169.254, 127.0.0.1:*, 10/172.16/192.168,
  a host that 302s to metadata, DNS-rebind) all refused; proto lints clean.

### Phase 1 — ProofpackService + config + auth (2 d)
- `ProofpackService` wraps `capture`/`verify`/`extract`, all outbound dials
  routed through `egress.py`.
- S2 bounds: `corroboration_nodes` ≤ 8, `wait_seconds` clamp, global + per-key
  `asyncio.Semaphore`, request deadlines.
- `auth.py`: API-key file, constant-time compare.
- **DoD:** service-layer unit tests pass in-process (no transport yet); bounds
  and auth enforced; egress guard cannot be bypassed via the service.

### Phase 2 — Storage (1 d)
- `BundleStore` ABC + `SqliteBundleStore`. Content-addressed by
  `sha256(bundle_bytes)`; index `(tenant, chain, round, txid) → content_hash`.
- S5: ownership check on **every** method; not-owned → **not-found** (never
  403); `meta.source_node` treated as sensitive.
- **DoD:** storage unit tests incl. a cross-tenant read attempt that returns
  not-found; no existence leak.

### Phase 3 — gRPC server (2 d)
- grpclib server, generated stubs, TLS (`grpc.ssl_server_credentials`
  equivalent), API-key `CallCredentials`, bounds wired, `CaptureStream`
  server-streaming progress.
- **DoD:** all 6 RPCs reachable over TLS with a valid key; unauthenticated and
  over-limit calls rejected.

### Phase 4 — REST gateway (1 d)
- Thin `/v1/` HTTP/JSON deserialising into the **same** request objects the
  gRPC handler uses; same service layer, same egress/bounds/auth.
- **DoD:** every RPC has a REST equivalent; error shapes consistent.

### Phase 5 — Scheduler (1 d)
- Background worker: poll `/v2/stateproofs/{round}` for maturity → capture →
  store. NTP-sanity check on startup (server clock is a trust input).
- **DoD:** a scheduled capture completes and is retrievable from the store.

### Phase 6 — Tests (2 d)
- **Parity:** Verify/Extract of the *same* bundle bytes via gRPC ≡ REST
  (identical reports). Capture parity compares everything **except** `meta`
  (captured_at/source_node vary) — the design's "byte-identical capture" claim
  is only achievable with a frozen clock/source, so test the achievable
  invariant.
- **Security regression:** SSRF refusal, DoS bounds, tenant IDOR, and
  "verdict-without-bytes is impossible" (S4).
- **Integration:** capture+verify against a real testnet algod via
  docker-compose.
- **DoD:** parity + security + integration suites green.

### Phase 7 — Ship (1 d)
- Dockerfile, docker-compose (algod + proofpack-server), user docs, the
  `[server]` extra, release notes.
- **DoD:** `docker compose up` yields a working end-to-end capture→verify.

---

## 4. Security controls as code (S1–S6)

- **S1 SSRF** → `egress.py`: allowlist + private-range denial + DNS pin +
  redirects disabled; every outbound dial (capture and corroborate) goes
  through it. This is the make-or-break control.
- **S2 DoS** → `config.py` caps + `asyncio.Semaphore` (global + per-key) +
  deadlines; corroboration runs with a concurrency limit, not an unbounded
  sequential loop.
- **S3 proto fidelity** → `PaymentFact` carries `close_remainder_to`,
  `asset_close_to`, `app_id`, `limitations`.
- **S4 trust anchor** → every response includes `bundle_json`;
  `report`/`fully_corroborated` are documented non-authoritative; there is **no
  verdict-only RPC**. A consumer re-verifies offline.
- **S5 store** → tenant-scoped index; ownership on every method; not-found
  masking; `source_node` sensitive.
- **S6 quarantine** → `_experimental` stays excluded from the wheel; the server
  never imports it.

---

## 5. Risks & sequencing notes

- **betterproto is beta** — pin exact; have grpcio+google-protobuf as a
  documented fallback path.
- **Streaming vs REST** — `CaptureStream` is server-streaming gRPC; the REST
  equivalent is chunked transfer or a poll-status endpoint (less elegant,
  acceptable).
- **Server clock is a trust input** for scheduled capture — validate NTP on
  startup.
- **Do not let the extra's deps leak into the core** — CI must assert the core
  installs and its tests pass with zero third-party packages present.

---

## 6. Definition of done (phase gate)

Core still zero-dependency and behaviourally unchanged; `avm-proofpack[server]`
installs and runs; gRPC ≡ REST parity green; the full SSRF / DoS / IDOR /
trust-anchor security-regression suite passes; integration test captures and
verifies against live testnet; `docker compose up` works end-to-end. Only then
is the service releasable (as a separate version bump; see the release plan).

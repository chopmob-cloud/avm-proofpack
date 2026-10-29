# Changelog

All notable changes to avm-proofpack. The bundle format (SPEC.md) is
versioned separately from the library; every release below reads and writes
format version 1 unchanged.

## 0.4.1 - 2026-10-29

### Security

- **The stake-attested tier no longer accepts a self-attested state proof.**
  `verify_bundle`'s internal `_verify_stake_attested` reached
  `trust_root == "stake_attested"` while (a) taking its trust anchor
  (`VotersCommitment`, `LnProvenWeight`) straight from the bundle's own,
  unauthenticated `previous_state_proof_message`, and (b) never binding the
  revealed participants to that commitment — it omitted both
  `verify_participant_tree_membership` and `verify_signature_tree_membership`.
  A forger could therefore reveal self-generated Falcon keys with arbitrary
  weights (and `ln_proven_weight = 0` to collapse the threshold) and reach the
  top trust tier for a transaction consensus never attested — exactly the
  failure the tier exists to prevent. Reported by security review.

  The fix makes the tier require a **caller-supplied trust anchor**, the new
  `TrustedVoters(voters_commitment, ln_proven_weight)` passed as
  `verify_bundle(..., trusted_voters=...)`. Against that anchor the verifier now
  binds every reveal to the trusted voters commitment (participant-tree
  membership) and to the proof's signature commitment (signature-tree
  membership), checks the signed-weight threshold against the anchor's proven
  weight, verifies each reveal's Falcon signature and ephemeral-key membership,
  and confirms coin selection — the same sound logic as
  `consensus.chain.verify_link`. A bundle's own `previous_state_proof_message`
  is no longer trusted; if present it must merely agree with the anchor.

  **Behavior change:** without a `trusted_voters` anchor, `verify_bundle` (and
  the CLI and server, which pass none) now report `trust_root == "unattested"`
  rather than a forgeable `"stake_attested"`. Supply an anchor you independently
  trust to reach attestation.

- **`TrustedVoters`** is exported from `avm_proofpack`.

### Fixed

- Packaging: the `pyproject.toml` comment claimed the `consensus` package was
  excluded from the wheel. It was not (and must not be, since `verify_bundle`
  imports it); the comment is corrected.
- Docs: README, SPEC §6 and the `consensus` module docstrings described the
  Falcon/state-proof tier as experimental, "not wired into `verify_bundle`" and
  living under a non-existent `src/avm_proofpack/_experimental/` directory. They
  now describe the shipped, anchor-gated stake-attested tier under
  `src/avm_proofpack/consensus/`.

## 0.3.0 - 2026-08-02

### Added

- **Optional gRPC + REST service layer** (`src/avm_proofpack_server/`), behind
  the new `avm-proofpack[server]` extra. Two transports over ONE
  `ProofpackService`: a `grpclib` gRPC server and a thin stdlib ASGI REST
  gateway served by `uvicorn`, exposing `Capture` / `CaptureStream` / `Verify` /
  `Extract` / `Corroborate` / `Health` (gRPC) and the matching `/v1/` endpoints
  (REST, with NDJSON streaming capture). The service is a **separate
  distribution shape**: the extra pulls the transport runtime
  (`grpclib==0.4.7`, `betterproto==2.0.0b7`, `uvicorn==0.30.6`), while the
  verification **core (`src/avm_proofpack/`) stays zero-dependency and
  behaviourally unchanged** — `pip install avm-proofpack` pulls nothing but
  CPython stdlib, and offline verification is untouched. Ships with an SSRF
  egress guard on every outbound dial (S1), global/per-key concurrency and
  node/wait bounds (S2), full-fidelity `PaymentFact` on the wire (S3), a
  bundle-is-the-sole-trust-anchor contract with no verdict-only path (S4), a
  tenant-scoped content-addressed store (S5), constant-time API-key auth, and
  in-process TLS (or reverse-proxy termination). The experimental
  Falcon/state-proof tier is NOT part of the service and does not remove node
  trust. Packaged via a multi-stage `Dockerfile` (non-root, `python:3.12-slim`,
  runs `python -m avm_proofpack_server`) and `docker-compose.yml`; documented in
  [docs/service.md](docs/service.md). The published proto contract lives in
  `protos/avm_proofpack/v1/`. Additive; no change to the bundle format or
  existing verification behaviour.
- `vectors/`: a frozen, documented **cross-implementation conformance vector
  set** (SPEC.md section 7). `vectors/positive/*.json` records, per fixture,
  the authoritative derived values an independent verifier must reproduce
  (genesis hash, txid, block hash, `txn256` root, transaction and light-header
  leaf hashes, block-headers commitment root, attested interval, trust root,
  and extracted `PaymentFacts`); `vectors/negative/*.json` is a canonical
  tamper set, each naming the exact fail-closed step. Every expected value is
  generated from the live fixtures by the reference library
  (`vectors/generate.py`), never hand-authored, and `tests/test_vectors.py`
  re-validates the whole set against the library so it cannot drift. See
  `vectors/README.md` for the file format, encoding conventions, `schema`
  versioning and the declarative mutation DSL. Additive and stdlib-only; no
  change to the bundle format or existing verification behaviour.

## 0.2.0 (unreleased)

Additive release. Bundle format v1 is unchanged; every 0.1.0 bundle
verifies identically.

### Added

- `avm_proofpack.extract`: payment-fact extraction from verified bundles.
  `extract_payment` decodes the bundle's top-level transaction and surfaces
  type, sender, receiver, amount (microalgos for `pay`, ASA base units for
  `axfer`), close-out flags, fee, validity window, note, group id and chain
  identity as a `PaymentFacts` dataclass. Extraction verifies the bundle
  internally unless the caller passes the matching `VerificationReport`,
  so facts can never be read out of unverified bytes. For `appl`
  transactions the facts carry an explicit limitation: inner-transaction
  effects are not proven by a v1 bundle.
- `encode_address` / `decode_address`: standard Algorand base32-with-checksum
  address text encoding (go-algorand `data/basics/address.go`).
- `matches_reference`: recompute a hashed payment reference (e.g.
  `sha256("{tenant}:{txid}:{network}")`) from a caller-supplied template and
  a verified bundle's txid, compared in constant time, closing the privacy
  loop described in docs/INTEGRATION.md.
- `avm_proofpack.chains`: registry of known chains (algorand-mainnet,
  algorand-testnet, voi-mainnet) with genesis id/hash, CAIP-2 identifier
  (CASA algorand namespace) and default corroboration node lists.
- CLI: `extract` subcommand (verify with the same trust-root gating as
  `verify`, then print PaymentFacts as JSON); `--chain <name>` on `verify`,
  `extract` (mutually exclusive with `--genesis-hash`) and `capture`
  (refuses a bundle from the wrong chain); `--corroborate default` expands
  to the pinned chain's default node list.
- CI workflow: pytest on Python 3.10/3.11/3.12 across Ubuntu and Windows,
  plus a packaging check (`python -m build` + `twine check`).

### Changed

- SPEC.md section 6 states the inner-transaction limitation of v1 bundles.
- pyproject gains `[project.urls]`.

## 0.1.0 (2026-07-30)

Initial release.

- Bundle format v1: state-proof-anchored, offline-verifiable transaction
  evidence for Algorand and Voi (SPEC.md).
- Zero-dependency canonical msgpack codec, vector commitment verification,
  transaction/light-header reconstruction with go-algorand-cited semantics.
- `capture` with five hard integrity gates; `verify_bundle` fail-closed
  offline verification; `corroborate` multi-node trust-root comparison.
- CLI: `capture` and `verify` with explicit trust-root gating
  (`--corroborate` / `--accept-unattested`) and chain pinning
  (`--genesis-hash`).
- Test suite: unit vectors, live-captured mainnet fixtures (Algorand pay,
  Algorand appl, Voi appl), full tamper suite, codec fuzzing.

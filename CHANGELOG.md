# Changelog

All notable changes to avm-proofpack. The bundle format (SPEC.md) is
versioned separately from the library; every release below reads and writes
format version 1 unchanged.

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

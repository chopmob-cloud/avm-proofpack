# AlgoVoi proofpack platform roadmap

**Status:** Product/platform proposal

**Date:** 29 October 2026

**Technical base:** `chopmob-cloud/avm-proofpack`, currently at package version `0.3.0` in this checkout.

## 1. Product position

`avm-proofpack` should become the **evidence layer for AVM settlement and state claims**: a portable, content-addressed proof object that can be captured by one party, independently checked by another, and retained for the life of an audit, payment, bridge, governance or RWA obligation.

It should not become a general-purpose bridge, wallet, explorer or compliance authority. Those products should consume the same open proof protocol and preserve its trust boundaries.

### North-star outcome

> Any material Algorand or Voi claim — payment settled, asset transferred, governance action executed, bridge condition met or RWA record updated — can be accompanied by a proofpack whose bytes, chain identity, trust tier and limitations are explicit.

### Product wedges, in order

1. **Settlement evidence:** prove top-level transaction inclusion and bind it to receipts.
2. **Operational evidence:** capture before node pruning, archive it, and make verification boring.
3. **Developer distribution:** make the verifier available in the languages and surfaces where payments are built.
4. **Higher assurance:** promote state-proof signature verification only after all missing trust-root checks are implemented and independently reviewed.
5. **Policy rails:** let bridges, treasuries and enterprises consume a proof without confusing evidence with redemption, legal title or application execution.

## 2. Baseline and honest trust ladder

The current repository already provides a strong v1 evidence primitive:

- The core is a zero-runtime-dependency Python verifier and capture path (`src/avm_proofpack/`).
- Bundle v1 carries canonical block-header and signed-transaction bytes, Merkle paths, state-proof message fields and the raw state proof (`SPEC.md` §§1–5).
- Capture has five integrity gates, including canonical round-trip, transaction identity, block linkage and a final offline verification (`src/avm_proofpack/capture.py`).
- Offline verification recomputes transaction identity, transaction commitment membership and block-header commitment membership, but its trust root is the bundle's own state-proof message (`src/avm_proofpack/verify.py`, `SPEC.md` §6).
- Corroboration compares that message across nodes; it is not cryptographic state-proof attestation (`src/avm_proofpack/verify.py`, `README.md`).
- Payment extraction is safe by default and explicitly marks the v1 limitation that inner transactions and application effects are not proven (`src/avm_proofpack/extract.py`, `SPEC.md` §6).
- The optional server already has gRPC/REST, egress controls, bounds, tenant-scoped SQLite storage and a maturity scheduler, while keeping the core additive (`src/avm_proofpack_server/`, `docs/service.md`).
- Conformance vectors and settlement-evidence binding vectors exist, including negative cases (`vectors/`, `vectors/settlement_evidence_binding/`).

The roadmap must preserve the following levels and names:

| Tier | Meaning | Current status | Product use |
|---|---|---|---|
| **T0 — structurally verified** | The bundle is internally consistent with its embedded state-proof message. | Shipped as `trust_root="unattested"`. | Local inspection, low-risk reconciliation, development. |
| **T1 — corroborated** | Independent nodes return the same state-proof message. | Shipped through `corroborate`; operator independence remains a human/configuration assumption. | Payment receipts, operational audit, dispute handling. |
| **T2 — stake-attested** | The state-proof signatures, key commitments, signed weight, reveal selection and voter commitment are all authenticated. | **Not shipped.** Experimental Falcon, Sumhash, A2 membership and A3 groundwork are quarantined and not wired into `verify_bundle`. | Trust-minimised bridges, high-value settlement and regulated evidence. |
| **T3 — application-effect proven** | The claimed inner transactions, state deltas, logs or application effects are committed by a verifiable execution/effect proof. | **Not shipped.** v1 proves the top-level application call only. | DeFi settlement, RWA ownership/state, DAO execution and app-mediated payments. |
| **T4 — policy-enforced cross-system action** | A target bridge, escrow, treasury or enterprise policy accepts a specific proof tier and prevents replay. | Future product/adaptor layer; never implied by a proofpack alone. | Automated release, mint/burn, reconciliation or approval. |

**Release rule:** no UI, API, badge or marketing copy may call T0/T1 “consensus-attested” or “trustless”. T2 and T3 remain future tiers until their acceptance gates below are met.

## 3. Platform principles

1. **The bundle is the trust anchor.** Every hosted response or signed receipt that reports a result must carry, or content-address, the exact bundle bytes. Never ship a verdict-only API.
2. **Open protocol, hosted convenience.** The format, verifier, SDK contracts, conformance vectors and local verification UX remain open-source. Hosting sells capture timing, archive, reliability, policy, support and integration — not the right to verify.
3. **Additive compatibility.** Keep bundle v1 readable forever. Introduce v2 only for new claims or proof tiers; do not silently reinterpret v1 fields.
4. **Separate evidence from policy.** A proof says what a chain committed. An escrow, bridge, treasury or compliance policy decides what to do about it.
5. **Capture asynchronously.** Receipts are issued when settlement occurs; proofpack capture runs after the 256-round state-proof interval matures and before public nodes prune the data (`docs/INTEGRATION.md`).
6. **Make limitations machine-readable.** Trust tier, chain pin, application-effect caveat, close-out/clawback caveat, capture time and verifier version must be visible in APIs and UIs.
7. **Design for independent re-verification.** Multi-language implementations must agree byte-for-byte on positive and negative vectors, not merely agree with a hosted service.
8. **Privacy by disclosure.** A proofpack reveals the transaction and its contents. Store it separately from privacy-preserving receipts and disclose it to entitled parties only.

## 4. Layered product roadmap

### Layer 1 — Core proof protocol

**Objective:** turn the current v1 bundle into a stable, extensible evidence protocol without weakening its trust model.

**MVP features**

- Freeze and publish a normative v1 profile: media type, JSON schema, canonical byte rules, chain identity, replay identity and error taxonomy.
- Add a machine-readable `trust_tier`/`verification_scope` result rather than relying on prose around `trust_root`.
- Add a proof manifest containing bundle byte hash, format version, verifier version, capture timestamp, source provenance and disclosure classification.
- Standardise the `chain_binding` receipt attachment described in `docs/INTEGRATION.md`, including explicit chain pinning and bundle hash semantics.
- Keep the current single-transaction bundle stable; define a separate interval/shared-state-proof object only when storage savings justify it.
- Publish the existing positive, negative, state-proof and settlement-binding vectors as the cross-language contract.
- Add an offline verifier command that emits a stable JSON audit report suitable for CI and legal/audit retention.

**Moat**

- A trusted, implementation-independent evidence format with unusually explicit failure semantics.
- A growing corpus of real Algorand/Voi proofpacks, negative cases and cross-language conformance results.
- Compatibility history: once receipts and audit systems bind to proofpack hashes, the format becomes a durable evidence interchange.

**Dependencies**

- Existing `SPEC.md`, `Bundle`, `verify_bundle`, `dump_bundle`, chain registry and vector suite.
- A decision on whether the next manifest is additive metadata or a v2 envelope; do not change the v1 hash contract casually.
- Independent review by Algorand/Voi protocol engineers before declaring T2.

**Acceptance criteria**

- A clean checkout can build the core with no third-party runtime dependency.
- Python, TypeScript and at least one systems-language verifier reproduce every positive vector and the named failure step for every negative vector.
- Re-serialising an unchanged v1 bundle does not change its content hash.
- A verifier with no network access can distinguish T0, T1, T2 and T3 states and refuses to overstate a lower tier.
- Receipt binding rejects wrong bytes, wrong chain, wrong round, wrong payment reference and non-canonical bundle hashes.

**Open-source / hosted split**

- **Open-source:** format, schemas, reference verifier, vectors, test fixtures, CLI and audit-report schema.
- **Hosted:** no protocol authority; only optional indexing, retention, freshness alerts and managed capture.

### Layer 2 — Developer SDKs

**Objective:** make proofpack a normal library call rather than a Python-only tool or a subprocess.

**MVP features**

- TypeScript SDK for Node.js and browser/WASM use: `capture`, `verify`, `extract`, `corroborate`, `bindReceipt` and typed trust/caveat results.
- Go or Rust verifier for server, relayer and operator deployments; choose one as the second independent implementation and use the other as the next target.
- Shared generated types for bundle, payment facts, corroboration and settlement binding.
- Adapters for common Algorand/Voi transaction clients, but keep the proof verifier independent of any SDK.
- Streaming and batch APIs for hosted capture, with explicit retryable `not-yet-provable` outcomes.
- Examples for x402, AP2, treasury reconciliation, wallet import and bridge policy evaluation.

**Moat**

- The same evidence semantics across backend, browser, wallet and relayer environments.
- Conformance tests become an integration gate for wallets, facilitators and bridge operators.
- A small, auditable verifier is easier to embed than a full node or indexer.

**Dependencies**

- Layer 1 stable schemas and vectors.
- A portable cryptographic implementation strategy; do not make browser consumers trust a hosted API.
- Clear distinction between blocking offline verification and optional network corroboration.

**Acceptance criteria**

- Each SDK verifies the same fixture and produces the same derived txid, block hash, commitments, facts and trust tier.
- Each SDK rejects all current negative vectors and settlement-binding canaries.
- Browser verification runs without a network request and exposes no “verified” state until the local check completes.
- Public API documents all unsupported claims, especially `appl` inner effects, close-out and clawback semantics.

**Open-source / hosted split**

- **Open-source:** SDKs, generated types, WASM/core verifier, examples and conformance harness.
- **Hosted:** optional capture, corroboration fan-out, archive and webhook APIs.

### Layer 3 — Hosted capture, archive and verification services

**Objective:** solve the operational problem that proof material is available only for a limited window.

**MVP features**

- Managed capture API for Algorand mainnet, Algorand testnet and Voi mainnet.
- Scheduler that accepts `(chain, txid, round)` at settlement time, waits for proof maturity, captures before pruning and emits a webhook.
- Immutable, tenant-scoped, content-addressed bundle storage with retention policies and export to customer object storage.
- Multi-node corroboration with visible operator/node identity and an explicit “same operator” warning where diversity is weak.
- REST/gRPC API that always returns the bundle bytes or exact content hash and advertises reports as non-authoritative hints.
- Health, capture-lag, maturity-window, node-agreement and failure metrics.
- Self-hostable server distribution remains available for organisations that cannot use the hosted service.

**Moat**

- Capture-window reliability and historical coverage, not a proprietary verdict.
- A diverse node/operator network and evidence archive that can answer “what was captured and when?”
- Operational integrations: webhooks, retention, export, incident replay and audit trails.
- High-quality chain-specific failure handling and support for long-lived customer obligations.

**Dependencies**

- Current `avm_proofpack_server` security controls: SSRF egress policy, request bounds, tenant isolation and TLS (`docs/service.md`).
- Durable object storage, key management, billing, tenancy and observability.
- A clearly documented default-store limitation: the current module entry point uses an in-memory store unless a durable store is wired programmatically (`docs/service.md`).
- Chain endpoint contracts and a node/operator diversity policy.

**Acceptance criteria**

- Every successful capture is independently re-verified from returned bytes in a clean container.
- A scheduled job survives a process restart, records terminal state and never silently loses a customer obligation.
- Cross-tenant reads, bundle enumeration, SSRF targets, redirects, oversized bodies and unbounded corroboration are rejected.
- A customer can export all bytes, manifests and audit reports and terminate the account without losing evidence portability.
- Service status pages distinguish “not yet provable”, “node unavailable”, “bundle invalid” and “corroboration disagreement”.

**Open-source / hosted split**

- **Open-source:** server core, egress guard, SQLite store, scheduler, proto, Docker reference deployment and security tests.
- **Hosted:** managed archive, multi-region durability, node diversity, SLA, retention, alerting, customer identity and billing.

### Layer 4 — Wallet and mobile evidence

**Objective:** let a user verify and share evidence without trusting an explorer or facilitator.

**MVP features**

- Import a proofpack JSON file or QR/deep link containing a content hash and authorised retrieval reference.
- On-device offline verification with chain pinning and a prominent T0/T1/T2/T3 label.
- Human-readable transaction facts: sender, receiver, amount, asset, round, close-out/clawback warnings and `appl` limitations.
- “Share evidence” flow that sends a bundle or an authorised retrieval link, not a mutable explorer URL.
- Watch state: receipt received now, proof pending maturity, proof captured, corroboration status and final export.
- Privacy controls: do not auto-upload a bundle merely because it was opened.

**Moat**

- The first wallet surface that treats proof bytes and caveats as first-class objects rather than a green check mark.
- User-generated distribution of portable evidence through merchants, auditors and counterparties.
- A common mobile verifier can be embedded by multiple Algorand/Voi wallets.

**Dependencies**

- TypeScript/WASM or Rust mobile core from Layer 2.
- Stable trust-tier result and disclosure metadata from Layer 1.
- Wallet partners and a safe deep-link/QR scheme.

**Acceptance criteria**

- Airplane-mode verification succeeds for an imported bundle.
- The UI never describes a top-level `appl` call as proof of an inner payment.
- A bundle from the wrong genesis hash is visibly rejected.
- Shared evidence re-verifies on a second device with the same derived values.
- No private transaction data leaves the device without an explicit user action.

**Open-source / hosted split**

- **Open-source:** verifier core, mobile library, QR/deep-link format and reference viewer.
- **Hosted:** optional evidence retrieval, notification, backup and merchant-facing proof requests.

### Layer 5 — Explorer and auditor workbench

**Objective:** make evidence review faster without turning the explorer into the trust root.

**MVP features**

- Browser-side upload and verification of a bundle.
- Search by txid, bundle hash, chain, round, receipt reference and customer-controlled labels where disclosure permits.
- Evidence timeline: receipt issued, transaction confirmed, state-proof interval matured, bundle captured, corroboration results and export time.
- Raw bundle download, derived facts, failed-check explanation and machine-readable audit report.
- Compare two bundles or a bundle against a receipt; show exactly which bytes and claims disagree.
- Auditor package export containing bundle, hashes, report, vector/verifier version and chain registry snapshot.
- Public/read-only index only for explicitly published bundles; private tenant evidence stays access-controlled.

**Moat**

- Indexed historical evidence and high-quality discrepancy analysis.
- A neutral presentation layer that makes it easier to audit a facilitator, bridge or treasury.
- Feedback from real negative cases improves vectors and SDKs.

**Dependencies**

- Hosted archive/index from Layer 3 and browser verifier from Layer 2.
- Privacy, retention and publication controls.
- A stable audit-report schema.

**Acceptance criteria**

- The browser verifies locally and displays the same result as the CLI.
- The explorer cannot produce a green result when local verification fails or the chain is unpinned.
- Every displayed claim links to the exact evidence bytes/hash and its trust tier.
- An auditor can reproduce the report offline from the export without explorer access.

**Open-source / hosted split**

- **Open-source:** verification UI components, audit-report renderer, export format and self-hostable workbench.
- **Hosted:** indexing, search, access control, collaboration, retention and public publication.

### Layer 6 — Payments, x402 and AP2

**Objective:** make proof-backed settlement the default upgrade path for machine and human payment receipts.

**MVP features**

- An open `avm-proofpack/1` `chain_binding` adapter for x402 settlement responses and resource-server receipts.
- Facilitator middleware that records the txid and round immediately, schedules proof capture after maturity and appends the bundle binding later.
- AP2 payment-result adapter that attaches evidence to the outcome leg while preserving mandate/authorisation semantics.
- Receipt verifier that enforces the five settlement-binding rules in `vectors/settlement_evidence_binding/`.
- Webhook events: `settlement_seen`, `proof_pending`, `proof_captured`, `corroborated`, `proof_failed` and `disagreement`.
- Replay/nullification hooks keyed by `(genesis_hash, txid)` for consuming systems; proofpack itself remains evidence, not redemption.
- Privacy-preserving reference matching using the verified txid, as already described by `matches_reference` and `docs/INTEGRATION.md`.

**Moat**

- A proof-carrying payment receipt becomes a network effect: every facilitator integration creates evidence that merchants, agents, wallets and auditors can reuse.
- A conformance suite protects against subtle receipt/hash/round/chain-binding drift.
- Capture reliability and dispute tooling become differentiated infrastructure for x402/AP2 operators.

**Dependencies**

- Stable Layer 1 binding schema and Layer 3 scheduler/archive.
- x402 facilitator and AP2 payment-result integration points.
- Customer-side policy for what T0/T1 is sufficient; high-value use cases should wait for T2.

**Acceptance criteria**

- A receipt can be issued immediately, then linked to a bundle after state-proof maturity without changing the original settlement claim.
- All R1–R5 settlement-binding rules pass, including the deliberate non-JCS canary.
- Wrong chain, wrong round, wrong txid/reference, wrong bundle bytes and replayed evidence are rejected.
- A consumer can verify the bundle without calling the facilitator or hosted API.
- Product copy states that a facilitator-supplied T0/T1 bundle is not yet stake attestation.

**Open-source / hosted split**

- **Open-source:** receipt binding schema, middleware interfaces, verifier, conformance vectors and reference adapters.
- **Hosted:** facilitator capture, archive, webhooks, reconciliation, SLA and merchant dashboards.

### Layer 7 — Bridge and light-client adapters

**Objective:** make proofpack consumable by bridge policy engines without claiming that a JSON proof is itself a bridge.

**MVP features**

- A language-neutral `ProofPolicy` interface: accepted chain, accepted tier, maximum age, confirmation/finality rule, asset/amount/recipient claim and replay key.
- Off-chain adapter that evaluates a proofpack before releasing an existing escrow or submitting a target-chain transaction.
- Algorand↔Voi relayer reference integration for top-level payment/asset-transfer evidence, with human review mode first.
- Target-chain receipt containing the source bundle hash, source genesis identity and policy decision.
- Fork/reorg and duplicate-delivery handling; never release on a mismatched chain or reused `(genesis_hash, txid)`.
- A path to compact on-chain verification only after a target environment can economically verify the required commitments.

**Moat**

- Policy-aware evidence adapters that bridge teams can audit and self-host.
- Cross-chain replay and mismatch test corpus built from real proofpacks.
- A source-chain proof is reusable across multiple target systems; the bridge policy remains replaceable.

**Dependencies**

- T1 for operational release and T2 for trust-minimised release.
- Target-chain escrow contracts, relayer security and asset identity mapping.
- Clear treatment of finality, reorgs, timeout and manual override.
- T3 if the source event is an application-induced transfer rather than a top-level transaction.

**Acceptance criteria**

- The adapter refuses any proof below its configured tier and refuses an unpinned chain.
- A replayed proof cannot release the same obligation twice.
- A source-chain transaction that only calls an application does not satisfy a payment-release policy unless an approved T3 effect proof exists.
- Every target decision is reproducible from the source bundle, policy version and replay store.
- Security review covers relayer compromise, malicious bundles, node disagreement, delayed proofs and target-chain failures.

**Open-source / hosted split**

- **Open-source:** policy interface, reference adapters, replay model, test vectors and contract-facing schemas.
- **Hosted:** managed relayers, node fleet, alerting, multi-party approvals and operational support.

### Layer 8 — Governance and treasury

**Objective:** provide proof-backed accounting and execution evidence for AlgoVoi treasuries, grants and DAOs.

**MVP features**

- Import proofpacks and match them to approved payment instructions, invoices, grant IDs or proposal IDs.
- Treasury reconciliation for ALGO/VOI and ASA transfers, including close-out, clawback, rekey and group caveats.
- Evidence package export for monthly close, grant reporting and external audit.
- Governance execution tracker: prove that the top-level execution transaction was included, while clearly separating inclusion from proof of the proposal's off-chain meaning.
- Multi-approver workflow for releasing funds based on a configured proof tier; keep the policy decision auditable.

**Moat**

- A durable, machine-readable treasury evidence trail that can be consumed by accountants, auditors and governance tooling.
- Reusable policy templates for grants, payroll, vendor settlement and reserve movements.
- Better incident response because every accepted payment has an evidence hash and verification report.

**Dependencies**

- Layers 1, 3 and 5; wallet/identity integrations are useful but not required for the first release.
- Accounting export formats and treasury policy ownership.
- T3 for application-mediated governance effects; v1 is not enough to prove inner transfers.

**Acceptance criteria**

- Every reconciled line item points to a verified bundle and a pinned chain.
- Close-out, clawback, rekey and application limitations are visible before approval.
- A reviewer can reproduce an approval decision offline from the evidence package and policy version.
- Deleting or replacing hosted data cannot change a previously exported evidence package.

**Open-source / hosted split**

- **Open-source:** import/export schema, reconciliation engine, policy templates and CLI.
- **Hosted:** collaborative approvals, scheduled capture, retention, accounting connectors and audit workspace.

### Layer 9 — Enterprise and RWA

**Objective:** package proof-backed chain events for issuers, custodians, payment firms and auditors without overclaiming legal or economic facts.

**MVP features**

- Enterprise evidence envelope combining a proofpack, issuer/custodian attestation, document hash, business identifier and retention metadata.
- Permissioned evidence delivery with selective disclosure and customer-controlled object storage export.
- RWA transfer certificate for **on-chain transfer inclusion**, with explicit separation from legal title, asset existence, valuation, custody and regulatory status.
- Retention, legal hold, key rotation, access logs, data residency and on-prem deployment options.
- Evidence API for risk, compliance and reconciliation systems.

**Moat**

- A credible bridge between open chain proofs and enterprise controls, rather than a proprietary “trust score”.
- Long-lived audit records and integrations into systems that already own the business obligation.
- Higher assurance tiers and independent verification reduce counterparty friction for repeat settlement flows.

**Dependencies**

- T1 for operational evidence; T2 for high-value consensus claims; T3 for app-mediated ownership/state.
- Legal review of claims and retention obligations; no proofpack field should be presented as legal title without an issuer/legal framework.
- Enterprise identity, KMS/HSM, policy, tenancy and deployment controls.

**Acceptance criteria**

- The envelope is verifiable offline and identifies which claims are cryptographic, issuer-attested or policy-derived.
- Selective disclosure does not allow a disclosed bundle to be substituted for another bundle.
- On-prem customers can export and independently verify all evidence without AlgoVoi hosting.
- Marketing and UI language never upgrades “included transfer” into “asset exists”, “ownership is valid” or “compliance is satisfied”.

**Open-source / hosted split**

- **Open-source:** envelope schema, verifier, redaction/selective-disclosure rules where safe, deployment reference and audit export.
- **Hosted/commercial:** managed compliance controls, retention, support, connectors, private tenancy, HSM/KMS integration and contractual SLAs.

### Layer 10 — Node and operator tooling

**Objective:** make proof capture a first-class operational responsibility for node operators, facilitators and infrastructure providers.

**MVP features**

- `proofpack-agent` daemon/sidecar for scheduled capture, queueing, retry, proof-maturity polling and object-store export.
- Endpoint allowlists, SSRF-safe node access, API-token handling, TLS, NTP/clock checks and bounded concurrency.
- Prometheus/OpenTelemetry metrics for state-proof availability, capture latency, prune-window risk, node disagreement and storage growth.
- Operator dashboard and alert rules for “round will become unprovable soon”.
- Batch capture by transaction list or round, with deterministic manifests and resumable jobs.
- Public operator metadata: chain, endpoint, region, operator identity and evidence service version, without pretending that two endpoints imply two independent operators.

**Moat**

- Coverage and reliability of the evidence supply chain.
- A diverse operator set improves T1 corroboration and provides the raw material for T2 validation.
- Operational data reveals which protocol, node and SDK edge cases matter in production.

**Dependencies**

- Current service scheduler, egress guard, storage and health modules.
- Durable object storage and a documented retention/export contract.
- Cooperation from Algorand/Voi node operators and public endpoint providers.

**Acceptance criteria**

- A daemon can be restarted without losing or duplicating a scheduled obligation.
- It refuses private/loopback/link-local targets and redirect-based SSRF.
- It emits an alert before the normal public-node retention window expires.
- Every stored bundle has a manifest and can be verified with no node access.
- A two-endpoint setup reports operator identity/diversity honestly.

**Open-source / hosted split**

- **Open-source:** agent, metrics, dashboards, configuration schema, deployment charts and runbooks.
- **Hosted:** managed node fleet, archive, alerting, operator directory and support.

## 5. State-proof and application-effect workstreams

These are high-value trust upgrades, not current product claims.

### T2 state-proof attestation gate

The experimental code and tests establish useful building blocks:

- Falcon signatures can be checked against the reconstructed state-proof message.
- A2 ephemeral-key membership is implemented in experimental code and exercised against real fixtures.
- A3 signature-tree membership, participant-tree reconstruction and signed-weight threshold checks are exercised against real fixtures.
- The tests explicitly record that A4 coin selection and A5 voter-commitment anchoring remain incomplete, and the structured result always reports `is_trust_root=False`.

Before T2 is wired into the shipped verifier, all of the following must be complete:

1. **A4 coin-based reveal-position selection** is implemented from the consensus rules and bound to the declared signed weight and reveal set.
2. **A5 voter-commitment anchoring** is implemented. The verifier must carry or retrieve the correct signing-voter commitment from the required earlier header/interval; it must not assume the message's next-interval commitment is the signing set.
3. All state-proof fields needed for A4/A5 are carried in a versioned bundle without relying on an untrusted node response at verification time.
4. Positive and negative vectors cover both Algorand and Voi, including voter-set changes, malformed proofs, selected/unselected positions, weight boundary cases and cross-chain transplantation.
5. At least two independent implementations agree on the result, followed by an external cryptographic/protocol review.
6. The published result has a new explicit tier such as `stake-attested`; existing T0/T1 reports remain unchanged.

### T3 application-effect proof gate

v1 cannot prove inner transactions, application state deltas or logs because those effects have no commitment path to the v1 state-proof message (`SPEC.md` §6). Do not work around this by trusting an indexer or facilitator.

The first T3 milestone should be a protocol/design track, not a product claim:

- Identify the exact AVM consensus commitment or execution-proof mechanism required.
- Define a versioned effect-proof object for inner transactions, state deltas and logs.
- Prove that the object is bound to the top-level transaction, application ID, group and round.
- Define privacy/selective-disclosure behaviour for application arguments, logs and state.
- Build a reference prover/verifier and negative vectors before integrating it into payments, bridges or RWA claims.

Until that gate passes, products may show application-call inclusion, but must label all effects as **unproven by proofpack v1**.

## 6. Sequencing and release gates

### Phase 0 — Contract and adoption foundation (0–90 days)

**Ship**

- v1 protocol/profile freeze and audit-report schema.
- TypeScript SDK plus the second independent verifier implementation.
- Current conformance vectors extended for binding, trust tiers and chain pinning.
- Production hardening of the hosted service: durable store wiring, restart-safe scheduler, exports, observability and operator identity.
- x402/AP2 reference adapters and asynchronous proof-pending webhooks.
- Proofpack browser viewer and minimal wallet import flow.
- Operator agent reference deployment.

**Exit gate**

A merchant, facilitator or auditor can capture a real Algorand or Voi settlement, receive a receipt immediately, obtain a proofpack after maturity, verify it offline in two languages and export an audit package.

### Phase 1 — Settlement network and public evidence (3–6 months)

**Ship**

- Managed capture/archive service with free developer quota and paid retention/SLA tiers.
- Auditor workbench and opt-in public evidence index.
- Wallet/mobile SDK integration with at least one partner wallet.
- Treasury reconciliation MVP.
- Node/operator directory and capture-window alerts.

**Exit gate**

At least three independent product surfaces — facilitator, wallet and auditor — consume the same bundle without calling one another's private APIs for verification.

### Phase 2 — T2 state-proof attestation (6–12 months; gated, not calendar-guaranteed)

**Ship only if gates pass**

- A4/A5 implementation, dual implementation, real-fixture and adversarial validation.
- New stake-attested result and upgraded bundle/manifest support.
- Hosted service can report T2 only when all required checks pass; otherwise it reports T0/T1 honestly.
- High-value bridge and enterprise policies can require T2.

**Exit gate**

Independent reviewers agree that a malicious bundle author cannot satisfy the T2 result without the required state-proof signatures, committed keys, threshold, selected reveals and correctly anchored voter commitment, subject only to the chain's stated consensus assumptions.

### Phase 3 — Policy rails (12–18 months)

**Ship**

- Bridge/light-client adapter interfaces and reference relayer.
- Treasury/DAO policy engine with replay protection and approvals.
- On-chain or target-chain verification experiments where economically viable.
- T2-aware x402/AP2 high-value settlement profiles.

**Exit gate**

A bridge or treasury can reproduce every automated decision from source bundle, policy version, target transaction and replay record; a lower-tier or application-only proof cannot trigger a policy that requires T2/T3.

### Phase 4 — T3 and enterprise/RWA (18–30 months; research-dependent)

**Ship only after protocol capability exists**

- Application-effect proof specification and reference implementation.
- Enterprise evidence envelope, selective disclosure, on-prem controls and retention/compliance integrations.
- RWA and app-mediated settlement profiles that explicitly identify cryptographic versus issuer/legal claims.
- T3-aware governance, bridge and payment policies.

**Exit gate**

A third party can independently verify the claimed application effect and distinguish it from issuer attestation, legal title, valuation and policy decisions.

## 7. Dependency graph

```text
v1 spec + vectors
        |
        +--> TypeScript / Go-or-Rust SDKs --> browser verifier --> wallet/mobile
        |
        +--> hosted capture + archive --> x402/AP2 --> merchant/agent receipts
        |                                  |
        |                                  +--> explorer/auditor
        |                                  +--> treasury reconciliation
        |
        +--> operator agent + diverse nodes --> stronger T1 corroboration
        |
        +--> A2/A3 experimental work
                    |
                    +--> A4 coin selection + A5 voter anchoring --> T2
                                                        |
                                                        +--> bridge policies
                                                        +--> high-value settlement
                                                        +--> enterprise assurance

AVM application/effect commitment or execution proof --> T3
                                                        |
                                                        +--> app-mediated payments
                                                        +--> RWA ownership/state claims
                                                        +--> governance execution effects
```

The critical path is not the explorer UI. It is: **stable protocol → independent SDKs → reliable capture/archive → honest trust tiers → T2 → policy rails → T3-dependent products**.

## 8. Open-source versus hosted boundary

| Capability | Default posture | Reason |
|---|---|---|
| Bundle format, hashes, canonical encoding and trust semantics | Open-source | Neutral interoperability and auditability. |
| Offline verifier and CLI | Open-source | The user must not trust AlgoVoi or any hosted operator to verify evidence. |
| Conformance vectors and negative tests | Open-source | Prevents ecosystem forks from silently changing meaning. |
| Python/TypeScript/Go/Rust/mobile SDKs | Open-source | Distribution and adoption matter more than licence revenue here. |
| Server core, scheduler, egress guard and reference stores | Open-source | Self-hosting improves credibility and gives operators a safe baseline. |
| Capture/archive API and node fleet | Hosted plus self-host option | Operational timing, retention and reliability are valuable services. |
| Indexing, collaboration, alerts and dashboards | Hosted, with self-hostable auditor UI | Convenience and workflow are monetisable without owning the proof. |
| Enterprise tenancy, KMS/HSM, retention, legal hold and data residency | Hosted/commercial | Real operating cost and contractual support. |
| Managed relayers and bridge operations | Hosted/commercial; adapter code open | Customers pay for uptime and operations, not an opaque policy. |
| Proprietary trust score or closed verifier | Do not build | It would recreate the trusted intermediary that proofpack is meant to remove. |

## 9. Monetisation and adoption loops

### Commercial offers

1. **Free/open tier:** unlimited local verification, public SDKs, conformance vectors and a small hosted capture allowance.
2. **Developer tier:** API quota, webhooks, short retention, testnet/mainnet endpoints and basic explorer access.
3. **Production tier:** higher capture volume, durable retention, export, corroboration diversity, alerting and SLA.
4. **Enterprise tier:** private tenancy, on-prem deployment, KMS/HSM, data residency, legal hold, SSO, support and audit integrations.
5. **Infrastructure tier:** managed node fleet, archive, operator monitoring and relayer/bridge operations.
6. **Professional services:** protocol integration, conformance certification, security review support and migration from opaque processor receipts.

Do not charge for the act of verifying an open bundle. Charge for capture timing, storage, reliability, policy execution, workflow and support.

### Adoption loops

- **Payment loop:** facilitator emits a receipt → hosted capture produces a proofpack → merchant/auditor verifies it → the proofpack becomes a reusable attachment for disputes and reconciliation.
- **SDK loop:** every integration adds a conformance test and example → fewer bespoke integrations → more wallets, agents and facilitators adopt the same evidence object.
- **Explorer loop:** published bundles create searchable evidence → auditors find discrepancies → new negative vectors improve the protocol.
- **Operator loop:** operators run the open agent → more capture coverage and endpoint diversity → stronger T1 corroboration → more confidence in hosted service SLAs.
- **Policy loop:** treasury/bridge users require a declared tier and replay policy → product teams implement the open policy interface → high-value use waits for T2/T3 rather than forcing overclaims.
- **Trust loop:** honest caveats build credibility; a deliberately withheld “fully attested” badge is more valuable than a premature one.

## 10. Risks and decisions to resolve early

- **State-proof complexity:** T2 must not be scheduled as a cosmetic feature. A4/A5 are consensus semantics, not UI work.
- **Application-proof availability:** if the AVM does not expose the required commitments, T3 may require protocol changes or a new execution-proof system; do not sell it as an SDK feature.
- **Operator diversity:** multiple URLs run by one operator do not provide independent corroboration. Record operator identity where possible.
- **Capture timing:** public-node pruning makes hosted reliability and operator tooling a core product, not a secondary feature.
- **Receipt hash semantics:** preserve the deliberate distinction between pretty-JSON bundle hashing and JCS attestation hashing; never “simplify” the rule without a version bump.
- **Privacy:** raw bundles disclose transaction content. Build access control and selective disclosure before public indexing of customer evidence.
- **Replay and redemption:** proofpack must never imply that a valid past event automatically authorises a future transfer. Consumers own escrow ordering, nullification and obligation binding.
- **Protocol stewardship:** keep the format and conformance suite under open governance with published change control, so AlgoVoi is a trusted maintainer rather than a mandatory intermediary.

## 11. Recommended first commitment

Prioritise the settlement wedge, not the whole platform:

1. Freeze the v1 contract and trust-tier vocabulary.
2. Ship TypeScript plus one independent verifier and the browser viewer.
3. Make capture/archive production-safe and restart-safe.
4. Integrate x402/AP2 with asynchronous evidence binding.
5. Publish the operator agent and auditor export.
6. Run the T2 workstream in parallel, but keep it quarantined until A4/A5, dual implementation and external review are complete.
7. Treat bridge, governance, enterprise/RWA and application-effect products as policy consumers of the protocol, not reasons to weaken its proof boundary.

That sequence creates immediate utility for Algorand and Voi while preserving the long-term moat: an open, independently verifiable evidence standard with the operational network and integrations needed to make it ubiquitous.

# avm-proofpack

**A Python library for offline Algorand state-proof verification.** Portable,
offline-verifiable transaction evidence for **Algorand** and **Voi**, anchored in
[state proofs](https://developer.algorand.org/docs/get-details/stateproofs/).

A *proofpack bundle* is a single JSON file binding a specific transaction to a
chain's state proof commitments. Capture it once, while public nodes still
hold the round, and anyone can re-check it forever, offline, with no node and
no SDK: the verifier recomputes every hash and Merkle link from raw bytes and
confirms the transaction is committed by the bundle's state proof message.

Read the trust model before you rely on it. Offline verification proves
internal consistency down to one trust root: the bundle's own state proof
message. That message is **not** authenticated by the default offline path, so
offline-alone does not prove the message was genuinely produced by the chain's
consensus stake. Raising that trust root is a separate, explicit step:

- `--corroborate` compares the message against independent nodes today;
- **stake attestation** cryptographically verifies the state proof's Falcon
  signatures, reveal membership, signed-weight threshold and coin selection.
  This is implemented (`avm_proofpack.consensus`, wired into `verify_bundle`),
  but because a single bundle cannot authenticate the *signing* interval's
  voters commitment, it is reached only when the caller passes a
  `TrustedVoters` anchor it independently trusts (from a trusted node, an
  earlier verified link, or a pinned genesis). Without that anchor the trust
  root stays `unattested` — the default. See
  [`consensus/chain.py`](src/avm_proofpack/consensus/chain.py) to authenticate
  a whole chain of proofs from one anchor.

Treat a structure-only (`unattested`) result as "this bundle is internally
consistent", not "consensus attests this". See [SPEC.md](SPEC.md) section 6.

Zero runtime dependencies. Pure Python. Works unchanged on any AVM chain that
generates state proofs (verified live against Algorand mainnet and Voi mainnet).

Documentation: [docs.algovoi.co.uk/avm-proofpack](https://docs.algovoi.co.uk/avm-proofpack),
including how the bundle binds x402 settlement evidence to
[offline-verifiable receipts](https://docs.algovoi.co.uk/offline-verifiable-receipts).

## Why

Payment processors, custodians and auditors routinely assert "transaction X
settled on chain Y" and back it with nothing but their own signature. Algorand
and Voi commit, every 256 rounds, to a stake-signed vector commitment over
their block headers, which makes such claims *falsifiable*: evidence can be
checked against consensus itself rather than against the claimant.

Two facts shape the design:

1. **Public nodes prune.** Non-archival nodes serve proof material for roughly
   the most recent 1,000 rounds only. Evidence must therefore be captured near
   settlement time and stored; it cannot be fetched years later on demand.
2. **Verification must not require trusting the capturer.** A bundle carries
   raw canonical bytes, not quoted values; the verifier recomputes every hash
   and Merkle link itself.

## Install

```bash
pip install avm-proofpack
```

(Or vendor the `src/avm_proofpack` directory; it is stdlib-only by design.)

## Usage

Capture evidence for a confirmed transaction (any algod endpoint):

```bash
avm-proofpack capture \
  --node https://mainnet-api.algonode.cloud \
  --txid KOERHNGJPLUUQK4WJ4YPY5OC3BOINDH2J4E6HM2RYARSJ5R3FAYA \
  --round 63604900 \
  -o evidence.json
```

A state proof covers a round only after its 256-round interval closes
(roughly 12 to 15 minutes); pass `--wait 1200` to poll until then.

Verify it later. Structure-only verification is fully offline but reports the
trust root as unattested and exits non-zero unless you either corroborate or
explicitly accept unattested evidence:

```bash
avm-proofpack verify evidence.json --accept-unattested
```

Pin the chain and corroborate the trust root against independent nodes:

```bash
avm-proofpack verify evidence.json \
  --genesis-hash wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --corroborate https://mainnet-api.4160.nodely.dev,https://mainnet-api.algonode.cloud
```

Or pin by registry name (`algorand-mainnet`, `algorand-testnet`,
`voi-mainnet`; mutually exclusive with `--genesis-hash`), letting
`--corroborate default` expand to the chain's default node list (both
`algorand-mainnet` and `voi-mainnet` ship two default endpoints):

```bash
avm-proofpack verify evidence.json --chain algorand-mainnet --corroborate default
```

Extract the payment facts of the proven transaction (same trust-root gating
as `verify`; stdout is one JSON object):

```bash
avm-proofpack extract evidence.json --chain algorand-mainnet --corroborate default
```

Extraction covers the top-level transaction only: for `appl` transactions
the output states explicitly that inner-transaction effects are not proven
by a v1 bundle (SPEC.md section 6).

From Python:

```python
from avm_proofpack import Bundle, capture, extract_payment, verify_bundle

bundle_dict = capture("https://mainnet-api.voi.nodely.io", txid, round_number)
bundle = Bundle.from_dict(bundle_dict)
report = verify_bundle(bundle)
print(report.checks)

facts = extract_payment(bundle, report=report)  # or omit report: verifies itself
print(facts.txn_type, facts.sender, facts.receiver, facts.amount)
```

`extract_payment` refuses to read facts out of unverified bytes: it either
verifies the bundle itself or cross-checks the supplied report against the
bundle. `matches_reference` closes the hashed-receipt privacy loop
(docs/INTEGRATION.md): it recomputes e.g.
`sha256("{tenant}:{txid}:{network}")` from the verified txid and compares
in constant time.

## What verification proves

Offline, from the bundle's raw bytes alone, the verifier re-derives:

1. the transaction id (both its SHA-512/256 and SHA-256 forms) from the
   canonical transaction bytes, binding the claimed txid to the evidence;
2. the transaction Merkle leaf and its membership in the block's SHA-256
   transaction commitment;
3. the block hash, the light block header encoding, and its membership in the
   state proof's block-headers commitment.

The remaining trust root is the state proof message itself. `--corroborate`
reduces that from "the capturing node was honest" to "these independent nodes
do not all collude". **Stake attestation** removes node trust entirely by
cryptographically verifying the state proof's Falcon signatures, reveal
membership, signed-weight threshold and coin selection; it is shipped in
`avm_proofpack.consensus` and wired into `verify_bundle`, and is reached by
passing a `TrustedVoters` anchor (see [Stake attestation](#stake-attestation)
below). The bundle already stores the raw state proof, so existing bundles
authenticate without recapture.

Two operational consequences of node pruning:

- **Capture promptly.** Non-archival nodes serve proof material for only
  ~1,000 rounds. Capture soon after the interval closes, or use an archival
  node.
- **Corroborate promptly, or against an archival node.** `--corroborate`
  queries `/v2/stateproofs/{round}`, which is subject to the same pruning, so
  corroboration of a months-old round needs an archival node. Corroborating at
  or near capture time (the intended workflow) always works.

See [SPEC.md](SPEC.md) for the format and the full verification algorithm, and
[docs/INTEGRATION.md](docs/INTEGRATION.md) for how to attach bundles to
payment-protocol receipts.

## What this is not

- **Not a bridge.** A bundle proves an event happened; it does not make anyone
  pay. Redemption safety is an escrow-design problem, deliberately out of
  scope.
- **Not stronger than the chain.** An adversary controlling a supermajority of
  stake could sign a false history; evidence inherits the source chain's
  security assumption, no more.
- **Not private.** A bundle necessarily reveals the transaction it proves.
  Systems that hash transaction ids for privacy should treat bundle disclosure
  as opt-in (see docs/INTEGRATION.md).

## Stake attestation

`src/avm_proofpack/consensus/` cryptographically verifies the state proof
itself — removing node trust (down to a caller-supplied anchor) and making
`--corroborate` unnecessary for an attested verdict. It contains:

- `falcon.py` — a stdlib-only Falcon-1024 (deterministic, compressed) signature
  verifier, validated against authentic go-algorand/Falcon known-answer vectors
  (`tests/falcon_kat/`).
- `sumhash.py` / `merklesig.py` — Sumhash512 and the merklesignature key-tree
  membership proof binding each reveal's ephemeral key to its participant.
- `stateproof.py` — the state-proof *message hash* reconstruction, per-reveal
  Falcon verification, signature- and participant-tree membership, and the
  log-domain signed-weight threshold.
- `coins.py` — Fiat-Shamir coin selection: that the revealed positions are the
  ones the proof's coins actually select.
- `chain.py` — walks a chain of state proofs from one trusted `ChainAnchor`,
  authenticating each link with the previous interval's verified inputs.

To reach `trust_root == "stake_attested"`, pass `verify_bundle` a
`TrustedVoters` anchor for the signing interval:

```python
from avm_proofpack import Bundle, TrustedVoters, verify_bundle

anchor = TrustedVoters(voters_commitment=..., ln_proven_weight=...)  # you trust these
report = verify_bundle(Bundle.from_dict(data), trusted_voters=anchor)
assert report.trust_root == "stake_attested"
```

**Why an anchor is required.** A state proof is signed by the voters committed
one interval earlier; a single bundle carries that commitment only as unverified
`previous_message`, so it cannot authenticate its own signing set. The caller
must supply the voters commitment it independently trusts (a trusted node, an
earlier verified link, or a pinned genesis). Without it, the participant weights
and key commitments would be attacker-supplied and the tier would be forgeable —
so `verify_bundle` stays `unattested` unless the anchor is given, and every
reveal is bound to that anchor's commitment before the verdict is raised.

A design for exposing capture/verify as a gRPC + REST service (additive to the
zero-dependency core) is sketched in
[design/grpc-rest-service-design.md](design/grpc-rest-service-design.md),
including its mandatory security requirements.

## Service (optional)

An **optional, additive** gRPC + REST service exposes the same capture / verify /
extract / corroborate operations to non-Python consumers. It lives behind an
extra and does **not** touch the core: `pip install avm-proofpack` stays
zero-dependency and offline verification is unchanged. The service (and only the
service) pulls a transport runtime:

```bash
pip install "avm-proofpack[server]"
python -m avm_proofpack_server        # gRPC on :50051, REST on :8080
```

The server's verdict is a non-authoritative hint; consumers re-verify the bundle
offline exactly as above. See [docs/service.md](docs/service.md) for
configuration, TLS, API-key auth, the endpoints, Docker/compose, and the full
security model.

## Development

```bash
pip install -e .[dev]
python -m pytest            # offline: unit vectors, live-captured fixtures, tamper suite

python scripts/adversarial_secval.py \
    tests/fixtures/algorand-mainnet-pay.json tests/fixtures/voi-mainnet-appl.json
```

The test fixtures are real bundles captured from Algorand and Voi mainnet. The
tamper suite mutates every component of every fixture and requires
verification to fail closed each time. `scripts/adversarial_secval.py` is a
standalone adversarial harness that asserts every forgery, cross-chain, and
report-confusion attempt against real bundles fails closed.

## AlgoVoi AVM evidence & interoperability suite

This repository is one of a set of AlgoVoi projects for Algorand and Voi settlement evidence and cross-chain interoperability. A bridge or relayer executes a transfer; [avm-proofpack](https://github.com/chopmob-cloud/avm-proofpack) makes the underlying chain facts independently verifiable offline; and [avm-algovoi-falcon](https://github.com/chopmob-cloud/avm-algovoi-falcon) supplies post-quantum signing for keys, accounts and attestations. The row for **this repository** is shown in **bold**.

| Repository | Role |
|---|---|
| **[avm-proofpack](https://github.com/chopmob-cloud/avm-proofpack)** | Portable, offline-verifiable Algorand/Voi transaction evidence anchored in State Proofs — the shared evidence core. |
| [avm-algovoi-falcon](https://github.com/chopmob-cloud/avm-algovoi-falcon) | Falcon-1024 (FIPS 206) post-quantum keys, Algorand `falcon_verify` LogicSig accounts and offline attestations — the identity layer. |
| [avm-voi-algo-bridge](https://github.com/chopmob-cloud/avm-voi-algo-bridge) | VOI → Algorand mainnet bridge: on-chain log validator, escrow and relayer. |
| [avm-algo-voi-bridge](https://github.com/chopmob-cloud/avm-algo-voi-bridge) | Algorand → VOI mainnet bridge (reverse direction). |
| [avm-wormhole-ntt-relayer](https://github.com/chopmob-cloud/avm-wormhole-ntt-relayer) | Wormhole NTT relayer bridging tokens between Algorand and Base. |
| [avm-hbar-bridge-relayer](https://github.com/chopmob-cloud/avm-hbar-bridge-relayer) | Treasury-model bridge relayer between Algorand and Hedera (HBAR/HTS). |

## Licence

Apache-2.0, Copyright 2026 AlgoVoi. Created and maintained by AlgoVoi and
offered as a gift to the Algorand and Voi communities: free to use, modify, and
redistribute, with the attribution in [NOTICE](NOTICE) retained (Apache-2.0,
Section 4). Cryptographic semantics (domain separators, vector commitment
structure, canonical encoding) follow
[go-algorand](https://github.com/algorand/go-algorand); the experimental
Falcon-1024 verifier follows the Falcon specification and the
[algorand/falcon](https://github.com/algorand/falcon) C reference semantics.
Each is cited at its point of use in the source. avm-proofpack is a clean-room
implementation and contains no go-algorand or Falcon-reference code.

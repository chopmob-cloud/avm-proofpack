# Mapping proofpack evidence into payment protocols

A bundle is deliberately protocol-neutral: it proves a chain fact and nothing
else. This document describes the recommended pattern for attaching that fact
to payment-protocol receipts so that a settlement claim becomes independently
falsifiable, without changing the receipt formats themselves.

## The general pattern: an optional `chain_binding`

A settlement receipt or attestation (x402 settlement response, AP2 payment
result, a processor's signed receipt) typically already asserts something
like "payment P settled on chain C". Add one optional, additive field:

```json
"chain_binding": {
  "scheme": "avm-proofpack/1",
  "bundle_sha256": "<hex sha256 of the bundle file bytes>",
  "bundle_ref": "https://... or opaque locator (optional)"
}
```

- The receipt binds the bundle by content hash, so the receipt's existing
  signature now also covers the evidence, byte-exactly.
- The bundle itself binds the chain: anyone holding receipt + bundle verifies
  the hash, then runs `avm-proofpack verify --corroborate <nodes>` (structure
  plus trust-root corroboration; a bare structure-only pass is explicitly
  reported as unattested), then checks the transaction's content against the
  receipt's claims (asset, amount, receiver, round).
- Verifiers MUST pin the chain: the receipt names the chain (for AVM chains,
  prefer a CAIP-2 identifier derived from the genesis hash) and the
  verifier passes that genesis hash to verification. Without pinning, an
  internally sound bundle from a different AVM chain would satisfy the check.

Because the field is optional and additive, receipts without evidence remain
valid, and the upgrade is backwards-compatible.

## Timing: mint now, bind evidence when it exists

State proofs cover a round only after its 256-round interval closes (~12 to
15 minutes). Receipts are typically minted at settlement time (seconds). Do
not delay receipts for evidence; instead:

1. mint the receipt immediately, recording the txid and confirmed round;
2. a background worker captures the bundle once the interval closes, while
   nodes still hold the data (non-archival nodes prune after ~1,000 rounds,
   roughly 45 to 80 minutes on a 2.8 s AVM chain, so the worker has a
   deadline, not a suggestion);
3. store the bundle and publish the `chain_binding` through whatever channel
   the receipt is re-fetched or re-verified from (a verification endpoint, a
   receipt store, an appended attestation).

One state proof covers every transaction in its 256-round interval, so
storage amortises: store the state proof message once per interval and the
per-transaction remainder (a few KB) per receipt.

## Privacy: hashed txids and opt-in disclosure

Receipt schemes often hide raw transaction ids, e.g. a content-addressed
reference such as `sha256(tenant || txid || network)`. A bundle necessarily
reveals the txid and the transaction's full content, so:

- keep the bundle out of the receipt itself (bind by hash, store separately);
- release the bundle only to parties entitled to the underlying transaction
  (the payer, the merchant, an auditor), making disclosure opt-in per tenant;
- at disclosure time the verifier recomputes the hashed reference from the
  bundle's txid and checks it against the receipt, closing the loop between
  the private reference and the public chain fact.

## Protocol-specific notes

**x402.** The natural attachment points are the settlement response returned
by a facilitator's `/settle` and any receipt object the resource server
issues. A facilitator settling on Algorand or Voi adds `chain_binding` to its
settlement attestation; the client (or any later auditor) then re-derives the
chain facts itself instead of taking the facilitator's word.

Be precise about how much trust this removes, because a malicious facilitator
is exactly the adversary here. Offline verification of a facilitator-supplied
bundle proves the bundle is internally consistent with *its own* state proof
message, a message the facilitator supplied. A dishonest facilitator can
fabricate a fully self-consistent bundle for a payment that never settled. The
trust upgrade is real only once the consumer raises the trust root: corroborate
the state proof message against independent nodes at (or near) receipt time,
and, when the Falcon-verification tier ships, verify the state proof
signatures. Until then, treat a facilitator's bundle as "verifiable in
principle, pending corroboration", and corroborate before relying on it.

**AP2.** Attach the binding to the payment-result evidence in the mandate
chain. The mandate chain then carries intent (user-signed), authorisation and
outcome (chain-attested) with no gap: every link is independently
verifiable.

**Plain processor receipts.** Sign `{claims..., chain_binding}` as one
object. Any signed-receipt scheme gains falsifiability with a single added
field.

## What a binding does not do

Evidence is not redemption. A receipt with a valid bundle proves the past; it
does not make anyone pay in the future. Systems that release funds against
evidence must supply their own escrow-first ordering, timeouts, content
binding to the specific obligation, and replay tracking (nullify per
`(genesis_hash, txid)`), as set out in SPEC.md section 6.

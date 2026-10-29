# A6 — reaching `stake_attested` (plan + blocker found empirically)

**Status:** not started. This is a plan and a finding, not an implementation.

**Date:** 29 October 2026

## The goal

Take the offline verification spike from exit code `2` (`structure OK, trust root NOT attested`) to exit
code `0` with `trust_root: stake_attested`, by verifying the state proof's Falcon-1024 signature and
its signing weight against the authenticated previous interval.

## The blocker, found by inspection of a real captured bundle

The obvious plan — "move `_experimental/falcon.py` into the shipped path" — **would change nothing**,
because the bundle does not contain the state proof. A real captured bundle
(`J6FPFF4C…` @ round `66457600`, 428 KB) has these top-level keys:

```
block_header_msgpack_b64      light_header_proof      meta
chain                         state_proof_message     state_proof_msgpack_b64
format                        stib_msgpack_b64        transaction
txn_proof                     version
```

`state_proof_message` contains exactly five fields:

```
block_headers_commitment_b64, first_attested_round, last_attested_round,
ln_proven_weight, voters_commitment_b64
```

There are **no reveals, no signature, and no signature weight**. So the bundle proves *inclusion in an
attested block interval* but carries nothing that could be Falcon-verified. This is a **capture-format
limitation, not a verifier limitation** — and it is the real reason the label cannot advance.

## What has to change, in order

1. **Extend the capture format** with an optional `state_proof` section carrying the full
   `StateProof` msgpack from `/v2/stateproofs/{round}` (reveals, `w`, `pr`, `c`, signature). Expect
   the bundle to grow substantially; see the size note below.
2. **Verify the message hash first.** `stateproof.state_proof_message_hash` over the captured message
   must equal the hash the reveals sign. Nothing else is meaningful until this holds.
3. **Verify each reveal's Falcon-1024 signature** (`verify_reveal`) — stdlib-only, already KAT-validated
   against go-algorand vectors.
4. **Verify ephemeral-key membership** (`verify_ephemeral_key_membership`) against the `"KP"` leaf at
   `round - round % KeyLifetime`.
5. **Verify the signing weight** against the **authenticated previous-interval `ln_proven_weight` —
   never the message's own** (`chain.py` already does this correctly; `stateproof.verify_signed_weight_threshold`
   is the trap and now carries a warning).
6. **Run A4 coin selection** with the authenticated participants commitment, so the declared weight is
   bound to the revealed signers rather than asserted.
7. **Only then** set `stake_attested`. Every step must fail closed, and the tier must be `structural`
   or `corroborated` if any step is skipped — never silently upgraded.

## Two constraints that shape the implementation

- **Size.** One bundle is already 428 KB. Adding a state proof makes it larger. A per-transaction bundle
  is therefore the wrong wire format for x402/MPP/AP2: store the state proof **once per attested
  interval** (it covers 256 rounds and thousands of transactions) and let receipts reference it by
  digest. Do not inline proofs per receipt.
- **A5 composition.** A5 (`chain.py`) authenticates a chain of intervals from a caller-supplied anchor.
  `stake_attested` is only meaningful relative to that anchor. The verifier must state what the anchor
  is and where it came from; an anchor supplied by the same party that supplied the proof confers no
  trust. Do not let A5's green tests imply more than they do.

## Definition of done

The spike script (`netblock` + `verify` on a real bundle) returns exit code `0`, prints
`trust root: stake_attested`, and a **negative control** — the same bundle with one signature byte
flipped, and separately with the message's own `ln_proven_weight` substituted — returns a non-zero exit
and never `stake_attested`. Without both controls, the tier is unproven.

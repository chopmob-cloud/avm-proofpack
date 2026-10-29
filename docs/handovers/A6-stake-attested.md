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


## VERIFIED SO FAR — steps 2, 3 and 4 work offline today

Run against a real Algorand mainnet bundle (`J6FPFF4C…` @ round `66457600`) with no network, using only
what the bundle carries:

```
message hash:  fc3c12522f6c2a88bde53d62d4c4cb8d34517065cdae1126ef8035e2efa194a7
reveals:       71
signature verifies:                    71/71
signature + key membership verifies:   71/71
negative control (ln_proven_weight+1):  0/71   <- correctly zero
```

So **step 2** (`state_proof_message_hash` over the captured message) is exact, **step 3** (per-reveal
Falcon-1024 signature verification) passes for every reveal, and **step 4** (ephemeral-key membership
against the `"KP"` leaf) passes for every reveal as well. The negative control confirms the signatures
genuinely bind the message rather than verifying vacuously — a one-field tamper takes the pass count to
zero.

The cryptographic core of the stake-attested tier therefore already works; what remains is **step 5**
(signing weight against the *authenticated previous-interval* `ln_proven_weight`, which needs the
previous interval's message as well as this one), **step 6** (A4 coin selection with the authenticated
participants commitment), and **step 7** (emit the tier and fail closed).

Note on counts: `sp["pr"]` holds 151 *positions to reveal* while `sp["r"]` holds 71 actual reveals. Do
not use `len(pr)` as the reveal count when iterating (`iter_reveals` yields `(position, reveal)` pairs,
not bare reveals).


## VERIFIED — steps 5 and 6 (authenticated inputs) on real mainnet data

```
round                    66457600   (previous interval 66457344)
declared weight w        1,960,644,431,120,003
positions to reveal      151
message's OWN ln         2,230,417
AUTHENTICATED ln         2,230,418        <- differ by exactly 1, as the interval model predicts

threshold with AUTHENTICATED ln         : True
threshold with message's OWN ln         : True    <- this fixture does NOT discriminate
coin selection, authenticated inputs    : True
coin selection, message's OWN c + ln    : False   <- correct rejection
```

**The offset is real and observable**: the message's own `ln_proven_weight` is one greater than the
previous interval's, which is exactly the trap round 1 fell into — feeding the message value in gives an
attacker-chosen bound, and the values are close enough that the defect is invisible without knowing the
interval model.

**Honest caveat, recorded because a reviewer will ask:** for this fixture the *threshold* check passes
with either value, because the declared weight (~1.96e15) clears both bounds comfortably. The
discrimination comes from **coin selection**, which returns `False` when given the message's own
participants commitment and ln. So step 5 alone is not a sufficient pin — the authenticated-input
guarantee must be pinned through coin selection, and a dedicated small-weight fixture should be built so
the threshold itself discriminates too.

**Remaining offline gap:** this probe fetched the previous interval's message live. For the tier to be
claimable offline, the bundle must carry the previous interval's message alongside its own — that is a
capture-format change (A6 step 1 extension), not a verifier change.


## VERIFIED — all six cryptographic steps, entirely offline, with negative controls

`capture` now also carries `previous_state_proof_message` (the authenticated signing set and weight
bound). With sockets disabled before import, and **no live fetch**, a real bundle gives:

```
network: blocked

step 2 message hash        fc3c12522f6c2a88bde53d62…
step 3 falcon signatures   71/71
step 4 key membership      (verify_reveal performs both, so included in the 71/71)
step 5 weight (auth ln)    True
step 6 coin selection      True

negative controls:
  wrong ln                 False
  wrong commitment         False
  tampered message hash    0/71
```

Captured intervals are contiguous and the offset is visible: previous `[66457089, 66457344]`
ln = 2,230,418; own `[66457345, 66457600]` ln = 2,230,417.

**So the entire cryptographic core of `stake_attested` works offline from the bundle alone.** Only
**step 7** remains: emit the tier from `verify_bundle` (and the CLI), failing closed to
`structural`/`corroborated` when `state_proof_b64` or `previous_state_proof_message` is absent — which is
the case for every bundle captured before this change, so the fallback path is exercised by existing
fixtures rather than hypothetical.

Regression: 102 passed, 6 skipped across capture/bundle/verify.

## Definition of done

The spike script (`netblock` + `verify` on a real bundle) returns exit code `0`, prints
`trust root: stake_attested`, and a **negative control** — the same bundle with one signature byte
flipped, and separately with the message's own `ln_proven_weight` substituted — returns a non-zero exit
and never `stake_attested`. Without both controls, the tier is unproven.

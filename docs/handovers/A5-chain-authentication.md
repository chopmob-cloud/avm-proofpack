# Handover — A5: State Proof chain authentication (experimental)

**Status:** implementation + tests complete; hardening applied; independent review pending.
**Branch:** `feat/stateproof-a5-chain-walk`
**Base:** `origin/main` (`avm-proofpack` v0.3.0, after A4 merge `abd6ca2`)
**Scope:** experimental only. **Not wired into `verify_bundle`, the server, or any public API.**

---

## 1. Task

A4 verified coin selection against `participants_commitment` and `lnProvenWeight`
**supplied by the caller** — which means a caller could hand over values matching a forged
proof. A5 removes that assumption: it walks a chain of State Proofs forward from a
caller-supplied anchor, proving that each link's signing inputs are the ones the previous
link actually signed.

## 2. Interval model (confirmed against real mainnet data, not assumed)

- a State Proof at round `R` attests rounds `[R-255, R]` (`FirstAttestedRound`, `LastAttestedRound`);
- its message carries the voters commitment and `LnProvenWeight` for the **next** interval;
- therefore the proof at `R` is verified with inputs taken from `message(R - interval)`.

Verified empirically: the Algorand proof attesting `63604992` verifies with the message fields of
`63604736` — exactly `interval = 256` earlier. A 2-link Voi chain
(`21208576 → 21208832 → 21209088`) authenticates end to end.

## 3. Where this sits

| Milestone | Content | State |
|---|---|---|
| A1 | Sumhash512 | done, KAT-validated |
| A2 | Ephemeral-key commitment membership | done |
| A3 | Signed-weight threshold | done |
| A4 | Coin selection (seed, sampling, position/range) | done, merged (`abd6ca2`) |
| **A5** | **Chain authentication from a caller-supplied anchor** | **this milestone** |
| A6 | Trust tiers exposed to callers | not started |

## 4. Files

- `src/avm_proofpack/_experimental/chain.py` — `ChainAnchor`, `ChainLink`, `LinkResult`,
  `ChainResult`, `verify_link`, `authenticate_chain`, `message_round`, `ChainError`
- `tests/test_stateproof_chain.py` — 20 tests
- `tests/chain_kat/chains.json` — three consecutive real Voi state proofs + messages + genesis hash
- `tests/chain_kat/fetch_chains.py` — how the fixture was captured (re-runnable)

`_experimental` remains excluded from the wheel.

## 5. Decisions

1. **The anchor is caller trust, and the code says so.** `ChainResult.is_trust_root` is true only
   when every link verified *and* an anchor was supplied. It means "authenticated back to the anchor
   you gave me", not "authenticated absolutely". The module never invents a root and never reads
   config.
2. **Message fields are the signed preimage, not the signing set.** `verify_link` reconstructs the
   message hash from the message's *own* `VotersCommitment`/`LnProvenWeight`, but checks the
   participant tree and coin selection against the *previous interval's* authenticated values. Mixing
   these up is the single easiest way to build something that verifies but proves nothing.
3. **`genesis_hash` is CALLER BOOKKEEPING, not a cryptographic binding.** (Corrected after review:
   this section previously claimed it "prevents replaying a chain from another network" — that was
   false.) The state proof and its signed message contain no genesis field, so the value cannot bind
   to the chain; `authenticate_chain` only checks that the caller labelled every link consistently.
   Verified: the real Voi chain authenticates with `ok=True, links_verified=2, is_trust_root=True`
   after every `genesis_hash` is replaced with 32 zero bytes. **Cross-chain replay protection comes
   entirely from the anchor's voters commitment**, which is what the proofs are actually verified
   against. Do not present the genesis field as a security property.
4. **Fail closed on topology, not just crypto:** missing link, link keyed under the wrong round, a
   target at or before the anchor, a target off the interval grid, and a non-positive interval all
   refuse rather than guess.
5. **`verify_link` is public** so callers can verify a single hop without walking a chain.

## 6. Evidence

| Gate | Result |
|---|---|
| `pytest tests/test_stateproof_chain.py` | **20 passed** (real Falcon verification, not stubs) |
| Full suite `pytest -q` | **517 passed, 6 skipped** (re-measured at round 2) |
| Per-guard mutation | **18/23 killed**; 5 survivors, of which only ONE is a genuine equivalent mutant — see below |
| Real chain | 2 links, `is_trust_root is True` |
| `ruff check` | clean |

### Mutation accounting (corrected after review)

This number has been wrong twice; here is the round-2 independently measured position.
**18/23 killed, 5 survivors**, of which **one** is a genuine equivalent mutant
(`no_target_after_anchor` — the `ChainResult.__post_init__` invariant rejects the resulting
ok-with-no-inputs result). The four non-equivalent survivors (`no_anchor_ln_guard`,
`no_links_is_dict`, `no_walk_chainlink`, `no_msg_uint_type`) are all **fail-closed**: they change only
the error surface (ChainError vs a failed `ChainResult`), never turn a reject into an accept. Earlier
figures ("5/7", then "17/23") were both wrong.

**The one genuine equivalent mutant:** dropping the target-after-anchor check. With it removed, a
`target <= anchor` reaches `ChainResult(True, 0, target, None, None)`, which `__post_init__` rejects
with `ChainError`. Verified for `target == anchor` and `target == anchor - 256`. Behaviour preserved;
the explicit check stays only for the better error message.

**The claim I got wrong:** I previously described "use the message's own commitment as the signing
set" as equivalent, reasoning that coin selection independently rejects a wrong anchor. That was
false. On the Algorand rotation fixture the mutant returns `reveals_ok=False` for a **valid** proof —
it breaks liveness on every rotating interval. It survived only because all three Voi fixtures carry
an identical voters commitment (no rotation), i.e. a **fixture gap, not equivalence**. Fixed by
adding a rotation fixture (`tests/fixtures/algorand-mainnet-pay.json`), which kills it:
`test_rotation_fixture_verifies_with_previous_interval_inputs` fails under the mutation.

**Remaining survivors** (`anchor.ln_proven_weight` int guard, `links`-is-dict, walk non-`ChainLink`,
and the A3 threshold input) are pinned-or-eliminated by the fixes below or are fixture-limited. Treat
this list as live, not closed.

### SECURITY DEFECT found by review, and fixed

**The proven-weight bound was attacker-chosen.** `verify_link` fed the message's **own**
`LnProvenWeight` into `verify_all_reveals`, which uses that single value both as preimage input and
as the A3 threshold bound. The message is authored by whoever builds the proof, so the bound was
theirs to pick: the reviewer measured the minimum passing `SignedWeight` collapsing from ~6.6e14 at
the honest value to **4** at `ln=0`. Coin selection was still anchored correctly, so the failure was
confined to the weight property — but that is the property A3 exists to provide.

Fixed: `verify_link` no longer uses `reveals.all_checks_ok`. It composes the reveal/signature/participant
checks and then calls `signed_weight_meets_threshold` with the **authenticated previous-interval**
`ln_proven_weight` (the same value coin selection already uses). Pinned by
`test_threshold_uses_the_authenticated_ln_not_the_messages`, which asserts the threshold is invoked
with the authenticated value; the mutation that restores the defect is killed.

**Correction I previously claimed but had NOT made** (caught in round 2): `stateproof.py`'s A3
docstring still said the proven-weight bound was the message's `LnProvenWeight`, and
`verify_signed_weight_threshold` still took that value from a caller-supplied message — so
`{"w": 4, "pr": [...149 items...]}` with `ln = 0` returned `True`. A5's own path was never exposed
(it threads the authenticated value), but the hazard shipped as a documented public API. Both
docstrings now state that the bound comes from the verifier context, not the message, and the helper
carries an explicit warning that it does not authenticate its input. **Do not re-wire the threshold to
the message.**

### Defects found by the earlier (aborted) review, now fixed

- **Non-int anchor round raised `TypeError`, not `ChainError`.** The error surface is documented as
  `ChainError`, so a caller catching `ChainError` would have missed it. `authenticate_chain` now
  validates the anchor material (non-negative int round and `LnProvenWeight`, 64-byte voters
  commitment, 32-byte genesis hash) before any arithmetic.
- **`ChainResult` could be internally inconsistent** (e.g. `ok=True` with no `target_inputs`).
  A `__post_init__` invariant now forbids that. Note the honest limit, stated in the docstring: a
  caller can still hand-build a *consistent* `ok=True` result — that is inherent to a public
  dataclass. Only `authenticate_chain` verifies anything, so a verdict must come from it.

## 7. What A5 does NOT establish

- **The anchor itself is unverified.** Whoever supplies `ChainAnchor` is trusted. Choosing it badly
  (a round from the wrong chain, or one they never independently checked) defeats the walk.
- **Block headers are not checked against blocks.** A5 authenticates the *commitment* to block
  headers; proving a specific transaction is in a block is the next layer (the existing bundle
  path), not this one.
- **No trust tier is exposed.** A6 is still required before any caller-facing verdict changes.
- **Not wired in.** Nothing in the shipped verifier or server imports this module.

## 8. Commands

```bash
VENV=C:/Users/ETCMC/AppData/Local/hermes/cache/scratch/proofpack-a4/venv/Scripts/python.exe
cd C:/algo/worktrees/avm-proofpack-stateproof-a4
$VENV -m pytest tests/test_stateproof_chain.py -q    # 20 passed
$VENV -m pytest -q                                    # 517 passed, 6 skipped

# re-capture the chain fixture (needs network; writes tests/chain_kat/chains.json)
$VENV tests/chain_kat/fetch_chains.py tests/chain_kat
```

## 9. Next actions

1. **A6 (trust tiers):** expose `structural → corroborated → stake_attested` and make
   `stake_attested` reachable **only** through `authenticate_chain` with a supplied anchor. Keep the
   default at the lowest tier.
2. Wire A1–A5 behind those tiers; keep `_experimental` out of the wheel until A6 lands.
3. Extend the chain fixture with an Algorand multi-link chain once a node serves the needed rounds
   (the nodely Algorand endpoint returned HTTP 500 for all three rounds on 2026-10-29, so only the
   single-link Algorand fixture exists).
4. After A6, obtain a fresh independent review; this milestone's verdict does not carry over.

## 10. Constraints

- stdlib only; no network access inside the verifier.
- Never invent a trust anchor; never read config for one.
- Never let a caller mistake `is_trust_root` for absolute truth — it is relative to their anchor.
- Keep `_experimental` out of the wheel.

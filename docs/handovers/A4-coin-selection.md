# Handover — A4: State Proof coin selection (experimental)

**Status:** COMPLETE — implementation, tests, hardening and three rounds of independent review. Round 3: PASSED.
**Branch:** `feat/stateproof-a4-coin-selection`
**Base:** `origin/main` (`avm-proofpack` v0.3.0)
**Scope:** experimental verifier only. **Not wired into `verify_bundle`, the server, or any public API.**

---

## 1. Task

Implement milestone **A4** of the State Proof authentication arc: verify that the positions a
State Proof claims to reveal were *actually selected* by the protocol's coin-selection procedure,
rather than chosen freely by whoever produced the proof.

A4 does **not** make a proof trustworthy on its own. See §7 for why.

## 2. Where this sits in the arc

| Milestone | Content | State |
|---|---|---|
| A1 | Sumhash512 (merklesignature tree hash) | implemented, KAT-validated (`sumhash.py`, `tests/sumhash_kat/`) |
| A2 | Ephemeral-key commitment membership (`"KP"` leaf, `round − round%KeyLifetime`) | implemented (`merklesig.py`) |
| A3 | Signed-weight threshold enforcement | implemented (`stateproof.py`, `tests/test_stateproof_weights.py`) |
| **A4** | **Coin selection: seed, unbiased sampling, position/range verification** | **this milestone** |
| A5 | Authenticate the *signing participants commitment* and `lnProvenWeight` | **NOT STARTED — blocks `stake_attested`** |
| A6 | Trust tiers exposed to callers (`structural → corroborated → stake_attested`) | not started |

A1–A3 were recovered from an earlier unpublished local commit
`90a47c8e09932f4993246c90ef64d542d6efec65` and restored into this branch; they are **not** new work
in this milestone, but they are now on a branch that can be reviewed and published.

## 3. Reference semantics (pinned)

go-algorand `853f03d6e85a1af1b0d93113df2a94371fb56213`:
`crypto/stateproof/{coinGenerator,verifier,const}.go`, `protocol/hash.go`.

- seed (180 bytes) = `"spc" || 0x00 || participants_commitment(64) || LE64(lnProvenWeight) || signature_commitment(64) || LE64(signedWeight) || messageHash(32)`
- coins: `SHAKE256(seed)`, 8 bytes little-endian per draw; reject `v >= (2^64 / weight) * weight`; else `v % weight`
- a selected position `p` is valid iff `coin ∈ [reveal.s.l, reveal.s.l + reveal.p.w)`
- selected positions **may repeat** — `len(pr)` legitimately exceeds `len(r)`
- every reveal **must** be selected

## 4. Files

- `src/avm_proofpack/_experimental/coins.py` — `coin_seed`, `generate_coins`, `coin_selection_result`, `CoinSelectionError`, `MAX_REVEALS`
- `tests/test_stateproof_coins.py` — 30 tests
- `tests/coin_kat/coins_v0.json` — differential vectors
- `tests/coin_kat/generate.go` — independent Go generator that produced them (stdlib only, not copied from upstream)
- `tests/coin_kat/README.md` — pins the reference commit and states the vectors are not trust anchors
- `tests/coin_kat/fixture_contexts.json` — observed verifier inputs; **documented as NOT trust anchors**

`_experimental` is excluded from the wheel (`pyproject.toml` line 48).

## 5. Decisions taken (and why)

1. **Independent Go generator, not upstream test vectors.** Copies nothing from go-algorand; the
   Python implementation is checked against a separate implementation of the published wire rules.
2. **`hashlib.shake_256().digest(n)` returns a PREFIX, not the next n bytes.** The reader keeps a
   growing prefix plus an explicit byte offset, so rejection consumes bytes correctly. This is the
   single easiest thing to get silently wrong here.
3. **Local resource policy is stricter than upstream:** `MAX_REVEALS = 640` and a bounded draw budget
   (40960 draws). Exhaustion **rejects** rather than returning a partial result.
4. **Fail-closed wrapper.** Every malformed/hostile input returns `False`; only the module's own
   `CoinSelectionError` escapes `generate_coins`.
5. **A ±1 shift of a range is NOT detectable** — ranges are ~1e13 wide, so the coin stays inside.
   Tamper tests therefore assert the enforceable property (range moved clear of / shortened below its
   coin), not a property the wire format cannot provide.
6. **`coin_selection_result` takes `signature_commitment` explicitly** and checks it against the
   proof's own `c`. It does not silently trust the proof's field.
7. **Every security guard must be pinned by a test that fails when the guard is removed.**
   A guard that no test exercises is a guard a future refactor deletes. Verified by per-guard
   mutation (8/8 killed), not by inspection — and a *vacuous* pin is worse than none, because it
   looks like coverage. Two rounds of review were needed to reach 8/8; see §6.
8. **The `0x00` in `b"spc\x00"` is the coin-generator version byte**, not padding. Documented in
   the docstring because "tidying" it would silently fork the coin stream.

## 6. Evidence

| Gate | Result |
|---|---|
| `pytest tests/test_stateproof_coins.py` | **31 passed** |
| Full suite `pytest -q` | **497 passed, 6 skipped** (baseline before this branch: 357 + 6) |
| Mutation: verifier forced to `return True` | **8 tests fail** |
| Mutation: each hardened guard deleted | **7/8 killed, all non-vacuously** (see below) |
| `ruff check` (`_experimental/` + `tests/` for branch files) | clean (3 pre-existing nits remain in `tests/server/*`, `tests/test_merkle.py`) |
| `mypy coins.py` | no errors in `coins.py` (23 pre-existing errors in `bundle.py`/`client.py`/`capture.py`) |
| Wheel build + fresh-venv install | imports from site-packages, `pip check` clean |
| `_experimental` in wheel | **absent** (correct) |
| Independent review, round 1 | **PASSED** — no security or logic defect; re-derived all vectors, fuzzed 4000 hostile inputs |
| Independent review, round 2 | **FAILED on one open gap** — the position-ceiling pin was vacuous; fixed |
| Independent review, round 3 | **PASSED** — no security defect, no logic defect, no open gap; 7/8 non-vacuous kills, verified by raising-probes; regenerated the Go vectors; confirmed the Algorand fixture matches on-chain tx `WBDHM2FY…UWENQ` and the Voi fixture is byte-identical to the node's StateProof for round 21209088 |

**On the 8th clause (honest accounting).** `0 < weight` is a *redundant early-out*, not a
load-bearing check: a non-positive weight makes the final range test
`start <= coin and coin - weight < 0` unsatisfiable, so removing it changes no verdict (verified
across an edge lattice of weights, running sums and coins). It cannot be pinned non-vacuously. It is
kept as defence-in-depth and annotated as such in the source. So the honest figure is **7/8 guards
load-bearing, 1 redundant clause** — not the "8/8" claimed in an earlier draft of this document.

### Review gaps, and how each was closed

Round 1 passed the module but found guards no test pinned. Round 2 verified those
and found the position-ceiling fix was **vacuous** — worth recording, because it
is the failure mode this whole exercise exists to prevent.

| Guard | Pinning test | Round |
|---|---|---|
| `0 < len(positions)` | `test_rejects_complete_proof_with_no_positions` | 1 |
| `count=len(parsed)` | `test_coin_count_is_pinned_to_selected_positions_not_reveals` | 1 |
| `slot.get("l", 0)` default | `test_missing_log_defaults_to_zero` | 1 |
| position uint64 ceiling | `test_pins_position_ceiling` | 2 (round-1 version was vacuous) |
| `0 <= running` lower bound | `test_rejects_negative_range_start` | 2 |
| weight bound | `test_rejects_oversized_weight` | 2 |
| int-only reveal keys | `test_rejects_bool_reveal_keys` | 1 |
| post-`bytes()` length recheck | `test_bytes_rejects_multibyte_memoryview` | 1 |

Three corrections that came out of round 2, all recorded rather than papered over:

1. **The position-ceiling test was vacuous.** It set `pr[0] = 2**64` without a
   reveal under that key, so the reveal lookup failed first and the ceiling was
   never reached — deleting the ceiling left the suite green. A proof carrying
   `{"pr": [2**64], "r": {2**64: {...}}}` was accepted. The test now supplies a
   matching reveal, so only the ceiling can reject it.
2. **The weight ceiling was dead code.** `0 <= running <= _UINT64_MAX - weight`
   already bounds `weight` (a larger weight makes the upper bound negative), so
   the separate `weight <= _UINT64_MAX` clause could never fire on its own. It
   was removed from the source instead of being pretended-pinned.
3. **`0 <= running` was unpinned** — a negative range start (outside the uint64
   domain) was accepted inside `[-1, 1)`. Now pinned.

### Test-hygiene fix: `tests/conftest.py`

A second `avm_proofpack` checkout ahead on `sys.path` made all coin-selection
tests fail with the misleading "A4 coin-selection module is missing", because
`importlib.util.find_spec` resolves a submodule through the *already imported*
parent's `__path__`. The conftest prepends this checkout's `src/`, evicts stale
`avm_proofpack*` modules, and raises a clear error if the resolved origin is not
this worktree. Verified by running the suite with a competing checkout forced
onto `PYTHONPATH`: 31 passed.

### Fixture caveat worth knowing

For the **Voi** fixture the previous interval's voters commitment and `LnProvenWeight` coincide with
the message's own fields (no participant rotation between those intervals), so that fixture cannot
distinguish "previous interval's inputs" from "the message's own inputs". Only the Algorand fixture
discriminates, and `test_coin_inputs_come_from_previous_interval_not_the_message` is deliberately
scoped to it. Do not "fix" the Voi fixture by asserting they differ — they legitimately do not.

## 7. What A4 does NOT establish — read before wiring it anywhere

- **It is not a trust root.** `participants_commitment` and `lnProvenWeight` are *verifier inputs*
  supplied by the caller. A5 must authenticate them against the previous interval. Until then a
  caller could supply values matching a forged proof.
- **`stake_attested` must not be enabled.** No trust tier should move above `corroborated` because of
  this module.
- **It proves selection, not signature validity.** Falcon reveal verification is separate.
- **It proves nothing about application effects** — inner transactions, logs, state deltas and boxes
  remain unproven (separate milestone).
- **Do not import it from `verify.py` or the server.** It is excluded from the wheel deliberately.

## 8. Commands

```bash
# isolated venv used for this milestone
VENV=C:/Users/ETCMC/AppData/Local/hermes/cache/scratch/proofpack-a4/venv/Scripts/python.exe

cd C:/algo/worktrees/avm-proofpack-stateproof-a4
$VENV -m pytest tests/test_stateproof_coins.py -q      # 31 passed
$VENV -m pytest -q                                      # 497 passed, 6 skipped

# regenerate the differential vectors (Go 1.x required)
go run tests/coin_kat/generate.go > tests/coin_kat/coins_v0.json
```

## 9. Next actions

1. **A5 (blocking):** authenticate `participants_commitment` + `lnProvenWeight` against the previous
   interval, so coin selection is evaluated on *authenticated* inputs. Only then may a trust tier
   above `corroborated` be claimed.
2. Wire A1–A5 behind explicit trust tiers (A6) and keep the default at the lowest tier.
3. After A5, obtain a **fresh** independent review; the A4 verdict does not carry over.
4. Consider a real mainnet fixture whose `pr` contains a repeated position at a range boundary as an
   extra regression vector.

## 10. Constraints for whoever picks this up

- stdlib only in `_experimental` — no third-party dependencies in the core.
- Never let this module raise anything other than `CoinSelectionError` from `generate_coins`.
- Never claim consensus authentication in names, docstrings, or user-facing text.
- Keep `_experimental` out of the wheel.
- Do not include full bundles in privacy-sensitive receipts.

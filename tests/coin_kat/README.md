# A4 coin-selection differential vectors

Test-only material for `avm_proofpack._experimental.coins`. **Nothing here is a
trust anchor and none of it ships in the wheel.**

## What this proves

The Python coin-selection implementation is checked against a *separate*
implementation of the published wire rules, written in Go using only the
standard library (`crypto/sha3`, `math/big`). No code is copied from
go-algorand; the generator re-derives both the Fiat-Shamir seed and the coins
from the specification.

## Pinned reference

go-algorand `853f03d6e85a1af1b0d93113df2a94371fb56213`:
`crypto/stateproof/coinGenerator.go`, `crypto/stateproof/verifier.go`,
`crypto/stateproof/const.go`, `protocol/hash.go`.

Wire rules:

- seed (180 bytes) = `"spc" || 0x00 || participants_commitment(64) || LE64(lnProvenWeight) || signature_commitment(64) || LE64(signedWeight) || messageHash(32)`
  - the single `0x00` is the coin-generator **version byte**, not padding
- coins = `SHAKE256(seed)`, 8 bytes little-endian per draw
- reject a draw when `v >= (2^64 / weight) * weight`, otherwise accept `v % weight`
- a selected position `p` is valid iff the coin falls in `[reveal.s.l, reveal.s.l + reveal.p.w)`

## Files

| File | Purpose |
|---|---|
| `generate.go` | Independent generator. `go run generate.go > coins_v0.json` |
| `coins_v0.json` | Vectors across weights `1, 2, 1024, 1025, 2^63+1, 2^64-1` and two real mainnet weights, including the draw counts that cross SHAKE refill boundaries |
| `fixture_contexts.json` | Verifier inputs observed from public APIs for the real-fixture tests |

## `fixture_contexts.json` is NOT a trust anchor

It records the signing participants commitment and `lnProvenWeight` observed
from public node/indexer responses on 2026-10-29, purely so the real mainnet
proofs can be exercised. Authenticating those values against the previous
interval is milestone **A5** and is not implemented. A test passing here means
coin selection is self-consistent — **not** that a proof is trustworthy.

## Regenerating

```bash
cd tests/coin_kat
go run generate.go > coins_v0.json
```

Requires a Go toolchain. The committed JSON is the reviewed artefact; regenerate
only when the pinned upstream reference changes, and review the diff.

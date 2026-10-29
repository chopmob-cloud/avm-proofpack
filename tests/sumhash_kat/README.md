# Sumhash512 known-answer test vectors

`sumhash512_kat.json` holds authentic **Algorand Sumhash512** known-answer test
vectors — `(input, expected 64-byte digest)` — used to validate
`avm_proofpack._experimental.sumhash.sumhash512` /
`avm_proofpack._experimental.sumhash.Sumhash512`.

## What Sumhash512 is

Algorand's state-proof Merkle trees hash with **Sumhash512** (a reveal's
`prf.hsh` type is `1` = Sumhash, 64-byte nodes), not SHA-256. Sumhash512 is a
subset-sum compression function over a fixed 8×1024 `uint64` matrix, expanded
from the ASCII seed `"Algorand"` via SHAKE256, wrapped in a Merkle–Damgård
construction (block size 64, all-zero IV, `0x01` padding, 128-bit little-endian
bit-length). See the module docstring for the full construction and its
go-sumhash source references.

## Provenance (how the vectors were obtained)

Every value here is copied **byte-for-byte** from the official
`github.com/algorand/go-sumhash` test suite — specifically `sumhash512_test.go`:

- `string_vectors` are the entries of that file's `testVector` table, each hashed
  in go-sumhash's `TestSumHash512TestVector` with `New512(nil)` (unsalted) and
  `h.Sum(nil)`.
- `shake_vectors` are the streaming tests from the same file. The input is
  `SHAKE256("sumhash input")` read for 6000 bytes; the salted case XORs each
  block with `SHAKE256("sumhash salt")` read for 64 bytes. Both inputs are
  regenerated deterministically in `tests/test_sumhash.py` (pure stdlib
  `hashlib.shake_256`), so no opaque blob is vendored.

These are the hash author's own published test vectors, so a byte-for-byte match
is direct evidence the implementation reproduces go-sumhash exactly. The
go-sumhash sources and Go toolchain are **not** vendored (they require Go);
only the resulting offline vectors are, keeping the test suite pure-stdlib.

## Coverage

- Empty input (padding-only single block).
- Single-block inputs (`a`, `ab`, `abc`, `abcd`).
- Multi-block: the 67-byte Gandhi quotation (2 blocks) and the 6000-byte
  (~94-block) SHAKE256-derived input.
- Non-ASCII bytes: the Descartes quotation contains a UTF-8 en-dash.
- Salted construction parity: the salted 6000-byte case.

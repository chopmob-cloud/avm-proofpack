# avm-proofpack conformance vectors

This directory is the **normative, cross-implementation conformance test set**
for the proofpack bundle format (see [`../SPEC.md`](../SPEC.md)). It exists so
that an implementation which is **not** this Python library, a future JS or Go
verifier, can prove byte-for-byte agreement with the reference by running these
vectors and reproducing every recorded value.

A conforming verifier passes the set iff:

- every **positive** vector's bundle verifies, and the verifier reproduces
  every expected derived value it records; and
- every **negative** vector fails closed, at the exact named step.

Everything in this directory is generated from the live-captured fixtures in
[`../tests/fixtures/`](../tests/fixtures) by
[`generate.py`](generate.py); no expected value is hand-authored. Regenerate
with, from the repo root:

```
PYTHONPATH=src python vectors/generate.py
```

The files are stable JSON (`sort_keys=True`, two-space indent), so they are
diffable and hash-stable: regenerating against an unchanged library and
unchanged fixtures reproduces identical bytes, and any diff signals a real
behavioural change. [`../tests/test_vectors.py`](../tests/test_vectors.py)
re-checks every recorded value against the library on every test run, so the
vectors cannot silently drift from the code.

## Versioning

Every vector carries `"schema": "avm-proofpack-conformance/v1"`. The schema
version is independent of both the library version and the bundle format
version (`SPEC.md`, format v1). A consumer MUST reject a vector whose `schema`
it does not understand rather than guessing. Backward-compatible additions
(new optional fields, new vectors) keep `v1`; any change to the meaning of an
existing field bumps the schema.

## Encoding conventions

- All raw hash / commitment / digest values are **lowercase hex** and carry a
  `_hex` suffix (`genesis_hash_hex`, `block_hash_hex`, `txn_leaf_hash_hex`,
  ...). A 32-byte digest is 64 hex characters.
- `txid` is the canonical 52-character **base32** transaction id (no padding),
  exactly as it appears in a bundle and on chain explorers.
- Rounds and indices are JSON integers.
- `payment_facts` is embedded verbatim as the JSON object produced by the
  reference `PaymentFacts.as_dict()`; its own byte fields (`note_b64`,
  `group_b64`, `genesis_hash_b64`) are **base64**, as that method emits them.
- Bundles are referenced by a **relative path** (`bundle_path` /
  `base_bundle_path`), resolved against the vector file's own directory, rather
  than embedded, so the ~380 KB fixtures are not duplicated.

## Positive vectors (`positive/*.json`)

One per fixture. Shape:

```json
{
  "schema": "avm-proofpack-conformance/v1",
  "kind": "positive",
  "name": "algorand-mainnet-pay",
  "description": "...",
  "bundle_path": "../../tests/fixtures/algorand-mainnet-pay.json",
  "expected": { ... }
}
```

To run a positive vector: load the bundle at `bundle_path`, verify it fully
offline, and assert each `expected` field. Fields under `expected`:

| Field | Meaning | Source in the reference |
|-------|---------|-------------------------|
| `verifies` | Always `true`. | — |
| `trust_root` | Always `"unattested"`: offline verification proves commitment by the bundle's own state proof message (SPEC §6). | `VerificationReport.trust_root` |
| `txid` | Transaction id, base32, re-derived from the reconstructed transaction (`base32(sha512_256("TX"‖txn))`). | `VerificationReport.txid` |
| `round` | The transaction's round. | `VerificationReport.round` |
| `genesis_id` | Chain genesis id; must equal the header's `gen`. | `VerificationReport.genesis_id` |
| `genesis_hash_hex` | 32-byte chain genesis hash. | `VerificationReport.genesis_hash_b64` |
| `first_attested_round` / `last_attested_round` | State proof message's attested interval. | `VerificationReport` |
| `light_header_variant` | `"block_hash"` (v39+) or `"seed"`. | `VerificationReport.light_header_variant` |
| `block_hash_hex` | `sha512_256("BH"‖header_bytes)`. | `VerificationReport.block_hash_b64` |
| `txn_commitment_root_hex` | The block's SHA-256 transaction-commitment root (`txn256`); the root the transaction proof proves into. | `VerificationReport.txn_commitment_b64` |
| `txn_leaf_hash_hex` | Transaction Merkle leaf: `sha256("TL"‖sha256("TX"‖txn)‖sha256("STIB"‖stib))`. | `avm.txn_hashes` + `avm.stib_hash_sha256` + `hashes.sha256` (as in `verify.py`) |
| `light_header_leaf_hash_hex` | Light block header leaf: `sha256("B256"‖canonical(light_header))`. | `avm.light_block_header_leaf` |
| `block_headers_commitment_root_hex` | The state proof message's block-headers commitment; the root the light-header proof proves into. | `VerificationReport.block_headers_commitment_b64` |
| `checks` | Ordered list of passed step labels. | `VerificationReport.checks` |
| `payment_facts` | Top-level transaction payment semantics. | `extract_payment(...).as_dict()` |

The two leaf hashes are the intermediate values `verify_bundle` feeds into the
two vector commitment proofs. They are the highest-value cross-check for an
independent implementation because they exercise transaction reconstruction,
domain-separated hashing and canonical msgpack together, yet they are not
otherwise exposed on the report; they are recomputed here through the same
library functions `verify.py` uses.

## Negative vectors (`negative/*.json`)

A canonical tamper set. Each vector names a base bundle, a declarative
mutation, and the failure the reference produces. Shape:

```json
{
  "schema": "avm-proofpack-conformance/v1",
  "kind": "negative",
  "name": "substituted-txid",
  "description": "...",
  "base_bundle_path": "../../tests/fixtures/algorand-mainnet-pay.json",
  "mutation": [ { "op": "set", "path": "transaction.txid", "value": "..." } ],
  "expected": { "verifies": false, "error_type": "VerificationError",
                "failed_check": "transaction" }
}
```

### Fail-closed contract

A negative vector **passes iff verification fails, and (when
`error_type` is `VerificationError`) fails AT the named step**:

- `error_type: "VerificationError"` with `failed_check: "<step>"` — the bundle
  parses, but `verify_bundle` aborts raising a verification error whose
  `check` equals `<step>`. Failing at a *different* step is a conformance
  failure just as much as not failing at all: it means the two implementations
  disagree about *why* the bundle is bad.
- `error_type: "BundleError"` — the mutation is rejected at schema validation,
  before any verification step runs (e.g. a round outside the attested
  interval). There is no `failed_check`; a `detail` string is recorded for
  humans only and is not part of the contract.

The `failed_check` values are the reference's real step labels, captured by
actually applying each mutation, never assumed. The full ordered set of steps
a verifier walks is, in order: `canonical` / `decode` (byte-level),
`canonical-form`, `block-header`, `chain-identity` (only when the caller pins
`expected_genesis_hash`), `transaction`, `txn-proof`, `light-header` /
`light-header-proof`, `state-proof-present`. (`transaction-id`,
`txn-commitment-membership` and `block-headers-commitment-membership` are the
*success* labels recorded in `checks`; the corresponding *failure* labels are
`transaction`, `txn-proof` and `light-header-proof`.)

### `verify_options`

A vector may carry `verify_options`. The only one defined is
`expected_genesis_hash_hex`: the verifier must pass this 32-byte value as the
pinned expected genesis hash (`verify_bundle(..., expected_genesis_hash=...)`).
This is how the `chain-identity` step is exercised without mutating the bundle.

### Mutation op DSL

`mutation` is an ordered list of ops applied to the base bundle's raw JSON. A
`path` is dot-separated (`transaction.round`, `chain.genesis_hash_b64`;
top-level keys have no dot). An independent implementation reimplements these
five ops; the reference is `apply_mutation` in both `generate.py` and
`tests/test_vectors.py` (kept byte-identical so the vectors are self-checking).

| `op` | Fields | Effect |
|------|--------|--------|
| `set` | `path`, `value` | Set `path` to the literal JSON `value`. |
| `add_int` | `path`, `delta` | Integer-add `delta` to the integer at `path`. |
| `flip_b64_bit` | `path`, `byte_offset`, `xor` (default `1`) | base64-decode the string at `path`, `XOR` the byte at `byte_offset % len` with `xor`, re-encode. |
| `truncate_b64_tail` | `path`, `drop_bytes` | base64-decode, drop the last `drop_bytes` bytes, re-encode. |
| `copy_from` | `path`, `from_fixture`, `from_path` | Copy the value at `from_path` of fixture `from_fixture` (by stem, from `tests/fixtures/`) into `path`. |

### The set

| Vector | Base | Mutation gist | `error_type` | `failed_check` |
|--------|------|---------------|--------------|----------------|
| `stib-byte-flip` | alg-pay | flip a stib byte | VerificationError | `transaction` |
| `header-byte-flip` | alg-pay | flip a header byte | VerificationError | `light-header-proof` |
| `substituted-txid` | alg-pay | replace claimed txid | VerificationError | `transaction` |
| `altered-round` | alg-pay | round + 1 | VerificationError | `block-header` |
| `txn-proof-byte-flip` | alg-pay | flip txn proof byte | VerificationError | `txn-proof` |
| `txn-proof-index` | alg-pay | txn proof index + 1 | VerificationError | `txn-proof` |
| `txn-proof-truncated` | alg-pay | drop a proof sibling | VerificationError | `txn-proof` |
| `light-proof-byte-flip` | alg-pay | flip light proof byte | VerificationError | `light-header-proof` |
| `headers-commitment-flip` | alg-pay | flip commitment root | VerificationError | `light-header-proof` |
| `interval-shift` | alg-pay | shift attested interval | VerificationError | `light-header-proof` |
| `genesis-hash-flip` | alg-pay | flip genesis hash | VerificationError | `block-header` |
| `variant-flip` | alg-pay | claim `seed` variant | VerificationError | `light-header-proof` |
| `noncanonical-header` | alg-pay | non-shortest int re-encode | VerificationError | `canonical` |
| `chain-identity-mismatch` | alg-pay | pin a different chain | VerificationError | `chain-identity` |
| `junk-state-proof` | alg-pay | junk state proof blob | VerificationError | `state-proof-present` |
| `transplanted-stib` | alg-appl | splice another tx's stib+proof | VerificationError | `transaction` |
| `cross-chain-transplant` | alg-appl | Voi message under Algorand | BundleError | (schema) |

## How to consume this set from another language

1. Read every file in `positive/` and `negative/`; reject any whose `schema`
   you do not recognise.
2. For a positive vector: load the bundle at `bundle_path`, run your verifier,
   and assert equality of each `expected` field, hex-encoding your digests
   lowercase and base32-encoding your txid.
3. For a negative vector: apply the `mutation` ops to the base bundle, run your
   verifier (honouring `verify_options`), and assert it fails, with your
   equivalent of `failed_check` matching for a `VerificationError`, or a
   schema rejection for `BundleError`.

Report any vector your implementation cannot reproduce; a mismatch is either a
bug in that implementation or a genuine ambiguity in `SPEC.md` worth fixing at
the spec level.

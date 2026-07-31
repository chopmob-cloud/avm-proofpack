# Proofpack bundle format, version 1

A bundle is a JSON object proving that one transaction is part of the
finalised history of an AVM chain (Algorand, Voi, or any fork that generates
state proofs). This document defines the format and the exact verification
algorithm. Normative cryptographic semantics are those of
[go-algorand](https://github.com/algorand/go-algorand); file references below
are to that repository.

## 1. Format

```json
{
  "format": "avm-proofpack",
  "version": 1,
  "chain": {
    "genesis_id": "mainnet-v1.0",
    "genesis_hash_b64": "<32 bytes>"
  },
  "transaction": {
    "txid": "<52-char base32>",
    "round": 63604900
  },
  "block_header_msgpack_b64": "<canonical msgpack of the block header>",
  "stib_msgpack_b64": "<canonical msgpack of the SignedTxnInBlock>",
  "txn_proof": {
    "index": 0,
    "tree_depth": 4,
    "proof_b64": "<tree_depth * 32 bytes>"
  },
  "light_header_proof": {
    "tree_depth": 8,
    "proof_b64": "<tree_depth * 32 bytes>"
  },
  "state_proof_message": {
    "block_headers_commitment_b64": "<32 bytes>",
    "first_attested_round": 63604737,
    "last_attested_round": 63604992,
    "ln_proven_weight": 2231545,
    "voters_commitment_b64": "<bytes>"
  },
  "state_proof_msgpack_b64": "<raw state proof, retained for future tiers>",
  "meta": {
    "light_header_variant": "block_hash",
    "captured_at": "2026-07-31T12:00:00+00:00",
    "source_node": "https://..."
  }
}
```

Notes:

- The light header proof's element index is **not** stored; verifiers must
  derive it as `round - first_attested_round`.
- `meta` is descriptive except `light_header_variant`, which selects the
  light header encoding (section 4).
- `state_proof_msgpack_b64` is carried but not yet consumed by verification;
  it preserves upgradeability to full state proof verification without
  recapture.

## 2. Canonical msgpack

All hashed encodings are go-codec canonical msgpack:

- map keys are uniformly `str` (struct codec tags) or uniformly `int` (e.g.
  the block header's state proof tracking map); `str` keys sort by UTF-8
  bytes, `int` keys numerically;
- integers use the shortest msgpack representation;
- Go `string` fields use the msgpack str family and may contain arbitrary
  non-UTF-8 bytes (TEAL values, application logs); Go `[]byte` fields use the
  bin family;
- zero-valued fields are omitted (`omitempty`) by the object's encoder;
- float and ext types never occur.

A verifier MUST check that re-encoding the decoded block header and stib
reproduces the transported bytes exactly (canonical-form check); without it,
hash comparisons are meaningless.

## 3. Domain separation and hashes

Every hashed object is `hash(domain || encoding)` (`crypto/util.go`,
`HashRep`). Domains used (`protocol/hash.go`):

| Domain  | Object                              | Hash        |
|---------|-------------------------------------|-------------|
| `TX`    | transaction                         | SHA-512/256 for the display txid, SHA-256 for the commitment leaf |
| `STIB`  | signed transaction in block         | SHA-256     |
| `TL`    | transaction Merkle leaf             | SHA-256     |
| `BH`    | block header (block hash)           | SHA-512/256 |
| `B256`  | light block header                  | SHA-256     |
| `MA`    | Merkle internal node                | SHA-256     |
| `MB`    | vector commitment padding leaf      | SHA-256     |

## 4. Verification algorithm

Given a bundle, all offline:

1. **Schema**: validate structure, base64, and that
   `first_attested_round <= round <= last_attested_round`.
2. **Canonical form**: decode header and stib; re-encode; require byte
   equality with the transported bytes.
3. **Block header**: require `rnd == transaction.round`,
   `gh == chain.genesis_hash` (and `== expected genesis hash` if the caller
   pins a chain), `gen == chain.genesis_id` if present, and a 32-byte
   `txn256` commitment.
4. **Transaction identity**: rebuild the standalone transaction from the stib
   (`data/bookkeeping/block.go`, `DecodeSignedTxn`): restore `gen` from the
   header iff the stib's `hgi` flag is set; restore `gh` unconditionally
   (every round bearing a `txn256` commitment is consensus v34+, where
   `RequireGenesisHash` holds). Compute
   `preimage = "TX" || canonical(txn)`; require
   `base32(sha512_256(preimage)) == transaction.txid`; keep
   `t256 = sha256(preimage)`.
5. **Transaction membership**: leaf =
   `sha256("TL" || t256 || sha256("STIB" || stib_bytes))`
   (`data/bookkeeping/txn_merkle.go`). Verify a vector commitment proof
   (section 5) for element `txn_proof.index` at `txn_proof.tree_depth`
   against root `txn256`.
6. **Light header membership**: block hash =
   `sha512_256("BH" || header_bytes)`. Build the light block header
   (`data/bookkeeping/lightBlockHeader.go`), canonically encoded with codec
   tags, zero fields omitted:
   - variant `block_hash` (consensus v39+,
     `StateProofBlockHashInLightHeader`): `{"1": block_hash, "gh": gh,
     "r": round, "tc": txn256}`;
   - variant `seed` (pre-v39): `{"0": seed, "gh": gh, "r": round,
     "tc": txn256}`.
   Leaf = `sha256("B256" || encoding)`. Verify a vector commitment proof for
   element `round - first_attested_round` at `light_header_proof.tree_depth`
   against root `block_headers_commitment`, requiring
   `interval_size <= 2^tree_depth`.

Verification fails closed: any broken link aborts with the failed step named.

Variant note: both variants are honest historical encodings of the same
domain-separated struct, committed by consensus; accepting a bundle's declared
variant cannot admit a forgery, since either encoding must still prove into
the stake-attested commitment.

## 5. Vector commitment proofs

(`crypto/merklearray/`.) A vector commitment stores element `i` of an array
at bit-reversed position `reverse_bits(i, tree_depth)` in a power-of-two
Merkle tree padded with `sha256("MB")` leaves. Internal node =
`sha256("MA" || left || right)`, no length prefixes; a missing child is 32
zero bytes. A single-element proof is the authentication path's sibling
hashes, bottom-up, 32 bytes each; `tree_depth = 0` means the root is the leaf
and the proof is empty.

## 6. Trust model and security considerations

- **Trust root**: the state proof message. Offline verification proves the
  transaction is committed *by that message*. Corroboration (comparing the
  message across independent nodes) reduces node trust; full Falcon
  verification of the state proof (future tier) removes it, leaving only the
  chain's stake-honesty assumption.
- **Capture window**: non-archival nodes prune (~1,000 rounds). Capture
  promptly after the interval closes, or use an archival node.
- **Chain pinning**: a bundle is internally consistent for *its* chain;
  consumers comparing against an expectation MUST pin the genesis hash
  (`--genesis-hash`), or a valid bundle from a different AVM chain would be
  accepted as internally sound.
- **Replay**: a bundle is evidence, not an instruction; it can be copied
  freely. Systems granting value against bundles MUST track redemption
  (e.g. nullify per `(genesis_hash, txid)`) and bind the transaction's
  content to the specific obligation. This library deliberately does not do
  redemption.
- **Privacy**: a bundle reveals the transaction, its block position and its
  content. Treat disclosure as opt-in where receipts hash transaction ids.
- **Non-goals**: no absence proofs (a bundle proves inclusion, never
  non-inclusion), no account-state proofs, no consensus-liveness guarantees.

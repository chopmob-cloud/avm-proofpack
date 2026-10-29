# settlement_evidence_binding_v1

Conformance vectors for the **binding layer** above the raw avm-proofpack bundle:
how a captured bundle is bound to a round-bearing settlement attestation as
portable, offline-verifiable evidence, exactly as the gateway emits it
(`settlement_evidence_service.py`, `receipt_verify.py`).

The raw on-chain anchor (and its 17 tamper negatives) lives in [`../positive`](../positive)
and [`../negative`](../negative). This set does **not** duplicate those; it adds
the layer that binds a verified bundle to a settlement attestation and a charge.

## The binding record

```
scheme                     = "avm-proofpack/1"
settled_payment_ref        = "sha256:" + SHA-256(f"{tenant_id}:{tx_id}:{network}")
round                      = confirmed round of the settling transaction
chain_genesis_id           = the bundle's chain identity
bundle_sha256              = SHA-256( dump_bundle(bundle) )   # NOT JCS
attestation_content_hash   = the round-bearing settlement attestation (JCS)
attestation_settlement_round
```

## Load-bearing rules (a conformant verifier MUST enforce all five)

| Rule | Requirement |
|------|-------------|
| **R1** | `bundle_sha256 == SHA-256( json.dumps(bundle, indent=2, sort_keys=True) + "\n" )` — the bytes `avm_proofpack.dump_bundle` writes. **Not** RFC 8785 JCS. |
| **R2** | `settled_payment_ref` recomputes from `(tenant_id, tx_id, network)`. |
| **R3** | `round == bundle.round == attestation_settlement_round` (the L2 join). |
| **R4** | `chain_genesis_id == bundle.genesis_id` (chain-identity pin). |
| **R5** | the bundle verifies under `avm_proofpack.verify_bundle` (the anchor is real). |

## The non-JCS canary (`seb-v1-r05`)

`bundle_sha256` for a proofpack bundle is a hash of the **indent-2 / sort_keys**
pretty JSON `dump_bundle` writes, chosen so a downloaded `.proofpack.json`
verifies with plain `sha256sum`. It is **deliberately different** from the RFC
8785 JCS compact form the rest of the substrate uses for
`attestation_content_hash`. `seb-v1-r05` publishes the JCS/compact hash as
`bundle_sha256`; a verifier that wrongly assumes JCS would accept it, so a
conformant verifier MUST reject it (rule R1). The two canons are not
interchangeable and a verifier must not silently pick one.

## Run

```
python generate.py        # regenerate deterministically from the fixture
python verify_binding.py  # R1-R5 reimplemented from the contract; exit 0 == all pass
```

Exercised in CI by `tests/test_settlement_evidence_binding.py`.

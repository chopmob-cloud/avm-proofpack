# Show & Tell: portable, offline-verifiable transaction evidence for Algorand and Voi

## Try it

```bash
git clone https://github.com/chopmob-cloud/avm-proofpack.git
cd avm-proofpack
python -m pip install .

# verify a proofpack bundle offline (recomputes every hash + Merkle link from raw bytes)
python -m pytest tests/          # the bundled verification tests

# read the trust model FIRST, it matters (see below)
sed -n '1,80p' SPEC.md
```

A proofpack bundle is one JSON file binding a specific transaction to a chain's state-proof
commitments. Capture it once, and anyone can re-check it forever, offline, with no node and no SDK.

## What it is

An open (Apache-2.0), zero-dependency, pure-Python library for **offline Algorand / Voi state-proof
verification**. It recomputes every hash and Merkle link from raw bytes and confirms the transaction
is committed by the bundle's state-proof message. Works unchanged on any AVM chain that generates
state proofs (verified live against Algorand mainnet and Voi mainnet).

## Read the trust model before you rely on it (we say this up front)

Offline verification proves internal consistency down to **one trust root: the bundle's own
state-proof message**. In this release that message is **not** cryptographically verified offline,
so offline-alone does not prove the message was genuinely produced by the chain's consensus stake.
Raising that trust root is a separate, explicit step:

- `--corroborate` compares the message against independent public nodes today.
- Falcon signature verification of the state proof (removing node trust entirely) is the planned
  next tier.

Treat a structure-only result as "this bundle is internally consistent", not "consensus attests
this". Full detail is in `SPEC.md` section 6. We would rather state the boundary plainly than let
anyone over-read the guarantee.

## What makes it useful

- **Falsifiable settlement claims.** Payment processors and custodians assert "transaction X settled
  on chain Y" backed by their own signature. Algorand and Voi commit, every 256 rounds, to a
  stake-signed vector commitment over block headers, which makes the claim checkable.
- **No node, no SDK, offline forever.** Capture the bundle while public nodes still hold the round;
  re-check it later with pure Python and zero runtime dependencies.
- **Two chains, one verifier.** The same code verifies Algorand and Voi.

## Why we're posting it

"It settled, trust me" should be replaceable with "here is a bundle you can re-check yourself." We
built the verifier and are releasing it openly, with the trust boundary stated in plain language, so
auditors and counterparties can hold settlement claims to a falsifiable standard. No account, no
telemetry.

## License

Apache-2.0. Forks and contributions welcome; attribution is all we ask.

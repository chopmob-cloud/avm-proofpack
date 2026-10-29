"""Offline bundle verification and multi-node corroboration.

Trust model, stated plainly:

- ``verify_bundle`` is fully offline and recomputes every link itself:
  transaction id, stib hash, transaction Merkle leaf, SHA-256 transaction
  commitment membership, block hash, light block header encoding, and
  membership in the state proof's block-headers commitment. Its trust root
  is the *state proof message* embedded in the bundle.
- ``corroborate`` then checks that trust root against independent nodes:
  each queried node must report the byte-identical state proof message for
  the interval. This is not cryptographic verification of the state proof
  itself (Falcon signature verification is a planned tier, see SPEC.md),
  but it reduces the trust assumption from "the capturing node was honest"
  to "the corroborating nodes do not all collude".
"""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field

from . import mpack
from .avm import (
    ReconstructionError,
    block_hash,
    light_block_header_leaf,
    stib_hash_sha256,
    transaction_from_stib,
    txn_hashes,
)
from .bundle import VARIANT_BLOCK_HASH, Bundle
from .client import NodeClient, NodeError
from .hashes import DOMAIN_TXN_MERKLE_LEAF, sha256, txid_from_bytes
from .merkle import ProofError, verify_vector_commitment

__all__ = [
    "VerificationError",
    "VerificationReport",
    "CorroborationResult",
    "CorroborationReport",
    "verify_bundle",
    "corroborate",
]

_MAX_LIGHT_TREE_DEPTH = 20  # a state proof interval is 256 rounds; depth 8
_MAX_TXN_TREE_DEPTH = 32


class VerificationError(Exception):
    """Verification failed. ``check`` names the failed step."""

    def __init__(self, check: str, detail: str) -> None:
        self.check = check
        self.detail = detail
        super().__init__(f"{check}: {detail}")


@dataclass(frozen=True)
class VerificationReport:
    """Successful verification: every derived value, for display or audit."""

    txid: str
    round: int
    genesis_id: str
    genesis_hash_b64: str
    block_hash_b64: str
    txn_commitment_b64: str
    light_header_variant: str
    first_attested_round: int
    last_attested_round: int
    block_headers_commitment_b64: str
    voters_commitment_b64: str
    checks: tuple[str, ...] = field(default_factory=tuple)

    # The trust anchor offline verification reaches. Always "unattested"
    # here: offline verification proves the transaction is committed by the
    # bundle's *own* state proof message, which is unauthenticated data the
    # bundle author supplied. Reducing this ("corroborated") or removing it
    # ("stake-attested") requires corroborate() or, in a future tier, Falcon
    # verification of the state proof. See SPEC.md section 6.
    trust_root: str = "unattested"


def _verify_stake_attested(bundle, state_proof) -> bool:
    """Full consensus authentication of the bundle's state proof. Fail-closed.

    Requires the bundle to carry the full StateProof and the PREVIOUS interval's
    message. The previous message supplies the trusted VotersCommitment and
    LnProvenWeight; the message inside this bundle is authored by the proof builder
    and carries the NEXT interval's values, so using it as the bound would make the
    weight threshold attacker-chosen.

    Any malformed or hostile input returns False; this never raises.
    """
    prev = bundle.previous_message
    if not isinstance(prev, dict):
        return False
    try:
        from .consensus.coins import coin_selection_result
        from .consensus.stateproof import (
            iter_reveals,
            signed_weight_meets_threshold,
            state_proof_message_hash,
            verify_reveal,
        )

        prev_ln = int(prev["ln_proven_weight"])
        if prev_ln < 0:
            return False
        prev_commit = base64.b64decode(prev["voters_commitment_b64"], validate=True)
        if len(prev_commit) != 64:
            return False

        message_hash = state_proof_message_hash(
            block_headers_commitment=bundle.block_headers_commitment,
            voters_commitment=bundle.voters_commitment,
            ln_proven_weight=bundle.ln_proven_weight,
            first_attested_round=bundle.first_attested_round,
            last_attested_round=bundle.last_attested_round,
        )

        weight = state_proof.get("w")
        positions = state_proof.get("pr")
        sig_commit = state_proof.get("c")
        if not isinstance(positions, list) or not positions:
            return False
        if not signed_weight_meets_threshold(weight, prev_ln, len(positions)):
            return False
        for _position, reveal in iter_reveals(state_proof):
            if not verify_reveal(reveal, message_hash, bundle.last_attested_round):
                return False
        return coin_selection_result(
            state_proof,
            participants_commitment=prev_commit,
            ln_proven_weight=prev_ln,
            signature_commitment=sig_commit,
            message_hash=message_hash,
        )
    except Exception:
        return False

def _fail(check: str, detail: str) -> VerificationError:
    return VerificationError(check, detail)


def verify_bundle(
    bundle: Bundle,
    *,
    expected_genesis_hash: bytes | None = None,
) -> VerificationReport:
    """Verify every link of a bundle offline; raise on the first broken one.

    On success returns a :class:`VerificationReport`. ``expected_genesis_hash``
    pins the chain the caller believes this evidence belongs to; without it,
    the bundle's own genesis hash is used and reported (the proof chain is
    still internally sound, but the caller must then check the chain
    identity themselves).
    """
    checks: list[str] = []

    # -- decode the captured canonical bytes ------------------------------
    try:
        header = mpack.decode(bundle.block_header_bytes)
        stib = mpack.decode(bundle.stib_bytes)
    except mpack.DecodeError as exc:
        raise _fail("decode", str(exc)) from exc
    if not isinstance(header, dict) or not isinstance(stib, dict):
        raise _fail("decode", "block header and stib must decode to maps")

    # Canonical-form check: re-encoding must reproduce the captured bytes,
    # otherwise the bytes are not the canonical encoding of what they claim
    # to be and every downstream hash comparison would be meaningless.
    # encode_canonical is guarded: a hostile bundle whose bytes decode but do
    # not re-encode (structurally impossible after the uniform-key decode
    # rule, but defended anyway) must fail closed as a typed VerificationError.
    try:
        header_canonical = mpack.encode_canonical(header)
        stib_canonical = mpack.encode_canonical(stib)
    except mpack.EncodeError as exc:
        raise _fail("canonical", str(exc)) from exc
    if header_canonical != bundle.block_header_bytes:
        raise _fail("canonical", "block header bytes are not in canonical form")
    if stib_canonical != bundle.stib_bytes:
        raise _fail("canonical", "stib bytes are not in canonical form")
    checks.append("canonical-form")

    # -- block header sanity ---------------------------------------------
    header_round = header.get("rnd")
    # Require a genuine integer round: bool subclasses int, and a header
    # encoding 'rnd' as msgpack true/false survives the canonical-form gate,
    # so guard against it explicitly (mirrors bundle.py's _uint) before the
    # equality check below can be satisfied by True == 1.
    if not isinstance(header_round, int) or isinstance(header_round, bool):
        raise _fail("block-header", f"header round is not an integer: {header_round!r}")
    if header_round != bundle.round:
        raise _fail(
            "block-header",
            f"header round {header_round!r} does not match claimed round {bundle.round}",
        )
    header_gh = header.get("gh")
    if header_gh != bundle.genesis_hash:
        raise _fail("block-header", "header genesis hash mismatches bundle chain")
    if expected_genesis_hash is not None and header_gh != expected_genesis_hash:
        raise _fail(
            "chain-identity",
            "bundle is for a different chain than the expected genesis hash",
        )
    # Every chain this library targets (consensus v34+, RequireGenesisHash)
    # emits 'gen'. Require it and require it to match, so genesis_id is never
    # a free-text label a forger can set arbitrarily.
    header_gen = header.get("gen")
    if not isinstance(header_gen, str):
        raise _fail("block-header", "header has no genesis id (gen)")
    if header_gen != bundle.genesis_id:
        raise _fail("block-header", "header genesis id mismatches bundle chain")
    txn_commitment = header.get("txn256")
    if not isinstance(txn_commitment, bytes) or len(txn_commitment) != 32:
        raise _fail(
            "block-header",
            "header has no 32-byte SHA-256 transaction commitment (txn256); "
            "the round may predate consensus v34",
        )
    checks.append("block-header")

    # -- transaction identity --------------------------------------------
    try:
        txn = transaction_from_stib(stib, header)
    except ReconstructionError as exc:
        raise _fail("transaction", str(exc)) from exc
    try:
        txid_512, txid_256 = txn_hashes(txn)
    except mpack.EncodeError as exc:
        raise _fail("transaction", f"transaction is not canonically encodable: {exc}") from exc
    derived_txid = txid_from_bytes(txid_512)
    if derived_txid != bundle.txid:
        raise _fail(
            "transaction",
            f"captured transaction hashes to {derived_txid}, not claimed {bundle.txid}",
        )
    checks.append("transaction-id")

    # -- transaction Merkle leaf -> txn256 commitment ---------------------
    stib_hash = stib_hash_sha256(bundle.stib_bytes)
    leaf = sha256(DOMAIN_TXN_MERKLE_LEAF + txid_256 + stib_hash)
    if bundle.txn_proof_depth > _MAX_TXN_TREE_DEPTH:
        raise _fail("txn-proof", f"implausible tree depth {bundle.txn_proof_depth}")
    try:
        member = verify_vector_commitment(
            leaf,
            bundle.txn_proof_index,
            bundle.txn_proof_depth,
            bundle.txn_proof,
            txn_commitment,
        )
    except ProofError as exc:
        raise _fail("txn-proof", str(exc)) from exc
    if not member:
        raise _fail(
            "txn-proof",
            "transaction leaf does not prove into the block's SHA-256 commitment",
        )
    checks.append("txn-commitment-membership")

    # -- light block header -> block-headers commitment -------------------
    interval_size = bundle.last_attested_round - bundle.first_attested_round + 1
    light_index = bundle.round - bundle.first_attested_round
    if bundle.light_header_proof_depth > _MAX_LIGHT_TREE_DEPTH:
        raise _fail(
            "light-header-proof",
            f"implausible tree depth {bundle.light_header_proof_depth}",
        )
    if interval_size > (1 << bundle.light_header_proof_depth):
        raise _fail(
            "light-header-proof",
            f"interval of {interval_size} rounds cannot fit a depth-"
            f"{bundle.light_header_proof_depth} tree",
        )

    derived_block_hash = block_hash(bundle.block_header_bytes)
    try:
        if bundle.light_header_variant == VARIANT_BLOCK_HASH:
            light_leaf = light_block_header_leaf(
                bundle.round,
                bundle.genesis_hash,
                txn_commitment,
                block_hash_digest=derived_block_hash,
            )
        else:
            seed = header.get("seed")
            if not isinstance(seed, bytes) or len(seed) != 32:
                raise _fail(
                    "light-header",
                    "seed variant requested but header has no 32-byte seed",
                )
            light_leaf = light_block_header_leaf(
                bundle.round,
                bundle.genesis_hash,
                txn_commitment,
                seed=seed,
            )
    except ReconstructionError as exc:
        raise _fail("light-header", str(exc)) from exc

    try:
        member = verify_vector_commitment(
            light_leaf,
            light_index,
            bundle.light_header_proof_depth,
            bundle.light_header_proof,
            bundle.block_headers_commitment,
        )
    except ProofError as exc:
        raise _fail("light-header-proof", str(exc)) from exc
    if not member:
        raise _fail(
            "light-header-proof",
            "light block header does not prove into the state proof's "
            "block-headers commitment",
        )
    checks.append("block-headers-commitment-membership")

    # -- retained state proof is structurally present ---------------------
    # Offline verification does NOT check the state proof's Falcon signatures
    # (that is the future stake-attested tier). But the raw state proof must
    # at least be well-formed msgpack, so the retained blob is genuine
    # material a later tier or an independent verifier can act on, and a
    # forger cannot ship "junk" in its place unnoticed. This is a presence
    # check, not an attestation, hence it does not raise the trust_root.
    try:
        state_proof = mpack.decode(bundle.state_proof_bytes)
    except mpack.DecodeError as exc:
        raise _fail("state-proof-present", f"state proof is not valid msgpack: {exc}") from exc
    if not isinstance(state_proof, dict) or not state_proof:
        raise _fail(
            "state-proof-present",
            "state proof did not decode to a non-empty structure",
        )
    checks.append("state-proof-present")

    # -- stake-attested tier ------------------------------------------------
    # Reachable only when the bundle carries BOTH the full state proof and the
    # previous interval's message. Older bundles carry neither, so they stay at
    # "unattested" -- the degraded path is real, not hypothetical.
    trust_root = "unattested"
    if bundle.state_proof_proof_bytes is not None and bundle.previous_message is not None:
        if _verify_stake_attested(bundle, state_proof):
            checks.append("state-proof-stake-attested")
            trust_root = "stake_attested"

    return VerificationReport(
        txid=bundle.txid,
        round=bundle.round,
        genesis_id=bundle.genesis_id,
        genesis_hash_b64=base64.b64encode(bundle.genesis_hash).decode("ascii"),
        block_hash_b64=base64.b64encode(derived_block_hash).decode("ascii"),
        txn_commitment_b64=base64.b64encode(txn_commitment).decode("ascii"),
        light_header_variant=bundle.light_header_variant,
        first_attested_round=bundle.first_attested_round,
        last_attested_round=bundle.last_attested_round,
        block_headers_commitment_b64=base64.b64encode(
            bundle.block_headers_commitment
        ).decode("ascii"),
        voters_commitment_b64=base64.b64encode(bundle.voters_commitment).decode(
            "ascii"
        ),
        checks=tuple(checks),
        trust_root=trust_root,
    )


@dataclass(frozen=True)
class CorroborationResult:
    node: str
    status: str  # "agree" | "mismatch" | "error"
    detail: str = ""


@dataclass(frozen=True)
class CorroborationReport:
    results: tuple[CorroborationResult, ...]

    @property
    def agreeing(self) -> int:
        return sum(1 for r in self.results if r.status == "agree")


def _message_fields(message: dict) -> tuple:
    return (
        message.get("BlockHeadersCommitment"),
        message.get("FirstAttestedRound"),
        message.get("LastAttestedRound"),
        message.get("LnProvenWeight"),
        message.get("VotersCommitment"),
    )


def corroborate(
    bundle: Bundle, node_urls: list[str], *, timeout: float = 30.0,
    opener=None, validator=None
) -> CorroborationReport:
    """Compare the bundle's state proof message against independent nodes."""
    expected = (
        base64.b64encode(bundle.block_headers_commitment).decode("ascii"),
        bundle.first_attested_round,
        bundle.last_attested_round,
        bundle.ln_proven_weight,
        base64.b64encode(bundle.voters_commitment).decode("ascii"),
    )
    results: list[CorroborationResult] = []
    for url in node_urls:
        try:
            client = NodeClient(url, timeout=timeout, opener=opener, validator=validator)
            response = client.get_json(f"/v2/stateproofs/{bundle.round}")
            message = response.get("Message")
            if not isinstance(message, dict):
                results.append(
                    CorroborationResult(url, "error", "response has no Message object")
                )
                continue
            got = _message_fields(message)
            if got == expected:
                results.append(CorroborationResult(url, "agree"))
            else:
                diffs = [
                    f"{name}: node={g!r} bundle={e!r}"
                    for name, g, e in zip(
                        (
                            "BlockHeadersCommitment",
                            "FirstAttestedRound",
                            "LastAttestedRound",
                            "LnProvenWeight",
                            "VotersCommitment",
                        ),
                        got,
                        expected,
                    )
                    if not (
                        hmac.compare_digest(str(g), str(e))
                        if isinstance(g, str) and isinstance(e, str)
                        else g == e
                    )
                ]
                results.append(
                    CorroborationResult(url, "mismatch", "; ".join(diffs))
                )
        except (NodeError, ValueError) as exc:
            results.append(CorroborationResult(url, "error", str(exc)))
    return CorroborationReport(tuple(results))

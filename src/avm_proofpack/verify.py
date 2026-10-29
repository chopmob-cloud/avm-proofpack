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
    "TrustedVoters",
    "verify_bundle",
    "corroborate",
]

_MAX_LIGHT_TREE_DEPTH = 20  # a state proof interval is 256 rounds; depth 8
_MAX_TXN_TREE_DEPTH = 32
_VOTERS_COMMITMENT_SIZE = 64  # merklesignature root == Sumhash512 digest size


@dataclass(frozen=True)
class TrustedVoters:
    """A caller-supplied trust anchor for the stake-attested tier.

    The participants that sign a state proof attesting round ``R`` are committed
    by the voters commitment published one interval earlier, in the message of
    round ``R - StateProofInterval``. A single bundle cannot authenticate that
    commitment -- it carries it only as unverified ``previous_message`` -- so the
    caller must supply the value it independently trusts: taken from a node it
    trusts, from an earlier verified link (see
    :mod:`avm_proofpack.consensus.chain`), or from a pinned genesis bootstrap.

    Without a ``TrustedVoters`` anchor, :func:`verify_bundle` cannot raise the
    trust root above ``"unattested"``: the stake-attested tier is *defined*
    relative to this anchor, exactly as
    :class:`avm_proofpack.consensus.chain.ChainAnchor` is. ``voters_commitment``
    is the 64-byte signing-interval voters commitment; ``ln_proven_weight`` is
    the matching proven-weight bound (both from that earlier message).
    """

    voters_commitment: bytes
    ln_proven_weight: int


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

    # The trust tier this verification reached. "unattested" (the default):
    # offline verification proved the transaction is committed by the bundle's
    # *own* state proof message, which is unauthenticated data the bundle author
    # supplied. "stake_attested": the caller supplied a TrustedVoters anchor and
    # the full state proof -- its reveals, their membership in the trusted voters
    # and signature commitments, the signed-weight threshold and the coin
    # selection -- authenticated against it (node trust removed, down to the
    # anchor). corroborate() separately reduces the unattested trust root by
    # cross-checking the message against independent nodes. See SPEC.md section 6.
    trust_root: str = "unattested"


def _verify_stake_attested(bundle, state_proof, trusted) -> bool:
    """Full consensus authentication of the bundle's state proof. Fail-closed.

    The trust root is the CALLER-SUPPLIED ``trusted`` :class:`TrustedVoters`
    anchor -- the signing interval's voters commitment and proven-weight bound,
    which a single bundle cannot authenticate on its own. Against that anchor:

    * every revealed participant is bound to the trusted voters commitment
      (participant-tree membership), so its weight and key commitment are real
      and not attacker-supplied;
    * every revealed signature slot is bound to the proof's own signature
      commitment (signature-tree membership), so its running weight ``L`` is
      real;
    * the aggregate signed-weight threshold uses the anchor's proven weight
      (never the message's own, which is part of the attacker-authored signed
      preimage);
    * every reveal's Falcon signature verifies over the reconstructed message
      and its ephemeral key is committed under the now-authenticated participant
      key commitment; and
    * the Fiat-Shamir coins, seeded from the anchor, select exactly the revealed
      positions.

    This mirrors the audited single-link logic in
    :func:`avm_proofpack.consensus.chain.verify_link`. WITHOUT the anchor and the
    two membership bindings the participant weights and key commitments are
    attacker-supplied and the tier is forgeable, so all three are mandatory.

    The bundle's own ``previous_message`` is unauthenticated convenience data: if
    present it must AGREE with the trusted anchor, otherwise the bundle asserts a
    different signing set than the caller trusts and is rejected.

    Any malformed or hostile input returns False; this never raises.
    """
    if trusted is None:
        return False
    try:
        from .consensus.coins import coin_selection_result
        from .consensus.stateproof import (
            iter_reveals,
            signed_weight_meets_threshold,
            state_proof_message_hash,
            verify_participant_tree_membership,
            verify_reveal,
            verify_signature_tree_membership,
        )

        if not isinstance(trusted.voters_commitment, (bytes, bytearray)):
            return False
        anchor_commit = bytes(trusted.voters_commitment)
        if len(anchor_commit) != _VOTERS_COMMITMENT_SIZE:
            return False
        anchor_ln = trusted.ln_proven_weight
        if not isinstance(anchor_ln, int) or isinstance(anchor_ln, bool) or anchor_ln < 0:
            return False

        # The bundle's own previous_message is unauthenticated. If present it
        # must match the trusted anchor, or the bundle is lying about which
        # interval signed it.
        prev = bundle.previous_message
        if isinstance(prev, dict):
            try:
                prev_commit = base64.b64decode(prev["voters_commitment_b64"], validate=True)
                prev_ln = int(prev["ln_proven_weight"])
            except Exception:
                return False
            if len(prev_commit) != _VOTERS_COMMITMENT_SIZE:
                return False
            if not hmac.compare_digest(prev_commit, anchor_commit) or prev_ln != anchor_ln:
                return False

        message_hash = state_proof_message_hash(
            block_headers_commitment=bundle.block_headers_commitment,
            voters_commitment=bundle.voters_commitment,
            ln_proven_weight=bundle.ln_proven_weight,
            first_attested_round=bundle.first_attested_round,
            last_attested_round=bundle.last_attested_round,
        )

        positions = state_proof.get("pr")
        if not isinstance(positions, list) or not positions:
            return False

        # BIND every reveal to the trusted commitment and to the proof's own
        # signature commitment. These two checks are what make the weights and
        # key commitments below trustworthy rather than attacker-chosen.
        if not verify_participant_tree_membership(state_proof, anchor_commit):
            return False
        if not verify_signature_tree_membership(state_proof):
            return False

        # Threshold against the TRUSTED proven-weight bound.
        if not signed_weight_meets_threshold(
            state_proof.get("w"), anchor_ln, len(positions)
        ):
            return False

        for _position, reveal in iter_reveals(state_proof):
            if not verify_reveal(reveal, message_hash, bundle.last_attested_round):
                return False

        return coin_selection_result(
            state_proof,
            participants_commitment=anchor_commit,
            ln_proven_weight=anchor_ln,
            signature_commitment=state_proof.get("c"),
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
    trusted_voters: "TrustedVoters | None" = None,
) -> VerificationReport:
    """Verify every link of a bundle offline; raise on the first broken one.

    On success returns a :class:`VerificationReport`. ``expected_genesis_hash``
    pins the chain the caller believes this evidence belongs to; without it,
    the bundle's own genesis hash is used and reported (the proof chain is
    still internally sound, but the caller must then check the chain
    identity themselves).

    ``trusted_voters`` is the caller's trust anchor for the stake-attested tier
    (see :class:`TrustedVoters`). Only when it is supplied -- and the bundle's
    full state proof authenticates against it -- does the report reach
    ``trust_root == "stake_attested"``. Offline bundle data alone can never reach
    that tier: the signing voters commitment is not self-authenticating, so
    without an anchor the trust root stays ``"unattested"``.
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
    # Reachable only when the caller supplies a TrustedVoters anchor for the
    # signing interval AND the bundle's full state proof authenticates against
    # it. Offline bundle data alone can never reach this tier: the signing
    # voters commitment is not self-authenticating (see TrustedVoters), so
    # without an anchor the verdict stays "unattested" -- the degraded path is
    # the default, not the exception.
    trust_root = "unattested"
    if trusted_voters is not None and _verify_stake_attested(
        bundle, state_proof, trusted_voters
    ):
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

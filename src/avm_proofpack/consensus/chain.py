"""State Proof chain authentication (A5): walk a chain from a trusted anchor.

A4 verified coin selection against caller-supplied inputs. A5 removes that
assumption by walking a chain of State Proofs from a caller-supplied anchor and
proving that each link's signing inputs are the ones the previous link actually
signed.

Interval model (confirmed against real mainnet data):

* a State Proof at round ``R`` attests rounds ``[R-255, R]``;
* its message carries the voters commitment and ``LnProvenWeight`` for the
  **next** interval;
* therefore the proof at ``R`` is verified with the inputs taken from
  ``message(R - interval)``.

The root of trust is the caller's anchor. This module never invents one, never
reads config, and never touches the network. It is shipped in the package. The
single-bundle verifier (:func:`avm_proofpack.verify.verify_bundle`) performs the
equivalent single-link check inline against a ``TrustedVoters`` anchor; use
:func:`authenticate_chain` here to authenticate a multi-interval chain from one
anchor.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from .coins import CoinSelectionError, coin_selection_result
from .stateproof import (
    STRENGTH_TARGET_DEFAULT,
    StateProofError,
    signed_weight_meets_threshold,
    state_proof_message_hash,
    verify_all_reveals,
)

DEFAULT_INTERVAL = 256

_MSG_KEYS = {
    "block_headers_commitment": ("BlockHeadersCommitment", "block_headers_commitment_b64"),
    "voters_commitment": ("VotersCommitment", "voters_commitment_b64"),
    "ln_proven_weight": ("LnProvenWeight", "ln_proven_weight"),
    "first_attested_round": ("FirstAttestedRound", "first_attested_round"),
    "last_attested_round": ("LastAttestedRound", "last_attested_round"),
}


class ChainError(ValueError):
    """Malformed anchor, link or chain topology."""


def _message_value(message: object, field: str) -> object:
    if not isinstance(message, dict):
        raise ChainError(f"message must be a mapping, got {type(message).__name__}")
    for key in _MSG_KEYS[field]:
        if key in message:
            return message[key]
    raise ChainError(f"message is missing {field}")


def _message_bytes(message: object, field: str) -> bytes:
    raw = _message_value(message, field)
    if isinstance(raw, str):
        try:
            raw = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ChainError(f"message field {field} is not valid base64") from exc
    if not isinstance(raw, (bytes, bytearray)):
        raise ChainError(f"message field {field} must be bytes or base64 str")
    return bytes(raw)


def _message_uint(message: object, field: str) -> int:
    raw = _message_value(message, field)
    if type(raw) is not int or raw < 0:
        raise ChainError(f"message field {field} must be a non-negative int")
    return raw


def message_round(message: object) -> int:
    """The round a message's proof attests (``LastAttestedRound``)."""
    return _message_uint(message, "last_attested_round")


@dataclass(frozen=True)
class ChainAnchor:
    """Caller-supplied trust root: a round whose message the caller accepts.

    ``genesis_hash`` is CALLER BOOKKEEPING ONLY. The state proof and its signed
    message contain no genesis field, so this value cannot bind to the chain
    cryptographically -- it only checks that the caller labelled every link
    consistently. Cross-chain replay protection comes from the ANCHOR's voters
    commitment, which is what the proofs are actually verified against.

    Original note:

    ``voters_commitment`` and ``ln_proven_weight`` are that round's message
    fields -- the inputs needed to verify the proof at ``round + interval``.
    ``genesis_hash`` binds the walk to one chain.
    """

    round: int
    voters_commitment: bytes
    ln_proven_weight: int
    genesis_hash: bytes


@dataclass(frozen=True)
class ChainLink:
    """One state proof and the message it signed, plus the chain it belongs to."""

    state_proof: object
    message: object
    genesis_hash: bytes


@dataclass(frozen=True)
class LinkResult:
    """Outcome of verifying a single link against authenticated inputs."""

    round: int
    reveals_ok: bool
    coin_selection_ok: bool

    @property
    def ok(self) -> bool:
        return self.reveals_ok and self.coin_selection_ok


@dataclass(frozen=True)
class ChainResult:
    """Outcome of the whole walk.

    ``is_trust_root`` is true only when every link verified *and* the caller
    supplied an anchor. It means "authenticated back to the anchor you gave me",
    not "authenticated absolutely" -- the anchor itself is caller trust.
    """

    ok: bool
    links_verified: int
    target_round: int
    target_inputs: tuple[bytes, int] | None
    failure: str | None

    def __post_init__(self) -> None:
        """Keep the result internally consistent so a malformed one cannot exist.

        A caller can still build a consistent `ok=True` result by hand -- that is
        inherent to a public dataclass. Only :func:`authenticate_chain` actually
        verifies anything, so a verdict must come from it, not be constructed.
        """
        if self.links_verified < 0:
            raise ChainError("links_verified must be non-negative")
        if self.ok and (self.failure is not None or self.target_inputs is None):
            raise ChainError("an ok ChainResult must carry target_inputs and no failure")
        if not self.ok and self.failure is None:
            raise ChainError("a failed ChainResult must record a failure reason")

    @property
    def is_trust_root(self) -> bool:
        return self.ok and self.failure is None and self.target_inputs is not None


def verify_link(
    link: ChainLink,
    *,
    voters_commitment: bytes,
    ln_proven_weight: int,
    genesis_hash: bytes,
) -> LinkResult:
    """Verify one link using the *previous* interval's authenticated inputs.

    ``voters_commitment``/``ln_proven_weight`` are the signing set and proven
    weight taken from ``message(round - interval)``. They are NOT the message's
    own fields: those describe the next interval and form part of the signed
    preimage.
    """
    if not isinstance(link, ChainLink):
        raise ChainError("link must be a ChainLink")
    if link.genesis_hash != genesis_hash:
        raise ChainError("link genesis hash does not match the anchor")
    state_proof = link.state_proof
    if not isinstance(state_proof, dict):
        raise ChainError("link state_proof must be a mapping")

    message = link.message
    block_headers_commitment = _message_bytes(message, "block_headers_commitment")
    own_voters_commitment = _message_bytes(message, "voters_commitment")
    own_ln_proven_weight = _message_uint(message, "ln_proven_weight")
    first_round = _message_uint(message, "first_attested_round")
    last_round = _message_uint(message, "last_attested_round")

    message_hash = state_proof_message_hash(
        block_headers_commitment=block_headers_commitment,
        voters_commitment=own_voters_commitment,
        ln_proven_weight=own_ln_proven_weight,
        first_attested_round=first_round,
        last_attested_round=last_round,
    )

    try:
        reveals = verify_all_reveals(
            state_proof,
            block_headers_commitment=block_headers_commitment,
            voters_commitment=own_voters_commitment,
            ln_proven_weight=own_ln_proven_weight,
            first_attested_round=first_round,
            last_attested_round=last_round,
            participants_commitment=voters_commitment,
        )
        # SECURITY: the proven-weight bound must use the AUTHENTICATED
        # previous-interval value, NOT the message's own LnProvenWeight.
        # The message is authored by whoever builds the proof, so taking the
        # bound from it makes the threshold attacker-chosen (measured: the
        # minimum passing SignedWeight collapses from ~6.6e14 to 4).
        # verify_all_reveals computes its own threshold from the message
        # value, so we deliberately do not use all_checks_ok here.
        reveals_ok = (
            reveals.all_reveals_ok
            and reveals.sig_tree_ok
            and reveals.part_tree_ok
            and signed_weight_meets_threshold(
                state_proof.get("w"),
                ln_proven_weight,
                len(state_proof.get("pr") or ()),
                STRENGTH_TARGET_DEFAULT,
            )
        )
    except (StateProofError, ValueError):
        reveals_ok = False

    try:
        coin_ok = coin_selection_result(
            state_proof,
            participants_commitment=voters_commitment,
            ln_proven_weight=ln_proven_weight,
            signature_commitment=state_proof["c"],
            message_hash=message_hash,
        )
    except (CoinSelectionError, KeyError, TypeError, ValueError):
        coin_ok = False

    return LinkResult(round=last_round, reveals_ok=reveals_ok, coin_selection_ok=coin_ok)


def authenticate_chain(
    anchor: ChainAnchor,
    links: dict[int, ChainLink],
    *,
    target_round: int,
    interval: int = DEFAULT_INTERVAL,
) -> ChainResult:
    """Walk from ``anchor`` forward to ``target_round``, verifying every link.

    Fails closed on: a malformed anchor, a non-positive or non-dividing
    interval, a target at or before the anchor, a missing link, a link whose
    message attests a different round than its key, a genesis mismatch, or any
    link that fails verification.
    """
    if not isinstance(anchor, ChainAnchor):
        raise ChainError("anchor must be a ChainAnchor")
    if type(interval) is not int or interval <= 0:
        raise ChainError("interval must be a positive int")
    # Validate the anchor itself: a str round previously raised a bare TypeError
    # from the arithmetic below, which is not the documented error surface.
    if type(anchor.round) is not int or anchor.round < 0:
        raise ChainError("anchor.round must be a non-negative int")
    if type(anchor.ln_proven_weight) is not int or anchor.ln_proven_weight < 0:
        raise ChainError("anchor.ln_proven_weight must be a non-negative int")
    if not isinstance(anchor.voters_commitment, (bytes, bytearray)) or len(anchor.voters_commitment) != 64:
        raise ChainError("anchor.voters_commitment must be 64 bytes")
    if not isinstance(anchor.genesis_hash, (bytes, bytearray)) or len(anchor.genesis_hash) != 32:
        raise ChainError("anchor.genesis_hash must be 32 bytes")
    if type(target_round) is not int or target_round <= anchor.round:
        raise ChainError("target_round must be greater than the anchor round")
    if (target_round - anchor.round) % interval:
        raise ChainError("target_round is not on the anchor's interval grid")
    if not isinstance(links, dict):
        raise ChainError("links must be a mapping of round -> ChainLink")

    current_commitment = anchor.voters_commitment
    current_ln = anchor.ln_proven_weight
    round_ = anchor.round + interval
    verified = 0
    target_inputs: tuple[bytes, int] | None = None

    while round_ <= target_round:
        link = links.get(round_)
        if link is None:
            return ChainResult(False, verified, target_round, None,
                               f"missing link for round {round_}")
        if not isinstance(link, ChainLink):
            return ChainResult(False, verified, target_round, None,
                               f"link for round {round_} is not a ChainLink")
        if link.genesis_hash != anchor.genesis_hash:
            return ChainResult(False, verified, target_round, None,
                               f"genesis mismatch at round {round_}")
        try:
            attested = message_round(link.message)
        except ChainError as exc:
            return ChainResult(False, verified, target_round, None, str(exc))
        if attested != round_:
            return ChainResult(False, verified, target_round, None,
                               f"link keyed {round_} attests {attested}")

        result = verify_link(
            link,
            voters_commitment=current_commitment,
            ln_proven_weight=current_ln,
            genesis_hash=anchor.genesis_hash,
        )
        if not result.ok:
            which = "reveals" if not result.reveals_ok else "coin selection"
            return ChainResult(False, verified, target_round, None,
                               f"{which} failed at round {round_}")

        # These are the inputs that authenticated the round we just verified.
        target_inputs = (current_commitment, current_ln)
        verified += 1
        current_commitment = _message_bytes(link.message, "voters_commitment")
        current_ln = _message_uint(link.message, "ln_proven_weight")
        round_ += interval

    return ChainResult(True, verified, target_round, target_inputs, None)

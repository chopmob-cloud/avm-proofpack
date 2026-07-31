"""Payment-fact extraction from verified bundles.

A bundle proves that one transaction is committed by a state proof message;
this module answers the follow-up question every receipt consumer has:
*what does that transaction actually pay?* It decodes the bundle's stib,
restores the standalone transaction exactly as verification does
(:func:`avm_proofpack.avm.transaction_from_stib`), and surfaces the payment
semantics as a plain :class:`PaymentFacts` dataclass.

Extraction is only meaningful over *verified* bytes. An unverified bundle's
stib is an arbitrary byte string; quoting fields out of it would let a
forger put any amount or receiver next to a real-looking txid. So
:func:`extract_payment` verifies the bundle itself by default, and only
skips re-verification when the caller passes the
:class:`~avm_proofpack.verify.VerificationReport` that
:func:`~avm_proofpack.verify.verify_bundle` returned for this same bundle
(cross-checked against the bundle's binding fields). This design was chosen
over a mandatory report argument because it matches the library's existing
"a bundle that exists, verifies" posture (see ``capture.py``): the safe
path is the default path, and the report parameter is purely an
optimisation for callers (like the CLI) that have already verified.

Scope boundary, stated plainly: extraction covers the TOP-LEVEL transaction
only. For ``appl`` transactions, a v1 bundle proves that the application
call is committed, but the *effects* of that call, inner transactions,
state deltas, logs, are recorded in the stib's apply data and are NOT
independently provable from a v1 bundle (there is no commitment path from
apply data to the state proof message in this format). ``extract_payment``
therefore returns only the call's own fields for ``appl`` and records the
limitation explicitly in :attr:`PaymentFacts.limitations`. See SPEC.md
section 6.

Address rendering follows go-algorand ``data/basics/address.go``: a textual
address is ``base32(public_key || checksum)`` without padding, where the
checksum is the last 4 bytes of ``sha512_256(public_key)`` (58 characters
total).
"""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field

from . import mpack
from .avm import ReconstructionError, transaction_from_stib
from .bundle import Bundle
from .hashes import sha256, sha512_256
from .verify import VerificationReport, verify_bundle

__all__ = [
    "ExtractionError",
    "PaymentFacts",
    "encode_address",
    "extract_payment",
    "matches_reference",
]

_CHECKSUM_BYTES = 4
_ZERO_ADDRESS_KEY = b"\x00" * 32

#: The stated v1 limitation for application calls, recorded verbatim in
#: :attr:`PaymentFacts.limitations` so downstream consumers cannot miss it.
APPL_INNER_TXN_LIMITATION = (
    "appl: a v1 bundle proves the application call is committed, but inner "
    "transactions, state deltas and logs (the call's effects) are NOT proven "
    "by this bundle; do not treat this evidence as proof of any payment made "
    "by the application"
)


class ExtractionError(ValueError):
    """Raised when payment facts cannot be extracted coherently."""


def encode_address(public_key: bytes) -> str:
    """Render a 32-byte public key as a standard Algorand textual address.

    go-algorand ``data/basics/address.go``: the checksum is the last 4
    bytes of ``sha512_256(public_key)``; the address is the unpadded
    base32 of ``public_key || checksum``, always 58 characters.
    """
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ExtractionError(
            f"address public key must be 32 bytes, got "
            f"{len(public_key) if isinstance(public_key, bytes) else type(public_key).__name__}"
        )
    checksum = sha512_256(public_key)[-_CHECKSUM_BYTES:]
    return base64.b32encode(public_key + checksum).decode("ascii").rstrip("=")


def decode_address(address: str) -> bytes:
    """Decode a 58-character textual address back to its 32-byte public key.

    The checksum is recomputed and required to match, so a mistyped or
    truncated address fails closed rather than silently denoting a
    different account.
    """
    if not isinstance(address, str) or len(address) != 58:
        raise ExtractionError(
            "address must be a 58-character base32 string, got "
            f"{len(address) if isinstance(address, str) else type(address).__name__}"
        )
    try:
        raw = base64.b32decode(address + "======")
    except Exception as exc:
        raise ExtractionError(f"address is not valid base32: {exc}") from exc
    if len(raw) != 32 + _CHECKSUM_BYTES:
        raise ExtractionError(
            f"decoded address is {len(raw)} bytes, expected {32 + _CHECKSUM_BYTES}"
        )
    public_key, checksum = raw[:32], raw[32:]
    if not hmac.compare_digest(sha512_256(public_key)[-_CHECKSUM_BYTES:], checksum):
        raise ExtractionError("address checksum mismatch")
    return public_key


@dataclass(frozen=True)
class PaymentFacts:
    """Payment semantics of a bundle's top-level transaction.

    Field semantics by transaction type:

    - ``pay``: ``amount`` is microalgos (codec tag ``amt``), ``receiver``
      is ``rcv``; ``close_remainder_to`` is set when the transaction also
      closes the sender's account (``close``), sending its entire
      remaining balance there, an effect strictly larger than ``amount``.
    - ``axfer``: ``amount`` is ASA base units (``aamt``), ``receiver`` is
      ``arcv``, ``asset_id`` is ``xaid``; ``asset_close_to`` (``aclose``)
      likewise moves the sender's whole remaining asset balance.
    - ``appl``: ``app_id`` is set; ``amount``/``receiver`` are ``None``
      and ``limitations`` states that inner-transaction effects are not
      proven by a v1 bundle.
    - any other type: identity fields only, with a limitation note.

    Omitted zero fields (canonical msgpack ``omitempty``) surface as their
    go-algorand zero values: amount 0, fee 0, and the zero address for an
    omitted receiver, exactly as a node would report them.
    """

    txid: str
    round: int
    genesis_id: str
    genesis_hash_b64: str
    txn_type: str
    sender: str
    fee: int
    first_valid: int
    last_valid: int
    note: bytes | None = None
    group_b64: str | None = None
    receiver: str | None = None
    amount: int | None = None
    close_remainder_to: str | None = None
    asset_id: int | None = None
    asset_close_to: str | None = None
    app_id: int | None = None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        """JSON-safe dict view (bytes fields rendered as base64)."""
        return {
            "txid": self.txid,
            "round": self.round,
            "genesis_id": self.genesis_id,
            "genesis_hash_b64": self.genesis_hash_b64,
            "txn_type": self.txn_type,
            "sender": self.sender,
            "fee": self.fee,
            "first_valid": self.first_valid,
            "last_valid": self.last_valid,
            "note_b64": (
                base64.b64encode(self.note).decode("ascii")
                if self.note is not None
                else None
            ),
            "group_b64": self.group_b64,
            "receiver": self.receiver,
            "amount": self.amount,
            "close_remainder_to": self.close_remainder_to,
            "asset_id": self.asset_id,
            "asset_close_to": self.asset_close_to,
            "app_id": self.app_id,
            "limitations": list(self.limitations),
        }


def _uint_or_zero(txn: dict, key: str) -> int:
    """Read an optional canonical uint field; omitted means zero (omitempty)."""
    value = txn.get(key, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ExtractionError(f"transaction field {key!r} is not a non-negative integer")
    return value


def _address_or_zero(txn: dict, key: str) -> str:
    """Read an optional address field; omitted means the zero address."""
    value = txn.get(key, _ZERO_ADDRESS_KEY)
    if not isinstance(value, bytes) or len(value) != 32:
        raise ExtractionError(f"transaction field {key!r} is not a 32-byte address")
    return encode_address(value)


def _address_if_present(txn: dict, key: str) -> str | None:
    value = txn.get(key)
    if value is None:
        return None
    if not isinstance(value, bytes) or len(value) != 32:
        raise ExtractionError(f"transaction field {key!r} is not a 32-byte address")
    return encode_address(value)


def _type_specific_fields(txn: dict) -> dict:
    """Payment semantics per transaction type, as PaymentFacts field values.

    Split out from :func:`extract_payment` so the per-type field mapping
    (including the close-out and clawback flags, which the live fixtures do
    not exercise) is unit-testable against synthetic transaction maps.
    """
    txn_type = txn.get("type")
    if not isinstance(txn_type, str) or not txn_type:
        raise ExtractionError("transaction has no 'type' field")

    limitations: list[str] = []
    if "rekey" in txn:
        limitations.append(
            "rekey: this transaction also changed the sender's authorized "
            "spending key ('rekey' present)"
        )

    fields: dict = {"txn_type": txn_type}
    if txn_type == "pay":
        fields["amount"] = _uint_or_zero(txn, "amt")
        fields["receiver"] = _address_or_zero(txn, "rcv")
        fields["close_remainder_to"] = _address_if_present(txn, "close")
        if fields["close_remainder_to"] is not None:
            limitations.append(
                "close: the sender's ENTIRE remaining balance was also sent "
                "to close_remainder_to; the transferred value exceeds 'amount'"
            )
    elif txn_type == "axfer":
        asset_id = _uint_or_zero(txn, "xaid")
        if asset_id == 0:
            raise ExtractionError("axfer transaction has no asset id (xaid)")
        fields["asset_id"] = asset_id
        fields["amount"] = _uint_or_zero(txn, "aamt")
        fields["receiver"] = _address_or_zero(txn, "arcv")
        fields["asset_close_to"] = _address_if_present(txn, "aclose")
        if fields["asset_close_to"] is not None:
            limitations.append(
                "aclose: the sender's ENTIRE remaining asset balance was also "
                "sent to asset_close_to; the transferred value exceeds 'amount'"
            )
        if "asnd" in txn:
            limitations.append(
                "asnd: clawback transfer; the asset moved from the 'asnd' "
                "account, not from the outer sender"
            )
    elif txn_type == "appl":
        # apid is 0 (omitted) for application creation calls.
        fields["app_id"] = _uint_or_zero(txn, "apid")
        limitations.append(APPL_INNER_TXN_LIMITATION)
    else:
        limitations.append(
            f"{txn_type}: no payment semantics extracted for this transaction "
            "type; only identity fields are surfaced"
        )
    fields["limitations"] = tuple(limitations)
    return fields


def _require_matching_report(bundle: Bundle, report: VerificationReport) -> None:
    """Refuse a report that does not bind to this exact bundle.

    A VerificationReport only exists for a bundle that passed
    :func:`~avm_proofpack.verify.verify_bundle`; the binding fields below
    (txid, round, genesis hash) are all values verification derived from
    the bundle's raw bytes, so equality here ties the report to these
    bytes and blocks the obvious misuse of pairing bundle A with the
    report of bundle B.
    """
    genesis_b64 = base64.b64encode(bundle.genesis_hash).decode("ascii")
    if (
        report.txid != bundle.txid
        or report.round != bundle.round
        or report.genesis_hash_b64 != genesis_b64
    ):
        raise ExtractionError(
            "verification report does not match this bundle (txid, round or "
            "genesis hash differ); pass the report returned by verify_bundle "
            "for this exact bundle, or omit it to verify internally"
        )


def extract_payment(
    bundle: Bundle,
    *,
    report: VerificationReport | None = None,
) -> PaymentFacts:
    """Extract the top-level transaction's payment facts from a verified bundle.

    If ``report`` is ``None`` (the default and the safe path), the bundle
    is verified internally first and any
    :class:`~avm_proofpack.verify.VerificationError` propagates: extraction
    from an unverifiable bundle is impossible, not merely inadvisable.
    Passing the :class:`~avm_proofpack.verify.VerificationReport` previously
    returned by :func:`~avm_proofpack.verify.verify_bundle` *for this same
    bundle* skips the redundant re-verification; the report is cross-checked
    against the bundle's binding fields and rejected on any mismatch.

    Covers the TOP-LEVEL transaction only. For ``appl`` transactions the
    returned facts carry an explicit limitation: inner-transaction effects
    are not proven by a v1 bundle (SPEC.md section 6).
    """
    if report is None:
        report = verify_bundle(bundle)  # VerificationError propagates: fail closed
    else:
        _require_matching_report(bundle, report)

    # Post-verification these decodes cannot fail (verification already
    # decoded and canonical-checked the same bytes); the guards keep the
    # failure typed if this function is ever reached with a hand-built
    # Bundle object and a forged report.
    try:
        header = mpack.decode(bundle.block_header_bytes)
        stib = mpack.decode(bundle.stib_bytes)
        if not isinstance(header, dict) or not isinstance(stib, dict):
            raise ExtractionError("block header and stib must decode to maps")
        txn = transaction_from_stib(stib, header)
    except (mpack.DecodeError, ReconstructionError) as exc:
        raise ExtractionError(f"cannot reconstruct transaction: {exc}") from exc

    sender = txn.get("snd")
    if not isinstance(sender, bytes) or len(sender) != 32:
        raise ExtractionError("transaction has no 32-byte sender (snd)")

    note = txn.get("note")
    if note is not None and not isinstance(note, bytes):
        raise ExtractionError("transaction 'note' is not bytes")
    group = txn.get("grp")
    if group is not None and (not isinstance(group, bytes) or len(group) != 32):
        raise ExtractionError("transaction 'grp' is not a 32-byte group id")

    return PaymentFacts(
        txid=bundle.txid,
        round=bundle.round,
        genesis_id=bundle.genesis_id,
        genesis_hash_b64=base64.b64encode(bundle.genesis_hash).decode("ascii"),
        sender=encode_address(sender),
        fee=_uint_or_zero(txn, "fee"),
        first_valid=_uint_or_zero(txn, "fv"),
        last_valid=_uint_or_zero(txn, "lv"),
        note=note,
        group_b64=(
            base64.b64encode(group).decode("ascii") if group is not None else None
        ),
        **_type_specific_fields(txn),
    )


def matches_reference(
    bundle: Bundle,
    ref_hex: str,
    *,
    template: str,
    report: VerificationReport | None = None,
    **fields: str,
) -> bool:
    """Check a hashed payment reference against a verified bundle's txid.

    Receipt schemes that hide raw transaction ids publish a hashed
    reference instead, e.g. ``sha256("{tenant}:{txid}:{network}")`` (see
    docs/INTEGRATION.md, "Privacy"). At disclosure time this helper closes
    the loop: it verifies the bundle (same gating as
    :func:`extract_payment`), formats ``template`` with the verified
    ``txid`` plus the caller-supplied ``fields``, hashes the UTF-8 bytes
    with SHA-256, and compares against ``ref_hex`` in constant time
    (``hmac.compare_digest``), so the comparison itself leaks nothing
    about how close a guessed reference was.

    The template is caller-supplied and generic; the only reserved
    placeholder is ``{txid}``, which always comes from the verified bundle
    and cannot be overridden. A malformed ``ref_hex`` or an unresolvable
    template raises :class:`ExtractionError` rather than returning
    ``False``: garbage input is an integration bug, not a mismatch.
    """
    try:
        expected = bytes.fromhex(ref_hex)
    except (TypeError, ValueError) as exc:
        raise ExtractionError(f"ref_hex is not valid hex: {exc}") from exc
    if len(expected) != 32:
        raise ExtractionError(
            f"ref_hex must be a 32-byte SHA-256 digest, got {len(expected)} bytes"
        )
    if "txid" in fields:
        raise ExtractionError(
            "the {txid} placeholder is reserved and always taken from the "
            "verified bundle; do not pass txid as a field"
        )

    facts = extract_payment(bundle, report=report)
    try:
        preimage = template.format(txid=facts.txid, **fields)
    except (KeyError, IndexError, ValueError) as exc:
        raise ExtractionError(f"cannot format reference template: {exc}") from exc
    return hmac.compare_digest(sha256(preimage.encode("utf-8")), expected)

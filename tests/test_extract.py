"""Payment-fact extraction: fixture vectors, address encoding, references.

Expected values are decoded from the live-captured fixtures themselves and
pinned exactly: extraction must reproduce, byte for byte, what the chain
committed, not what a node or a capturer quoted.
"""

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from avm_proofpack.bundle import Bundle
from avm_proofpack.extract import (
    APPL_INNER_TXN_LIMITATION,
    ExtractionError,
    _type_specific_fields,
    decode_address,
    encode_address,
    extract_payment,
    matches_reference,
)
from avm_proofpack.verify import VerificationError, verify_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _bundle(name: str) -> Bundle:
    return Bundle.from_dict(_load(name))


# ---------------------------------------------------------------------------
# Address encoding (go-algorand data/basics/address.go)
# ---------------------------------------------------------------------------

# The canonical zero address is a published go-algorand constant, so this
# vector checks the checksum construction against an external truth.
ZERO_ADDRESS = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

ADDRESS_VECTORS = [
    (b"\x00" * 32, ZERO_ADDRESS),
    # Sender keys of the live fixtures (values pinned from the stib bytes).
    (
        base64.b64decode("BaL8/p58AkelA1aXWgGz8vXiERNh+xCp1V5OfVfJOz4="),
        "AWRPZ7U6PQBEPJIDK2LVUANT6L26EEITMH5RBKOVLZHH2V6JHM7BPNQN6U",
    ),
    (
        base64.b64decode("eTS0e8rfsxSsYgPa6xRtQFJrh6jSEruPGAHQcSGyVv8="),
        "PE2LI66K36ZRJLDCAPNOWFDNIBJGXB5I2IJLXDYYAHIHCINSK37UCYVLJM",
    ),
]


@pytest.mark.parametrize("public_key,expected", ADDRESS_VECTORS)
def test_encode_address_vectors(public_key, expected):
    address = encode_address(public_key)
    assert address == expected
    assert len(address) == 58


@pytest.mark.parametrize("public_key,expected", ADDRESS_VECTORS)
def test_address_round_trip(public_key, expected):
    assert decode_address(encode_address(public_key)) == public_key


def test_encode_address_rejects_wrong_length():
    with pytest.raises(ExtractionError):
        encode_address(b"\x01" * 31)
    with pytest.raises(ExtractionError):
        encode_address(b"\x01" * 33)
    with pytest.raises(ExtractionError):
        encode_address("not bytes")


def test_decode_address_rejects_bad_checksum():
    good = encode_address(b"\x07" * 32)
    tampered = ("A" if good[0] != "A" else "B") + good[1:]
    with pytest.raises(ExtractionError):
        decode_address(tampered)
    with pytest.raises(ExtractionError):
        decode_address(good[:-1])


# ---------------------------------------------------------------------------
# Fixture extraction: exact expected values
# ---------------------------------------------------------------------------

def test_extract_algorand_pay():
    facts = extract_payment(_bundle("algorand-mainnet-pay"))
    assert facts.txid == "CCQU5VMM5K5OHNLK6IVRI5XTKI57HIODHPLKGGS4RZ5GWP3OZYHA"
    assert facts.round == 63604900
    assert facts.genesis_id == "mainnet-v1.0"
    assert facts.genesis_hash_b64 == "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
    assert facts.txn_type == "pay"
    assert facts.sender == (
        "AWRPZ7U6PQBEPJIDK2LVUANT6L26EEITMH5RBKOVLZHH2V6JHM7BPNQN6U"
    )
    assert facts.receiver == (
        "JFNBMPWLEPDNVG4CGMAHYMJGCYMPQHIJTIVAXJ5EPUQ67UK2D4WZAXR2CE"
    )
    assert facts.amount == 230000
    assert facts.fee == 1000
    assert facts.first_valid == 63604896
    assert facts.last_valid == 63605896
    assert facts.note is None
    assert facts.group_b64 is None
    assert facts.close_remainder_to is None
    assert facts.asset_id is None
    assert facts.asset_close_to is None
    assert facts.app_id is None
    assert facts.limitations == ()


def test_extract_algorand_appl():
    facts = extract_payment(_bundle("algorand-mainnet-appl"))
    assert facts.txid == "KOERHNGJPLUUQK4WJ4YPY5OC3BOINDH2J4E6HM2RYARSJ5R3FAYA"
    assert facts.round == 63604900
    assert facts.txn_type == "appl"
    assert facts.sender == (
        "TIGER63IT7F5HDLXJYLXRPXGWAT6JCLWCN7OJBR4VGYTFQTPDNCKZHCDAU"
    )
    assert facts.app_id == 1284326447
    assert facts.fee == 2001
    assert facts.first_valid == 63604898
    assert facts.last_valid == 63605898
    # An application call proves the call, never its inner effects.
    assert facts.amount is None
    assert facts.receiver is None
    assert APPL_INNER_TXN_LIMITATION in facts.limitations


def test_extract_voi_appl():
    facts = extract_payment(_bundle("voi-mainnet-appl"))
    assert facts.txid == "YPKQYJQDVICJV6PHRSTPZW6MFWVCNPXOV2BZWRZVMJ2CFPGTVCYA"
    assert facts.round == 21209054
    assert facts.genesis_id == "voimain-v1.0"
    assert facts.genesis_hash_b64 == "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
    assert facts.txn_type == "appl"
    assert facts.sender == (
        "PE2LI66K36ZRJLDCAPNOWFDNIBJGXB5I2IJLXDYYAHIHCINSK37UCYVLJM"
    )
    assert facts.app_id == 47138069
    assert facts.fee == 1000
    assert facts.first_valid == 21209052
    assert facts.last_valid == 21210052
    assert facts.note == b"arccjs-v2.10.6:u post_price transaction"
    assert facts.group_b64 == "DbF8+yBS33lBwb1jp26mT/pMXaVUaJ7vNWMmT8FWcHo="
    assert APPL_INNER_TXN_LIMITATION in facts.limitations


def test_as_dict_is_json_safe():
    facts = extract_payment(_bundle("voi-mainnet-appl"))
    rendered = json.dumps(facts.as_dict(), sort_keys=True)
    parsed = json.loads(rendered)
    assert parsed["note_b64"] == base64.b64encode(facts.note).decode("ascii")
    assert parsed["amount"] is None
    assert parsed["limitations"] == list(facts.limitations)


# ---------------------------------------------------------------------------
# Extraction is impossible without verification
# ---------------------------------------------------------------------------

def test_extract_refuses_tampered_bundle():
    """A tampered stib must abort extraction inside internal verification."""
    data = copy.deepcopy(_load("algorand-mainnet-pay"))
    raw = bytearray(base64.b64decode(data["stib_msgpack_b64"]))
    raw[5] ^= 0x01
    data["stib_msgpack_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(VerificationError):
        extract_payment(Bundle.from_dict(data))


def test_extract_rejects_mismatched_report():
    """A report from bundle A must not unlock extraction of bundle B."""
    report_a = verify_bundle(_bundle("algorand-mainnet-pay"))
    bundle_b = _bundle("voi-mainnet-appl")
    with pytest.raises(ExtractionError):
        extract_payment(bundle_b, report=report_a)


def test_extract_accepts_matching_report():
    bundle = _bundle("algorand-mainnet-pay")
    report = verify_bundle(bundle)
    facts = extract_payment(bundle, report=report)
    assert facts.amount == 230000


# ---------------------------------------------------------------------------
# Per-type field mapping unit vectors (paths the live fixtures do not hit)
# ---------------------------------------------------------------------------

_PK_A = bytes(range(32))
_PK_B = bytes(range(1, 33))
_PK_C = bytes(range(2, 34))


def test_fields_pay_with_close():
    fields = _type_specific_fields(
        {"type": "pay", "amt": 5, "rcv": _PK_A, "close": _PK_B}
    )
    assert fields["amount"] == 5
    assert fields["receiver"] == encode_address(_PK_A)
    assert fields["close_remainder_to"] == encode_address(_PK_B)
    assert any("close" in note for note in fields["limitations"])


def test_fields_pay_zero_omitted():
    """omitempty: an omitted amt/rcv is a zero payment to the zero address."""
    fields = _type_specific_fields({"type": "pay"})
    assert fields["amount"] == 0
    assert fields["receiver"] == encode_address(b"\x00" * 32)
    assert fields["close_remainder_to"] is None
    assert fields["limitations"] == ()


def test_fields_axfer_with_close_and_clawback():
    fields = _type_specific_fields(
        {
            "type": "axfer",
            "xaid": 123,
            "aamt": 7,
            "arcv": _PK_A,
            "aclose": _PK_B,
            "asnd": _PK_C,
        }
    )
    assert fields["asset_id"] == 123
    assert fields["amount"] == 7
    assert fields["receiver"] == encode_address(_PK_A)
    assert fields["asset_close_to"] == encode_address(_PK_B)
    assert any("aclose" in note for note in fields["limitations"])
    assert any("asnd" in note for note in fields["limitations"])


def test_fields_axfer_requires_asset_id():
    with pytest.raises(ExtractionError):
        _type_specific_fields({"type": "axfer", "aamt": 7, "arcv": _PK_A})


def test_fields_other_type_flagged():
    fields = _type_specific_fields({"type": "keyreg"})
    assert fields.get("amount") is None
    assert any("keyreg" in note for note in fields["limitations"])


def test_fields_rekey_flagged():
    fields = _type_specific_fields({"type": "pay", "rekey": _PK_A})
    assert any("rekey" in note for note in fields["limitations"])


def test_fields_missing_type_fails():
    with pytest.raises(ExtractionError):
        _type_specific_fields({"amt": 5})


# ---------------------------------------------------------------------------
# Hashed payment references (docs/INTEGRATION.md privacy loop)
# ---------------------------------------------------------------------------

def _reference_hex(preimage: str) -> str:
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def test_matches_reference_positive():
    bundle = _bundle("voi-mainnet-appl")
    txid = "YPKQYJQDVICJV6PHRSTPZW6MFWVCNPXOV2BZWRZVMJ2CFPGTVCYA"
    ref = _reference_hex(f"acme:{txid}:voi-mainnet")
    assert matches_reference(
        bundle,
        ref,
        template="{tenant}:{txid}:{network}",
        tenant="acme",
        network="voi-mainnet",
    )


def test_matches_reference_negative():
    bundle = _bundle("voi-mainnet-appl")
    txid = "YPKQYJQDVICJV6PHRSTPZW6MFWVCNPXOV2BZWRZVMJ2CFPGTVCYA"
    ref = _reference_hex(f"acme:{txid}:voi-mainnet")
    assert not matches_reference(
        bundle,
        ref,
        template="{tenant}:{txid}:{network}",
        tenant="evil-corp",
        network="voi-mainnet",
    )


def test_matches_reference_rejects_malformed_ref():
    bundle = _bundle("voi-mainnet-appl")
    with pytest.raises(ExtractionError):
        matches_reference(bundle, "zz" * 32, template="{txid}")
    with pytest.raises(ExtractionError):
        matches_reference(bundle, "ab" * 16, template="{txid}")  # 16 bytes


def test_matches_reference_txid_not_overridable():
    bundle = _bundle("voi-mainnet-appl")
    ref = _reference_hex("A" * 52)
    with pytest.raises(ExtractionError):
        matches_reference(bundle, ref, template="{txid}", txid="A" * 52)


def test_matches_reference_unresolved_placeholder():
    bundle = _bundle("voi-mainnet-appl")
    ref = _reference_hex("anything")
    with pytest.raises(ExtractionError):
        matches_reference(bundle, ref, template="{tenant}:{txid}")


def test_matches_reference_requires_verification():
    data = copy.deepcopy(_load("voi-mainnet-appl"))
    raw = bytearray(base64.b64decode(data["stib_msgpack_b64"]))
    raw[5] ^= 0x01
    data["stib_msgpack_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    ref = _reference_hex("anything")
    with pytest.raises(VerificationError):
        matches_reference(Bundle.from_dict(data), ref, template="{txid}")

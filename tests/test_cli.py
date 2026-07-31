"""CLI: chain pinning by name, extract subcommand, trust-root gating.

Everything here is offline: no test may reach a node, so --corroborate is
only exercised through its failure paths ('default' without --chain).
"""

import base64
import copy
import json
from pathlib import Path

import pytest

from avm_proofpack.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
PAY = str(FIXTURES / "algorand-mainnet-pay.json")
APPL = str(FIXTURES / "algorand-mainnet-appl.json")
VOI = str(FIXTURES / "voi-mainnet-appl.json")


def _tampered_bundle_path(tmp_path) -> str:
    data = copy.deepcopy(
        json.loads(Path(PAY).read_text(encoding="utf-8"))
    )
    raw = bytearray(base64.b64decode(data["stib_msgpack_b64"]))
    raw[5] ^= 0x01
    data["stib_msgpack_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# verify --chain
# ---------------------------------------------------------------------------

def test_verify_chain_accepts_matching_chain(capsys):
    code = main(["verify", PAY, "--chain", "algorand-mainnet", "--accept-unattested"])
    assert code == 0
    out = capsys.readouterr().out
    assert "verification: OK" in out


def test_verify_chain_rejects_wrong_chain(capsys):
    code = main(["verify", PAY, "--chain", "voi-mainnet", "--accept-unattested"])
    assert code == 1
    err = capsys.readouterr().err
    assert "chain-identity" in err


def test_verify_voi_chain_accepts_voi_fixture(capsys):
    code = main(["verify", VOI, "--chain", "voi-mainnet", "--accept-unattested"])
    assert code == 0


def test_verify_unknown_chain_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["verify", PAY, "--chain", "nonexistent-chain"])
    assert excinfo.value.code == 2


def test_chain_and_genesis_hash_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "verify",
                PAY,
                "--chain",
                "algorand-mainnet",
                "--genesis-hash",
                "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
            ]
        )
    assert excinfo.value.code == 2


def test_corroborate_default_requires_chain(capsys):
    code = main(["verify", PAY, "--corroborate", "default"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--corroborate default requires --chain" in err


def test_verify_still_gates_unattested(capsys):
    """--chain does not weaken the trust-root gate."""
    code = main(["verify", PAY, "--chain", "algorand-mainnet"])
    assert code == 2
    err = capsys.readouterr().err
    assert "NOT attested" in err


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------

def test_extract_pay_outputs_json(capsys):
    code = main(
        ["extract", PAY, "--chain", "algorand-mainnet", "--accept-unattested"]
    )
    assert code == 0
    captured = capsys.readouterr()
    facts = json.loads(captured.out)  # stdout must be pure JSON
    assert facts["txn_type"] == "pay"
    assert facts["amount"] == 230000
    assert facts["sender"] == (
        "AWRPZ7U6PQBEPJIDK2LVUANT6L26EEITMH5RBKOVLZHH2V6JHM7BPNQN6U"
    )
    assert facts["receiver"] == (
        "JFNBMPWLEPDNVG4CGMAHYMJGCYMPQHIJTIVAXJ5EPUQ67UK2D4WZAXR2CE"
    )
    assert facts["limitations"] == []
    # Human-facing status goes to stderr, keeping stdout machine-readable.
    assert "verification: OK" in captured.err


def test_extract_appl_flags_inner_txn_limitation(capsys):
    code = main(
        ["extract", APPL, "--chain", "algorand-mainnet", "--accept-unattested"]
    )
    assert code == 0
    facts = json.loads(capsys.readouterr().out)
    assert facts["txn_type"] == "appl"
    assert facts["app_id"] == 1284326447
    assert facts["amount"] is None
    assert any("inner" in note for note in facts["limitations"])


def test_extract_gates_unattested(capsys):
    """Without corroboration or --accept-unattested, no facts are printed."""
    code = main(["extract", PAY, "--chain", "algorand-mainnet"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "NOT attested" in captured.err


def test_extract_refuses_tampered_bundle(tmp_path, capsys):
    code = main(
        [
            "extract",
            _tampered_bundle_path(tmp_path),
            "--chain",
            "algorand-mainnet",
            "--accept-unattested",
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "VERIFICATION FAILED" in captured.err


def test_extract_rejects_wrong_chain(capsys):
    code = main(["extract", VOI, "--chain", "algorand-mainnet", "--accept-unattested"])
    assert code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "chain-identity" in captured.err


def test_extract_genesis_hash_pinning_still_works(capsys):
    code = main(
        [
            "extract",
            VOI,
            "--genesis-hash",
            "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=",
            "--accept-unattested",
        ]
    )
    assert code == 0
    facts = json.loads(capsys.readouterr().out)
    assert facts["genesis_id"] == "voimain-v1.0"

"""Chain registry: identity constants, CAIP-2 derivation, fixture agreement.

The registry's constants must never drift from the evidence this repository
already carries: the algorand-mainnet and voi-mainnet hashes are asserted
against the live-captured fixtures, whose offline verification binds those
hashes into stake-committed structures. algorand-testnet has no fixture
here and is asserted only against its pinned literal.
"""

import base64
import json
from pathlib import Path

import pytest

from avm_proofpack.bundle import Bundle
from avm_proofpack.chains import CHAINS, UnknownChainError, get_chain
from avm_proofpack.verify import verify_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_registry_names():
    assert set(CHAINS) == {"algorand-mainnet", "algorand-testnet", "voi-mainnet"}


@pytest.mark.parametrize(
    "name,genesis_id,genesis_hash_b64,caip2",
    [
        (
            "algorand-mainnet",
            "mainnet-v1.0",
            "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
            "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k",
        ),
        (
            "algorand-testnet",
            "testnet-v1.0",
            "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
            "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe",
        ),
        (
            "voi-mainnet",
            "voimain-v1.0",
            "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=",
            # base64url swaps '/' for '_' before the 32-char truncation.
            "algorand:r20fSQI8gWe_kFZziNonSPCXLwcQmH_n",
        ),
    ],
)
def test_chain_constants(name, genesis_id, genesis_hash_b64, caip2):
    chain = get_chain(name)
    assert chain.name == name
    assert chain.genesis_id == genesis_id
    assert chain.genesis_hash_b64 == genesis_hash_b64
    assert len(chain.genesis_hash) == 32
    assert chain.caip2 == caip2


def test_unknown_chain_fails_closed():
    with pytest.raises(UnknownChainError):
        get_chain("algorand")
    with pytest.raises(UnknownChainError):
        get_chain("")


@pytest.mark.parametrize(
    "chain_name,fixture_name",
    [
        ("algorand-mainnet", "algorand-mainnet-pay"),
        ("algorand-mainnet", "algorand-mainnet-appl"),
        ("voi-mainnet", "voi-mainnet-appl"),
    ],
)
def test_registry_agrees_with_fixture_evidence(chain_name, fixture_name):
    """Registry hash == fixture hash, and the fixture verifies pinned to it."""
    chain = get_chain(chain_name)
    data = _fixture(fixture_name)
    assert data["chain"]["genesis_hash_b64"] == chain.genesis_hash_b64
    assert data["chain"]["genesis_id"] == chain.genesis_id
    report = verify_bundle(
        Bundle.from_dict(data), expected_genesis_hash=chain.genesis_hash
    )
    assert report.genesis_hash_b64 == chain.genesis_hash_b64


def test_default_corroboration_nodes_are_https():
    for chain in CHAINS.values():
        assert chain.default_corroboration_nodes, chain.name
        for url in chain.default_corroboration_nodes:
            assert url.startswith("https://"), url


def test_caip2_reference_is_base64url_prefix():
    for chain in CHAINS.values():
        namespace, reference = chain.caip2.split(":")
        assert namespace == "algorand"
        assert len(reference) == 32
        expected = base64.urlsafe_b64encode(chain.genesis_hash).decode("ascii")[:32]
        assert reference == expected

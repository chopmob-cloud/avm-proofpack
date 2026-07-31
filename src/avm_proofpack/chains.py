"""Registry of known AVM chains: genesis identity and corroboration defaults.

A bundle names its chain by genesis hash, and SPEC.md section 6 requires
consumers to *pin* that hash rather than trust the bundle's self-declared
identity. This module gives the pin a memorable name: ``--chain
algorand-mainnet`` instead of a pasted base64 blob.

Provenance of the constants (this library is offline-first, so each value
states how it can be re-checked without trusting this file):

- ``algorand-mainnet``: genesis hash as it appears in this repository's
  README verification example and in both Algorand mainnet test fixtures
  (``tests/fixtures/algorand-mainnet-*.json``), whose offline verification
  binds the hash into the block header and the light-header commitment.
- ``voi-mainnet``: extracted from the live-captured fixture
  ``tests/fixtures/voi-mainnet-appl.json``, which verifies offline against
  that genesis hash (the hash is committed by the fixture's block header
  and state proof message, not merely quoted).
- ``algorand-testnet``: the well-known published value. This repository
  carries no testnet fixture, so unlike the other two entries this hash
  CANNOT be re-verified offline from material in this repo; confirm it
  against a live testnet node (``GET /v2/genesis`` or any block header)
  before relying on it for anything adversarial.

CAIP-2 identifiers follow the CASA ``algorand`` namespace specification
(chain-agnostic/namespaces, ``algorand/caip2.md``): the reference is the
first 32 characters of the base64url encoding of the 32-byte genesis
hash, giving e.g. ``algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k`` for
Algorand mainnet. Voi is an AVM chain and uses the same derivation over
its own genesis hash.

Default corroboration nodes are the independent public endpoints already
cited in this repository (README examples and docstrings): AlgoNode and
Nodely for Algorand, Nodely for Voi. They are *defaults for convenience*,
not an authority claim; corroboration reduces trust to "these operators do
not all collude", and operators can and should be overridden with their
own node list.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

__all__ = ["Chain", "CHAINS", "UnknownChainError", "get_chain"]

_CAIP2_NAMESPACE = "algorand"
_CAIP2_REFERENCE_CHARS = 32


class UnknownChainError(ValueError):
    """Raised when a chain name is not in the registry."""


@dataclass(frozen=True)
class Chain:
    """One known AVM chain: identity constants and corroboration defaults."""

    name: str
    genesis_id: str
    genesis_hash: bytes
    default_corroboration_nodes: tuple[str, ...]

    @property
    def genesis_hash_b64(self) -> str:
        return base64.b64encode(self.genesis_hash).decode("ascii")

    @property
    def caip2(self) -> str:
        """CAIP-2 chain id per the CASA algorand namespace.

        ``algorand:<first 32 chars of base64url(genesis_hash)>``
        (chain-agnostic/namespaces, ``algorand/caip2.md``).
        """
        reference = base64.urlsafe_b64encode(self.genesis_hash).decode("ascii")
        return f"{_CAIP2_NAMESPACE}:{reference[:_CAIP2_REFERENCE_CHARS]}"


def _chain(
    name: str, genesis_id: str, genesis_hash_b64: str, nodes: tuple[str, ...]
) -> Chain:
    genesis_hash = base64.b64decode(genesis_hash_b64, validate=True)
    if len(genesis_hash) != 32:
        raise ValueError(f"registry entry {name}: genesis hash is not 32 bytes")
    return Chain(
        name=name,
        genesis_id=genesis_id,
        genesis_hash=genesis_hash,
        default_corroboration_nodes=nodes,
    )


CHAINS: dict[str, Chain] = {
    chain.name: chain
    for chain in (
        _chain(
            "algorand-mainnet",
            "mainnet-v1.0",
            # Matches README and tests/fixtures/algorand-mainnet-*.json,
            # which verify offline against this hash.
            "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
            (
                "https://mainnet-api.algonode.cloud",
                "https://mainnet-api.4160.nodely.dev",
            ),
        ),
        _chain(
            "algorand-testnet",
            "testnet-v1.0",
            # Well-known published value. NOT re-verifiable offline from this
            # repository (no testnet fixture exists here); confirm against a
            # live testnet node before adversarial use.
            "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
            (
                "https://testnet-api.algonode.cloud",
                "https://testnet-api.4160.nodely.dev",
            ),
        ),
        _chain(
            "voi-mainnet",
            "voimain-v1.0",
            # Extracted from tests/fixtures/voi-mainnet-appl.json, a
            # live-captured bundle that verifies offline against this hash.
            "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=",
            # The only Voi endpoint cited in this repository. A single
            # default cannot by itself demonstrate operator independence;
            # add further nodes for meaningful corroboration.
            ("https://mainnet-api.voi.nodely.io",),
        ),
    )
}


def get_chain(name: str) -> Chain:
    """Look up a chain by registry name; unknown names fail closed."""
    try:
        return CHAINS[name]
    except KeyError:
        known = ", ".join(sorted(CHAINS))
        raise UnknownChainError(
            f"unknown chain {name!r}; known chains: {known}"
        ) from None

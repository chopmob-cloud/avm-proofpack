"""avm-proofpack: portable, offline-verifiable settlement evidence for
Algorand and Voi, anchored in state proofs.

Capture a bundle once, while public nodes still hold the data, and anyone
can re-verify the transaction against chain consensus forever, offline::

    from avm_proofpack import capture, Bundle, verify_bundle

    bundle_dict = capture("https://mainnet-api.algonode.cloud", txid, round_number)
    report = verify_bundle(Bundle.from_dict(bundle_dict))
"""

from .bundle import Bundle, BundleError, dump_bundle
from .capture import CaptureError, NotYetProvable, capture
from .chains import CHAINS, Chain, UnknownChainError, get_chain
from .extract import (
    ExtractionError,
    PaymentFacts,
    decode_address,
    encode_address,
    extract_payment,
    matches_reference,
)
from .mpack import DecodeError, EncodeError
from .verify import (
    CorroborationReport,
    CorroborationResult,
    TrustedVoters,
    VerificationError,
    VerificationReport,
    corroborate,
    verify_bundle,
)

__version__ = "0.4.1"

__all__ = [
    "Bundle",
    "BundleError",
    "CHAINS",
    "CaptureError",
    "Chain",
    "CorroborationReport",
    "CorroborationResult",
    "DecodeError",
    "EncodeError",
    "ExtractionError",
    "NotYetProvable",
    "PaymentFacts",
    "TrustedVoters",
    "UnknownChainError",
    "VerificationError",
    "VerificationReport",
    "__version__",
    "capture",
    "corroborate",
    "decode_address",
    "dump_bundle",
    "encode_address",
    "extract_payment",
    "get_chain",
    "matches_reference",
    "verify_bundle",
]

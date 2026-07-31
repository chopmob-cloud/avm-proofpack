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
from .mpack import DecodeError, EncodeError
from .verify import (
    CorroborationReport,
    CorroborationResult,
    VerificationError,
    VerificationReport,
    corroborate,
    verify_bundle,
)

__version__ = "0.1.0"

__all__ = [
    "Bundle",
    "BundleError",
    "CaptureError",
    "CorroborationReport",
    "CorroborationResult",
    "DecodeError",
    "EncodeError",
    "NotYetProvable",
    "VerificationError",
    "VerificationReport",
    "__version__",
    "capture",
    "corroborate",
    "dump_bundle",
    "verify_bundle",
]

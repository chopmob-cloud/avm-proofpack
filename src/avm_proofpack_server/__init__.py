"""Optional service layer for avm-proofpack.

This package is the additive gRPC + REST service around the zero-dependency
core. The service's transport dependencies (grpclib, betterproto, an HTTP
server) live behind the ``server`` extra::

    pip install avm-proofpack[server]

The Phase-0 security pieces - :mod:`avm_proofpack_server.egress` (the SSRF
guard) and :mod:`avm_proofpack_server.config` - are stdlib-only and always
importable, so ``import avm_proofpack_server`` never hard-fails just because
the extra is absent. The transport modules (``grpc_server``, ``rest_gateway``)
import their third-party deps lazily and only when actually loaded, raising a
clear "install avm-proofpack[server]" error if the extra is missing.

The core (:mod:`avm_proofpack`) is untouched by importing this package and
still pulls no third-party dependency.
"""
from __future__ import annotations

# Stdlib-only Phase-0 pieces: safe to import eagerly, no extra required.
from .config import ServerConfig
from .egress import EgressBlocked, EgressPolicy, PinnedOpener, guarded_opener

__all__ = [
    "ServerConfig",
    "EgressBlocked",
    "EgressPolicy",
    "PinnedOpener",
    "guarded_opener",
    # Lazily resolved (see __getattr__): pure-stdlib service/storage load on
    # demand; grpc_server/rest_gateway require the [server] extra.
    "ProofpackService",
    "BundleStore",
    "BundleNotFound",
    "SqliteBundleStore",
]

# Map lazily-exported names to the submodule that defines them. Deferring the
# import keeps `import avm_proofpack_server` stdlib-clean and turns a missing
# extra into a clear message at first use rather than an import-time hard fail.
_LAZY = {
    "ProofpackService": "service",
    "BundleStore": "storage",
    "BundleNotFound": "storage",
    "SqliteBundleStore": "storage",
}


def __getattr__(name: str):
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    try:
        module = importlib.import_module(f".{module_name}", __name__)
    except ImportError as exc:  # a transport dep from the extra is missing
        raise ImportError(
            f"{name} requires the service extra; install avm-proofpack[server] "
            f"(original error: {exc})"
        ) from exc
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))

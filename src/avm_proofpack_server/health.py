from __future__ import annotations
from importlib.metadata import version, PackageNotFoundError

def health() -> dict:
    try: value = version("avm-proofpack")
    except PackageNotFoundError: value = "unknown"
    return {"ok": True, "version": value}

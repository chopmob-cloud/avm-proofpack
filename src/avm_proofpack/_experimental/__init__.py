"""Experimental trust-root groundwork. NOT part of the published package.

This sub-package holds the beginnings of the *next* trust tier: cryptographic
verification of the Algorand/Voi state proof itself (Falcon-1024 signature
verification plus state-proof message reconstruction), which would remove node
trust entirely. It is deliberately quarantined:

* It is **not imported by** :func:`avm_proofpack.verify.verify_bundle` and
  changes no shipped behaviour.
* It is **excluded from the built distribution** (see ``pyproject.toml``
  ``[tool.setuptools.packages.find]`` ``exclude``), so ``pip install
  avm-proofpack`` does not ship it. It lives in the source tree for development
  and review only.
* Verifying a state proof's Falcon signatures proves only that some ephemeral
  keys signed the message; it does **not** yet establish attestation. The
  reveal-signature helper returns a *count*
  (:class:`avm_proofpack._experimental.stateproof.RevealSignatureCount`) whose
  ``is_trust_root`` is always ``False`` until the deferred key-commitment
  membership, signed-weight threshold, coin-position selection, and
  voters-commitment anchoring are implemented.

Do not gate any trust decision on anything in this package.
"""

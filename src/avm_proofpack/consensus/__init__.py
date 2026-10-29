"""State-proof consensus verification: the stake-attested trust tier.

This sub-package cryptographically verifies the Algorand/Voi state proof itself
and so removes node trust (down to a caller-supplied anchor). It is shipped in
the built distribution and is used by :func:`avm_proofpack.verify.verify_bundle`
to reach ``trust_root == "stake_attested"`` when the caller passes a
:class:`avm_proofpack.verify.TrustedVoters` anchor.

Modules:

* :mod:`.falcon` -- a stdlib-only Falcon-1024 (det1024, compressed) verifier.
* :mod:`.sumhash` -- Algorand Sumhash512.
* :mod:`.merklesig` -- merklesignature key-tree membership (binds each reveal's
  ephemeral key to its participant's key commitment).
* :mod:`.stateproof` -- message-hash reconstruction, per-reveal Falcon + key
  membership, signature-/participant-tree membership, and the signed-weight
  threshold.
* :mod:`.coins` -- Fiat-Shamir coin selection.
* :mod:`.chain` -- multi-interval chain authentication from a trusted anchor.

Trust note: NONE of these is a trust root on its own. Attestation requires the
full combination AND a caller-supplied trusted anchor for the signing interval's
voters commitment (a single bundle cannot authenticate that commitment). A
bundle's own ``previous_state_proof_message`` is attacker-authored and is never a
trust anchor.
"""

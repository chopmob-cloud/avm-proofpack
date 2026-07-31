"""Regenerate the conformance vector set from the live-captured fixtures.

Run from the repo root:

    PYTHONPATH=src python vectors/generate.py

Every expected value written into ``vectors/positive/*.json`` and
``vectors/negative/*.json`` is produced by calling this library's own
verification and derivation functions against the fixtures in
``tests/fixtures/`` -- nothing here is hand-authored. The output is
byte-for-byte stable (``sort_keys=True, indent=2``), so re-running this on an
unchanged library and unchanged fixtures reproduces identical files, and any
diff signals a real behavioural change. ``tests/test_vectors.py`` re-checks
every recorded value against the library, so the vectors cannot silently
drift away from the code that generated them.

The negative vectors' ``expected.failed_check`` values are captured by
actually applying each mutation and observing which step the library fails at;
they are never assumed. The mutation operations are declarative (see
``apply_mutation`` and ``vectors/README.md``) so an independent implementation
in another language can reproduce each tampered bundle without this code.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

from avm_proofpack import mpack
from avm_proofpack.avm import (
    block_hash,
    light_block_header_leaf,
    stib_hash_sha256,
    transaction_from_stib,
    txn_hashes,
)
from avm_proofpack.bundle import Bundle, BundleError
from avm_proofpack.extract import extract_payment
from avm_proofpack.hashes import DOMAIN_TXN_MERKLE_LEAF, sha256
from avm_proofpack.verify import VerificationError, verify_bundle

SCHEMA = "avm-proofpack-conformance/v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
VECTORS_DIR = REPO_ROOT / "vectors"
POSITIVE_DIR = VECTORS_DIR / "positive"
NEGATIVE_DIR = VECTORS_DIR / "negative"

FIXTURE_NAMES = [
    "algorand-mainnet-pay",
    "algorand-mainnet-appl",
    "voi-mainnet-appl",
]

# Path each vector uses to reach its fixture, expressed relative to the
# vector file's own directory (vectors/positive/ or vectors/negative/).
FIXTURE_REL = "../../tests/fixtures"


def _hex(b: bytes) -> str:
    return b.hex()


def _load_dict(name: str) -> dict:
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _write(path: Path, obj: dict) -> None:
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


# --------------------------------------------------------------------------
# Positive vectors: every expected value comes from the library.
# --------------------------------------------------------------------------

def _derived_leaves(bundle: Bundle) -> tuple[str, str]:
    """Reproduce verify.py's two intermediate leaf hashes, via library calls.

    Returns (txn_merkle_leaf_hex, light_block_header_leaf_hex). These mirror,
    line for line, the leaves verify_bundle feeds into the two vector
    commitment proofs; they are not otherwise surfaced on VerificationReport.
    """
    header = mpack.decode(bundle.block_header_bytes)
    stib = mpack.decode(bundle.stib_bytes)
    txn = transaction_from_stib(stib, header)
    _, txid_256 = txn_hashes(txn)
    stib_hash = stib_hash_sha256(bundle.stib_bytes)
    txn_leaf = sha256(DOMAIN_TXN_MERKLE_LEAF + txid_256 + stib_hash)

    txn_commitment = header["txn256"]
    if bundle.light_header_variant == "block_hash":
        light_leaf = light_block_header_leaf(
            bundle.round,
            bundle.genesis_hash,
            txn_commitment,
            block_hash_digest=block_hash(bundle.block_header_bytes),
        )
    else:
        light_leaf = light_block_header_leaf(
            bundle.round,
            bundle.genesis_hash,
            txn_commitment,
            seed=header["seed"],
        )
    return _hex(txn_leaf), _hex(light_leaf)


def build_positive(name: str) -> dict:
    bundle = Bundle.load(FIXTURES_DIR / f"{name}.json")
    report = verify_bundle(bundle)
    facts = extract_payment(bundle, report=report)
    txn_leaf_hex, light_leaf_hex = _derived_leaves(bundle)

    genesis_hash = base64.b64decode(report.genesis_hash_b64)
    block_hash_bytes = base64.b64decode(report.block_hash_b64)
    txn_commitment = base64.b64decode(report.txn_commitment_b64)
    headers_commitment = base64.b64decode(report.block_headers_commitment_b64)

    return {
        "schema": SCHEMA,
        "kind": "positive",
        "name": name,
        "description": (
            f"Live-captured {name} bundle. Verifies offline; every expected "
            "value below was derived by this library and must be reproduced "
            "byte-for-byte by a conforming implementation."
        ),
        "bundle_path": f"{FIXTURE_REL}/{name}.json",
        "expected": {
            "verifies": True,
            "trust_root": report.trust_root,
            "txid": report.txid,
            "round": report.round,
            "genesis_id": report.genesis_id,
            "genesis_hash_hex": _hex(genesis_hash),
            "first_attested_round": report.first_attested_round,
            "last_attested_round": report.last_attested_round,
            "light_header_variant": report.light_header_variant,
            "block_hash_hex": _hex(block_hash_bytes),
            "txn_commitment_root_hex": _hex(txn_commitment),
            "txn_leaf_hash_hex": txn_leaf_hex,
            "light_header_leaf_hash_hex": light_leaf_hex,
            "block_headers_commitment_root_hex": _hex(headers_commitment),
            "checks": list(report.checks),
            "payment_facts": facts.as_dict(),
        },
    }


# --------------------------------------------------------------------------
# Mutation DSL. apply_mutation() is the reference implementation; an
# independent verifier reimplements these few ops in its own language.
# tests/test_vectors.py carries a byte-identical copy so the vectors are
# self-checking.
# --------------------------------------------------------------------------

def _get_parent(data: dict, path: str) -> tuple[dict, str]:
    parts = path.split(".")
    node = data
    for part in parts[:-1]:
        node = node[part]
    return node, parts[-1]


def apply_mutation(data: dict, ops: list[dict], fixture_loader) -> dict:
    """Apply an ordered list of mutation ops to a deep copy of ``data``.

    ``fixture_loader(name)`` returns the raw dict of another fixture, used by
    the ``copy_from`` op. Ops:

    - ``set``            {path, value}            -> set path to a literal
    - ``add_int``        {path, delta}            -> integer add at path
    - ``flip_b64_bit``   {path, byte_offset, xor} -> XOR one byte of decoded b64
    - ``truncate_b64_tail`` {path, drop_bytes}    -> drop trailing bytes of b64
    - ``copy_from``      {path, from_fixture, from_path} -> copy a field across
    """
    out = copy.deepcopy(data)
    for op in ops:
        kind = op["op"]
        if kind == "set":
            parent, key = _get_parent(out, op["path"])
            parent[key] = op["value"]
        elif kind == "add_int":
            parent, key = _get_parent(out, op["path"])
            parent[key] = parent[key] + op["delta"]
        elif kind == "flip_b64_bit":
            parent, key = _get_parent(out, op["path"])
            raw = bytearray(base64.b64decode(parent[key]))
            raw[op["byte_offset"] % len(raw)] ^= op.get("xor", 0x01)
            parent[key] = base64.b64encode(bytes(raw)).decode("ascii")
        elif kind == "truncate_b64_tail":
            parent, key = _get_parent(out, op["path"])
            raw = base64.b64decode(parent[key])
            parent[key] = base64.b64encode(raw[: len(raw) - op["drop_bytes"]]).decode(
                "ascii"
            )
        elif kind == "copy_from":
            src = fixture_loader(op["from_fixture"])
            src_parent, src_key = _get_parent(src, op["from_path"])
            dst_parent, dst_key = _get_parent(out, op["path"])
            dst_parent[dst_key] = copy.deepcopy(src_parent[src_key])
        else:  # pragma: no cover - guards generator/test drift
            raise ValueError(f"unknown mutation op {kind!r}")
    return out


def _noncanonical_header_b64(name: str) -> str:
    """A block-header msgpack blob that DECODES to the real header but is not
    canonical: the first small integer value is re-encoded in a longer-than-
    shortest form (uint8 where a positive fixint suffices). The library's
    canonical-form check must reject it."""
    data = _load_dict(name)
    header = mpack.decode(base64.b64decode(data["block_header_msgpack_b64"]))

    expanded = {"done": False}

    def enc(obj: object) -> bytes:
        # Canonical encoder, except the first int in [0, 0x7f] is emitted as a
        # non-shortest uint8 (0xcc, value). Decodes to the same value; differs
        # from the canonical byte stream, so encode(decode(x)) != x.
        if isinstance(obj, bool):
            return b"\xc3" if obj else b"\xc2"
        if obj is None:
            return b"\xc0"
        if isinstance(obj, int):
            if 0 <= obj <= 0x7F and not expanded["done"]:
                expanded["done"] = True
                return b"\xcc" + bytes([obj])
            return mpack.encode_canonical(obj)
        if isinstance(obj, (bytes, bytearray, str)):
            return mpack.encode_canonical(obj)
        if isinstance(obj, list):
            body = b"".join(enc(x) for x in obj)
            n = len(obj)
            head = bytes([0x90 | n]) if n <= 0x0F else b"\xdc" + n.to_bytes(2, "big")
            return head + body
        if isinstance(obj, dict):
            keys = sorted(
                obj.keys(),
                key=(
                    (lambda k: k.encode("utf-8", "surrogateescape"))
                    if all(isinstance(k, str) for k in obj)
                    else (lambda k: k)
                ),
            )
            body = b"".join(enc(k) + enc(obj[k]) for k in keys)
            n = len(keys)
            head = bytes([0x80 | n]) if n <= 0x0F else b"\xde" + n.to_bytes(2, "big")
            return head + body
        raise TypeError(type(obj).__name__)

    blob = enc(header)
    # Sanity: it decodes to the same object but is not the canonical bytes.
    assert mpack.decode(blob) == header
    assert blob != base64.b64decode(data["block_header_msgpack_b64"])
    assert expanded["done"], "no expandable integer found in header"
    return base64.b64encode(blob).decode("ascii")


def _observe(base_name: str, ops: list[dict], verify_options: dict | None) -> dict:
    """Run the mutation through the library and record how it fails."""
    mutated = apply_mutation(_load_dict(base_name), ops, _load_dict)
    kwargs = {}
    if verify_options and "expected_genesis_hash_hex" in verify_options:
        kwargs["expected_genesis_hash"] = bytes.fromhex(
            verify_options["expected_genesis_hash_hex"]
        )
    try:
        bundle = Bundle.from_dict(mutated)
    except BundleError as exc:
        return {"verifies": False, "error_type": "BundleError", "detail": str(exc)}
    try:
        verify_bundle(bundle, **kwargs)
    except VerificationError as exc:
        return {
            "verifies": False,
            "error_type": "VerificationError",
            "failed_check": exc.check,
        }
    raise SystemExit(f"NEGATIVE VECTOR DID NOT FAIL: {base_name} {ops}")


def build_negative(
    name: str,
    base_name: str,
    description: str,
    ops: list[dict],
    verify_options: dict | None = None,
) -> dict:
    expected = _observe(base_name, ops, verify_options)
    vec = {
        "schema": SCHEMA,
        "kind": "negative",
        "name": name,
        "description": description,
        "base_bundle_path": f"{FIXTURE_REL}/{base_name}.json",
        "mutation": ops,
        "expected": expected,
    }
    if verify_options:
        vec["verify_options"] = verify_options
    return vec


def _claimed_txid_replacement(base_name: str) -> str:
    txid = _load_dict(base_name)["transaction"]["txid"]
    return ("A" if txid[0] != "A" else "B") + txid[1:]


def negative_specs() -> list[dict]:
    alg = "algorand-mainnet-pay"
    return [
        dict(
            name="stib-byte-flip",
            base_name=alg,
            description="Flip one bit inside the SignedTxnInBlock msgpack bytes.",
            ops=[{"op": "flip_b64_bit", "path": "stib_msgpack_b64",
                  "byte_offset": 5, "xor": 0x01}],
        ),
        dict(
            name="header-byte-flip",
            base_name=alg,
            description="Flip one bit inside the block header msgpack bytes.",
            ops=[{"op": "flip_b64_bit", "path": "block_header_msgpack_b64",
                  "byte_offset": 5, "xor": 0x01}],
        ),
        dict(
            name="substituted-txid",
            base_name=alg,
            description="Replace the claimed transaction id with a different one.",
            ops=[{"op": "set", "path": "transaction.txid",
                  "value": _claimed_txid_replacement(alg)}],
        ),
        dict(
            name="altered-round",
            base_name=alg,
            description="Advance the claimed round by one (stays inside the "
                        "attested interval, so schema validation still passes).",
            ops=[{"op": "add_int", "path": "transaction.round", "delta": 1}],
        ),
        dict(
            name="txn-proof-byte-flip",
            base_name=alg,
            description="Flip one bit in the transaction Merkle proof path.",
            ops=[{"op": "flip_b64_bit", "path": "txn_proof.proof_b64",
                  "byte_offset": 0, "xor": 0x01}],
        ),
        dict(
            name="txn-proof-index",
            base_name=alg,
            description="Advance the transaction proof's element index by one.",
            ops=[{"op": "add_int", "path": "txn_proof.index", "delta": 1}],
        ),
        dict(
            name="txn-proof-truncated",
            base_name=alg,
            description="Drop the last 32-byte sibling from the transaction proof.",
            ops=[{"op": "truncate_b64_tail", "path": "txn_proof.proof_b64",
                  "drop_bytes": 32}],
        ),
        dict(
            name="light-proof-byte-flip",
            base_name=alg,
            description="Flip one bit in the light block header proof path.",
            ops=[{"op": "flip_b64_bit", "path": "light_header_proof.proof_b64",
                  "byte_offset": 0, "xor": 0x01}],
        ),
        dict(
            name="headers-commitment-flip",
            base_name=alg,
            description="Flip one bit in the state proof's block-headers "
                        "commitment (the light-header membership root).",
            ops=[{"op": "flip_b64_bit",
                  "path": "state_proof_message.block_headers_commitment_b64",
                  "byte_offset": 0, "xor": 0x01}],
        ),
        dict(
            name="interval-shift",
            base_name=alg,
            description="Shift the attested interval by one round in each "
                        "direction, so the light-header element index is wrong.",
            ops=[
                {"op": "add_int",
                 "path": "state_proof_message.first_attested_round", "delta": 1},
                {"op": "add_int",
                 "path": "state_proof_message.last_attested_round", "delta": 1},
            ],
        ),
        dict(
            name="genesis-hash-flip",
            base_name=alg,
            description="Flip one bit in the chain genesis hash.",
            ops=[{"op": "flip_b64_bit", "path": "chain.genesis_hash_b64",
                  "byte_offset": 0, "xor": 0x01}],
        ),
        dict(
            name="variant-flip",
            base_name=alg,
            description="Claim the 'seed' light-header variant for a bundle "
                        "committed under the 'block_hash' variant.",
            ops=[{"op": "set", "path": "meta.light_header_variant",
                  "value": "seed"}],
        ),
        dict(
            name="noncanonical-header",
            base_name=alg,
            description="Re-encode the block header with a non-shortest integer "
                        "so it decodes to the same header but is not canonical.",
            ops=[{"op": "set", "path": "block_header_msgpack_b64",
                  "value": _noncanonical_header_b64(alg)}],
        ),
        dict(
            name="chain-identity-mismatch",
            base_name=alg,
            description="Verify a valid bundle while pinning a different chain "
                        "via expected_genesis_hash (all-zero here).",
            ops=[],
            verify_options={"expected_genesis_hash_hex": "00" * 32},
        ),
        dict(
            name="junk-state-proof",
            base_name=alg,
            description="Replace the retained state proof blob with junk that "
                        "is not well-formed msgpack.",
            ops=[{"op": "set", "path": "state_proof_msgpack_b64",
                  "value": base64.b64encode(b"not a state proof").decode("ascii")}],
        ),
        dict(
            name="transplanted-stib",
            base_name="algorand-mainnet-appl",
            description="Splice a different transaction's stib and proof (from "
                        "the pay bundle in the same block) under this bundle's "
                        "claimed txid; membership alone must not vouch for it.",
            ops=[
                {"op": "copy_from", "path": "stib_msgpack_b64",
                 "from_fixture": "algorand-mainnet-pay",
                 "from_path": "stib_msgpack_b64"},
                {"op": "copy_from", "path": "txn_proof",
                 "from_fixture": "algorand-mainnet-pay",
                 "from_path": "txn_proof"},
            ],
        ),
        dict(
            name="cross-chain-transplant",
            base_name="algorand-mainnet-appl",
            description="Substitute a Voi state proof message and light-header "
                        "proof for an Algorand bundle.",
            ops=[
                {"op": "copy_from", "path": "state_proof_message",
                 "from_fixture": "voi-mainnet-appl",
                 "from_path": "state_proof_message"},
                {"op": "copy_from", "path": "light_header_proof",
                 "from_fixture": "voi-mainnet-appl",
                 "from_path": "light_header_proof"},
            ],
        ),
    ]


def main() -> None:
    POSITIVE_DIR.mkdir(parents=True, exist_ok=True)
    NEGATIVE_DIR.mkdir(parents=True, exist_ok=True)

    for name in FIXTURE_NAMES:
        _write(POSITIVE_DIR / f"{name}.json", build_positive(name))
        print(f"positive: {name}")

    for spec in negative_specs():
        vec = build_negative(**spec)
        _write(NEGATIVE_DIR / f"{spec['name']}.json", vec)
        exp = vec["expected"]
        step = exp.get("failed_check", exp.get("error_type"))
        print(f"negative: {spec['name']:<24} -> {step}")


if __name__ == "__main__":
    main()

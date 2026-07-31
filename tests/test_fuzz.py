"""Deterministic fuzzing of the decode surfaces.

The codec and bundle loader are the parts of the library that consume
attacker-controlled bytes. These tests feed them seeded-random garbage and
mutations of real data, and require that the only possible outcomes are
success or the module's own typed error, never a crash, hang, or foreign
exception. Seeds are fixed so failures reproduce exactly.
"""

import base64
import copy
import json
import random
from pathlib import Path

import pytest

from avm_proofpack import mpack
from avm_proofpack.bundle import Bundle, BundleError
from avm_proofpack.verify import VerificationError, verify_bundle

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))

RANDOM_BLOB_ITERATIONS = 4000
MUTATION_ITERATIONS = 4000
BUNDLE_MUTATION_ITERATIONS = 400


def test_decoder_survives_random_blobs():
    rng = random.Random(0xA1B2)
    for _ in range(RANDOM_BLOB_ITERATIONS):
        blob = rng.randbytes(rng.randrange(0, 200))
        try:
            decoded = mpack.decode(blob)
        except mpack.DecodeError:
            continue
        # Anything that decodes must re-encode without a foreign exception.
        try:
            mpack.encode_canonical(decoded)
        except mpack.EncodeError:
            pass


def test_decoder_survives_mutations_of_real_data():
    data = json.loads(FIXTURES[0].read_text(encoding="utf-8"))
    stib = bytearray(base64.b64decode(data["stib_msgpack_b64"]))
    header = bytearray(base64.b64decode(data["block_header_msgpack_b64"]))
    rng = random.Random(0xC3D4)
    for source in (stib, header):
        for _ in range(MUTATION_ITERATIONS):
            mutated = bytearray(source)
            for _ in range(rng.randrange(1, 4)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            if rng.random() < 0.2:
                mutated = mutated[: rng.randrange(len(mutated) + 1)]
            try:
                decoded = mpack.decode(bytes(mutated))
            except mpack.DecodeError:
                continue
            try:
                mpack.encode_canonical(decoded)
            except mpack.EncodeError:
                pass


@pytest.mark.parametrize("path", FIXTURES, ids=[p.stem for p in FIXTURES])
def test_verifier_survives_bundle_mutations(path):
    """Random field-level corruption of a real bundle must yield only a typed
    rejection (or, for mutations of non-load-bearing metadata, success)."""
    original = json.loads(path.read_text(encoding="utf-8"))
    rng = random.Random(0xE5F6)

    b64_fields = [
        ("block_header_msgpack_b64",),
        ("stib_msgpack_b64",),
        ("txn_proof", "proof_b64"),
        ("light_header_proof", "proof_b64"),
        ("state_proof_message", "block_headers_commitment_b64"),
        # voters_commitment_b64 is deliberately absent: it is trust-root
        # material consumed by corroboration and future tiers, not by
        # offline verification, so mutating it does not (and must not
        # be expected to) fail the offline check.
        ("chain", "genesis_hash_b64"),
    ]
    int_fields = [
        ("transaction", "round"),
        ("txn_proof", "index"),
        ("txn_proof", "tree_depth"),
        ("light_header_proof", "tree_depth"),
        ("state_proof_message", "first_attested_round"),
        # last_attested_round is deliberately absent: shrinking it slightly is
        # offline-neutral (the light header index derives from
        # first_attested_round; last only bounds the claimed interval), and
        # like voters_commitment its exact value is trust-root material that
        # corroboration validates. Growing it is covered by the tamper suite.
    ]

    def get_parent(data, spec):
        node = data
        for key in spec[:-1]:
            node = node[key]
        return node, spec[-1]

    for _ in range(BUNDLE_MUTATION_ITERATIONS):
        data = copy.deepcopy(original)
        if rng.random() < 0.5:
            parent, key = get_parent(data, rng.choice(b64_fields))
            raw = bytearray(base64.b64decode(parent[key]))
            if not raw:
                continue
            choice = rng.random()
            if choice < 0.6:
                raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            elif choice < 0.8:
                raw = raw[: rng.randrange(len(raw))]
            else:
                raw += rng.randbytes(rng.randrange(1, 40))
            parent[key] = base64.b64encode(bytes(raw)).decode("ascii")
        else:
            parent, key = get_parent(data, rng.choice(int_fields))
            delta = rng.choice([-2, -1, 1, 2, 10**6])
            mutated_value = max(0, parent[key] + delta)
            if mutated_value == parent[key]:
                continue  # e.g. 0 + (-1) clamped back to 0: not a mutation
            parent[key] = mutated_value

        try:
            verify_bundle(Bundle.from_dict(data))
        except (BundleError, VerificationError):
            continue
        pytest.fail(
            f"mutated bundle unexpectedly verified: {json.dumps(data)[:400]}"
        )

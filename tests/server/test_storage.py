"""Storage DoD + S5 tenant-isolation suite (design §9, S5).

Content-addressing, index behaviour, and the tenant-isolation guarantees:
cross-tenant reads mask as not-found (no existence leak), every method is
ownership-scoped, and a shared content hash never leaks one tenant's
``meta.source_node`` to another. The store is content-agnostic, so fake JSON
blobs stand in for real bundles.
"""
from __future__ import annotations

import hashlib

import pytest

from avm_proofpack_server.storage import BundleNotFound, SqliteBundleStore


def _store(tmp_path):
    return SqliteBundleStore(tmp_path / "bundles.sqlite")


A = "tenant-a"
B = "tenant-b"
BYTES_A = b'{"meta":{"source_node":"https://private-a.example"},"n":1}'
BYTES_B = b'{"meta":{"source_node":"https://private-b.example"},"n":2}'


# -- content addressing + index ------------------------------------------

def test_put_is_content_addressed(tmp_path):
    store = _store(tmp_path)
    digest = store.put(A, "algorand", 100, "TX1", BYTES_A)
    assert digest == hashlib.sha256(BYTES_A).hexdigest()


def test_get_round_trips_bytes(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    assert store.get(A, "algorand", 100, "TX1") == BYTES_A


def test_put_same_bytes_dedups_within_tenant(tmp_path):
    store = _store(tmp_path)
    d1 = store.put(A, "algorand", 100, "TX1", BYTES_A)
    d2 = store.put(A, "algorand", 101, "TX2", BYTES_A)  # same bytes, new coord
    assert d1 == d2
    rows = store._db.execute("SELECT COUNT(*) FROM bundles WHERE tenant=?", (A,)).fetchone()
    assert rows[0] == 1  # one shared blob within the tenant


def test_put_rejects_empty_identity(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.put("", "algorand", 100, "TX1", BYTES_A)
    with pytest.raises(ValueError):
        store.put(A, "algorand", 100, "TX1", "not-bytes")  # type: ignore[arg-type]


def test_list_returns_only_this_tenant(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    store.put(A, "voi", 5, "TX3", BYTES_A)
    store.put(B, "algorand", 100, "TX1", BYTES_B)
    listed_a = store.list(A)
    assert {(r["chain"], r["round"], r["txid"]) for r in listed_a} == {
        ("algorand", 100, "TX1"), ("voi", 5, "TX3")}
    listed_b = store.list(B)
    assert {(r["chain"], r["round"], r["txid"]) for r in listed_b} == {
        ("algorand", 100, "TX1")}


def test_list_requires_tenant(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.list("")


# -- delete ownership -----------------------------------------------------

def test_delete_removes_only_owner_entry(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    store.delete(A, "algorand", 100, "TX1")
    with pytest.raises(BundleNotFound):
        store.get(A, "algorand", 100, "TX1")


def test_delete_missing_raises_not_found(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(BundleNotFound):
        store.delete(A, "algorand", 100, "TX1")


def test_delete_requires_tenant(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.delete("", "algorand", 100, "TX1")


# -- S5: cross-tenant read masks as not-found, no existence leak ----------

def test_cross_tenant_read_returns_not_found(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    # B guesses A's low-entropy coordinate; must be not-found, never a 403 that
    # would confirm the coordinate exists for another tenant.
    with pytest.raises(BundleNotFound):
        store.get(B, "algorand", 100, "TX1")


def test_owned_and_unowned_misses_are_indistinguishable(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)

    def miss(exc):
        return (type(exc), str(exc))

    with pytest.raises(BundleNotFound) as unowned:
        store.get(B, "algorand", 100, "TX1")       # exists for A, not for B
    with pytest.raises(BundleNotFound) as absent:
        store.get(B, "algorand", 999, "NOPE")      # never stored at all
    # Same exception type and message: no existence signal leaks to B.
    assert miss(unowned.value) == miss(absent.value)


def test_cross_tenant_delete_returns_not_found(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    with pytest.raises(BundleNotFound):
        store.delete(B, "algorand", 100, "TX1")
    # A's bundle survives B's delete attempt.
    assert store.get(A, "algorand", 100, "TX1") == BYTES_A


# -- S5: source_node isolation across a shared content hash --------------

def test_source_node_does_not_cross_tenants(tmp_path):
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)  # carries private-a
    store.put(B, "algorand", 100, "TX1", BYTES_B)  # carries private-b, same coord
    got_a = store.get(A, "algorand", 100, "TX1")
    got_b = store.get(B, "algorand", 100, "TX1")
    assert b"private-a" in got_a and b"private-b" not in got_a
    assert b"private-b" in got_b and b"private-a" not in got_b


def test_identical_bytes_are_stored_per_tenant(tmp_path):
    # Two tenants store byte-identical bundles that collide on hash. The blob is
    # kept per tenant, so deleting one tenant's copy cannot affect the other.
    store = _store(tmp_path)
    store.put(A, "algorand", 100, "TX1", BYTES_A)
    store.put(B, "algorand", 100, "TX1", BYTES_A)  # identical bytes -> same hash
    total = store._db.execute("SELECT COUNT(*) FROM bundles").fetchone()[0]
    assert total == 2  # not deduplicated across the tenant boundary
    store.delete(A, "algorand", 100, "TX1")
    with pytest.raises(BundleNotFound):
        store.get(A, "algorand", 100, "TX1")
    # B's copy is untouched by A's delete.
    assert store.get(B, "algorand", 100, "TX1") == BYTES_A

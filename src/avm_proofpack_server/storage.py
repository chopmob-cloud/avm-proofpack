"""Tenant-scoped content-addressed bundle storage (design §9, S5).

Two-table model:

* ``bundles(tenant, hash, body)`` - the immutable bundle bytes, content-addressed
  by ``sha256(bundle_bytes)`` and DEDUPLICATED PER TENANT (the primary key is
  ``(tenant, hash)``, not ``hash`` alone).
* ``bundle_index(tenant, chain, round, txid) -> hash`` - the low-entropy,
  enumerable coordinate a caller uses to fetch a bundle.

S5 controls enforced here:

* **Ownership on EVERY method.** ``put``, ``get``, ``delete`` and ``list`` are
  all scoped by ``tenant``; a caller can only ever touch rows carrying its own
  tenant id.
* **Existence-masked cross-tenant reads.** A caller guessing another tenant's
  ``(chain, round, txid)`` gets ``BundleNotFound`` - identical to a coordinate
  that was never stored. Not-owned and not-existent are indistinguishable, so
  the store never reveals which transactions another tenant is watching (no
  ``403`` existence leak).
* **``meta.source_node`` isolation across a shared content hash.**
  ``meta.source_node`` records the capturing node URL verbatim (possibly a
  tenant's private algod) and is part of the bundle bytes. We keep the blob
  PER TENANT: the ``bundles`` primary key is ``(tenant, hash)`` and ``get``
  joins ``bundles`` on BOTH ``tenant`` and ``hash``. So even if two tenants
  store byte-identical bundles that collide on ``hash``, each holds its own blob
  row and a tenant's ``get`` can only ever return the blob it stored itself -
  one tenant's ``source_node`` can never be served to another through a shared
  content-addressed object. Content-addressing (dedup of a tenant's own
  re-captures, immutability) is preserved WITHIN each tenant's namespace; the
  only property traded away is cross-tenant blob dedup, which is a storage
  optimisation, not a security property, and which in practice almost never
  fires because ``meta.captured_at``/``source_node`` differ per capture.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
import hashlib
import sqlite3
import threading
from pathlib import Path


class BundleNotFound(KeyError):
    pass


class BundleStore(ABC):
    @abstractmethod
    def put(self, tenant: str, chain: str, round_number: int, txid: str, bundle_json: bytes) -> str: ...
    @abstractmethod
    def get(self, tenant: str, chain: str, round_number: int, txid: str) -> bytes: ...
    @abstractmethod
    def delete(self, tenant: str, chain: str, round_number: int, txid: str) -> None: ...
    @abstractmethod
    def list(self, tenant: str) -> list[dict]: ...


def _require_tenant(tenant: str) -> None:
    if not tenant or not isinstance(tenant, str):
        raise ValueError("tenant is required")


class SqliteBundleStore(BundleStore):
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS bundles (
          tenant TEXT NOT NULL, hash TEXT NOT NULL, body BLOB NOT NULL,
          PRIMARY KEY (tenant, hash));
        CREATE TABLE IF NOT EXISTS bundle_index (
          tenant TEXT NOT NULL, chain TEXT NOT NULL, round INTEGER NOT NULL,
          txid TEXT NOT NULL, hash TEXT NOT NULL,
          PRIMARY KEY (tenant, chain, round, txid),
          FOREIGN KEY (tenant, hash) REFERENCES bundles(tenant, hash));
        """)
        self._db.commit()

    def put(self, tenant, chain, round_number, txid, bundle_json):
        _require_tenant(tenant)
        if not chain or not txid or not isinstance(bundle_json, bytes):
            raise ValueError("invalid bundle identity or bytes")
        digest = hashlib.sha256(bundle_json).hexdigest()
        with self._lock, self._db:
            # Blob is content-addressed but scoped to the owning tenant, so a
            # shared hash never crosses the tenant boundary (S5 source_node).
            self._db.execute(
                "INSERT OR IGNORE INTO bundles(tenant,hash,body) VALUES (?,?,?)",
                (tenant, digest, bundle_json))
            # Reclaim a blob orphaned if this coordinate previously pointed at
            # different bytes owned only by this tenant.
            prior = self._db.execute(
                "SELECT hash FROM bundle_index WHERE tenant=? AND chain=? AND round=? AND txid=?",
                (tenant, chain, round_number, txid)).fetchone()
            self._db.execute(
                "INSERT OR REPLACE INTO bundle_index(tenant,chain,round,txid,hash) VALUES (?,?,?,?,?)",
                (tenant, chain, round_number, txid, digest))
            if prior is not None and prior[0] != digest:
                self._gc_blob(tenant, prior[0])
        return digest

    def get(self, tenant, chain, round_number, txid):
        _require_tenant(tenant)
        with self._lock:
            row = self._db.execute(
                "SELECT b.body FROM bundle_index i "
                "JOIN bundles b ON b.tenant=i.tenant AND b.hash=i.hash "
                "WHERE i.tenant=? AND i.chain=? AND i.round=? AND i.txid=?",
                (tenant, chain, round_number, txid)).fetchone()
        if row is None:
            # Not-owned and not-existent are indistinguishable (no 403 leak).
            raise BundleNotFound("bundle not found")
        return bytes(row[0])

    def delete(self, tenant, chain, round_number, txid):
        _require_tenant(tenant)
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT hash FROM bundle_index WHERE tenant=? AND chain=? AND round=? AND txid=?",
                (tenant, chain, round_number, txid)).fetchone()
            if row is None:
                raise BundleNotFound("bundle not found")
            self._db.execute(
                "DELETE FROM bundle_index WHERE tenant=? AND chain=? AND round=? AND txid=?",
                (tenant, chain, round_number, txid))
            self._gc_blob(tenant, row[0])

    def list(self, tenant):
        """List this tenant's stored coordinates only (S5 ownership)."""
        _require_tenant(tenant)
        with self._lock:
            rows = self._db.execute(
                "SELECT chain, round, txid FROM bundle_index WHERE tenant=? "
                "ORDER BY chain, round, txid", (tenant,)).fetchall()
        return [{"chain": r[0], "round": r[1], "txid": r[2]} for r in rows]

    def _gc_blob(self, tenant: str, digest: str) -> None:
        """Drop a tenant's blob once no index row of that tenant references it."""
        self._db.execute(
            "DELETE FROM bundles WHERE tenant=? AND hash=? AND NOT EXISTS "
            "(SELECT 1 FROM bundle_index WHERE tenant=? AND hash=?)",
            (tenant, digest, tenant, digest))

    def close(self):
        self._db.close()

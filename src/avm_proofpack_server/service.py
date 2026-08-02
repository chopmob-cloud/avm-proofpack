"""Transport-independent proofpack service.

S4 trust-anchor posture (design §9): the bundle bytes are the SOLE trust
anchor. Every method that returns a verification/corroboration result also
returns ``bundle_json``; there is deliberately NO verdict-only path. The
``report`` and ``fully_corroborated`` values are NON-AUTHORITATIVE hints for
display and triage only - a consumer MUST re-run ``verify_bundle`` on
``bundle_json`` offline and reach its own verdict. Trusting the server's
verdict re-introduces the trusted third party this format exists to remove.

Every outbound dial (capture AND corroborate) is routed through the injected
egress opener/validator (design §9, S1); the service never dials a caller URL
directly.
"""
from __future__ import annotations
import asyncio
import base64
import json
import functools
from avm_proofpack.bundle import Bundle
from avm_proofpack.capture import capture
from avm_proofpack.extract import extract_payment
from avm_proofpack.verify import verify_bundle, corroborate, CorroborationReport
from .config import ServerConfig
from .egress import EgressPolicy

class ProofpackService:
    def __init__(self, config: ServerConfig | None = None, *, egress: EgressPolicy | None = None, store=None):
        self.config = config or ServerConfig()
        self.store = store
        self._max_bundle_bytes = min(self.config.max_bundle_bytes, Bundle.MAX_FILE_BYTES)
        self.egress = egress or EgressPolicy(allowlist=set(self.config.node_allowlist))
        self._global = asyncio.Semaphore(self.config.global_concurrency)
        self._keys: dict[str, asyncio.Semaphore] = {}
        self._keys_lock = asyncio.Lock()

    async def _key_semaphore(self, key: str) -> asyncio.Semaphore:
        # Serialise creation so concurrent first requests cannot replace a
        # semaphore and evade the per-key limit.
        async with self._keys_lock:
            return self._keys.setdefault(key, asyncio.Semaphore(self.config.per_key_concurrency))

    async def _corroborate_concurrent(self, bundle: Bundle, nodes: list[str]) -> CorroborationReport | None:
        """Fan corroboration fetches out with a concurrency cap (S2).

        The core ``corroborate`` runs a sequential loop; at the service layer a
        single request must not hold a worker for ``len(nodes) * timeout`` while
        it walks nodes one at a time. Each node is fetched in a worker thread
        (the core client is blocking urllib), bounded by
        ``config.corroboration_concurrency`` so N nodes never open more than the
        cap of concurrent dials. Every fetch still goes through the egress
        opener/validator. Results are returned in input order. The whole fan-out
        is deadline-bounded by the caller via ``asyncio.wait_for``.
        """
        if not nodes:
            return None
        limit = asyncio.Semaphore(self.config.corroboration_concurrency)

        async def one(url: str):
            async with limit:
                report = await asyncio.to_thread(
                    corroborate, bundle, [url],
                    timeout=self.config.request_timeout,
                    opener=self.egress.opener(), validator=self.egress.validate,
                )
                return report.results[0]

        results = await asyncio.gather(*(one(url) for url in nodes))
        return CorroborationReport(tuple(results))

    def _bundle(self, raw: bytes) -> Bundle:
        if not isinstance(raw, bytes):
            raise ValueError("bundle must be bytes")
        if len(raw) > self._max_bundle_bytes:
            raise ValueError("bundle exceeds size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid bundle JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("bundle JSON must be an object")
        return Bundle.from_dict(value)

    async def capture(self, *, api_key: str, chain: str, txid: str, round_number: int, source_node: str, corroboration_nodes: list[str] = (), wait_seconds: int = 0, tenant: str = "default") -> dict:
        nodes = self.config.clamp_nodes(list(corroboration_nodes))
        wait_seconds = self.config.clamp_wait(wait_seconds)
        key_semaphore = await self._key_semaphore(api_key)
        async with self._global, key_semaphore:
            loop = asyncio.get_running_loop()
            raw_dict = await asyncio.wait_for(
                loop.run_in_executor(
                    None, functools.partial(
                        capture, source_node, txid, round_number,
                        timeout=self.config.request_timeout,
                        opener=self.egress.opener(), validator=self.egress.validate,
                    )
                ), self.config.request_timeout)
            raw = json.dumps(raw_dict, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            bundle = self._bundle(raw)
            report = verify_bundle(bundle)
            if self.store is not None:
                self.store.put(tenant, chain, round_number, txid, raw)
            corroboration = (await asyncio.wait_for(
                self._corroborate_concurrent(bundle, nodes),
                self.config.request_timeout
            )) if nodes else None
            # S4: bundle_json is always present; report/corroboration are hints.
            return {"bundle_json": raw, "report": report, "corroboration": corroboration}

    def verify(self, bundle_json: bytes, expected_genesis_hash_b64: str | None = None) -> dict:
        bundle = self._bundle(bundle_json)
        expected = base64.b64decode(expected_genesis_hash_b64) if expected_genesis_hash_b64 else None
        return {"bundle_json": bundle_json, "report": verify_bundle(bundle, expected_genesis_hash=expected)}

    def extract(self, bundle_json: bytes) -> dict:
        bundle = self._bundle(bundle_json)
        return {"bundle_json": bundle_json, "facts": extract_payment(bundle)}

    async def corroborate_async(self, *, api_key: str, bundle_json: bytes, nodes: list[str]) -> dict:
        bundle = self._bundle(bundle_json)
        bounded_nodes = self.config.clamp_nodes(nodes)
        key_semaphore = await self._key_semaphore(api_key)
        async with self._global, key_semaphore:
            result = await asyncio.wait_for(
                self._corroborate_concurrent(bundle, bounded_nodes),
                self.config.request_timeout,
            )
        results = result.results if result is not None else ()
        # S4: the bundle bytes are returned so the caller re-verifies offline;
        # fully_corroborated is a non-authoritative hint.
        return {"bundle_json": bundle_json, "results": results,
                "fully_corroborated": bool(results) and result.agreeing == len(results)}

    def corroborate(self, bundle_json: bytes, nodes: list[str]) -> dict:
        """Synchronous compatibility wrapper for non-async callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.corroborate_async(api_key="sync", bundle_json=bundle_json, nodes=nodes))
        raise RuntimeError("use corroborate_async from an event loop")

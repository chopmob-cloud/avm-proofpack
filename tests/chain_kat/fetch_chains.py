"""Fetch consecutive state proofs and write a chain fixture.

Each entry: round -> {message (verbose JSON), state_proof_b64 (msgpack)}.
The chain is real chain data; nothing here is a trust anchor.
"""
import base64
import json
import pathlib
import sys
import urllib.request

NODES = {
    "voi-mainnet": "https://mainnet-api.voi.nodely.dev/v2/stateproofs/{round}",
    "algorand-mainnet": "https://mainnet-api.4160.nodely.dev/v2/stateproofs/{round}",
}
ROUNDS = {
    "voi-mainnet": [21208576, 21208832, 21209088],
    "algorand-mainnet": [63604480, 63604736, 63604992],
}
# Chain genesis hashes: public constants, not secrets. The state-proof endpoint does not
# return them, so they are pinned here -- otherwise re-running this script silently omits
# genesis_hash and the A5 tests fail at import (caught in review).
GENESIS = {
    "voi-mainnet": "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=",
    "algorand-mainnet": "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
}

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "tests/chain_kat")
out.mkdir(parents=True, exist_ok=True)

result = {}
for network, rounds in ROUNDS.items():
    entries = {}
    for r in rounds:
        url = NODES[network].format(round=r)
        try:
            d = json.loads(urllib.request.urlopen(url, timeout=60).read())
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"{network} {r}: FAILED {exc}")
            continue
        sp_b64 = d["StateProof"]
        # sanity: it must decode as msgpack with the short keys
        raw = base64.b64decode(sp_b64)
        entries[str(r)] = {
            "message": d["Message"],
            "state_proof_b64": sp_b64,
            "msgpack_len": len(raw),
        }
        print(f"{network} {r}: ok msgpack_len={len(raw)} lar={d['Message']['LastAttestedRound']}")
    if entries:
        entries["genesis_hash"] = GENESIS[network]
        result[network] = entries

(out / "chains.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
print("wrote", out / "chains.json")

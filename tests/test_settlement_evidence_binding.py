"""CI hook for the settlement_evidence_binding_v1 conformance set.

Drives the set's own runner (which reimplements rules R1-R5 from the written
contract) and asserts every vector lands on its declared accept/reject.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SET_DIR = Path(__file__).resolve().parent.parent / "vectors" / "settlement_evidence_binding"
VECTORS = SET_DIR / "settlement_evidence_binding_v1.json"


def _runner():
    spec = importlib.util.spec_from_file_location(
        "seb_runner", SET_DIR / "verify_binding.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cases():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    return [(v["vector_id"], v) for v in data["vectors"]]


@pytest.mark.parametrize("vid,vec", _cases(), ids=[c[0] for c in _cases()])
def test_binding_vector(vid, vec):
    runner = _runner()
    want = vec["expectation"]  # accept | reject
    if want == "accept":
        runner.verify_binding(vec["binding"])  # must not raise
    else:
        with pytest.raises(runner.BindingReject) as exc:
            runner.verify_binding(vec["binding"])
        # the declared reject_rule (its Rn prefix) must be what actually fired
        declared = vec.get("reject_rule", "")
        if declared:
            assert exc.value.rule == declared.split("_", 1)[0], (
                f"{vid}: fired {exc.value.rule}, declared {declared}"
            )


def test_full_runner_exit_zero():
    runner = _runner()
    assert runner.main() == 0


def test_non_jcs_canary_present():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    canaries = [v for v in data["vectors"] if v["kind"] == "canary"]
    assert canaries, "the non-JCS canary must be present"
    assert all(c["expectation"] == "reject" for c in canaries)

"""Make the tests exercise THIS checkout, and say so loudly when they cannot.

A second `avm_proofpack` earlier on `sys.path` (another checkout, or PYTHONPATH
pointing elsewhere) makes every coin-selection test fail with the misleading
"A4 coin-selection module is missing": `importlib.util.find_spec` resolves the
submodule through the *already imported* parent's `__path__`, which points at
the other tree.

Prepending this checkout's `src/` is not enough on its own, because the parent
package may already be in `sys.modules`. So: prepend, evict any stale
`avm_proofpack*` entries, then verify the resolved origin is this worktree.
"""
import sys
from pathlib import Path

_SRC = (Path(__file__).resolve().parent.parent / "src").resolve()
_SRC_STR = str(_SRC)

if _SRC_STR in sys.path:
    sys.path.remove(_SRC_STR)
sys.path.insert(0, _SRC_STR)

for _name in [m for m in list(sys.modules) if m == "avm_proofpack" or m.startswith("avm_proofpack.")]:
    del sys.modules[_name]

import avm_proofpack

_origin = Path(avm_proofpack.__file__).resolve()
if _SRC not in _origin.parents:
    raise RuntimeError(
        f"tests are importing avm_proofpack from {_origin}, not from this checkout "
        f"({_SRC}). Unset PYTHONPATH or run: PYTHONPATH={_SRC_STR} pytest"
    )


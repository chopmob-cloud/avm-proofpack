"""Shared fixtures for the server suites.

Only the throwaway-TLS fixture lives here so the Phase 6 suites
(``test_parity.py`` / ``test_security.py``) share one loopback cert instead of
each regenerating it. ``test_grpc.py`` keeps its own module-scoped ``tls_files``
(a module fixture shadows this conftest one for that module only), so nothing
existing changes. Pure helper functions live in ``_kit.py``.
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory):
    pytest.importorskip("cryptography")
    from ._kit import make_tls_files

    return make_tls_files(tmp_path_factory.mktemp("tls-shared"))

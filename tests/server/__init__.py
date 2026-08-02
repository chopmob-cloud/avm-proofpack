"""Server test package.

Makes ``tests/server`` an importable package so its modules live in the
``server.*`` namespace. Without this, pytest's default (prepend) import mode
derives a module name from the bare filename, and ``tests/server/test_security.py``
would collide with the core ``tests/test_security.py`` (both -> module
``test_security``) at collection time. Packaging keeps the requested filenames
and lets the Phase 6 suites import shared helpers via ``from ._kit import ...``.
"""

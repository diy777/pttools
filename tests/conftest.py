"""Shared pytest fixtures.

Auto-applied per-test fixtures are kept minimal and only added when
they prevent a real foot-gun (e.g. tests dropping out of `pttools start`
because the AUP gate isn't accepted).
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _aup_accepted_in_tests(monkeypatch):
    """Tests run non-interactively. Pre-accept the AUP so `pttools start`
    and similar commands aren't blocked by the consent gate.

    The consent gate itself is exercised by tests/test_aup_consent.py
    where it explicitly clears this env var via tmp-dir fixtures.
    """
    if "PENTEST_TOOLS_AUP_ACCEPTED" not in os.environ:
        monkeypatch.setenv("PENTEST_TOOLS_AUP_ACCEPTED", "1")
    yield

"""Tests for engine.aup_consent — first-run AUP / authorization gate.

The module persists a one-line consent token under ~/.pentest-tools/ so we
only prompt once per machine. Subsequent invocations are silent unless
the user passes --reset-consent.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from engine import aup_consent


@pytest.fixture
def tmp_consent_home(tmp_path, monkeypatch):
    """Redirect the consent file to a temp dir so tests don't touch the real one.

    Also clears PENTEST_TOOLS_AUP_ACCEPTED — the global conftest sets it so
    `pttools start` tests don't hit the gate, but this module's tests need
    to exercise the gate's actual prompt/persist behavior.
    """
    monkeypatch.setenv("PENTEST_TOOLS_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("PENTEST_TOOLS_AUP_ACCEPTED", raising=False)
    monkeypatch.setattr(aup_consent, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(aup_consent, "CONSENT_PATH", tmp_path / "aup-consent.txt")
    yield tmp_path


def test_has_consent_returns_false_when_file_missing(tmp_consent_home):
    assert aup_consent.has_consent() is False


def test_has_consent_returns_true_after_grant(tmp_consent_home):
    aup_consent.grant_consent()
    assert aup_consent.has_consent() is True


def test_grant_consent_writes_iso_timestamp(tmp_consent_home):
    aup_consent.grant_consent()
    text = (tmp_consent_home / "aup-consent.txt").read_text()
    assert "accepted_at:" in text
    assert "version:" in text
    # ISO timestamp in body
    assert text.count("T") >= 1
    assert "Z" in text or "+" in text or "-" in text


def test_grant_consent_writes_aup_url(tmp_consent_home):
    aup_consent.grant_consent()
    text = (tmp_consent_home / "aup-consent.txt").read_text()
    assert "pentest-tools.local/aup" in text


def test_revoke_consent_removes_file(tmp_consent_home):
    aup_consent.grant_consent()
    assert aup_consent.has_consent() is True
    aup_consent.revoke_consent()
    assert aup_consent.has_consent() is False


def test_revoke_consent_when_no_file_is_noop(tmp_consent_home):
    # Must not raise
    aup_consent.revoke_consent()


def test_ensure_consent_skipped_with_env_override(tmp_consent_home, monkeypatch):
    """Setting PENTEST_TOOLS_AUP_ACCEPTED=1 bypasses the prompt for CI/scripts."""
    monkeypatch.setenv("PENTEST_TOOLS_AUP_ACCEPTED", "1")
    accepted = aup_consent.ensure_consent(interactive=True)
    assert accepted is True
    # Should NOT have written the file (env override doesn't persist)
    assert not (tmp_consent_home / "aup-consent.txt").exists()


def test_ensure_consent_returns_true_when_already_granted(tmp_consent_home):
    aup_consent.grant_consent()
    accepted = aup_consent.ensure_consent(interactive=False)
    assert accepted is True


def test_ensure_consent_returns_false_when_not_granted_and_non_interactive(tmp_consent_home):
    accepted = aup_consent.ensure_consent(interactive=False)
    assert accepted is False


def test_ensure_consent_prompts_and_grants_on_yes(tmp_consent_home, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "yes")
    monkeypatch.setattr("sys.stdout", io.StringIO())
    accepted = aup_consent.ensure_consent(interactive=True)
    assert accepted is True
    assert aup_consent.has_consent() is True


def test_ensure_consent_prompts_and_refuses_on_no(tmp_consent_home, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "no")
    monkeypatch.setattr("sys.stdout", io.StringIO())
    accepted = aup_consent.ensure_consent(interactive=True)
    assert accepted is False
    assert aup_consent.has_consent() is False


def test_ensure_consent_prompts_and_refuses_on_blank(tmp_consent_home, monkeypatch):
    """Blank input defaults to NO — safer for offensive tooling."""
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    monkeypatch.setattr("sys.stdout", io.StringIO())
    accepted = aup_consent.ensure_consent(interactive=True)
    assert accepted is False


def test_ensure_consent_handles_eof(tmp_consent_home, monkeypatch):
    """Ctrl+D mid-prompt counts as refusal, not a crash."""
    def _eof(_prompt=""):
        raise EOFError()
    monkeypatch.setattr("builtins.input", _eof)
    monkeypatch.setattr("sys.stdout", io.StringIO())
    accepted = aup_consent.ensure_consent(interactive=True)
    assert accepted is False


def test_consent_file_has_secure_permissions(tmp_consent_home):
    """Consent file should not be world-readable."""
    if os.name == "nt":
        pytest.skip("POSIX permission semantics not applicable on Windows")
    aup_consent.grant_consent()
    path = Path(tmp_consent_home) / "aup-consent.txt"
    mode = path.stat().st_mode & 0o077
    # No bits set in group/other read+write
    assert mode == 0

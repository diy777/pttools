"""Tests for the env-var credential resolver."""

from __future__ import annotations

import pytest

from cli.credential_resolvers import SecurityError
from cli.credential_resolvers.env import EnvResolver


def test_resolves_set_env_var(monkeypatch):
    monkeypatch.setenv("PTAI_TEST_PASS", "hunter2")
    cred = EnvResolver().resolve("PTAI_TEST_PASS")
    assert cred.reveal() == "hunter2"
    assert cred.source == "env"
    assert cred.ref == "PTAI_TEST_PASS"


def test_unset_env_var_raises_security_error(monkeypatch):
    monkeypatch.delenv("NEVER_SET_VAR_PTAI", raising=False)
    with pytest.raises(SecurityError) as exc:
        EnvResolver().resolve("NEVER_SET_VAR_PTAI")
    assert "unset or empty" in str(exc.value).lower()


def test_empty_env_var_raises_security_error(monkeypatch):
    monkeypatch.setenv("PTAI_EMPTY", "")
    with pytest.raises(SecurityError):
        EnvResolver().resolve("PTAI_EMPTY")


def test_empty_ref_raises():
    with pytest.raises(SecurityError):
        EnvResolver().resolve("")


def test_invalid_ref_name_raises():
    # env var names must be valid identifiers
    for bad in ("9LEADS_DIGIT", "has-dash", "has space", "has;semicolon"):
        with pytest.raises(SecurityError):
            EnvResolver().resolve(bad)


def test_resolved_value_does_not_leak_in_repr(monkeypatch):
    monkeypatch.setenv("PTAI_TEST_PASS", "hunter2")
    cred = EnvResolver().resolve("PTAI_TEST_PASS")
    assert "hunter2" not in repr(cred)
    assert "[REDACTED]" in repr(cred)

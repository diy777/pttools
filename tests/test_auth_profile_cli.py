"""Phase 1 integration tests: --auth-profile flag wires through start command."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from cli.auth_profiles import (
    AuthProfile,
    add_profile,
)
from cli.main import app

runner = CliRunner()


@pytest.fixture
def tmp_home(tmp_path, monkeypatch):
    """Redirect HOME so the profiles file lives in a tmp dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # cli.auth_profiles caches Path.home() at import-time so we patch the constants
    new_dir = tmp_path / ".pentest-tools"
    new_dir.mkdir(mode=0o700)
    new_file = new_dir / "auth-profiles.yaml"
    monkeypatch.setattr("cli.auth_profiles.PENTEST_TOOLS_DIR", new_dir)
    monkeypatch.setattr("cli.auth_profiles.PROFILES_FILE", new_file)
    return new_file


def test_auth_profile_flag_rejects_when_combined_with_login_flags(tmp_home, monkeypatch):
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="STAGE_PASS",
        ),
        tmp_home,
    )
    monkeypatch.setenv("STAGE_PASS", "hunter2")
    result = runner.invoke(
        app,
        [
            "start",
            "https://x.example",
            "--auth-profile",
            "staging",
            "--login-url",
            "https://x.example/login",
        ],
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output.lower()


def test_auth_profile_flag_rejects_unknown_profile(tmp_home):
    result = runner.invoke(
        app, ["start", "https://x.example", "--auth-profile", "ghost"]
    )
    assert result.exit_code == 2
    assert "ghost" in result.output


def test_auth_profile_resolves_and_passes_to_scan(tmp_home, monkeypatch):
    """--auth-profile X should resolve password from env and call the scan helper.

    We patch _run_authenticated_scan_cli to capture the password it received,
    and assert it matches the env var value.
    """
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            success_marker="Welcome",
            password_source="env",
            password_ref="PTAI_TEST_PROFILE_PASS",
        ),
        tmp_home,
    )
    monkeypatch.setenv("PTAI_TEST_PROFILE_PASS", "secret-from-env")

    with patch("cli.main._run_authenticated_scan_cli") as mock_scan:
        result = runner.invoke(
            app, ["start", "https://x.example", "--auth-profile", "staging"]
        )

    assert result.exit_code == 0, result.output
    mock_scan.assert_called_once()
    kwargs = mock_scan.call_args.kwargs
    assert kwargs["target"] == "https://x.example"
    assert kwargs["login_url"] == "https://x.example/login"
    assert kwargs["login_user"] == "admin"
    assert kwargs["resolved_password"] == "secret-from-env"
    assert kwargs["success_marker"] == "Welcome"


def test_auth_profile_with_unset_env_fails_security_error(tmp_home, monkeypatch):
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="PTAI_NEVER_SET_VAR_XYZ",
        ),
        tmp_home,
    )
    monkeypatch.delenv("PTAI_NEVER_SET_VAR_XYZ", raising=False)
    result = runner.invoke(
        app, ["start", "https://x.example", "--auth-profile", "staging"]
    )
    assert result.exit_code == 2
    assert "credential resolve failed" in result.output.lower()


def test_legacy_login_flags_still_work(tmp_home, monkeypatch):
    """Backward compat: existing --login-url / --login-password-env still works."""
    monkeypatch.setenv("LEGACY_PASS", "legacy-secret")
    with patch("cli.main._run_authenticated_scan_cli") as mock_scan:
        result = runner.invoke(
            app,
            [
                "start",
                "https://x.example",
                "--login-url",
                "https://x.example/login",
                "--login-user",
                "admin",
                "--login-password-env",
                "LEGACY_PASS",
            ],
        )
    assert result.exit_code == 0, result.output
    mock_scan.assert_called_once()
    kwargs = mock_scan.call_args.kwargs
    assert kwargs["login_password_env"] == "LEGACY_PASS"
    assert kwargs.get("resolved_password") is None


def test_unsupported_profile_flow_rejected(tmp_home, monkeypatch):
    """Bearer / ntlm profiles aren't supported on `start` yet (will land later)."""
    add_profile(
        AuthProfile(
            name="api",
            flow="bearer",
            token_source="env",
            token_ref="API_TOK",
        ),
        tmp_home,
    )
    monkeypatch.setenv("API_TOK", "tok")
    result = runner.invoke(
        app, ["start", "https://api.example", "--auth-profile", "api"]
    )
    assert result.exit_code == 2
    assert "form_post" in result.output

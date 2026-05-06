"""Phase 6 tests: import-from-flags migration helper."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from cli.auth_profiles import get_profile
from cli.main import app

runner = CliRunner()


@pytest.fixture
def tmp_profiles(tmp_path, monkeypatch):
    new_dir = tmp_path / ".pentest-tools"
    new_dir.mkdir(mode=0o700)
    new_file = new_dir / "auth-profiles.yaml"
    monkeypatch.setattr("cli.auth_profiles.PENTEST_TOOLS_DIR", new_dir)
    monkeypatch.setattr("cli.auth_profiles.PROFILES_FILE", new_file)
    return new_file


def test_import_from_flags_creates_profile(tmp_profiles):
    r = runner.invoke(
        app,
        [
            "auth", "profile", "import-from-flags",
            "--name", "dvwa",
            "--login-url", "http://dvwa.local/login.php",
            "--login-user", "admin",
            "--login-password-env", "DVWA_PASS",
            "--login-success-marker", "Welcome",
        ],
    )
    assert r.exit_code == 0, r.output
    p = get_profile("dvwa")
    assert p.flow == "form_post"
    assert p.login_url == "http://dvwa.local/login.php"
    assert p.username == "admin"
    assert p.password_source == "env"
    assert p.password_ref == "DVWA_PASS"
    assert p.success_marker == "Welcome"


def test_import_from_flags_dry_run_does_not_write(tmp_profiles):
    r = runner.invoke(
        app,
        [
            "auth", "profile", "import-from-flags",
            "--name", "preview",
            "--login-url", "http://x/login",
            "--login-user", "u",
            "--login-password-env", "P",
            "--dry-run",
        ],
    )
    assert r.exit_code == 0
    assert "Would save" in r.output
    # profile not actually written
    from cli.auth_profiles import ProfileError

    with pytest.raises(ProfileError):
        get_profile("preview")


def test_import_from_flags_missing_required_args(tmp_profiles):
    r = runner.invoke(
        app,
        ["auth", "profile", "import-from-flags", "--name", "x"],
    )
    assert r.exit_code != 0


def test_import_from_flags_never_writes_password_value(tmp_profiles, monkeypatch):
    """Migration helper writes only the env var NAME, not the value."""
    monkeypatch.setenv("DVWA_PASS", "actualSecretLeakSentinel999")
    runner.invoke(
        app,
        [
            "auth", "profile", "import-from-flags",
            "--name", "dvwa",
            "--login-url", "http://x/login",
            "--login-user", "admin",
            "--login-password-env", "DVWA_PASS",
        ],
    )
    raw = tmp_profiles.read_text()
    assert "DVWA_PASS" in raw
    assert "actualSecretLeakSentinel999" not in raw

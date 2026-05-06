"""Tests for the auth profile manager."""

from __future__ import annotations

import os
import stat
import sys

import pytest
import yaml

from cli.auth_profiles import (
    AuthProfile,
    ProfileError,
    add_profile,
    get_active_name,
    get_profile,
    list_profiles,
    load_profiles_file,
    remove_profile,
    resolve,
    save_profiles_file,
    set_active,
)
from cli.credential_resolvers import SecurityError

# Unix file-mode assertions are no-ops on Windows (uses ACLs, not mode bits).
_skip_windows_perms = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix file mode bits not meaningful on Windows"
)


@pytest.fixture
def tmp_profiles_path(tmp_path):
    return tmp_path / "auth-profiles.yaml"


def _make_profile(name="staging", source="env", ref="ACME_PASS"):
    return AuthProfile(
        name=name,
        flow="form_post",
        login_url="https://staging.example.com/login",
        username="admin",
        password_source=source,
        password_ref=ref,
    )


# ---------- file CRUD ----------


def test_load_missing_file_returns_empty(tmp_profiles_path):
    pf = load_profiles_file(tmp_profiles_path)
    assert pf.version == 1
    assert pf.profiles == {}
    assert pf.active == ""


@_skip_windows_perms
def test_save_creates_0600_file(tmp_profiles_path):
    pf = load_profiles_file(tmp_profiles_path)
    pf.profiles["x"] = _make_profile("x")
    save_profiles_file(pf, tmp_profiles_path)
    mode = stat.S_IMODE(tmp_profiles_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


@_skip_windows_perms
def test_load_refuses_world_readable_file(tmp_profiles_path):
    pf = load_profiles_file(tmp_profiles_path)
    pf.profiles["x"] = _make_profile("x")
    save_profiles_file(pf, tmp_profiles_path)
    os.chmod(tmp_profiles_path, 0o644)
    with pytest.raises(SecurityError) as exc:
        load_profiles_file(tmp_profiles_path)
    assert "insecure permissions" in str(exc.value)


@_skip_windows_perms
def test_load_refuses_group_readable_file(tmp_profiles_path):
    pf = load_profiles_file(tmp_profiles_path)
    pf.profiles["x"] = _make_profile("x")
    save_profiles_file(pf, tmp_profiles_path)
    os.chmod(tmp_profiles_path, 0o640)
    with pytest.raises(SecurityError):
        load_profiles_file(tmp_profiles_path)


def test_malformed_yaml_raises_profile_error(tmp_profiles_path):
    tmp_profiles_path.write_text("this is: not: valid: yaml: : :")
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError):
        load_profiles_file(tmp_profiles_path)


def test_unknown_version_rejected(tmp_profiles_path):
    tmp_profiles_path.write_text("version: 99\nprofiles: {}")
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError) as exc:
        load_profiles_file(tmp_profiles_path)
    assert "unsupported version" in str(exc.value)


def test_active_pointing_to_missing_profile_rejected(tmp_profiles_path):
    tmp_profiles_path.write_text("version: 1\nactive: ghost\nprofiles: {}")
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError):
        load_profiles_file(tmp_profiles_path)


# ---------- profile schema validation ----------


def test_profile_invalid_flow_rejected(tmp_profiles_path):
    yaml_content = (
        "version: 1\nprofiles:\n  bad:\n    flow: unknown_flow\n"
        "    password_source: env\n    password_ref: X\n"
    )
    tmp_profiles_path.write_text(yaml_content)
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError) as exc:
        load_profiles_file(tmp_profiles_path)
    assert "invalid flow" in str(exc.value)


def test_profile_invalid_source_rejected(tmp_profiles_path):
    yaml_content = (
        "version: 1\nprofiles:\n  bad:\n    flow: form_post\n"
        "    password_source: hocus_pocus\n    password_ref: X\n"
    )
    tmp_profiles_path.write_text(yaml_content)
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError):
        load_profiles_file(tmp_profiles_path)


def test_profile_with_bare_password_key_rejected(tmp_profiles_path):
    """Defense in depth: refuse to load a file with a literal password key."""
    yaml_content = (
        "version: 1\nprofiles:\n  bad:\n    flow: form_post\n"
        "    password: actualPlaintextPassword\n"
    )
    tmp_profiles_path.write_text(yaml_content)
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError) as exc:
        load_profiles_file(tmp_profiles_path)
    assert "bare" in str(exc.value).lower()


def test_profile_with_bare_token_key_rejected(tmp_profiles_path):
    yaml_content = (
        "version: 1\nprofiles:\n  bad:\n    flow: bearer\n"
        "    token: actualPlaintextToken\n"
    )
    tmp_profiles_path.write_text(yaml_content)
    tmp_profiles_path.chmod(0o600)
    with pytest.raises(ProfileError):
        load_profiles_file(tmp_profiles_path)


# ---------- public API ----------


def test_add_and_get_profile(tmp_profiles_path):
    p = _make_profile("acme")
    add_profile(p, tmp_profiles_path)
    got = get_profile("acme", tmp_profiles_path)
    assert got.name == "acme"
    assert got.flow == "form_post"
    assert got.password_ref == "ACME_PASS"


def test_first_added_becomes_active(tmp_profiles_path):
    add_profile(_make_profile("first"), tmp_profiles_path)
    assert get_active_name(tmp_profiles_path) == "first"


def test_subsequent_adds_do_not_change_active(tmp_profiles_path):
    add_profile(_make_profile("first"), tmp_profiles_path)
    add_profile(_make_profile("second", ref="OTHER_PASS"), tmp_profiles_path)
    assert get_active_name(tmp_profiles_path) == "first"


def test_duplicate_add_raises(tmp_profiles_path):
    add_profile(_make_profile("dupe"), tmp_profiles_path)
    with pytest.raises(ProfileError):
        add_profile(_make_profile("dupe"), tmp_profiles_path)


def test_set_active(tmp_profiles_path):
    add_profile(_make_profile("a"), tmp_profiles_path)
    add_profile(_make_profile("b", ref="B_PASS"), tmp_profiles_path)
    set_active("b", tmp_profiles_path)
    assert get_active_name(tmp_profiles_path) == "b"


def test_set_active_missing_raises(tmp_profiles_path):
    with pytest.raises(ProfileError):
        set_active("ghost", tmp_profiles_path)


def test_remove_active_picks_next(tmp_profiles_path):
    add_profile(_make_profile("a"), tmp_profiles_path)
    add_profile(_make_profile("b", ref="B_PASS"), tmp_profiles_path)
    remove_profile("a", tmp_profiles_path)
    assert get_active_name(tmp_profiles_path) == "b"


def test_remove_only_profile_clears_active(tmp_profiles_path):
    add_profile(_make_profile("a"), tmp_profiles_path)
    remove_profile("a", tmp_profiles_path)
    assert get_active_name(tmp_profiles_path) == ""
    assert list_profiles(tmp_profiles_path) == []


def test_get_missing_raises(tmp_profiles_path):
    with pytest.raises(ProfileError):
        get_profile("ghost", tmp_profiles_path)


# ---------- credential resolution ----------


def test_resolve_password_via_env(tmp_profiles_path, monkeypatch):
    monkeypatch.setenv("PTAI_RESOLVE_PASS", "hunter2")
    add_profile(_make_profile("acme", source="env", ref="PTAI_RESOLVE_PASS"), tmp_profiles_path)
    p = get_profile("acme", tmp_profiles_path)
    resolved = resolve(p)
    assert resolved.password is not None
    assert resolved.password.reveal() == "hunter2"
    assert resolved.token is None


def test_resolve_token_via_env(tmp_profiles_path, monkeypatch):
    monkeypatch.setenv("PTAI_RESOLVE_TOK", "tok-abc")
    p = AuthProfile(
        name="api",
        flow="bearer",
        token_source="env",
        token_ref="PTAI_RESOLVE_TOK",
    )
    add_profile(p, tmp_profiles_path)
    got = get_profile("api", tmp_profiles_path)
    resolved = resolve(got)
    assert resolved.token is not None
    assert resolved.token.reveal() == "tok-abc"
    assert resolved.password is None


def test_resolve_unset_env_var_raises(tmp_profiles_path, monkeypatch):
    monkeypatch.delenv("PTAI_NOT_SET", raising=False)
    add_profile(_make_profile("acme", source="env", ref="PTAI_NOT_SET"), tmp_profiles_path)
    p = get_profile("acme", tmp_profiles_path)
    with pytest.raises(SecurityError):
        resolve(p)


# ---------- security: profile file never contains credential values ----------


def test_saved_file_never_contains_credential_value(tmp_profiles_path, monkeypatch):
    """Sentinel password is set in env; saved file must not contain it."""
    monkeypatch.setenv("PTAI_SENTINEL_VAR", "leakIfYouFind123")
    add_profile(_make_profile("acme", source="env", ref="PTAI_SENTINEL_VAR"), tmp_profiles_path)
    raw = tmp_profiles_path.read_text()
    assert "leakIfYouFind123" not in raw


def test_round_trip_yaml_only_has_references(tmp_profiles_path):
    add_profile(_make_profile("acme", source="env", ref="ACME_PASS"), tmp_profiles_path)
    raw = yaml.safe_load(tmp_profiles_path.read_text())
    profile_yaml = raw["profiles"]["acme"]
    assert profile_yaml["password_source"] == "env"
    assert profile_yaml["password_ref"] == "ACME_PASS"
    # The literal "password" key must never appear
    assert "password" not in profile_yaml


# ---------- bearer flow ----------


def test_bearer_profile_uses_token_keys(tmp_profiles_path):
    p = AuthProfile(
        name="api",
        flow="bearer",
        token_source="env",
        token_ref="API_TOKEN",
    )
    add_profile(p, tmp_profiles_path)
    got = get_profile("api", tmp_profiles_path)
    assert got.flow == "bearer"
    assert got.token_source == "env"
    assert got.token_ref == "API_TOKEN"

"""Phase 2 tests: MCP server tools accept auth_profile, credentials never in MCP payload.

Security gate S2: confirm that when an MCP client passes auth_profile, the
underlying credential value never appears in the MCP request payload's
named arguments. The MCP client (Claude Code, Cursor, Desktop) only ever
sees the profile name string.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, patch

import pytest

from cli.auth_profiles import AuthProfile, add_profile
from mcp_server import server as mcp_server


@pytest.fixture
def tmp_profiles(tmp_path, monkeypatch):
    new_dir = tmp_path / ".pentest-tools"
    new_dir.mkdir(mode=0o700)
    new_file = new_dir / "auth-profiles.yaml"
    monkeypatch.setattr("cli.auth_profiles.PENTEST_TOOLS_DIR", new_dir)
    monkeypatch.setattr("cli.auth_profiles.PROFILES_FILE", new_file)
    return new_file


# ---------- Tool signature inspection ----------


def _tool_signature(name: str) -> inspect.Signature:
    """Look up an MCP tool function on the server module by attribute name."""
    return inspect.signature(getattr(mcp_server, name))


def test_authenticated_scan_signature_includes_auth_profile():
    sig = _tool_signature("authenticated_scan")
    assert "auth_profile" in sig.parameters


def test_test_web_app_signature_includes_auth_profile():
    sig = _tool_signature("test_web_app")
    assert "auth_profile" in sig.parameters


def test_test_active_directory_signature_includes_auth_profile():
    sig = _tool_signature("test_active_directory")
    assert "auth_profile" in sig.parameters


def test_test_cloud_signature_includes_auth_profile():
    sig = _tool_signature("test_cloud")
    assert "auth_profile" in sig.parameters


# ---------- Behavior: profile resolves server-side ----------


@pytest.mark.asyncio
async def test_authenticated_scan_with_profile_resolves_server_side(tmp_profiles, monkeypatch):
    """auth_profile must resolve credentials server-side, not via MCP payload."""
    SENTINEL = "leakDetectorSentinel987"
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="PTAI_MCP_TEST_PASS",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("PTAI_MCP_TEST_PASS", SENTINEL)

    # Patch the actual scanner so we don't hit the network. Capture the
    # WebAuthenticator the tool builds and assert it has the resolved password.
    with patch("engine.authenticated_scan.run_authenticated_scan") as mock_scan:
        mock_scan.return_value = {"findings": []}
        result = await mcp_server.authenticated_scan(
            target="https://x.example",
            auth_profile="staging",
        )

    # The result returned by the MCP tool should not echo the password back.
    assert SENTINEL not in str(result)
    # The authenticator passed to run_authenticated_scan should have the resolved pass.
    call_kwargs = mock_scan.call_args.kwargs
    auth = call_kwargs["authenticator"]
    assert auth.password == SENTINEL
    assert auth.login_url == "https://x.example/login"
    assert auth.username == "admin"


@pytest.mark.asyncio
async def test_authenticated_scan_profile_and_password_mutually_exclusive(tmp_profiles):
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="X",
        ),
        tmp_profiles,
    )
    result = await mcp_server.authenticated_scan(
        target="https://x.example",
        auth_profile="staging",
        password="someotherpass",
    )
    assert "error" in result
    assert "mutually exclusive" in result["error"].lower()


@pytest.mark.asyncio
async def test_authenticated_scan_unknown_profile_returns_error(tmp_profiles):
    result = await mcp_server.authenticated_scan(
        target="https://x.example",
        auth_profile="ghost",
    )
    assert "error" in result
    assert "ghost" in result["error"]


@pytest.mark.asyncio
async def test_authenticated_scan_legacy_path_still_works():
    """Backward compat: legacy password param still works (with warning)."""
    with patch("engine.authenticated_scan.run_authenticated_scan") as mock_scan:
        mock_scan.return_value = {"findings": []}
        await mcp_server.authenticated_scan(
            target="https://x.example",
            login_url="https://x.example/login",
            username="admin",
            password="legacy123",
        )
    auth = mock_scan.call_args.kwargs["authenticator"]
    assert auth.password == "legacy123"


@pytest.mark.asyncio
async def test_test_active_directory_with_profile_resolves(tmp_profiles, monkeypatch):
    SENTINEL = "adSentinel765"
    add_profile(
        AuthProfile(
            name="ad-prof",
            flow="ntlm",
            domain="corp.local",
            username="scanner",
            password_source="env",
            password_ref="PTAI_AD_PASS",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("PTAI_AD_PASS", SENTINEL)

    with patch("agents.ad.ad_agent.ADAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await mcp_server.test_active_directory(
            domain="corp.local", target_ip="10.0.0.1", auth_profile="ad-prof"
        )

    creds_passed = instance.run_assessment.call_args.args[2]
    assert creds_passed["password"] == SENTINEL
    assert creds_passed["username"] == "scanner"
    assert creds_passed["domain"] == "corp.local"
    assert SENTINEL not in str(result)


@pytest.mark.asyncio
async def test_test_cloud_with_profile_resolves(tmp_profiles, monkeypatch):
    SENTINEL = "cloudKeySentinel123"
    add_profile(
        AuthProfile(
            name="aws-key",
            flow="bearer",
            token_source="env",
            token_ref="PTAI_CLOUD_KEY",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("PTAI_CLOUD_KEY", SENTINEL)

    with patch("agents.cloud.cloud_agent.CloudAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await mcp_server.test_cloud(
            provider="aws", target="account-123", auth_profile="aws-key"
        )

    creds_passed = instance.run_assessment.call_args.args[2]
    assert creds_passed["secret"] == SENTINEL
    assert SENTINEL not in str(result)

"""Phase 4 tests: pttools chain — sequential multi-target scans with isolation."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from cli.auth_profiles import AuthProfile, add_profile
from cli.chain import (
    ChainStep,
    parse_pair,
    run_chain,
)


@pytest.fixture
def tmp_profiles(tmp_path, monkeypatch):
    new_dir = tmp_path / ".pentest-tools"
    new_dir.mkdir(mode=0o700)
    new_file = new_dir / "auth-profiles.yaml"
    monkeypatch.setattr("cli.auth_profiles.PENTEST_TOOLS_DIR", new_dir)
    monkeypatch.setattr("cli.auth_profiles.PROFILES_FILE", new_file)
    return new_file


# ---------- pair parsing ----------


def test_parse_pair_valid():
    step = parse_pair("staging=https://x.example")
    assert step.profile_name == "staging"
    assert step.target == "https://x.example"


def test_parse_pair_strips_whitespace():
    step = parse_pair("  staging  =  https://x.example  ")
    assert step.profile_name == "staging"
    assert step.target == "https://x.example"


def test_parse_pair_no_equals_raises():
    with pytest.raises(ValueError):
        parse_pair("just-a-name")


def test_parse_pair_empty_target_raises():
    with pytest.raises(ValueError):
        parse_pair("staging=")


def test_parse_pair_empty_profile_raises():
    with pytest.raises(ValueError):
        parse_pair("=https://x.example")


# ---------- chain execution ----------


@pytest.mark.asyncio
async def test_chain_runs_each_step_with_correct_profile(tmp_profiles, monkeypatch):
    """Each step uses its own profile's resolved password."""
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://stage.example/login",
            username="admin",
            password_source="env",
            password_ref="STAGE_PASS",
        ),
        tmp_profiles,
    )
    add_profile(
        AuthProfile(
            name="prod",
            flow="form_post",
            login_url="https://prod.example/login",
            username="readonly",
            password_source="env",
            password_ref="PROD_PASS",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("STAGE_PASS", "stage-secret")
    monkeypatch.setenv("PROD_PASS", "prod-secret")

    captured_authenticators = []

    async def _mock_run(target, authenticator, max_pages=None, **kw):
        captured_authenticators.append(
            {
                "target": target,
                "username": authenticator.username,
                "password": authenticator.password,
                "login_url": authenticator.login_url,
            }
        )
        return {"findings": []}

    with patch("engine.authenticated_scan.run_authenticated_scan", side_effect=_mock_run), patch(
        "engine.findings_db.FindingsDB"
    ) as MockDb:
        db = MockDb.return_value
        db.create_engagement = AsyncMock(side_effect=lambda **kw: {"id": f"eng-{kw['target']}"})
        db.add_finding = AsyncMock()
        db.get_engagement_summary = AsyncMock(return_value={"total_findings": 0})
        db.close = AsyncMock()

        results = await run_chain(
            [
                ChainStep("staging", "https://stage.example"),
                ChainStep("prod", "https://prod.example"),
            ]
        )

    assert len(results) == 2
    assert results[0]["status"] == "ok"
    assert results[1]["status"] == "ok"
    assert len(captured_authenticators) == 2
    # Step 1: staging with stage-secret
    assert captured_authenticators[0]["username"] == "admin"
    assert captured_authenticators[0]["password"] == "stage-secret"
    # Step 2: prod with prod-secret (not stage-secret — isolation guarantee)
    assert captured_authenticators[1]["username"] == "readonly"
    assert captured_authenticators[1]["password"] == "prod-secret"


@pytest.mark.asyncio
async def test_chain_unknown_profile_marks_skipped(tmp_profiles):
    results = await run_chain([ChainStep("ghost", "https://x.example")])
    assert results[0]["status"] == "skipped"
    assert "ghost" in results[0]["error"]


@pytest.mark.asyncio
async def test_chain_unsupported_flow_marks_skipped(tmp_profiles, monkeypatch):
    add_profile(
        AuthProfile(
            name="api",
            flow="bearer",
            token_source="env",
            token_ref="API_TOK",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("API_TOK", "tok")
    results = await run_chain([ChainStep("api", "https://api.example")])
    assert results[0]["status"] == "skipped"
    assert "form_post" in results[0]["error"]


@pytest.mark.asyncio
async def test_chain_unset_env_marks_failed(tmp_profiles, monkeypatch):
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="PTAI_NEVER_SET_CHAIN",
        ),
        tmp_profiles,
    )
    monkeypatch.delenv("PTAI_NEVER_SET_CHAIN", raising=False)
    results = await run_chain([ChainStep("staging", "https://x.example")])
    assert results[0]["status"] == "failed"
    assert "credential resolve" in results[0]["error"].lower()


@pytest.mark.asyncio
async def test_chain_findings_tagged_with_engagement_id(tmp_profiles, monkeypatch):
    """Per-engagement isolation: each finding gets its scan's engagement_id."""
    add_profile(
        AuthProfile(
            name="staging",
            flow="form_post",
            login_url="https://x.example/login",
            username="admin",
            password_source="env",
            password_ref="STAGE_PASS",
        ),
        tmp_profiles,
    )
    monkeypatch.setenv("STAGE_PASS", "x")

    added_findings: list[dict] = []

    async def _mock_run(target, authenticator, max_pages=None, **kw):
        return {"findings": [{"title": "test1", "severity": "high"}]}

    with patch("engine.authenticated_scan.run_authenticated_scan", side_effect=_mock_run), patch(
        "engine.findings_db.FindingsDB"
    ) as MockDb:
        db = MockDb.return_value
        db.create_engagement = AsyncMock(return_value={"id": "eng-staging-1"})

        async def _capture_finding(f):
            added_findings.append(dict(f))
            return None

        db.add_finding = AsyncMock(side_effect=_capture_finding)
        db.get_engagement_summary = AsyncMock(return_value={"total_findings": 1})
        db.close = AsyncMock()

        await run_chain([ChainStep("staging", "https://x.example")])

    assert len(added_findings) == 1
    assert added_findings[0]["engagement_id"] == "eng-staging-1"

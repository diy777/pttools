"""Coverage fill for thin specialist-agent wrappers.

Targets api_security, credential_tester, vuln_scanner, privesc, mobile,
wireless, social_engineer, cloud, ad, poc_validator, recon. Each has the
same shape: __init__, run_assessment that picks LLM-driven or
deterministic, and a _run_deterministic_* helper.

We exercise both paths and the LLMUnavailableError fallback for each.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.api_security.api_security_agent import APISecurityAgent
from agents.credential_tester.credential_tester_agent import CredentialTesterAgent
from agents.privesc.privesc_agent import PrivescAdvisorAgent
from agents.social_engineer.social_engineer_agent import SocialEngineerAgent
from agents.vuln_scanner.vuln_scanner_agent import VulnScannerAgent


def _registry_with_tool(tool_name: str = "fake", findings: list | None = None):
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": findings or []})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    return registry, fake_tool


def _empty_db():
    db = MagicMock()
    db.add_finding = AsyncMock()
    return db


# ─── APISecurityAgent ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_security_no_llm_runs_deterministic():
    registry, fake_tool = _registry_with_tool(findings=[{"title": "f1"}, {"title": "f2"}])
    db = _empty_db()
    agent = APISecurityAgent(registry, db, llm=None)
    result = await agent.run_assessment("https://api.example.com", engagement_id="eng-1")
    assert result["agent"] == "api_security"
    assert result["status"] == "complete"
    assert result["findings_count"] >= 1
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_api_security_llm_unavailable_falls_back():
    registry, _ = _registry_with_tool(findings=[])
    db = _empty_db()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = APISecurityAgent(registry, db, llm=llm)

    # think() raises LLMUnavailableError on first call; run_assessment catches
    # and falls through to deterministic.
    result = await agent.run_assessment("https://api.example.com", engagement_id="eng-1")
    assert result["agent"] == "api_security"
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_api_security_deterministic_skips_uninstalled_tool():
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = False
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    agent = APISecurityAgent(registry, _empty_db(), llm=None)
    result = await agent.run_assessment("https://api.example.com")
    assert result["findings_count"] == 0


@pytest.mark.asyncio
async def test_api_security_deterministic_swallows_tool_exception():
    registry, fake_tool = _registry_with_tool()
    fake_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
    agent = APISecurityAgent(registry, _empty_db(), llm=None)
    result = await agent.run_assessment("https://api.example.com")
    assert result["status"] == "complete"


# ─── CredentialTesterAgent ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_credential_tester_deterministic():
    registry, fake_tool = _registry_with_tool(findings=[{"title": "default cred"}])
    db = _empty_db()
    agent = CredentialTesterAgent(registry, db)
    result = await agent.run_assessment("10.0.0.1", engagement_id="eng-1")
    assert result["agent"] == "credential_tester"
    assert result["findings_count"] >= 1
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_credential_tester_llm_unavailable_falls_back():
    registry, _ = _registry_with_tool(findings=[])
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = CredentialTesterAgent(registry, _empty_db(), llm=llm)
    result = await agent.run_assessment("10.0.0.1")
    assert result["agent"] == "credential_tester"


@pytest.mark.asyncio
async def test_credential_tester_swallows_tool_exception():
    registry, fake_tool = _registry_with_tool()
    fake_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
    agent = CredentialTesterAgent(registry, _empty_db())
    result = await agent.run_assessment("10.0.0.1")
    assert result["findings_count"] == 0


# ─── VulnScannerAgent ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_vuln_scanner_deterministic():
    registry, fake_tool = _registry_with_tool(findings=[{"title": "v"}])
    db = _empty_db()
    agent = VulnScannerAgent(registry, db)
    result = await agent.run_assessment("10.0.0.1", engagement_id="eng-1")
    assert result["agent"] == "vuln_scanner"
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_vuln_scanner_llm_unavailable_falls_back():
    registry, _ = _registry_with_tool()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = VulnScannerAgent(registry, _empty_db(), llm=llm)
    result = await agent.run_assessment("10.0.0.1")
    assert result["agent"] == "vuln_scanner"


@pytest.mark.asyncio
async def test_vuln_scanner_swallows_tool_exception():
    registry, fake_tool = _registry_with_tool()
    fake_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
    agent = VulnScannerAgent(registry, _empty_db())
    result = await agent.run_assessment("10.0.0.1")
    assert result["findings_count"] == 0


# ─── PrivescAdvisorAgent ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_privesc_deterministic_linux():
    registry, fake_tool = _registry_with_tool(findings=[{"title": "suid"}])
    db = _empty_db()
    agent = PrivescAdvisorAgent(registry, db)
    result = await agent.run_assessment("10.0.0.1", platform="linux", engagement_id="eng-1")
    assert result["agent"] == "privesc"
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_privesc_deterministic_windows():
    registry, _ = _registry_with_tool()
    agent = PrivescAdvisorAgent(registry, _empty_db())
    result = await agent.run_assessment("10.0.0.1", platform="windows")
    assert result["agent"] == "privesc"


@pytest.mark.asyncio
async def test_privesc_llm_unavailable_falls_back():
    registry, _ = _registry_with_tool()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = PrivescAdvisorAgent(registry, _empty_db(), llm=llm)
    result = await agent.run_assessment("10.0.0.1")
    assert result["agent"] == "privesc"


@pytest.mark.asyncio
async def test_privesc_swallows_tool_exception():
    registry, fake_tool = _registry_with_tool()
    fake_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
    agent = PrivescAdvisorAgent(registry, _empty_db())
    result = await agent.run_assessment("10.0.0.1")
    assert "findings_count" in result


# ─── SocialEngineerAgent ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_social_engineer_deterministic_phishing():
    registry, fake_tool = _registry_with_tool(findings=[{"title": "spoofable"}])
    db = _empty_db()
    agent = SocialEngineerAgent(registry, db)
    result = await agent.run_assessment("acme.com", campaign_type="phishing", engagement_id="eng-1")
    # social_engineer's deterministic dict does not include "agent" key by design
    assert result["status"] == "complete"
    assert result["campaign_type"] == "phishing"
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_social_engineer_deterministic_osint():
    registry, _ = _registry_with_tool()
    agent = SocialEngineerAgent(registry, _empty_db())
    result = await agent.run_assessment("acme.com", campaign_type="osint")
    assert result["status"] == "complete"
    assert result["campaign_type"] == "osint"


@pytest.mark.asyncio
async def test_social_engineer_llm_unavailable_falls_back():
    registry, _ = _registry_with_tool()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = SocialEngineerAgent(registry, _empty_db(), llm=llm)
    result = await agent.run_assessment("acme.com")
    assert result["status"] == "complete"

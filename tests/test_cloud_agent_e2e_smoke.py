"""End-to-end smoke test for CloudAgent provider dispatch.

CloudAgent delegates entirely to external tools (prowler for AWS,
scoutsuite for multi-cloud, azurehound for Azure, etc.) so a
"fully real" E2E would need those tools + cloud credentials. Instead
this tests the wire path that's actually agent-internal:

- Provider strings dispatch to the right tool list
- A tool that produces findings has those findings persisted with the
  engagement_id tag
- The result dict carries the contractual fields (provider, target,
  findings_count, status)
- An unknown provider falls back to the multi-cloud default (scoutsuite)
  rather than crashing

No external services, no cloud credentials, no docker. Runs in every
CI matrix cell.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.cloud.cloud_agent import CloudAgent
from engine.findings_db import FindingsDB


def _make_fake_tool(findings: list[dict[str, Any]]):
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        return {"findings": findings, "exit_code": 0}

    tool.execute = _execute
    return tool


def _make_uninstalled_tool():
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=False)
    return tool


@pytest.mark.asyncio
async def test_aws_dispatches_to_prowler_pacu_cloudfox(tmp_path):
    """provider='aws' must invoke prowler / pacu / cloudfox."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        if name in ("prowler", "pacu", "cloudfox"):
            return _make_fake_tool([
                {
                    "title": f"Finding from {name}",
                    "severity": "medium",
                    "category": "iam",
                    "tool_source": name,
                    "target": "test-account",
                }
            ])
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="test-account", scope="cloud", intensity="normal"
        )
        agent = CloudAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            provider="aws",
            target="test-account",
            engagement_id=engagement["id"],
        )
        assert result["provider"] == "aws"
        assert result["target"] == "test-account"
        assert result["status"] == "complete"
        assert result["findings_count"] == 3, (
            f"expected 3 findings (prowler+pacu+cloudfox), got: {result}"
        )

        # Each tool's finding should have been persisted with engagement_id.
        findings = await db.get_findings(engagement_id=engagement["id"])
        assert len(findings) == 3
        sources = {f["tool_source"] for f in findings}
        assert sources == {"prowler", "pacu", "cloudfox"}
        # Wire path check: registry was queried for the right tools.
        assert {"prowler", "pacu", "cloudfox"}.issubset(set(invoked))
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_azure_dispatches_to_scoutsuite_azurehound(tmp_path):
    """provider='azure' must invoke scoutsuite + azurehound, not the AWS set."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_uninstalled_tool()  # nothing installed; just check dispatch

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="test-tenant", scope="cloud", intensity="normal"
        )
        agent = CloudAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            provider="azure",
            target="test-tenant",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert {"scoutsuite", "azurehound"}.issubset(set(invoked))
        assert "prowler" not in invoked
        assert "pacu" not in invoked
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_unknown_provider_falls_back_to_scoutsuite(tmp_path):
    """An unknown provider string must not crash, just fall back to multi-cloud."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="weird-cloud", scope="cloud", intensity="normal"
        )
        agent = CloudAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            provider="oracle-cloud-galactic",
            target="weird-cloud",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert "scoutsuite" in invoked
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_no_findings_when_no_tools_installed(tmp_path):
    """Cloud assessment without any tools installed should still complete cleanly.

    A new user without prowler/scoutsuite installed should NOT see crashes,
    just an empty findings list. Catches regressions where missing tools
    silently break the agent.
    """
    registry = MagicMock()
    registry.get_tool = lambda _name: _make_uninstalled_tool()

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="test-account", scope="cloud", intensity="normal"
        )
        agent = CloudAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            provider="aws",
            target="test-account",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert result["findings_count"] == 0
        findings = await db.get_findings(engagement_id=engagement["id"])
        assert findings == []
    finally:
        await db.close()

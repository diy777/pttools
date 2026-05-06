"""End-to-end smoke test for ADAgent dispatch and tool integration.

Like CloudAgent, ADAgent delegates entirely to external tools
(enum4linux, ldapsearch, rpcclient, smbclient, nbtscan, netexec,
kerbrute). A "fully real" E2E would require a docker'd Samba/AD test
domain. Instead this tests the wire path that's actually agent-internal:

- run_assessment dispatches across the four phases (enumeration,
  smb_enum, kerberoasting, asrep_roast)
- Findings from each tool get tagged with engagement_id and persisted
- Result dict carries the contractual fields (target, domain,
  findings_count, status)
- Missing tools are skipped silently — new users without netexec
  installed must not see crashes

No external services. Runs in every CI matrix cell.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.ad.ad_agent import ADAgent
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
async def test_ad_dispatches_across_all_four_phases(tmp_path):
    """The agent must invoke tools from enumeration, smb_enum, kerberoasting,
    and asrep_roast phases — not just the first."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_fake_tool([
            {
                "title": f"AD finding from {name}",
                "severity": "high",
                "category": "ad",
                "tool_source": name,
                "target": "dc.test.local",
            }
        ])

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="dc.test.local", scope="ad", intensity="normal"
        )
        agent = ADAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="dc.test.local",
            domain="TEST.LOCAL",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert result["target"] == "dc.test.local"
        assert result["domain"] == "TEST.LOCAL"

        # Wire path: every phase tool should have been queried.
        expected = {
            "enum4linux", "ldapsearch", "rpcclient",
            "smbclient", "nbtscan",
            "netexec",
            "kerbrute",
        }
        assert expected.issubset(set(invoked)), (
            f"missing phase dispatch: {expected - set(invoked)}"
        )
        assert result["findings_count"] == len(expected), (
            f"expected one finding per dispatched tool, got {result['findings_count']}"
        )

        findings = await db.get_findings(engagement_id=engagement["id"])
        assert len(findings) == len(expected)
        for f in findings:
            assert f["engagement_id"] == engagement["id"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_ad_no_tools_installed_returns_clean_zero(tmp_path):
    """Without any AD tools installed, the agent must complete with zero
    findings rather than crash. Catches the new-user-no-tools regression."""
    registry = MagicMock()
    registry.get_tool = lambda _name: _make_uninstalled_tool()

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="dc.test.local", scope="ad", intensity="normal"
        )
        agent = ADAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="dc.test.local",
            domain="TEST.LOCAL",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert result["findings_count"] == 0
        findings = await db.get_findings(engagement_id=engagement["id"])
        assert findings == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_ad_partial_tool_install_collects_what_it_can(tmp_path):
    """Some tools installed, others not. The agent must collect findings
    from the installed tools and skip the rest silently — common partial-
    install state for users on Kali / their own VM."""
    installed = {"enum4linux", "smbclient"}

    def _registry_get(name: str):
        if name in installed:
            return _make_fake_tool([
                {
                    "title": f"Finding from {name}",
                    "severity": "medium",
                    "category": "ad",
                    "tool_source": name,
                    "target": "dc.test.local",
                }
            ])
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="dc.test.local", scope="ad", intensity="normal"
        )
        agent = ADAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="dc.test.local",
            domain="TEST.LOCAL",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        # Only the two installed tools should have produced findings.
        assert result["findings_count"] == 2
        findings = await db.get_findings(engagement_id=engagement["id"])
        sources = {f["tool_source"] for f in findings}
        assert sources == installed
    finally:
        await db.close()

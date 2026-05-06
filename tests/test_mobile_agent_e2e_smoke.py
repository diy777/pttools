"""End-to-end smoke test for MobileAgent platform dispatch.

MobileAgent runs static analysis tools (jadx/apktool for Android,
class-dump/otool for iOS), dynamic instrumentation (frida, objection),
and network interception (burp, mitmproxy). A "fully real" E2E would
need a real APK or IPA + the static analysis toolchain installed.
Instead this tests the wire path:

- Android targets dispatch to jadx/apktool/drozer + frida/objection
  + network tools, NOT the iOS toolchain.
- iOS targets dispatch to class-dump/otool/binwalk + frida/objection
  + network tools, NOT the Android toolchain.
- Each tool's findings get tagged with engagement_id and persisted.
- An unknown platform falls back to dynamic + network tools (no
  static phase) rather than crashing.

No external services. Runs in every CI matrix cell.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.mobile.mobile_agent import MobileAgent
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
async def test_android_dispatches_static_dynamic_network_phases(tmp_path):
    """An android target must invoke jadx/apktool/drozer + frida/objection + net tools."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_fake_tool([
            {
                "title": f"Mobile finding from {name}",
                "severity": "medium",
                "category": "mobile",
                "tool_source": name,
                "target": "/tmp/test.apk",
            }
        ])

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="/tmp/test.apk", scope="mobile", intensity="normal"
        )
        agent = MobileAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="/tmp/test.apk",
            platform="android",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert result["platform"] == "android"
        assert result["target"] == "/tmp/test.apk"

        expected_android = {
            "jadx", "apktool", "drozer",  # static
            "frida", "objection",          # dynamic
            "burp", "mitmproxy", "nuclei", # network
        }
        assert expected_android.issubset(set(invoked)), (
            f"missing android phase tools: {expected_android - set(invoked)}"
        )
        # iOS-only tools must NOT be invoked.
        assert "class-dump" not in invoked
        assert "otool" not in invoked
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_ios_dispatches_to_ios_static_toolchain(tmp_path):
    """An iOS target must invoke class-dump/otool/binwalk, NOT the android set."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="/tmp/test.ipa", scope="mobile", intensity="normal"
        )
        agent = MobileAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="/tmp/test.ipa",
            platform="ios",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        assert result["platform"] == "ios"

        expected_ios = {"class-dump", "otool", "binwalk"}
        assert expected_ios.issubset(set(invoked))
        # Android-specific static tools must NOT be invoked.
        assert "jadx" not in invoked
        assert "apktool" not in invoked
        assert "drozer" not in invoked
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_unknown_platform_falls_back_to_dynamic_and_network_only(tmp_path):
    """An unknown platform string must not crash — just skips static analysis."""
    invoked: list[str] = []

    def _registry_get(name: str):
        invoked.append(name)
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="/tmp/x.bin", scope="mobile", intensity="normal"
        )
        agent = MobileAgent(registry=registry, db=db, llm=None)
        result = await agent.run_assessment(
            target="/tmp/x.bin",
            platform="windows-phone-2007",
            engagement_id=engagement["id"],
        )
        assert result["status"] == "complete"
        # No static-analysis tools queried for an unknown platform.
        assert "jadx" not in invoked
        assert "class-dump" not in invoked
        # Dynamic + network tools still tried.
        assert "frida" in invoked
        assert "burp" in invoked
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_findings_carry_engagement_id_and_required_fields(tmp_path):
    """Every persisted finding must have engagement_id + the standard fields."""
    def _registry_get(name: str):
        if name == "jadx":
            return _make_fake_tool([
                {
                    "title": "Hardcoded API key in com/example/Config.java",
                    "severity": "high",
                    "category": "mobile",
                    "tool_source": "jadx",
                    "target": "/tmp/test.apk",
                }
            ])
        return _make_uninstalled_tool()

    registry = MagicMock()
    registry.get_tool = _registry_get

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="/tmp/test.apk", scope="mobile", intensity="normal"
        )
        agent = MobileAgent(registry=registry, db=db, llm=None)
        await agent.run_assessment(
            target="/tmp/test.apk",
            platform="android",
            engagement_id=engagement["id"],
        )
        findings = await db.get_findings(engagement_id=engagement["id"])
        assert len(findings) == 1
        f = findings[0]
        assert f["title"] == "Hardcoded API key in com/example/Config.java"
        assert f["severity"] == "high"
        assert f["tool_source"] == "jadx"
        assert f["engagement_id"] == engagement["id"]
    finally:
        await db.close()

"""Tests for arjun parameter-discovery integration.

Two layers:
1. Output parser: arjun's stdout format varies by version, so the parser
   must extract param names from any of the known intro phrases without
   coupling to a single layout.
2. WebAgent integration: when arjun discovers hidden params, the deterministic
   pipeline must synthesize injection URLs from base target + param names so
   sqlmap and dalfox have something to attack on parameter-less targets.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.web.web_agent import WebAgent
from tools.registry import _extract_arjun_params, parse_arjun

# ─── Output parser ────────────────────────────────────────────────────────


class TestExtractArjunParams:
    def test_parameters_found_line(self):
        stdout = (
            "[~] Probing the target for stability\n"
            "[+] Stable response with 200\n"
            "[+] Parameters found: id, page, user\n"
        )
        assert _extract_arjun_params(stdout) == ["id", "page", "user"]

    def test_discovered_parameters_line(self):
        stdout = "[~] Discovered parameters: q, search, limit"
        assert _extract_arjun_params(stdout) == ["q", "search", "limit"]

    def test_heuristic_scanner_phrasing(self):
        stdout = "[+] Heuristic scanner found these parameters: token, csrf"
        assert _extract_arjun_params(stdout) == ["token", "csrf"]

    def test_dedupes_repeated_params(self):
        stdout = (
            "[~] Reflections: id, page\n"
            "[+] Parameters found: id, page, user\n"
        )
        assert _extract_arjun_params(stdout) == ["id", "page", "user"]

    def test_returns_empty_on_no_params(self):
        stdout = "[~] No parameters identified."
        assert _extract_arjun_params(stdout) == []

    def test_filters_out_status_words(self):
        # The "Heuristic scanner found these parameters" phrase contains
        # several identifier-shaped words that aren't actual params.
        stdout = "[+] Heuristic scanner found these parameters: id, q"
        params = _extract_arjun_params(stdout)
        assert "scanner" not in params
        assert "found" not in params
        assert params == ["id", "q"]

    def test_handles_mixed_case_intro(self):
        stdout = "[+] PARAMETERS FOUND: id"
        assert _extract_arjun_params(stdout) == ["id"]


class TestParseArjun:
    def test_returns_single_discovery_finding(self):
        result = {
            "stdout": "[+] Parameters found: id, q",
            "target": "http://test.local",
        }
        findings = parse_arjun(result)
        assert len(findings) == 1
        f = findings[0]
        assert f["tool_source"] == "arjun"
        assert f["category"] == "discovery"
        assert f["severity"] == "info"
        assert "id" in f["description"] and "q" in f["description"]
        assert "id,q" in f["evidence"]

    def test_returns_empty_when_no_params(self):
        result = {"stdout": "no params here", "target": "http://test.local"}
        assert parse_arjun(result) == []


# ─── WebAgent pipeline integration ────────────────────────────────────────


def _make_arjun_tool(stdout: str):
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        return {
            "stdout": stdout,
            "exit_code": 0,
            "findings": parse_arjun({"stdout": stdout, "target": target}),
        }

    tool.execute = _execute
    return tool


def _make_inert_crawler():
    """Crawler that returns no parameterized URLs (forces arjun fallback)."""
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        return {"stdout": "", "exit_code": 0, "findings": []}

    tool.execute = _execute
    return tool


@pytest.mark.asyncio
async def test_discover_hidden_params_returns_arjun_param_list():
    """When arjun runs, _discover_hidden_params must surface its param list."""
    arjun = _make_arjun_tool("[+] Parameters found: id, q, page")
    registry = MagicMock()
    registry.get_tool = lambda name: arjun if name == "arjun" else None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    params = await agent._discover_hidden_params("http://test.local", "eng-1")
    assert params == ["id", "q", "page"]
    # Discovery finding must have been persisted.
    db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_discover_hidden_params_empty_when_arjun_not_installed():
    registry = MagicMock()
    registry.get_tool = lambda name: None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    params = await agent._discover_hidden_params("http://test.local", "eng-1")
    assert params == []


@pytest.mark.asyncio
async def test_arjun_synthesizes_injection_targets_when_crawler_finds_nothing():
    """The whole point of arjun: bare targets get param-injection URLs synthesized."""
    arjun = _make_arjun_tool("[+] Parameters found: id, q")
    crawler = _make_inert_crawler()

    captured_targets: list[str] = []

    def _make_injection_tool(name):
        tool = MagicMock()
        tool.is_installed = MagicMock(return_value=True)

        async def _execute(target, args=None, timeout=600.0):
            captured_targets.append(target)
            return {"findings": [], "exit_code": 0}

        tool.execute = _execute
        return tool

    sqlmap = _make_injection_tool("sqlmap")
    dalfox = _make_injection_tool("dalfox")

    registry = MagicMock()

    def _get(name):
        return {
            "arjun": arjun,
            "katana": crawler,
            "sqlmap": sqlmap,
            "dalfox": dalfox,
        }.get(name)

    registry.get_tool = _get
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    result = await agent._run_deterministic("http://test.local", ["sqli", "xss"], "eng-1")

    assert result["hidden_params_discovered"] == 2
    # injection tools must have been called against synthesized parameterized URLs
    assert any("?id=1" in t or "?q=1" in t for t in captured_targets), (
        f"injection tools never received arjun-derived URLs: {captured_targets}"
    )

"""Verifies the crawl-then-inject pipeline in WebAgent deterministic mode.

Without this pipeline sqlmap and dalfox were given the bare target URL with
no query parameters and produced zero findings. The crawler now runs first,
extracts parameterized URLs, and feeds each URL to the injection tools in
parallel.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.web.web_agent import WebAgent


def _make_crawler(urls_stdout: str):
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        return {"stdout": urls_stdout, "exit_code": 0, "findings": []}

    tool.execute = _execute
    return tool


def _make_injection_tool(name: str, finding_per_url: bool = True):
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)
    tool.calls = []

    async def _execute(target, args=None, timeout=600.0):
        tool.calls.append(target)
        if not finding_per_url:
            return {"findings": [], "exit_code": 0}
        return {
            "findings": [
                {
                    "title": f"{name}-found-on-{target}",
                    "severity": "high",
                    "category": "injection",
                    "tool_source": name,
                    "target": target,
                }
            ],
            "exit_code": 0,
        }

    tool.execute = _execute
    return tool


@pytest.mark.asyncio
async def test_discover_param_urls_extracts_parameterized_urls():
    """Crawler stdout with a mix of plain and parameterized URLs returns only the parameterized ones."""
    crawler_stdout = "\n".join(
        [
            "http://test.local/",
            "http://test.local/about",
            "http://test.local/search?q=test",
            "http://test.local/product?id=1",
            "http://test.local/product?id=1",  # duplicate, dedup
            "garbage line not a url",
            "https://test.local/api/users?limit=10",
        ]
    )
    registry = MagicMock()
    registry.get_tool = lambda name: _make_crawler(crawler_stdout) if name == "katana" else None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls("http://test.local")

    assert urls == [
        "http://test.local/search?q=test",
        "http://test.local/product?id=1",
        "https://test.local/api/users?limit=10",
    ]


@pytest.mark.asyncio
async def test_discover_param_urls_returns_empty_when_no_crawler_installed():
    registry = MagicMock()
    registry.get_tool = lambda name: None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls("http://test.local")
    assert urls == []


@pytest.mark.asyncio
async def test_discover_param_urls_caps_at_max_targets():
    """A chatty crawler that emits 100 parameterized URLs is capped to _MAX_INJECTION_TARGETS."""
    stdout = "\n".join(f"http://test.local/p{i}?id={i}" for i in range(100))
    registry = MagicMock()
    registry.get_tool = lambda name: _make_crawler(stdout) if name == "katana" else None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls("http://test.local")
    assert len(urls) == agent._MAX_INJECTION_TARGETS


@pytest.mark.asyncio
async def test_injection_phase_runs_tool_once_per_url():
    """sqlmap should be invoked once per parameterized URL with that URL as target."""
    sqlmap = _make_injection_tool("sqlmap")
    registry = MagicMock()
    registry.get_tool = lambda name: sqlmap if name == "sqlmap" else None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = [
        "http://test.local/search?q=x",
        "http://test.local/product?id=1",
        "http://test.local/api?u=admin",
    ]
    result = await agent._run_injection_phase("sqlmap", urls, "eng-test", "sqli")

    assert sorted(sqlmap.calls) == sorted(urls)
    assert result["findings_count"] == 3
    assert result["targets_tested"] == 3
    assert db.add_finding.await_count == 3


@pytest.mark.asyncio
async def test_injection_phase_no_op_when_tool_not_installed():
    registry = MagicMock()
    registry.get_tool = lambda name: None
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)
    result = await agent._run_injection_phase("sqlmap", ["http://x?id=1"], "eng-test", "sqli")
    assert result == {"phase": "sqli", "findings_count": 0}

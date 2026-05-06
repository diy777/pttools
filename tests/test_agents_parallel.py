"""Verifies agents run their tool phases in parallel, not sequentially.

Regression guard for the bug where WebAgent's deterministic mode took >20s
because each tool ran in series. With three 0.5s tools running in parallel
the wall-clock should be near 0.5s, not 1.5s.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.web.web_agent import WebAgent


def _make_slow_tool(name: str, delay: float, findings_count: int = 1):
    """Return a SecurityTool-like mock whose execute() sleeps for `delay` seconds."""
    tool = MagicMock()
    tool.name = name
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        # Honor timeout: simulates SecurityTool.execute killing a slow subprocess.
        # If the configured delay exceeds timeout, return a timed-out result with
        # exit_code=-1 (matches the real production signature).
        try:
            await asyncio.wait_for(asyncio.sleep(delay), timeout=timeout)
        except asyncio.TimeoutError:
            return {"findings": [], "exit_code": -1}
        return {
            "findings": [
                {
                    "title": f"finding-{name}-{i}",
                    "severity": "info",
                    "category": "discovery",
                    "tool_source": name,
                    "target": target,
                }
                for i in range(findings_count)
            ]
        }

    tool.execute = _execute
    return tool


@pytest.mark.asyncio
async def test_web_agent_runs_tools_within_phase_in_parallel():
    """Three tools with 0.5s sleeps should complete in roughly 0.5s, not 1.5s."""
    registry = MagicMock()
    tools = {
        "gobuster": _make_slow_tool("gobuster", 0.5),
        "ffuf": _make_slow_tool("ffuf", 0.5),
        "feroxbuster": _make_slow_tool("feroxbuster", 0.5),
        "dirsearch": _make_slow_tool("dirsearch", 0.5),
        "katana": _make_slow_tool("katana", 0.5),
    }
    registry.get_tool = lambda name: tools.get(name)

    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)

    start = time.perf_counter()
    result = await agent._run_tool_phase(
        ["gobuster", "ffuf", "feroxbuster", "dirsearch", "katana"],
        "http://test.local",
        "eng-test",
        "content_discovery",
    )
    elapsed = time.perf_counter() - start

    # 5 tools × 0.5s sequential = 2.5s. Parallel should be ~0.5s.
    # Allow generous slack for CI; anything under 1.5s proves parallelism.
    assert elapsed < 1.5, f"phase took {elapsed:.2f}s; expected <1.5s with parallel execution"
    assert result["findings_count"] == 5
    assert db.add_finding.await_count == 5


@pytest.mark.asyncio
async def test_web_agent_per_tool_timeout_does_not_block_others():
    """One slow tool that exceeds timeout should not block the rest of the phase."""
    registry = MagicMock()
    tools = {
        "gobuster": _make_slow_tool("gobuster", 0.1),
        "ffuf": _make_slow_tool("ffuf", 0.1),
        # Simulate a hanging tool: sleeps longer than the per-tool timeout.
        "feroxbuster": _make_slow_tool("feroxbuster", WebAgent._DETERMINISTIC_TOOL_TIMEOUT + 1.0),
    }
    registry.get_tool = lambda name: tools.get(name)
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)

    # Use a much shorter timeout so the test is fast.
    agent._DETERMINISTIC_TOOL_TIMEOUT = 0.5

    start = time.perf_counter()
    result = await agent._run_tool_phase(
        ["gobuster", "ffuf", "feroxbuster"],
        "http://test.local",
        "eng-test",
        "content_discovery",
    )
    elapsed = time.perf_counter() - start

    # Should be bounded by the timeout, not the slow tool.
    assert elapsed < 1.5, f"phase took {elapsed:.2f}s; timeout should bound it"
    # gobuster + ffuf produced findings; feroxbuster timed out.
    assert result["findings_count"] == 2


@pytest.mark.asyncio
async def test_web_agent_skips_uninstalled_tools_quickly():
    """Phases with no installed tools should return immediately."""
    registry = MagicMock()
    registry.get_tool = lambda name: None  # nothing installed
    db = MagicMock()
    db.add_finding = AsyncMock()

    agent = WebAgent(registry=registry, db=db, llm=None)

    start = time.perf_counter()
    result = await agent._run_tool_phase(
        ["gobuster", "ffuf", "feroxbuster"],
        "http://test.local",
        "eng-test",
        "content_discovery",
    )
    elapsed = time.perf_counter() - start

    assert elapsed < 0.1, "phase with no installed tools should return immediately"
    assert result["findings_count"] == 0

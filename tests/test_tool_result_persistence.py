"""Regression guard for SecurityTool.execute() audit-row persistence.

Two pre-existing gaps caused gobuster/ffuf/dalfox to be missing from the
tool_results audit table on engagement re-runs:

1. Cache hits returned the cached payload without persisting a new
   tool_results row, so the second engagement looked like it never ran
   those tools.
2. Exceptions in parse_output or cache.put were caught by the broad
   except Exception in execute(), which returned early and skipped
   persistence even though the subprocess succeeded.

These tests pin both behaviours so they can't regress silently.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.registry import SecurityTool


@pytest.fixture(autouse=True)
def _reset_cache():
    """Make sure leftover cache state from another test doesn't leak in."""
    SecurityTool._cache = None
    SecurityTool._cache_disabled = False
    yield
    SecurityTool._cache = None
    SecurityTool._cache_disabled = False


@pytest.mark.asyncio
async def test_cache_hit_still_persists_audit_row():
    """Cache hits must produce a tool_results row for the current engagement."""
    cached_payload = {
        "tool": "gobuster",
        "target": "http://t.local",
        "exit_code": 0,
        "stdout": "/admin\n/api",
        "stderr": "",
        "duration": 1.0,
        "findings": [{"title": "x", "severity": "info"}],
    }

    fake_cache = MagicMock()
    fake_cache.get = AsyncMock(return_value=dict(cached_payload))
    fake_cache.put = AsyncMock()
    SecurityTool._cache = fake_cache

    persist_mock = AsyncMock()
    with patch("tools.registry._persist_tool_result", persist_mock):
        tool = SecurityTool("gobuster", "web", "x", "gobuster")
        result = await tool.execute("http://t.local")

    assert result["cache_hit"] is True
    assert result["findings"] == [{"title": "x", "severity": "info"}]
    persist_mock.assert_awaited_once()
    persisted_result, _persisted_args = persist_mock.call_args.args
    assert persisted_result["tool"] == "gobuster"
    assert persisted_result["cache_hit"] is True


@pytest.mark.asyncio
async def test_parse_output_failure_still_persists():
    """A buggy parser must not lose the audit row."""

    def _bad_parser(_result: dict[str, Any]) -> list[dict[str, Any]]:
        raise ValueError("parser exploded")

    persist_mock = AsyncMock()
    fake_proc = MagicMock()
    fake_proc.communicate = AsyncMock(return_value=(b"some output", b""))
    fake_proc.returncode = 0

    with (
        patch("tools.registry._persist_tool_result", persist_mock),
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)),
    ):
        tool = SecurityTool("ffuf", "web", "x", "ffuf", parse_output=_bad_parser)
        result = await tool.execute("http://t.local")

    # The result still comes back, just with empty findings since the parser failed.
    assert result["exit_code"] == 0
    assert result["findings"] == []
    persist_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_cache_put_failure_still_persists():
    """Cache write failure must not lose the audit row."""
    fake_cache = MagicMock()
    fake_cache.get = AsyncMock(return_value=None)
    fake_cache.put = AsyncMock(side_effect=RuntimeError("disk full"))
    SecurityTool._cache = fake_cache

    persist_mock = AsyncMock()
    fake_proc = MagicMock()
    fake_proc.communicate = AsyncMock(return_value=(b"output", b""))
    fake_proc.returncode = 0

    with (
        patch("tools.registry._persist_tool_result", persist_mock),
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)),
    ):
        tool = SecurityTool("dalfox", "web", "x", "dalfox")
        result = await tool.execute("http://t.local")

    assert result["exit_code"] == 0
    persist_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_binary_does_not_persist():
    """FileNotFoundError on missing binary should NOT write an audit row."""
    persist_mock = AsyncMock()

    with (
        patch("tools.registry._persist_tool_result", persist_mock),
        patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError())),
    ):
        tool = SecurityTool("does-not-exist", "web", "x", "does-not-exist")
        result = await tool.execute("http://t.local")

    assert "error" in result
    persist_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_subprocess_failure_persists_with_error():
    """Other subprocess errors must still produce an audit row."""
    persist_mock = AsyncMock()

    with (
        patch("tools.registry._persist_tool_result", persist_mock),
        patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=PermissionError("denied"))),
    ):
        tool = SecurityTool("gobuster", "web", "x", "gobuster")
        result = await tool.execute("http://t.local")

    assert result.get("error") == "denied"
    assert result.get("exit_code") == -2
    persist_mock.assert_awaited_once()

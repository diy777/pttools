"""Coverage fill for agents/base.py BaseAgent.

The existing test_agents.py covers a few high-level agent flows. This file
targets the BaseAgent primitives that every specialist inherits: setters,
scope checks, the tool-call dispatcher branches (analyze_findings,
store_finding success + dedup, builtin/security routing, unknown), the
deterministic fallback, the timeout/retry branches in _run_security_tool
and _run_builtin_scanner, plus _truncate edge cases.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.base import (
    DEFAULT_TOOL_TIMEOUT,
    MAX_OUTPUT_CHARS,
    BaseAgent,
    LLMUnavailableError,
    _truncate,
)
from engine.auth_handler import AuthCredentials
from engine.llm.client import LLMResponse, ToolCall


def _agent(**kw):
    registry = kw.get("registry") or MagicMock()
    db = kw.get("db") or MagicMock()
    db.add_finding = AsyncMock()
    return BaseAgent(registry=registry, db=db, llm=kw.get("llm"), scope=kw.get("scope"))


# ─── setters / getters ──────────────────────────────────────────────────


def test_set_context_stores_recon_context():
    a = _agent()
    a.set_context({"target": "x", "open_ports": [80, 443]})
    assert a._recon_context["target"] == "x"


def test_set_rate_limiter_stores():
    a = _agent()
    rl = MagicMock()
    a.set_rate_limiter(rl)
    assert a._rate_limiter is rl


def test_set_auth_stores():
    a = _agent()
    creds = AuthCredentials(auth_type="bearer", bearer_token="abc")
    a.set_auth(creds)
    assert a._auth is creds


def test_get_system_prompt_falls_back_to_recon():
    a = _agent()
    a.agent_type = "definitely-not-a-known-type"
    prompt = a._get_system_prompt()
    assert isinstance(prompt, str) and len(prompt) > 0


def test_get_available_tools_skips_uninstalled():
    a = _agent()
    installed_tool = MagicMock()
    installed_tool.is_installed.return_value = True
    installed_tool.name = "nmap"
    installed_tool.category = "network"
    installed_tool.description = "x"
    missing_tool = MagicMock()
    missing_tool.is_installed.return_value = False
    a.registry.list_tools.return_value = [installed_tool, missing_tool]

    tools = a._get_available_tools()
    names = [t.name for t in tools]
    assert "run_nmap" in names


def test_get_available_tools_no_registry():
    a = _agent()
    a.registry = None
    tools = a._get_available_tools()
    assert isinstance(tools, list)
    assert len(tools) > 0  # still has agent_decision_tools + builtin_scanner_tools


# ─── _check_scope ───────────────────────────────────────────────────────


def test_check_scope_no_scope_returns_none():
    a = _agent()
    assert a._check_scope("x.test", "nmap") is None


def test_check_scope_blocks_when_disallowed():
    scope = MagicMock()
    scope.check.return_value = (False, "out of bounds")
    a = _agent(scope=scope)
    err = a._check_scope("evil.test", "nmap")
    assert err is not None
    assert "out of bounds" in err


def test_check_scope_allows_when_ok():
    scope = MagicMock()
    scope.check.return_value = (True, "ok")
    a = _agent(scope=scope)
    assert a._check_scope("ok.test", "nmap") is None


# ─── _execute_tool_call branches ────────────────────────────────────────


@pytest.mark.asyncio
async def test_execute_analyze_findings():
    a = _agent()
    tc = ToolCall(id="1", name="analyze_findings", arguments={"next_action": "complete"})
    msg = await a._execute_tool_call(tc, "eng-1")
    assert "complete" in msg


@pytest.mark.asyncio
async def test_execute_store_finding_persists_and_counts():
    a = _agent()
    tc = ToolCall(id="2", name="store_finding", arguments={
        "title": "RCE",
        "description": "shell on box",
        "severity": "critical",
        "category": "rce",
        "target": "10.0.0.1",
        "evidence": "id; uid=0",
    })
    with patch("engine.cvss.calculate_cvss", return_value=9.8), \
         patch("engine.compliance.map_finding_compliance", return_value={"owasp": ["A01"]}):
        msg = await a._execute_tool_call(tc, "eng-1")
    assert a._findings_count == 1
    a.db.add_finding.assert_awaited_once()
    assert "Finding stored" in msg


@pytest.mark.asyncio
async def test_execute_store_finding_invalid_severity_falls_to_info():
    a = _agent()
    tc = ToolCall(id="3", name="store_finding", arguments={
        "title": "x", "description": "x", "severity": "totally-bogus",
        "category": "x", "target": "x", "evidence": "x",
    })
    with patch("engine.cvss.calculate_cvss", return_value=1.0), \
         patch("engine.compliance.map_finding_compliance", return_value={}):
        await a._execute_tool_call(tc, "eng-1")
    args = a.db.add_finding.await_args
    assert args[0][0]["severity"] == "info"


@pytest.mark.asyncio
async def test_execute_store_finding_dedupe_skips():
    a = _agent()
    a._dedup.is_duplicate = MagicMock(return_value=(True, "existing-1"))
    tc = ToolCall(id="4", name="store_finding", arguments={"title": "dup", "severity": "high"})
    msg = await a._execute_tool_call(tc, "eng-1")
    assert "Duplicate" in msg
    a.db.add_finding.assert_not_called()


@pytest.mark.asyncio
async def test_execute_unknown_tool_returns_unknown_message():
    a = _agent()
    tc = ToolCall(id="5", name="completely_made_up", arguments={})
    msg = await a._execute_tool_call(tc, "eng-1")
    assert "Unknown" in msg


@pytest.mark.asyncio
async def test_execute_routes_builtin():
    a = _agent()
    tc = ToolCall(id="6", name="builtin_port_scan", arguments={"target": "x"})
    with patch.object(a, "_run_builtin_scanner", new=AsyncMock(return_value="builtin-result")) as m:
        msg = await a._execute_tool_call(tc, "eng-1")
    m.assert_awaited_once()
    assert msg == "builtin-result"


@pytest.mark.asyncio
async def test_execute_routes_run_tool():
    a = _agent()
    tc = ToolCall(id="7", name="run_nmap", arguments={"target": "x"})
    with patch.object(a, "_run_security_tool", new=AsyncMock(return_value="tool-result")) as m:
        msg = await a._execute_tool_call(tc, "eng-1")
    m.assert_awaited_once()
    assert msg == "tool-result"


# ─── _run_builtin_scanner ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_builtin_unknown_returns_msg():
    a = _agent()
    tc = ToolCall(id="b1", name="builtin_does_not_exist", arguments={"target": "x"})
    msg = await a._run_builtin_scanner(tc)
    assert "Unknown" in msg


@pytest.mark.asyncio
async def test_run_builtin_scope_violation_returns_msg():
    scope = MagicMock()
    scope.check.return_value = (False, "blocked")
    a = _agent(scope=scope)
    tc = ToolCall(id="b2", name="builtin_port_scan", arguments={"target": "evil"})
    msg = await a._run_builtin_scanner(tc)
    assert "Scope violation" in msg


@pytest.mark.asyncio
async def test_run_builtin_success(monkeypatch):
    a = _agent()
    tc = ToolCall(id="b3", name="builtin_port_scan", arguments={"target": "x"})
    monkeypatch.setattr("engine.scanners.scan_ports", AsyncMock(return_value=[{"title": "open"}]))
    msg = await a._run_builtin_scanner(tc)
    assert "open" in msg


@pytest.mark.asyncio
async def test_run_builtin_timeout(monkeypatch):
    a = _agent()
    tc = ToolCall(id="b4", name="builtin_port_scan", arguments={"target": "x"})

    async def slow(target):
        await asyncio.sleep(10)
        return []

    monkeypatch.setattr("engine.scanners.scan_ports", slow)
    monkeypatch.setattr(a, "_get_timeout", lambda: 0)
    msg = await a._run_builtin_scanner(tc)
    assert "timed out" in msg


@pytest.mark.asyncio
async def test_run_builtin_exception(monkeypatch):
    a = _agent()
    tc = ToolCall(id="b5", name="builtin_port_scan", arguments={"target": "x"})
    monkeypatch.setattr("engine.scanners.scan_ports", AsyncMock(side_effect=RuntimeError("boom")))
    msg = await a._run_builtin_scanner(tc)
    assert "error" in msg.lower()


# ─── _run_security_tool ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_security_tool_not_in_registry():
    a = _agent()
    a.registry.get_tool.return_value = None
    tc = ToolCall(id="t1", name="run_madeup", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert "not found" in msg


@pytest.mark.asyncio
async def test_run_security_tool_not_installed():
    a = _agent()
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = False
    a.registry.get_tool.return_value = fake_tool
    tc = ToolCall(id="t2", name="run_nmap", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert "not installed" in msg


@pytest.mark.asyncio
async def test_run_security_tool_scope_violation():
    scope = MagicMock()
    scope.check.return_value = (False, "blocked")
    a = _agent(scope=scope)
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    a.registry.get_tool.return_value = fake_tool
    tc = ToolCall(id="t3", name="run_nmap", arguments={"target": "evil"})
    msg = await a._run_security_tool(tc)
    assert "Scope violation" in msg


@pytest.mark.asyncio
async def test_run_security_tool_success_counts_findings():
    a = _agent()
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": [{"title": "f1"}, {"title": "f2"}]})
    a.registry.get_tool.return_value = fake_tool
    tc = ToolCall(id="t4", name="run_nmap", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert a._findings_count == 2
    assert "findings" in msg


@pytest.mark.asyncio
async def test_run_security_tool_underscore_fallback():
    """When 'run_foo_bar' fails the dash form 'foo-bar', it tries 'foo_bar'."""
    a = _agent()
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": []})

    def get_tool(name):
        if name == "foo-bar":
            return None
        if name == "foo_bar":
            return fake_tool
        return None

    a.registry.get_tool.side_effect = get_tool
    tc = ToolCall(id="t5", name="run_foo_bar", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert "findings" in msg


@pytest.mark.asyncio
async def test_run_security_tool_timeout_no_retry(monkeypatch):
    a = _agent()

    async def slow(target, args):
        await asyncio.sleep(10)
        return {}

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = slow
    a.registry.get_tool.return_value = fake_tool
    monkeypatch.setattr(a, "_get_timeout", lambda: 0)
    monkeypatch.setattr(a, "_get_max_retries", lambda: 0)
    tc = ToolCall(id="t6", name="run_nmap", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert "timed out" in msg


@pytest.mark.asyncio
async def test_run_security_tool_exception_no_retry(monkeypatch):
    a = _agent()
    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
    a.registry.get_tool.return_value = fake_tool
    monkeypatch.setattr(a, "_get_max_retries", lambda: 0)
    tc = ToolCall(id="t7", name="run_nmap", arguments={"target": "x"})
    msg = await a._run_security_tool(tc)
    assert "error" in msg.lower()


@pytest.mark.asyncio
async def test_run_security_tool_with_auth_injects_auth_args():
    a = _agent()
    creds = AuthCredentials(auth_type="bearer", bearer_token="abc")
    a.set_auth(creds)

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": []})
    a.registry.get_tool.return_value = fake_tool

    tc = ToolCall(id="t8", name="run_nmap", arguments={"target": "x", "extra_args": {}})
    with patch("agents.base.build_auth_args", return_value={"username": "u"}):
        await a._run_security_tool(tc)

    fake_tool.execute.assert_awaited_once()
    call_args = fake_tool.execute.await_args.args
    # extra_args is the second positional arg
    assert call_args[1].get("_auth_args") == {"username": "u"}


# ─── _get_timeout / _get_max_retries ────────────────────────────────────


def test_get_timeout_default():
    a = _agent()
    assert a._get_timeout() == DEFAULT_TOOL_TIMEOUT


def test_get_timeout_from_rate_limiter():
    a = _agent()
    rl = MagicMock()
    rl.profile.tool_timeout_seconds = 42
    a.set_rate_limiter(rl)
    assert a._get_timeout() == 42


def test_get_max_retries_default():
    a = _agent()
    assert a._get_max_retries() == 1


def test_get_max_retries_from_rate_limiter():
    a = _agent()
    rl = MagicMock()
    rl.profile.max_retries = 5
    a.set_rate_limiter(rl)
    assert a._get_max_retries() == 5


# ─── run_tool_loop ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_tool_loop_no_llm_falls_back_to_deterministic():
    a = _agent()
    result = await a.run_tool_loop("do something", "eng-1")
    assert result["status"] == "complete"
    assert "No LLM" in result["summary"]


@pytest.mark.asyncio
async def test_run_tool_loop_executes_tool_calls_then_completes():
    llm = MagicMock()
    # First response has a tool call, second indicates completion via analyze_findings
    first = LLMResponse(content="thinking", tool_calls=[
        ToolCall(id="x", name="builtin_port_scan", arguments={"target": "x"}),
    ])
    final = LLMResponse(content="done", tool_calls=[
        ToolCall(id="y", name="analyze_findings", arguments={"next_action": "complete"}),
    ])
    llm.complete = AsyncMock(side_effect=[first, final])

    a = _agent(llm=llm)
    a.registry.list_tools.return_value = []

    with patch.object(a, "_run_builtin_scanner", new=AsyncMock(return_value="ok")):
        result = await a.run_tool_loop("start", "eng-1")
    assert result["agent"] == "base"
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_think_first_call_failure_raises_llm_unavailable():
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("boom"))
    a = _agent(llm=llm)
    a.registry.list_tools.return_value = []

    with pytest.raises(LLMUnavailableError):
        await a.think("first prompt")


@pytest.mark.asyncio
async def test_think_midloop_failure_returns_fallback_response():
    llm = MagicMock()
    a = _agent(llm=llm)
    a.registry.list_tools.return_value = []
    # Seed conversation so it's NOT a first call
    from engine.llm.client import LLMMessage
    a._conversation.append(LLMMessage(role="system", content="seed"))
    llm.complete = AsyncMock(side_effect=ConnectionError("boom"))

    resp = await a.think("more prompt")
    assert resp.tool_calls == []
    assert "deterministic" in resp.content.lower()


# ─── _truncate ──────────────────────────────────────────────────────────


def test_truncate_short_passthrough():
    assert _truncate("short") == "short"


def test_truncate_long_appends_marker():
    long = "x" * (MAX_OUTPUT_CHARS + 100)
    out = _truncate(long)
    assert "truncated" in out
    assert len(out) < len(long) + 100


# ─── _run_deterministic ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_deterministic_returns_no_findings_summary():
    a = _agent()
    result = await a._run_deterministic("anything", "eng-1")
    assert result["findings_count"] == 0
    assert "No LLM" in result["summary"]

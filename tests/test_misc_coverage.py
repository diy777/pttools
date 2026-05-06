"""Coverage fill: engine/auth_handler, engine/llm/providers/anthropic,
agents/report/renderer, cli/credential_resolvers/aws_sm.

These are small modules that can each be brought to 80%+ in a few tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── engine/auth_handler ─────────────────────────────────────────────────


def test_auth_credentials_from_dict_empty():
    from engine.auth_handler import AuthCredentials
    assert AuthCredentials.from_dict(None).is_set is False
    assert AuthCredentials.from_dict({}).is_set is False


def test_auth_credentials_from_dict_full():
    from engine.auth_handler import AuthCredentials
    creds = AuthCredentials.from_dict({
        "type": "bearer",
        "token": "abc",
        "headers": {"X-Tenant": "acme"},
        "form_fields": {"u": "x"},
    })
    assert creds.bearer_token == "abc"
    assert creds.headers == {"X-Tenant": "acme"}
    assert creds.is_set is True


def test_auth_credentials_from_cli_args_cookie():
    from engine.auth_handler import AuthCredentials
    creds = AuthCredentials.from_cli_args(cookie="sess=abc")
    assert creds.auth_type == "cookie"
    assert creds.cookies == "sess=abc"


def test_auth_credentials_from_cli_args_basic():
    from engine.auth_handler import AuthCredentials
    creds = AuthCredentials.from_cli_args(basic_auth="u:p")
    assert creds.auth_type == "basic"


def test_auth_credentials_from_cli_args_authorization_header():
    from engine.auth_handler import AuthCredentials
    creds = AuthCredentials.from_cli_args(header="Authorization: Bearer xyz")
    assert creds.auth_type == "bearer"
    assert "Authorization" in creds.headers


def test_auth_credentials_from_cli_args_other_header():
    from engine.auth_handler import AuthCredentials
    creds = AuthCredentials.from_cli_args(header="X-Tenant: acme")
    assert creds.headers == {"X-Tenant": "acme"}


def test_build_auth_args_no_creds():
    from engine.auth_handler import AuthCredentials, build_auth_args
    assert build_auth_args("nuclei", AuthCredentials()) == []


def test_build_auth_args_unknown_tool():
    from engine.auth_handler import AuthCredentials, build_auth_args
    creds = AuthCredentials(cookies="sess=abc", auth_type="cookie")
    # unknown tool returns empty list
    assert build_auth_args("does-not-exist", creds) == []


def test_build_auth_args_nuclei_cookie():
    from engine.auth_handler import AuthCredentials, build_auth_args
    creds = AuthCredentials(cookies="sess=abc", auth_type="cookie")
    args = build_auth_args("nuclei", creds)
    assert "-H" in args
    assert any("Cookie" in a for a in args)


def test_build_auth_args_nuclei_bearer():
    from engine.auth_handler import AuthCredentials, build_auth_args
    creds = AuthCredentials(bearer_token="xyz", auth_type="bearer")
    args = build_auth_args("nuclei", creds)
    assert any("Bearer" in a for a in args)


def test_build_auth_args_sqlmap_basic():
    from engine.auth_handler import AuthCredentials, build_auth_args
    creds = AuthCredentials(basic_auth="u:p", auth_type="basic")
    args = build_auth_args("sqlmap", creds)
    assert any("auth-cred" in a for a in args)


def test_build_auth_args_with_extra_header():
    from engine.auth_handler import AuthCredentials, build_auth_args
    creds = AuthCredentials(headers={"X-Tenant": "acme"}, auth_type="bearer")
    args = build_auth_args("ffuf", creds)
    # Should contain the X-Tenant header rendered for ffuf's header flag
    assert any("X-Tenant" in a for a in args)


# ─── engine/llm/providers/anthropic ─────────────────────────────────────


@pytest.mark.asyncio
async def test_anthropic_provider_complete_simple_message():
    from engine.llm.client import LLMMessage
    from engine.llm.providers.anthropic import AnthropicProvider

    p = AnthropicProvider(api_key="sk-test")
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "content": [{"type": "text", "text": "hello"}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "end_turn",
    }
    fake_response.raise_for_status = MagicMock()

    with patch.object(p._client, "post", new=AsyncMock(return_value=fake_response)):
        resp = await p.complete([LLMMessage(role="user", content="hi")])

    await p.close()
    assert resp.content == "hello"
    assert resp.usage.prompt_tokens == 10
    assert resp.finish_reason == "end_turn"


@pytest.mark.asyncio
async def test_anthropic_provider_complete_with_system_and_tools():
    from engine.llm.client import LLMMessage, ToolDefinition
    from engine.llm.providers.anthropic import AnthropicProvider

    p = AnthropicProvider(api_key="sk-test")
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "content": [
            {"type": "text", "text": "thinking"},
            {"type": "tool_use", "id": "t1", "name": "scan", "input": {"target": "x"}},
        ],
        "usage": {"input_tokens": 5, "output_tokens": 3},
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "tool_use",
    }
    fake_response.raise_for_status = MagicMock()

    captured = {}

    async def fake_post(url, json):
        captured.update(json)
        return fake_response

    with patch.object(p._client, "post", side_effect=fake_post):
        resp = await p.complete(
            [
                LLMMessage(role="system", content="You are a security analyst."),
                LLMMessage(role="user", content="Scan example.com"),
            ],
            tools=[ToolDefinition(
                name="scan",
                description="run a scan",
                parameters={"type": "object", "properties": {}},
            )],
        )

    await p.close()
    assert "system" in captured
    assert "tools" in captured and len(captured["tools"]) == 1
    assert resp.tool_calls
    assert resp.tool_calls[0].name == "scan"


@pytest.mark.asyncio
async def test_anthropic_provider_handles_tool_messages():
    """A tool-result LLMMessage gets translated to a Claude user/tool_result block."""
    from engine.llm.client import LLMMessage, ToolCall
    from engine.llm.providers.anthropic import AnthropicProvider

    p = AnthropicProvider(api_key="sk-test")
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "content": [{"type": "text", "text": "ack"}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
        "model": "claude-sonnet-4-20250514",
    }
    fake_response.raise_for_status = MagicMock()
    captured = {}

    async def fake_post(url, json):
        captured.update(json)
        return fake_response

    with patch.object(p._client, "post", side_effect=fake_post):
        await p.complete(
            [
                LLMMessage(
                    role="assistant",
                    content="planning",
                    tool_calls=(ToolCall(id="t1", name="scan", arguments={"x": 1}),),
                ),
                LLMMessage(role="tool", content="result", tool_call_id="t1"),
                LLMMessage(role="user", content="continue"),
            ]
        )

    await p.close()
    msgs = captured["messages"]
    # Assistant tool_use turn
    asst = next(m for m in msgs if m["role"] == "assistant")
    assert any(b["type"] == "tool_use" for b in asst["content"])
    # User turn carrying tool_result for tool_call_id t1
    user_turns = [m for m in msgs if m["role"] == "user"]
    assert any(
        any(b.get("type") == "tool_result" and b.get("tool_use_id") == "t1" for b in (m["content"] if isinstance(m["content"], list) else []))
        for m in user_turns
    )


# ─── agents/report/renderer ─────────────────────────────────────────────


def test_render_html_assigns_critical_risk_level():
    """Critical findings drive risk_level to CRITICAL (rendered into HTML)."""
    from agents.report.renderer import render_html
    html = render_html(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[{"title": "RCE", "severity": "critical"}],
        chains=[],
        summary={"by_severity": {"critical": 1, "high": 0, "medium": 0}, "total_findings": 1},
        detection_rules=[],
    )
    assert "CRITICAL" in html


def test_render_html_high_risk_level():
    from agents.report.renderer import render_html
    html = render_html(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[{"title": "x", "severity": "high"}],
        chains=[],
        summary={"by_severity": {"critical": 0, "high": 2, "medium": 0}, "total_findings": 2},
    )
    assert "HIGH" in html


def test_render_html_medium_risk_level():
    from agents.report.renderer import render_html
    html = render_html(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[{"title": "x", "severity": "medium"}],
        chains=[],
        summary={"by_severity": {"critical": 0, "high": 0, "medium": 3}, "total_findings": 3},
    )
    assert "MEDIUM" in html


def test_render_html_low_risk_default():
    from agents.report.renderer import render_html
    html = render_html(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[],
        chains=[],
        summary={"by_severity": {}, "total_findings": 0},
    )
    assert "LOW" in html


def test_render_pdf_calls_weasyprint(monkeypatch):
    from agents.report import renderer
    fake_html = MagicMock()
    fake_html.write_pdf.return_value = b"%PDF"
    fake_module = MagicMock()
    fake_module.HTML = MagicMock(return_value=fake_html)
    monkeypatch.setitem(__import__("sys").modules, "weasyprint", fake_module)
    out = renderer.render_pdf("<html>x</html>")
    assert out == b"%PDF"

"""Coverage fill for ollama + openai providers, poc_validator,
ad_agent, wireless_agent, cloud_agent."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── OllamaProvider ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ollama_complete_simple():
    from engine.llm.client import LLMMessage
    from engine.llm.providers.ollama import OllamaProvider

    p = OllamaProvider(model="llama3")
    fake = MagicMock()
    fake.json.return_value = {
        "message": {"content": "ok", "tool_calls": []},
        "model": "llama3",
        "prompt_eval_count": 5,
        "eval_count": 3,
    }
    fake.raise_for_status = MagicMock()
    with patch.object(p._client, "post", new=AsyncMock(return_value=fake)):
        resp = await p.complete([LLMMessage(role="user", content="hi")])
    await p.close()
    assert resp.content == "ok"
    assert resp.usage.total_tokens == 8


@pytest.mark.asyncio
async def test_ollama_complete_with_tool_calls():
    from engine.llm.client import LLMMessage, ToolDefinition
    from engine.llm.providers.ollama import OllamaProvider

    p = OllamaProvider()
    fake = MagicMock()
    fake.json.return_value = {
        "message": {
            "content": "thinking",
            "tool_calls": [
                {"function": {"name": "scan", "arguments": {"x": 1}}},
                {"function": {"name": "lookup", "arguments": '{"y":2}'}},  # JSON string
                {"function": {"name": "broken", "arguments": "not json"}},
            ],
        },
        "model": "llama3",
    }
    fake.raise_for_status = MagicMock()
    with patch.object(p._client, "post", new=AsyncMock(return_value=fake)):
        resp = await p.complete(
            [LLMMessage(role="user", content="x")],
            tools=[ToolDefinition(name="scan", description="d", parameters={})],
        )
    await p.close()
    assert len(resp.tool_calls) == 3
    assert resp.tool_calls[1].arguments == {"y": 2}
    assert resp.tool_calls[2].arguments == {}  # bad JSON falls to {}


def test_ollama_base_url_normalized():
    from engine.llm.providers.ollama import OllamaProvider
    p = OllamaProvider(base_url="http://localhost:11434/")
    assert p.base_url == "http://localhost:11434"


# ─── OpenAIProvider ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_openai_complete_simple():
    from engine.llm.client import LLMMessage
    from engine.llm.providers.openai import OpenAIProvider

    p = OpenAIProvider(api_key="sk-test")
    fake = MagicMock()
    fake.json.return_value = {
        "choices": [{
            "message": {"content": "hello", "tool_calls": []},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9},
        "model": "gpt-4o",
    }
    fake.raise_for_status = MagicMock()
    with patch.object(p._client, "post", new=AsyncMock(return_value=fake)):
        resp = await p.complete([LLMMessage(role="user", content="hi")])
    await p.close()
    assert resp.content == "hello"
    assert resp.finish_reason == "stop"
    assert resp.usage.total_tokens == 9


@pytest.mark.asyncio
async def test_openai_format_message_with_tool_calls():
    from engine.llm.client import LLMMessage, ToolCall
    from engine.llm.providers.openai import _format_message

    out = _format_message(LLMMessage(
        role="assistant",
        content="thinking",
        tool_calls=(ToolCall(id="t1", name="scan", arguments={"x": 1}),),
    ))
    assert "tool_calls" in out
    assert out["tool_calls"][0]["function"]["name"] == "scan"


def test_openai_format_message_with_tool_call_id():
    from engine.llm.client import LLMMessage
    from engine.llm.providers.openai import _format_message
    out = _format_message(LLMMessage(role="tool", content="r", tool_call_id="t1", name="scan"))
    assert out["tool_call_id"] == "t1"
    assert out["name"] == "scan"


@pytest.mark.asyncio
async def test_openai_parses_tool_calls_with_json_args():
    from engine.llm.client import LLMMessage, ToolDefinition
    from engine.llm.providers.openai import OpenAIProvider

    p = OpenAIProvider(api_key="sk-test")
    fake = MagicMock()
    fake.json.return_value = {
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [
                    {"id": "t1", "function": {"name": "scan", "arguments": '{"target":"x"}'}},
                    {"id": "t2", "function": {"name": "broken", "arguments": "not json"}},
                ],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        "model": "gpt-4o",
    }
    fake.raise_for_status = MagicMock()
    with patch.object(p._client, "post", new=AsyncMock(return_value=fake)):
        resp = await p.complete(
            [LLMMessage(role="user", content="x")],
            tools=[ToolDefinition(name="scan", description="d", parameters={})],
        )
    await p.close()
    assert len(resp.tool_calls) == 2
    assert resp.tool_calls[0].arguments == {"target": "x"}
    assert resp.tool_calls[1].arguments == {}  # bad JSON


# ─── PoCAgent ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poc_validate_finding_not_found():
    from agents.poc_validator.poc_agent import PoCAgent
    db = MagicMock()
    db.get_findings = AsyncMock(return_value=[])
    agent = PoCAgent(db=db)
    result = await agent.validate_finding("missing", "eng-1")
    assert "error" in result


@pytest.mark.asyncio
async def test_poc_validate_finding_static_poc_for_injection():
    from agents.poc_validator.poc_agent import PoCAgent
    db = MagicMock()
    db.get_findings = AsyncMock(return_value=[
        {"id": "f1", "category": "injection", "target": "http://x.test"},
    ])
    agent = PoCAgent(db=db, llm=None)
    result = await agent.validate_finding("f1", "eng-1")
    assert "SQLi" in result["poc"] or "AND SLEEP" in result["poc"]


@pytest.mark.asyncio
async def test_poc_validate_finding_static_poc_unknown_category():
    from agents.poc_validator.poc_agent import PoCAgent
    db = MagicMock()
    db.get_findings = AsyncMock(return_value=[
        {"id": "f1", "category": "weird-thing", "target": "x"},
    ])
    agent = PoCAgent(db=db, llm=None)
    result = await agent.validate_finding("f1")
    assert "Manual" in result["poc"]


@pytest.mark.asyncio
async def test_poc_validate_all_filters_by_severity():
    from agents.poc_validator.poc_agent import PoCAgent
    db = MagicMock()
    db.get_findings = AsyncMock(return_value=[
        {"id": "f1", "severity": "critical", "category": "xss", "target": "x"},
        {"id": "f2", "severity": "info", "category": "discovery", "target": "x"},
    ])
    agent = PoCAgent(db=db, llm=None)
    results = await agent.validate_all("eng-1")
    # Only critical/high get validated
    assert len(results) == 1


# ─── AD / Wireless / Cloud thin agents ──────────────────────────────────


@pytest.mark.asyncio
async def test_ad_agent_no_llm_runs_deterministic():
    from agents.ad.ad_agent import ADAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": [{"title": "f"}]})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    agent = ADAgent(registry, db)
    result = await agent.run_assessment("10.0.0.10", "CORP")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_ad_agent_llm_unavailable_falls_back():
    from agents.ad.ad_agent import ADAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": []})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = ADAgent(registry, db, llm=llm)
    result = await agent.run_assessment("10.0.0.10", "CORP")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_wireless_agent_deterministic():
    from agents.wireless.wireless_agent import WirelessAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": [{"title": "ap"}]})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    agent = WirelessAgent(registry, db)
    result = await agent.run_assessment("AP-name")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_wireless_agent_llm_unavailable_falls_back():
    from agents.wireless.wireless_agent import WirelessAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": []})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = WirelessAgent(registry, db, llm=llm)
    result = await agent.run_assessment("AP-name")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_cloud_agent_deterministic():
    from agents.cloud.cloud_agent import CloudAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": [{"title": "iam"}]})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    agent = CloudAgent(registry, db)
    result = await agent.run_assessment("aws", "arn:aws:account:123")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_cloud_agent_llm_unavailable_falls_back():
    from agents.cloud.cloud_agent import CloudAgent

    fake_tool = MagicMock()
    fake_tool.is_installed.return_value = True
    fake_tool.execute = AsyncMock(return_value={"findings": []})
    registry = MagicMock()
    registry.get_tool.return_value = fake_tool
    db = MagicMock()
    db.add_finding = AsyncMock()
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=ConnectionError("down"))
    agent = CloudAgent(registry, db, llm=llm)
    result = await agent.run_assessment("aws", "x")
    assert isinstance(result, dict)

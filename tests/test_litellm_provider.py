"""Tests for the LiteLLM provider — uses a stub litellm module so the
test does not require the real package or network access.
"""

from __future__ import annotations

import json
import sys
import types
from typing import Any

import pytest

from engine.llm.client import LLMMessage, ToolDefinition


def _install_fake_litellm(response_payload: dict[str, Any]) -> types.ModuleType:
    """Inject a fake litellm module into sys.modules before importing the provider."""

    fake = types.ModuleType("litellm")

    async def _acompletion(**kwargs: Any) -> Any:
        # Capture the kwargs the provider sent (for assertion)
        fake.last_call_kwargs = kwargs

        # Build a minimal response shape that matches OpenAI's:
        # response.choices[0].message.{content, tool_calls}, response.usage.*, response.model
        class _Func:
            def __init__(self, name: str, arguments: str):
                self.name = name
                self.arguments = arguments

        class _ToolCall:
            def __init__(self, id_: str, name: str, arguments: str):
                self.id = id_
                self.function = _Func(name, arguments)

        class _Message:
            def __init__(self, content: str, tool_calls: list[_ToolCall]):
                self.content = content
                self.tool_calls = tool_calls

        class _Choice:
            def __init__(self, message: _Message, finish_reason: str):
                self.message = message
                self.finish_reason = finish_reason

        class _Usage:
            def __init__(self, p: int, c: int, t: int):
                self.prompt_tokens = p
                self.completion_tokens = c
                self.total_tokens = t

        class _Response:
            def __init__(self) -> None:
                tcs = [
                    _ToolCall(tc["id"], tc["name"], json.dumps(tc["arguments"]))
                    for tc in response_payload.get("tool_calls", [])
                ]
                msg = _Message(response_payload.get("content", ""), tcs)
                self.choices = [_Choice(msg, response_payload.get("finish_reason", "stop"))]
                u = response_payload.get("usage", {})
                self.usage = _Usage(u.get("prompt", 0), u.get("completion", 0), u.get("total", 0))
                self.model = response_payload.get("model", "fake/model-x")

        return _Response()

    fake.acompletion = _acompletion
    fake.suppress_debug_info = False
    sys.modules["litellm"] = fake
    return fake


@pytest.mark.asyncio
async def test_litellm_provider_sends_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_fake_litellm({
        "content": "ok",
        "tool_calls": [],
        "usage": {"prompt": 5, "completion": 7, "total": 12},
        "model": "openrouter/anthropic/claude-sonnet-4",
    })

    # Import after injection so the provider picks up the fake
    from engine.llm.providers.litellm_provider import LiteLLMProvider

    provider = LiteLLMProvider(model="openrouter/anthropic/claude-sonnet-4", api_key="sk-test")
    msgs = [
        LLMMessage(role="system", content="be helpful"),
        LLMMessage(role="user", content="hi"),
    ]
    tools = [
        ToolDefinition(
            name="ping",
            description="ping a host",
            parameters={"type": "object", "properties": {"host": {"type": "string"}}},
        )
    ]

    response = await provider.complete(messages=msgs, tools=tools, temperature=0.1, max_tokens=512)
    await provider.close()

    # Outbound payload sanity
    sent = fake.last_call_kwargs
    assert sent["model"] == "openrouter/anthropic/claude-sonnet-4"
    assert sent["temperature"] == 0.1
    assert sent["max_tokens"] == 512
    assert sent["api_key"] == "sk-test"
    assert len(sent["messages"]) == 2
    assert sent["messages"][0]["role"] == "system"
    assert sent["tools"][0]["function"]["name"] == "ping"

    # Response parsing sanity
    assert response.content == "ok"
    assert response.tool_calls == ()
    assert response.model == "openrouter/anthropic/claude-sonnet-4"
    assert response.usage is not None and response.usage.total_tokens == 12


@pytest.mark.asyncio
async def test_litellm_provider_parses_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_litellm({
        "content": "",
        "tool_calls": [
            {"id": "call_1", "name": "scan_host", "arguments": {"host": "10.0.0.1", "ports": "80,443"}},
        ],
        "usage": {"prompt": 1, "completion": 1, "total": 2},
        "model": "azure/gpt-4o",
    })

    from engine.llm.providers.litellm_provider import LiteLLMProvider

    provider = LiteLLMProvider(model="azure/gpt-4o")
    response = await provider.complete(messages=[LLMMessage(role="user", content="scan it")])
    await provider.close()

    assert len(response.tool_calls) == 1
    tc = response.tool_calls[0]
    assert tc.id == "call_1"
    assert tc.name == "scan_host"
    assert tc.arguments == {"host": "10.0.0.1", "ports": "80,443"}


@pytest.mark.asyncio
async def test_litellm_provider_raises_when_litellm_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the import to fail
    sys.modules.pop("litellm", None)

    # Block import even if the real package is installed
    import builtins

    real_import = builtins.__import__

    def _blocking_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "litellm":
            raise ImportError("simulated missing litellm")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocking_import)

    from engine.llm.providers.litellm_provider import LiteLLMProvider

    provider = LiteLLMProvider(model="any/model")

    with pytest.raises(RuntimeError, match=r"litellm.+not installed"):
        await provider.complete(messages=[LLMMessage(role="user", content="hi")])

    await provider.close()


@pytest.mark.asyncio
async def test_factory_routes_litellm_provider() -> None:
    """create_llm_client('litellm', model=...) returns a LiteLLMProvider instance."""
    _install_fake_litellm({"content": "ping", "tool_calls": [], "usage": {}, "model": "x/y"})

    from engine.llm.factory import create_llm_client
    from engine.llm.providers.litellm_provider import LiteLLMProvider

    client = create_llm_client(provider="litellm", model="groq/llama-3.1-70b-versatile")
    # Factory wraps every client with CostTrackingLLMClient; unwrap for the
    # provider-type assertion.
    inner = getattr(client, "inner", client)
    assert isinstance(inner, LiteLLMProvider)
    assert inner.model == "groq/llama-3.1-70b-versatile"

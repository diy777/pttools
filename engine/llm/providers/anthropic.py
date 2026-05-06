"""Anthropic Claude LLM provider using httpx directly."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolCall, ToolDefinition

logger = logging.getLogger("pentest-tools.llm.anthropic")

DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicProvider:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self._client = httpx.AsyncClient(
            base_url=DEFAULT_BASE_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": API_VERSION,
                "Content-Type": "application/json",
            },
            timeout=120.0,
        )

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        system_prompt = ""
        api_messages = []
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            elif msg.role == "tool":
                api_messages.append({
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": msg.tool_call_id, "content": msg.content}],
                })
            elif msg.role == "assistant" and msg.tool_calls:
                content: list[dict[str, Any]] = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    content.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
                api_messages.append({"role": "assistant", "content": content})
            else:
                api_messages.append({"role": msg.role, "content": msg.content})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = [_format_tool(t) for t in tools]

        logger.debug(f"Anthropic request: model={self.model}, messages={len(api_messages)}, tools={len(tools or [])}")
        response = await self._client.post("/v1/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        return _parse_response(data)

    async def close(self) -> None:
        await self._client.aclose()


def _format_tool(tool: ToolDefinition) -> dict[str, Any]:
    return {"name": tool.name, "description": tool.description, "input_schema": tool.parameters}


def _parse_response(data: dict[str, Any]) -> LLMResponse:
    content_parts = []
    tool_calls = []

    for block in data.get("content", []):
        if block["type"] == "text":
            content_parts.append(block["text"])
        elif block["type"] == "tool_use":
            tool_calls.append(ToolCall(id=block["id"], name=block["name"], arguments=block.get("input", {})))

    usage_data = data.get("usage", {})
    usage = TokenUsage(
        prompt_tokens=usage_data.get("input_tokens", 0),
        completion_tokens=usage_data.get("output_tokens", 0),
        total_tokens=usage_data.get("input_tokens", 0) + usage_data.get("output_tokens", 0),
    )

    return LLMResponse(
        content="\n".join(content_parts),
        tool_calls=tuple(tool_calls),
        usage=usage,
        model=data.get("model", ""),
        finish_reason=data.get("stop_reason", ""),
    )

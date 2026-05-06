"""OpenAI-compatible LLM provider using httpx directly."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolCall, ToolDefinition

logger = logging.getLogger("pentest-tools.llm.openai")

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider:
    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            timeout=120.0,
        )

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [_format_message(m) for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            payload["tools"] = [_format_tool(t) for t in tools]

        logger.debug(f"OpenAI request: model={self.model}, messages={len(messages)}, tools={len(tools or [])}")
        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        return _parse_response(data)

    async def close(self) -> None:
        await self._client.aclose()


def _format_message(msg: LLMMessage) -> dict[str, Any]:
    result: dict[str, Any] = {"role": msg.role, "content": msg.content}
    if msg.tool_call_id:
        result["tool_call_id"] = msg.tool_call_id
    if msg.name:
        result["name"] = msg.name
    if msg.tool_calls:
        result["tool_calls"] = [
            {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
            for tc in msg.tool_calls
        ]
    return result


def _format_tool(tool: ToolDefinition) -> dict[str, Any]:
    return {"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": tool.parameters}}


def _parse_response(data: dict[str, Any]) -> LLMResponse:
    choice = data["choices"][0]
    message = choice["message"]

    tool_calls = []
    for tc in message.get("tool_calls", []):
        func = tc["function"]
        try:
            args = json.loads(func["arguments"])
        except (json.JSONDecodeError, TypeError):
            args = {}
        tool_calls.append(ToolCall(id=tc["id"], name=func["name"], arguments=args))

    usage_data = data.get("usage", {})
    usage = TokenUsage(
        prompt_tokens=usage_data.get("prompt_tokens", 0),
        completion_tokens=usage_data.get("completion_tokens", 0),
        total_tokens=usage_data.get("total_tokens", 0),
    )

    return LLMResponse(
        content=message.get("content") or "",
        tool_calls=tuple(tool_calls),
        usage=usage,
        model=data.get("model", ""),
        finish_reason=choice.get("finish_reason", ""),
    )

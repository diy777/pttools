"""Ollama local LLM provider using httpx directly."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolCall, ToolDefinition

logger = logging.getLogger("pentest-tools.llm.ollama")

DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider:
    def __init__(self, model: str = "llama3.1", base_url: str = ""):
        self.model = model
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=300.0)

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }

        if tools:
            payload["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools
            ]

        logger.debug(f"Ollama request: model={self.model}, messages={len(messages)}")
        response = await self._client.post("/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()

        return _parse_response(data)

    async def close(self) -> None:
        await self._client.aclose()


def _parse_response(data: dict[str, Any]) -> LLMResponse:
    message = data.get("message", {})
    tool_calls = []

    for tc in message.get("tool_calls", []):
        func = tc.get("function", {})
        args = func.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        tool_calls.append(ToolCall(id=f"ollama_{id(tc)}", name=func.get("name", ""), arguments=args))

    prompt_tokens = data.get("prompt_eval_count", 0)
    completion_tokens = data.get("eval_count", 0)

    return LLMResponse(
        content=message.get("content", ""),
        tool_calls=tuple(tool_calls),
        usage=TokenUsage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=prompt_tokens + completion_tokens),
        model=data.get("model", ""),
        finish_reason="tool_calls" if tool_calls else "stop",
    )

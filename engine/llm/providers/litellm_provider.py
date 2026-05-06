"""LiteLLM provider — unified access to 300+ models via litellm.

Lets users specify any LiteLLM-supported model string (provider-prefixed)
without pentest-tools having to ship a per-provider HTTP client. Examples:

    --provider litellm --model openrouter/anthropic/claude-sonnet-4
    --provider litellm --model azure/gpt-4o
    --provider litellm --model deepseek/deepseek-chat
    --provider litellm --model groq/llama-3.1-70b-versatile
    --provider litellm --model mistral/mistral-large-latest
    --provider litellm --model together_ai/meta-llama/Llama-3.1-70B-Instruct

Auth is handled by LiteLLM via standard env vars (OPENAI_API_KEY,
ANTHROPIC_API_KEY, AZURE_API_KEY + AZURE_API_BASE, OPENROUTER_API_KEY,
DEEPSEEK_API_KEY, GROQ_API_KEY, MISTRAL_API_KEY, TOGETHERAI_API_KEY,
etc.). See https://docs.litellm.ai/docs/providers for the full list.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolCall, ToolDefinition

logger = logging.getLogger("pentest-tools.llm.litellm")


class LiteLLMProvider:
    """Generic provider that proxies to litellm.acompletion."""

    def __init__(self, model: str, api_key: str = "", base_url: str = ""):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self._kwargs: dict[str, Any] = {}
        if api_key:
            self._kwargs["api_key"] = api_key
        if base_url:
            self._kwargs["api_base"] = base_url

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        try:
            import litellm  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "LiteLLM provider requested but `litellm` package is not installed. "
                "Install with: pip install pentest-tools[litellm]  or  pip install litellm"
            ) from e

        # Quiet down LiteLLM's own verbose logger
        litellm.suppress_debug_info = True

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [_format_message(m) for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
            **self._kwargs,
        }

        if tools:
            payload["tools"] = [_format_tool(t) for t in tools]

        logger.debug(
            "LiteLLM request: model=%s messages=%d tools=%d",
            self.model,
            len(messages),
            len(tools or []),
        )

        response = await litellm.acompletion(**payload)
        return _parse_response(response)

    async def close(self) -> None:  # noqa: D401
        # LiteLLM manages its own clients; nothing to close.
        return None


def _format_message(msg: LLMMessage) -> dict[str, Any]:
    result: dict[str, Any] = {"role": msg.role, "content": msg.content}
    if msg.tool_call_id:
        result["tool_call_id"] = msg.tool_call_id
    if msg.name:
        result["name"] = msg.name
    if msg.tool_calls:
        result["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
            }
            for tc in msg.tool_calls
        ]
    return result


def _format_tool(tool: ToolDefinition) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    }


def _parse_response(response: Any) -> LLMResponse:
    """Convert a LiteLLM ModelResponse into our LLMResponse dataclass."""
    # LiteLLM normalizes responses to OpenAI's format. choices[0].message has
    # .content and optional .tool_calls. Some providers may emit empty content
    # alongside tool_calls; downstream code handles that.
    choice = response.choices[0]
    message = choice.message

    tool_calls: list[ToolCall] = []
    raw_tool_calls = getattr(message, "tool_calls", None) or []
    for tc in raw_tool_calls:
        func = tc.function if hasattr(tc, "function") else tc.get("function", {})
        name = getattr(func, "name", None) or func.get("name", "")
        raw_args = getattr(func, "arguments", None) or func.get("arguments", "{}")
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
        except (json.JSONDecodeError, TypeError):
            args = {}
        tc_id = getattr(tc, "id", None) or tc.get("id", "")
        tool_calls.append(ToolCall(id=tc_id, name=name, arguments=args))

    usage_obj = getattr(response, "usage", None)
    if usage_obj is not None:
        usage = TokenUsage(
            prompt_tokens=getattr(usage_obj, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage_obj, "completion_tokens", 0) or 0,
            total_tokens=getattr(usage_obj, "total_tokens", 0) or 0,
        )
    else:
        usage = TokenUsage()

    content = getattr(message, "content", None) or ""
    return LLMResponse(
        content=content,
        tool_calls=tuple(tool_calls),
        usage=usage,
        model=getattr(response, "model", "") or "",
        finish_reason=getattr(choice, "finish_reason", "") or "",
    )

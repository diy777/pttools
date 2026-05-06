"""Factory for creating LLM clients from config.

Supported providers:
- `anthropic` — direct Anthropic Messages API (Claude family)
- `openai`   — direct OpenAI Chat Completions API (and OpenAI-compatible)
- `ollama`   — local Ollama runtime
- `litellm`  — universal adapter for 300+ providers (OpenRouter, Azure,
               DeepSeek, Groq, Mistral, Together AI, Fireworks, Bedrock,
               Vertex AI, Cohere, etc.). Model string must be the LiteLLM
               provider-prefixed form, e.g. `openrouter/anthropic/claude-sonnet-4`.

The provider string is also the env var fallback. Set
`PENTEST_TOOLS_LLM_PROVIDER` to default for the session.

Every client returned is wrapped with CostTrackingLLMClient so that an
engagement-scoped CostTracker (registered via set_current_tracker) sees
every LLM call regardless of provider. The wrapper is a no-op when no
tracker is set, so non-engagement callers (e.g. one-off CLI commands)
are unaffected.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.llm.client import LLMClient


# Single source of truth for the supported provider names.
SUPPORTED_PROVIDERS: tuple[str, ...] = ("anthropic", "openai", "ollama", "litellm")


def create_llm_client(provider: str = "", model: str = "", api_key: str = "", base_url: str = "") -> LLMClient:
    inner, resolved_model = _create_inner_client(
        provider=provider, model=model, api_key=api_key, base_url=base_url
    )
    from engine.llm.cost import CostTrackingLLMClient

    return CostTrackingLLMClient(inner, model=resolved_model)


def _create_inner_client(
    provider: str = "", model: str = "", api_key: str = "", base_url: str = ""
) -> tuple[LLMClient, str]:
    """Build the raw provider client without cost-tracking. Returns (client, model)."""
    provider = (provider or os.getenv("PENTEST_TOOLS_LLM_PROVIDER", "openai")).lower().strip()
    api_key = api_key or os.getenv("PENTEST_TOOLS_API_KEY", "") or os.getenv("OPENAI_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", "")

    if provider == "anthropic":
        from engine.llm.providers.anthropic import AnthropicProvider

        chosen = model or "claude-sonnet-4-20250514"
        return AnthropicProvider(
            api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""),
            model=chosen,
        ), chosen

    if provider == "ollama":
        from engine.llm.providers.ollama import OllamaProvider

        chosen = model or "llama3.1"
        return OllamaProvider(
            model=chosen,
            base_url=base_url or os.getenv("OLLAMA_BASE_URL", ""),
        ), chosen

    if provider == "litellm":
        from engine.llm.providers.litellm_provider import LiteLLMProvider

        chosen_model = model or os.getenv("PENTEST_TOOLS_MODEL", "") or "gpt-4o"
        return LiteLLMProvider(
            model=chosen_model,
            api_key=api_key,
            base_url=base_url,
        ), chosen_model

    if provider != "openai":
        # Unknown provider: route through LiteLLM if it's installed. Lets users
        # supply e.g. provider=openrouter without pentest-tools needing a per-provider
        # adapter. Falls back to OpenAI on import error.
        try:
            from engine.llm.providers.litellm_provider import LiteLLMProvider

            chosen = model or provider  # treat bare provider as model id
            return LiteLLMProvider(
                model=chosen,
                api_key=api_key,
                base_url=base_url,
            ), chosen
        except Exception:  # noqa: BLE001
            pass  # fall through to OpenAI

    from engine.llm.providers.openai import OpenAIProvider

    chosen = model or "gpt-4o"
    return OpenAIProvider(
        api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
        model=chosen,
        base_url=base_url or os.getenv("OPENAI_BASE_URL", ""),
    ), chosen

"""Cost tracker and PTAI_PRICE_LIMIT enforcement for LLM calls.

Aggregates token usage across an engagement and converts to USD via
LiteLLM's cost_per_token helper. When PTAI_PRICE_LIMIT is set, the
next call after the threshold is crossed raises CostLimitError so
the caller can stop the engagement cleanly. Tracker is contextvar
scoped so parallel agents share one budget per engagement.

Configuration:
    PTAI_PRICE_LIMIT=5.00    Hard cap in USD. Unset or 0 = no limit.

Usage in the engine:

    tracker = make_tracker_from_env()
    token = set_current_tracker(tracker)
    try:
        # ... run engagement; LLM calls auto-accumulate via the wrapper ...
        print(tracker.summary())
    except CostLimitError as e:
        print(f"aborted: {e}")
    finally:
        reset_current_tracker(token)
"""

from __future__ import annotations

import logging
import os
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from engine.llm.client import LLMClient, LLMMessage, LLMResponse, ToolDefinition

logger = logging.getLogger("pentest-tools.cost")

PRICE_LIMIT_ENV = "PTAI_PRICE_LIMIT"


class CostLimitError(RuntimeError):
    """Raised when cumulative LLM spend crosses the configured price limit."""

    def __init__(self, total_usd: float, limit_usd: float):
        super().__init__(
            f"PTAI_PRICE_LIMIT exceeded: spent ${total_usd:.4f} of ${limit_usd:.4f} budget"
        )
        self.total_usd = total_usd
        self.limit_usd = limit_usd


@dataclass
class CostTracker:
    """Thread-safe aggregator of LLM spend with optional hard limit."""

    limit_usd: float = 0.0  # 0 means no limit
    total_usd: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    call_count: int = 0
    _lock: Any = field(default_factory=threading.Lock, repr=False)

    def add(self, response: LLMResponse, model: str) -> None:
        cost = _calc_cost_usd(response, model)
        with self._lock:
            self.call_count += 1
            self.total_usd += cost
            if response.usage:
                self.total_prompt_tokens += response.usage.prompt_tokens
                self.total_completion_tokens += response.usage.completion_tokens

    def check_limit(self) -> None:
        """Raise CostLimitError if total spend has crossed the limit."""
        if self.limit_usd > 0 and self.total_usd >= self.limit_usd:
            raise CostLimitError(self.total_usd, self.limit_usd)

    def summary(self) -> dict[str, Any]:
        return {
            "total_usd": round(self.total_usd, 6),
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "call_count": self.call_count,
            "limit_usd": self.limit_usd,
        }


def _calc_cost_usd(response: LLMResponse, model: str) -> float:
    """Compute USD cost. Returns 0.0 on any failure (unknown model,
    no usage data, litellm not installed, local Ollama models, etc.)."""
    if not response.usage or response.usage.total_tokens == 0:
        return 0.0
    try:
        import litellm  # type: ignore[import-not-found]
    except ImportError:
        return 0.0
    if litellm is None:  # explicit None sentinel used by some tests
        return 0.0
    try:
        prompt_cost, completion_cost = litellm.cost_per_token(
            model=model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )
        return float(prompt_cost) + float(completion_cost)
    except Exception as e:  # noqa: BLE001
        logger.debug("cost calc failed for model=%s: %s", model, e)
        return 0.0


# ─── Engagement-scoped tracker via contextvar ───────────────────────────


_current_tracker: ContextVar[CostTracker | None] = ContextVar(
    "current_cost_tracker", default=None
)


def get_current_tracker() -> CostTracker | None:
    return _current_tracker.get()


def set_current_tracker(tracker: CostTracker | None) -> Any:
    return _current_tracker.set(tracker)


def reset_current_tracker(token: Any) -> None:
    _current_tracker.reset(token)


def make_tracker_from_env() -> CostTracker:
    raw = os.environ.get(PRICE_LIMIT_ENV, "").strip()
    try:
        limit = float(raw) if raw else 0.0
    except ValueError:
        logger.warning("invalid %s value %r, ignoring", PRICE_LIMIT_ENV, raw)
        limit = 0.0
    return CostTracker(limit_usd=max(limit, 0.0))


# ─── LLM client wrapper ──────────────────────────────────────────────────


class CostTrackingLLMClient:
    """Decorates any LLMClient with cost accumulation + price-limit checks.

    When a tracker is registered in the current contextvar:
      - Before each call, raises CostLimitError if already over budget.
      - After each call, adds the response's cost to the tracker.

    When no tracker is set (e.g. CLI commands that don't open an engagement),
    the wrapper is a no-op and just forwards to the inner client.

    The wrapper is structurally compatible with the LLMClient Protocol.
    """

    def __init__(self, inner: LLMClient, model: str):
        self.inner = inner
        self.model = model

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        tracker = _current_tracker.get()
        if tracker is not None:
            # Pre-flight: refuse to spend more if already over budget.
            tracker.check_limit()
        response = await self.inner.complete(
            messages=messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if tracker is not None:
            tracker.add(response, self.model)
        return response

    async def close(self) -> None:
        await self.inner.close()

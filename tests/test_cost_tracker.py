"""Tests for engine.llm.cost — cost tracker and PTAI_PRICE_LIMIT enforcement."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolDefinition


def _install_fake_litellm(prompt_cost: float, completion_cost: float) -> types.ModuleType:
    """Stub litellm.cost_per_token so tests don't need the real package."""
    fake = types.ModuleType("litellm")

    def _cost_per_token(model: str, prompt_tokens: int, completion_tokens: int) -> tuple[float, float]:  # noqa: ARG001
        # Return whatever the test asked for, scaled by token count
        return (prompt_cost * prompt_tokens, completion_cost * completion_tokens)

    fake.cost_per_token = _cost_per_token  # type: ignore[attr-defined]
    sys.modules["litellm"] = fake
    return fake


def _install_failing_litellm() -> None:
    """Stub litellm.cost_per_token that raises — for unknown-model path."""
    fake = types.ModuleType("litellm")

    def _cost_per_token(**_kwargs: Any) -> tuple[float, float]:
        raise ValueError("model not found in pricing map")

    fake.cost_per_token = _cost_per_token  # type: ignore[attr-defined]
    sys.modules["litellm"] = fake


def _remove_fake_litellm() -> None:
    sys.modules.pop("litellm", None)


@pytest.fixture(autouse=True)
def _cleanup_litellm():
    yield
    _remove_fake_litellm()


# ─── _calc_cost_usd ────────────────────────────────────────────────────


def test_calc_cost_returns_zero_when_no_usage():
    from engine.llm.cost import _calc_cost_usd
    resp = LLMResponse(content="hi")  # usage=None
    assert _calc_cost_usd(resp, "gpt-4o") == 0.0


def test_calc_cost_returns_zero_when_total_tokens_zero():
    from engine.llm.cost import _calc_cost_usd
    resp = LLMResponse(content="hi", usage=TokenUsage(0, 0, 0))
    assert _calc_cost_usd(resp, "gpt-4o") == 0.0


def test_calc_cost_returns_sum_of_prompt_and_completion():
    _install_fake_litellm(prompt_cost=0.0001, completion_cost=0.0003)
    from engine.llm.cost import _calc_cost_usd
    resp = LLMResponse(content="hi", usage=TokenUsage(100, 50, 150))
    cost = _calc_cost_usd(resp, "gpt-4o")
    assert cost == pytest.approx(0.0001 * 100 + 0.0003 * 50)


def test_calc_cost_returns_zero_when_litellm_raises():
    _install_failing_litellm()
    from engine.llm.cost import _calc_cost_usd
    resp = LLMResponse(content="hi", usage=TokenUsage(100, 50, 150))
    assert _calc_cost_usd(resp, "fictional-model-9000") == 0.0


def test_calc_cost_returns_zero_when_litellm_not_installed():
    _remove_fake_litellm()
    # Force ImportError by inserting a sentinel that raises on attribute access
    sys.modules["litellm"] = None  # type: ignore[assignment]
    try:
        from engine.llm.cost import _calc_cost_usd
        resp = LLMResponse(content="hi", usage=TokenUsage(100, 50, 150))
        assert _calc_cost_usd(resp, "gpt-4o") == 0.0
    finally:
        sys.modules.pop("litellm", None)


# ─── CostTracker ───────────────────────────────────────────────────────


def test_tracker_starts_at_zero():
    from engine.llm.cost import CostTracker
    t = CostTracker()
    assert t.total_usd == 0.0
    assert t.call_count == 0
    assert t.total_prompt_tokens == 0
    assert t.total_completion_tokens == 0


def test_tracker_accumulates_across_calls():
    _install_fake_litellm(prompt_cost=0.001, completion_cost=0.002)
    from engine.llm.cost import CostTracker
    t = CostTracker()
    t.add(LLMResponse(content="a", usage=TokenUsage(10, 5, 15)), "gpt-4o")
    t.add(LLMResponse(content="b", usage=TokenUsage(20, 10, 30)), "gpt-4o")
    assert t.call_count == 2
    assert t.total_prompt_tokens == 30
    assert t.total_completion_tokens == 15
    assert t.total_usd == pytest.approx(0.001 * 30 + 0.002 * 15)


def test_tracker_check_limit_no_op_when_limit_zero():
    from engine.llm.cost import CostTracker
    t = CostTracker(limit_usd=0.0)
    t.total_usd = 999.0
    t.check_limit()  # must not raise


def test_tracker_check_limit_raises_when_exceeded():
    from engine.llm.cost import CostLimitError, CostTracker
    t = CostTracker(limit_usd=1.0)
    t.total_usd = 1.5
    with pytest.raises(CostLimitError) as excinfo:
        t.check_limit()
    assert excinfo.value.total_usd == 1.5
    assert excinfo.value.limit_usd == 1.0


def test_tracker_check_limit_quiet_under_threshold():
    from engine.llm.cost import CostTracker
    t = CostTracker(limit_usd=1.0)
    t.total_usd = 0.9
    t.check_limit()  # no exception


def test_tracker_summary_returns_dict():
    from engine.llm.cost import CostTracker
    t = CostTracker(limit_usd=2.0)
    t.total_usd = 0.5
    t.call_count = 3
    s = t.summary()
    assert s["total_usd"] == 0.5
    assert s["call_count"] == 3
    assert s["limit_usd"] == 2.0


# ─── make_tracker_from_env ─────────────────────────────────────────────


def test_make_tracker_from_env_reads_var(monkeypatch):
    monkeypatch.setenv("PTAI_PRICE_LIMIT", "5.50")
    from engine.llm.cost import make_tracker_from_env
    t = make_tracker_from_env()
    assert t.limit_usd == 5.50


def test_make_tracker_from_env_zero_when_unset(monkeypatch):
    monkeypatch.delenv("PTAI_PRICE_LIMIT", raising=False)
    from engine.llm.cost import make_tracker_from_env
    t = make_tracker_from_env()
    assert t.limit_usd == 0.0


def test_make_tracker_from_env_ignores_garbage(monkeypatch):
    monkeypatch.setenv("PTAI_PRICE_LIMIT", "not-a-number")
    from engine.llm.cost import make_tracker_from_env
    t = make_tracker_from_env()
    assert t.limit_usd == 0.0


def test_make_tracker_from_env_clamps_negative(monkeypatch):
    monkeypatch.setenv("PTAI_PRICE_LIMIT", "-3")
    from engine.llm.cost import make_tracker_from_env
    t = make_tracker_from_env()
    assert t.limit_usd == 0.0


# ─── CostTrackingLLMClient ─────────────────────────────────────────────


class _StubLLM:
    def __init__(self, response: LLMResponse):
        self._response = response
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        self.calls.append({
            "messages": messages, "tools": tools,
            "temperature": temperature, "max_tokens": max_tokens,
        })
        return self._response

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_wrapper_passes_call_through_without_tracker():
    from engine.llm.cost import CostTrackingLLMClient
    inner = _StubLLM(LLMResponse(content="ok", usage=TokenUsage(10, 5, 15)))
    client = CostTrackingLLMClient(inner, model="gpt-4o")
    resp = await client.complete(messages=[LLMMessage(role="user", content="hi")])
    assert resp.content == "ok"
    assert len(inner.calls) == 1


@pytest.mark.asyncio
async def test_wrapper_accumulates_when_tracker_set():
    _install_fake_litellm(prompt_cost=0.01, completion_cost=0.02)
    from engine.llm.cost import (
        CostTracker,
        CostTrackingLLMClient,
        reset_current_tracker,
        set_current_tracker,
    )
    tracker = CostTracker(limit_usd=0.0)
    token = set_current_tracker(tracker)
    try:
        inner = _StubLLM(LLMResponse(content="ok", usage=TokenUsage(10, 5, 15)))
        client = CostTrackingLLMClient(inner, model="gpt-4o")
        await client.complete(messages=[LLMMessage(role="user", content="hi")])
        assert tracker.call_count == 1
        assert tracker.total_usd == pytest.approx(0.01 * 10 + 0.02 * 5)
    finally:
        reset_current_tracker(token)


@pytest.mark.asyncio
async def test_wrapper_aborts_before_next_call_when_over_limit():
    _install_fake_litellm(prompt_cost=1.0, completion_cost=1.0)  # very expensive
    from engine.llm.cost import (
        CostLimitError,
        CostTracker,
        CostTrackingLLMClient,
        reset_current_tracker,
        set_current_tracker,
    )
    tracker = CostTracker(limit_usd=1.0)
    token = set_current_tracker(tracker)
    try:
        inner = _StubLLM(LLMResponse(content="ok", usage=TokenUsage(1, 1, 2)))
        client = CostTrackingLLMClient(inner, model="gpt-4o")
        # First call: spends $2, crosses limit
        await client.complete(messages=[LLMMessage(role="user", content="hi")])
        assert tracker.total_usd == 2.0
        # Second call: pre-flight check must raise BEFORE inner.complete is called
        before = len(inner.calls)
        with pytest.raises(CostLimitError):
            await client.complete(messages=[LLMMessage(role="user", content="hi")])
        assert len(inner.calls) == before  # inner not invoked
    finally:
        reset_current_tracker(token)


@pytest.mark.asyncio
async def test_wrapper_close_delegates():
    from engine.llm.cost import CostTrackingLLMClient
    inner = _StubLLM(LLMResponse(content="ok"))
    client = CostTrackingLLMClient(inner, model="gpt-4o")
    await client.close()
    assert inner.closed is True

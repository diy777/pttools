"""Gated LLM end-to-end smoke test.

Skipped by default. Runs only when both ANTHROPIC_API_KEY and PTAI_E2E_LIVE=1
are set in the environment, so CI and local unit-test runs do not touch a
live API or burn credits.

What it proves: the LLM client factory wires up correctly, the configured
provider reaches the API, and a BaseAgent-driven think() round trip
completes with a structured response. Combined with the unit tests that
mock LLM calls, this is the minimum live-path proof we need before
recording the demo video or pointing a real customer at the LLM mode.

Run:

    export ANTHROPIC_API_KEY=...
    export PTAI_E2E_LIVE=1
    pytest tests/test_llm_e2e_smoke.py -v
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY") or os.getenv("PTAI_E2E_LIVE") != "1",
    reason="needs ANTHROPIC_API_KEY and PTAI_E2E_LIVE=1",
)


@pytest.mark.asyncio
async def test_anthropic_provider_completes_simple_prompt():
    """Smoke: the Anthropic provider can complete a one-shot prompt."""
    from engine.llm.client import LLMMessage
    from engine.llm.factory import create_llm_client

    client = create_llm_client(provider="anthropic")
    try:
        response = await client.complete(
            messages=[
                LLMMessage(role="system", content="You are a security analyst. Reply in one sentence."),
                LLMMessage(role="user", content="What is the OWASP Top 10 in one sentence?"),
            ],
            tools=[],
        )
    finally:
        if hasattr(client, "close"):
            await client.close()

    assert response is not None
    assert isinstance(response.content, str)
    assert len(response.content) > 10, "expected a non-empty model response"


@pytest.mark.asyncio
async def test_baseagent_think_round_trip_with_real_llm():
    """Smoke: BaseAgent.think() drives a real LLM call and returns a response."""
    from unittest.mock import MagicMock

    from agents.base import BaseAgent
    from engine.llm.factory import create_llm_client

    llm = create_llm_client(provider="anthropic")
    registry = MagicMock()
    registry.list_tools.return_value = []
    db = MagicMock()

    agent = BaseAgent(registry=registry, db=db, llm=llm)
    agent.set_context({"target": "example.com", "open_ports": [80, 443]})

    try:
        response = await agent.think(
            "Briefly outline what you would check next for a recon engagement on example.com."
        )
    finally:
        if hasattr(llm, "close"):
            await llm.close()

    assert response is not None
    assert isinstance(response.content, str)
    assert len(response.content) > 0


# ─── LLM-driven agent loop E2E ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_llm_driven_web_assessment_picks_tools_and_completes():
    """The LLM tool loop drives a full WebAgent assessment against a real target.

    This is the path most paying users hit through Claude Code MCP. Verifies:
    1. The LLM actually selects tools from the registered toolset
    2. The tool loop iterates productively (more than zero tool calls)
    3. The loop terminates rather than running away to the iteration cap
    4. The agent produces a structured result with findings_count and status

    Uses Haiku to keep the token cost minimal; the goal is wire-path
    verification, not benchmarking model quality.
    """
    import socket

    from aiohttp import web

    from agents.web.web_agent import WebAgent
    from engine.findings_db import FindingsDB
    from engine.llm.factory import create_llm_client
    from tools.registry import ToolRegistry

    async def _index(_):
        return web.Response(
            text='<html><body><h1>Hello</h1><a href="/about">About</a></body></html>',
            content_type="text/html",
        )

    async def _about(_):
        return web.Response(text="<html>About</html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/about", _about)

    runner = web.AppRunner(app)
    await runner.setup()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()

    target = f"http://127.0.0.1:{port}"

    llm = create_llm_client(provider="anthropic", model="claude-haiku-4-5-20251001")
    registry = ToolRegistry()
    db = FindingsDB(":memory:")

    try:
        agent = WebAgent(registry=registry, db=db, llm=llm)
        result = await agent.run_assessment(
            target=target,
            focus_areas=["all"],
            engagement_id="llm-smoke-1",
        )
    finally:
        if hasattr(llm, "close"):
            await llm.close()
        await db.close()
        await runner.cleanup()

    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result.get("status") == "complete", f"agent didn't complete: {result}"
    # The LLM must have invoked at least one tool, otherwise the loop
    # devolved into a single chat turn that doesn't exercise the tool path.
    iterations = result.get("iterations", 0)
    assert iterations > 0, (
        f"LLM tool loop ran zero iterations — model never selected a tool. "
        f"Result: {result}"
    )
    # Sanity cap: should not have run away to the max-iterations safety cap.
    from agents.base import MAX_TOOL_LOOP_ITERATIONS
    assert iterations < MAX_TOOL_LOOP_ITERATIONS, (
        f"LLM hit the iteration cap ({MAX_TOOL_LOOP_ITERATIONS}); "
        f"loop never stopped on its own"
    )

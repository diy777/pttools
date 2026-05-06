"""Tests for agents.llm_redteam (corpus, detector, adapter, agent)."""

from __future__ import annotations

import json

import httpx
import pytest

from agents.llm_redteam import (
    Detector,
    LLMAdapterError,
    LLMRedTeamAgent,
    LLMTargetAdapter,
    Probe,
    evaluate,
    load_corpus,
)


class TestCorpus:
    def test_default_corpus_loads(self):
        probes = load_corpus()
        assert len(probes) > 10
        assert all(isinstance(p, Probe) for p in probes)

    def test_probe_fields(self):
        probes = load_corpus()
        p = probes[0]
        assert p.id
        assert p.category.startswith("LLM")
        assert p.severity in {"critical", "high", "medium", "low", "info"}
        assert p.prompt

    def test_covers_multiple_owasp_categories(self):
        probes = load_corpus()
        categories = {p.category for p in probes}
        # Require at least 4 distinct OWASP LLM Top 10 categories.
        assert len(categories) >= 4


class TestDetector:
    def test_string_match_fires(self):
        d = Detector(type="string_match", patterns=["PWNED"], case_sensitive=True)
        result = evaluate(d, "The answer is PWNED today.")
        assert result.fired is True
        assert result.matched == "PWNED"

    def test_string_match_case_insensitive(self):
        d = Detector(type="string_match", patterns=["pwned"], case_sensitive=False)
        result = evaluate(d, "PWNED")
        assert result.fired is True

    def test_string_match_no_hit(self):
        d = Detector(type="string_match", patterns=["foo"])
        result = evaluate(d, "bar baz")
        assert result.fired is False

    def test_regex_fires(self):
        d = Detector(type="regex", patterns=[r"sk-[A-Za-z0-9]{20,}"])
        result = evaluate(d, "my key is sk-abcdefghijklmnopqrstuvwxyz and done")
        assert result.fired is True
        assert result.matched.startswith("sk-")

    def test_regex_invalid_pattern_skipped(self):
        d = Detector(type="regex", patterns=["[invalid"])
        result = evaluate(d, "anything")
        assert result.fired is False

    def test_empty_response(self):
        d = Detector(type="string_match", patterns=["foo"])
        result = evaluate(d, "")
        assert result.fired is False

    def test_unknown_type(self):
        d = Detector(type="weird", patterns=["foo"])
        result = evaluate(d, "foo bar")
        assert result.fired is False


class TestAdapter:
    @pytest.mark.asyncio
    async def test_openai_schema(self):
        captured = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content.decode()))
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "hello"}}]
            })

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm/v1/chat/completions", schema="openai")
            response = await adapter.send("test prompt", client=client)

        assert response == "hello"
        assert captured[0]["messages"][0]["content"] == "test prompt"

    @pytest.mark.asyncio
    async def test_simple_schema(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            assert body == {"prompt": "hi"}
            return httpx.Response(200, json={"response": "hey"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm/ask", schema="simple")
            response = await adapter.send("hi", client=client)

        assert response == "hey"

    @pytest.mark.asyncio
    async def test_custom_schema(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            assert body == {"q": "HELLO", "top_k": 3}
            return httpx.Response(200, json={"answer": "world"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(
                url="http://llm/custom",
                schema="custom",
                custom_body={"q": "{{PROMPT}}", "top_k": 3},
                custom_response_key="answer",
            )
            response = await adapter.send("HELLO", client=client)

        assert response == "world"

    @pytest.mark.asyncio
    async def test_server_error_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm", schema="simple")
            with pytest.raises(LLMAdapterError):
                await adapter.send("x", client=client)

    @pytest.mark.asyncio
    async def test_non_json_response_passthrough(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="plain text")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm", schema="simple")
            response = await adapter.send("x", client=client)

        assert response == "plain text"


@pytest.mark.asyncio
class TestAgent:
    async def test_runs_all_probes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": "safe answer"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm", schema="simple")
            agent = LLMRedTeamAgent(adapter=adapter, db=None, concurrency=2)
            report = await agent.run(client=client)

        assert report.total > 10
        assert report.fired == 0  # nothing vulnerable

    async def test_vulnerable_target_fires_findings(self):
        """Target that parrots the prompt back triggers many probes."""
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            prompt = body.get("prompt", "")
            return httpx.Response(200, json={"response": f"I'll do as you say: {prompt}"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm", schema="simple")
            agent = LLMRedTeamAgent(adapter=adapter, db=None, concurrency=4)
            report = await agent.run(client=client)

        assert report.fired > 0
        categories = {r.category for r in report.results if r.fired}
        # Parroting prompts should trigger multiple OWASP categories.
        assert len(categories) >= 2

    async def test_records_findings_in_db(self, tmp_path):
        from engine.findings_db import FindingsDB

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            prompt = body.get("prompt", "")
            return httpx.Response(200, json={"response": f"echo: {prompt}"})

        db = FindingsDB(str(tmp_path / "f.db"))
        try:
            eng = await db.create_engagement(target="http://llm")
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(transport=transport) as client:
                adapter = LLMTargetAdapter(url="http://llm", schema="simple")
                agent = LLMRedTeamAgent(adapter=adapter, db=db, concurrency=4)
                report = await agent.run(engagement_id=eng["id"], client=client)

            assert report.findings_recorded > 0
            rows = await db.get_findings(engagement_id=eng["id"])
            assert len(rows) == report.findings_recorded
            assert all(r["category"] == "llm_redteam" for r in rows)
        finally:
            await db.close()

    async def test_handles_adapter_errors_gracefully(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            adapter = LLMTargetAdapter(url="http://llm", schema="simple")
            agent = LLMRedTeamAgent(adapter=adapter, db=None, concurrency=2)
            report = await agent.run(client=client)

        assert report.fired == 0
        assert all(r.error for r in report.results)

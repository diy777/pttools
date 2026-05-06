"""LLM red-team agent: runs probes against an LLM target and records findings."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .adapter import LLMAdapterError, LLMTargetAdapter
from .corpus import Probe, load_corpus
from .detector import evaluate

logger = logging.getLogger("pentest-tools.llm_redteam")


@dataclass
class ProbeResult:
    probe_id: str
    category: str
    severity: str
    fired: bool
    matched: str = ""
    response_excerpt: str = ""
    error: str = ""


@dataclass
class LLMRedTeamReport:
    target: str
    total: int
    fired: int
    results: list[ProbeResult] = field(default_factory=list)
    findings_recorded: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total": self.total,
            "fired": self.fired,
            "findings_recorded": self.findings_recorded,
            "results": [r.__dict__ for r in self.results],
        }


class LLMRedTeamAgent:
    """Runs the OWASP LLM Top 10 probe corpus against an HTTP LLM target."""

    def __init__(
        self,
        adapter: LLMTargetAdapter,
        db: Any = None,
        corpus_path: str | Path | None = None,
        concurrency: int = 4,
    ) -> None:
        self.adapter = adapter
        self.db = db
        self.corpus = load_corpus(corpus_path)
        self.concurrency = max(1, concurrency)

    async def run(
        self,
        engagement_id: str = "",
        client: httpx.AsyncClient | None = None,
    ) -> LLMRedTeamReport:
        report = LLMRedTeamReport(target=self.adapter.url, total=len(self.corpus), fired=0)
        sem = asyncio.Semaphore(self.concurrency)

        async def _run_one(probe: Probe) -> ProbeResult:
            async with sem:
                return await self._probe(probe, client)

        tasks = [asyncio.create_task(_run_one(p)) for p in self.corpus]
        for result in await asyncio.gather(*tasks):
            report.results.append(result)
            if result.fired:
                report.fired += 1
                if self.db and engagement_id:
                    await self._record_finding(result, engagement_id)
                    report.findings_recorded += 1

        return report

    async def _probe(self, probe: Probe, client: httpx.AsyncClient | None) -> ProbeResult:
        try:
            response = await self.adapter.send(probe.prompt, client=client)
        except LLMAdapterError as e:
            return ProbeResult(
                probe_id=probe.id,
                category=probe.category,
                severity=probe.severity,
                fired=False,
                error=str(e),
            )
        except httpx.HTTPError as e:
            return ProbeResult(
                probe_id=probe.id,
                category=probe.category,
                severity=probe.severity,
                fired=False,
                error=f"HTTP error: {e}",
            )

        detection = evaluate(probe.detect, response)
        return ProbeResult(
            probe_id=probe.id,
            category=probe.category,
            severity=probe.severity,
            fired=detection.fired,
            matched=detection.matched,
            response_excerpt=response[:400],
        )

    async def _record_finding(self, result: ProbeResult, engagement_id: str) -> None:
        finding = {
            "id": uuid.uuid4().hex[:8],
            "engagement_id": engagement_id,
            "title": f"LLM {result.category}: {result.probe_id}",
            "description": (
                f"Probe `{result.probe_id}` ({result.category}) fired against "
                f"{self.adapter.url}. Matched pattern: `{result.matched}`."
            ),
            "severity": result.severity,
            "category": "llm_redteam",
            "tool_source": "llm_redteam",
            "target": self.adapter.url,
            "evidence": result.response_excerpt,
            "owasp_category": result.category,
        }
        try:
            await self.db.add_finding(finding)
        except Exception as e:
            logger.exception(f"Failed to record LLM red-team finding: {e}")

"""End-to-end smoke tests for engagement lifecycle paths users hit often:

- Resume after interrupt: real users hit Ctrl+C; pttools resume picks up
  where it left off rather than starting from scratch.
- Multi-target campaign: real users scan a list of subdomains; every
  engagement should reach 'completed' even if some phases find nothing.
- Report generation: every engagement ends with a generated report;
  the file must exist on disk with the expected sections, not crash on
  empty findings or missing chains.

All three use a tiny aiohttp app as the target so the tests run in
under a few seconds and don't depend on external services or docker.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
from aiohttp import web

# Resume + campaign tests run the full deterministic phase list and take
# a few minutes each. The repo's pre-push hook runs pytest with
# --timeout=30, so an explicit per-test timeout is required to keep these
# from being killed prematurely. CI's e2e-juiceshop job sets its own
# 30-minute job timeout that this stays well under.
pytestmark = pytest.mark.timeout(900)

# ─── Tiny target server fixture ───────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_static_app() -> web.Application:
    """Trivial app: two pages, no auth, no vulns. Just something to scan."""
    async def index(_: web.Request) -> web.Response:
        return web.Response(
            text='<html><body><h1>Index</h1><a href="/about">About</a></body></html>',
            content_type="text/html",
        )

    async def about(_: web.Request) -> web.Response:
        return web.Response(text="<html><body>About</body></html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/about", about)
    return app


@pytest.fixture
async def static_app_url():
    app = _build_static_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = _free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


@pytest.fixture
async def three_static_app_urls():
    """Three independent app instances on three free ports."""
    runners = []
    urls = []
    try:
        for _ in range(3):
            app = _build_static_app()
            runner = web.AppRunner(app)
            await runner.setup()
            port = _free_port()
            site = web.TCPSite(runner, "127.0.0.1", port)
            await site.start()
            runners.append(runner)
            urls.append(f"http://127.0.0.1:{port}")
        yield urls
    finally:
        for r in runners:
            await r.cleanup()


# ─── Resume E2E ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resume_engagement_runs_only_remaining_phases(tmp_path, monkeypatch, static_app_url):
    """A previously interrupted engagement should resume from the next phase.

    This proves the resume code path:
    1. Reads the checkpoint (completed_phases)
    2. Builds the phase list
    3. Skips already-completed phases
    4. Runs remaining phases
    5. Marks engagement 'completed' at the end
    """
    monkeypatch.setenv("PTAI_DB_PATH", str(tmp_path / "findings.db"))

    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator
    from tools.registry import SecurityTool

    SecurityTool._cache = None
    SecurityTool._cache_disabled = True

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        # Simulate a previously-interrupted engagement: status='interrupted'
        # and recon already done. Resume should start from the web phase.
        engagement = await db.create_engagement(
            target=static_app_url, scope="web", intensity="normal"
        )
        eng_id = engagement["id"]
        await db.update_engagement_status(eng_id, "interrupted")
        await db.update_engagement_phase(eng_id, "recon", completed=True)

        checkpoint = await db.get_checkpoint(eng_id)
        assert "recon" in checkpoint["completed_phases"], (
            "test setup invariant: recon should be in completed_phases"
        )

        # Track which phases the resume runs by spying on update_engagement_phase.
        completed_during_resume: list[str] = []
        orig_update = db.update_engagement_phase

        async def _spy(engagement_id, phase, completed=False):
            if completed:
                completed_during_resume.append(phase)
            return await orig_update(engagement_id, phase, completed=completed)

        monkeypatch.setattr(db, "update_engagement_phase", _spy)

        engagement_for_resume = await db.get_engagement(eng_id)
        assert engagement_for_resume is not None
        orch = AgentOrchestrator(db=db)
        await orch.resume_engagement(engagement_for_resume)

        final = await db.get_engagement(eng_id)
        assert final is not None
        assert final["status"] == "completed", (
            f"resume failed to complete: status={final['status']}"
        )
        # Resume must NOT mark recon completed again (would double-count).
        assert "recon" not in completed_during_resume, (
            f"resume re-ran recon: {completed_during_resume}"
        )
        # Resume must mark the report phase completed (last phase in scope=web).
        assert "report" in completed_during_resume, (
            f"resume never reached report phase: {completed_during_resume}"
        )
    finally:
        await db.close()


# ─── Multi-target campaign E2E ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_multi_target_campaign_completes_every_engagement(
    tmp_path, monkeypatch, three_static_app_urls
):
    """Three sequential engagements against three targets must all reach completed.

    Catches regressions where a campaign loop bails on the first failure or
    leaves engagements stuck in 'running'.
    """
    monkeypatch.setenv("PTAI_DB_PATH", str(tmp_path / "findings.db"))

    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator
    from tools.registry import SecurityTool

    SecurityTool._cache = None
    SecurityTool._cache_disabled = True

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement_ids = []
        for url in three_static_app_urls:
            engagement = await db.create_engagement(target=url, scope="web", intensity="normal")
            orch = AgentOrchestrator(db=db)
            await orch.start_engagement(engagement)
            engagement_ids.append(engagement["id"])

        statuses = []
        for eid in engagement_ids:
            row = await db.get_engagement(eid)
            assert row is not None
            statuses.append(row["status"])

        assert statuses == ["completed", "completed", "completed"], (
            f"campaign left engagements unfinished: {statuses}"
        )
    finally:
        await db.close()


# ─── Report generation E2E ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_generation_writes_files_with_expected_sections(tmp_path, monkeypatch):
    """ReportAgent must write a markdown + html report with the engagement's
    target, severity counts, and finding titles. Catches regressions where
    the renderer drops sections or the writer fails on empty inputs.
    """
    # ReportAgent writes to "reports/" relative to cwd. Pin cwd to tmp_path.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PTAI_DB_PATH", str(tmp_path / "findings.db"))

    from agents.report.report_agent import ReportAgent
    from engine.findings_db import FindingsDB

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="http://test.local", scope="web", intensity="normal"
        )
        eid = engagement["id"]
        # Seed a couple of findings of varying severity. The report should
        # surface the high-severity one and aggregate severity counts.
        await db.add_finding({
            "engagement_id": eid,
            "title": "Reflected XSS in q parameter",
            "description": "Reflected XSS on /search?q=",
            "severity": "high",
            "category": "xss",
            "tool_source": "synthetic",
            "target": "http://test.local/search",
        })
        await db.add_finding({
            "engagement_id": eid,
            "title": "HSTS header missing",
            "description": "Strict-Transport-Security not present",
            "severity": "low",
            "category": "headers",
            "tool_source": "scan-headers",
            "target": "http://test.local",
        })

        agent = ReportAgent(db=db, llm=None)
        result = await agent.generate_report(eid, format="all")

        assert result["engagement_id"] == eid
        assert result["total_findings"] == 2
        # Markdown is the always-on path; HTML and PDF are optional.
        md_path = result["output_paths"].get("markdown", "")
        assert md_path, f"no markdown report path returned: {result}"
        md_file = Path(md_path)
        assert md_file.exists(), f"markdown report not written to disk: {md_path}"
        md_content = md_file.read_text()

        # Critical content the report must expose.
        assert "http://test.local" in md_content, "report missing target"
        assert "Reflected XSS in q parameter" in md_content, "report missing high-sev finding title"
        assert "high" in md_content.lower(), "report missing severity label"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_report_generation_does_not_crash_on_zero_findings(tmp_path, monkeypatch):
    """An engagement with no findings should still produce a report, not crash.

    Real-world: a hardened target genuinely produces zero findings. The
    report path was previously a regression hot spot for None-handling.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PTAI_DB_PATH", str(tmp_path / "findings.db"))

    from agents.report.report_agent import ReportAgent
    from engine.findings_db import FindingsDB

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target="http://hardened.local", scope="web", intensity="normal"
        )
        agent = ReportAgent(db=db, llm=None)
        result = await agent.generate_report(engagement["id"], format="markdown")
        assert result["total_findings"] == 0
        md_path = Path(result["output_paths"]["markdown"])
        assert md_path.exists()
        # Should still mention the target even with empty findings.
        assert "hardened.local" in md_path.read_text()
    finally:
        await db.close()


# Ensure cleanup on any leftover background tasks from aiohttp fixtures.
def _drain():
    return asyncio.get_event_loop()

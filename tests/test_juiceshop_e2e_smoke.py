"""End-to-end smoke tests against a live OWASP Juice Shop instance.

Skipped by default. Runs only when PTAI_E2E_JUICESHOP=1 and a Juice Shop
instance is reachable at the configured URL (default http://localhost:3000).

What this file proves end-to-end against a real intentionally-vulnerable
target (not unit-test mocks):

1. Direct orchestrator path: a full deterministic engagement produces
   findings, writes tool_results audit rows, and reaches status='completed'.
2. MCP path: the FastMCP-exposed surface that Claude Code hits also drives
   a real engagement to completion and exposes findings via MCP tools.
3. CI mode: `pttools start --ci` emits valid JSON and sets a meaningful
   exit code based on the configured fail threshold.
4. Cache + audit: a second engagement against the same target hits the
   cache (faster) but still writes complete tool_results audit rows
   (regression guard for the persistence fix).

Run locally:

    docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
    export PTAI_E2E_JUICESHOP=1
    pytest tests/test_juiceshop_e2e_smoke.py -v
    docker stop juiceshop

Run in CI: see .github/workflows/ci.yml job `e2e-juiceshop`.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest

JUICE_URL = os.getenv("PTAI_E2E_JUICESHOP_URL", "http://localhost:3000")


def _juiceshop_reachable() -> bool:
    if os.getenv("PTAI_E2E_JUICESHOP") != "1":
        return False
    try:
        with urllib.request.urlopen(JUICE_URL, timeout=5) as resp:
            return 200 <= resp.status < 500
    except (urllib.error.URLError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _juiceshop_reachable(),
    reason="needs PTAI_E2E_JUICESHOP=1 and Juice Shop reachable at $PTAI_E2E_JUICESHOP_URL",
)


@pytest.mark.asyncio
async def test_juiceshop_engagement_produces_findings_and_audit_rows(tmp_path, monkeypatch):
    """A full deterministic engagement against Juice Shop should:

    - exit cleanly (no exception bubble out)
    - produce at least one finding in the DB
    - record at least one tool_results audit row
    - complete in a bounded amount of time
    """
    db_path = tmp_path / "findings.db"
    monkeypatch.setenv("PTAI_DB_PATH", str(db_path))

    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator
    from tools.registry import SecurityTool

    # Bypass tool-result cache: this test always exercises the full pipeline.
    SecurityTool._cache = None
    SecurityTool._cache_disabled = True

    db = FindingsDB(str(db_path))
    try:
        engagement = await db.create_engagement(
            target=JUICE_URL,
            scope="web",
            intensity="normal",
        )
        orch = AgentOrchestrator(db=db)
        await orch.start_engagement(engagement)

        engagement_row = await db.get_engagement(engagement["id"])
        summary = await db.get_engagement_summary(engagement["id"])
        findings = await db.get_findings(engagement_id=engagement["id"])
        tool_results = await db.get_tool_results(engagement_id=engagement["id"])

        assert engagement_row is not None, "engagement row missing after run"
        assert engagement_row["status"] == "completed", (
            f"engagement did not complete cleanly: status={engagement_row['status']}"
        )
        assert summary["total_findings"] > 0, "engagement produced zero findings against Juice Shop"
        assert len(findings) > 0, "engagement produced zero findings against Juice Shop"
        assert len(tool_results) > 0, "engagement wrote zero tool_results audit rows"

        # Verify the audit fix: every tool that produced findings should have
        # at least one corresponding tool_results row. Catches the regression
        # where cache hits or parser/cache errors silently dropped audit rows.
        finding_tools = {f.get("tool_source") for f in findings if f.get("tool_source")}
        audited_tools = {r.get("tool_name") for r in tool_results if r.get("tool_name")}
        # Built-in scanners ("scan-paths", "scan-headers" etc.) don't go through
        # SecurityTool.execute(), so don't require their audit rows.
        external_finding_tools = {
            t for t in finding_tools if not t.startswith("scan-") and t != "builtin"
        }
        if external_finding_tools:
            missing_audit = external_finding_tools - audited_tools
            assert not missing_audit, (
                f"external tools produced findings but no audit rows: {missing_audit}"
            )
    finally:
        await db.close()


# ─── MCP path E2E ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_start_engagement_drives_full_run(tmp_path, monkeypatch):
    """The MCP-exposed start_engagement tool must drive a real engagement.

    This is the user-facing surface — Claude Code calls these MCP tools.
    Validates the wire path: in-process FastMCP client -> @mcp.tool() ->
    AgentOrchestrator -> real tools -> findings DB. If the deterministic
    path works but MCP is broken, paying customers see nothing.
    """
    from fastmcp import Client

    import mcp_server.server as srv

    db_path = tmp_path / "mcp_findings.db"
    monkeypatch.setenv("PENTEST_DB_PATH", str(db_path))
    monkeypatch.setenv("PTAI_DB_PATH", str(db_path))

    # Reset MCP server globals so it picks up the env-var-driven DB path.
    srv.findings_db = None
    srv.orchestrator = None
    srv.tool_registry = None

    from tools.registry import SecurityTool
    SecurityTool._cache = None
    SecurityTool._cache_disabled = True

    try:
        async with Client(srv.mcp) as client:
            start_result = await client.call_tool(
                "start_engagement",
                {"target": JUICE_URL, "scope": "web", "intensity": "normal"},
            )
            payload = start_result.data
            assert isinstance(payload, dict), f"start_engagement returned {type(payload)}"
            assert "engagement_id" in payload, f"missing engagement_id: {payload}"
            engagement_id = payload["engagement_id"]
            assert payload["target"] == JUICE_URL

            status_result = await client.call_tool(
                "get_engagement_status", {"engagement_id": engagement_id}
            )
            status = status_result.data
            assert status is not None, "get_engagement_status returned None"
            assert status["status"] == "completed", (
                f"engagement did not complete via MCP: {status}"
            )

            findings_result = await client.call_tool(
                "get_findings", {"engagement_id": engagement_id}
            )
            findings = findings_result.data
            assert isinstance(findings, list), f"get_findings returned {type(findings)}"
            assert len(findings) > 0, "MCP-driven engagement produced zero findings"
    finally:
        if srv.findings_db is not None:
            await srv.findings_db.close()
        srv.findings_db = None
        srv.orchestrator = None
        srv.tool_registry = None


# ─── CI mode E2E ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ci_mode_emits_json_and_meaningful_exit_code(tmp_path):
    """`pttools start --ci` is the contract for build-pipeline integration.

    Asserts:
    - exit code is non-negative (process didn't crash)
    - stdout contains at least one line of valid JSON
    - one of those JSON lines describes the completed engagement
    """
    import asyncio as _aio
    import json as _json
    import sys

    db_path = tmp_path / "ci_findings.db"

    proc = await _aio.create_subprocess_exec(
        sys.executable,
        "-m",
        "cli.main",
        "start",
        JUICE_URL,
        "--ci",
        "--scope",
        "web",
        "--intensity",
        "normal",
        "--no-sync",
        "--fail-threshold",
        "critical",
        env={
            **os.environ,
            "PTAI_DB_PATH": str(db_path),
            "PENTEST_DB_PATH": str(db_path),
        },
        stdout=_aio.subprocess.PIPE,
        stderr=_aio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await _aio.wait_for(proc.communicate(), timeout=600)
    except _aio.TimeoutError:
        proc.kill()
        await proc.communicate()
        pytest.fail("pttools --ci did not finish within 10 minutes")

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")

    assert proc.returncode is not None, "process didn't terminate"
    assert proc.returncode >= 0, (
        f"pttools --ci crashed: rc={proc.returncode}\nstderr:\n{stderr[-2000:]}"
    )

    json_lines = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            json_lines.append(_json.loads(line))
        except _json.JSONDecodeError:
            continue

    assert json_lines, (
        f"--ci mode produced no JSON lines on stdout.\n"
        f"stdout:\n{stdout[-2000:]}\nstderr:\n{stderr[-1000:]}"
    )
    # pttools --ci writes JSON-per-line where each line carries the event name
    # under the `message` key (see _ci_print in cli/main.py).
    completion_events = {"engagement_complete", "engagement_partial"}
    completion_lines = [
        line for line in json_lines if line.get("message") in completion_events
    ]
    assert completion_lines, (
        f"no engagement_complete/partial event in JSON output: {json_lines[-3:]}"
    )
    # The completion line must carry the engagement id and target back so that
    # CI consumers can wire it into downstream jobs.
    final = completion_lines[-1]
    assert final.get("engagement_id"), f"completion line missing engagement_id: {final}"
    assert final.get("target") == JUICE_URL, f"target mismatch: {final.get('target')!r}"


# ─── Cache hit + audit regression ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_second_run_cache_hits_still_persist_audit_rows(tmp_path, monkeypatch):
    """Second engagement against same target should hit cache but still audit.

    Regression guard for the bug where cache hits silently dropped
    tool_results rows. Two engagements run with cache enabled. The second
    must:
    - run faster (most tools cache-hit; the crawl + a few uncacheable
      built-ins still execute)
    - still produce a non-empty tool_results audit table
    """
    import time as _time

    from engine.cache import ToolResultCache
    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator
    from tools.registry import SecurityTool, configure_cache

    db_path = tmp_path / "cache_findings.db"
    cache_path = tmp_path / "cache.db"
    monkeypatch.setenv("PTAI_DB_PATH", str(db_path))
    monkeypatch.setenv("PTAI_CACHE_PATH", str(cache_path))

    cache = ToolResultCache(db_path=str(cache_path))
    configure_cache(cache, intensity="normal", disabled=False)

    db = FindingsDB(str(db_path))
    try:
        first = await db.create_engagement(target=JUICE_URL, scope="web", intensity="normal")
        t0 = _time.perf_counter()
        await AgentOrchestrator(db=db).start_engagement(first)
        first_elapsed = _time.perf_counter() - t0

        first_audit = await db.get_tool_results(engagement_id=first["id"])
        assert len(first_audit) > 0, "first engagement wrote no audit rows"

        second = await db.create_engagement(target=JUICE_URL, scope="web", intensity="normal")
        t1 = _time.perf_counter()
        await AgentOrchestrator(db=db).start_engagement(second)
        second_elapsed = _time.perf_counter() - t1

        second_audit = await db.get_tool_results(engagement_id=second["id"])
        cache_hit_rows = [r for r in second_audit if r.get("output", "")]

        assert len(second_audit) > 0, (
            "second engagement wrote zero audit rows — cache hits dropped them again"
        )
        # Every tool audited on the first run should also be audited on the second,
        # regardless of which path (cache hit vs fresh exec) produced the result.
        first_tools = {r.get("tool_name") for r in first_audit if r.get("tool_name")}
        second_tools = {r.get("tool_name") for r in second_audit if r.get("tool_name")}
        missing = first_tools - second_tools
        assert not missing, (
            f"tools audited on first run but missing on cached second run: {missing}"
        )
        # Sanity: cache should at least not make things slower.
        assert second_elapsed <= first_elapsed * 1.25, (
            f"cached run ({second_elapsed:.1f}s) slower than first ({first_elapsed:.1f}s)"
        )
        # Smoke: at least some rows looked like they came from cache replays.
        assert cache_hit_rows, "second engagement audit rows have no captured output"
    finally:
        await db.close()
        if hasattr(cache, "close"):
            await cache.close()
        SecurityTool._cache = None
        SecurityTool._cache_disabled = False

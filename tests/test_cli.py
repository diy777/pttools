"""Tests for CLI commands in cli/main.py."""

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def _mock_db(get_engagement=None, get_findings=None, get_engagement_summary=None, get_checkpoint=None):
    mock = MagicMock()
    mock.get_engagement = AsyncMock(return_value=get_engagement)
    mock.get_findings = AsyncMock(return_value=get_findings or [])
    mock.get_engagement_summary = AsyncMock(
        return_value=get_engagement_summary
        or {
            "total_findings": 0,
            "by_severity": {},
            "attack_chains": 0,
            "detection_rules": 0,
        }
    )
    mock.get_checkpoint = AsyncMock(
        return_value=get_checkpoint
        or {"current_phase": None, "completed_phases": [], "status": "running"}
    )
    mock.list_engagements = AsyncMock(return_value=[])
    mock.update_engagement_phase = AsyncMock()
    mock.update_engagement_status = AsyncMock()
    mock.get_attack_chains = AsyncMock(return_value=[])
    mock.close = AsyncMock()
    return mock


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


def test_status_engagement_not_found():
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_engagement=None)):
        result = runner.invoke(app, ["status", "eng-missing"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_status_engagement_found():
    engagement = {
        "id": "eng-1",
        "target": "10.0.0.1",
        "status": "running",
        "created_at": "2026-01-01",
        "scope": "full",
    }
    summary = {
        "total_findings": 3,
        "by_severity": {"critical": 1, "high": 2},
        "attack_chains": 1,
        "detection_rules": 2,
    }
    with patch(
        "engine.findings_db.FindingsDB",
        return_value=_mock_db(get_engagement=engagement, get_engagement_summary=summary),
    ):
        result = runner.invoke(app, ["status", "eng-1"])
    assert result.exit_code == 0
    assert "10.0.0.1" in result.output


# ---------------------------------------------------------------------------
# findings command
# ---------------------------------------------------------------------------


def test_findings_no_results():
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_findings=[])):
        result = runner.invoke(app, ["findings", "eng-1"])
    assert "No findings" in result.output


def test_findings_with_results():
    rows = [
        {
            "severity": "critical",
            "title": "SQL Injection",
            "target": "10.0.0.1",
            "category": "web",
            "status": "confirmed",
        }
    ]
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_findings=rows)):
        result = runner.invoke(app, ["findings", "eng-1"])
    assert "SQL Injection" in result.output


def test_findings_severity_filter():
    mock_db = _mock_db(get_findings=[])
    with patch("engine.findings_db.FindingsDB", return_value=mock_db):
        runner.invoke(app, ["findings", "eng-1", "--severity", "critical"])
    mock_db.get_findings.assert_called_once_with(engagement_id="eng-1", severity="critical")


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


def test_report_engagement_not_found():
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_engagement=None)):
        result = runner.invoke(app, ["report", "eng-missing"])
    assert result.exit_code == 1


def test_report_success():
    engagement = {
        "id": "eng-1",
        "target": "10.0.0.1",
        "status": "complete",
        "created_at": "2026-01-01",
    }
    report_result = {
        "output_path": "reports/eng-1.md",
        "total_findings": 5,
        "attack_chains": 1,
        "output_paths": {"markdown": "reports/eng-1.md"},
    }
    mock_db = _mock_db(get_engagement=engagement)
    mock_agent = MagicMock()
    mock_agent.generate_report = AsyncMock(return_value=report_result)

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "agents.report.report_agent.ReportAgent", return_value=mock_agent
    ):
        result = runner.invoke(app, ["report", "eng-1"])
    assert result.exit_code == 0
    assert "reports/" in result.output


# ---------------------------------------------------------------------------
# auth command
# ---------------------------------------------------------------------------


def test_auth_status_not_linked():
    with patch("cli.auth.load_api_key", return_value=None):
        result = runner.invoke(app, ["auth", "status"])
    assert "Not linked" in result.output


def test_auth_logout_calls_remove_credentials():
    with patch("cli.auth.key_source", return_value="file"), patch(
        "cli.auth.remove_credentials"
    ) as mock_remove:
        result = runner.invoke(app, ["auth", "logout", "--yes"])
    mock_remove.assert_called_once()
    assert result.exit_code == 0


def test_auth_invalid_key_exits_nonzero():
    with patch("cli.auth.validate_key_remote", return_value=None):
        result = runner.invoke(app, ["auth", "login", "bad-key-1234"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------


def test_list_no_engagements():
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db()):
        result = runner.invoke(app, ["list"])
    assert "No engagements" in result.output


def test_list_with_engagements():
    mock = _mock_db()
    mock.list_engagements = AsyncMock(return_value=[
        {
            "id": "eng-1",
            "target": "10.0.0.1",
            "scope": "full",
            "status": "completed",
            "created_at": "2026-01-01T00:00:00",
            "total_findings": 5,
            "by_severity": {"critical": 1, "high": 2},
        }
    ])
    with patch("engine.findings_db.FindingsDB", return_value=mock):
        result = runner.invoke(app, ["list"])
    assert "10.0.0.1" in result.output
    assert "eng-1" in result.output


def test_list_ci_mode():
    mock = _mock_db()
    mock.list_engagements = AsyncMock(return_value=[])
    with patch("engine.findings_db.FindingsDB", return_value=mock):
        result = runner.invoke(app, ["list", "--ci"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# resume command
# ---------------------------------------------------------------------------


def test_resume_not_found():
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_engagement=None)):
        result = runner.invoke(app, ["resume", "eng-missing"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# status --ci flag
# ---------------------------------------------------------------------------


def test_status_ci_mode():
    engagement = {
        "id": "eng-1",
        "target": "10.0.0.1",
        "status": "running",
        "created_at": "2026-01-01",
        "scope": "full",
    }
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_engagement=engagement)):
        result = runner.invoke(app, ["status", "eng-1", "--ci"])
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert data["engagement"]["target"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# findings --ci flag
# ---------------------------------------------------------------------------


def test_findings_ci_mode():
    rows = [{"severity": "critical", "title": "SQLi", "target": "10.0.0.1", "category": "web", "status": "confirmed"}]
    with patch("engine.findings_db.FindingsDB", return_value=_mock_db(get_findings=rows)):
        result = runner.invoke(app, ["findings", "eng-1", "--ci"])
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert len(data) == 1


# ---------------------------------------------------------------------------
# report sarif/junit formats
# ---------------------------------------------------------------------------


def test_report_sarif_format(tmp_path):
    engagement = {"id": "eng-1", "target": "10.0.0.1", "status": "complete", "created_at": "2026-01-01", "scope": "full"}
    findings_rows = [{"title": "SQLi", "severity": "critical", "category": "web", "target": "10.0.0.1", "description": "test", "cwe_id": "CWE-89"}]
    mock = _mock_db(get_engagement=engagement, get_findings=findings_rows)
    out_path = str(tmp_path / "report.sarif.json")
    with patch("engine.findings_db.FindingsDB", return_value=mock):
        result = runner.invoke(app, ["report", "eng-1", "--format", "sarif", "--output", out_path])
    assert result.exit_code == 0
    import json
    with open(out_path) as f:
        sarif = json.load(f)
    assert sarif["version"] == "2.1.0"


def test_report_junit_format(tmp_path):
    engagement = {"id": "eng-1", "target": "10.0.0.1", "status": "complete", "created_at": "2026-01-01", "scope": "full"}
    findings_rows = [{"title": "SQLi", "severity": "critical", "category": "web", "target": "10.0.0.1", "description": "test"}]
    mock = _mock_db(get_engagement=engagement, get_findings=findings_rows)
    out_path = str(tmp_path / "report.junit.xml")
    with patch("engine.findings_db.FindingsDB", return_value=mock):
        result = runner.invoke(app, ["report", "eng-1", "--format", "junit", "--output", out_path])
    assert result.exit_code == 0
    with open(out_path) as f:
        content = f.read()
    assert "<testsuite" in content


# ---------------------------------------------------------------------------
# start command — regression tests for the "start doesn't scan, it launches
# MCP" bug. See cli/main.py `start`. These must fail against 0.9.0.
# ---------------------------------------------------------------------------


def _start_mock_db(engagement_id: str = "eng-new"):
    engagement = {
        "id": engagement_id,
        "target": "http://example.test/",
        "scope": "recon",
        "intensity": "normal",
        "status": "pending",
        "created_at": "2026-04-18T00:00:00",
    }
    mock = _mock_db(
        get_engagement=engagement,
        get_engagement_summary={
            "total_findings": 1,
            "by_severity": {"high": 1},
            "attack_chains": 0,
            "detection_rules": 0,
        },
    )
    mock.create_engagement = AsyncMock(return_value=engagement)
    mock.reconcile_stale_engagements = AsyncMock(return_value=0)
    return mock, engagement


def test_start_requires_target():
    """pttools start with no target and no --targets file exits non-zero."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code != 0


def test_start_creates_engagement_with_correct_args(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    mock_db, _engagement = _start_mock_db()
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock(return_value=None)

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "engine.orchestrator.AgentOrchestrator", return_value=mock_orch
    ):
        result = runner.invoke(
            app,
            ["start", "http://example.test/", "--scope", "recon", "--intensity", "stealth"],
        )

    assert result.exit_code == 0, result.output
    mock_db.create_engagement.assert_called_once()
    kwargs = mock_db.create_engagement.call_args.kwargs
    assert kwargs.get("target") == "http://example.test/"
    assert kwargs.get("scope") == "recon"
    assert kwargs.get("intensity") == "stealth"


def test_start_max_findings_per_phase_sets_env_vars(monkeypatch):
    """--max-findings-per-phase 50 should set every PENTEST_TOOLS_MAX_FINDINGS_*
    var so recon caps every phase identically for this run."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    # Clear any pre-existing per-phase env so we know the flag set them.
    for v in (
        "PENTEST_TOOLS_MAX_FINDINGS_SUBDOMAIN_ENUM",
        "PENTEST_TOOLS_MAX_FINDINGS_OSINT",
        "PENTEST_TOOLS_MAX_FINDINGS_PORT_SCAN",
        "PENTEST_TOOLS_MAX_FINDINGS_WEB_TECH",
        "PENTEST_TOOLS_MAX_FINDINGS_VULN_SCAN",
        "PENTEST_TOOLS_MAX_FINDINGS_CONTENT_DISCOVERY",
    ):
        monkeypatch.delenv(v, raising=False)

    mock_db, _engagement = _start_mock_db()
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock(return_value=None)

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "engine.orchestrator.AgentOrchestrator", return_value=mock_orch
    ):
        result = runner.invoke(
            app,
            ["start", "http://example.test/", "--scope", "recon",
             "--max-findings-per-phase", "50"],
        )

    assert result.exit_code == 0, result.output
    import os
    assert os.environ.get("PENTEST_TOOLS_MAX_FINDINGS_SUBDOMAIN_ENUM") == "50"
    assert os.environ.get("PENTEST_TOOLS_MAX_FINDINGS_VULN_SCAN") == "50"


def test_start_max_findings_per_phase_default_zero_no_env_change(monkeypatch):
    """--max-findings-per-phase 0 (default) must not touch the env vars."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    monkeypatch.delenv("PENTEST_TOOLS_MAX_FINDINGS_PORT_SCAN", raising=False)

    mock_db, _engagement = _start_mock_db()
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock(return_value=None)

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "engine.orchestrator.AgentOrchestrator", return_value=mock_orch
    ):
        result = runner.invoke(app, ["start", "http://example.test/", "--scope", "recon"])

    assert result.exit_code == 0, result.output
    import os
    assert os.environ.get("PENTEST_TOOLS_MAX_FINDINGS_PORT_SCAN") is None


def test_start_invokes_orchestrator_not_mcp_server(monkeypatch):
    """The root of Bug B: `start` must run a scan via the orchestrator,
    NOT launch the MCP stdio server (which also causes the Rich/stdout crash)."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    mock_db, engagement = _start_mock_db()
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock(return_value=None)
    mock_run_server = MagicMock()

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "engine.orchestrator.AgentOrchestrator", return_value=mock_orch
    ), patch("mcp_server.server.run_server", mock_run_server):
        result = runner.invoke(app, ["start", "http://example.test/", "--scope", "recon"])

    assert result.exit_code == 0, result.output
    mock_orch.start_engagement.assert_called_once()
    called_engagement = mock_orch.start_engagement.call_args.args[0]
    assert called_engagement["id"] == engagement["id"]
    mock_run_server.assert_not_called()


def test_start_without_llm_key_falls_back_to_deterministic(monkeypatch, tmp_path):
    """A user with no API key should NOT get a hard exit. CLI runs in
    deterministic mode, since customers using pttools through Claude Code MCP
    don't need an API key for direct CLI calls.
    """
    for var in (
        "PENTEST_TOOLS_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "PENTEST_TOOLS_LLM_PROVIDER",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("HOME", str(tmp_path))

    mock_db, _engagement = _start_mock_db()
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock(return_value=None)

    with patch("engine.findings_db.FindingsDB", return_value=mock_db), patch(
        "engine.orchestrator.AgentOrchestrator", return_value=mock_orch
    ):
        result = runner.invoke(app, ["start", "http://example.test/", "--scope", "recon"])

    assert result.exit_code == 0, result.output
    combined = result.output.lower()
    assert "deterministic" in combined or "no ai" in combined or "no llm" in combined
    mock_orch.start_engagement.assert_called_once()


def test_root_version_flag():
    """`pttools --version` must work (it's the first thing every CLI user tries)."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    # Version string should look like a semver
    import re
    assert re.search(r"\d+\.\d+\.\d+", result.output), result.output

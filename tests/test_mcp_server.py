"""Tests for MCP server tool functions."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp_server.server as srv


@pytest.fixture(autouse=True)
def _reset_globals():
    """Reset server globals between tests."""
    srv.findings_db = None
    srv.orchestrator = None
    srv.tool_registry = None
    yield
    srv.findings_db = None
    srv.orchestrator = None
    srv.tool_registry = None


def _mock_db(**overrides):
    db = MagicMock()
    db.get_engagement = AsyncMock(return_value=overrides.get("get_engagement"))
    db.get_findings = AsyncMock(return_value=overrides.get("get_findings", []))
    db.get_attack_chains = AsyncMock(return_value=overrides.get("get_attack_chains", []))
    db.get_engagement_summary = AsyncMock(return_value=overrides.get("get_engagement_summary", {
        "total_findings": 0, "by_severity": {}, "attack_chains": 0, "detection_rules": 0,
    }))
    db.create_engagement = AsyncMock(return_value=overrides.get("create_engagement", {
        "id": "eng-abc", "target": "10.0.0.1", "status": "running",
    }))
    db.add_finding = AsyncMock()
    db._db = MagicMock()
    db._db.execute = AsyncMock()
    db._db.commit = AsyncMock()
    return db


# ─── Helper function tests ──────────────────────────────────────────────


def test_get_findings_db_creates_singleton():
    with patch("mcp_server.server.FindingsDB") as mock_cls:
        mock_cls.return_value = MagicMock()
        db1 = srv.get_findings_db()
        db2 = srv.get_findings_db()
        assert db1 is db2
        mock_cls.assert_called_once()


def test_get_orchestrator_creates_singleton():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    with patch("mcp_server.server.AgentOrchestrator") as mock_cls:
        mock_cls.return_value = MagicMock()
        o1 = srv.get_orchestrator()
        o2 = srv.get_orchestrator()
        assert o1 is o2
        mock_cls.assert_called_once()


def test_get_tool_registry_creates_singleton():
    with patch("mcp_server.server.ToolRegistry") as mock_cls:
        mock_cls.return_value = MagicMock()
        r1 = srv.get_tool_registry()
        r2 = srv.get_tool_registry()
        assert r1 is r2
        mock_cls.assert_called_once()


# ─── Engagement tools ───────────────────────────────────────────────────


async def test_get_engagement_status():
    mock_db = _mock_db(get_engagement={"id": "eng-1", "status": "running"})
    srv.findings_db = mock_db
    result = await srv.get_engagement_status("eng-1")
    assert result["status"] == "running"
    mock_db.get_engagement.assert_awaited_once_with("eng-1")


async def test_get_engagement_status_not_found():
    mock_db = _mock_db(get_engagement=None)
    srv.findings_db = mock_db
    result = await srv.get_engagement_status("eng-999")
    assert result is None


async def test_get_findings_filters():
    mock_findings = [{"severity": "critical", "title": "RCE"}]
    mock_db = _mock_db(get_findings=mock_findings)
    srv.findings_db = mock_db
    result = await srv.get_findings(engagement_id="eng-1", severity="critical")
    assert len(result) == 1
    mock_db.get_findings.assert_awaited_once_with(
        engagement_id="eng-1", severity="critical", status=None,
    )


async def test_get_attack_chains():
    chains = [{"id": "chain-1", "name": "Web to Shell"}]
    mock_db = _mock_db(get_attack_chains=chains)
    srv.findings_db = mock_db
    result = await srv.get_attack_chains("eng-1")
    assert result[0]["name"] == "Web to Shell"


async def test_get_engagement_summary():
    summary = {"total_findings": 5, "by_severity": {"critical": 2}, "attack_chains": 1, "detection_rules": 3}
    mock_db = _mock_db(get_engagement_summary=summary)
    srv.findings_db = mock_db
    result = await srv.get_engagement_summary("eng-1")
    assert result["total_findings"] == 5


async def test_start_engagement():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    mock_orch = MagicMock()
    mock_orch.start_engagement = AsyncMock()
    srv.orchestrator = mock_orch

    result = await srv.start_engagement("10.0.0.1", scope="web")
    assert result["engagement_id"] == "eng-abc"
    assert result["status"] == "running"
    mock_db.create_engagement.assert_awaited_once()
    mock_orch.start_engagement.assert_awaited_once()


async def test_close_engagement():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    result = await srv.close_engagement("eng-1")
    assert result["status"] == "completed"
    mock_db._db.execute.assert_awaited_once()
    mock_db._db.commit.assert_awaited_once()


# ─── Tool execution ─────────────────────────────────────────────────────


async def test_list_tools():
    mock_tool = MagicMock()
    mock_tool.name = "nmap"
    mock_tool.category = "network"
    mock_tool.description = "Port scanner"
    mock_tool.required_deps = ["nmap"]
    mock_tool.is_installed.return_value = True

    mock_registry = MagicMock()
    mock_registry.list_tools.return_value = [mock_tool]
    srv.tool_registry = mock_registry

    result = await srv.list_tools(category="network")
    assert len(result) == 1
    assert result[0]["name"] == "nmap"
    assert result[0]["installed"] is True


async def test_run_tool_not_found():
    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = None
    srv.tool_registry = mock_registry

    result = await srv.run_tool("nonexistent", "10.0.0.1")
    assert "error" in result


async def test_run_tool_not_installed():
    mock_tool = MagicMock()
    mock_tool.is_installed.return_value = False
    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool
    srv.tool_registry = mock_registry

    result = await srv.run_tool("nmap", "10.0.0.1")
    assert "not installed" in result["error"]


async def test_run_tool_success_stores_findings():
    mock_tool = MagicMock()
    mock_tool.is_installed.return_value = True
    mock_tool.execute = AsyncMock(return_value={
        "findings": [{"title": "Open port 80", "severity": "info"}]
    })
    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool
    srv.tool_registry = mock_registry

    mock_db = _mock_db()
    srv.findings_db = mock_db

    result = await srv.run_tool("nmap", "10.0.0.1")
    assert len(result["findings"]) == 1
    mock_db.add_finding.assert_awaited_once()


# ─── Builtin scanner wrappers ───────────────────────────────────────────


async def test_scan_ports_builtin():
    mock_findings = [{"title": "Port 80 open"}]
    with patch("engine.scanners.scan_ports", new=AsyncMock(return_value=mock_findings)):
        result = await srv.scan_ports_builtin("10.0.0.1")
        assert result["findings_count"] == 1
        assert result["findings"][0]["title"] == "Port 80 open"


async def test_builtin_scan_stores_findings():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    mock_result = {"findings": [{"title": "Test finding", "severity": "info"}], "findings_count": 1}

    with patch("engine.scanners.run_builtin_scan", new=AsyncMock(return_value=mock_result)):
        result = await srv.builtin_scan("10.0.0.1", scan_type="ports")
        assert result["findings_count"] == 1
        mock_db.add_finding.assert_awaited_once()


# ─── run_server ──────────────────────────────────────────────────────────


def test_run_server_stdio():
    with patch.object(srv.mcp, "run") as mock_run:
        srv.run_server(transport="stdio")
        mock_run.assert_called_once_with(transport="stdio")


def test_run_server_sse():
    with patch.object(srv.mcp, "run") as mock_run:
        srv.run_server(transport="sse", host="127.0.0.1", port=9000)
        mock_run.assert_called_once_with(transport="sse", host="127.0.0.1", port=9000)

"""Tests for the orchestrator (engine/orchestrator.py)."""

from unittest.mock import MagicMock, patch

import pytest

from engine.findings_db import FindingsDB
from engine.orchestrator import AgentOrchestrator
from engine.scope import ScopeEnforcer


@pytest.fixture
def db():
    return FindingsDB(":memory:")


@pytest.fixture
async def engagement(db):
    return await db.create_engagement("example.com", "full", "", "normal")


class TestOrchestratorInit:
    def test_init_minimal(self, db):
        orch = AgentOrchestrator(db)
        assert not orch.is_running
        assert orch.current_phase is None

    def test_init_with_scope(self, db):
        scope = ScopeEnforcer(allowed_targets=["example.com"])
        orch = AgentOrchestrator(db, scope=scope)
        assert orch.scope is not None

    def test_init_with_llm(self, db):
        mock_llm = MagicMock()
        orch = AgentOrchestrator(db, llm=mock_llm)
        assert orch.llm is mock_llm


class TestOrchestratorRegistry:
    def test_get_registry(self, db):
        orch = AgentOrchestrator(db)
        registry = orch._get_registry()
        assert len(registry.list_tools()) >= 170

    def test_scope_wrapping(self, db):
        scope = ScopeEnforcer(allowed_targets=["example.com"])
        orch = AgentOrchestrator(db, scope=scope)
        registry = orch._get_registry()
        assert registry is not None


class TestOrchestratorPhases:
    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_recon_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_recon(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_web_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_web_assessment(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_ad_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_ad_assessment(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_cloud_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_cloud_assessment(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_exploit_chaining_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_exploit_chaining(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_poc_validation_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_poc_validation(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_detection_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._run_detection_generation(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_report_phase(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch._generate_report(engagement)

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_full_engagement(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch.start_engagement(engagement)
        assert not orch.is_running


class TestPhaseList:
    def test_full_scope_includes_all(self, db):
        orch = AgentOrchestrator(db)
        phases = orch._build_phase_list("full", {"target": "10.0.0.1"})
        names = [name for name, _ in phases]
        assert "recon" in names
        assert "web" in names
        assert "ad" in names
        assert "cloud" in names
        assert "chaining" in names
        assert "report" in names

    def test_web_scope_excludes_ad_cloud(self, db):
        orch = AgentOrchestrator(db)
        phases = orch._build_phase_list("web", {"target": "10.0.0.1"})
        names = [name for name, _ in phases]
        assert "web" in names
        assert "ad" not in names
        assert "cloud" not in names

    def test_mobile_requires_target(self, db):
        orch = AgentOrchestrator(db)
        phases_no = orch._build_phase_list("full", {"target": "10.0.0.1"})
        phases_yes = orch._build_phase_list("full", {"target": "10.0.0.1", "mobile_target": "app.apk"})
        assert "mobile" not in [n for n, _ in phases_no]
        assert "mobile" in [n for n, _ in phases_yes]


class TestProgressCallback:
    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_progress_called(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        calls = []
        await orch.start_engagement(engagement, on_progress=lambda p, m, pct: calls.append((p, m, pct)))
        phases_reported = [p for p, _, _ in calls]
        assert "recon" in phases_reported
        assert "done" in phases_reported

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_engagement_marked_completed(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch.start_engagement(engagement)
        eng = await db.get_engagement(engagement["id"])
        assert eng["status"] == "completed"

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_phase_checkpoint_saved(self, _m, db, engagement):
        orch = AgentOrchestrator(db)
        await orch.start_engagement(engagement)
        checkpoint = await db.get_checkpoint(engagement["id"])
        assert "recon" in checkpoint["completed_phases"]
        assert "report" in checkpoint["completed_phases"]


class TestResume:
    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_resume_skips_completed(self, _m, db, engagement):
        orch1 = AgentOrchestrator(db)
        await orch1.start_engagement(engagement)

        await db._get_db()
        await db._db.execute(
            "UPDATE engagements SET status = 'failed', completed_phases = ? WHERE id = ?",
            ('["recon","web","ad","cloud","chaining","validation"]', engagement["id"]),
        )
        await db._db.commit()

        orch2 = AgentOrchestrator(db)
        calls = []
        await orch2.resume_engagement(engagement, on_progress=lambda p, m, pct: calls.append(p))
        phases_run = [p for p in calls if p not in ("done",)]
        assert "recon" not in phases_run

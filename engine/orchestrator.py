"""
Agent Orchestrator — Coordinates multiple specialist agents across an engagement.

Manages the lifecycle: recon -> analysis -> exploitation -> chaining -> reporting.
Each agent runs in sequence or parallel depending on scope and findings.
Supports checkpoint/resume for interrupted engagements.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from engine.auth_handler import AuthCredentials
from engine.exec_context import current_engagement_id, current_findings_db
from engine.findings_db import FindingsDB
from engine.llm.client import LLMClient
from engine.llm.cost import (
    CostLimitError,
    make_tracker_from_env,
    reset_current_tracker,
    set_current_tracker,
)
from engine.rate_limiter import RateLimiter, ScanProfile
from engine.scope import ScopeEnforcer
from engine.workflow import WorkflowPlan, WorkflowStage, build_workflow_plan

logger = logging.getLogger("pentest-tools.orchestrator")

ProgressCallback = Callable[[str, str, float], None]

WORKFLOW_LABELS = {
    "recon": "asset discovery and baseline mapping",
    "web": "web application assessment",
    "ad": "directory and identity assessment",
    "cloud": "cloud configuration assessment",
    "mobile": "mobile application assessment",
    "chaining": "attack path construction",
    "validation": "proof-of-concept validation",
    "detection": "detection content generation",
    "report": "report assembly",
}


class AgentOrchestrator:
    def __init__(
        self,
        db: FindingsDB,
        llm: LLMClient | None = None,
        scope: ScopeEnforcer | None = None,
    ):
        self.db = db
        self.llm = llm
        self.scope = scope
        self._running = False
        self._current_phase: str | None = None
        self._recon_context: dict[str, Any] = {}
        self._rate_limiter: RateLimiter | None = None
        self._auth: AuthCredentials = AuthCredentials()
        self._phase_errors: dict[str, str] = {}
        self._workflow_plan: WorkflowPlan | None = None
        self._stage_records: list[dict[str, Any]] = []

    async def set_intensity(self, engagement_id: str, intensity: str) -> None:
        if intensity not in ("stealth", "normal", "aggressive"):
            raise ValueError(f"unsupported intensity: {intensity!r}")
        await self.db.update_engagement_intensity(engagement_id, intensity)
        if self._running:
            self._rate_limiter = RateLimiter(ScanProfile.from_intensity(intensity))
            logger.info("engagement %s intensity changed live to %s", engagement_id, intensity)

    def set_auth(self, creds: AuthCredentials) -> None:
        self._auth = creds

    async def start_engagement(
        self,
        engagement: dict[str, Any],
        on_progress: ProgressCallback | None = None,
    ) -> None:
        await self._execute_workflow(engagement, on_progress=on_progress, resume=False)

    async def resume_engagement(
        self,
        engagement: dict[str, Any],
        on_progress: ProgressCallback | None = None,
    ) -> None:
        await self._execute_workflow(engagement, on_progress=on_progress, resume=True)

    async def _execute_workflow(
        self,
        engagement: dict[str, Any],
        *,
        on_progress: ProgressCallback | None,
        resume: bool,
    ) -> None:
        self._running = True
        self._phase_errors = {}
        self._stage_records = []
        self._current_phase = None
        engagement_id = engagement["id"]
        scope = engagement.get("scope", "full")
        intensity = engagement.get("intensity", "normal")
        progress = on_progress or _noop_progress

        profile = ScanProfile.from_intensity(intensity)
        self._rate_limiter = RateLimiter(profile)

        token_eid = current_engagement_id.set(engagement_id)
        token_db = current_findings_db.set(self.db)
        cost_tracker = make_tracker_from_env()
        token_cost = set_current_tracker(cost_tracker)

        try:
            self._workflow_plan = build_workflow_plan(
                scope,
                engagement.get("target", ""),
                intensity,
                mobile_target=bool(engagement.get("mobile_target")),
            )
            logger.info("workflow plan: %s", self._workflow_plan.summary())
            stages = self._build_executable_stages(engagement)

            if resume:
                checkpoint = await self.db.get_checkpoint(engagement_id)
                completed = set(checkpoint["completed_phases"]) if checkpoint else set()
                stages = [stage for stage in stages if stage.name not in completed]
                done_count = len(completed)
                logger.info("resuming engagement %s, completed phases: %s", engagement_id, sorted(completed))
            else:
                done_count = 0
                logger.info("starting engagement %s against %s (intensity=%s)", engagement_id, engagement["target"], intensity)
                await self.db.update_engagement_status(engagement_id, "running")

            total = max(len(stages), 1)

            for idx, stage in enumerate(stages):
                await self._run_stage(
                    engagement=engagement,
                    stage=stage,
                    progress=progress,
                    engagement_id=engagement_id,
                    idx=idx,
                    total=total,
                    done_count=done_count,
                    resume=resume,
                )

            await self.db.update_engagement_status(engagement_id, "completed")
            self._record_stage_event(engagement_id, WorkflowStage("done", "workflow complete"), "completed", 1.0)
            progress("done", "Workflow complete", 1.0)

        except asyncio.CancelledError:
            logger.warning("engagement %s cancelled at %s", engagement_id, self._current_phase)
            await self.db.update_engagement_status(engagement_id, "interrupted")
            if self._current_phase:
                self._record_stage_event(
                    engagement_id,
                    WorkflowStage(self._current_phase, WORKFLOW_LABELS.get(self._current_phase, self._current_phase)),
                    "cancelled",
                    0.0,
                )
            raise
        except CostLimitError:
            raise
        except Exception as e:
            logger.error("engagement %s failed during %s: %s", engagement_id, self._current_phase, e)
            await self.db.update_engagement_status(engagement_id, "failed")
            raise
        finally:
            logger.info("LLM cost summary: %s", cost_tracker.summary())
            reset_current_tracker(token_cost)
            self._running = False
            self._current_phase = None
            current_engagement_id.reset(token_eid)
            current_findings_db.reset(token_db)
            if self.llm and hasattr(self.llm, "close"):
                await self.llm.close()

    async def _run_stage(
        self,
        *,
        engagement: dict[str, Any],
        stage: WorkflowStage,
        progress: ProgressCallback,
        engagement_id: str,
        idx: int,
        total: int,
        done_count: int,
        resume: bool,
    ) -> None:
        pct = (done_count + idx) / total if resume else idx / total
        self._current_phase = stage.name
        await self.db.update_engagement_phase(engagement_id, stage.name)
        self._record_stage_event(engagement_id, stage, "started", pct)
        progress(stage.name, f"Running {WORKFLOW_LABELS.get(stage.name, stage.name)}", pct)

        if self._rate_limiter and self._rate_limiter.profile.delay_between_phases > 0 and idx > 0:
            await asyncio.sleep(self._rate_limiter.profile.delay_between_phases)

        try:
            await self._dispatch_stage(stage, engagement)
        except asyncio.CancelledError:
            logger.warning("engagement %s cancelled during %s", engagement_id, stage.name)
            await self.db.update_engagement_status(engagement_id, "interrupted")
            self._record_stage_event(engagement_id, stage, "cancelled", pct)
            progress(stage.name, "cancelled by signal", pct)
            raise
        except CostLimitError as cost_err:
            logger.warning("engagement %s aborted at %s by price limit: %s", engagement_id, stage.name, cost_err)
            await self.db.update_engagement_status(engagement_id, "aborted_cost_limit")
            self._record_stage_event(engagement_id, stage, "aborted_cost_limit", pct, details=str(cost_err))
            progress(stage.name, f"aborted: {cost_err}", pct)
            raise
        except Exception as phase_err:
            logger.error("phase %s failed: %s", stage.name, phase_err)
            self._phase_errors[stage.name] = str(phase_err)
            self._record_stage_event(engagement_id, stage, "failed", pct, details=str(phase_err))
            progress(stage.name, f"{WORKFLOW_LABELS.get(stage.name, stage.name)} failed, continuing", pct)
            return

        await self.db.update_engagement_phase(engagement_id, stage.name, completed=True)
        self._record_stage_event(engagement_id, stage, "completed", (done_count + idx + 1) / total)
        progress(stage.name, f"{WORKFLOW_LABELS.get(stage.name, stage.name)} complete", (done_count + idx + 1) / total)

    async def _dispatch_stage(self, stage: WorkflowStage, engagement: dict[str, Any]) -> None:
        if stage.runner is None:
            raise RuntimeError(f"workflow stage {stage.name!r} has no runner")
        await stage.runner(engagement)

    def _build_executable_stages(self, engagement: dict[str, Any]) -> list[WorkflowStage]:
        assert self._workflow_plan is not None
        stage_map = {
            "recon": WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping", runner=self._run_recon),
            "web": WorkflowStage("web", "web assessment", description="Web application assessment", runner=self._run_web_assessment),
            "ad": WorkflowStage("ad", "directory assessment", description="Directory and identity assessment", runner=self._run_ad_assessment),
            "cloud": WorkflowStage("cloud", "cloud assessment", description="Cloud configuration assessment", runner=self._run_cloud_assessment),
            "mobile": WorkflowStage("mobile", "mobile assessment", description="Mobile application assessment", runner=self._run_mobile_assessment),
            "chaining": WorkflowStage("chaining", "attack chain discovery", description="Multi-step attack path construction", runner=self._run_exploit_chaining),
            "validation": WorkflowStage("validation", "PoC validation", description="Proof-of-concept validation", runner=self._run_poc_validation),
            "detection": WorkflowStage("detection", "detection generation", description="Detection content generation", runner=self._run_detection_generation),
            "report": WorkflowStage("report", "report generation", description="Report assembly", runner=self._generate_report),
        }
        return [
            WorkflowStage(
                name=stage.name,
                title=stage.title,
                automated=stage.automated,
                depends_on=stage.depends_on,
                description=stage.description,
                enabled_if=stage.enabled_if,
                runner=stage_map[stage.name].runner,
            )
            for stage in self._workflow_plan.enabled_stages(engagement)
            if stage.name in stage_map
        ]

    def _record_stage_event(
        self,
        engagement_id: str,
        stage: WorkflowStage,
        status: str,
        progress: float,
        details: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        record = {
            "engagement_id": engagement_id,
            "stage": stage.name,
            "title": stage.title,
            "status": status,
            "progress": round(progress, 4),
            "details": details,
            "description": stage.description,
            "automated": stage.automated,
            "depends_on": list(stage.depends_on),
            "started_at": now if status == "started" else None,
            "completed_at": now if status in {"completed", "failed", "cancelled", "aborted_cost_limit"} else None,
            "duration_ms": None,
            "recorded_at": now,
        }
        self._stage_records.append(record)
        try:
            self.db.add_stage_record(record)
        except AttributeError:
            logger.debug("stage record persistence unavailable")

    @property
    def stage_records(self) -> list[dict[str, Any]]:
        return list(self._stage_records)

    @property
    def workflow_plan(self) -> WorkflowPlan | None:
        return self._workflow_plan

    @property
    def phase_errors(self) -> dict[str, str]:
        return dict(self._phase_errors)

    def _get_registry(self):
        from tools.registry import ToolRegistry
        return ToolRegistry()

    async def _run_recon(self, engagement: dict[str, Any]) -> None:
        from agents.recon.recon_agent import ReconAgent

        registry = self._get_registry()
        agent = ReconAgent(registry, self.db, llm=self.llm, scope=self.scope)
        agent.set_rate_limiter(self._rate_limiter)
        agent.set_auth(self._auth)
        result = await agent.run_recon(engagement["target"], engagement_id=engagement["id"])

        self._recon_context = {
            "findings_count": result.get("findings_count", 0),
            "summary": result.get("summary", ""),
            "target": engagement["target"],
        }
        findings = await self.db.get_findings(engagement_id=engagement["id"])
        open_ports = []
        services = []
        for f in findings:
            title = f.get("title", "").lower()
            if "open port" in title or "port" in f.get("category", "").lower():
                open_ports.append(f.get("title", ""))
            if "service" in title or "technology" in title:
                services.append(f.get("title", ""))
        self._recon_context["open_ports"] = open_ports
        self._recon_context["services"] = services

        logger.info("recon complete: %s findings", result.get('findings_count', 0))

    def _configure_agent(self, agent: Any) -> None:
        if hasattr(agent, "set_rate_limiter") and self._rate_limiter:
            agent.set_rate_limiter(self._rate_limiter)
        if hasattr(agent, "set_auth") and self._auth.is_set:
            agent.set_auth(self._auth)

    async def _run_web_assessment(self, engagement: dict[str, Any]) -> None:
        from agents.web.web_agent import WebAgent

        registry = self._get_registry()
        agent = WebAgent(registry, self.db, llm=self.llm, scope=self.scope)
        if self._recon_context:
            agent.set_context(self._recon_context)
        self._configure_agent(agent)
        result = await agent.run_assessment(engagement["target"], engagement_id=engagement["id"])
        logger.info("web assessment complete: %s findings", result.get('findings_count', 0))

    async def _run_ad_assessment(self, engagement: dict[str, Any]) -> None:
        from agents.ad.ad_agent import ADAgent

        registry = self._get_registry()
        agent = ADAgent(registry, self.db, llm=self.llm, scope=self.scope)
        if self._recon_context:
            agent.set_context(self._recon_context)
        self._configure_agent(agent)
        result = await agent.run_assessment(
            engagement["target"], engagement.get("domain", engagement["target"]), engagement_id=engagement["id"]
        )
        logger.info("ad assessment complete: %s findings", result.get('findings_count', 0))

    async def _run_cloud_assessment(self, engagement: dict[str, Any]) -> None:
        from agents.cloud.cloud_agent import CloudAgent

        registry = self._get_registry()
        agent = CloudAgent(registry, self.db, llm=self.llm, scope=self.scope)
        if self._recon_context:
            agent.set_context(self._recon_context)
        self._configure_agent(agent)
        result = await agent.run_assessment(
            engagement.get("cloud_provider", "aws"), engagement["target"], engagement_id=engagement["id"]
        )
        logger.info("cloud assessment complete: %s findings", result.get('findings_count', 0))

    async def _run_mobile_assessment(self, engagement: dict[str, Any]) -> None:
        from agents.mobile.mobile_agent import MobileAgent

        registry = self._get_registry()
        agent = MobileAgent(registry, self.db, llm=self.llm, scope=self.scope)
        self._configure_agent(agent)
        result = await agent.run_assessment(
            engagement["mobile_target"],
            platform=engagement.get("mobile_platform", "android"),
            engagement_id=engagement["id"],
        )
        logger.info("mobile assessment complete: %s findings", result.get('findings_count', 0))

    async def _run_exploit_chaining(self, engagement: dict[str, Any]) -> None:
        from agents.exploit_chain.chain_agent import ExploitChainAgent

        agent = ExploitChainAgent(self.db, llm=self.llm, scope=self.scope)
        chains = await agent.discover_chains(engagement["id"])
        logger.info("exploit chaining complete: %s chains discovered", len(chains))

    async def _run_poc_validation(self, engagement: dict[str, Any]) -> None:
        from agents.poc_validator.poc_agent import PoCAgent

        agent = PoCAgent(self.db, llm=self.llm, scope=self.scope)
        await agent.validate_all(engagement["id"])
        chain_results = await agent.validate_chains(engagement["id"])
        confirmed = sum(1 for r in chain_results if r["status"] == "confirmed")
        logger.info(
            "poc validation complete: %d/%d chains confirmed",
            confirmed,
            len(chain_results),
        )

    async def _run_detection_generation(self, engagement: dict[str, Any]) -> None:
        from agents.detection.detection_agent import DetectionAgent

        agent = DetectionAgent(self.db, llm=self.llm, scope=self.scope)
        rules = await agent.generate_rules(engagement["id"])
        logger.info("detection rules generated: %s rules", len(rules))

    async def _generate_report(self, engagement: dict[str, Any]) -> None:
        from agents.report.report_agent import ReportAgent

        agent = ReportAgent(self.db, llm=self.llm, scope=self.scope)
        report = await agent.generate_report(engagement["id"])
        logger.info("report generated: %s", report.get('output_path', 'unknown'))

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_phase(self) -> str | None:
        return self._current_phase

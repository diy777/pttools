"""Workflow planning helpers for pentest-tools.

This module centralizes the phase plan used by the orchestrator and CLI so the
project clearly exposes its work orchestration model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


WorkflowCondition = Callable[[dict[str, Any]], bool]
WorkflowRunner = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class WorkflowStage:
    name: str
    title: str
    automated: bool = True
    depends_on: tuple[str, ...] = ()
    description: str = ""
    enabled_if: WorkflowCondition | None = None
    runner: WorkflowRunner | None = None

    def is_enabled(self, engagement: dict[str, Any]) -> bool:
        return True if self.enabled_if is None else bool(self.enabled_if(engagement))


@dataclass(frozen=True)
class WorkflowPlan:
    scope: str
    intensity: str
    target: str
    stages: list[WorkflowStage] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def stage_names(self) -> list[str]:
        return [stage.name for stage in self.stages]

    def enabled_stages(self, engagement: dict[str, Any]) -> list[WorkflowStage]:
        return [stage for stage in self.stages if stage.is_enabled(engagement)]

    def summary(self) -> str:
        parts = [f"target={self.target}", f"scope={self.scope}", f"intensity={self.intensity}"]
        parts.append("stages=" + ",".join(self.stage_names()))
        return " | ".join(parts)


_SCOPE_STAGES: dict[str, list[WorkflowStage]] = {
    "recon": [WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping")],
    "web": [
        WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping"),
        WorkflowStage("web", "web assessment", depends_on=("recon",), description="Web application assessment"),
    ],
    "ad": [
        WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping"),
        WorkflowStage("ad", "directory assessment", depends_on=("recon",), description="Directory and identity assessment"),
    ],
    "cloud": [
        WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping"),
        WorkflowStage("cloud", "cloud assessment", depends_on=("recon",), description="Cloud configuration assessment"),
    ],
    "mobile": [
        WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping"),
        WorkflowStage(
            "mobile",
            "mobile assessment",
            depends_on=("recon",),
            description="Mobile application assessment",
            enabled_if=lambda engagement: bool(engagement.get("mobile_target")),
        ),
    ],
    "full": [
        WorkflowStage("recon", "reconnaissance", description="Asset discovery and baseline mapping"),
        WorkflowStage("web", "web assessment", depends_on=("recon",), description="Web application assessment"),
        WorkflowStage("ad", "directory assessment", depends_on=("recon",), description="Directory and identity assessment"),
        WorkflowStage("cloud", "cloud assessment", depends_on=("recon",), description="Cloud configuration assessment"),
        WorkflowStage(
            "mobile",
            "mobile assessment",
            depends_on=("recon",),
            description="Mobile application assessment",
            enabled_if=lambda engagement: bool(engagement.get("mobile_target")),
        ),
    ],
}


def build_workflow_plan(scope: str, target: str, intensity: str, *, mobile_target: bool = False) -> WorkflowPlan:
    scope_l = (scope or "full").lower()
    base_stages = list(_SCOPE_STAGES.get(scope_l, _SCOPE_STAGES["full"]))

    if scope_l != "recon":
        base_stages.extend(
            [
                WorkflowStage("chaining", "attack chain discovery", depends_on=("recon",), description="Multi-step attack path construction"),
                WorkflowStage("validation", "PoC validation", depends_on=("chaining",), description="Proof-of-concept validation"),
                WorkflowStage("detection", "detection generation", depends_on=("validation",), description="Detection content generation"),
                WorkflowStage("report", "report generation", depends_on=("detection",), description="Report assembly"),
            ]
        )

    if scope_l == "mobile" and not mobile_target:
        base_stages = [stage for stage in base_stages if stage.name != "mobile"]

    return WorkflowPlan(scope=scope_l, intensity=intensity, target=target, stages=base_stages)

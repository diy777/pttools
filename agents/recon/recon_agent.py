"""Recon Agent — LLM-driven network reconnaissance and OSINT orchestration.

When an LLM is configured, the agent reasons about which tools to run,
interprets results, and adapts its approach based on findings.
Falls back to deterministic tool loops when no LLM is available.
"""

import asyncio
import logging
import os
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.recon")


def _env_int(name: str, default: int) -> int:
    """Read PENTEST_TOOLS_MAX_FINDINGS_<name> override, fall back to default."""
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


class ReconAgent(BaseAgent):
    agent_type = "recon"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_recon(self, target: str, depth: str = "standard", engagement_id: str = "") -> dict[str, Any]:
        logger.info(f"Starting recon against {target} (depth: {depth})")

        if self.llm:
            prompt = (
                f"Run {depth} reconnaissance against {target}.\n\n"
                f"Available depth levels:\n"
                f"- passive: subdomain enum, OSINT only (no direct contact with target)\n"
                f"- standard: passive + port scanning + web tech detection\n"
                f"- deep: standard + vulnerability scanning + content discovery\n\n"
                f"Start by running built-in scanners (always available), then use external tools if installed.\n"
                f"Analyze each result before deciding what to run next."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic recon")

        return await self._run_deterministic_recon(target, depth, engagement_id)

    async def _run_deterministic_recon(self, target: str, depth: str, engagement_id: str) -> dict[str, Any]:
        tasks: list[Any] = []

        if depth in ("passive", "standard", "deep"):
            tasks.extend([self._run_subdomain_enum(target, engagement_id), self._run_osint(target)])

        if depth in ("standard", "deep"):
            tasks.extend([self._run_port_scan(target, engagement_id), self._run_web_tech_detect(target)])

        if depth == "deep":
            tasks.extend([self._run_vuln_scan(target, engagement_id), self._run_content_discovery(target, engagement_id)])

        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_findings = sum(r.get("findings_count", 0) for r in results if isinstance(r, dict))

        return {
            "target": target,
            "depth": depth,
            "findings_count": total_findings,
            "status": "complete",
            "phases_completed": len([r for r in results if isinstance(r, dict)]),
        }

    # Per-phase finding caps. Some recon tools (subfinder against popular domains
    # like example.com) return tens of thousands of findings via cert transparency
    # logs. Without a cap the DB explodes and the report becomes unreadable.
    # Each cap is overridable via PENTEST_TOOLS_MAX_FINDINGS_<PHASE> env var.
    PHASE_FINDING_CAPS = {
        "subdomain_enum": _env_int("PENTEST_TOOLS_MAX_FINDINGS_SUBDOMAIN_ENUM", 200),
        "osint": _env_int("PENTEST_TOOLS_MAX_FINDINGS_OSINT", 200),
        "port_scan": _env_int("PENTEST_TOOLS_MAX_FINDINGS_PORT_SCAN", 500),
        "web_tech": _env_int("PENTEST_TOOLS_MAX_FINDINGS_WEB_TECH", 100),
        "vuln_scan": _env_int("PENTEST_TOOLS_MAX_FINDINGS_VULN_SCAN", 1000),
        "content_discovery": _env_int("PENTEST_TOOLS_MAX_FINDINGS_CONTENT_DISCOVERY", 500),
    }

    _DETERMINISTIC_TOOL_TIMEOUT = 60.0

    async def _run_tool_phase(self, tool_names: list[str], target: str, engagement_id: str, phase: str) -> dict[str, Any]:
        """Run all installed tools in this phase in parallel, then enforce the cap.

        Cap is applied after collection rather than mid-stream, so we can run
        tools concurrently; some over-collection is acceptable since tools take
        a full pass anyway.
        """
        cap = self.PHASE_FINDING_CAPS.get(phase, 1000)
        cap_hit = False

        installed = []
        for name in tool_names:
            tool = self.registry.get_tool(name) if self.registry else None
            if tool and tool.is_installed():
                installed.append((name, tool))

        async def _run_one(name: str, tool: Any) -> list[dict[str, Any]]:
            try:
                result = await asyncio.wait_for(tool.execute(target), timeout=self._DETERMINISTIC_TOOL_TIMEOUT)
                return result.get("findings", []) or []
            except asyncio.TimeoutError:
                logger.warning(f"{name} timed out after {self._DETERMINISTIC_TOOL_TIMEOUT}s in phase {phase}")
                return []
            except Exception as e:
                logger.warning(f"{name} failed in phase {phase}: {e}")
                return []

        all_findings_lists = await asyncio.gather(*[_run_one(n, t) for n, t in installed]) if installed else []
        # Flatten, then enforce the cap.
        all_findings: list[dict[str, Any]] = []
        for findings in all_findings_lists:
            all_findings.extend(findings)
        if len(all_findings) > cap:
            cap_hit = True
        to_store = all_findings[:cap]
        for f in to_store:
            f["engagement_id"] = engagement_id
            await self.db.add_finding(f)
        findings_count = len(to_store)
        if cap_hit and engagement_id:
            await self.db.add_finding({
                "id": f"{phase}-cap-{engagement_id[:8]}",
                "engagement_id": engagement_id,
                "title": f"{phase}: result cap reached ({cap})",
                "description": (
                    f"The {phase} phase produced more than {cap} findings against {target}. "
                    "Findings beyond the cap were dropped to keep the engagement bounded. "
                    "Re-run with a narrower target if you need full enumeration."
                ),
                "severity": "info",
                "category": "recon",
                "tool_source": phase,
                "target": target,
                "evidence": "",
                "remediation": "",
            })
        return {"tool": phase, "findings_count": findings_count, "cap_hit": cap_hit}

    async def _run_subdomain_enum(self, target: str, eid: str) -> dict[str, Any]:
        return await self._run_tool_phase(["amass", "subfinder", "assetfinder", "knockpy"], target, eid, "subdomain_enum")

    async def _run_osint(self, target: str) -> dict[str, Any]:
        return await self._run_tool_phase(["theharvester", "sherlock"], target, "", "osint")

    async def _run_port_scan(self, target: str, eid: str) -> dict[str, Any]:
        return await self._run_tool_phase(["nmap", "rustscan", "naabu"], target, eid, "port_scan")

    async def _run_web_tech_detect(self, target: str) -> dict[str, Any]:
        return await self._run_tool_phase(["whatweb", "httpx", "httprobe"], target, "", "web_tech")

    async def _run_vuln_scan(self, target: str, eid: str) -> dict[str, Any]:
        return await self._run_tool_phase(["nuclei", "nikto"], target, eid, "vuln_scan")

    async def _run_content_discovery(self, target: str, eid: str) -> dict[str, Any]:
        return await self._run_tool_phase(["gobuster", "feroxbuster", "dirsearch"], target, eid, "content_discovery")

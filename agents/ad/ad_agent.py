"""AD Agent — LLM-driven Active Directory security assessment."""

import asyncio
import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.ad")

_DETERMINISTIC_TOOL_TIMEOUT = 30.0


class ADAgent(BaseAgent):
    agent_type = "ad"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(self, target: str, domain: str, engagement_id: str = "") -> dict[str, Any]:
        logger.info(f"Starting AD assessment against {target} (domain: {domain})")

        if self.llm:
            prompt = (
                f"Run an Active Directory security assessment against {target} in domain {domain}.\n\n"
                f"Methodology:\n"
                f"1. Domain enumeration: users, groups, GPOs, trusts, SPNs\n"
                f"2. SMB enumeration: shares, null sessions, signing\n"
                f"3. Kerberoasting: find SPNs, request tickets\n"
                f"4. AS-REP roasting: find users without preauth\n"
                f"5. ACL analysis: look for write permissions leading to escalation\n"
                f"6. Password spraying (if approved): common/seasonal passwords\n\n"
                f"Start with enumeration. Only attempt active attacks after understanding the environment."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic AD assessment")

        return await self._run_deterministic_ad(target, domain, engagement_id)

    async def _run_deterministic_ad(self, target: str, domain: str, engagement_id: str) -> dict[str, Any]:
        phases = [
            (["enum4linux", "ldapsearch", "rpcclient"], "enumeration"),
            (["smbclient", "nbtscan"], "smb_enum"),
            (["netexec"], "kerberoasting"),
            (["kerbrute"], "asrep_roast"),
        ]

        async def _run_tool(name: str, phase: str) -> list[dict[str, Any]]:
            tool = self.registry.get_tool(name) if self.registry else None
            if not (tool and tool.is_installed()):
                return []
            try:
                result = await asyncio.wait_for(tool.execute(target), timeout=_DETERMINISTIC_TOOL_TIMEOUT)
                return result.get("findings", []) or []
            except asyncio.TimeoutError:
                logger.warning(f"{name} timed out in {phase}")
                return []
            except Exception as e:
                logger.warning(f"{name} failed in {phase}: {e}")
                return []

        coros = [_run_tool(n, phase) for tool_names, phase in phases for n in tool_names]
        all_findings_lists = await asyncio.gather(*coros) if coros else []
        findings_count = 0
        for findings in all_findings_lists:
            findings_count += len(findings)
            for f in findings:
                f["engagement_id"] = engagement_id
                await self.db.add_finding(f)
        return {"target": target, "domain": domain, "findings_count": findings_count, "status": "complete"}

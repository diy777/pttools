"""Vulnerability Scanner Agent, Nuclei + custom CVE detection with deduplication."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.vuln_scanner")


class VulnScannerAgent(BaseAgent):
    agent_type = "vuln_scanner"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        templates: str = "cves,vulnerabilities,misconfiguration,exposures",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting vulnerability scanning of {target}")

        if self.llm:
            prompt = (
                f"Run vulnerability scanning against {target}.\n"
                f"Template categories: {templates}\n\n"
                f"Methodology:\n"
                f"1. Service enumeration: identify what to scan (HTTP, SMB, SSH, etc.)\n"
                f"2. Nuclei: run targeted templates by service. Skip noisy DOS or fuzz templates.\n"
                f"3. Network CVEs: RouterSploit for embedded devices and routers\n"
                f"4. Web CVEs: nikto and dirb for known-vulnerable paths\n"
                f"5. CVE matching: cross-reference service banners against current CVE feed\n"
                f"6. Deduplication: skip findings already reported by recon agent\n"
                f"7. False-positive filtering: re-validate findings before storing as confirmed\n"
                f"8. Severity scoring: CVSS v3.1 plus EPSS exploit probability when available\n\n"
                f"Tools: nuclei, routersploit, nikto, dirb, searchsploit, vulners\n\n"
                f"Focus on exploitable findings with proven impact. Skip informational-only findings unless asked."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic vuln scan")

        return await self._run_deterministic_vuln(target, engagement_id)

    async def _run_deterministic_vuln(self, target: str, engagement_id: str) -> dict[str, Any]:
        """Run nuclei + nikto without LLM reasoning."""
        findings_count = 0
        for tool_name in ("nuclei", "nikto"):
            tool = self.registry.get_tool(tool_name) if self.registry else None
            if tool and tool.is_installed():
                try:
                    result = await tool.execute(target)
                    for f in result.get("findings", []):
                        f["engagement_id"] = engagement_id
                        await self.db.add_finding(f)
                    findings_count += len(result.get("findings", []))
                except Exception as e:
                    logger.warning(f"{tool_name} failed: {e}")
        return {
            "agent": self.agent_type,
            "target": target,
            "findings_count": findings_count,
            "status": "complete",
        }

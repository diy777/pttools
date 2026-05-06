"""Social Engineer Agent — LLM-driven phishing and social engineering assessment."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.social_engineer")


class SocialEngineerAgent(BaseAgent):
    agent_type = "social_engineer"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        campaign_type: str = "phishing",
        targets_list: list[str] | None = None,
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting {campaign_type} assessment against {target}")

        if self.llm:
            targets_str = ", ".join(targets_list) if targets_list else "to be enumerated via OSINT"
            prompt = (
                f"Run a social engineering assessment against {target}.\n"
                f"Campaign type: {campaign_type}\n"
                f"Target list: {targets_str}\n\n"
                f"Methodology:\n"
                f"1. OSINT preparation: gather emails, names, org structure, social media\n"
                f"2. Email security analysis: check SPF, DKIM, DMARC records for spoofing risk\n"
                f"3. Pretext development: craft realistic scenario based on OSINT\n"
                f"4. Campaign execution: send payloads via approved channel\n"
                f"5. Credential capture: track clicks, submissions, credential harvesting\n\n"
                f"Tools: gophish, setoolkit, evilginx2, sherlock, theharvester\n\n"
                f"Rules:\n"
                f"- Only target approved scope\n"
                f"- No destructive payloads\n"
                f"- Track all interactions for reporting\n"
                f"- Stop if out-of-scope targets are discovered"
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic social assessment")

        return await self._run_deterministic_social(target, campaign_type, targets_list, engagement_id)

    async def _run_deterministic_social(
        self, target: str, campaign_type: str, targets_list: list[str] | None, engagement_id: str
    ) -> dict[str, Any]:
        findings_count = 0

        osint_tools = ["sherlock", "theharvester", "social-analyzer"]
        for tool_name in osint_tools:
            tool = self.registry.get_tool(tool_name) if self.registry else None
            if tool and tool.is_installed():
                result = await tool.execute(target)
                for f in result.get("findings", []):
                    f["engagement_id"] = engagement_id
                    await self.db.add_finding(f)
                findings_count += len(result.get("findings", []))

        if campaign_type == "phishing":
            for tool_name in ["gophish", "setoolkit", "evilginx2"]:
                tool = self.registry.get_tool(tool_name) if self.registry else None
                if tool and tool.is_installed():
                    result = await tool.execute(target)
                    for f in result.get("findings", []):
                        f["engagement_id"] = engagement_id
                        await self.db.add_finding(f)
                    findings_count += len(result.get("findings", []))

            for tool_name in ["spoofcheck", "dmarc-report"]:
                tool = self.registry.get_tool(tool_name) if self.registry else None
                if tool and tool.is_installed():
                    result = await tool.execute(target)
                    for f in result.get("findings", []):
                        f["engagement_id"] = engagement_id
                        await self.db.add_finding(f)
                    findings_count += len(result.get("findings", []))

        return {
            "target": target,
            "campaign_type": campaign_type,
            "findings_count": findings_count,
            "status": "complete",
        }

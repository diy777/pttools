"""Cloud Agent — LLM-driven AWS/Azure/GCP security assessment."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.cloud")


class CloudAgent(BaseAgent):
    agent_type = "cloud"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(self, provider: str, target: str, engagement_id: str = "") -> dict[str, Any]:
        logger.info(f"Starting cloud assessment for {provider} ({target})")

        if self.llm:
            prompt = (
                f"Run a cloud security assessment for {provider} environment targeting {target}.\n\n"
                f"Methodology:\n"
                f"1. IAM review: overprivileged roles, unused credentials, cross-account access\n"
                f"2. Storage: public buckets/blobs, exposed databases\n"
                f"3. Network: security groups, exposed services, VPC config\n"
                f"4. Compute: metadata service (IMDSv1 vs v2), container escape paths\n"
                f"5. Secrets: hardcoded credentials, unrotated keys\n"
                f"6. Logging: CloudTrail/Azure Monitor gaps\n\n"
                f"Focus on IAM privilege escalation paths. Use prowler for AWS, scout-suite for multi-cloud."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic cloud assessment")

        return await self._run_deterministic_cloud(provider, target, engagement_id)

    async def _run_deterministic_cloud(self, provider: str, target: str, engagement_id: str) -> dict[str, Any]:
        findings_count = 0
        tools_by_provider = {
            "aws": ["prowler", "pacu", "cloudfox"],
            "azure": ["scoutsuite", "azurehound"],
            "gcp": ["scoutsuite"],
        }
        for tool_name in tools_by_provider.get(provider.lower(), ["scoutsuite"]):
            tool = self.registry.get_tool(tool_name)
            if tool and tool.is_installed():
                result = await tool.execute(target)
                count = len(result.get("findings", []))
                findings_count += count
                for f in result.get("findings", []):
                    f["engagement_id"] = engagement_id
                    await self.db.add_finding(f)
        return {"provider": provider, "target": target, "findings_count": findings_count, "status": "complete"}

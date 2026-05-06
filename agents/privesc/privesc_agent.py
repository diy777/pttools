"""Privesc Advisor Agent, local enumeration and privilege escalation on compromised hosts."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.privesc")


class PrivescAdvisorAgent(BaseAgent):
    agent_type = "privesc"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        platform: str = "linux",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting privilege escalation enumeration on {platform} target {target}")

        if self.llm:
            prompt = (
                f"Run privilege escalation enumeration on {target}.\n"
                f"Platform: {platform}\n\n"
                f"Linux methodology:\n"
                f"1. System info: kernel version, distro, sudo version, world-writable files\n"
                f"2. SUID/SGID: enumerate, check GTFOBins for known privesc binaries\n"
                f"3. Sudo: NOPASSWD entries, env_keep, command wildcards\n"
                f"4. Cron: writable cron scripts, PATH abuse, root-owned tasks\n"
                f"5. Capabilities: getcap exploitation paths\n"
                f"6. Services: writable service files, weak service permissions\n"
                f"7. Kernel exploits: match version against linux-exploit-suggester\n\n"
                f"Windows methodology:\n"
                f"1. System info: OS, missing patches, WSUS, AlwaysInstallElevated\n"
                f"2. Services: unquoted paths, weak permissions, DLL hijacking\n"
                f"3. Tokens: SeImpersonate, SeAssignPrimaryToken (Potato family)\n"
                f"4. Stored creds: registry, Group Policy Preferences, Credential Manager\n"
                f"5. UAC bypass: known auto-elevate binaries, fodhelper, eventvwr\n\n"
                f"Container and cloud:\n"
                f"1. Container escape: privileged containers, mounted docker sock, capabilities\n"
                f"2. Cloud IAM abuse: instance metadata, attached roles, AssumeRole chains\n\n"
                f"Tools: linpeas, winpeas, linux-exploit-suggester, pspy, deepce, kubehound\n\n"
                f"Always enumerate first. Do not run exploits before confirming the path is reliable."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic privesc enum")

        return await self._run_deterministic_privesc(target, platform, engagement_id)

    async def _run_deterministic_privesc(self, target: str, platform: str, engagement_id: str) -> dict[str, Any]:
        """Enumerate privesc paths via local enum tools without LLM reasoning."""
        findings_count = 0
        tools_by_platform = {
            "linux": ["linpeas", "linux-exploit-suggester", "pspy"],
            "windows": ["winpeas"],
            "container": ["deepce"],
        }
        names = tools_by_platform.get(platform, [])
        for tool_name in names:
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
            "platform": platform,
            "findings_count": findings_count,
            "status": "complete",
        }

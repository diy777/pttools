"""Mobile Agent — LLM-driven Android/iOS application security testing."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.mobile")


class MobileAgent(BaseAgent):
    agent_type = "mobile"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        platform: str = "android",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting {platform} assessment for {target}")

        if self.llm:
            prompt = (
                f"Run a mobile application security assessment for {platform} target: {target}.\n\n"
                f"Methodology (OWASP Mobile Top 10):\n"
                f"1. Static analysis: decompile APK/IPA, review manifest, check for hardcoded secrets\n"
                f"2. Dynamic analysis: runtime hooking with Frida, method tracing, bypass checks\n"
                f"3. Network analysis: intercept traffic, check certificate pinning, API security\n"
                f"4. Storage analysis: check local databases, shared preferences, keychain\n"
                f"5. Authentication: test biometric bypass, token handling, session management\n"
                f"6. Binary protections: check for obfuscation, anti-tampering, root/jailbreak detection\n\n"
                f"Platform-specific tools:\n"
                f"- Android: jadx, apktool, drozer, frida, objection\n"
                f"- iOS: class-dump, otool, frida, objection\n"
                f"- Both: burp/mitmproxy for network, nuclei for API scanning\n\n"
                f"Start with static analysis to understand the app before dynamic testing."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic mobile assessment")

        return await self._run_deterministic_mobile(target, platform, engagement_id)

    async def _run_deterministic_mobile(self, target: str, platform: str, engagement_id: str) -> dict[str, Any]:
        findings_count = 0

        static_tools = {
            "android": ["jadx", "apktool", "drozer"],
            "ios": ["class-dump", "otool", "binwalk"],
        }
        dynamic_tools = ["frida", "objection"]
        network_tools = ["burp", "mitmproxy", "nuclei"]

        for phase_tools in [static_tools.get(platform, []), dynamic_tools, network_tools]:
            for tool_name in phase_tools:
                tool = self.registry.get_tool(tool_name) if self.registry else None
                if tool and tool.is_installed():
                    result = await tool.execute(target)
                    for f in result.get("findings", []):
                        f["engagement_id"] = engagement_id
                        await self.db.add_finding(f)
                    findings_count += len(result.get("findings", []))

        return {
            "platform": platform,
            "target": target,
            "findings_count": findings_count,
            "status": "complete",
        }

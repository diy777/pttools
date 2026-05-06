"""Wireless Agent — LLM-driven WiFi/Bluetooth security testing."""

import asyncio
import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.wireless")

_DETERMINISTIC_TOOL_TIMEOUT = 30.0


class WirelessAgent(BaseAgent):
    agent_type = "wireless"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        interface: str = "wlan0",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting wireless assessment on {interface} targeting {target}")

        if self.llm:
            prompt = (
                f"Run a wireless security assessment targeting {target} on interface {interface}.\n\n"
                f"Methodology:\n"
                f"1. Reconnaissance: scan for access points, clients, hidden SSIDs\n"
                f"2. Protocol analysis: identify WPA/WPA2/WPA3, check for WPS\n"
                f"3. Attack execution: deauth, handshake capture, PMKID extraction\n"
                f"4. Credential recovery: offline crack captured handshakes\n"
                f"5. Rogue AP detection: identify unauthorized access points\n"
                f"6. Bluetooth scanning: discover BLE devices, check for pairing vulnerabilities\n\n"
                f"Tools: airodump-ng, aireplay-ng, wash, kismet, hashcat, john\n"
                f"Bluetooth: bluelog, blueranger, btscanner\n\n"
                f"Start with passive reconnaissance before any active attacks."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic wireless assessment")

        return await self._run_deterministic_wireless(target, interface, engagement_id)

    async def _run_deterministic_wireless(self, target: str, interface: str, engagement_id: str) -> dict[str, Any]:
        phases = [
            (["airodump-ng", "kismet", "wash"], interface),
            (["aireplay-ng", "hashcat", "john"], target),
            (["bluelog", "blueranger", "btscanner"], "scan"),
        ]

        async def _run_tool(name: str, exec_target: str) -> list[dict[str, Any]]:
            tool = self.registry.get_tool(name) if self.registry else None
            if not (tool and tool.is_installed()):
                return []
            try:
                result = await asyncio.wait_for(tool.execute(exec_target), timeout=_DETERMINISTIC_TOOL_TIMEOUT)
                return result.get("findings", []) or []
            except asyncio.TimeoutError:
                logger.warning(f"{name} timed out")
                return []
            except Exception as e:
                logger.warning(f"{name} failed: {e}")
                return []

        coros = [_run_tool(n, exec_target) for tool_names, exec_target in phases for n in tool_names]
        all_findings_lists = await asyncio.gather(*coros) if coros else []
        findings_count = 0
        for findings in all_findings_lists:
            findings_count += len(findings)
            for f in findings:
                f["engagement_id"] = engagement_id
                await self.db.add_finding(f)

        return {
            "target": target,
            "interface": interface,
            "findings_count": findings_count,
            "status": "complete",
        }

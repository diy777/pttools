"""Credential Tester Agent, password attacks and authentication testing."""

import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.credential_tester")


class CredentialTesterAgent(BaseAgent):
    agent_type = "credential_tester"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        userlist: str = "",
        wordlist: str = "",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting credential testing against {target}")

        if self.llm:
            prompt = (
                f"Run credential testing against {target}.\n"
                f"User list: {userlist or 'auto-build from OSINT and target enumeration'}\n"
                f"Wordlist: {wordlist or 'targeted wordlist via cupp or CeWL based on target context'}\n\n"
                f"Methodology:\n"
                f"1. Default credentials: test common defaults for detected services\n"
                f"2. Username enumeration: timing attacks, error message analysis\n"
                f"3. Password spray: 1 to 3 common passwords across all users (lockout-safe)\n"
                f"4. Targeted brute force: per-account brute force on confirmed users only\n"
                f"5. Hash crack: offline cracking of captured hashes (NTLM, bcrypt, MD5, etc.)\n"
                f"6. MFA bypass: SMS interception, TOTP brute-force, backup code abuse, push fatigue\n"
                f"7. Token analysis: predictable session IDs, JWT secret crack, cookie entropy\n\n"
                f"Tools: hydra, medusa, ncrack, hashcat, john, kerbrute, cupp, CeWL, hashid, haiti\n\n"
                f"Always respect lockout policies. Prefer spraying over brute force on production targets."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic credential testing")

        return await self._run_deterministic_credentials(target, engagement_id)

    async def _run_deterministic_credentials(self, target: str, engagement_id: str) -> dict[str, Any]:
        """Run safe, lockout-aware credential checks without LLM reasoning.

        Limited to non-destructive default-credential probes via tools that
        are installed locally. Avoids brute force entirely without LLM
        reasoning to gauge target risk tolerance.
        """
        findings_count = 0
        for tool_name in ("hashid", "haiti", "cupp"):
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
            "note": "Deterministic mode: skipped active brute-force; ran wordlist/hash analysis only.",
        }

"""API Security Agent, REST and GraphQL security testing."""

import asyncio
import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.api_security")

_DETERMINISTIC_TOOL_TIMEOUT = 30.0


class APISecurityAgent(BaseAgent):
    agent_type = "api_security"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        spec_url: str = "",
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting API security assessment of {target}")

        if self.llm:
            prompt = (
                f"Run an API security assessment against {target}.\n"
                f"Spec URL: {spec_url or 'auto-discover (OpenAPI, Swagger, GraphQL introspection)'}\n\n"
                f"Methodology (OWASP API Security Top 10):\n"
                f"1. Endpoint discovery: parse OpenAPI/Swagger, GraphQL introspection, fuzz common paths\n"
                f"2. Broken object-level auth (BOLA/IDOR): swap resource IDs across users\n"
                f"3. Broken authentication: missing auth, JWT alg-confusion (none/HS256/RS256), token reuse\n"
                f"4. Broken function-level auth (BFLA): test admin endpoints with low-priv tokens\n"
                f"5. OAuth/OIDC: callback URL validation, state parameter, PKCE, token leakage\n"
                f"6. Rate limiting: probe per-endpoint and global rate limits, header bypass tricks\n"
                f"7. Mass assignment: send unexpected fields and check if persisted\n"
                f"8. Excessive data exposure: response payload analysis for over-exposed fields\n"
                f"9. GraphQL specific: introspection enabled, batching attacks, depth/complexity limits\n\n"
                f"Tools: ffuf, hakrawler, kiterunner, jwt_tool, graphw00f, postman, curl\n\n"
                f"Start with discovery, then unauthenticated probes, then authenticated probes."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic API security scan")

        return await self._run_deterministic_api(target, engagement_id)

    async def _run_deterministic_api(self, target: str, engagement_id: str) -> dict[str, Any]:
        """Run a tool-driven API security pass without LLM reasoning, in parallel."""
        phases: list[tuple[list[str], str]] = [
            (["ffuf", "kiterunner", "hakrawler"], "endpoint_discovery"),
            (["jwt_tool", "graphw00f"], "auth_probes"),
            (["nuclei"], "api_misconfig_scan"),
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
        return {
            "agent": self.agent_type,
            "target": target,
            "findings_count": findings_count,
            "status": "complete",
        }

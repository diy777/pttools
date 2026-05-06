"""Base agent class providing LLM-driven decision making for all specialist agents."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from engine.auth_handler import AuthCredentials, build_auth_args
from engine.dedup import FindingDeduplicator
from engine.llm.client import LLMClient, LLMMessage, LLMResponse, ToolCall, ToolDefinition
from engine.llm.prompts import AGENT_PROMPTS
from engine.llm.tool_schemas import agent_decision_tools, builtin_scanner_tools, security_tool_to_llm_tool
from engine.rate_limiter import RateLimiter

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

logger = logging.getLogger("pentest-tools.agent")


class LLMUnavailableError(RuntimeError):
    """Raised when the configured LLM provider is unreachable on the first call.

    Lets agent entry points catch the failure and fall back to deterministic
    methods instead of returning silent zero-finding results.
    """

MAX_TOOL_LOOP_ITERATIONS = 20
MAX_OUTPUT_CHARS = 8000
DEFAULT_TOOL_TIMEOUT = 120


class BaseAgent:
    agent_type: str = "base"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        self.registry = registry
        self.db = db
        self.llm = llm
        self.scope = scope
        self._conversation: list[LLMMessage] = []
        self._findings_count = 0
        self._recon_context: dict[str, Any] = {}
        self._dedup = FindingDeduplicator()
        self._rate_limiter: RateLimiter | None = None
        self._auth: AuthCredentials = AuthCredentials()

    def set_context(self, context: dict[str, Any]) -> None:
        self._recon_context = context

    def set_rate_limiter(self, limiter: RateLimiter | None) -> None:
        self._rate_limiter = limiter

    def set_auth(self, creds: AuthCredentials) -> None:
        self._auth = creds

    def _get_system_prompt(self) -> str:
        return AGENT_PROMPTS.get(self.agent_type, AGENT_PROMPTS["recon"])

    def _get_available_tools(self) -> list[ToolDefinition]:
        tools = agent_decision_tools()
        tools.extend(builtin_scanner_tools())

        if self.registry:
            for tool in self.registry.list_tools():
                if tool.is_installed():
                    tools.append(
                        security_tool_to_llm_tool(
                            name=tool.name,
                            category=tool.category,
                            description=tool.description,
                            installed=True,
                        )
                    )
        return tools

    async def think(self, context: str) -> LLMResponse:
        is_first_call = not self._conversation
        if is_first_call:
            system_prompt = self._get_system_prompt()
            if self._recon_context:
                ctx_parts = [f"Target: {self._recon_context.get('target', '')}"]
                if self._recon_context.get("open_ports"):
                    ctx_parts.append(f"Open ports: {', '.join(self._recon_context['open_ports'][:20])}")
                if self._recon_context.get("services"):
                    ctx_parts.append(f"Services: {', '.join(self._recon_context['services'][:20])}")
                if self._recon_context.get("summary"):
                    ctx_parts.append(f"Recon summary: {self._recon_context['summary'][:500]}")
                system_prompt += "\n\nPrevious reconnaissance found:\n" + "\n".join(ctx_parts)
            self._conversation.append(LLMMessage(role="system", content=system_prompt))

        self._conversation.append(LLMMessage(role="user", content=context))
        tools = self._get_available_tools()

        try:
            response = await self.llm.complete(messages=self._conversation, tools=tools)
        except Exception as e:
            logger.warning(f"LLM call failed: {e}")
            self._conversation.pop()
            if is_first_call:
                # First-call failure means provider is unreachable. Raise so the
                # caller (run_tool_loop) can fall through to deterministic mode.
                raise LLMUnavailableError(str(e)) from e
            # Mid-loop failure: keep going with what we have, don't abort the run.
            return LLMResponse(content=f"LLM unavailable ({e}), falling back to deterministic mode.", tool_calls=[])

        self._conversation.append(
            LLMMessage(role="assistant", content=response.content, tool_calls=response.tool_calls)
        )
        return response

    async def run_tool_loop(self, initial_prompt: str, engagement_id: str = "") -> dict[str, Any]:
        if not self.llm:
            return await self._run_deterministic(initial_prompt, engagement_id)

        # Note: think() raises LLMUnavailableError on first-call failure; we let
        # it propagate so agent entry points (run_recon, run_assessment, etc.)
        # can catch and dispatch to their own deterministic methods, which know
        # the structured args (target, depth, platform, etc.).
        response = await self.think(initial_prompt)
        iterations = 0

        while response.tool_calls and iterations < MAX_TOOL_LOOP_ITERATIONS:
            iterations += 1
            for tc in response.tool_calls:
                result = await self._execute_tool_call(tc, engagement_id)
                self._conversation.append(
                    LLMMessage(role="tool", content=_truncate(result), tool_call_id=tc.id)
                )

            response = await self.llm.complete(messages=self._conversation, tools=self._get_available_tools())
            self._conversation.append(
                LLMMessage(role="assistant", content=response.content, tool_calls=response.tool_calls)
            )

            if any(tc.name == "analyze_findings" and tc.arguments.get("next_action") == "complete" for tc in response.tool_calls):
                break

        return {
            "agent": self.agent_type,
            "findings_count": self._findings_count,
            "iterations": iterations,
            "status": "complete",
            "summary": response.content,
        }

    async def _execute_tool_call(self, tc: ToolCall, engagement_id: str) -> str:
        if tc.name == "analyze_findings":
            return f"Analysis recorded. Next action: {tc.arguments.get('next_action', 'continue')}"

        if tc.name == "store_finding":
            raw_severity = tc.arguments.get("severity", "info")
            severity = raw_severity if raw_severity in VALID_SEVERITIES else "info"
            finding = {
                "id": uuid.uuid4().hex[:8],
                "engagement_id": engagement_id,
                "title": tc.arguments.get("title", ""),
                "description": tc.arguments.get("description", ""),
                "severity": severity,
                "category": tc.arguments.get("category", "general"),
                "tool_source": self.agent_type,
                "target": tc.arguments.get("target", ""),
                "evidence": tc.arguments.get("evidence", ""),
                "remediation": tc.arguments.get("remediation", ""),
            }
            finding = self._dedup.enrich(finding)
            is_dup, existing_id = self._dedup.is_duplicate(finding)
            if is_dup:
                return f"Duplicate finding (matches {existing_id}), skipped: {finding['title']}"
            from engine.cvss import calculate_cvss
            finding["cvss_score"] = calculate_cvss(finding)
            from engine.compliance import map_finding_compliance
            finding["compliance_mapping"] = map_finding_compliance(finding)
            await self.db.add_finding(finding)
            self._findings_count += 1
            return f"Finding stored: {finding['title']} ({finding['severity']}, CVSS {finding['cvss_score']})"

        if tc.name.startswith("builtin_"):
            return await self._run_builtin_scanner(tc)

        if tc.name.startswith("run_"):
            return await self._run_security_tool(tc)

        return f"Unknown tool: {tc.name}"

    def _check_scope(self, target: str, tool_name: str) -> str | None:
        if not self.scope:
            return None
        allowed, reason = self.scope.check(target, tool_name)
        if not allowed:
            logger.warning(f"Scope blocked {tool_name} targeting {target}: {reason}")
            return f"Scope violation: {reason}"
        return None

    async def _run_builtin_scanner(self, tc: ToolCall) -> str:
        from engine.scanners import check_dns, check_ssl, scan_common_paths, scan_http_headers, scan_ports, scan_secrets_in_response

        target = tc.arguments.get("target", "")

        scope_error = self._check_scope(target, tc.name)
        if scope_error:
            return scope_error

        scanner_map = {
            "builtin_port_scan": scan_ports,
            "builtin_http_headers": scan_http_headers,
            "builtin_ssl_check": check_ssl,
            "builtin_path_scan": scan_common_paths,
            "builtin_dns_enum": check_dns,
            "builtin_secret_scan": scan_secrets_in_response,
        }
        scanner = scanner_map.get(tc.name)
        if not scanner:
            return f"Unknown built-in scanner: {tc.name}"

        timeout = self._get_timeout()
        try:
            if self._rate_limiter:
                async with self._rate_limiter:
                    results = await asyncio.wait_for(scanner(target), timeout=timeout)
            else:
                results = await asyncio.wait_for(scanner(target), timeout=timeout)
            return str(results)
        except asyncio.TimeoutError:
            logger.warning(f"Scanner {tc.name} timed out after {timeout}s")
            return f"Scanner {tc.name} timed out after {timeout}s"
        except Exception as e:
            logger.exception(f"Scanner error in {tc.name}")
            return f"Scanner error: {e}"

    def _get_timeout(self) -> int:
        if self._rate_limiter:
            return self._rate_limiter.profile.tool_timeout_seconds
        return DEFAULT_TOOL_TIMEOUT

    def _get_max_retries(self) -> int:
        if self._rate_limiter:
            return self._rate_limiter.profile.max_retries
        return 1

    async def _run_security_tool(self, tc: ToolCall) -> str:
        tool_name = tc.name.removeprefix("run_").replace("_", "-")
        tool = self.registry.get_tool(tool_name) if self.registry else None

        if not tool:
            tool_name_underscore = tc.name.removeprefix("run_")
            tool = self.registry.get_tool(tool_name_underscore) if self.registry else None

        if not tool:
            return f"Tool '{tool_name}' not found in registry"
        if not tool.is_installed():
            return f"Tool '{tool_name}' is not installed on this system"

        target = tc.arguments.get("target", "")

        scope_error = self._check_scope(target, tool_name)
        if scope_error:
            return scope_error

        extra_args = tc.arguments.get("extra_args", {})

        if self._auth.is_set:
            auth_args = build_auth_args(tool_name, self._auth)
            if auth_args:
                extra_args["_auth_args"] = auth_args

        timeout = self._get_timeout()
        max_retries = self._get_max_retries()

        for attempt in range(max_retries + 1):
            try:
                if self._rate_limiter:
                    async with self._rate_limiter:
                        result = await asyncio.wait_for(tool.execute(target, extra_args), timeout=timeout)
                else:
                    result = await asyncio.wait_for(tool.execute(target, extra_args), timeout=timeout)

                findings = result.get("findings", [])
                self._findings_count += len(findings)
                return str(result)
            except asyncio.TimeoutError:
                logger.warning(f"Tool '{tool_name}' timed out after {timeout}s (attempt {attempt + 1})")
                if attempt == max_retries:
                    return f"Tool '{tool_name}' timed out after {timeout}s"
            except Exception as e:
                logger.exception(f"Tool execution error in {tool_name} (attempt {attempt + 1})")
                if attempt == max_retries:
                    return f"Tool execution error: {e}"

        return f"Tool '{tool_name}' failed after {max_retries + 1} attempts"

    async def _run_deterministic(self, prompt: str, engagement_id: str) -> dict[str, Any]:
        return {
            "agent": self.agent_type, "findings_count": 0,
            "status": "complete",
            "summary": "No LLM configured. Run with --provider to enable AI-driven assessment.",
        }


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(text)} total chars)"

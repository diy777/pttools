"""Convert SecurityTool definitions into LLM function-calling schemas."""

from __future__ import annotations

from typing import Any

from engine.llm.client import ToolDefinition


def security_tool_to_llm_tool(name: str, category: str, description: str, installed: bool) -> ToolDefinition:
    return ToolDefinition(
        name=f"run_{name.replace('-', '_')}",
        description=f"[{'installed' if installed else 'not installed'}] {description}",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname, IP, or URL"},
                "extra_args": {"type": "object", "description": "Additional tool-specific arguments", "default": {}},
            },
            "required": ["target"],
        },
    )


def registry_to_llm_tools(registry: Any, categories: list[str] | None = None) -> list[ToolDefinition]:
    tools = []
    for tool in registry.list_tools(categories=categories):
        tools.append(
            security_tool_to_llm_tool(
                name=tool.name,
                category=tool.category,
                description=tool.description,
                installed=tool.is_installed(),
            )
        )
    return tools


def builtin_scanner_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="builtin_port_scan",
            description="Zero-dependency async TCP port scanner (25 common ports)",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
        ToolDefinition(
            name="builtin_http_headers",
            description="Check HTTP security headers (HSTS, CSP, X-Frame-Options, cookies)",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
        ToolDefinition(
            name="builtin_ssl_check",
            description="Check SSL/TLS certificate expiry, deprecated protocols, weak ciphers",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
        ToolDefinition(
            name="builtin_path_scan",
            description="Probe 40 sensitive paths (.env, .git, admin panels, backups)",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
        ToolDefinition(
            name="builtin_dns_enum",
            description="DNS A record resolution and subdomain brute-force (10 common prefixes)",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
        ToolDefinition(
            name="builtin_secret_scan",
            description="Scan HTTP responses for leaked AWS keys, tokens, JWTs, connection strings",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        ),
    ]


def agent_decision_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="analyze_findings",
            description="Analyze current findings and decide on next steps. Call this to reason about what you've found so far.",
            parameters={
                "type": "object",
                "properties": {
                    "analysis": {"type": "string", "description": "Your analysis of findings so far"},
                    "next_action": {"type": "string", "enum": ["continue_scanning", "pivot_target", "escalate", "complete"]},
                    "reasoning": {"type": "string"},
                },
                "required": ["analysis", "next_action", "reasoning"],
            },
        ),
        ToolDefinition(
            name="store_finding",
            description="Store a new finding in the engagement database.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "category": {"type": "string"},
                    "target": {"type": "string"},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": ["title", "description", "severity", "category", "target"],
            },
        ),
    ]

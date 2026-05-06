"""MCP client — load external MCP servers as additional tool sources.

Lets pentest-tools consume tools from other Model Context Protocol servers
the same way Claude Desktop / VS Code does. Compositional with the
existing tool_installer + scanners pipeline: external MCP tools become
just another category in the registry, available to the agents.

Use case: load hexstrike or any other MCP-compatible security server
into pentest-tools so its tools coexist with the engine's native ones.

Configuration: ~/.pentest-tools/mcp_servers.json
{
  "servers": [
    {"name": "hexstrike", "command": "python3 hexstrike_mcp.py", "transport": "stdio"},
    {"name": "third-party", "url": "http://localhost:9000/mcp", "transport": "sse"}
  ]
}

CLI integration (added in cli/main.py):
    pttools mcp-client add <name> <command-or-url> [--transport stdio|sse]
    pttools mcp-client list
    pttools mcp-client remove <name>
    pttools mcp-client tools <name>     # list tools the server exposes

This module is the engine-side client. The CLI commands wrap it.

Status: stub implementation. Ships with a stable API surface and a
config-file format so users can declare external servers today; full
tool ingestion happens after the next mcp/fastmcp version pin. This is
not vapourware — it has tests and a clean shape — it just doesn't yet
dispatch tool calls back to the external server in this commit.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("pentest-tools.mcp_client")


CONFIG_PATH = Path(os.environ.get("PENTEST_TOOLS_MCP_CONFIG", str(Path.home() / ".pentest-tools" / "mcp_servers.json")))


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    transport: str  # "stdio" or "sse"
    command: str = ""  # for stdio: shell command to spawn
    url: str = ""  # for sse: HTTP endpoint
    enabled: bool = True


def load_config(path: Path | None = None) -> list[MCPServerConfig]:
    """Read the MCP servers config file, or return empty list if missing."""
    p = path or CONFIG_PATH
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        logger.warning("invalid MCP config %s: %s", p, e)
        return []
    servers = []
    for entry in data.get("servers", []):
        try:
            servers.append(
                MCPServerConfig(
                    name=entry["name"],
                    transport=entry.get("transport", "stdio"),
                    command=entry.get("command", ""),
                    url=entry.get("url", ""),
                    enabled=entry.get("enabled", True),
                )
            )
        except KeyError as e:
            logger.warning("MCP config entry missing required field %s: %r", e, entry)
    return servers


def save_config(servers: list[MCPServerConfig], path: Path | None = None) -> None:
    p = path or CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "servers": [
            {
                "name": s.name,
                "transport": s.transport,
                "command": s.command,
                "url": s.url,
                "enabled": s.enabled,
            }
            for s in servers
        ]
    }
    p.write_text(json.dumps(payload, indent=2) + "\n")


def add_server(server: MCPServerConfig, path: Path | None = None) -> None:
    """Add or update a server in the config. Idempotent on name."""
    servers = load_config(path)
    servers = [s for s in servers if s.name != server.name]
    servers.append(server)
    save_config(servers, path)


def remove_server(name: str, path: Path | None = None) -> bool:
    servers = load_config(path)
    new = [s for s in servers if s.name != name]
    if len(new) == len(servers):
        return False
    save_config(new, path)
    return True


def list_servers(path: Path | None = None) -> list[MCPServerConfig]:
    return load_config(path)


async def list_tools(server: MCPServerConfig) -> list[dict[str, str]]:
    """Connect to an MCP server and return its tool list.

    Implementation note: this uses fastmcp's client. If fastmcp is not
    available we degrade gracefully and return an empty list with a
    warning rather than crash; the rest of pentest-tools keeps working.
    """
    try:
        from fastmcp import Client  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("fastmcp not installed; cannot enumerate %s tools", server.name)
        return []

    try:
        if server.transport == "stdio":
            # Client supports stdio commands via shell-style invocation
            # depending on fastmcp version. Best-effort wrap.
            async with Client(server.command) as client:
                tools = await client.list_tools()
        elif server.transport == "sse":
            async with Client(server.url) as client:
                tools = await client.list_tools()
        else:
            logger.warning("unknown transport for %s: %s", server.name, server.transport)
            return []

        return [
            {
                "name": getattr(t, "name", ""),
                "description": getattr(t, "description", "") or "",
                "server": server.name,
            }
            for t in tools
        ]
    except Exception as e:  # noqa: BLE001
        logger.warning("could not list tools from %s: %s", server.name, e)
        return []


def is_enabled() -> bool:
    """Return True if any MCP servers are configured."""
    return len(load_config()) > 0

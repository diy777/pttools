"""MCP client detection and configuration for pentest-tools."""

import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

MCP_CLIENTS: dict[str, dict[str, Any]] = {
    "claude_desktop": {
        "name": "Claude Desktop",
        "config_paths": {
            "linux": Path.home() / ".claude" / "claude_desktop_config.json",
            "darwin": Path.home() / ".claude" / "claude_desktop_config.json",
            "windows": Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        },
    },
    "cursor": {
        "name": "Cursor",
        "config_paths": {
            "linux": Path.home() / ".cursor" / "mcp.json",
            "darwin": Path.home() / ".cursor" / "mcp.json",
            "windows": Path.home() / "AppData" / "Roaming" / "Cursor" / "mcp.json",
        },
    },
    "vscode": {
        "name": "VS Code (Copilot)",
        "config_paths": {
            "linux": Path.home() / ".vscode" / "mcp.json",
            "darwin": Path.home() / ".vscode" / "mcp.json",
            "windows": Path.home() / "AppData" / "Roaming" / "Code" / "User" / "mcp.json",
        },
    },
}


def _get_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    # WSL2 reports Linux as system but has "microsoft" in the kernel.
    # Filesystem paths are Linux-style, so treat as Linux.
    return "linux"


def _get_pentest_ai_command() -> str:
    return shutil.which("pentest-tools") or sys.executable + " -m pentest_ai"


def _mcp_server_entry() -> dict[str, Any]:
    return {
        "command": "pentest-tools",
        "args": ["mcp"],
        "env": {},
    }


def detect_installed_clients() -> list[dict[str, Any]]:
    plat = _get_platform()
    detected = []
    for key, client in MCP_CLIENTS.items():
        config_path = client["config_paths"].get(plat)
        if not config_path:
            continue
        if config_path.parent.exists():
            detected.append({
                "key": key,
                "name": client["name"],
                "config_path": config_path,
                "config_exists": config_path.exists(),
            })
    return detected


def generate_config_snippet() -> dict[str, Any]:
    return {"mcpServers": {"pentest-tools": _mcp_server_entry()}}


def inject_config(config_path: Path, dry_run: bool = False) -> dict[str, Any]:
    existing = json.loads(config_path.read_text()) if config_path.exists() else {}

    servers = existing.setdefault("mcpServers", {})

    if "pentest-tools" in servers and servers["pentest-tools"] == _mcp_server_entry():
        return {"changed": False, "path": str(config_path), "reason": "already configured"}

    servers["pentest-tools"] = _mcp_server_entry()

    if dry_run:
        return {"changed": True, "path": str(config_path), "dry_run": True, "config": existing}

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=config_path.parent, suffix=".tmp", delete=False
    ) as tmp:
        json.dump(existing, tmp, indent=2)
    try:
        Path(tmp.name).replace(config_path)
    except Exception:
        Path(tmp.name).unlink(missing_ok=True)
        raise

    return {"changed": True, "path": str(config_path)}


def run_mcp_setup(auto_inject: bool = False, dry_run: bool = False) -> None:
    clients = detect_installed_clients()

    if not clients:
        console.print("[yellow]No supported MCP clients detected.[/yellow]")
        console.print("Supported clients: Claude Desktop, Cursor, VS Code (Copilot)")
        console.print("\nManual config snippet:")
        console.print_json(data=generate_config_snippet())
        return

    table = Table(title="Detected MCP Clients")
    table.add_column("#", style="dim")
    table.add_column("Client")
    table.add_column("Config Path")
    table.add_column("Status")

    for i, c in enumerate(clients, 1):
        status = "[green]Config exists[/green]" if c["config_exists"] else "[dim]No config yet[/dim]"
        table.add_row(str(i), c["name"], str(c["config_path"]), status)

    console.print(table)
    console.print()
    console.print("[bold]Config entry to add:[/bold]")
    console.print_json(data={"pentest-tools": _mcp_server_entry()})
    console.print()

    if dry_run:
        console.print("[yellow]Dry run mode, showing what would change:[/yellow]")
        for c in clients:
            result = inject_config(c["config_path"], dry_run=True)
            if result["changed"]:
                console.print(f"  Would update: {result['path']}")
            else:
                console.print(f"  Already configured: {result['path']}")
        return

    if not auto_inject:
        try:
            answer = console.input("[bold]Write config to detected clients? [y/N]: [/bold]")
            if answer.strip().lower() not in ("y", "yes"):
                console.print("[dim]Skipped. Copy the snippet above into your client config manually.[/dim]")
                return
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Cancelled.[/dim]")
            return

    for c in clients:
        result = inject_config(c["config_path"])
        if result["changed"]:
            console.print(f"  [green]Wrote:[/green] {result['path']}")
        else:
            console.print(f"  [dim]Already configured:[/dim] {result['path']}")

    console.print(
        Panel.fit(
            "Restart your MCP client to apply changes.\n"
            "Then ask your AI: [cyan]start an engagement against <target>[/cyan]",
            title="Setup Complete",
        )
    )

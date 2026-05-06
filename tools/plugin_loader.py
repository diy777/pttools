"""YAML plugin loader for custom security tools.

Loads tool definitions from ~/.pentest-tools/plugins/*.yaml and registers
them into the ToolRegistry at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("pentest-tools.plugins")

DEFAULT_PLUGIN_DIR = Path.home() / ".pentest-tools" / "plugins"

REQUIRED_FIELDS = {"name", "category", "command"}


def load_plugins(plugin_dir: Path | None = None) -> list[dict[str, Any]]:
    directory = plugin_dir or DEFAULT_PLUGIN_DIR
    if not directory.exists():
        return []

    plugins: list[dict[str, Any]] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        try:
            plugin = _load_plugin_file(yaml_file)
            if plugin:
                plugins.append(plugin)
        except Exception as e:
            logger.warning(f"Failed to load plugin {yaml_file.name}: {e}")

    logger.info(f"Loaded {len(plugins)} plugins from {directory}")
    return plugins


def _load_plugin_file(path: Path) -> dict[str, Any] | None:
    data = yaml.safe_load(path.read_text())
    if not data or not isinstance(data, dict):
        return None

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        logger.warning(f"Plugin {path.name} missing fields: {missing}")
        return None

    return {
        "name": data["name"],
        "category": data.get("category", "custom"),
        "command": data["command"],
        "args": data.get("args", []),
        "description": data.get("description", f"Custom plugin: {data['name']}"),
        "output_parser": data.get("output_parser", "raw"),
        "install_check": data.get("install_check", f"which {data['command']}"),
        "source": "plugin",
        "plugin_path": str(path),
    }


def validate_plugin(plugin: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not plugin.get("name"):
        errors.append("name is required")
    if not plugin.get("command"):
        errors.append("command is required")
    if not plugin.get("category"):
        errors.append("category is required")
    return errors

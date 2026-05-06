"""Tests for cli/mcp_setup.py."""

import json
from pathlib import Path
from unittest.mock import patch

from cli.mcp_setup import detect_installed_clients, generate_config_snippet, inject_config

# ---------------------------------------------------------------------------
# detect_installed_clients
# ---------------------------------------------------------------------------


def test_detect_installed_clients_finds_claude_desktop():
    # Resolve the actual parent path for the current platform so the mock
    # returns True only for that directory (simulating it existing).
    from cli.mcp_setup import MCP_CLIENTS, _get_platform

    plat = _get_platform()
    claude_parent = MCP_CLIENTS["claude_desktop"]["config_paths"][plat].parent

    def path_exists(self):
        return Path(self) == claude_parent

    with patch.object(Path, "exists", path_exists):
        clients = detect_installed_clients()

    keys = [c["key"] for c in clients]
    assert "claude_desktop" in keys


def test_detect_installed_clients_none_found():
    with patch.object(Path, "exists", return_value=False):
        clients = detect_installed_clients()
    assert clients == []


# ---------------------------------------------------------------------------
# generate_config_snippet
# ---------------------------------------------------------------------------


def test_generate_config_snippet_structure():
    snippet = generate_config_snippet()
    assert "mcpServers" in snippet
    assert "pentest-tools" in snippet["mcpServers"]
    entry = snippet["mcpServers"]["pentest-tools"]
    assert "command" in entry
    assert "args" in entry


# ---------------------------------------------------------------------------
# inject_config
# ---------------------------------------------------------------------------


def test_inject_config_new_file(tmp_path):
    config_path = tmp_path / "subdir" / "config.json"
    result = inject_config(config_path)

    assert result["changed"] is True
    written = json.loads(config_path.read_text())
    assert "pentest-tools" in written["mcpServers"]


def test_inject_config_merges_existing_servers(tmp_path):
    config_path = tmp_path / "config.json"
    existing = {"mcpServers": {"other-tool": {"command": "other", "args": []}}}
    config_path.write_text(json.dumps(existing))

    result = inject_config(config_path)

    assert result["changed"] is True
    written = json.loads(config_path.read_text())
    assert "pentest-tools" in written["mcpServers"]
    assert "other-tool" in written["mcpServers"], "Existing servers must not be removed"


def test_inject_config_already_configured_returns_unchanged(tmp_path):
    config_path = tmp_path / "config.json"
    # Write the exact entry that inject_config would produce.
    snippet = generate_config_snippet()
    config_path.write_text(json.dumps(snippet))

    result = inject_config(config_path)

    assert result["changed"] is False


def test_inject_config_dry_run_does_not_write(tmp_path):
    config_path = tmp_path / "config.json"

    result = inject_config(config_path, dry_run=True)

    assert result["changed"] is True
    assert result.get("dry_run") is True
    assert not config_path.exists(), "Dry run must not create the file"

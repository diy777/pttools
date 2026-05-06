"""Tests for engine.mcp_client and engine.hitl helpers."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from engine import hitl
from engine.mcp_client import (
    MCPServerConfig,
    add_server,
    list_servers,
    load_config,
    remove_server,
    save_config,
)

# ─── mcp_client: config file round-trip ─────────────────────────────────


def test_load_returns_empty_when_file_missing() -> None:
    p = Path(tempfile.mkdtemp()) / "missing.json"
    assert load_config(p) == []


def test_save_then_load_round_trips() -> None:
    p = Path(tempfile.mkdtemp()) / "servers.json"
    servers = [
        MCPServerConfig(name="hexstrike", transport="stdio", command="python3 hexstrike_mcp.py"),
        MCPServerConfig(name="third-party", transport="sse", url="http://localhost:9000/mcp"),
    ]
    save_config(servers, p)
    loaded = load_config(p)
    assert len(loaded) == 2
    by_name = {s.name: s for s in loaded}
    assert by_name["hexstrike"].command == "python3 hexstrike_mcp.py"
    assert by_name["third-party"].url == "http://localhost:9000/mcp"


def test_add_server_is_idempotent_on_name() -> None:
    p = Path(tempfile.mkdtemp()) / "servers.json"
    add_server(MCPServerConfig(name="x", transport="stdio", command="cmd1"), p)
    add_server(MCPServerConfig(name="x", transport="stdio", command="cmd2"), p)
    servers = list_servers(p)
    assert len(servers) == 1
    assert servers[0].command == "cmd2"


def test_remove_server_returns_true_when_present() -> None:
    p = Path(tempfile.mkdtemp()) / "servers.json"
    add_server(MCPServerConfig(name="a", transport="stdio", command="cmd"), p)
    assert remove_server("a", p) is True
    assert remove_server("a", p) is False
    assert list_servers(p) == []


def test_invalid_json_returns_empty_with_warning(caplog) -> None:
    p = Path(tempfile.mkdtemp()) / "broken.json"
    p.write_text("{ this is not json")
    result = load_config(p)
    assert result == []


def test_missing_required_fields_are_skipped() -> None:
    p = Path(tempfile.mkdtemp()) / "partial.json"
    p.write_text(json.dumps({"servers": [
        {"name": "ok", "transport": "stdio", "command": "x"},
        {"transport": "stdio"},  # missing name
    ]}))
    result = load_config(p)
    assert len(result) == 1
    assert result[0].name == "ok"


# ─── hitl: signal-handler-free state machine paths ──────────────────────


def test_hitl_should_pause_starts_false() -> None:
    # Reset global state
    hitl._state.pause_requested = False
    hitl._state.abort_requested = False
    hitl._state.inject_queue.clear()
    assert hitl.should_pause() is False
    assert hitl.should_abort() is False


def test_hitl_consume_injects_drains_queue() -> None:
    hitl._state.inject_queue = ["one", "two"]
    assert hitl.consume_injects() == ["one", "two"]
    assert hitl.consume_injects() == []


def test_hitl_repl_resume_action(monkeypatch) -> None:
    """REPL with 'resume' input returns a resume directive."""
    hitl._state.pause_requested = True
    hitl._state.abort_requested = False
    hitl._state.inject_queue.clear()

    inputs = iter(["resume"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    state = {"engagement_id": "test-123", "current_phase": "recon", "findings": [], "last_decision": "scan"}
    result = hitl.repl(state)
    assert result == {"action": "resume", "inject": []}
    assert hitl._state.pause_requested is False


def test_hitl_repl_abort_action(monkeypatch) -> None:
    hitl._state.pause_requested = True
    hitl._state.abort_requested = False
    hitl._state.inject_queue.clear()

    inputs = iter(["abort"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    state = {"engagement_id": "test-123"}
    result = hitl.repl(state)
    assert result["action"] == "abort"
    assert hitl._state.abort_requested is True


def test_hitl_repl_inject_then_step(monkeypatch) -> None:
    hitl._state.pause_requested = True
    hitl._state.inject_queue.clear()

    inputs = iter(["inject look at /admin", "step"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    state = {"engagement_id": "test-123"}
    result = hitl.repl(state)
    assert result["action"] == "step"
    assert "look at /admin" in result["inject"]


def test_hitl_repl_unknown_command_then_resume(monkeypatch, capsys) -> None:
    hitl._state.pause_requested = True
    hitl._state.inject_queue.clear()

    inputs = iter(["banana", "resume"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    state = {"engagement_id": "x"}
    result = hitl.repl(state)
    captured = capsys.readouterr()
    assert "unknown" in captured.out.lower()
    assert result["action"] == "resume"


def test_hitl_install_uninstall_idempotent() -> None:
    # In the test thread we may or may not be in the main thread; just
    # make sure these don't raise.
    hitl.install()
    hitl.install()  # second install should be a no-op
    hitl.uninstall()
    hitl.uninstall()

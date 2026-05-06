"""Coverage fill for engine/hitl.py (signal-based human-in-the-loop)."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _reset_hitl_state():
    from engine import hitl
    hitl._state.last_sigint_time = 0.0
    hitl._state.pause_requested = False
    hitl._state.abort_requested = False
    hitl._state.inject_queue.clear()
    hitl._state.handler_installed = False
    yield
    hitl._state.last_sigint_time = 0.0
    hitl._state.pause_requested = False
    hitl._state.abort_requested = False
    hitl._state.inject_queue.clear()
    hitl._state.handler_installed = False


# ─── install / uninstall ────────────────────────────────────────────────


def test_install_uninstall_cycle():
    from engine import hitl
    with patch("engine.hitl.signal.signal"):
        hitl.install()
        assert hitl._state.handler_installed is True
        hitl.uninstall()
        assert hitl._state.handler_installed is False


def test_install_idempotent():
    from engine import hitl
    with patch("engine.hitl.signal.signal") as mock_signal:
        hitl.install()
        hitl.install()
    assert mock_signal.call_count == 1


def test_install_handles_value_error_gracefully():
    """Non-main-thread install raises ValueError; degrades silently."""
    from engine import hitl
    with patch("engine.hitl.signal.signal", side_effect=ValueError("not main thread")):
        hitl.install()
    assert hitl._state.handler_installed is False


def test_uninstall_when_not_installed_is_noop():
    from engine import hitl
    hitl.uninstall()  # must not raise
    assert hitl._state.handler_installed is False


# ─── should_pause / should_abort / consume_injects ──────────────────────


def test_should_pause_default_false():
    from engine import hitl
    assert hitl.should_pause() is False


def test_should_pause_true_after_request():
    from engine import hitl
    hitl._state.pause_requested = True
    assert hitl.should_pause() is True


def test_should_abort_default_false():
    from engine import hitl
    assert hitl.should_abort() is False


def test_consume_injects_empty():
    from engine import hitl
    assert hitl.consume_injects() == []


def test_consume_injects_drains_queue():
    from engine import hitl
    hitl._state.inject_queue = ["a", "b"]
    out = hitl.consume_injects()
    assert out == ["a", "b"]
    assert hitl._state.inject_queue == []


# ─── _on_sigint ─────────────────────────────────────────────────────────


def test_on_sigint_first_press_does_not_pause(capsys):
    from engine import hitl
    hitl._on_sigint(2, None)
    assert hitl._state.pause_requested is False
    out = capsys.readouterr().out
    assert "Ctrl+C again" in out


def test_on_sigint_double_press_within_window_pauses(capsys):
    import time as t

    from engine import hitl
    hitl._on_sigint(2, None)
    hitl._state.last_sigint_time = t.monotonic()  # ensure within window
    hitl._on_sigint(2, None)
    assert hitl._state.pause_requested is True
    out = capsys.readouterr().out
    assert "pause requested" in out


# ─── repl directives ────────────────────────────────────────────────────


def test_repl_resume_command(capsys):
    from engine import hitl
    hitl._state.pause_requested = True
    with patch("builtins.input", side_effect=["resume"]):
        result = hitl.repl({"engagement_id": "eng-1", "current_phase": "recon"})
    assert result["action"] == "resume"
    assert hitl._state.pause_requested is False


def test_repl_step_command():
    from engine import hitl
    with patch("builtins.input", side_effect=["step"]):
        result = hitl.repl({})
    assert result["action"] == "step"


def test_repl_abort_command():
    from engine import hitl
    with patch("builtins.input", side_effect=["abort"]):
        result = hitl.repl({})
    assert result["action"] == "abort"
    assert hitl._state.abort_requested is True


def test_repl_skip_command():
    from engine import hitl
    with patch("builtins.input", side_effect=["skip"]):
        result = hitl.repl({})
    assert result["action"] == "skip"


def test_repl_inject_command_queues():
    from engine import hitl
    with patch("builtins.input", side_effect=["inject focus on /admin", "resume"]):
        result = hitl.repl({})
    assert "focus on /admin" in result["inject"]
    assert "focus on /admin" in hitl._state.inject_queue


def test_repl_inject_without_text_warns(capsys):
    from engine import hitl
    with patch("builtins.input", side_effect=["inject", "resume"]):
        hitl.repl({})
    out = capsys.readouterr().out
    assert "usage" in out


def test_repl_help_command(capsys):
    from engine import hitl
    with patch("builtins.input", side_effect=["help", "resume"]):
        hitl.repl({})
    out = capsys.readouterr().out
    assert "Commands" in out


def test_repl_blank_line_loops():
    from engine import hitl
    with patch("builtins.input", side_effect=["", "", "resume"]):
        result = hitl.repl({})
    assert result["action"] == "resume"


def test_repl_unknown_command_warns(capsys):
    from engine import hitl
    with patch("builtins.input", side_effect=["bogus", "resume"]):
        hitl.repl({})
    out = capsys.readouterr().out
    assert "unknown" in out


def test_repl_eof_resumes():
    from engine import hitl
    with patch("builtins.input", side_effect=EOFError):
        result = hitl.repl({})
    assert result["action"] == "resume"


def test_repl_keyboard_interrupt_resumes():
    from engine import hitl
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        result = hitl.repl({})
    assert result["action"] == "resume"


# ─── _inspect ───────────────────────────────────────────────────────────


def test_repl_inspect_findings_empty(capsys):
    from engine import hitl
    with patch("builtins.input", side_effect=["inspect findings", "resume"]):
        hitl.repl({"findings": []})
    out = capsys.readouterr().out
    assert "no findings" in out


def test_repl_inspect_findings_truncates(capsys):
    from engine import hitl
    findings = [{"severity": "high", "title": f"f{i}"} for i in range(25)]
    with patch("builtins.input", side_effect=["inspect findings", "resume"]):
        hitl.repl({"findings": findings})
    out = capsys.readouterr().out
    assert "5 more" in out  # 25 - 20 = 5


def test_repl_inspect_chain_empty(capsys):
    from engine import hitl
    with patch("builtins.input", side_effect=["inspect chain", "resume"]):
        hitl.repl({"chain": None})
    out = capsys.readouterr().out
    assert "no chain" in out


def test_repl_inspect_chain_with_steps(capsys):
    from engine import hitl
    chain = {"steps": [{"description": "step1"}, {"description": "step2"}]}
    with patch("builtins.input", side_effect=["inspect chain", "resume"]):
        hitl.repl({"chain": chain})
    out = capsys.readouterr().out
    assert "step1" in out and "step2" in out


def test_repl_inspect_summary_default(capsys):
    from engine import hitl
    state = {
        "engagement_id": "eng-1",
        "findings": [1, 2, 3],
        "extra": object(),
    }
    with patch("builtins.input", side_effect=["inspect", "resume"]):
        hitl.repl(state)
    out = capsys.readouterr().out
    assert "engagement_id" in out
    assert "[3 items]" in out

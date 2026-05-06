"""Human-In-The-Loop teleoperation: pause an agent and take over from the CLI.

When an agent run is in progress, two consecutive Ctrl+C presses within a
short window pause the orchestrator and drop the user into a small REPL.
From there you can:

    step                # advance one agent decision
    inspect findings    # show current findings table
    inspect chain       # show the in-progress attack chain
    inject <command>    # add a free-form instruction the next turn
    skip                # tell the agent to skip the current step
    abort               # stop the engagement entirely
    resume              # let the agent run autonomously again
    help                # this help

The reason this pattern works is
that it acknowledges current LLMs are not fully autonomous. Letting the
operator step in WITHOUT killing the engagement is the usability gap
between "demo" and "actual tool a pro uses on a real engagement".

Implementation:

  - A signal handler counts SIGINT presses
  - The orchestrator polls hitl.should_pause() between agent decisions
  - When paused, the orchestrator yields control to hitl.repl(state)
  - The REPL returns a dict telling the orchestrator what to do next

This module is signal-based, not asyncio-based, because Ctrl+C arrives
via SIGINT regardless of where the asyncio loop is. The orchestrator
checks the flag at well-defined yield points.
"""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("pentest-tools.hitl")


# Time window during which two SIGINTs count as a pause request.
DOUBLE_CTRL_C_WINDOW_SECONDS = 0.6


@dataclass
class _State:
    last_sigint_time: float = 0.0
    pause_requested: bool = False
    abort_requested: bool = False
    inject_queue: list[str] = field(default_factory=list)
    handler_installed: bool = False


_state = _State()


def install() -> None:
    """Install the SIGINT handler. Call once at engagement start."""
    if _state.handler_installed:
        return
    try:
        signal.signal(signal.SIGINT, _on_sigint)
        _state.handler_installed = True
    except (ValueError, OSError):
        # SIGINT can only be installed in the main thread. In test/server
        # contexts we silently degrade to "no HITL"; the orchestrator
        # always works without it.
        logger.debug("SIGINT handler not installed (not in main thread)")


def uninstall() -> None:
    """Restore default SIGINT handler. Call at engagement end."""
    if not _state.handler_installed:
        return
    import contextlib

    with contextlib.suppress(ValueError, OSError):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    _state.handler_installed = False


def should_pause() -> bool:
    """Orchestrator polls this between agent decisions."""
    return _state.pause_requested


def should_abort() -> bool:
    return _state.abort_requested


def consume_injects() -> list[str]:
    """Return any injected instructions and clear the queue."""
    out = _state.inject_queue[:]
    _state.inject_queue.clear()
    return out


def _on_sigint(signum: int, frame: Any) -> None:  # noqa: ARG001
    now = time.monotonic()
    if now - _state.last_sigint_time < DOUBLE_CTRL_C_WINDOW_SECONDS:
        # Two presses within window → pause
        _state.pause_requested = True
        _state.last_sigint_time = 0.0
        print("\n[hitl] pause requested. orchestrator will yield at the next decision boundary.")
    else:
        _state.last_sigint_time = now
        print("\n[hitl] press Ctrl+C again within 600ms to pause for teleoperation, or wait to keep running.")


def repl(state: dict[str, Any]) -> dict[str, Any]:
    """Run the interactive REPL. Returns a directive dict.

    state: a snapshot of the orchestrator's current view. Should include
        - engagement_id: str
        - findings: list[dict]
        - chain: dict | None
        - current_phase: str
        - last_decision: str

    Returns:
        {"action": "resume" | "step" | "abort" | "skip", "inject": list[str]}
    """
    print("\n=== pentest-tools HITL ===")
    print(f"engagement: {state.get('engagement_id', '?')}")
    print(f"phase:      {state.get('current_phase', '?')}")
    print(f"findings:   {len(state.get('findings') or [])}")
    print(f"last:       {state.get('last_decision', '?')}")
    print("type 'help' for commands.")

    inject: list[str] = []

    while True:
        try:
            line = input("hitl> ").strip()
        except (EOFError, KeyboardInterrupt):
            # Bare Ctrl+C inside REPL = resume
            print()
            return {"action": "resume", "inject": inject}

        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        cmd = cmd.lower()

        if cmd in ("h", "help", "?"):
            print(_HELP_TEXT)
        elif cmd == "step":
            _state.pause_requested = False
            return {"action": "step", "inject": inject}
        elif cmd == "resume":
            _state.pause_requested = False
            return {"action": "resume", "inject": inject}
        elif cmd == "abort":
            _state.abort_requested = True
            _state.pause_requested = False
            return {"action": "abort", "inject": inject}
        elif cmd == "skip":
            _state.pause_requested = False
            return {"action": "skip", "inject": inject}
        elif cmd == "inject":
            if not rest:
                print("usage: inject <instruction>")
                continue
            inject.append(rest)
            _state.inject_queue.append(rest)
            print(f"queued injection: {rest!r}")
        elif cmd == "inspect":
            _inspect(state, rest.strip())
        else:
            print(f"unknown: {cmd!r} (type 'help')")


_HELP_TEXT = """\
Commands:
  step                advance one agent decision and pause again
  resume              continue autonomous run
  abort               stop the engagement
  skip                tell the agent to skip the current step
  inject <text>       add a free-form instruction for the next turn
  inspect findings    show the current findings table
  inspect chain       show the in-progress attack chain
  help                this list
"""


def _inspect(state: dict[str, Any], target: str) -> None:
    target = target.lower().strip() or "summary"
    if target == "findings":
        findings = state.get("findings") or []
        if not findings:
            print("(no findings yet)")
            return
        for i, f in enumerate(findings[:20], start=1):
            sev = f.get("severity", "?")
            title = f.get("title") or f.get("name") or "(untitled)"
            print(f"  {i:>2}. [{sev:<8}] {title}")
        if len(findings) > 20:
            print(f"  ... ({len(findings) - 20} more)")
    elif target == "chain":
        chain = state.get("chain") or {}
        if not chain:
            print("(no chain yet)")
            return
        for step in chain.get("steps", []):
            print(f"  → {step.get('description', step)}")
    else:
        # Default: summary
        for k, v in state.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                print(f"  {k}: {v}")
            elif isinstance(v, list):
                print(f"  {k}: [{len(v)} items]")
            else:
                print(f"  {k}: <{type(v).__name__}>")

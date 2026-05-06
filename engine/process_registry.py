"""Live process registry for security tool subprocesses.

Every SecurityTool.execute() that spawns an asyncio subprocess registers
its PID, tool name, and target here. Operators can then list running
processes (`pttools ps`), kill one (`pttools kill <pid>`), or query the
registry from MCP clients via list_processes / kill_process tools.

Threading model: the registry is a plain dict keyed by PID with a
threading.Lock for mutation. Reads return a snapshot copy so callers
can safely iterate without holding the lock.

The registry is process-local. pttools runs in a single process per
engagement, so this is sufficient. For cross-process tracking you'd
need a row in findings_db or a Redis hash, neither of which the
current operational model needs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("pentest-tools.process_registry")

# Windows has no SIGKILL; os.kill(pid, SIGTERM) on Windows already calls
# TerminateProcess (the moral equivalent of SIGKILL), so the escalation
# step is a no-op there. Fall back to SIGTERM so the code path is portable.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


@dataclass
class ProcessRecord:
    pid: int
    tool: str
    target: str
    started_at: float
    engagement_id: str = ""
    cmd: str = ""

    def runtime_seconds(self) -> float:
        return max(0.0, time.time() - self.started_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "tool": self.tool,
            "target": self.target,
            "started_at": self.started_at,
            "runtime_seconds": round(self.runtime_seconds(), 2),
            "engagement_id": self.engagement_id,
            "cmd": self.cmd,
        }


@dataclass
class ProcessRegistry:
    _records: dict[int, ProcessRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def register(self, record: ProcessRecord) -> None:
        with self._lock:
            self._records[record.pid] = record

    def unregister(self, pid: int) -> None:
        with self._lock:
            self._records.pop(pid, None)

    def get(self, pid: int) -> ProcessRecord | None:
        with self._lock:
            return self._records.get(pid)

    def list_records(self) -> list[ProcessRecord]:
        with self._lock:
            return list(self._records.values())

    async def kill(self, pid: int, grace_seconds: float = 2.0) -> bool:
        """Send SIGTERM then escalate to SIGKILL if still alive after grace.

        Returns True if a registered tool subprocess was killed, False if
        the PID is not in this registry or no longer alive. The registry
        check is a SAFETY GATE: pttools will only signal PIDs it spawned
        itself, never arbitrary system PIDs the user typed by mistake.
        """
        record = self.get(pid)
        if record is None:
            # Refuse to signal PIDs we did not spawn. This is the guard that
            # prevents `pttools kill 1` (or kill_process MCP call) from
            # terminating init or other unrelated processes on a privileged
            # host or container. List with list_processes() to see what's
            # actually killable.
            logger.info("kill refused: pid=%s not in process registry", pid)
            return False
        if not _pid_alive(pid):
            self.unregister(pid)
            return False

        # First try graceful term
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            self.unregister(pid)
            return False
        except PermissionError:
            logger.warning("no permission to kill pid=%s", pid)
            return False

        # Wait up to grace_seconds for it to die
        deadline = time.time() + max(0.0, grace_seconds)
        while time.time() < deadline:
            if not _pid_alive(pid):
                self.unregister(pid)
                return True
            await asyncio.sleep(0.05)

        # Escalate (no-op on Windows where SIGKILL doesn't exist; SIGTERM
        # there is already TerminateProcess so the first signal was hard).
        try:
            os.kill(pid, _SIGKILL)
        except ProcessLookupError:
            self.unregister(pid)
            return True
        # Give the kernel a moment to reap
        await asyncio.sleep(0.05)
        self.unregister(pid)
        return True


def _pid_alive(pid: int) -> bool:
    """Cheap kill-0 liveness check. Returns False on PermissionError too,
    since a process we can't signal is one we can't manage."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# ─── Singleton helper ────────────────────────────────────────────────────

_default: ProcessRegistry | None = None
_default_lock = threading.Lock()


def get_default_registry() -> ProcessRegistry:
    global _default
    with _default_lock:
        if _default is None:
            _default = ProcessRegistry()
        return _default

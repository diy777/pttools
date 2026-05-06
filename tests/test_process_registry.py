"""Tests for engine.process_registry — live tracking of running tool subprocesses."""

from __future__ import annotations

import sys
import time

import pytest

# Windows blocks os.kill against subprocesses we don't own with WinError 5,
# so the end-to-end "spawn and kill" test only runs on POSIX. Unit-level
# tests of the registry table run on every platform.
_skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32",
    reason="os.kill across processes requires elevation on Windows",
)


def test_register_then_list_returns_record():
    from engine.process_registry import ProcessRecord, ProcessRegistry
    reg = ProcessRegistry()
    rec = ProcessRecord(pid=1234, tool="nmap", target="example.com", started_at=time.time())
    reg.register(rec)
    records = reg.list_records()
    assert len(records) == 1
    assert records[0].pid == 1234
    assert records[0].tool == "nmap"


def test_unregister_removes_record():
    from engine.process_registry import ProcessRecord, ProcessRegistry
    reg = ProcessRegistry()
    reg.register(ProcessRecord(pid=1, tool="a", target="t", started_at=0.0))
    reg.register(ProcessRecord(pid=2, tool="b", target="t", started_at=0.0))
    reg.unregister(1)
    pids = [r.pid for r in reg.list_records()]
    assert pids == [2]


def test_unregister_missing_pid_is_noop():
    from engine.process_registry import ProcessRegistry
    reg = ProcessRegistry()
    # Must not raise
    reg.unregister(99999)


def test_get_returns_record_or_none():
    from engine.process_registry import ProcessRecord, ProcessRegistry
    reg = ProcessRegistry()
    reg.register(ProcessRecord(pid=42, tool="a", target="t", started_at=0.0))
    assert reg.get(42) is not None
    assert reg.get(43) is None


def test_runtime_seconds_increases_monotonically():
    from engine.process_registry import ProcessRecord
    rec = ProcessRecord(pid=1, tool="a", target="t", started_at=time.time() - 5.0)
    rt = rec.runtime_seconds()
    assert rt >= 5.0


def test_record_to_dict_serializes():
    from engine.process_registry import ProcessRecord
    rec = ProcessRecord(
        pid=1, tool="nmap", target="example.com",
        started_at=time.time(), engagement_id="eng-1", cmd="nmap",
    )
    d = rec.to_dict()
    assert d["pid"] == 1
    assert d["tool"] == "nmap"
    assert d["target"] == "example.com"
    assert d["engagement_id"] == "eng-1"
    assert d["cmd"] == "nmap"
    assert "runtime_seconds" in d


def test_singleton_get_default_returns_same_instance():
    from engine.process_registry import get_default_registry
    a = get_default_registry()
    b = get_default_registry()
    assert a is b


@pytest.mark.asyncio
async def test_kill_unknown_pid_returns_false():
    from engine.process_registry import ProcessRegistry
    reg = ProcessRegistry()
    result = await reg.kill(99999)
    assert result is False


@_skip_on_windows
@pytest.mark.asyncio
async def test_kill_refuses_unregistered_live_pid():
    """Safety gate: kill() must refuse a PID that is alive but not in the
    registry, so `pttools kill 1` cannot terminate init or any unrelated
    process on a privileged host."""
    import asyncio

    from engine.process_registry import ProcessRegistry

    # Spawn a real long-running subprocess but DO NOT register it.
    proc = await asyncio.create_subprocess_exec(
        "sleep", "30",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    reg = ProcessRegistry()  # fresh, empty registry
    try:
        result = await reg.kill(proc.pid)
        assert result is False  # refused by safety gate
        # Verify the process is still alive (we didn't kill it)
        assert proc.returncode is None
    finally:
        proc.kill()
        await proc.wait()


@_skip_on_windows
@pytest.mark.asyncio
async def test_kill_real_subprocess_returns_true():
    """Spawn a long-running 'sleep 30', register it, kill it, verify it dies."""
    import asyncio

    from engine.process_registry import ProcessRecord, ProcessRegistry

    proc = await asyncio.create_subprocess_exec(
        "sleep", "30",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    reg = ProcessRegistry()
    reg.register(ProcessRecord(pid=proc.pid, tool="sleep", target="-", started_at=time.time()))

    try:
        result = await reg.kill(proc.pid, grace_seconds=1.0)
        assert result is True
        # The process should now be reaped by the registry
        await asyncio.wait_for(proc.wait(), timeout=3.0)
        assert proc.returncode is not None
    finally:
        # Cleanup in case kill failed
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        reg.unregister(proc.pid)


def test_register_idempotent_on_same_pid():
    from engine.process_registry import ProcessRecord, ProcessRegistry
    reg = ProcessRegistry()
    reg.register(ProcessRecord(pid=1, tool="a", target="t1", started_at=0.0))
    reg.register(ProcessRecord(pid=1, tool="b", target="t2", started_at=0.0))  # overwrites
    records = reg.list_records()
    assert len(records) == 1
    assert records[0].tool == "b"
    assert records[0].target == "t2"


def test_list_records_returns_copy_not_live_view():
    from engine.process_registry import ProcessRecord, ProcessRegistry
    reg = ProcessRegistry()
    reg.register(ProcessRecord(pid=1, tool="a", target="t", started_at=0.0))
    snapshot = reg.list_records()
    reg.register(ProcessRecord(pid=2, tool="b", target="t", started_at=0.0))
    assert len(snapshot) == 1  # snapshot did not gain the new record

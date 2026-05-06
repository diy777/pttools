"""Tests for engine.exec_context tool_result persistence hook.

Verifies that SecurityTool.execute() writes a tool_results row to the
findings DB when an exec_context is active, and stays silent otherwise.
"""

from __future__ import annotations

import asyncio

import pytest

from engine.exec_context import exec_context, get_exec_context
from engine.findings_db import FindingsDB
from tools.registry import SecurityTool, configure_cache


@pytest.fixture(autouse=True)
def _isolate_tool_cache():
    """Some other tests configure a shared cache on SecurityTool. Reset between tests."""
    configure_cache(None, disabled=True)
    yield
    configure_cache(None, disabled=False)


class _FakeProc:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode = rc
        self._out = out
        self._err = err

    async def communicate(self):
        return (self._out, self._err)


def _patch_subprocess(monkeypatch, rc=0, out=b"hello", err=b""):
    async def _spawn(*args, **kwargs):
        return _FakeProc(rc, out, err)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)


@pytest.mark.asyncio
async def test_context_defaults_are_empty():
    eid, db = get_exec_context()
    assert eid == ""
    assert db is None


@pytest.mark.asyncio
async def test_context_manager_sets_and_resets(tmp_path):
    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        await db.init()
        with exec_context("eng-123", db):
            eid, ctx_db = get_exec_context()
            assert eid == "eng-123"
            assert ctx_db is db
        eid2, db2 = get_exec_context()
        assert eid2 == ""
        assert db2 is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_tool_run_persists_when_context_active(tmp_path, monkeypatch):
    _patch_subprocess(monkeypatch, rc=0, out=b"hello stdout", err=b"warn stderr")

    tool = SecurityTool(
        name="fake_tool",
        category="recon",
        description="mock",
        command="/bin/true",
    )

    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        await db.init()
        eng = await db.create_engagement(target="example.com")
        with exec_context(eng["id"], db):
            result = await tool.execute("example.com", {"flag": "v"})
        assert result["exit_code"] == 0

        backend = await db._get_db()
        async with backend.execute(
            "SELECT tool_name, target, exit_code, output FROM tool_results WHERE engagement_id = ?",
            (eng["id"],),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        assert len(rows) == 1
        assert rows[0]["tool_name"] == "fake_tool"
        assert rows[0]["target"] == "example.com"
        assert rows[0]["exit_code"] == 0
        assert "hello stdout" in rows[0]["output"]
        assert "warn stderr" in rows[0]["output"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_tool_run_noop_without_context(tmp_path, monkeypatch):
    """Bare tool.execute() with no exec_context must not crash, not persist."""
    _patch_subprocess(monkeypatch, rc=0, out=b"", err=b"")

    tool = SecurityTool(
        name="fake_tool2",
        category="recon",
        description="mock",
        command="/bin/true",
    )

    result = await tool.execute("host", {})
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_persistence_does_not_raise_on_db_error(tmp_path, monkeypatch):
    """Tool execution must survive a broken DB. Persistence is best-effort."""
    _patch_subprocess(monkeypatch, rc=0, out=b"ok", err=b"")

    class BrokenDB:
        async def add_tool_result(self, *_args, **_kw):
            raise RuntimeError("db is down")

    tool = SecurityTool(
        name="fake_tool3",
        category="recon",
        description="mock",
        command="/bin/true",
    )

    with exec_context("eng-x", BrokenDB()):
        result = await tool.execute("host", {})
    assert result["exit_code"] == 0

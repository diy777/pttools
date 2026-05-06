"""Tests for engine.cache (ToolResultCache)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from engine.cache import (
    DEFAULT_TTL,
    TTL_BY_CATEGORY,
    ToolResultCache,
    make_key,
    ttl_for,
)


@pytest.fixture
async def cache(tmp_path):
    c = ToolResultCache(db_path=tmp_path / "cache.db")
    await c.init() if hasattr(c, "init") else None
    yield c
    await c.close()


class TestMakeKey:
    def test_deterministic(self):
        a = make_key("nmap", "10.0.0.1", "normal", {"sV": True, "p": "80"})
        b = make_key("nmap", "10.0.0.1", "normal", {"p": "80", "sV": True})
        assert a == b

    def test_differs_on_target(self):
        a = make_key("nmap", "10.0.0.1", "normal", None)
        b = make_key("nmap", "10.0.0.2", "normal", None)
        assert a != b

    def test_differs_on_intensity(self):
        a = make_key("nmap", "10.0.0.1", "stealth", None)
        b = make_key("nmap", "10.0.0.1", "aggressive", None)
        assert a != b

    def test_differs_on_args(self):
        a = make_key("nmap", "10.0.0.1", "normal", {"p": "80"})
        b = make_key("nmap", "10.0.0.1", "normal", {"p": "443"})
        assert a != b

    def test_differs_on_tool(self):
        a = make_key("nmap", "10.0.0.1", "normal", None)
        b = make_key("nuclei", "10.0.0.1", "normal", None)
        assert a != b

    def test_no_args_equivalent_to_empty(self):
        a = make_key("nmap", "10.0.0.1", "normal", None)
        b = make_key("nmap", "10.0.0.1", "normal", {})
        assert a == b

    def test_intensity_default(self):
        a = make_key("nmap", "10.0.0.1", "", None)
        b = make_key("nmap", "10.0.0.1", "normal", None)
        assert a == b


class TestTTLFor:
    def test_recon_ttl(self):
        assert ttl_for("recon") == TTL_BY_CATEGORY["recon"]

    def test_vuln_ttl(self):
        assert ttl_for("vuln") == TTL_BY_CATEGORY["vuln"]

    def test_exploit_no_cache(self):
        assert ttl_for("exploit") == 0
        assert ttl_for("exploitation") == 0

    def test_unknown_category_falls_back(self):
        assert ttl_for("unknown-category") == DEFAULT_TTL

    def test_none_falls_back(self):
        assert ttl_for(None) == DEFAULT_TTL

    def test_case_insensitive(self):
        assert ttl_for("RECON") == TTL_BY_CATEGORY["recon"]


@pytest.mark.asyncio
class TestCacheRoundtrip:
    async def test_miss_returns_none(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            assert await c.get("nope") is None
        finally:
            await c.close()

    async def test_put_then_get(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put(
                "k1",
                {"hello": "world", "findings": []},
                tool="nmap",
                target="10.0.0.1",
                intensity="normal",
                ttl=60,
            )
            got = await c.get("k1")
            assert got == {"hello": "world", "findings": []}
        finally:
            await c.close()

    async def test_zero_ttl_is_noop(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put(
                "k1",
                {"x": 1},
                tool="msfconsole",
                target="t",
                intensity="normal",
                ttl=0,
            )
            assert await c.get("k1") is None
        finally:
            await c.close()

    async def test_expired_entry_returns_none_and_evicted(self, tmp_path, monkeypatch):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put(
                "k1",
                {"x": 1},
                tool="nmap",
                target="t",
                intensity="normal",
                ttl=1,
            )
            # Force time forward.
            real_time = time.time
            monkeypatch.setattr("engine.cache.time.time", lambda: real_time() + 5)
            assert await c.get("k1") is None
            # Confirm row is gone.
            stats = await c.stats()
            assert stats["total_entries"] == 0
        finally:
            await c.close()

    async def test_overwrite_same_key(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put("k", {"v": 1}, tool="nmap", target="t", intensity="normal", ttl=60)
            await c.put("k", {"v": 2}, tool="nmap", target="t", intensity="normal", ttl=60)
            assert (await c.get("k"))["v"] == 2
            stats = await c.stats()
            assert stats["total_entries"] == 1
        finally:
            await c.close()

    async def test_clear(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            for i in range(5):
                await c.put(
                    f"k{i}", {"i": i}, tool="nmap", target="t", intensity="normal", ttl=60
                )
            assert (await c.stats())["total_entries"] == 5
            removed = await c.clear()
            assert removed == 5
            assert (await c.stats())["total_entries"] == 0
        finally:
            await c.close()

    async def test_expire_removes_only_expired(self, tmp_path, monkeypatch):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put("a", {"v": 1}, tool="nmap", target="t", intensity="normal", ttl=1)
            await c.put("b", {"v": 2}, tool="nmap", target="t", intensity="normal", ttl=600)
            real_time = time.time
            monkeypatch.setattr("engine.cache.time.time", lambda: real_time() + 5)
            removed = await c.expire()
            assert removed == 1
            assert await c.get("b") is not None
        finally:
            await c.close()

    async def test_stats_groups_by_tool(self, tmp_path):
        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            await c.put("a", {}, tool="nmap", target="t", intensity="normal", ttl=60)
            await c.put("b", {}, tool="nmap", target="u", intensity="normal", ttl=60)
            await c.put("c", {}, tool="nuclei", target="t", intensity="normal", ttl=60)
            stats = await c.stats()
            tools = dict(stats["by_tool"])
            assert tools["nmap"] == 2
            assert tools["nuclei"] == 1
            assert stats["live_entries"] == 3
            assert stats["expired_entries"] == 0
            assert Path(stats["db_path"]).exists()
        finally:
            await c.close()


@pytest.mark.asyncio
class TestRegistryIntegration:
    async def test_configure_cache_sets_classvar(self, tmp_path):
        from tools.registry import SecurityTool, configure_cache

        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            configure_cache(c, intensity="stealth")
            assert SecurityTool._cache is c
            assert SecurityTool._cache_intensity == "stealth"
            assert SecurityTool._cache_disabled is False
        finally:
            configure_cache(None)
            await c.close()

    async def test_disable_flag(self, tmp_path):
        from tools.registry import SecurityTool, configure_cache

        c = ToolResultCache(db_path=tmp_path / "c.db")
        try:
            configure_cache(c, disabled=True)
            assert SecurityTool._cache_disabled is True
        finally:
            configure_cache(None)
            await c.close()

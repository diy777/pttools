"""Tool-result cache (SQLite, TTL'd) for pentest-tools.

Keyed on sha256(tool + sorted_args + target + intensity). Default TTLs
are tuned per category: recon results stay fresh for an hour, vuln scans
for six. Exploitation tools never cache.

The cache lives in a single SQLite file shared across engagements (default
location: ``~/.cache/pentest-tools/cache.db``) so back-to-back scans of the
same target reuse work transparently.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

DEFAULT_CACHE_PATH = Path(
    os.environ.get("PENTEST_TOOLS_CACHE", str(Path.home() / ".cache" / "pentest-tools" / "cache.db"))
)

# Per-category TTL defaults (seconds). Falls back to DEFAULT_TTL.
TTL_BY_CATEGORY: dict[str, int] = {
    "recon": 60 * 60,           # 1h
    "network": 60 * 60,         # 1h
    "vuln": 6 * 60 * 60,        # 6h
    "vulnerability": 6 * 60 * 60,
    "web": 6 * 60 * 60,         # 6h
    "exploit": 0,               # never cache
    "exploitation": 0,
    "validation": 0,
}
DEFAULT_TTL = 60 * 60  # 1h


def make_key(tool: str, target: str, intensity: str, args: dict[str, Any] | None) -> str:
    """Stable SHA-256 hash of (tool, target, intensity, sorted args)."""
    payload = {
        "tool": tool,
        "target": target,
        "intensity": intensity or "normal",
        "args": dict(sorted((args or {}).items())),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def ttl_for(category: str | None) -> int:
    if category is None:
        return DEFAULT_TTL
    return TTL_BY_CATEGORY.get(category.lower(), DEFAULT_TTL)


class ToolResultCache:
    """Async SQLite-backed cache with per-entry expiry."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_CACHE_PATH
        self._db: aiosqlite.Connection | None = None

    async def _get_db(self) -> aiosqlite.Connection:
        if self._db is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
            await self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tool_result_cache (
                    key TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    intensity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cache_expires ON tool_result_cache(expires_at);
                CREATE INDEX IF NOT EXISTS idx_cache_tool ON tool_result_cache(tool);
                """
            )
            await self._db.commit()
        return self._db

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def get(self, key: str) -> dict[str, Any] | None:
        db = await self._get_db()
        now = time.time()
        async with db.execute(
            "SELECT payload, expires_at FROM tool_result_cache WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if row["expires_at"] <= now:
            await db.execute("DELETE FROM tool_result_cache WHERE key = ?", (key,))
            await db.commit()
            return None
        return json.loads(row["payload"])

    async def put(
        self,
        key: str,
        result: dict[str, Any],
        *,
        tool: str,
        target: str,
        intensity: str,
        ttl: int,
    ) -> None:
        if ttl <= 0:
            return
        db = await self._get_db()
        now = time.time()
        await db.execute(
            "INSERT OR REPLACE INTO tool_result_cache "
            "(key, tool, target, intensity, payload, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key, tool, target, intensity, json.dumps(result), now, now + ttl),
        )
        await db.commit()

    async def expire(self) -> int:
        """Drop expired rows. Returns count removed."""
        db = await self._get_db()
        now = time.time()
        async with db.execute(
            "DELETE FROM tool_result_cache WHERE expires_at <= ?", (now,)
        ) as cur:
            removed = cur.rowcount
        await db.commit()
        return removed or 0

    async def clear(self) -> int:
        db = await self._get_db()
        async with db.execute("DELETE FROM tool_result_cache") as cur:
            removed = cur.rowcount
        await db.commit()
        return removed or 0

    async def stats(self) -> dict[str, Any]:
        db = await self._get_db()
        now = time.time()
        async with db.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS live "
            "FROM tool_result_cache",
            (now,),
        ) as cur:
            row = await cur.fetchone()
        total = (row["total"] if row else 0) or 0
        live = (row["live"] if row else 0) or 0
        async with db.execute(
            "SELECT tool, COUNT(*) AS n FROM tool_result_cache "
            "WHERE expires_at > ? GROUP BY tool ORDER BY n DESC",
            (now,),
        ) as cur:
            by_tool = [(r["tool"], r["n"]) for r in await cur.fetchall()]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "total_entries": total,
            "live_entries": live,
            "expired_entries": total - live,
            "by_tool": by_tool,
            "db_path": str(self.db_path),
            "db_size_bytes": size,
        }

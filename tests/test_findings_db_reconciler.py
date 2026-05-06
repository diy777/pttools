"""Integration tests for FindingsDB.reconcile_stale_engagements.

Uses a real SQLite DB (not mocks) so schema/column-name regressions get caught
in CI. The original reconciler shipped with `started_at` in the WHERE clause,
which doesn't exist on the engagements table. Mocked tests didn't catch it
because they don't talk to actual SQL.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from engine.findings_db import FindingsDB


@pytest.mark.asyncio
async def test_reconcile_marks_old_running_as_interrupted(tmp_path):
    db = FindingsDB(str(tmp_path / "reconcile.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        await db.update_engagement_status(eng["id"], "running")

        # Backdate created_at past the cutoff.
        backdate = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn = await db._get_db()
        await conn.execute(
            "UPDATE engagements SET created_at = ?, updated_at = ? WHERE id = ?",
            [backdate, backdate, eng["id"]],
        )
        await conn.commit()

        reconciled = await db.reconcile_stale_engagements(max_age_minutes=30)
        assert reconciled >= 1

        row = await db.get_engagement(eng["id"])
        assert row["status"] == "interrupted"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_reconcile_leaves_recent_running_alone(tmp_path):
    db = FindingsDB(str(tmp_path / "reconcile_recent.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        await db.update_engagement_status(eng["id"], "running")

        # No backdating - this engagement is fresh.
        reconciled = await db.reconcile_stale_engagements(max_age_minutes=30)
        assert reconciled == 0

        row = await db.get_engagement(eng["id"])
        assert row["status"] == "running"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_reconcile_does_not_touch_completed(tmp_path):
    db = FindingsDB(str(tmp_path / "reconcile_completed.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        await db.update_engagement_status(eng["id"], "completed")

        backdate = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn = await db._get_db()
        await conn.execute(
            "UPDATE engagements SET created_at = ?, updated_at = ? WHERE id = ?",
            [backdate, backdate, eng["id"]],
        )
        await conn.commit()

        reconciled = await db.reconcile_stale_engagements(max_age_minutes=30)
        assert reconciled == 0

        row = await db.get_engagement(eng["id"])
        assert row["status"] == "completed"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_reconcile_uses_real_columns(tmp_path):
    """Regression: the reconciler shipped with `started_at` in the WHERE clause
    but the engagements table has `created_at`, not `started_at`. Mocked tests
    missed this. A real-DB integration test catches it.
    """
    db = FindingsDB(str(tmp_path / "schema.db"))
    try:
        # Just running the query against a real schema is enough; if the column
        # name is wrong it raises OperationalError.
        await db.reconcile_stale_engagements(max_age_minutes=30)
    finally:
        await db.close()

"""Async-scoped execution context for pentest engagements.

Threads the active engagement_id and FindingsDB through the async stack
via contextvars, so SecurityTool.execute() can persist tool_results to
the database without every call site passing them explicitly.

Usage:
    token_eid = current_engagement_id.set(engagement_id)
    token_db = current_findings_db.set(db)
    try:
        # ... run phases / tools ...
    finally:
        current_engagement_id.reset(token_eid)
        current_findings_db.reset(token_db)
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

current_engagement_id: ContextVar[str] = ContextVar("current_engagement_id", default="")
current_findings_db: ContextVar[Any] = ContextVar("current_findings_db", default=None)


@contextmanager
def exec_context(engagement_id: str, db: Any):
    """Sync context manager wrapping both contextvars."""
    token_eid = current_engagement_id.set(engagement_id or "")
    token_db = current_findings_db.set(db)
    try:
        yield
    finally:
        current_engagement_id.reset(token_eid)
        current_findings_db.reset(token_db)


def get_exec_context() -> tuple[str, Any]:
    """Return (engagement_id, db) tuple. Either or both may be empty/None."""
    return current_engagement_id.get(), current_findings_db.get()

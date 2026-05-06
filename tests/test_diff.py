"""Tests for engine.diff (compute_diff + EngagementDiff)."""

from __future__ import annotations

import pytest

from engine.dedup import FindingDeduplicator
from engine.diff import EngagementDiff, compute_diff


def _f(target: str, category: str, title: str, severity: str = "medium") -> dict:
    return {
        "target": target,
        "category": category,
        "title": title,
        "severity": severity,
    }


class TestComputeDiff:
    def test_all_new(self):
        prev: list[dict] = []
        curr = [_f("a.com", "web", "SQL injection")]
        d = compute_diff("p", "c", prev, curr)
        assert d.total_new == 1
        assert d.total_resolved == 0
        assert d.total_unchanged == 0

    def test_all_resolved(self):
        prev = [_f("a.com", "web", "XSS")]
        curr: list[dict] = []
        d = compute_diff("p", "c", prev, curr)
        assert d.total_new == 0
        assert d.total_resolved == 1

    def test_all_unchanged(self):
        prev = [_f("a.com", "web", "Open port 80")]
        curr = [_f("a.com", "web", "Open port 80")]
        d = compute_diff("p", "c", prev, curr)
        assert d.total_unchanged == 1
        assert d.total_new == 0
        assert d.total_resolved == 0

    def test_mixed(self):
        prev = [
            _f("a.com", "web", "XSS"),
            _f("a.com", "web", "Open port 80"),
        ]
        curr = [
            _f("a.com", "web", "Open port 80"),       # unchanged
            _f("a.com", "web", "SQL injection"),      # new
        ]
        d = compute_diff("p", "c", prev, curr)
        assert d.total_new == 1
        assert d.total_resolved == 1
        assert d.total_unchanged == 1
        assert d.new[0]["title"] == "SQL injection"
        assert d.resolved[0]["title"] == "XSS"

    def test_matches_via_existing_fingerprint(self):
        dedup = FindingDeduplicator()
        prev_finding = _f("a.com", "web", "Open port 80")
        prev_finding["fingerprint"] = dedup.fingerprint(prev_finding)
        curr_finding = _f("a.com", "web", "Open port 80")
        curr_finding["fingerprint"] = dedup.fingerprint(curr_finding)
        d = compute_diff("p", "c", [prev_finding], [curr_finding])
        assert d.total_unchanged == 1

    def test_target_change_makes_new_finding(self):
        prev = [_f("a.com", "web", "XSS")]
        curr = [_f("b.com", "web", "XSS")]
        d = compute_diff("p", "c", prev, curr)
        assert d.total_new == 1
        assert d.total_resolved == 1

    def test_title_word_order_doesnt_matter(self):
        # FindingDeduplicator normalizes titles to sorted token sets.
        prev = [_f("a.com", "web", "SQL injection found")]
        curr = [_f("a.com", "web", "found injection SQL")]
        d = compute_diff("p", "c", prev, curr)
        assert d.total_unchanged == 1


class TestEngagementDiff:
    def test_severity_counts(self):
        d = EngagementDiff(
            prev_engagement_id="p",
            curr_engagement_id="c",
            new=[_f("t", "web", "x", "critical"), _f("t", "web", "y", "critical"), _f("t", "web", "z", "high")],
        )
        assert d.severity_counts("new") == {"critical": 2, "high": 1}

    def test_to_dict_shape(self):
        d = compute_diff("p", "c", [_f("a", "x", "old")], [_f("a", "x", "new1")])
        out = d.to_dict()
        assert out["prev_engagement_id"] == "p"
        assert out["curr_engagement_id"] == "c"
        assert out["summary"] == {"new": 1, "resolved": 1, "unchanged": 0}
        assert "by_severity" in out
        assert isinstance(out["new"], list)


@pytest.mark.asyncio
class TestRetestFlowIntegration:
    async def test_create_engagement_links_parent(self, tmp_path):
        from engine.findings_db import FindingsDB

        db = FindingsDB(str(tmp_path / "f.db"))
        try:
            parent = await db.create_engagement(target="example.com", scope="web")
            child = await db.create_engagement(
                target="example.com",
                scope="web",
                parent_engagement_id=parent["id"],
            )
            assert child["parent_engagement_id"] == parent["id"]
            fetched = await db.get_engagement(child["id"])
            assert fetched["parent_engagement_id"] == parent["id"]
        finally:
            await db.close()

    async def test_diff_against_real_db(self, tmp_path):
        from engine.findings_db import FindingsDB

        db = FindingsDB(str(tmp_path / "f.db"))
        try:
            e1 = await db.create_engagement(target="example.com")
            e2 = await db.create_engagement(target="example.com", parent_engagement_id=e1["id"])

            await db.add_finding({**_f("example.com", "web", "XSS"), "engagement_id": e1["id"]})
            await db.add_finding({**_f("example.com", "web", "Open port 80"), "engagement_id": e1["id"]})
            await db.add_finding({**_f("example.com", "web", "Open port 80"), "engagement_id": e2["id"]})
            await db.add_finding({**_f("example.com", "web", "SQL injection"), "engagement_id": e2["id"]})

            prev = await db.get_findings(engagement_id=e1["id"])
            curr = await db.get_findings(engagement_id=e2["id"])
            d = compute_diff(e1["id"], e2["id"], prev, curr)
            assert d.total_new == 1
            assert d.total_resolved == 1
            assert d.total_unchanged == 1
        finally:
            await db.close()

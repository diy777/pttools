"""Diff/retest support for pentest-tools engagements.

Given two engagements (typically a previous run and a re-test), compute
which findings are *new* (only in curr), *resolved* (only in prev), and
*unchanged* (present in both). Matching uses the same fingerprint that
the dedup engine uses, so the contract is consistent: target +
category + sorted title tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.dedup import FindingDeduplicator


@dataclass
class EngagementDiff:
    prev_engagement_id: str
    curr_engagement_id: str
    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return len(self.new)

    @property
    def total_resolved(self) -> int:
        return len(self.resolved)

    @property
    def total_unchanged(self) -> int:
        return len(self.unchanged)

    def severity_counts(self, bucket: str) -> dict[str, int]:
        items = getattr(self, bucket)
        out: dict[str, int] = {}
        for f in items:
            sev = (f.get("severity") or "info").lower()
            out[sev] = out.get(sev, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "prev_engagement_id": self.prev_engagement_id,
            "curr_engagement_id": self.curr_engagement_id,
            "summary": {
                "new": self.total_new,
                "resolved": self.total_resolved,
                "unchanged": self.total_unchanged,
            },
            "by_severity": {
                "new": self.severity_counts("new"),
                "resolved": self.severity_counts("resolved"),
                "unchanged": self.severity_counts("unchanged"),
            },
            "new": self.new,
            "resolved": self.resolved,
            "unchanged": self.unchanged,
        }


def compute_diff(
    prev_engagement_id: str,
    curr_engagement_id: str,
    prev_findings: list[dict[str, Any]],
    curr_findings: list[dict[str, Any]],
) -> EngagementDiff:
    """Bucket findings into new / resolved / unchanged via dedup fingerprint."""
    dedup = FindingDeduplicator()

    def index(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for f in items:
            fp = f.get("fingerprint") or dedup.fingerprint(f)
            # First write wins so we don't lose a finding if two share an fp.
            out.setdefault(fp, f)
        return out

    prev_idx = index(prev_findings)
    curr_idx = index(curr_findings)

    new: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    for fp, f in curr_idx.items():
        if fp in prev_idx:
            unchanged.append(f)
        else:
            new.append(f)

    resolved = [f for fp, f in prev_idx.items() if fp not in curr_idx]

    return EngagementDiff(
        prev_engagement_id=prev_engagement_id,
        curr_engagement_id=curr_engagement_id,
        new=new,
        resolved=resolved,
        unchanged=unchanged,
    )

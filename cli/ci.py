"""CI/CD integration helpers for pentest-tools.

Turns an engagement into a CI gate: generates SARIF, counts findings
at/above a severity threshold, writes GITHUB_OUTPUT when running inside
GitHub Actions, and optionally posts a PR comment via the GitHub API.
Exit codes follow the convention (0 = clean, 1 = findings gated).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from engine.sarif import findings_to_sarif

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def meets_threshold(severity: str, threshold: str) -> bool:
    """True if ``severity`` is at or worse than ``threshold``."""
    sev = (severity or "info").lower()
    th = (threshold or "high").lower()
    s_rank = SEVERITY_RANK.get(sev, len(SEVERITY_ORDER))
    t_rank = SEVERITY_RANK.get(th, len(SEVERITY_ORDER))
    return s_rank <= t_rank


@dataclass
class CIReport:
    engagement_id: str
    target: str
    threshold: str
    findings: list[dict[str, Any]]
    counts: dict[str, int] = field(default_factory=dict)
    gated: int = 0
    sarif_path: str | None = None
    exit_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target": self.target,
            "threshold": self.threshold,
            "counts": self.counts,
            "gated_findings": self.gated,
            "total_findings": len(self.findings),
            "sarif_path": self.sarif_path,
            "exit_code": self.exit_code,
        }


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in out:
            out[sev] += 1
    return out


def build_report(
    engagement: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    threshold: str = "high",
    sarif_output: str | None = None,
) -> CIReport:
    counts = count_by_severity(findings)
    gated = sum(1 for f in findings if meets_threshold(f.get("severity", "info"), threshold))

    sarif_path = None
    if sarif_output:
        sarif_doc = findings_to_sarif(findings, engagement)
        p = Path(sarif_output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        sarif_path = str(p)

    return CIReport(
        engagement_id=engagement.get("id", ""),
        target=engagement.get("target", ""),
        threshold=threshold,
        findings=findings,
        counts=counts,
        gated=gated,
        sarif_path=sarif_path,
        exit_code=1 if gated > 0 else 0,
    )


def render_markdown(report: CIReport) -> str:
    lines = [
        f"## pentest-tools CI Report — `{report.target}`",
        "",
        f"**Engagement:** `{report.engagement_id}`  |  "
        f"**Threshold:** `{report.threshold}`  |  "
        f"**Gated findings:** **{report.gated}**",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {report.counts.get(sev, 0)} |")

    if report.findings:
        lines.extend(["", "### Top findings", "", "| Severity | Title | Target |", "|---|---|---|"])
        top = sorted(
            report.findings,
            key=lambda f: SEVERITY_RANK.get((f.get("severity") or "info").lower(), 99),
        )[:20]
        for f in top:
            lines.append(
                f"| {f.get('severity', 'info')} | "
                f"{_md_escape(f.get('title', ''))} | "
                f"{_md_escape(f.get('target', ''))} |"
            )

    return "\n".join(lines)


def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")[:200]


def write_github_output(report: CIReport) -> bool:
    """Emit step outputs via the GITHUB_OUTPUT file. No-op outside Actions."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return False
    lines = [
        f"engagement_id={report.engagement_id}",
        f"target={report.target}",
        f"threshold={report.threshold}",
        f"gated={report.gated}",
        f"total={len(report.findings)}",
        f"exit_code={report.exit_code}",
    ]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return True


async def post_pr_comment(
    report: CIReport,
    *,
    repo: str | None = None,
    pr_number: int | None = None,
    token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """Post the markdown report as a PR comment. Returns True on success."""
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    token = token or os.environ.get("GITHUB_TOKEN")
    if pr_number is None:
        ref = os.environ.get("GITHUB_REF", "")
        if "/pull/" in ref:
            try:
                pr_number = int(ref.split("/pull/")[1].split("/")[0])
            except (IndexError, ValueError):
                pr_number = None

    if not (repo and pr_number and token):
        return False

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {"body": render_markdown(report)}

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=15.0)

    try:
        resp = await client.post(url, headers=headers, json=body)
        return 200 <= resp.status_code < 300
    finally:
        if owns_client:
            await client.aclose()

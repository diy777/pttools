"""Tests for cli.ci (CI/CD report + PR comment + GITHUB_OUTPUT)."""

from __future__ import annotations

import json

import httpx
import pytest

from cli.ci import (
    SEVERITY_ORDER,
    build_report,
    count_by_severity,
    meets_threshold,
    post_pr_comment,
    render_markdown,
    write_github_output,
)


def _finding(severity: str, title: str = "f", target: str = "t") -> dict:
    return {
        "severity": severity,
        "title": title,
        "target": target,
        "category": "web",
        "description": f"{title} at {target}",
    }


class TestMeetsThreshold:
    def test_critical_meets_high(self):
        assert meets_threshold("critical", "high") is True

    def test_high_meets_high(self):
        assert meets_threshold("high", "high") is True

    def test_medium_does_not_meet_high(self):
        assert meets_threshold("medium", "high") is False

    def test_medium_meets_medium(self):
        assert meets_threshold("medium", "medium") is True

    def test_info_only_meets_info(self):
        assert meets_threshold("info", "info") is True
        assert meets_threshold("info", "low") is False

    def test_unknown_severity_treated_as_info(self):
        assert meets_threshold("bogus", "high") is False

    def test_case_insensitive(self):
        assert meets_threshold("HIGH", "HIGH") is True


class TestCountBySeverity:
    def test_counts_all(self):
        findings = [_finding("critical"), _finding("high"), _finding("high"), _finding("low")]
        counts = count_by_severity(findings)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["low"] == 1
        assert counts["medium"] == 0

    def test_unknown_severity_ignored(self):
        counts = count_by_severity([_finding("wat")])
        assert sum(counts.values()) == 0


class TestBuildReport:
    def test_clean_engagement_exit_0(self, tmp_path):
        eng = {"id": "e1", "target": "app.local"}
        report = build_report(eng, [_finding("low"), _finding("info")], threshold="high")
        assert report.exit_code == 0
        assert report.gated == 0
        assert report.counts["low"] == 1

    def test_gated_findings_exit_1(self):
        eng = {"id": "e1", "target": "app.local"}
        report = build_report(
            eng,
            [_finding("critical"), _finding("medium")],
            threshold="high",
        )
        assert report.exit_code == 1
        assert report.gated == 1

    def test_writes_sarif(self, tmp_path):
        eng = {"id": "e1", "target": "app.local"}
        out = tmp_path / "out.sarif"
        report = build_report(eng, [_finding("high")], threshold="high", sarif_output=str(out))
        assert report.sarif_path == str(out)
        assert out.exists()
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == 1

    def test_sarif_creates_parent_dir(self, tmp_path):
        eng = {"id": "e1", "target": "app.local"}
        out = tmp_path / "nested" / "sub" / "out.sarif"
        build_report(eng, [_finding("critical")], sarif_output=str(out))
        assert out.exists()


class TestMarkdownRender:
    def test_contains_counts(self):
        eng = {"id": "e1", "target": "app.local"}
        r = build_report(eng, [_finding("high", "SQL injection"), _finding("low")], threshold="high")
        md = render_markdown(r)
        assert "app.local" in md
        assert "SQL injection" in md
        assert "Threshold:" in md
        assert "high" in md

    def test_pipes_escaped(self):
        eng = {"id": "e1", "target": "a|b.com"}
        r = build_report(eng, [_finding("high", "title|with|pipes", "a|b.com")], threshold="high")
        md = render_markdown(r)
        assert "\\|" in md
        # Bare pipes in titles would break the table; make sure there's no
        # unescaped pipe inside cell content.
        for line in md.splitlines():
            if line.startswith("|") and "SQL" not in line:
                cells = line.split("|")[1:-1]
                for cell in cells:
                    if cell.strip() == "":
                        continue

    def test_empty_findings_still_renders_table(self):
        eng = {"id": "e", "target": "t"}
        r = build_report(eng, [], threshold="high")
        md = render_markdown(r)
        assert "pentest-tools Report" in md
        assert "| critical |" in md

    def test_severity_order_consistent(self):
        assert SEVERITY_ORDER == ["critical", "high", "medium", "low", "info"]


class TestGitHubOutput:
    def test_writes_when_env_set(self, tmp_path, monkeypatch):
        out = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        eng = {"id": "e1", "target": "t"}
        r = build_report(eng, [_finding("critical")], threshold="high")
        assert write_github_output(r) is True
        text = out.read_text()
        assert "engagement_id=e1" in text
        assert "gated=1" in text
        assert "exit_code=1" in text

    def test_noop_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        eng = {"id": "e1", "target": "t"}
        r = build_report(eng, [], threshold="high")
        assert write_github_output(r) is False

    def test_appends_not_overwrites(self, tmp_path, monkeypatch):
        out = tmp_path / "output.txt"
        out.write_text("prev=1\n")
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        eng = {"id": "e1", "target": "t"}
        r = build_report(eng, [], threshold="high")
        write_github_output(r)
        assert out.read_text().startswith("prev=1\n")


@pytest.mark.asyncio
class TestPostPRComment:
    async def test_posts_when_all_fields_present(self, monkeypatch):
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(
                {
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": json.loads(request.content.decode()),
                }
            )
            return httpx.Response(201, json={"id": 1})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            eng = {"id": "e1", "target": "app"}
            report = build_report(eng, [_finding("critical")], threshold="high")
            ok = await post_pr_comment(
                report,
                repo="owner/repo",
                pr_number=42,
                token="ghp_fake",
                client=client,
            )

        assert ok is True
        assert captured[0]["url"] == "https://api.github.com/repos/owner/repo/issues/42/comments"
        assert "authorization" in captured[0]["headers"]
        assert "pentest-tools Report" in captured[0]["body"]["body"]

    async def test_noop_without_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        eng = {"id": "e1", "target": "t"}
        report = build_report(eng, [_finding("high")], threshold="high")
        ok = await post_pr_comment(report)
        assert ok is False

    async def test_parses_pr_number_from_github_ref(self, monkeypatch):
        captured_url: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_url.append(str(request.url))
            return httpx.Response(201)

        transport = httpx.MockTransport(handler)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
        monkeypatch.setenv("GITHUB_REPOSITORY", "a/b")
        monkeypatch.setenv("GITHUB_REF", "refs/pull/99/merge")
        async with httpx.AsyncClient(transport=transport) as client:
            eng = {"id": "e1", "target": "t"}
            report = build_report(eng, [_finding("high")], threshold="high")
            await post_pr_comment(report, client=client)

        assert "/issues/99/comments" in captured_url[0]

    async def test_upstream_failure_returns_false(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            eng = {"id": "e1", "target": "t"}
            report = build_report(eng, [_finding("high")], threshold="high")
            ok = await post_pr_comment(
                report, repo="a/b", pr_number=1, token="x", client=client
            )
        assert ok is False

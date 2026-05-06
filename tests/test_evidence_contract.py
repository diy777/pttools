"""Tests for the evidence-required contract on add_finding().

Blocks orphan/hallucinated findings from LLM agents that have severity
critical/high/medium or claim a deterministic tool_source but carry no
evidence, poc, raw_output, or tool_result_id.
"""

from __future__ import annotations

import pytest

from engine.findings_db import (
    DETERMINISTIC_TOOL_SOURCES,
    EvidenceMissingError,
    FindingsDB,
    _evidence_present,
    _validate_finding_evidence,
)


def test_evidence_present_detects_all_four_channels():
    assert _evidence_present({"evidence": "hit"})
    assert _evidence_present({"poc": "curl ..."})
    assert _evidence_present({"raw_output": "...stdout..."})
    assert _evidence_present({"tool_result_id": "abc123"})
    assert not _evidence_present({})
    assert not _evidence_present({"evidence": "   "})


def test_low_and_info_findings_always_pass():
    # info/low severity and unknown tool_source → skip gate entirely
    for sev in ("info", "low"):
        out = _validate_finding_evidence({"severity": sev, "title": "t"})
        assert out.get("status") != "unverified"


def test_lax_mode_coerces_to_unverified(monkeypatch):
    monkeypatch.delenv("PTAI_STRICT_EVIDENCE", raising=False)
    f = {"severity": "high", "title": "Fabricated XSS"}
    out = _validate_finding_evidence(f)
    assert out["status"] == "unverified"


def test_strict_mode_raises(monkeypatch):
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    with pytest.raises(EvidenceMissingError, match="no evidence"):
        _validate_finding_evidence({"severity": "critical", "title": "x"})


def test_deterministic_source_gated_even_at_info(monkeypatch):
    """LLM fabricates dns_check finding with severity=info but no evidence."""
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    with pytest.raises(EvidenceMissingError):
        _validate_finding_evidence({
            "severity": "info",
            "tool_source": "pentest-tools-dns-check",
            "title": "Fake DNS record",
        })


def test_deterministic_source_passes_with_tool_result_id(monkeypatch):
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    out = _validate_finding_evidence({
        "severity": "info",
        "tool_source": "pentest-tools-dns-check",
        "tool_result_id": "abc",
        "title": "Real DNS",
    })
    assert out["title"] == "Real DNS"


def test_known_sources_set_matches_constants():
    # Sanity check that we catch common scanners
    assert "authenticated_scan" in DETERMINISTIC_TOOL_SOURCES
    assert "pentest-tools-dns-check" in DETERMINISTIC_TOOL_SOURCES
    assert "sqlmap" in DETERMINISTIC_TOOL_SOURCES


@pytest.mark.asyncio
async def test_add_finding_lax_marks_unverified(tmp_path, monkeypatch):
    monkeypatch.delenv("PTAI_STRICT_EVIDENCE", raising=False)
    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        await db.add_finding({
            "engagement_id": eng["id"],
            "title": "Critical orphan",
            "severity": "critical",
            "category": "injection",
            "target": "app.local",
        })
        rows = await db.get_findings(engagement_id=eng["id"])
        assert len(rows) == 1
        assert rows[0]["status"] == "unverified"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_add_finding_strict_rejects(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        with pytest.raises(EvidenceMissingError):
            await db.add_finding({
                "engagement_id": eng["id"],
                "title": "Critical orphan",
                "severity": "high",
                "category": "injection",
                "target": "app.local",
            })
        rows = await db.get_findings(engagement_id=eng["id"])
        assert rows == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_add_finding_with_evidence_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        fid = await db.add_finding({
            "engagement_id": eng["id"],
            "title": "Real SQLi",
            "severity": "critical",
            "category": "injection",
            "target": "app.local/vulnerabilities/sqli/",
            "evidence": "TRUE payload 42 chars / FALSE payload 0 chars",
            "tool_source": "authenticated_scan",
        })
        assert fid
        rows = await db.get_findings(engagement_id=eng["id"])
        assert len(rows) == 1
        assert rows[0]["status"] == "confirmed"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_tool_result_id_column_persists(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAI_STRICT_EVIDENCE", "1")
    db = FindingsDB(str(tmp_path / "f.db"))
    try:
        eng = await db.create_engagement(target="app.local")
        await db.add_finding({
            "engagement_id": eng["id"],
            "title": "Linked finding",
            "severity": "high",
            "category": "recon",
            "target": "app.local",
            "tool_result_id": "tr-xyz",
            "tool_source": "nmap",
        })
        rows = await db.get_findings(engagement_id=eng["id"])
        assert rows[0]["tool_result_id"] == "tr-xyz"
    finally:
        await db.close()

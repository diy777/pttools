"""Tests for finding deduplication and CWE mapping (engine/dedup.py)."""

import pytest

from engine.dedup import FindingDeduplicator


@pytest.fixture
def dedup():
    return FindingDeduplicator()


class TestFingerprinting:
    def test_same_finding_same_fingerprint(self, dedup):
        f1 = {"target": "example.com", "category": "injection", "title": "SQL Injection on login"}
        f2 = {"target": "example.com", "category": "injection", "title": "SQL Injection on login"}
        assert dedup.fingerprint(f1) == dedup.fingerprint(f2)

    def test_different_target_different_fingerprint(self, dedup):
        f1 = {"target": "a.com", "category": "injection", "title": "SQLi"}
        f2 = {"target": "b.com", "category": "injection", "title": "SQLi"}
        assert dedup.fingerprint(f1) != dedup.fingerprint(f2)

    def test_different_category_different_fingerprint(self, dedup):
        f1 = {"target": "example.com", "category": "injection", "title": "test"}
        f2 = {"target": "example.com", "category": "xss", "title": "test"}
        assert dedup.fingerprint(f1) != dedup.fingerprint(f2)

    def test_title_word_order_doesnt_matter(self, dedup):
        f1 = {"target": "example.com", "category": "injection", "title": "SQL injection found"}
        f2 = {"target": "example.com", "category": "injection", "title": "found SQL injection"}
        assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


class TestDuplicateDetection:
    def test_exact_duplicate(self, dedup):
        f1 = {"id": "f-1", "target": "example.com", "category": "injection", "title": "SQL Injection"}
        is_dup_first, _ = dedup.is_duplicate(f1)
        assert not is_dup_first
        is_dup_second, original = dedup.is_duplicate(f1)
        assert is_dup_second

    def test_not_duplicate(self, dedup):
        f1 = {"id": "f-1", "target": "example.com", "category": "injection", "title": "SQL Injection"}
        f2 = {"id": "f-2", "target": "other.com", "category": "xss", "title": "Reflected XSS"}
        dedup.is_duplicate(f1)
        is_dup, _ = dedup.is_duplicate(f2)
        assert not is_dup

    def test_fuzzy_duplicate(self, dedup):
        f1 = {"id": "f-1", "target": "example.com", "category": "injection", "title": "SQL Injection on login page"}
        f2 = {"id": "f-2", "target": "example.com", "category": "injection", "title": "SQL Injection on login form"}
        result = dedup.check_fuzzy_duplicate(f2, [f1])
        assert result is not None


class TestCWEMapping:
    def test_sql_injection_mapping(self, dedup):
        f = {"target": "x", "category": "injection", "title": "SQL Injection", "description": "SQL injection found"}
        enriched = dedup.enrich(f)
        assert enriched.get("cwe_id") == "CWE-89"

    def test_xss_mapping(self, dedup):
        f = {"target": "x", "category": "xss", "title": "Cross-site scripting", "description": "XSS reflected"}
        enriched = dedup.enrich(f)
        assert enriched.get("cwe_id") == "CWE-79"

    def test_ssrf_mapping(self, dedup):
        f = {"target": "x", "category": "ssrf", "title": "SSRF", "description": "Server-side request forgery"}
        enriched = dedup.enrich(f)
        assert enriched.get("cwe_id") == "CWE-918"

    def test_owasp_mapping(self, dedup):
        f = {"target": "x", "category": "injection", "title": "SQL Injection", "description": "injection attack"}
        enriched = dedup.enrich(f)
        assert enriched.get("owasp_category") is not None

    def test_fingerprint_added(self, dedup):
        f = {"target": "x", "category": "test", "title": "Test finding", "description": "test"}
        enriched = dedup.enrich(f)
        assert "fingerprint" in enriched

    def test_unknown_category_no_crash(self, dedup):
        f = {"target": "x", "category": "unknown", "title": "Unknown thing", "description": "no match expected"}
        enriched = dedup.enrich(f)
        assert "fingerprint" in enriched

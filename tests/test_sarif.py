"""Tests for SARIF and JUnit XML export."""

import json
import xml.etree.ElementTree as ET

from engine.junit_xml import findings_to_junit
from engine.sarif import SARIF_VERSION, findings_to_sarif

SAMPLE_ENGAGEMENT = {"id": "eng-1", "target": "10.0.0.1", "scope": "full"}

SAMPLE_FINDINGS = [
    {
        "title": "SQL Injection",
        "description": "Parameter 'id' vulnerable to SQL injection",
        "severity": "critical",
        "category": "web",
        "target": "10.0.0.1/users",
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "remediation": "Use parameterized queries",
        "compliance_mapping": {"pci_dss": ["6.5.1"]},
    },
    {
        "title": "Missing HSTS",
        "description": "HTTP Strict-Transport-Security header not set",
        "severity": "low",
        "category": "web",
        "target": "10.0.0.1",
        "cwe_id": "CWE-693",
        "cvss_score": 3.0,
    },
]


class TestSarif:
    def test_valid_sarif_structure(self):
        sarif = findings_to_sarif(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "pentest-tools"
        assert len(run["results"]) == 2

    def test_rules_deduplication(self):
        findings = [
            {"title": "SQLi 1", "severity": "critical", "cwe_id": "CWE-89", "category": "web"},
            {"title": "SQLi 2", "severity": "critical", "cwe_id": "CWE-89", "category": "web"},
        ]
        sarif = findings_to_sarif(findings, SAMPLE_ENGAGEMENT)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_severity_mapping(self):
        sarif = findings_to_sarif(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "note"

    def test_properties_include_cvss(self):
        sarif = findings_to_sarif(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["cvss_score"] == 9.8

    def test_empty_findings(self):
        sarif = findings_to_sarif([], SAMPLE_ENGAGEMENT)
        assert len(sarif["runs"][0]["results"]) == 0

    def test_serializable(self):
        sarif = findings_to_sarif(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        json_str = json.dumps(sarif)
        assert len(json_str) > 0


class TestJunitXml:
    def test_valid_xml(self):
        xml_str = findings_to_junit(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuite"
        assert root.get("tests") == "2"

    def test_failure_count(self):
        xml_str = findings_to_junit(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        root = ET.fromstring(xml_str)
        assert root.get("failures") == "1"

    def test_critical_finding_is_failure(self):
        xml_str = findings_to_junit(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        root = ET.fromstring(xml_str)
        testcases = root.findall("testcase")
        sqli_tc = [tc for tc in testcases if tc.get("name") == "SQL Injection"][0]
        assert sqli_tc.find("failure") is not None

    def test_low_finding_is_not_failure(self):
        xml_str = findings_to_junit(SAMPLE_FINDINGS, SAMPLE_ENGAGEMENT)
        root = ET.fromstring(xml_str)
        testcases = root.findall("testcase")
        hsts_tc = [tc for tc in testcases if tc.get("name") == "Missing HSTS"][0]
        assert hsts_tc.find("failure") is None

    def test_empty_findings(self):
        xml_str = findings_to_junit([], SAMPLE_ENGAGEMENT)
        root = ET.fromstring(xml_str)
        assert root.get("tests") == "0"
        assert root.get("failures") == "0"

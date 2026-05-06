"""JUnit XML export for pentest findings.

Converts findings into JUnit XML format so CI systems (Jenkins, GitHub Actions,
GitLab CI) can display security findings as test results.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

FAILURE_SEVERITIES = frozenset({"critical", "high"})


def findings_to_junit(
    findings: list[dict[str, Any]],
    engagement: dict[str, Any],
) -> str:
    suite = ET.Element("testsuite")
    suite.set("name", f"pentest-tools: {engagement.get('target', 'unknown')}")
    suite.set("tests", str(len(findings)))

    failures = sum(1 for f in findings if f.get("severity") in FAILURE_SEVERITIES)
    suite.set("failures", str(failures))
    suite.set("errors", "0")

    for finding in findings:
        tc = ET.SubElement(suite, "testcase")
        tc.set("name", finding.get("title", "Unknown"))
        tc.set("classname", f"pentest-tools.{finding.get('category', 'general')}")
        tc.set("time", "0")

        severity = finding.get("severity", "info")
        if severity in FAILURE_SEVERITIES:
            fail = ET.SubElement(tc, "failure")
            fail.set("message", f"[{severity.upper()}] {finding.get('title', '')}")
            fail.set("type", finding.get("cwe_id", severity))
            parts = [finding.get("description", "")]
            if finding.get("target"):
                parts.append(f"Target: {finding['target']}")
            if finding.get("cvss_score"):
                parts.append(f"CVSS: {finding['cvss_score']}")
            if finding.get("remediation"):
                parts.append(f"Remediation: {finding['remediation']}")
            fail.text = "\n".join(parts)
        else:
            props = ET.SubElement(tc, "system-out")
            props.text = f"[{severity.upper()}] {finding.get('description', '')}"

    return ET.tostring(suite, encoding="unicode", xml_declaration=True)

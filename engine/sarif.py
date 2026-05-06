"""SARIF v2.1.0 export for pentest findings.

Converts pentest-tools findings into Static Analysis Results Interchange Format
for CI/CD integration with GitHub Code Scanning, Azure DevOps, etc.
"""

from __future__ import annotations

from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def findings_to_sarif(
    findings: list[dict[str, Any]],
    engagement: dict[str, Any],
) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    for finding in findings:
        rule_id = finding.get("cwe_id") or f"pentest-tools/{finding.get('category', 'general')}"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rule_def: dict[str, Any] = {
                "id": rule_id,
                "name": finding.get("title", "Unknown"),
                "shortDescription": {"text": finding.get("title", "Unknown")},
                "fullDescription": {"text": finding.get("description", "")[:1000] or finding.get("title", "")},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "info"), "note"),
                },
            }
            if finding.get("remediation"):
                rule_def["help"] = {"text": finding["remediation"][:2000]}
            rules.append(rule_def)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "info"), "note"),
            "message": {"text": finding.get("description", finding.get("title", ""))},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("target", engagement.get("target", "")),
                        },
                    },
                },
            ],
        }

        props: dict[str, Any] = {}
        if finding.get("cvss_score"):
            props["cvss_score"] = finding["cvss_score"]
        if finding.get("cwe_id"):
            props["cwe_id"] = finding["cwe_id"]
        if finding.get("compliance_mapping"):
            props["compliance"] = finding["compliance_mapping"]
        if props:
            result["properties"] = props

        results.append(result)

    # Resolve the installed package version dynamically so SARIF doesn't lie
    # about the tool that produced it. Falls back to "unknown" only if the
    # package metadata is genuinely missing (editable install during dev).
    try:
        from importlib.metadata import version as _pkg_version
        _pttools_version = _pkg_version("pttools")
    except Exception:
        _pttools_version = "unknown"

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pentest-tools",
                        "version": _pttools_version,
                        "informationUri": "https://github.com/pentest-tools/pentest-tools",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "engagement_id": engagement.get("id", ""),
                            "target": engagement.get("target", ""),
                            "scope": engagement.get("scope", "full"),
                        },
                    },
                ],
            },
        ],
    }

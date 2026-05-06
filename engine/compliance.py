"""Compliance framework mapping for findings.

Maps CWE IDs and finding categories to PCI-DSS, HIPAA, SOC2, and OWASP controls.
"""

from __future__ import annotations

from typing import Any

CWE_TO_PCI: dict[str, list[str]] = {
    "CWE-89": ["6.5.1"],
    "CWE-79": ["6.5.7"],
    "CWE-78": ["6.5.1"],
    "CWE-22": ["6.5.8"],
    "CWE-918": ["6.5.9"],
    "CWE-611": ["6.5.1"],
    "CWE-502": ["6.5.1"],
    "CWE-352": ["6.5.9"],
    "CWE-287": ["8.1", "8.2"],
    "CWE-862": ["7.1", "7.2"],
    "CWE-200": ["3.4", "6.5.3"],
    "CWE-327": ["4.1", "6.5.3"],
    "CWE-798": ["2.1", "8.2.1"],
    "CWE-693": ["6.5.10"],
    "CWE-295": ["4.1"],
    "CWE-434": ["6.5.8"],
    "CWE-1392": ["2.1"],
    "CWE-307": ["8.1.6"],
    "CWE-522": ["8.2.1"],
}

CWE_TO_HIPAA: dict[str, list[str]] = {
    "CWE-89": ["164.312(a)(1)"],
    "CWE-79": ["164.312(a)(1)"],
    "CWE-78": ["164.312(a)(1)"],
    "CWE-287": ["164.312(d)"],
    "CWE-862": ["164.312(a)(1)"],
    "CWE-200": ["164.312(e)(1)", "164.502"],
    "CWE-327": ["164.312(e)(1)"],
    "CWE-798": ["164.312(d)"],
    "CWE-295": ["164.312(e)(1)"],
    "CWE-307": ["164.312(d)"],
    "CWE-522": ["164.312(d)"],
}

CWE_TO_SOC2: dict[str, list[str]] = {
    "CWE-89": ["CC6.1"],
    "CWE-79": ["CC6.1"],
    "CWE-78": ["CC6.1"],
    "CWE-287": ["CC6.1", "CC6.2"],
    "CWE-862": ["CC6.3"],
    "CWE-200": ["CC6.5", "CC6.7"],
    "CWE-327": ["CC6.7"],
    "CWE-798": ["CC6.1"],
    "CWE-295": ["CC6.7"],
    "CWE-307": ["CC6.1"],
}

CATEGORY_COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "network": {
        "pci_dss": ["1.1", "1.2", "11.2"],
        "hipaa": ["164.312(e)(1)"],
        "soc2": ["CC6.6"],
        "owasp": ["A05:2021"],
    },
    "web": {
        "pci_dss": ["6.5", "6.6"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.1"],
        "owasp": ["A03:2021"],
    },
    "authentication": {
        "pci_dss": ["8.1", "8.2"],
        "hipaa": ["164.312(d)"],
        "soc2": ["CC6.1", "CC6.2"],
        "owasp": ["A07:2021"],
    },
    "encryption": {
        "pci_dss": ["4.1"],
        "hipaa": ["164.312(e)(1)"],
        "soc2": ["CC6.7"],
        "owasp": ["A02:2021"],
    },
    # Categories that real findings actually use. Without these, query_compliance
    # returned empty for nikto/nuclei output, which classifies findings as
    # "vulnerability" or "discovery" rather than the abstract types above.
    "vulnerability": {
        "pci_dss": ["6.1", "6.2", "11.2"],
        "hipaa": ["164.308(a)(1)"],
        "soc2": ["CC7.1"],
        "owasp": ["A06:2021"],  # Vulnerable and Outdated Components
    },
    "discovery": {
        "pci_dss": ["11.2"],
        "hipaa": ["164.308(a)(8)"],
        "soc2": ["CC4.1"],
        "owasp": ["A05:2021"],  # Security Misconfiguration
    },
    "injection": {
        "pci_dss": ["6.5.1"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.1"],
        "owasp": ["A03:2021"],
    },
    "xss": {
        "pci_dss": ["6.5.7"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.1"],
        "owasp": ["A03:2021"],
    },
    "ssrf": {
        "pci_dss": ["6.5.9"],
        "soc2": ["CC6.6"],
        "owasp": ["A10:2021"],
    },
    "authz": {
        "pci_dss": ["7.1", "7.2"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.3"],
        "owasp": ["A01:2021"],
    },
    "authorization": {
        "pci_dss": ["7.1", "7.2"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.3"],
        "owasp": ["A01:2021"],
    },
    "secrets": {
        "pci_dss": ["3.4", "8.2.1"],
        "hipaa": ["164.312(e)(1)"],
        "soc2": ["CC6.7"],
        "owasp": ["A02:2021"],
    },
    "headers": {
        "pci_dss": ["6.5.10"],
        "soc2": ["CC6.7"],
        "owasp": ["A05:2021"],
    },
    "ssl": {
        "pci_dss": ["4.1"],
        "hipaa": ["164.312(e)(1)"],
        "soc2": ["CC6.7"],
        "owasp": ["A02:2021"],
    },
}


def map_finding_compliance(finding: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    cwe = finding.get("cwe_id", "")
    owasp = finding.get("owasp_category", "")
    category = finding.get("category", "").lower()

    if cwe:
        if cwe in CWE_TO_PCI:
            result.setdefault("pci_dss", []).extend(CWE_TO_PCI[cwe])
        if cwe in CWE_TO_HIPAA:
            result.setdefault("hipaa", []).extend(CWE_TO_HIPAA[cwe])
        if cwe in CWE_TO_SOC2:
            result.setdefault("soc2", []).extend(CWE_TO_SOC2[cwe])

    if owasp:
        result["owasp"] = [owasp]

    if category in CATEGORY_COMPLIANCE:
        cat_map = CATEGORY_COMPLIANCE[category]
        for framework, controls in cat_map.items():
            result.setdefault(framework, []).extend(controls)

    for key in result:
        result[key] = sorted(set(result[key]))

    return result

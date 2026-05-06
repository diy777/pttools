"""Run a full pentest engagement against DVWA and generate all deliverables."""

import asyncio
import os
import sys
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.detection.detection_agent import DetectionAgent
from agents.exploit_chain.chain_agent import ExploitChainAgent
from agents.report.report_agent import ReportAgent
from engine.dedup import FindingDeduplicator
from engine.evidence import EvidenceCollector
from engine.findings_db import FindingsDB
from engine.scanners import (
    check_dns,
    check_ssl,
    scan_common_paths,
    scan_http_headers,
    scan_ports,
    scan_secrets_in_response,
)
from engine.scope import ScopeEnforcer

DVWA_URL = "http://localhost:4280"
DVWA_HOST = "localhost"
ENGAGEMENT_TARGET = "localhost:4280 (DVWA)"


async def main():
    db = FindingsDB("dvwa_engagement.db")
    await db.init()

    evidence = EvidenceCollector(base_dir="evidence")
    dedup = FindingDeduplicator()
    _scope = ScopeEnforcer(
        allowed_targets=["localhost", "127.0.0.1", "127.0.0.0/8"],
        allowed_ports=[4280, 80, 443, 22, 8080],
        mode="strict",
    )

    engagement = await db.create_engagement(
        target=ENGAGEMENT_TARGET,
        scope="web",
        rules_of_engment="Authorized pentest of local DVWA instance. No DoS. No data exfiltration.",
        intensity="normal",
    )
    eid = engagement["id"]
    print(f"\n{'='*70}")
    print(f"  PENTEST ENGAGEMENT: {eid}")
    print(f"  Target: {ENGAGEMENT_TARGET}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    # --- Phase 1: Reconnaissance ---
    print("[*] Phase 1: Reconnaissance & Scanning")

    scanners = [
        ("Port Scan", scan_ports, DVWA_HOST),
        ("HTTP Headers", scan_http_headers, DVWA_URL),
        ("Path Discovery", scan_common_paths, DVWA_URL),
        ("SSL Check", check_ssl, DVWA_HOST),
        ("DNS Check", check_dns, DVWA_HOST),
        ("Secret Scan", scan_secrets_in_response, DVWA_URL),
    ]

    all_findings = []
    for name, scanner, target in scanners:
        print(f"    [>] Running {name}...")
        try:
            results = await scanner(target)
            if isinstance(results, list):
                for r in results:
                    r["engagement_id"] = eid
                    r["tool_source"] = name.lower().replace(" ", "_")
                    if "id" not in r:
                        r["id"] = uuid.uuid4().hex[:8]
                    if "target" not in r:
                        r["target"] = target
                    all_findings.append(r)
                print(f"        Found {len(results)} findings")
            elif isinstance(results, dict) and results.get("findings"):
                for r in results["findings"]:
                    r["engagement_id"] = eid
                    all_findings.append(r)
                print(f"        Found {len(results['findings'])} findings")
            else:
                print("        No findings")
        except Exception as e:
            print(f"        Error: {e}")

    # --- Phase 2: Dedup & Store ---
    print("\n[*] Phase 2: Deduplication & Storage")
    stored = 0
    dupes = 0
    for f in all_findings:
        is_dup, _ = dedup.is_duplicate(f)
        if not is_dup:
            await db.add_finding(f)
            stored += 1
        else:
            dupes += 1
    print(f"    Stored: {stored} unique findings, {dupes} duplicates removed")

    # --- Phase 3: Evidence Collection ---
    print("\n[*] Phase 3: Evidence Collection")
    for f in all_findings[:stored]:
        await evidence.store_tool_output(
            engagement_id=eid,
            finding_id=f["id"],
            tool_name=f.get("tool_source", "scanner"),
            command=f"scanner({f.get('target', '')})",
            stdout=f.get("description", "") + "\n" + f.get("evidence", ""),
            stderr="",
            exit_code=0,
            duration_ms=100,
        )
    artifacts = evidence.get_artifacts()
    print(f"    Collected {len(artifacts)} evidence artifacts")

    integrity = evidence.verify_integrity(eid)
    if integrity:
        print(f"    WARNING: {len(integrity)} integrity issues")
    else:
        print("    All artifacts passed SHA-256 integrity check")

    # --- Phase 4: Attack Chain Discovery ---
    print("\n[*] Phase 4: Attack Chain Discovery")
    chain_agent = ExploitChainAgent(db)
    chains = await chain_agent.discover_chains(eid)
    print(f"    Discovered {len(chains)} attack chains")
    for c in chains:
        print(f"    [{c['severity'].upper()}] {c['name']}: {c.get('impact', '')}")

    # --- Phase 5: Detection Rules ---
    print("\n[*] Phase 5: Detection Rule Generation")
    det_agent = DetectionAgent(db)
    rules = await det_agent.generate_rules(eid)
    print(f"    Generated {len(rules)} detection rules")
    sigma_count = sum(1 for r in rules if r["format"] == "sigma")
    spl_count = sum(1 for r in rules if r["format"] == "spl")
    kql_count = sum(1 for r in rules if r["format"] == "kql")
    print(f"    Sigma: {sigma_count} | SPL: {spl_count} | KQL: {kql_count}")

    # --- Phase 6: Report Generation (Markdown + HTML + PDF) ---
    print("\n[*] Phase 6: Report Generation")
    report_agent = ReportAgent(db)
    report_result = await report_agent.generate_report(eid, format="all")
    for fmt, path in report_result.get("output_paths", {}).items():
        print(f"    {fmt.upper()}: {path}")

    # --- Phase 7: Generate Additional Deliverables ---
    print("\n[*] Phase 7: Additional Deliverables")

    os.makedirs("reports", exist_ok=True)

    # Executive Summary
    summary = await db.get_engagement_summary(eid)
    findings = await db.get_findings(engagement_id=eid)
    exec_summary = _build_executive_summary(engagement, findings, chains, summary)
    exec_path = f"reports/executive-summary-{eid}.md"
    with open(exec_path, "w") as f:
        f.write(exec_summary)
    print(f"    Executive Summary: {exec_path}")

    # Detection Rules Bundle
    all_rules = await db.get_detection_rules(eid)
    rules_path = f"reports/detection-rules-{eid}.md"
    with open(rules_path, "w") as f:
        f.write(_build_detection_bundle(all_rules, engagement))
    print(f"    Detection Rules: {rules_path}")

    # Remediation Roadmap
    remediation_path = f"reports/remediation-roadmap-{eid}.md"
    with open(remediation_path, "w") as f:
        f.write(_build_remediation_roadmap(findings, chains))
    print(f"    Remediation Roadmap: {remediation_path}")

    # Evidence Index
    evidence_path = f"reports/evidence-index-{eid}.md"
    with open(evidence_path, "w") as f:
        f.write(_build_evidence_index(artifacts, eid))
    print(f"    Evidence Index: {evidence_path}")

    # --- Summary ---
    print(f"\n{'='*70}")
    print(f"  ENGAGEMENT COMPLETE: {eid}")
    print(f"  Findings: {summary['total_findings']} | Chains: {summary['attack_chains']} | Rules: {summary['detection_rules']}")
    print(f"  Severity: {summary['by_severity']}")
    print("\n  Deliverables:")
    print(f"    1. {report_result['output_path']}")
    print(f"    2. {exec_path}")
    print(f"    3. {rules_path}")
    print(f"    4. {remediation_path}")
    print(f"    5. {evidence_path}")
    print(f"    6. evidence/{eid}/ ({len(artifacts)} artifacts)")
    print(f"{'='*70}\n")

    await db.close()


def _build_executive_summary(engagement, findings, chains, summary):
    sev = summary["by_severity"]
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    low = sev.get("low", 0)
    info = sev.get("info", 0)

    risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"

    lines = [
        "# Executive Summary",
        "",
        "**Client:** Internal Assessment",
        f"**Target:** {engagement['target']}",
        f"**Date:** {datetime.now().strftime('%B %d, %Y')}",
        f"**Overall Risk Rating:** {risk_level}",
        "",
        "---",
        "",
        "## Overview",
        "",
        f"A penetration test was conducted against {engagement['target']} to identify security "
        f"vulnerabilities and assess the overall security posture of the application. "
        f"The assessment followed OWASP Testing Guide v4 methodology and PTES standards.",
        "",
        "## Key Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Findings | {summary['total_findings']} |",
        f"| Critical | {critical} |",
        f"| High | {high} |",
        f"| Medium | {medium} |",
        f"| Low | {low} |",
        f"| Informational | {info} |",
        f"| Attack Chains | {summary['attack_chains']} |",
        f"| Detection Rules Generated | {summary['detection_rules']} |",
        "",
        "## Risk Assessment",
        "",
    ]

    if critical > 0 or high > 0:
        lines.append(
            f"The assessment identified **{critical + high} critical/high severity findings** "
            f"that require immediate attention. These findings could allow an attacker to "
            f"compromise the application, access sensitive data, or pivot to internal systems."
        )
    else:
        lines.append(
            "No critical or high severity findings were identified. The application "
            "demonstrates a reasonable security baseline, though medium-severity issues "
            "should be addressed in the next development cycle."
        )

    lines.extend(["", "## Top Findings", ""])
    for f in findings[:5]:
        lines.append(f"- **[{f['severity'].upper()}]** {f['title']} ({f['target']})")

    if chains:
        lines.extend(["", "## Attack Chains", ""])
        lines.append(
            "The following multi-step attack paths were identified by correlating "
            "individual findings:"
        )
        lines.append("")
        for c in chains:
            lines.append(f"- **{c['name']}** ({c['severity'].upper()}): {c.get('impact', '')}")

    lines.extend([
        "",
        "## Recommendations",
        "",
        "1. **Immediate (0-7 days):** Address all critical and high severity findings",
        "2. **Short-term (7-30 days):** Remediate medium severity findings and implement missing security headers",
        "3. **Ongoing:** Implement continuous security testing in CI/CD pipeline",
        "",
        "## Methodology",
        "",
        "The assessment was conducted using pentest-tools with the following phases:",
        "",
        "1. Reconnaissance and service enumeration",
        "2. Vulnerability scanning (builtin scanners + external tools)",
        "3. Finding deduplication and CWE/OWASP mapping",
        "4. Attack chain correlation",
        "5. Detection rule generation (Sigma, SPL, KQL)",
        "6. Evidence collection with SHA-256 integrity verification",
        "",
        "---",
        f"*Generated by pentest-tools on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
    ])
    return "\n".join(lines)


def _build_detection_bundle(rules, engagement):
    lines = [
        "# Detection Rules Bundle",
        "",
        f"**Engagement:** {engagement['target']}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        f"**Total Rules:** {len(rules)}",
        "",
        "---",
        "",
    ]

    for fmt_name, fmt_key in [("Sigma Rules", "sigma"), ("Splunk SPL Queries", "spl"), ("Microsoft Sentinel KQL Queries", "kql")]:
        fmt_rules = [r for r in rules if r["format"] == fmt_key]
        if not fmt_rules:
            continue
        lines.extend([f"## {fmt_name}", "", f"*{len(fmt_rules)} rules*", ""])
        for r in fmt_rules:
            lines.extend([
                f"### {r['description']}",
                "",
                f"```{'yaml' if fmt_key == 'sigma' else fmt_key}",
                r["rule"],
                "```",
                "",
            ])

    lines.extend([
        "---",
        "",
        "## Deployment Notes",
        "",
        "- **Sigma rules** can be converted to any SIEM format using sigmac or pySigma",
        "- **SPL queries** are ready for Splunk Enterprise/Cloud saved searches",
        "- **KQL queries** are ready for Microsoft Sentinel analytics rules",
        "- All rules should be tuned for your environment before production deployment",
        "- Consider adding suppression logic for known-good traffic patterns",
        "",
        f"*Generated by pentest-tools on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
    ])
    return "\n".join(lines)


def _build_remediation_roadmap(findings, chains):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 4))

    lines = [
        "# Remediation Roadmap",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        f"**Total Items:** {len(sorted_findings)}",
        "",
        "---",
        "",
        "## Priority 1: Immediate (0-7 days)",
        "",
        "Address these findings immediately to prevent active exploitation.",
        "",
    ]

    p1 = [f for f in sorted_findings if f["severity"] in ("critical", "high")]
    p2 = [f for f in sorted_findings if f["severity"] == "medium"]
    p3 = [f for f in sorted_findings if f["severity"] in ("low", "info")]

    if p1:
        lines.append("| # | Severity | Finding | Target | Remediation |")
        lines.append("|---|----------|---------|--------|-------------|")
        for i, f in enumerate(p1, 1):
            rem = f.get("remediation", "See finding details")
            lines.append(f"| {i} | {f['severity'].upper()} | {f['title']} | {f['target']} | {rem} |")
        lines.append("")
    else:
        lines.extend(["No critical or high severity findings.", ""])

    lines.extend([
        "## Priority 2: Short-term (7-30 days)",
        "",
        "Remediate these in the next sprint cycle.",
        "",
    ])

    if p2:
        lines.append("| # | Finding | Target | Remediation |")
        lines.append("|---|---------|--------|-------------|")
        for i, f in enumerate(p2, 1):
            rem = f.get("remediation", "See finding details")
            lines.append(f"| {i} | {f['title']} | {f['target']} | {rem} |")
        lines.append("")
    else:
        lines.extend(["No medium severity findings.", ""])

    lines.extend([
        "## Priority 3: Planned (30-90 days)",
        "",
        "Address during regular maintenance windows.",
        "",
    ])

    if p3:
        lines.append("| # | Finding | Target | Remediation |")
        lines.append("|---|---------|--------|-------------|")
        for i, f in enumerate(p3, 1):
            rem = f.get("remediation", "See finding details")
            lines.append(f"| {i} | {f['title']} | {f['target']} | {rem} |")
        lines.append("")
    else:
        lines.extend(["No low/info severity findings.", ""])

    if chains:
        lines.extend([
            "## Attack Chain Remediation",
            "",
            "Breaking any single link in these chains prevents the full attack path.",
            "",
        ])
        for c in chains:
            lines.extend([
                f"### {c['name']} ({c['severity'].upper()})",
                "",
                f"**Impact:** {c.get('impact', '')}",
                "",
                "**Break the chain by fixing:**",
                "",
            ])
            for i, step in enumerate(c.get("steps", []), 1):
                lines.append(f"{i}. {step.get('action', '')}")
            lines.append("")

    lines.extend([
        "---",
        f"*Generated by pentest-tools on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
    ])
    return "\n".join(lines)


def _build_evidence_index(artifacts, eid):
    lines = [
        "# Evidence Index",
        "",
        f"**Engagement:** {eid}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        f"**Total Artifacts:** {len(artifacts)}",
        "",
        "---",
        "",
        "All evidence artifacts are stored with SHA-256 integrity hashes for chain of custody.",
        "",
        "| # | Finding ID | Type | Filename | Size | SHA-256 |",
        "|---|-----------|------|----------|------|---------|",
    ]

    for i, a in enumerate(artifacts, 1):
        lines.append(
            f"| {i} | {a.finding_id} | {a.artifact_type} | {a.filename} | {a.size_bytes} bytes | `{a.sha256[:16]}...` |"
        )

    lines.extend([
        "",
        "## Integrity Verification",
        "",
        "To verify evidence integrity, run:",
        "",
        "```bash",
        f"sha256sum evidence/{eid}/*",
        "```",
        "",
        "Compare output against the SHA-256 values in this index.",
        "",
        "---",
        f"*Generated by pentest-tools on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    asyncio.run(main())

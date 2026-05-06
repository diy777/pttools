"""Full pentest engagement against DVWA using real tools (nmap, nuclei, nikto, etc.)."""

import asyncio
import os
import subprocess
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
DVWA_IP = "127.0.0.1"
GO_BIN = os.path.expanduser("~/go/bin")
os.environ["PATH"] = os.environ["PATH"] + f":{GO_BIN}"


def run_tool(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", -2


def parse_nmap_findings(output: str, target: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0]
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            severity = "medium" if service in ("http", "ftp", "telnet", "mysql", "postgres") else "info"
            findings.append({
                "id": uuid.uuid4().hex[:8],
                "title": f"Open port {port} ({service})" + (f" - {version}" if version else ""),
                "description": f"Port {port} is open running {service}" + (f" version {version}" if version else ""),
                "severity": severity,
                "category": "network",
                "target": f"{target}:{port.split('/')[0]}",
                "tool_source": "nmap",
                "evidence": line,
                "remediation": f"Review if {service} on {port} needs to be exposed" if severity != "info" else "",
            })
    return findings


def parse_nuclei_findings(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("[INF]") or line.startswith("[WRN]"):
            continue
        severity = "info"
        for sev in ["critical", "high", "medium", "low"]:
            if f"[{sev}]" in line.lower():
                severity = sev
                break
        parts = line.split("] ")
        title = parts[-1] if parts else line
        if "[" in title and "]" in title:
            title = title.split("] ")[-1]
        findings.append({
            "id": uuid.uuid4().hex[:8],
            "title": title[:200],
            "description": line,
            "severity": severity,
            "category": "vulnerability",
            "target": DVWA_URL,
            "tool_source": "nuclei",
            "evidence": line,
        })
    return findings


def parse_nikto_findings(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        text = line[2:]
        if any(skip in text.lower() for skip in ["nikto", "target", "start time", "end time", "host(s) tested"]):
            continue
        severity = "medium"
        if any(w in text.lower() for w in ["xss", "injection", "rce", "remote code"]):
            severity = "high"
        elif any(w in text.lower() for w in ["header", "cookie", "version"]):
            severity = "low"
        findings.append({
            "id": uuid.uuid4().hex[:8],
            "title": text[:200],
            "description": text,
            "severity": severity,
            "category": "vulnerability",
            "target": DVWA_URL,
            "tool_source": "nikto",
            "evidence": text,
        })
    return findings


async def main():
    db = FindingsDB("dvwa_full_engagement.db")
    await db.init()
    evidence = EvidenceCollector(base_dir="evidence")
    dedup = FindingDeduplicator()
    _scope = ScopeEnforcer(
        allowed_targets=["localhost", "127.0.0.1", "127.0.0.0/8"],
        allowed_ports=[4280, 80, 443, 22, 8080],
        mode="strict",
    )

    engagement = await db.create_engagement(
        target=f"{DVWA_URL} (DVWA)",
        scope="web",
        rules_of_engment="Authorized pentest of local DVWA. No DoS.",
        intensity="normal",
    )
    eid = engagement["id"]
    print(f"\n{'='*70}")
    print(f"  FULL PENTEST ENGAGEMENT: {eid}")
    print(f"  Target: {DVWA_URL}")
    print("  Tools: nmap, nuclei, nikto, whatweb, sslscan + builtin scanners")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    all_findings: list[dict] = []

    # --- Phase 1: Builtin Scanners ---
    print("[*] Phase 1: Builtin Scanners")
    for name, scanner, target in [
        ("Port Scan", scan_ports, DVWA_HOST),
        ("HTTP Headers", scan_http_headers, DVWA_URL),
        ("Path Discovery", scan_common_paths, DVWA_URL),
        ("SSL Check", check_ssl, DVWA_HOST),
        ("DNS Check", check_dns, DVWA_HOST),
        ("Secret Scan", scan_secrets_in_response, DVWA_URL),
    ]:
        print(f"    [>] {name}...")
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
                print(f"        {len(results)} findings")
        except Exception as e:
            print(f"        Error: {e}")

    # --- Phase 2: Nmap ---
    print("\n[*] Phase 2: Nmap Service Scan")
    stdout, stderr, rc = run_tool([
        "nmap", "-sV", "-sC", "--top-ports", "1000", "-T4", DVWA_IP, "-p", "4280,80,443,22,8080"
    ], timeout=120)
    if rc == 0:
        nmap_findings = parse_nmap_findings(stdout, DVWA_IP)
        for f in nmap_findings:
            f["engagement_id"] = eid
            all_findings.append(f)
        print(f"    {len(nmap_findings)} findings")
        await evidence.store_tool_output(eid, "nmap-scan", "nmap", f"nmap -sV -sC {DVWA_IP}", stdout, stderr, rc, 0)
    else:
        print(f"    Failed: {stderr[:200]}")

    # --- Phase 3: Nuclei ---
    print("\n[*] Phase 3: Nuclei Vulnerability Scan")
    stdout, stderr, rc = run_tool([
        "nuclei", "-u", DVWA_URL, "-severity", "info,low,medium,high,critical", "-silent", "-nc"
    ], timeout=300)
    nuclei_findings = parse_nuclei_findings(stdout)
    for f in nuclei_findings:
        f["engagement_id"] = eid
        all_findings.append(f)
    print(f"    {len(nuclei_findings)} findings")
    await evidence.store_tool_output(eid, "nuclei-scan", "nuclei", f"nuclei -u {DVWA_URL}", stdout, stderr, rc, 0)

    # --- Phase 4: Nikto ---
    print("\n[*] Phase 4: Nikto Web Scanner")
    stdout, stderr, rc = run_tool([
        "nikto", "-h", DVWA_URL, "-C", "all", "-maxtime", "120s"
    ], timeout=180)
    nikto_findings = parse_nikto_findings(stdout)
    for f in nikto_findings:
        f["engagement_id"] = eid
        all_findings.append(f)
    print(f"    {len(nikto_findings)} findings")
    await evidence.store_tool_output(eid, "nikto-scan", "nikto", f"nikto -h {DVWA_URL}", stdout, stderr, rc, 0)

    # --- Phase 5: WhatWeb ---
    print("\n[*] Phase 5: WhatWeb Fingerprinting")
    stdout, stderr, rc = run_tool(["whatweb", "--color=never", "-a", "3", DVWA_URL], timeout=60)
    if rc == 0 and stdout.strip():
        all_findings.append({
            "id": uuid.uuid4().hex[:8],
            "engagement_id": eid,
            "title": f"Technology fingerprint: {stdout.strip()[:100]}",
            "description": stdout.strip(),
            "severity": "info",
            "category": "recon",
            "target": DVWA_URL,
            "tool_source": "whatweb",
            "evidence": stdout.strip(),
        })
        print("    Fingerprint captured")
        await evidence.store_tool_output(eid, "whatweb", "whatweb", f"whatweb {DVWA_URL}", stdout, stderr, rc, 0)
    else:
        print("    No output")

    # --- Phase 6: SSLScan ---
    print("\n[*] Phase 6: SSLScan")
    stdout, stderr, rc = run_tool(["sslscan", "--no-colour", f"{DVWA_HOST}:4280"], timeout=30)
    if rc == 0 and "ssl" in stdout.lower():
        all_findings.append({
            "id": uuid.uuid4().hex[:8],
            "engagement_id": eid,
            "title": "SSL/TLS scan results",
            "description": stdout[:500],
            "severity": "info",
            "category": "network",
            "target": f"{DVWA_HOST}:4280",
            "tool_source": "sslscan",
            "evidence": stdout[:1000],
        })
        print("    SSL findings captured")
    else:
        print("    No SSL on this port (expected for HTTP)")

    # --- Phase 7: Dedup & Store ---
    print("\n[*] Phase 7: Deduplication & Storage")
    stored = 0
    dupes = 0
    for f in all_findings:
        is_dup, _ = dedup.is_duplicate(f)
        if not is_dup:
            await db.add_finding(f)
            stored += 1
        else:
            dupes += 1
    print(f"    Stored: {stored} unique, {dupes} duplicates removed")

    # --- Phase 8: Attack Chains ---
    print("\n[*] Phase 8: Attack Chain Discovery")
    chain_agent = ExploitChainAgent(db)
    chains = await chain_agent.discover_chains(eid)
    print(f"    {len(chains)} chains discovered")
    for c in chains:
        print(f"    [{c['severity'].upper()}] {c['name']}: {c.get('impact', '')}")

    # --- Phase 9: Detection Rules ---
    print("\n[*] Phase 9: Detection Rule Generation")
    det_agent = DetectionAgent(db)
    rules = await det_agent.generate_rules(eid)
    sigma = sum(1 for r in rules if r["format"] == "sigma")
    spl = sum(1 for r in rules if r["format"] == "spl")
    kql = sum(1 for r in rules if r["format"] == "kql")
    print(f"    {len(rules)} rules (Sigma: {sigma} | SPL: {spl} | KQL: {kql})")

    # --- Phase 10: Reports (MD + HTML + PDF) ---
    print("\n[*] Phase 10: Report Generation")
    report_agent = ReportAgent(db)
    report_result = await report_agent.generate_report(eid, format="all")
    for fmt, path in report_result.get("output_paths", {}).items():
        print(f"    {fmt.upper()}: {path}")

    # --- Summary ---
    summary = await db.get_engagement_summary(eid)
    print(f"\n{'='*70}")
    print(f"  ENGAGEMENT COMPLETE: {eid}")
    print(f"  Findings: {summary['total_findings']} | Chains: {summary['attack_chains']} | Rules: {summary['detection_rules']}")
    print(f"  Severity: {summary['by_severity']}")
    print(f"{'='*70}\n")

    await db.close()


if __name__ == "__main__":
    asyncio.run(main())

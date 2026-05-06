"""Detection Agent — LLM-driven Sigma, SPL, and KQL rule generation."""

import logging
from typing import Any

from agents.base import BaseAgent
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.detection")

MITRE_CATEGORY_MAP = {
    "recon": ("T1595", "Active Scanning"),
    "discovery": ("T1046", "Network Service Scanning"),
    "injection": ("T1190", "Exploit Public-Facing Application"),
    "authentication": ("T1110", "Brute Force"),
    "xss": ("T1059.007", "JavaScript"),
    "ssrf": ("T1090", "Proxy"),
    "ad": ("T1558", "Steal or Forge Kerberos Tickets"),
    "cloud": ("T1078.004", "Cloud Accounts"),
    "network": ("T1046", "Network Service Scanning"),
    "vulnerability": ("T1190", "Exploit Public-Facing Application"),
}


class DetectionAgent(BaseAgent):
    agent_type = "detection"

    def __init__(self, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry=None, db=db, llm=llm, scope=scope)

    async def generate_rules(self, engagement_id: str) -> list[dict[str, Any]]:
        findings = await self.db.get_findings(engagement_id=engagement_id)
        if not findings:
            return []

        if self.llm:
            return await self._llm_generate_rules(findings, engagement_id)

        return await self._template_generate_rules(findings, engagement_id)

    async def _llm_generate_rules(self, findings: list[dict[str, Any]], engagement_id: str) -> list[dict[str, Any]]:
        findings_text = "\n".join(
            f"- [{f.get('severity', 'info')}] {f.get('title', '')} | category: {f.get('category', '')} | target: {f.get('target', '')}"
            for f in findings
        )
        prompt = (
            f"Generate detection rules for these {len(findings)} pentest findings:\n\n"
            f"{findings_text}\n\n"
            f"For each critical/high finding, generate:\n"
            f"1. A Sigma rule (YAML) with proper logsource, detection logic, and MITRE ATT&CK mapping\n"
            f"2. A Splunk SPL query\n"
            f"3. A Microsoft Sentinel KQL query\n\n"
            f"Use realistic detection logic, not just target-name matching. Consider what logs would show during the actual attack."
        )
        await self.run_tool_loop(prompt, engagement_id)
        return await self.db.get_detection_rules(engagement_id)

    async def _template_generate_rules(self, findings: list[dict[str, Any]], engagement_id: str) -> list[dict[str, Any]]:
        rules = []
        for finding in findings:
            if finding.get("severity") not in ("critical", "high", "medium"):
                continue

            category = finding.get("category", "").lower()
            technique_id, technique_name = MITRE_CATEGORY_MAP.get(category, ("T1190", "Exploit Public-Facing Application"))
            target = finding.get("target", "unknown")
            title = finding.get("title", "Unknown Finding")

            sigma_rule = _build_sigma_rule(title, target, technique_id, technique_name, category)
            spl_query = _build_spl_query(title, target, category)
            kql_query = _build_kql_query(title, target, category)

            for fmt, rule_text in [("sigma", sigma_rule), ("spl", spl_query), ("kql", kql_query)]:
                rule = {
                    "engagement_id": engagement_id,
                    "finding_id": finding["id"],
                    "format": fmt,
                    "rule": rule_text,
                    "description": f"Detection for: {title}",
                }
                await self.db.add_detection_rule(rule)
                rules.append(rule)

        return rules


def _build_sigma_rule(title: str, target: str, technique_id: str, technique_name: str, category: str) -> str:
    logsource_map = {
        "injection": ("web", "proxy"),
        "xss": ("web", "proxy"),
        "ssrf": ("web", "proxy"),
        "authentication": ("windows", "security"),
        "ad": ("windows", "security"),
        "network": ("network", "firewall"),
        "cloud": ("cloud", "cloudtrail"),
        "discovery": ("network", "firewall"),
    }
    product, service = logsource_map.get(category, ("generic", "generic"))

    return (
        f"title: Detect {title}\n"
        f"status: experimental\n"
        f"description: Detection rule for pentest finding - {title}\n"
        f"logsource:\n"
        f"    product: {product}\n"
        f"    service: {service}\n"
        f"detection:\n"
        f"    selection:\n"
        f"        DestinationHostname|contains: '{target}'\n"
        f"    condition: selection\n"
        f"level: high\n"
        f"tags:\n"
        f"    - attack.{technique_id.lower()}\n"
        f"    - attack.{technique_name.lower().replace(' ', '_')}\n"
    )


def _build_spl_query(title: str, target: str, category: str) -> str:
    if category in ("injection", "xss", "ssrf"):
        return (
            f'index=web sourcetype=access_combined dest="{target}"'
            ' | where match(uri_path, "(?i)(select|union|script|curl|127\\.0\\.0\\.1)")'
            " | stats count by src_ip, uri_path, status"
        )
    if category in ("authentication", "ad"):
        return (
            f'index=wineventlog EventCode IN (4625, 4768, 4769) TargetUserName!="*$" ComputerName="{target}"'
            " | stats count by TargetUserName, IpAddress, EventCode | where count > 5"
        )
    return f'index=* dest="{target}" | stats count by src_ip, action, app'


def _build_kql_query(title: str, target: str, category: str) -> str:
    if category in ("injection", "xss", "ssrf"):
        return (
            f'CommonSecurityLog\n| where DestinationHostName contains "{target}"'
            '\n| where RequestURL matches regex @"(?i)(select|union|script|curl|127\\.0\\.0\\.1)"'
            "\n| summarize count() by SourceIP, RequestURL, Activity"
        )
    if category in ("authentication", "ad"):
        return (
            "SecurityEvent\n| where EventID in (4625, 4768, 4769)"
            f'\n| where Computer contains "{target}"'
            "\n| summarize count() by TargetAccount, IpAddress, EventID\n| where count_ > 5"
        )
    return f'CommonSecurityLog\n| where DestinationHostName contains "{target}"\n| summarize count() by SourceIP, Activity, DeviceAction'

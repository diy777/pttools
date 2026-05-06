"""PoC Agent — LLM-driven safe, non-destructive proof-of-concept validation."""

import logging
from typing import Any

from agents.base import BaseAgent
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.poc")


class PoCAgent(BaseAgent):
    agent_type = "poc_validator"

    def __init__(self, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry=None, db=db, llm=llm, scope=scope)

    async def validate_finding(self, finding_id: str, engagement_id: str = "") -> dict[str, Any]:
        findings = await self.db.get_findings(engagement_id=engagement_id)
        finding = next((f for f in findings if f.get("id") == finding_id), None)
        if not finding:
            return {"error": f"Finding {finding_id} not found"}

        if self.llm:
            prompt = (
                f"Generate a safe, non-destructive proof of concept for this finding:\n\n"
                f"Title: {finding.get('title', '')}\n"
                f"Severity: {finding.get('severity', '')}\n"
                f"Category: {finding.get('category', '')}\n"
                f"Target: {finding.get('target', '')}\n"
                f"Description: {finding.get('description', '')}\n\n"
                f"Rules:\n"
                f"- NEVER use destructive payloads\n"
                f"- NEVER exfiltrate real data\n"
                f"- NEVER persist access\n"
                f"- Use read-only operations (SELECT version(), id, whoami)\n"
                f"- Provide the exact request/command and expected response"
            )
            return await self.run_tool_loop(prompt, engagement_id)

        return self._generate_static_poc(finding)

    async def validate_all(self, engagement_id: str) -> list[dict[str, Any]]:
        findings = await self.db.get_findings(engagement_id=engagement_id)
        results = []
        for f in findings:
            if f.get("severity") in ("critical", "high"):
                result = await self.validate_finding(f["id"], engagement_id)
                results.append(result)
                # Mirror the evidence-gate signal onto poc_status so chain
                # validation downstream has a single field to read.
                poc_status = "confirmed" if f.get("status") == "confirmed" else "rejected"
                poc_text = result.get("poc") if isinstance(result, dict) else None
                try:
                    await self.db.update_finding_poc_status(f["id"], poc_status, poc=poc_text)
                except Exception as e:  # pragma: no cover - best-effort
                    logger.warning("update_finding_poc_status failed for %s: %s", f["id"], e)
        return results

    async def validate_chains(self, engagement_id: str) -> list[dict[str, Any]]:
        """Mark each attack chain confirmed or unvalidated based on its findings.

        Rule: a chain is 'confirmed' iff every finding it references has
        status='confirmed' on the finding row (evidence-gated at ingest time)
        AND none of those findings are scanner-noise titles. Anything else is
        'unvalidated'. Chains with no resolvable findings are marked 'rejected'.
        """
        chains = await self.db.get_attack_chains(engagement_id)
        findings = await self.db.get_findings(engagement_id=engagement_id)
        by_id = {f["id"]: f for f in findings}

        # Local copy of the noise check to avoid a circular import on the
        # exploit_chain module.
        noise_substrings = (
            "no web server found", "0 host(s) tested", "no host",
            "no open port", "scan complete: 0", "no findings",
            "host unreachable", "connection refused", "connection timed out",
        )

        def _is_noise(f: dict[str, Any]) -> bool:
            t = (f.get("title") or "").lower()
            return any(s in t for s in noise_substrings)

        results: list[dict[str, Any]] = []
        for chain in chains:
            fids = chain.get("finding_ids") or []
            referenced = [by_id.get(fid) for fid in fids]
            if not fids or not all(referenced) or any(_is_noise(f) for f in referenced):
                new_status = "rejected"
            elif all((f.get("status") == "confirmed") for f in referenced):
                new_status = "confirmed"
            else:
                new_status = "unvalidated"

            await self.db.update_chain_status(chain["id"], new_status)
            results.append({"chain_id": chain["id"], "status": new_status})
        return results

    def _generate_static_poc(self, finding: dict[str, Any]) -> dict[str, Any]:
        category = finding.get("category", "").lower()
        poc_templates = {
            "injection": "curl -s '{target}' --data 'param=1 AND SLEEP(5)' (time-based blind SQLi detection)",
            "xss": "curl -s '{target}' --data 'q=<script>alert(document.domain)</script>' (reflected XSS check)",
            "ssrf": "curl -s '{target}/api?url=http://169.254.169.254/latest/meta-data/' (SSRF to cloud metadata)",
            "authentication": "curl -s '{target}/admin' -H 'Authorization: Bearer invalid' (auth bypass check)",
            "discovery": "nmap -sV -p {port} {target} (service version confirmation)",
            "network": "nmap -sV --script vuln {target} (vulnerability script scan)",
        }

        template = poc_templates.get(category, "Manual verification required for {target}")
        poc_text = template.format(target=finding.get("target", "TARGET"), port=finding.get("port", "80"))

        return {
            "finding_id": finding["id"],
            "poc": poc_text,
            "poc_status": "template",
            "validated": False,
        }

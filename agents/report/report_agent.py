"""Report Agent — LLM-driven professional pentest report generation."""

import logging
import os
from datetime import datetime
from typing import Any

from agents.base import BaseAgent
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.report")


class ReportAgent(BaseAgent):
    agent_type = "report"

    def __init__(self, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry=None, db=db, llm=llm, scope=scope)

    async def generate_report(
        self,
        engagement_id: str,
        format: str = "all",
        include_pocs: bool = True,
        include_detections: bool = True,
    ) -> dict[str, Any]:
        engagement = await self.db.get_engagement(engagement_id)
        findings = await self.db.get_findings(engagement_id=engagement_id)
        chains = await self.db.get_attack_chains(engagement_id)
        summary = await self.db.get_engagement_summary(engagement_id)
        detection_rules = await self.db.get_detection_rules(engagement_id) if include_detections else []
        stage_records = await self.db.get_stage_records(engagement_id)

        if self.llm:
            md_report = await self._llm_generate_report(
                engagement, findings, chains, summary, include_pocs, include_detections, stage_records
            )
        else:
            md_report = self._build_markdown_report(
                engagement, findings, chains, summary, include_pocs, include_detections, stage_records
            )

        date_str = datetime.now().strftime("%Y%m%d")
        base = f"pentest-{engagement_id}-{date_str}"
        os.makedirs("reports", exist_ok=True)
        output_paths: dict[str, str] = {}

        if format in ("markdown", "all"):
            md_path = f"reports/{base}.md"
            with open(md_path, "w") as f:
                f.write(md_report)
            output_paths["markdown"] = md_path

        if format in ("html", "pdf", "all"):
            from agents.report.renderer import render_html, render_pdf

            html_content = render_html(engagement, findings, chains, summary, detection_rules)

            if format in ("html", "all"):
                html_path = f"reports/{base}.html"
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                output_paths["html"] = html_path

            if format in ("pdf", "all"):
                try:
                    pdf_bytes = render_pdf(html_content)
                    pdf_path = f"reports/{base}.pdf"
                    with open(pdf_path, "wb") as f:
                        f.write(pdf_bytes)
                    output_paths["pdf"] = pdf_path
                except RuntimeError as e:
                    logger.warning(f"PDF generation skipped: {e}")

        return {
            "engagement_id": engagement_id,
            "format": format,
            "output_path": output_paths.get("markdown", output_paths.get("html", "")),
            "output_paths": output_paths,
            "total_findings": summary["total_findings"],
            "attack_chains": summary["attack_chains"],
        }

    async def _llm_generate_report(
        self, engagement, findings, chains, summary, include_pocs, include_detections, stage_records
    ) -> str:
        findings_text = "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', '')} on {f.get('target', '')} "
            f"(category: {f.get('category', '')}) — {f.get('description', '')[:200]}"
            for f in findings
        )
        chains_text = "\n".join(
            f"- {c.get('name', '')}: {c.get('impact', '')} ({len(c.get('steps', []))} steps)"
            for c in chains
        ) if chains else "No attack chains discovered."
        stages_text = "\n".join(
            f"- {s.get('stage', '')}: {s.get('status', '')} ({int((s.get('progress', 0) or 0) * 100)}%)"
            for s in stage_records
        ) if stage_records else "No stage timeline recorded."

        prompt = (
            f"Write a professional penetration test report in Markdown.\n\n"
            f"Engagement: {engagement.get('target', '')} | Scope: {engagement.get('scope', '')}\n"
            f"Summary: {summary['total_findings']} findings, {summary.get('attack_chains', 0)} chains\n"
            f"Severity breakdown: {summary.get('by_severity', {})}\n\n"
            f"Findings:\n{findings_text}\n\n"
            f"Attack Chains:\n{chains_text}\n\n"
            f"Workflow Timeline:\n{stages_text}\n\n"
            f"Sections required:\n"
            f"1. Executive Summary (business impact, non-technical)\n"
            f"2. Scope and Methodology\n"
            f"3. Risk Rating Summary (table)\n"
            f"4. Detailed Findings (each with: description, impact, evidence, remediation, CVSS)\n"
            f"5. Attack Chains (narrative showing multi-step paths)\n"
            f"{'6. Detection Rules' + chr(10) if include_detections else ''}"
            f"{'7. PoC Evidence' + chr(10) if include_pocs else ''}"
            f"8. Remediation Roadmap (prioritized)\n"
            f"9. Appendix (methodology, tools used)\n\n"
            f"Write for a CISO audience. Lead with business risk, not technical jargon."
        )
        result = await self.run_tool_loop(prompt, engagement.get("id", ""))
        return result.get("summary", self._build_markdown_report(
            engagement, findings, chains, summary, include_pocs, include_detections
        ))

    def _build_markdown_report(self, engagement, findings, chains, summary, include_pocs, include_detections, stage_records):
        lines = [
            "# Penetration Test Report",
            "",
            f"**Target:** {engagement['target']}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**Scope:** {engagement['scope']}",
            f"**Status:** {engagement['status']}",
            "",
            "## Executive Summary",
            "",
            f"Total findings: {summary['total_findings']}",
            f"Attack chains discovered: {summary['attack_chains']}",
            "",
            "### Severity Breakdown",
            "",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary["by_severity"].get(sev, 0)
            lines.append(f"- **{sev.upper()}:** {count}")

        lines.extend(["", "## Findings", ""])

        for f in findings:
            lines.extend([
                f"### [{f['severity'].upper()}] {f['title']}",
                "",
                f"{f['description']}",
                "",
                f"- **Target:** {f['target']}",
                f"- **Category:** {f['category']}",
                f"- **Tool:** {f.get('tool_source', 'N/A')}",
                "",
            ])
            if f.get("remediation"):
                lines.extend([f"**Remediation:** {f['remediation']}", ""])

        if chains:
            lines.extend(["## Attack Chains", ""])
            for c in chains:
                lines.extend([
                    f"### {c['name']}",
                    "",
                    f"{c.get('description', c.get('impact', ''))}",
                    "",
                    f"**Impact:** {c['impact']}",
                    "",
                    "**Steps:**",
                    "",
                ])
                for i, step in enumerate(c["steps"], 1):
                    action = step.get("action", "")
                    sev = step.get("severity", "")
                    sev_str = f" ({sev})" if sev else ""
                    lines.append(f"{i}. {action}{sev_str}")
                lines.append("")

        lines.extend(["## Workflow Timeline", ""])
        if stage_records:
            for s in stage_records:
                lines.append(
                    f"- **{s.get('stage', 'stage')}** — {s.get('status', 'unknown')} — "
                    f"{int((s.get('progress', 0) or 0) * 100)}%"
                )
                if s.get("details"):
                    lines.append(f"  - {s['details']}")
                if s.get("recorded_at"):
                    lines.append(f"  - Recorded: {s['recorded_at']}")
            lines.append("")
        else:
            lines.extend(["No stage timeline recorded.", ""])

        if include_detections:
            lines.extend(["## Detection Rules", "", "Detection rules generated for all confirmed findings.", ""])

        return "\n".join(lines)

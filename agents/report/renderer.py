"""Report renderer: Markdown, HTML, and PDF output from engagement data."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("pentest-tools.report.renderer")

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(
    engagement: dict[str, Any],
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    summary: dict[str, Any],
    detection_rules: list[dict[str, Any]] | None = None,
) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    sev = summary.get("by_severity", {})
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)

    if critical > 0:
        risk_level = "CRITICAL"
    elif high > 0:
        risk_level = "HIGH"
    elif medium > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return template.render(
        engagement=engagement,
        findings=findings,
        chains=chains,
        summary=summary,
        detection_rules=detection_rules or [],
        risk_level=risk_level,
        date=datetime.now().strftime("%B %d, %Y"),
    )


def render_pdf(html_content: str) -> bytes:
    try:
        from weasyprint import HTML
    except ImportError as err:
        raise RuntimeError(
            "WeasyPrint is required for PDF output. Install with: pip install weasyprint"
        ) from err

    return HTML(string=html_content).write_pdf()


def write_report(
    engagement: dict[str, Any],
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    summary: dict[str, Any],
    detection_rules: list[dict[str, Any]] | None = None,
    output_dir: str = "reports",
    formats: tuple[str, ...] = ("markdown", "html", "pdf"),
) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    eid = engagement.get("id", "unknown")
    date_str = datetime.now().strftime("%Y%m%d")
    base = f"pentest-{eid}-{date_str}"
    outputs: dict[str, str] = {}

    if "html" in formats or "pdf" in formats:
        html_content = render_html(engagement, findings, chains, summary, detection_rules)

        if "html" in formats:
            html_path = os.path.join(output_dir, f"{base}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            outputs["html"] = html_path
            logger.info(f"HTML report: {html_path}")

        if "pdf" in formats:
            try:
                pdf_bytes = render_pdf(html_content)
                pdf_path = os.path.join(output_dir, f"{base}.pdf")
                with open(pdf_path, "wb") as f:
                    f.write(pdf_bytes)
                outputs["pdf"] = pdf_path
                logger.info(f"PDF report: {pdf_path}")
            except RuntimeError as e:
                logger.warning(f"PDF generation skipped: {e}")

    return outputs

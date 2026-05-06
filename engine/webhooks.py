"""Webhook notifications for pentest-tools events.

Sends notifications to Slack, Jira, or generic HTTP endpoints
when key events occur during an engagement.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("pentest-tools.webhooks")

VALID_EVENTS = frozenset({
    "engagement.started",
    "engagement.completed",
    "engagement.failed",
    "finding.new",
    "finding.critical",
    "phase.started",
    "phase.completed",
})


class WebhookNotifier:
    def __init__(
        self,
        url: str | None = None,
        events: set[str] | None = None,
        headers: dict[str, str] | None = None,
        webhook_type: str = "generic",
    ):
        self.url = url or os.getenv("PENTEST_WEBHOOK_URL", "")
        self.events = events or VALID_EVENTS
        self.headers = headers or {}
        self.webhook_type = webhook_type

    def notify(self, event: str, payload: dict[str, Any]) -> bool:
        if not self.url:
            return False
        if event not in self.events:
            return False

        try:
            body = self._format_payload(event, payload)
            req = Request(
                self.url,
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", **self.headers},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.warning(f"Webhook delivery failed for {event}: {e}")
            return False

    def _format_payload(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.webhook_type == "slack":
            return self._format_slack(event, payload)
        return {"event": event, "data": payload}

    def _format_slack(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        icon = _event_icon(event)
        target = payload.get("target", "unknown")
        text = f"{icon} *{event}*\nTarget: `{target}`"

        if "severity" in payload:
            text += f"\nSeverity: *{payload['severity'].upper()}*"
        if "title" in payload:
            text += f"\nFinding: {payload['title']}"
        if "total_findings" in payload:
            text += f"\nTotal findings: {payload['total_findings']}"

        return {"text": text}


def _event_icon(event: str) -> str:
    icons = {
        "engagement.started": "[START]",
        "engagement.completed": "[DONE]",
        "engagement.failed": "[FAIL]",
        "finding.new": "[FINDING]",
        "finding.critical": "[CRITICAL]",
        "phase.started": "[PHASE]",
        "phase.completed": "[PHASE OK]",
    }
    return icons.get(event, "[EVENT]")


def create_notifier_from_env() -> WebhookNotifier | None:
    url = os.getenv("PENTEST_WEBHOOK_URL")
    if not url:
        return None
    webhook_type = os.getenv("PENTEST_WEBHOOK_TYPE", "generic")
    return WebhookNotifier(url=url, webhook_type=webhook_type)

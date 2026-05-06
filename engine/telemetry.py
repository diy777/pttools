"""Opt-in usage telemetry for pentest-tools.

Off by default. Users explicitly enable via env var or `pttools telemetry enable`.
When enabled, sends a small JSON payload at engagement start and end to a
Cloudflare Worker endpoint. No PII, no engagement targets, no findings — only
counts and durations.

Why opt-in: GDPR Article 6(1)(a) requires explicit consent for non-essential
data collection. We default to off and surface the toggle clearly.

Why telemetry at all: without ANY signal we don't know what's working, what's
breaking, what models are being used, or which agents are popular. Anonymous
counters tell us where to invest engineering time.

What gets sent (every event includes none of: target URLs, IP addresses,
findings content, credentials, PII):

    {
      "ts": "2026-04-28T12:34:56Z",
      "client_id": "<random uuid persisted in ~/.pentest-tools/client_id>",
      "version": "0.10.2",
      "event": "engagement.start" | "engagement.end" | "agent.run" | "tool.exec",
      "agent": "recon" | ...,
      "tool": "nmap" | null,
      "model": "claude-sonnet-4-20250514" | null,
      "duration_seconds": 142,
      "success": true,
      "platform": "linux" | "darwin" | "win32",
      "python_version": "3.12.3"
    }

Endpoint: https://telemetry.pentest-tools.local/v1/event (Cloudflare Worker that
writes to a privacy-safe aggregation store).

Disable any time: `pttools telemetry disable` or `unset PENTEST_TOOLS_TELEMETRY`.

Source available at https://github.com/pentest-tools/pentest-tools/blob/main/engine/telemetry.py
so anyone can audit exactly what is and isn't sent.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("pentest-tools.telemetry")


CONFIG_DIR = Path(os.environ.get("PENTEST_TOOLS_CONFIG_DIR", str(Path.home() / ".pentest-tools")))
CLIENT_ID_PATH = CONFIG_DIR / "client_id"
CONSENT_PATH = CONFIG_DIR / "telemetry_consent"
DEFAULT_ENDPOINT = "https://telemetry.pentest-tools.local/v1/event"
TIMEOUT_SECONDS = 3.0


# ─── Consent state ─────────────────────────────────────────────────────


def is_enabled() -> bool:
    """Telemetry is enabled when both env-permission AND consent file say yes.

    Hard rules:
      - PENTEST_TOOLS_TELEMETRY=0 always disables (overrides consent file)
      - Default is OFF unless consent file exists with content "yes"
      - Consent file must be created by an explicit user action
    """
    env = os.environ.get("PENTEST_TOOLS_TELEMETRY", "").lower()
    if env in ("0", "false", "off", "no"):
        return False
    if env in ("1", "true", "on", "yes"):
        return _has_consent_file()
    return _has_consent_file()


def _has_consent_file() -> bool:
    try:
        return CONSENT_PATH.is_file() and CONSENT_PATH.read_text().strip() == "yes"
    except OSError:
        return False


def grant_consent() -> None:
    """User explicitly opts in. Writes the consent file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONSENT_PATH.write_text("yes\n")
    # Also make sure we have a stable client_id
    _client_id()


def revoke_consent() -> None:
    """User opts out. Removes consent and client_id files."""
    import contextlib

    with contextlib.suppress(FileNotFoundError):
        CONSENT_PATH.unlink()
    with contextlib.suppress(FileNotFoundError):
        CLIENT_ID_PATH.unlink()


def consent_status() -> str:
    """Human-readable status string."""
    if not _has_consent_file():
        return "disabled (no consent file)"
    env = os.environ.get("PENTEST_TOOLS_TELEMETRY", "").lower()
    if env in ("0", "false", "off", "no"):
        return "disabled (PENTEST_TOOLS_TELEMETRY=" + env + " override)"
    return "enabled"


# ─── Client ID ─────────────────────────────────────────────────────────


def _client_id() -> str:
    """Stable random UUID per install. Created on first run after opt-in."""
    try:
        if CLIENT_ID_PATH.is_file():
            return CLIENT_ID_PATH.read_text().strip()
    except OSError:
        pass

    new_id = str(uuid.uuid4())
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CLIENT_ID_PATH.write_text(new_id + "\n")
    except OSError as e:
        logger.debug("could not persist client_id: %s", e)
    return new_id


# ─── Event sending ─────────────────────────────────────────────────────


def emit(event: str, **fields: Any) -> None:
    """Best-effort send. Returns immediately; never raises; never blocks the engagement."""
    if not is_enabled():
        return

    try:
        from importlib.metadata import version

        try:
            ver = version("pttools")
        except Exception:  # noqa: BLE001
            ver = "unknown"

        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "client_id": _client_id(),
            "version": ver,
            "event": event,
            "platform": sys.platform,
            "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
            "platform_machine": platform.machine(),
        }
        # Allow only safe field types and field names. Reject anything that
        # could leak sensitive data.
        for k, v in fields.items():
            if k in _BLOCKED_KEYS:
                continue
            if not isinstance(k, str) or not k.replace("_", "").replace(".", "").isalnum():
                continue
            if isinstance(v, (str, int, float, bool)) or v is None:
                payload[k] = v

        endpoint = os.environ.get("PENTEST_TOOLS_TELEMETRY_ENDPOINT", DEFAULT_ENDPOINT)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "pentest-tools-telemetry/1.0",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=TIMEOUT_SECONDS) as _resp:
                pass
        except (URLError, TimeoutError, OSError) as e:
            logger.debug("telemetry post failed: %s", e)
    except Exception as e:  # noqa: BLE001
        # Telemetry must never break the engagement. Swallow everything.
        logger.debug("telemetry emit failed: %s", e)


# ─── Hard-coded blocklist of field names that could leak data ──────────


_BLOCKED_KEYS = frozenset(
    {
        # Anything target-related
        "target",
        "url",
        "host",
        "domain",
        "ip",
        "ips",
        "hostname",
        "scope",
        # Findings content
        "title",
        "description",
        "evidence",
        "poc",
        "remediation",
        "request",
        "response",
        # Auth / secrets
        "api_key",
        "apikey",
        "token",
        "password",
        "secret",
        "key",
        "username",
        "user",
        "email",
        # Free-form text that could contain anything
        "message",
        "log",
        "stdout",
        "stderr",
        "raw",
        # Personal data
        "name",
        "company",
        "organization",
    }
)

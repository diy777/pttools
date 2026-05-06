"""Dashboard linking for pentest-tools CLI.

pentest-tools runs fully locally — all scans, all agents, all tools work
without auth. This module links the CLI to an app.pentest-tools.local workspace
so findings can sync to a cloud dashboard (Pro / Team / Enterprise tiers).

Key resolution order:
    1. PENTEST_TOOLS_API_KEY environment variable (takes precedence, good for CI/CD)
    2. ~/.pentest-tools/credentials (populated by `pentest-tools auth login`)

The validation endpoint /api/cli/validate is public; ingest endpoints require
the same key via Authorization: Bearer <key>.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger("pentest-tools.auth")

PENTEST_TOOLS_DIR = Path.home() / ".pentest-tools"
CREDENTIALS_FILE = PENTEST_TOOLS_DIR / "credentials"
ENV_VAR_NAME = "PENTESTAI_API_KEY"

DEFAULT_API_BASE = "https://app.pentest-tools.local"
VALIDATION_PATH = "/api/cli/validate"
INGEST_PATH = "/api/cli/ingest"


def api_base() -> str:
    """Dashboard base URL. Override with PENTEST_TOOLS_API_BASE for staging."""
    return os.environ.get("PENTESTAI_API_BASE", DEFAULT_API_BASE).rstrip("/")


def _ensure_dir() -> None:
    PENTEST_TOOLS_DIR.mkdir(mode=0o700, exist_ok=True)


# ---------- persistence ------------------------------------------------------

def store_api_key(api_key: str) -> None:
    """Persist an API key to the credentials file with 0600 perms."""
    _ensure_dir()
    CREDENTIALS_FILE.write_text(api_key.strip())
    CREDENTIALS_FILE.chmod(0o600)


def load_api_key() -> str | None:
    """Return the active API key, preferring the env var.

    Env-var priority keeps CI runners honest — `PENTESTAI_API_KEY` is the
    definitive source when present, so a stale stored credential from a
    previous user cannot accidentally send findings to the wrong workspace.
    """
    env_key = os.environ.get(ENV_VAR_NAME, "").strip()
    if env_key:
        return env_key
    if CREDENTIALS_FILE.exists():
        try:
            key = CREDENTIALS_FILE.read_text().strip()
            return key or None
        except OSError:
            return None
    return None


def key_source() -> str | None:
    """Return 'env' / 'file' / None, for display purposes."""
    if os.environ.get(ENV_VAR_NAME, "").strip():
        return "env"
    if CREDENTIALS_FILE.exists():
        try:
            if CREDENTIALS_FILE.read_text().strip():
                return "file"
        except OSError:
            pass
    return None


def remove_credentials() -> None:
    """Delete the credentials file. Cannot unset the env var (not our job)."""
    if CREDENTIALS_FILE.exists():
        CREDENTIALS_FILE.unlink()


# ---------- remote calls -----------------------------------------------------

def validate_key_remote(api_key: str, *, timeout: float = 10.0) -> dict | None:
    """POST the key to /api/cli/validate. Returns the org payload on success."""
    try:
        resp = httpx.post(
            f"{api_base()}{VALIDATION_PATH}",
            json={"api_key": api_key},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("valid"):
                return data
        return None
    except httpx.HTTPError as exc:
        logger.debug("Remote validation failed: %s", exc)
        return None


def ingest_engagement(
    payload: dict,
    *,
    api_key: str | None = None,
    timeout: float = 30.0,
) -> dict | None:
    """POST an engagement + findings payload to /api/cli/ingest.

    Payload shape expected by the server:
        {
          "engagement": {"name": str, "target": str, "external_id"?: str, ...},
          "findings":   [{"title": str, "severity": str, "target": str, ...}, ...]
        }

    Returns the server JSON on success.
    Returns a dict with `{"error": ..., "quota_exceeded": True, ...}` for 402
    quota responses so the caller can print a useful message.
    Returns None on network errors / unauth / unknown failures so sync is
    best-effort and never breaks a local scan.
    """
    key = api_key or load_api_key()
    if not key:
        return None
    try:
        resp = httpx.post(
            f"{api_base()}{INGEST_PATH}",
            json=payload,
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
        )
        if resp.status_code in (200, 201):
            return resp.json()
        if resp.status_code == 402:
            # Plan quota exceeded — surface the server-provided details so
            # the CLI can show an actionable upgrade prompt, not a silent drop.
            try:
                body = resp.json()
            except Exception:
                body = {}
            body["quota_exceeded"] = True
            return body
        logger.debug("Ingest non-2xx: %s %s", resp.status_code, resp.text[:200])
        return None
    except httpx.HTTPError as exc:
        logger.debug("Ingest failed: %s", exc)
        return None


# ---------- display helpers --------------------------------------------------

def mask_key(key: str) -> str:
    """Return `pttools_abcd…wxyz` style mask for logs and UI."""
    if not key or len(key) < 12:
        return "••••"
    return f"{key[:9]}…{key[-4:]}"

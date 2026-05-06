"""Selection (router) agent.

Picks one of pttools's specialist agents based on a target string plus an
optional free-form intent. Heuristic-only by default so it works without
an LLM and stays deterministic across releases. The deterministic core
is wrapped in a small async class so an LLM-driven variant can subclass
or replace it later without changing call sites.

Returned shape:
    {
      "target": str,          # echoed input target
      "agent": str,           # one of the specialist agent names
      "reason": str,          # short human-readable justification
      "confidence": float,    # 0.0 - 1.0, higher = stronger match
    }

Specialist agent names (must match agents.* keys used by orchestrator
and MCP test_* tools): web, api_security, recon, ad, cloud, mobile,
wireless, credential_tester, social_engineer, llm_redteam, privesc,
vulnerability_scanner.

Agents that don't take a target (detection, report, exploit_chain,
poc_validator) are deliberately not produced by the router because
they're invoked at a different stage of the engagement lifecycle.
"""

from __future__ import annotations

import re
from typing import Any

# Agent name constants — single source of truth.
WEB = "web"
API_SECURITY = "api_security"
RECON = "recon"
AD = "ad"
CLOUD = "cloud"
MOBILE = "mobile"
WIRELESS = "wireless"
CREDENTIAL_TESTER = "credential_tester"
SOCIAL_ENGINEER = "social_engineer"
LLM_REDTEAM = "llm_redteam"


_API_PATH_RE = re.compile(r"/(api|graphql|rest|v\d+)(/|$)", re.IGNORECASE)
_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)
_MOBILE_EXT_RE = re.compile(r"\.(apk|aab|ipa)$", re.IGNORECASE)
_CLOUD_RE = re.compile(
    r"(^arn:aws:|^s3://|^gs://|\.azurewebsites\.net$|\.cloudfront\.net$|"
    r"\.appspot\.com$|\.r2\.cloudflarestorage\.com$)",
    re.IGNORECASE,
)
_LOCAL_TLD_RE = re.compile(r"\.local$", re.IGNORECASE)
_DC_HOST_RE = re.compile(r"^(dc\d*|ad)\.", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)+$")


# Intent keyword groups, ordered by priority. The first matching group wins.
_INTENT_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (LLM_REDTEAM, ("prompt injection", "llm", "jailbreak", "system prompt")),
    (SOCIAL_ENGINEER, ("phish", "pretext", "vish", "social engineer")),
    (WIRELESS, ("wifi", "wireless", "ssid", "bssid", "wpa", "rogue ap")),
    (AD, ("active directory", "kerberos", "kerberoast", "domain controller", "ntds", "bloodhound")),
    (CREDENTIAL_TESTER, ("brute", "spray", "credential stuff", "password attack")),
    (CLOUD, ("aws", "azure", "gcp", "iam", "s3 bucket", "metadata service")),
    (MOBILE, ("apk", "ipa", "android app", "ios app", "frida")),
    (API_SECURITY, ("graphql", "rest api", "openapi", "swagger", "bola", "broken object")),
]


def route_target(target: str, intent: str = "") -> dict[str, Any]:
    """Heuristic router: classify a target into a specialist agent.

    Raises ValueError on empty/whitespace target. Always returns a result
    even for unknown inputs (recon fallback) so callers don't have to
    handle a None case.
    """
    if not target or not target.strip():
        raise ValueError("target must not be empty")
    target = target.strip()
    intent_lower = (intent or "").lower()

    # 1. Intent keywords get first priority — operator's stated goal beats
    #    string heuristics. Kerberoast intent on a web URL still routes to AD.
    for agent_name, keywords in _INTENT_KEYWORDS:
        for kw in keywords:
            if kw in intent_lower:
                return _result(target, agent_name, f"intent matched '{kw}'", 0.85)

    # 2. URL-based heuristics
    if _HTTP_RE.match(target):
        if _API_PATH_RE.search(target):
            return _result(target, API_SECURITY, "url contains api/graphql/rest/v\\d+ path", 0.9)
        return _result(target, WEB, "http(s) url without api path → web app", 0.85)

    # 3. File extensions
    if _MOBILE_EXT_RE.search(target):
        return _result(target, MOBILE, "mobile artifact extension", 0.95)

    # 4. Cloud resource identifiers
    if _CLOUD_RE.search(target):
        return _result(target, CLOUD, "cloud-resource identifier", 0.9)

    # 5. AD heuristics — .local TLD or dc/ad hostname prefix
    if _LOCAL_TLD_RE.search(target) or _DC_HOST_RE.match(target):
        return _result(target, AD, "AD-style hostname (dc*/ad. or .local)", 0.8)

    # 6. Bare IP/CIDR or domain → recon as the right entry point
    if _IP_RE.match(target):
        return _result(target, RECON, "bare IP or CIDR → recon", 0.85)
    if _DOMAIN_RE.match(target):
        return _result(target, RECON, "bare domain → recon", 0.8)

    # 7. Fallback
    return _result(target, RECON, "unrecognized target shape, defaulting to recon", 0.4)


def _result(target: str, agent: str, reason: str, confidence: float) -> dict[str, Any]:
    return {
        "target": target,
        "agent": agent,
        "reason": reason,
        "confidence": round(confidence, 2),
    }


class SelectionAgent:
    """Async wrapper around route_target.

    Kept as a class so a future LLM-backed variant can subclass and
    call super().route() as a fast deterministic fallback.
    """

    agent_type = "selection"

    def __init__(self, llm: Any | None = None):
        self.llm = llm  # currently unused; reserved for LLM-backed routing

    async def route(self, target: str, intent: str = "") -> dict[str, Any]:
        return route_target(target, intent=intent)

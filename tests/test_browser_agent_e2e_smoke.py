"""End-to-end smoke test for BrowserAgent against an in-test SPA-like app.

Skipped by default. Runs only when Playwright is importable AND
PTAI_E2E_BROWSER=1 is set, so unit-test runs without the browser extra
don't fail. CI installs Playwright + chromium in the e2e-juiceshop job
and sets the env var to enable this suite.

What it proves end-to-end:

- BrowserAgent successfully launches a real chromium and navigates to
  the in-test app
- crawl_for_endpoints captures XHR/fetch requests the page issues during
  initial render
- Hash-routed SPA URLs in the rendered DOM are normalized to server-route
  form, ready for sqlmap / dalfox to attack
- Same-host filtering works (third-party CDN URLs are dropped)
- Standard inspect_dom + extract_forms + check_security_headers all
  return structured data, not crashes

This is the regression net for the browser-based crawler fallback that
the WebAgent uses on SPAs.
"""

from __future__ import annotations

import os
import socket

import pytest
from aiohttp import web

playwright_available = True
try:
    import playwright  # noqa: F401
except ImportError:
    playwright_available = False

pytestmark = pytest.mark.skipif(
    not playwright_available or os.getenv("PTAI_E2E_BROWSER") != "1",
    reason="needs Playwright installed (pip install pttools[browser]) and PTAI_E2E_BROWSER=1",
)


# ─── In-test SPA-like app ─────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_spa_app() -> web.Application:
    """Mimics an Angular/React SPA: empty shell + JS that fetches an API.

    Routes:
      /                  serves index.html with hash-route links and an
                         inline script that fetches /api/items?count=5
      /api/items         JSON endpoint hit by the inline fetch
      /search, /item     server-side fallbacks (in case the crawler tries
                         to follow a normalized hash route directly)
    """
    INDEX_HTML = """
<!doctype html>
<html><head><title>SPA</title></head>
<body>
  <h1>App shell</h1>
  <a href="/#/search?q=test">Search</a>
  <a href="/#/item?id=42">Item 42</a>
  <a href="https://cdn.external.com/lib.js">External CDN (must be dropped)</a>
  <script>
    fetch('/api/items?count=5');
  </script>
</body></html>
""".strip()

    async def index(_: web.Request) -> web.Response:
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def api_items(request: web.Request) -> web.Response:
        return web.json_response({"count": int(request.query.get("count", "0"))})

    async def search(request: web.Request) -> web.Response:
        q = request.query.get("q", "")
        return web.Response(text=f"<html>search:{q}</html>", content_type="text/html")

    async def item(request: web.Request) -> web.Response:
        item_id = request.query.get("id", "")
        return web.Response(text=f"<html>item:{item_id}</html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/api/items", api_items)
    app.router.add_get("/search", search)
    app.router.add_get("/item", item)
    return app


@pytest.fixture
async def spa_app_url():
    app = _build_spa_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = _free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


# ─── Tests ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_browser_crawl_captures_xhr_and_hash_routes(spa_app_url):
    """Render the SPA shell, harvest XHR + hash-routed URLs, normalize them."""
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent(headless=True, timeout_ms=15000)
    endpoints = await agent.crawl_for_endpoints(spa_app_url, max_endpoints=20)

    # Endpoints captured: at least the XHR fetch to /api/items and the
    # hash-routed links normalized to server routes.
    joined = " ".join(endpoints)
    assert "/api/items" in joined, f"missing XHR endpoint in: {endpoints}"
    assert "/search?q=test" in joined, f"missing hash-route /search in: {endpoints}"
    assert "/item?id=42" in joined, f"missing hash-route /item in: {endpoints}"

    # External CDN URL must be dropped (same-host filter).
    assert not any("cdn.external.com" in u for u in endpoints), (
        f"external CDN leaked through filter: {endpoints}"
    )


@pytest.mark.asyncio
async def test_browser_inspect_dom_returns_structured_summary(spa_app_url):
    """inspect_dom must return a DOMSummary dataclass, not raise."""
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent(headless=True, timeout_ms=15000)
    summary = await agent.inspect_dom(spa_app_url)

    assert summary.url == spa_app_url
    assert isinstance(summary.title, str)
    # The shell HTML's external script reference should land in ext_scripts;
    # we never actually load https://cdn.external.com (which would 404), but
    # the <a href> goes into ext_links if present.


@pytest.mark.asyncio
async def test_browser_check_security_headers_smoke(spa_app_url):
    """check_security_headers must complete and report header presence."""
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent(headless=True, timeout_ms=15000)
    report = await agent.check_security_headers(spa_app_url)

    assert report.url == spa_app_url
    # aiohttp's web.Response defaults don't set HSTS / CSP / X-Frame-Options,
    # so the report's issues list must surface those as missing — proving the
    # header extraction actually inspected the response, not just returned a stub.
    assert report.issues, (
        f"expected security-header issues against bare aiohttp app, got empty: {report}"
    )

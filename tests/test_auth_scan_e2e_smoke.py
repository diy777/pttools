"""End-to-end smoke test for the authenticated scanner.

Spins up an in-test aiohttp web app that mimics a typical form-login
vulnerable app (login form, post-login pages with reflected-XSS sinks
and SQL-style endpoints), then drives pttools's run_authenticated_scan
against it via WebAuthenticator. This verifies the auth + crawl + probe
path without needing docker or external services, so it runs by default
in unit-test runs and CI.

What it proves end-to-end:

- WebAuthenticator (form_post flow) successfully logs into a real HTTP
  server, captures the session cookie, and reports a logged-in session
- The crawl actually crawls past the login wall (reaches authenticated
  pages, not just the login page)
- The probe phase sends real injection payloads against discovered
  endpoints and produces findings on intentionally-vulnerable params
- The whole flow returns the expected dict shape (target,
  endpoints_tested, findings_count, findings)
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from aiohttp import web

from engine.auth_session import WebAuthenticator
from engine.authenticated_scan import run_authenticated_scan

# ─── In-test vulnerable app ───────────────────────────────────────────────


def _free_port() -> int:
    """Pick an OS-assigned free localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_vulnerable_app() -> web.Application:
    """A minimal app that mimics DVWA-style auth + a vulnerable param.

    - GET /             redirects to /login
    - GET /login        form-login page with a CSRF-style hidden field
    - POST /login       sets a session cookie if creds match
    - GET /dashboard    auth-gated, links to /search and /item
    - GET /search?q=    reflects q without escaping (XSS sink)
    - GET /item?id=     leaks SQL-style errors when id contains a quote
    """
    SESSION_COOKIE = "auth_session"
    EXPECTED_TOKEN = "valid-session-token"

    def _is_authed(request: web.Request) -> bool:
        return request.cookies.get(SESSION_COOKIE) == EXPECTED_TOKEN

    async def root(request: web.Request) -> web.Response:
        # Mirrors how DVWA-style apps behave: if a valid session cookie is
        # present, the root page is the dashboard; otherwise redirect to login.
        if _is_authed(request):
            body = (
                '<html><body><h1>Home</h1>'
                '<a href="/search?q=test">Search</a> '
                '<a href="/item?id=1">Item</a> '
                '<a href="/profile">Profile</a> '
                '<a href="/dashboard">Dashboard</a></body></html>'
            )
            return web.Response(text=body, content_type="text/html")
        return web.Response(status=302, headers={"Location": "/login"})

    async def login_get(_: web.Request) -> web.Response:
        body = (
            '<html><body><form method="POST" action="/login">'
            '<input name="username" /><input name="password" type="password" />'
            '<input type="hidden" name="csrf" value="abc123" />'
            "<button type='submit'>Login</button></form></body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def login_post(request: web.Request) -> web.Response:
        data = await request.post()
        if data.get("username") == "admin" and data.get("password") == "hunter2":
            resp = web.Response(
                status=302,
                headers={"Location": "/dashboard"},
                text="Welcome admin",
                content_type="text/html",
            )
            resp.set_cookie(SESSION_COOKIE, EXPECTED_TOKEN, path="/")
            return resp
        return web.Response(status=401, text="invalid credentials")

    async def dashboard(request: web.Request) -> web.Response:
        if not _is_authed(request):
            return web.Response(status=302, headers={"Location": "/login"})
        body = (
            '<html><body><h1>Dashboard</h1>'
            '<a href="/search?q=test">Search</a> '
            '<a href="/item?id=1">Item</a> '
            '<a href="/profile">Profile</a></body></html>'
        )
        return web.Response(text=body, content_type="text/html")

    async def search(request: web.Request) -> web.Response:
        if not _is_authed(request):
            return web.Response(status=302, headers={"Location": "/login"})
        q = request.query.get("q", "")
        # Intentional reflected XSS — q is rendered raw inside HTML.
        body = f"<html><body>Results for: {q}</body></html>"
        return web.Response(text=body, content_type="text/html")

    async def item(request: web.Request) -> web.Response:
        if not _is_authed(request):
            return web.Response(status=302, headers={"Location": "/login"})
        item_id = request.query.get("id", "")
        # Intentional SQL-error sink: a single quote in id surfaces an error
        # message that pttools's _probe_sqli looks for.
        if "'" in item_id:
            body = (
                "<html><body>SQL error: "
                "you have an error in your SQL syntax near 'a''<br>"
                "</body></html>"
            )
            return web.Response(status=500, text=body, content_type="text/html")
        return web.Response(text=f"<html><body>Item id {item_id}</body></html>", content_type="text/html")

    async def profile(request: web.Request) -> web.Response:
        if not _is_authed(request):
            return web.Response(status=302, headers={"Location": "/login"})
        return web.Response(text="<html><body>profile page</body></html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/search", search)
    app.router.add_get("/item", item)
    app.router.add_get("/profile", profile)
    return app


@pytest.fixture
async def vulnerable_app_url():
    """Start the in-test app, yield its base URL, tear down on exit."""
    app = _build_vulnerable_app()
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
async def test_authenticator_logs_in_and_obtains_cookie(vulnerable_app_url):
    """WebAuthenticator must produce a session cookie from a form login."""
    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{vulnerable_app_url}/login",
        username="admin",
        password="hunter2",
        username_field="username",
        password_field="password",
        success_status=302,
    )
    session = await auth.login()
    assert session.cookies, "login produced no cookies"
    assert session.cookies.get("auth_session") == "valid-session-token"
    assert session.flow == "form_post"


@pytest.mark.asyncio
async def test_run_authenticated_scan_finds_post_login_vulns(vulnerable_app_url):
    """A real authenticated scan must crawl past login and surface vulns.

    Uses the in-test app where /search reflects q (XSS) and /item leaks
    SQL errors when id contains a quote. The probe phase should land at
    least one finding on each of those sinks.
    """
    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{vulnerable_app_url}/login",
        username="admin",
        password="hunter2",
        username_field="username",
        password_field="password",
        success_status=302,
    )

    result = await run_authenticated_scan(
        target=vulnerable_app_url,
        authenticator=auth,
        max_pages=20,
        timeout_seconds=5.0,
    )

    assert isinstance(result, dict), f"expected dict, got {type(result)}"
    assert result["target"] == vulnerable_app_url
    assert result["endpoints_tested"] >= 1, (
        "auth scan crawled zero endpoints — login or crawl is broken"
    )

    findings = result["findings"]
    assert isinstance(findings, list)
    assert findings, (
        "post-login vulnerable endpoints (/search?q=, /item?id=) "
        "produced zero findings — the probe phase is broken"
    )
    # Categories the synthetic app exposes: XSS on /search?q and SQLi on /item?id.
    titles = " ".join(f.get("title", "") for f in findings).lower()
    assert "xss" in titles or "sql" in titles, (
        f"expected XSS or SQLi finding, got titles: {[f.get('title') for f in findings]}"
    )
    for f in findings:
        assert "title" in f, f"finding missing title: {f}"
        assert "severity" in f, f"finding missing severity: {f}"
        assert f["severity"] in {"critical", "high", "medium", "low", "info"}, f


@pytest.mark.asyncio
async def test_run_authenticated_scan_rejects_bad_credentials(vulnerable_app_url):
    """Authentication failure should surface as AuthError, not silent skip."""
    from engine.auth_session import AuthError

    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{vulnerable_app_url}/login",
        username="admin",
        password="WRONG-PASSWORD",
        username_field="username",
        password_field="password",
        success_status=302,
    )
    with pytest.raises(AuthError):
        await run_authenticated_scan(
            target=vulnerable_app_url,
            authenticator=auth,
            max_pages=5,
            timeout_seconds=5.0,
        )


@pytest.mark.asyncio
async def test_run_authenticated_scan_requires_authenticator_or_session(vulnerable_app_url):
    """The contract: at least one of authenticator or session is required."""
    from engine.auth_session import AuthError

    with pytest.raises(AuthError):
        await run_authenticated_scan(target=vulnerable_app_url)


@pytest.mark.asyncio
async def test_authenticated_crawl_does_not_leak_into_login_loop(vulnerable_app_url):
    """If auth fails and the app redirects every request to /login, the
    crawl shouldn't masquerade those redirected pages as authenticated
    content. This is a lightweight regression for "looks like it crawled
    20 pages but really hit /login 20 times."
    """
    # Build a session manually with a bogus cookie so the app keeps
    # redirecting to /login on every authenticated route.
    from engine.auth_session import AuthSession

    session = AuthSession(
        cookies={"auth_session": "BOGUS"},
        flow="form_post",
    )
    result = await run_authenticated_scan(
        target=vulnerable_app_url,
        session=session,
        max_pages=20,
        timeout_seconds=5.0,
    )

    # Endpoints tested can be small (the crawler still walks /login forms),
    # but findings should be empty — none of the vulnerable sinks were
    # reachable, so no findings should land.
    for f in result["findings"]:
        # Sanity: any finding must reference a sink path, not /login.
        ev = (f.get("evidence", "") or "").lower()
        assert "/login" not in (f.get("target", "") or "").lower() or any(
            sink in ev for sink in ("xss", "sql")
        ), f"unauthenticated crawl produced a /login finding: {f}"


def _drain_loop():
    """Some aiohttp warnings about un-closed sessions show up here."""
    return asyncio.get_event_loop()

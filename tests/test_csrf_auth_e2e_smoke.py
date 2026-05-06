"""End-to-end smoke test for CSRF-token-aware form login.

Real-world apps like DVWA, Joomla, WordPress, and most modern Django/
Rails sites embed a CSRF token in the login form HTML and reject any
POST that doesn't echo it back. pttools's WebAuthenticator must:

1. GET the login page first
2. Extract the CSRF token from the form's hidden input
3. Include the token in the POST body when submitting credentials

This test uses an in-test aiohttp app that exposes a DVWA-style two-step
login flow (GET form -> extract csrf -> POST credentials with csrf), so
it runs without docker and verifies the wire path of capture_hidden_fields
in real HTTP.
"""

from __future__ import annotations

import secrets
import socket
from typing import Any

import pytest
from aiohttp import web

from engine.auth_session import WebAuthenticator
from engine.authenticated_scan import run_authenticated_scan

# ─── DVWA-style CSRF login app ────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_csrf_login_app() -> tuple[web.Application, dict[str, Any]]:
    """Returns (app, state) where state['issued_tokens'] tracks issued CSRFs.

    Each GET /login mints a fresh CSRF token in a server-side dict.
    POST /login requires the token AND the matching cookie. This is the
    DVWA shape: the form has a hidden user_token, the cookie carries
    the same value, both must be present for the POST to succeed.
    """
    state: dict[str, Any] = {"issued_tokens": set(), "logged_in_sessions": set()}

    SESSION_COOKIE = "PHPSESSID"
    CSRF_COOKIE = "user_token"

    async def login_get(request: web.Request) -> web.Response:
        token = secrets.token_hex(16)
        state["issued_tokens"].add(token)
        body = (
            "<html><body>"
            '<form method="POST" action="/login">'
            '<input name="username" /> '
            '<input name="password" type="password" /> '
            f'<input type="hidden" name="user_token" value="{token}" />'
            "<button type='submit'>Login</button>"
            "</form></body></html>"
        )
        resp = web.Response(text=body, content_type="text/html")
        resp.set_cookie(CSRF_COOKIE, token, path="/")
        return resp

    async def login_post(request: web.Request) -> web.Response:
        data = await request.post()
        submitted_token = data.get("user_token", "")
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        # CSRF check: form token must match the cookie AND have been issued.
        if (
            not submitted_token
            or submitted_token != cookie_token
            or submitted_token not in state["issued_tokens"]
        ):
            return web.Response(status=403, text="CSRF token mismatch")
        if data.get("username") == "admin" and data.get("password") == "password":
            sid = secrets.token_hex(16)
            state["logged_in_sessions"].add(sid)
            resp = web.Response(
                status=302,
                headers={"Location": "/dashboard"},
                text="Welcome admin",
                content_type="text/html",
            )
            resp.set_cookie(SESSION_COOKIE, sid, path="/")
            return resp
        return web.Response(status=401, text="invalid credentials")

    async def dashboard(request: web.Request) -> web.Response:
        sid = request.cookies.get(SESSION_COOKIE, "")
        if sid not in state["logged_in_sessions"]:
            return web.Response(status=302, headers={"Location": "/login"})
        return web.Response(
            text=(
                '<html><body><h1>Dashboard</h1>'
                '<a href="/search?q=test">Search</a></body></html>'
            ),
            content_type="text/html",
        )

    async def search(request: web.Request) -> web.Response:
        sid = request.cookies.get(SESSION_COOKIE, "")
        if sid not in state["logged_in_sessions"]:
            return web.Response(status=302, headers={"Location": "/login"})
        q = request.query.get("q", "")
        return web.Response(
            text=f"<html><body>Results for: {q}</body></html>",
            content_type="text/html",
        )

    async def root(request: web.Request) -> web.Response:
        # Mirrors DVWA: root redirects to /login when unauth'd, dashboard otherwise.
        sid = request.cookies.get(SESSION_COOKIE, "")
        if sid in state["logged_in_sessions"]:
            return web.Response(
                text=(
                    '<html><body><h1>Home</h1>'
                    '<a href="/dashboard">Dashboard</a> '
                    '<a href="/search?q=test">Search</a></body></html>'
                ),
                content_type="text/html",
            )
        return web.Response(status=302, headers={"Location": "/login"})

    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/search", search)
    return app, state


@pytest.fixture
async def csrf_app():
    app, state = _build_csrf_login_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = _free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        await runner.cleanup()


# ─── Tests ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authenticator_captures_csrf_token_from_login_form(csrf_app):
    """capture_hidden_fields must pull the CSRF token before submitting POST.

    With capture_hidden_fields=True (the default), WebAuthenticator should
    GET the login page first, parse the hidden user_token input, and
    include it in the POST body. Without this, the POST returns 403.
    """
    base, _state = csrf_app
    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{base}/login",
        username="admin",
        password="password",
        username_field="username",
        password_field="password",
        success_status=302,
        capture_hidden_fields=True,
    )
    session = await auth.login()
    # Login produced a session cookie — proves the CSRF round-trip worked.
    assert session.cookies, "no session cookies after CSRF login"
    assert "PHPSESSID" in session.cookies, (
        f"login didn't return session cookie; CSRF round-trip likely failed: "
        f"{session.cookies}"
    )


@pytest.mark.asyncio
async def test_authenticator_fails_when_capture_hidden_fields_disabled(csrf_app):
    """Disabling hidden-field capture against a CSRF-protected form must fail.

    Pins the contract: capture_hidden_fields=True is the only way to
    successfully authenticate against CSRF-protected forms. If a future
    refactor flips the default or breaks the capture, this test catches it.
    """
    from engine.auth_session import AuthError

    base, _state = csrf_app
    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{base}/login",
        username="admin",
        password="password",
        success_status=302,
        capture_hidden_fields=False,
    )
    with pytest.raises(AuthError):
        await auth.login()


@pytest.mark.asyncio
async def test_csrf_authenticated_scan_reaches_protected_pages(csrf_app):
    """A full authenticated scan with CSRF-protected login must crawl past it."""
    base, _state = csrf_app
    auth = WebAuthenticator(
        flow="form_post",
        login_url=f"{base}/login",
        username="admin",
        password="password",
        success_status=302,
        capture_hidden_fields=True,
    )
    result = await run_authenticated_scan(
        target=base,
        authenticator=auth,
        max_pages=10,
        timeout_seconds=5.0,
    )
    # The crawler should have reached the dashboard and seen /search?q.
    # (endpoints_tested counts parameterized endpoints discovered.)
    assert result["endpoints_tested"] >= 1, (
        f"CSRF auth crawl never reached parameterized endpoints: {result}"
    )

"""Tests for engine.auth_session (AuthSession + WebAuthenticator)."""

from __future__ import annotations

import time

import httpx
import pytest

from engine.auth_session import AuthError, AuthSession, WebAuthenticator


class TestAuthSession:
    def test_cookie_string_joins_pairs(self):
        s = AuthSession(cookies={"PHPSESSID": "abc", "security": "low"})
        # dict preserves insertion order in 3.7+, so the join is deterministic.
        assert "PHPSESSID=abc" in s.cookie_string()
        assert "security=low" in s.cookie_string()

    def test_is_expired(self):
        past = AuthSession(created_at=time.time() - 100, expires_at=time.time() - 1)
        assert past.is_expired is True

    def test_not_expired_when_no_ttl(self):
        s = AuthSession(created_at=time.time(), expires_at=None)
        assert s.is_expired is False

    def test_to_credentials_cookie(self):
        s = AuthSession(cookies={"s": "1"})
        creds = s.to_credentials()
        assert creds.auth_type == "cookie"
        assert creds.cookies == "s=1"

    def test_to_credentials_bearer_preferred(self):
        s = AuthSession(cookies={"s": "1"}, bearer_token="tok")
        creds = s.to_credentials()
        assert creds.auth_type == "bearer"
        assert creds.bearer_token == "tok"

    def test_to_credentials_headers(self):
        s = AuthSession(headers={"X-Api-Key": "k"})
        creds = s.to_credentials()
        assert creds.auth_type == "header"
        assert creds.headers["X-Api-Key"] == "k"

    def test_to_dict_roundtrip_safe(self):
        s = AuthSession(cookies={"a": "1"}, bearer_token="b", flow="form_post")
        d = s.to_dict()
        assert d["cookies"] == {"a": "1"}
        assert d["bearer_token"] == "b"
        assert d["flow"] == "form_post"


class TestBearerStaticFlow:
    @pytest.mark.asyncio
    async def test_success(self):
        auth = WebAuthenticator(flow="bearer_static", bearer_token="t0k3n", default_ttl_seconds=60)
        s = await auth.login()
        assert s.bearer_token == "t0k3n"
        assert s.flow == "bearer_static"
        assert s.expires_at is not None

    @pytest.mark.asyncio
    async def test_missing_token_raises(self):
        auth = WebAuthenticator(flow="bearer_static")
        with pytest.raises(AuthError, match="requires a bearer_token"):
            await auth.login()

    @pytest.mark.asyncio
    async def test_unsupported_flow(self):
        auth = WebAuthenticator(flow="oauth_password")
        with pytest.raises(AuthError, match="unsupported"):
            await auth.login()


class TestFormPostFlow:
    @pytest.mark.asyncio
    async def test_form_post_success_sets_cookie(self):
        """Mock login server via httpx MockTransport."""
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/login"
            body = request.content.decode() if request.content else ""
            assert "user=admin" in body
            assert "password=secret" in body
            resp = httpx.Response(200, text="Welcome admin")
            resp.headers["set-cookie"] = "PHPSESSID=abc123; Path=/"
            return resp

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://target.local/login",
                username="admin",
                password="secret",
                username_field="user",
                password_field="password",
                success_marker="Welcome",
            )
            session = await auth.login(client)

        assert session.cookies.get("PHPSESSID") == "abc123"
        assert session.flow == "form_post"

    @pytest.mark.asyncio
    async def test_form_post_missing_marker_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Invalid password")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://target.local/login",
                username="admin",
                password="wrong",
                success_marker="Welcome",
            )
            with pytest.raises(AuthError, match="success_marker"):
                await auth.login(client)

    @pytest.mark.asyncio
    async def test_form_post_wrong_status_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="nope")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://target.local/login",
                username="admin",
                password="wrong",
                success_status=200,
            )
            with pytest.raises(AuthError, match="status 401"):
                await auth.login(client)

    @pytest.mark.asyncio
    async def test_form_post_no_cookies_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://target.local/login",
                username="admin",
                password="pw",
            )
            with pytest.raises(AuthError, match="no cookies"):
                await auth.login(client)

    @pytest.mark.asyncio
    async def test_form_post_missing_config_raises(self):
        auth = WebAuthenticator(flow="form_post")
        with pytest.raises(AuthError, match="login_url"):
            await auth.login()

        auth = WebAuthenticator(flow="form_post", login_url="http://x/login")
        with pytest.raises(AuthError, match="username and password"):
            await auth.login()

    @pytest.mark.asyncio
    async def test_extra_form_fields_sent(self):
        captured_bodies: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(request.content.decode() if request.content else "")
            resp = httpx.Response(200, text="ok")
            resp.headers["set-cookie"] = "s=1"
            return resp

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://t/login",
                username="admin",
                password="pw",
                extra_form_fields={"csrf_token": "xyz", "Login": "Login"},
            )
            await auth.login(client)

        assert any("csrf_token=xyz" in b for b in captured_bodies)
        assert any("Login=Login" in b for b in captured_bodies)

    @pytest.mark.asyncio
    async def test_auto_captures_hidden_and_submit_fields(self):
        """DVWA-style login: CSRF hidden input + named submit button both posted.

        Locks in _fetch_hidden_fields pattern. Without this, PHP forms whose
        handler gates on $_POST['Login'] would silently not authenticate.
        """
        login_html = """
            <form action="/login.php" method="post">
                <input name="username" type="text" />
                <input name="password" type="password" />
                <input type="hidden" name="user_token" value="deadbeef" />
                <input type="submit" name="Login" value="Login" />
            </form>
        """
        captured_bodies: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=login_html)
            captured_bodies.append(request.content.decode() if request.content else "")
            resp = httpx.Response(200, text="Welcome")
            resp.headers["set-cookie"] = "PHPSESSID=xyz"
            return resp

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://app.local/login.php",
                username="admin",
                password="password",
                success_marker="Welcome",
            )
            await auth.login(client)

        assert captured_bodies, "no POST captured"
        body = captured_bodies[0]
        assert "user_token=deadbeef" in body, f"hidden CSRF not posted: {body}"
        assert "Login=Login" in body, f"submit button not posted: {body}"
        assert "username=admin" in body
        assert "password=password" in body

    @pytest.mark.asyncio
    async def test_auto_capture_skips_credential_fields(self):
        """Hidden/submit capture must not overwrite caller's username/password.

        A malicious or misconfigured page could ship a hidden input with the
        same name as the credential fields. The authenticator's caller-provided
        credentials must always win.
        """
        login_html = """
            <form action="/login" method="post">
                <input type="hidden" name="username" value="attacker" />
                <input type="hidden" name="password" value="attacker-pw" />
                <input type="hidden" name="csrf" value="tok" />
            </form>
        """
        captured_bodies: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=login_html)
            captured_bodies.append(request.content.decode() if request.content else "")
            resp = httpx.Response(200, text="ok")
            resp.headers["set-cookie"] = "s=1"
            return resp

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            auth = WebAuthenticator(
                flow="form_post",
                login_url="http://app.local/login",
                username="realuser",
                password="realpass",
            )
            await auth.login(client)

        body = captured_bodies[0]
        assert "username=realuser" in body
        assert "password=realpass" in body
        assert "attacker" not in body, f"hidden field overrode caller creds: {body}"
        assert "csrf=tok" in body


class TestFindingsDBAuditTrail:
    @pytest.mark.asyncio
    async def test_record_and_read_auth_sessions(self, tmp_path):
        from engine.findings_db import FindingsDB

        db = FindingsDB(str(tmp_path / "f.db"))
        try:
            eng = await db.create_engagement(target="app.local")
            sid = await db.record_auth_session(
                engagement_id=eng["id"],
                flow="form_post",
                login_url="http://app.local/login",
                username="admin",
                expires_at=time.time() + 3600,
            )
            assert sid
            rows = await db.get_auth_sessions(eng["id"])
            assert len(rows) == 1
            assert rows[0]["flow"] == "form_post"
            assert rows[0]["username"] == "admin"
            assert rows[0]["login_url"] == "http://app.local/login"
        finally:
            await db.close()

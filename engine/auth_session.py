"""Authenticated/stateful web scanning primitives.

Holds a live authenticated session (cookies, bearer, custom headers) and
knows how to perform a login flow to obtain one. The resulting session is
convertible to the existing ``AuthCredentials`` so every tool wrapper that
already respects auth flags picks up authenticated scans for free.

Supported flow types:

- ``form_post``: standard HTML login form. POSTs a username/password pair
  to the login URL and captures any Set-Cookie headers.
- ``bearer_static``: static API token in Authorization header. No network
  call; the token is just injected.

OAuth2 ROPC and Playwright-driven SPA logins are intentionally out of
scope here; they're planned as optional follow-ups and shouldn't pull a
heavy dependency (playwright) into the base install.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from engine.auth_handler import AuthCredentials


@dataclass
class AuthSession:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    created_at: float = 0.0
    expires_at: float | None = None  # absolute epoch seconds; None = no expiry known
    flow: str = ""
    last_login_url: str = ""

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() >= self.expires_at

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.created_at) if self.created_at else 0.0

    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def to_credentials(self) -> AuthCredentials:
        auth_type = ""
        if self.bearer_token:
            auth_type = "bearer"
        elif self.cookies:
            auth_type = "cookie"
        elif self.headers:
            auth_type = "header"
        return AuthCredentials(
            auth_type=auth_type,
            cookies=self.cookie_string(),
            bearer_token=self.bearer_token,
            headers=dict(self.headers),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "bearer_token": self.bearer_token,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "flow": self.flow,
            "last_login_url": self.last_login_url,
        }


class AuthError(Exception):
    pass


class WebAuthenticator:
    """Performs a login flow and returns an ``AuthSession``.

    The success check is deliberately customizable: a ``success_marker``
    substring must appear in the response body, or ``success_status`` must
    match the response code (default 200 or 302). This lets teams wire up
    any login form without code changes.
    """

    def __init__(
        self,
        *,
        flow: str,
        login_url: str = "",
        username: str = "",
        password: str = "",
        username_field: str = "username",
        password_field: str = "password",
        extra_form_fields: dict[str, str] | None = None,
        success_marker: str = "",
        success_status: int | None = None,
        bearer_token: str = "",
        default_ttl_seconds: int = 3600,
        timeout_seconds: float = 15.0,
        capture_hidden_fields: bool = True,
    ) -> None:
        self.flow = flow
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_form_fields = dict(extra_form_fields or {})
        self.success_marker = success_marker
        self.success_status = success_status
        self.bearer_token = bearer_token
        self.default_ttl_seconds = default_ttl_seconds
        self.timeout_seconds = timeout_seconds
        self.capture_hidden_fields = capture_hidden_fields

    async def login(self, client: httpx.AsyncClient | None = None) -> AuthSession:
        if self.flow == "form_post":
            return await self._login_form_post(client)
        if self.flow == "bearer_static":
            return self._login_bearer_static()
        raise AuthError(f"unsupported auth flow: {self.flow}")

    def _login_bearer_static(self) -> AuthSession:
        if not self.bearer_token:
            raise AuthError("bearer_static flow requires a bearer_token")
        now = time.time()
        return AuthSession(
            bearer_token=self.bearer_token,
            created_at=now,
            expires_at=now + self.default_ttl_seconds if self.default_ttl_seconds > 0 else None,
            flow="bearer_static",
        )

    async def _login_form_post(self, client: httpx.AsyncClient | None) -> AuthSession:
        if not self.login_url:
            raise AuthError("form_post flow requires login_url")
        if not self.username or not self.password:
            raise AuthError("form_post flow requires username and password")

        data = {
            self.username_field: self.username,
            self.password_field: self.password,
            **self.extra_form_fields,
        }

        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False)

        try:
            if self.capture_hidden_fields:
                hidden = await self._fetch_hidden_fields(client)
                for k, v in hidden.items():
                    data.setdefault(k, v)
            resp = await client.post(self.login_url, data=data)
            self._assert_success(resp)
            cookies = {k: v for k, v in resp.cookies.items()}
            if not cookies and client.cookies:
                cookies = {k: v for k, v in client.cookies.items()}
        finally:
            if owns_client:
                await client.aclose()

        if not cookies:
            raise AuthError(
                "login returned no cookies; check credentials or success_marker/success_status"
            )

        now = time.time()
        return AuthSession(
            cookies=cookies,
            created_at=now,
            expires_at=now + self.default_ttl_seconds if self.default_ttl_seconds > 0 else None,
            flow="form_post",
            last_login_url=self.login_url,
        )

    async def _fetch_hidden_fields(self, client: httpx.AsyncClient) -> dict[str, str]:
        """GET the login URL and return inputs the form needs beyond user/pass.

        Captures both hidden inputs (CSRF tokens like DVWA's ``user_token`` or
        Rails ``authenticity_token``) and submit buttons (DVWA's ``Login=Login``).
        PHP forms frequently require the submit button's name to be posted so
        their handler fires. The username/password fields are skipped so the
        authenticator's caller-provided credentials always win.
        """
        import re as _re

        try:
            resp = await client.get(self.login_url)
        except Exception:
            return {}
        html = resp.text
        pattern = _re.compile(
            r"<input\b[^>]*?type\s*=\s*['\"]?(hidden|submit)['\"]?[^>]*?>",
            flags=_re.IGNORECASE,
        )
        fields: dict[str, str] = {}
        skip = {self.username_field, self.password_field}
        for match in pattern.finditer(html):
            tag_text = match.group(0)
            name_m = _re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag_text, flags=_re.IGNORECASE)
            value_m = _re.search(r"value\s*=\s*['\"]([^'\"]*)['\"]", tag_text, flags=_re.IGNORECASE)
            if name_m and name_m.group(1) not in skip:
                fields[name_m.group(1)] = value_m.group(1) if value_m else ""
        return fields

    def _assert_success(self, resp: httpx.Response) -> None:
        if self.success_marker:
            if self.success_marker not in resp.text:
                raise AuthError(
                    f"login success_marker '{self.success_marker}' not in response "
                    f"(status {resp.status_code})"
                )
            return
        if self.success_status is not None:
            if resp.status_code != self.success_status:
                raise AuthError(
                    f"login returned status {resp.status_code}, expected {self.success_status}"
                )
            return
        # Default: accept 2xx and 3xx.
        if resp.status_code >= 400:
            raise AuthError(f"login returned error status {resp.status_code}")

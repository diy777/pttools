"""Tests for BrowserAgent — uses a stubbed Playwright module so the suite
does not need a real browser or network access.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest


def _install_fake_playwright(headers: dict[str, str], dom_payload: dict[str, Any]) -> types.ModuleType:
    """Inject a fake playwright.async_api into sys.modules."""
    pkg = types.ModuleType("playwright")
    api = types.ModuleType("playwright.async_api")

    class _Response:
        def __init__(self, hdrs: dict[str, str]) -> None:
            self.headers = hdrs
            self.status = 200
            self.url = "https://example.test/"
            self.request = type("R", (), {"method": "GET", "resource_type": "document", "headers": {}})()

    class _Page:
        def __init__(self) -> None:
            self.title_value = "Test page"
            self._handlers: dict[str, list[Any]] = {}

        async def goto(self, url: str, **kwargs: Any) -> _Response:
            self.url = url
            return _Response(headers)

        async def title(self) -> str:
            return self.title_value

        async def evaluate(self, script: str, *args: Any) -> Any:
            # Hand back canned values keyed on snippets we recognize
            if "querySelectorAll('iframe')" in script:
                return dom_payload.get("iframe_count", 0)
            if "querySelectorAll('form')" in script and "input_count" in script:
                return dom_payload.get("forms", [])
            if "querySelectorAll('form')" in script and "inputs:" in script:
                return dom_payload.get("forms_full", [])
            if "querySelectorAll('script[src]')" in script:
                return dom_payload.get("ext_scripts", [])
            if "querySelectorAll('a[href]')" in script:
                return dom_payload.get("ext_links", [])
            return None

        async def screenshot(self, **kwargs: Any) -> bytes:
            return b"\x89PNG\r\n\x1a\nfake-bytes"

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        def on(self, event: str, handler: Any) -> None:
            self._handlers.setdefault(event, []).append(handler)

    class _Ctx:
        async def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
            return None

        async def add_init_script(self, script: str) -> None:
            return None

        async def new_page(self) -> _Page:
            return _Page()

        async def close(self) -> None:
            return None

    class _Browser:
        async def new_context(self, **kwargs: Any) -> _Ctx:
            return _Ctx()

        async def close(self) -> None:
            return None

    class _Chromium:
        async def launch(self, **kwargs: Any) -> _Browser:
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

        async def stop(self) -> None:
            return None

    class _AsyncPlaywrightCtx:
        async def start(self) -> _Playwright:
            return _Playwright()

    def async_playwright() -> _AsyncPlaywrightCtx:
        return _AsyncPlaywrightCtx()

    api.async_playwright = async_playwright
    sys.modules["playwright"] = pkg
    sys.modules["playwright.async_api"] = api
    return api


@pytest.mark.asyncio
async def test_check_security_headers_flags_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(
        headers={"server": "nginx", "x-powered-by": "Express"},
        dom_payload={},
    )
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    report = await agent.check_security_headers("https://example.test/")

    issues_text = " ".join(report.issues)
    assert "Content-Security-Policy" in issues_text
    assert "Strict-Transport-Security" in issues_text
    assert "X-Frame-Options" in issues_text
    assert "X-Content-Type-Options" in issues_text
    assert "Referrer-Policy" in issues_text
    assert "Server banner exposed" in issues_text
    assert "X-Powered-By exposed" in issues_text


@pytest.mark.asyncio
async def test_check_security_headers_clean_when_all_present(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        },
        dom_payload={},
    )
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    report = await agent.check_security_headers("https://example.test/")
    assert report.issues == []


@pytest.mark.asyncio
async def test_inspect_dom_summarizes_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(
        headers={},
        dom_payload={
            "forms": [
                {"action": "/login", "method": "POST", "input_count": 3, "has_password": True, "has_csrf": True},
            ],
            "ext_scripts": ["https://cdn.example.com/a.js", "https://www.googletagmanager.com/x.js"],
            "ext_links": ["https://twitter.com/x"],
            "iframe_count": 1,
        },
    )
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    summary = await agent.inspect_dom("https://example.test/")
    assert summary.title == "Test page"
    assert summary.form_count == 1
    assert summary.script_count == 2
    assert summary.iframe_count == 1
    assert summary.forms[0]["has_password"] is True


@pytest.mark.asyncio
async def test_extract_forms_grades_security_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(
        headers={},
        dom_payload={
            "forms_full": [
                {
                    "action": "https://example.test/login",
                    "method": "POST",
                    "inputs": [
                        {"name": "email", "type": "email", "required": True, "placeholder": ""},
                        {"name": "password", "type": "password", "required": True, "placeholder": ""},
                        {"name": "csrf_token", "type": "hidden", "required": False, "placeholder": ""},
                    ],
                },
                {
                    "action": "http://insecure.test/submit",
                    "method": "POST",
                    "inputs": [
                        {"name": "msg", "type": "text", "required": False, "placeholder": ""},
                    ],
                },
            ],
        },
    )
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    forms = await agent.extract_forms("https://example.test/")
    assert len(forms) == 2
    assert forms[0].has_password_field is True
    assert forms[0].has_csrf_token is True
    assert forms[0].submitted_via_https is True
    assert forms[1].submitted_via_https is False
    assert forms[1].has_password_field is False


@pytest.mark.asyncio
async def test_capture_screenshot_returns_png_bytes(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _install_fake_playwright(headers={}, dom_payload={})
    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    out_path = str(tmp_path / "shot.png")
    png = await agent.capture_screenshot("https://example.test/", out_path=out_path)
    assert png.startswith(b"\x89PNG")
    # File written
    import os
    assert os.path.isfile(out_path)
    assert os.path.getsize(out_path) > 0


@pytest.mark.asyncio
async def test_browser_agent_raises_when_playwright_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    sys.modules.pop("playwright", None)
    sys.modules.pop("playwright.async_api", None)

    import builtins
    real_import = builtins.__import__

    def block(name: str, *a: Any, **kw: Any) -> Any:
        if name.startswith("playwright"):
            raise ImportError("simulated missing playwright")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", block)

    from agents.browser.browser_agent import BrowserAgent

    agent = BrowserAgent()
    with pytest.raises(RuntimeError, match=r"Playwright"):
        await agent.check_security_headers("https://example.test/")


@pytest.mark.asyncio
async def test_to_dict_serializes_dataclass() -> None:
    from agents.browser.browser_agent import SecurityHeadersReport, to_dict

    rep = SecurityHeadersReport(url="x", headers={"a": "b"}, issues=["i1", "i2"])
    d = to_dict(rep)
    assert d == {"url": "x", "headers": {"a": "b"}, "issues": ["i1", "i2"]}

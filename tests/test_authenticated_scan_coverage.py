"""Coverage fill for engine/authenticated_scan.py.

Targets the helpers that don't need a live HTTP server: _same_host,
_normalize_url, _FormLinkParser link/form extraction, _extract_endpoints
parameter parsing + destructive-param skipping, and _finding shape.

The probe functions and run_authenticated_scan integration are exercised
with httpx response mocks built from raw bytes, no real network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from engine.auth_session import AuthError, AuthSession
from engine.authenticated_scan import (
    DiscoveredEndpoint,
    ScanConfig,
    _crawl,
    _extract_endpoints,
    _finding,
    _FormLinkParser,
    _normalize_url,
    _probe_cmdi,
    _probe_sqli,
    _probe_xss,
    _same_host,
    _send_probe,
    run_authenticated_scan,
)

# ─── _same_host / _normalize_url ────────────────────────────────────────


def test_same_host_match():
    assert _same_host("http://x.test/a", "http://x.test/b") is True


def test_same_host_mismatch():
    assert _same_host("http://x.test", "http://y.test") is False


def test_same_host_case_insensitive():
    assert _same_host("http://X.test", "http://x.TEST") is True


def test_normalize_url_strips_fragment():
    assert _normalize_url("http://x.test/a", "/b#frag") == "http://x.test/b"


def test_normalize_url_resolves_relative():
    assert _normalize_url("http://x.test/a/", "b") == "http://x.test/a/b"


# ─── _FormLinkParser ────────────────────────────────────────────────────


def test_form_link_parser_collects_links_and_forms():
    html = """
    <html>
    <a href="/page1">p1</a>
    <a href="/page2?q=x">p2</a>
    <form action="/submit" method="post">
      <input name="username" value="">
      <input name="password" value="">
      <textarea name="comment">hi</textarea>
    </form>
    </html>
    """
    p = _FormLinkParser("http://x.test")
    p.feed(html)
    assert any("/page1" in link for link in p.links)
    assert any("/page2" in link for link in p.links)
    assert len(p.forms) == 1
    assert p.forms[0]["method"] == "post"
    assert "username" in p.forms[0]["fields"]


def test_form_link_parser_form_without_action_uses_base():
    html = '<form method="get"><input name="q" value=""></form>'
    p = _FormLinkParser("http://x.test/page")
    p.feed(html)
    assert p.forms[0]["action"].startswith("http://x.test/")


# ─── _extract_endpoints ─────────────────────────────────────────────────


def test_extract_endpoints_get_link_with_query():
    html = '<a href="/search?q=foo">s</a><a href="/other">o</a>'
    links, eps = _extract_endpoints("http://x.test", html)
    get_eps = [e for e in eps if e.method == "GET"]
    assert len(get_eps) == 1
    assert "q" in get_eps[0].params


def test_extract_endpoints_skips_destructive_get_link():
    """Links with destructive params (e.g. ?password_new=) must not be probed."""
    html = '<a href="/setup?password_new=evil">link</a>'
    _, eps = _extract_endpoints("http://x.test", html)
    assert eps == []


def test_extract_endpoints_skips_external_links():
    html = '<a href="http://other.test/p?q=x">o</a>'
    _, eps = _extract_endpoints("http://x.test", html)
    assert eps == []


def test_extract_endpoints_skips_destructive_post_form():
    html = """
    <form action="/admin" method="post">
      <input name="delete_user" value="">
    </form>
    """
    _, eps = _extract_endpoints("http://x.test", html)
    assert eps == []


def test_extract_endpoints_collects_safe_post_form():
    html = """
    <form action="/login" method="post">
      <input name="user" value="">
    </form>
    """
    _, eps = _extract_endpoints("http://x.test", html)
    post = [e for e in eps if e.method == "POST"]
    assert len(post) == 1
    assert "user" in post[0].params


def test_extract_endpoints_handles_html_parse_error(caplog):
    """A truly broken parse path should not crash; just log + return empty."""
    # Very malformed HTML; parser should handle without raising.
    html = "<<<>>>"
    _, eps = _extract_endpoints("http://x.test", html)
    # Either empty or non-crashing; the test is the no-exception
    assert isinstance(eps, list)


# ─── _finding ───────────────────────────────────────────────────────────


def test_finding_truncates_long_evidence_and_poc():
    f = _finding(
        title="t",
        description="d",
        severity="high",
        category="c",
        target="x",
        evidence="x" * 5000,
        poc="y" * 3000,
    )
    assert len(f["evidence"]) == 2000
    assert len(f["poc"]) == 1000


def test_finding_default_poc_empty():
    f = _finding(title="t", description="d", severity="info", category="c", target="x", evidence="e")
    assert f["poc"] == ""


# ─── _send_probe ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_probe_get():
    client = MagicMock()
    fake_resp = MagicMock(spec=httpx.Response)
    client.get = AsyncMock(return_value=fake_resp)
    ep = DiscoveredEndpoint(method="GET", url="http://x.test", params={"q": "old"})
    resp = await _send_probe(client, ep, "q", "new")
    assert resp is fake_resp
    args, kwargs = client.get.await_args
    assert kwargs["params"]["q"] == "new"


@pytest.mark.asyncio
async def test_send_probe_post():
    client = MagicMock()
    client.post = AsyncMock(return_value=MagicMock(spec=httpx.Response))
    ep = DiscoveredEndpoint(method="POST", url="http://x.test/login", params={"user": "u"})
    await _send_probe(client, ep, "user", "v")
    args, kwargs = client.post.await_args
    assert kwargs["data"]["user"] == "v"


@pytest.mark.asyncio
async def test_send_probe_swallows_exception():
    client = MagicMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test", params={"q": "1"})
    assert await _send_probe(client, ep, "q", "x") is None


# ─── _probe_sqli ────────────────────────────────────────────────────────


def _resp(status: int = 200, text: str = "") -> MagicMock:
    m = MagicMock(spec=httpx.Response)
    m.status_code = status
    m.text = text
    return m


@pytest.mark.asyncio
async def test_probe_sqli_detects_error_marker():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="warning: mysql_fetch_array() failed"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/q", params={"id": "1"})
    baseline = _resp(text="ok")
    findings = await _probe_sqli(client, ep, baseline)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_probe_sqli_no_error_no_diff_returns_empty():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="ok"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/q", params={"id": "1"})
    baseline = _resp(text="ok")
    findings = await _probe_sqli(client, ep, baseline)
    assert findings == []


@pytest.mark.asyncio
async def test_probe_sqli_handles_probe_failure():
    client = MagicMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/q", params={"id": "1"})
    baseline = _resp(text="ok")
    findings = await _probe_sqli(client, ep, baseline)
    assert findings == []


# ─── _probe_xss ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_xss_detects_reflection():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="<html>echoed: pttools_xss_probe</html>"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/q", params={"q": "1"})
    findings = await _probe_xss(client, ep)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_probe_xss_no_reflection():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="no echo here"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/q", params={"q": "1"})
    findings = await _probe_xss(client, ep)
    assert findings == []


# ─── _probe_cmdi ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_cmdi_detects_id_output():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="result: uid=33(www-data) gid=33(www-data)"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/ping", params={"host": "127.0.0.1"})
    findings = await _probe_cmdi(client, ep)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_probe_cmdi_no_id_marker():
    client = MagicMock()
    client.get = AsyncMock(return_value=_resp(text="echoed something"))
    ep = DiscoveredEndpoint(method="GET", url="http://x.test/ping", params={"host": "1"})
    findings = await _probe_cmdi(client, ep)
    assert findings == []


# ─── run_authenticated_scan ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_authenticated_scan_requires_authenticator_or_session():
    with pytest.raises(AuthError):
        await run_authenticated_scan("http://x.test", authenticator=None, session=None)


@pytest.mark.asyncio
async def test_run_authenticated_scan_with_session_minimal_html():
    """Smoke: scanner runs end-to-end with a session, no endpoints in HTML
    means no findings, but the function returns the expected dict shape."""
    session = AuthSession(cookies={}, headers={"X-Test": "1"}, bearer_token="")

    async def fake_get(url, **kwargs):
        m = MagicMock(spec=httpx.Response)
        m.status_code = 200
        m.text = "<html>nothing parameterized</html>"
        m.headers = {"content-type": "text/html"}
        m.url = url
        return m

    with patch("httpx.AsyncClient") as mock_client_cls:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.get = AsyncMock(side_effect=fake_get)
        mock_client_cls.return_value = client

        result = await run_authenticated_scan(
            "http://x.test",
            session=session,
            max_pages=1,
            timeout_seconds=1.0,
        )

    assert result["target"] == "http://x.test"
    assert "findings_count" in result


@pytest.mark.asyncio
async def test_run_authenticated_scan_calls_authenticator_when_no_session():
    auth = MagicMock()
    auth.login = AsyncMock(return_value=AuthSession(cookies={}, headers={}, bearer_token=""))

    async def fake_get(url, **kwargs):
        m = MagicMock(spec=httpx.Response)
        m.status_code = 200
        m.text = "<html></html>"
        m.headers = {"content-type": "text/html"}
        m.url = url
        return m

    with patch("httpx.AsyncClient") as mock_client_cls:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.get = AsyncMock(side_effect=fake_get)
        mock_client_cls.return_value = client

        await run_authenticated_scan(
            "http://x.test",
            authenticator=auth,
            max_pages=1,
            timeout_seconds=1.0,
        )

    auth.login.assert_awaited_once()


# ─── _crawl ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_crawl_skips_non_html_response():
    cfg = ScanConfig(target="http://x.test", max_pages=5)

    async def fake_get(url, **kwargs):
        m = MagicMock(spec=httpx.Response)
        m.status_code = 200
        m.text = "not html"
        m.headers = {"content-type": "application/octet-stream"}
        m.url = url
        return m

    client = MagicMock()
    client.get = AsyncMock(side_effect=fake_get)
    eps = await _crawl(client, "http://x.test", cfg)
    assert eps == []


@pytest.mark.asyncio
async def test_crawl_skips_url_with_skip_substring():
    cfg = ScanConfig(target="http://x.test", max_pages=5)
    client = MagicMock()
    client.get = AsyncMock()
    # Start URL contains "logout" which is in DEFAULT_SKIP_PATTERNS
    eps = await _crawl(client, "http://x.test/logout", cfg)
    assert eps == []
    client.get.assert_not_called()


@pytest.mark.asyncio
async def test_crawl_handles_http_error():
    cfg = ScanConfig(target="http://x.test", max_pages=5)
    client = MagicMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
    eps = await _crawl(client, "http://x.test", cfg)
    assert eps == []

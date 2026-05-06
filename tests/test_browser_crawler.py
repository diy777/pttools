"""Tests for the browser-based crawler used as a SPA fallback.

The hash-route normalization is the core of the SPA fix: external
crawlers like katana see only the empty SPA shell, but Playwright
renders the page and exposes URLs like https://app/#/search?q=test.
The injection phase needs those routes as if they were server-side
URLs (https://app/search?q=test) so sqlmap and dalfox can attack them.

These tests pin the normalization rules and the wiring fallback so a
future refactor doesn't quietly drop SPA coverage.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.browser.browser_agent import BrowserAgent
from agents.web.web_agent import WebAgent

# ─── URL normalization ────────────────────────────────────────────────────


class TestNormalizeEndpointUrl:
    def test_keeps_same_host_url(self):
        url = BrowserAgent._normalize_endpoint_url(
            "https://app.test/api/search?q=foo", "app.test"
        )
        assert url == "https://app.test/api/search?q=foo"

    def test_drops_external_host(self):
        url = BrowserAgent._normalize_endpoint_url(
            "https://cdn.example.com/lib.js", "app.test"
        )
        assert url is None

    def test_converts_hash_route_to_server_route(self):
        url = BrowserAgent._normalize_endpoint_url(
            "https://app.test/#/search?q=test", "app.test"
        )
        assert url == "https://app.test/search?q=test"

    def test_hash_route_without_query(self):
        url = BrowserAgent._normalize_endpoint_url(
            "https://app.test/#/about", "app.test"
        )
        assert url == "https://app.test/about"

    def test_hash_route_with_complex_query(self):
        url = BrowserAgent._normalize_endpoint_url(
            "https://app.test/#/search?q=test&page=2", "app.test"
        )
        assert url == "https://app.test/search?q=test&page=2"

    def test_drops_garbage_input(self):
        assert BrowserAgent._normalize_endpoint_url("", "app.test") is None
        assert BrowserAgent._normalize_endpoint_url("not-a-url", "app.test") is None
        assert BrowserAgent._normalize_endpoint_url(
            "javascript:void(0)", "app.test"
        ) is None

    def test_non_hash_fragment_left_alone(self):
        # Real anchor fragments like #section-2 should not be treated as a route.
        url = BrowserAgent._normalize_endpoint_url(
            "https://app.test/page?id=1#section-2", "app.test"
        )
        # The URL must still resolve to the original location (we only convert
        # hash-routes, not anchor fragments).
        assert url is not None
        assert "section-2" not in url or "?id=1" in url


# ─── WebAgent browser fallback wiring ─────────────────────────────────────


def _make_inert_external_crawler():
    tool = MagicMock()
    tool.is_installed = MagicMock(return_value=True)

    async def _execute(target, args=None, timeout=600.0):
        return {"stdout": "", "exit_code": 0, "findings": []}

    tool.execute = _execute
    return tool


@pytest.mark.asyncio
async def test_browser_fallback_invoked_when_external_crawler_finds_nothing(
    monkeypatch,
):
    """External crawler returns nothing → browser fallback runs."""
    crawler = _make_inert_external_crawler()
    registry = MagicMock()
    registry.get_tool = lambda name: crawler if name == "katana" else None

    db = MagicMock()
    db.add_finding = AsyncMock()

    fallback_called = {"n": 0}

    async def _fake_browser_crawl(self, target):
        fallback_called["n"] += 1
        return ["https://test.local/search?q=test"]

    monkeypatch.setattr(
        WebAgent, "_discover_param_urls_via_browser", _fake_browser_crawl
    )

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls("https://test.local")

    assert fallback_called["n"] == 1
    assert urls == ["https://test.local/search?q=test"]


@pytest.mark.asyncio
async def test_browser_fallback_skipped_when_external_crawler_succeeds(
    monkeypatch,
):
    """External crawler found URLs → browser fallback NOT invoked (avoid wasted Playwright launch)."""
    crawler = MagicMock()
    crawler.is_installed = MagicMock(return_value=True)

    async def _crawler_execute(target, args=None, timeout=600.0):
        return {
            "stdout": "https://test.local/search?q=foo\nhttps://test.local/item?id=1",
            "exit_code": 0,
            "findings": [],
        }

    crawler.execute = _crawler_execute
    registry = MagicMock()
    registry.get_tool = lambda name: crawler if name == "katana" else None

    db = MagicMock()
    db.add_finding = AsyncMock()

    fallback_called = {"n": 0}

    async def _fake_browser_crawl(self, target):
        fallback_called["n"] += 1
        return []

    monkeypatch.setattr(
        WebAgent, "_discover_param_urls_via_browser", _fake_browser_crawl
    )

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls("https://test.local")

    assert fallback_called["n"] == 0
    assert len(urls) == 2
    assert "https://test.local/search?q=foo" in urls


@pytest.mark.asyncio
async def test_browser_fallback_keeps_only_param_urls(monkeypatch):
    """Browser fallback's param-URL filter must drop URLs without query params."""
    crawler = _make_inert_external_crawler()
    registry = MagicMock()
    registry.get_tool = lambda name: crawler if name == "katana" else None

    db = MagicMock()
    db.add_finding = AsyncMock()

    # Mock BrowserAgent.crawl_for_endpoints to return mixed URLs.
    from agents.browser import browser_agent as ba_mod

    async def _fake_crawl(self, url, max_endpoints=50, wait_until="networkidle"):
        return [
            "https://test.local/",  # no params, drop
            "https://test.local/about",  # no params, drop
            "https://test.local/search?q=test",  # keep
            "https://test.local/api/products?id=1",  # keep
        ]

    monkeypatch.setattr(ba_mod.BrowserAgent, "crawl_for_endpoints", _fake_crawl)

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls_via_browser("https://test.local")

    assert urls == [
        "https://test.local/search?q=test",
        "https://test.local/api/products?id=1",
    ]


@pytest.mark.asyncio
async def test_browser_fallback_returns_empty_when_playwright_missing(
    monkeypatch,
):
    """If BrowserAgent raises RuntimeError (no playwright), fallback is silent."""
    from agents.browser import browser_agent as ba_mod

    async def _raises(self, url, max_endpoints=50, wait_until="networkidle"):
        raise RuntimeError("BrowserAgent requires Playwright. Install with: pip install pttools[browser]")

    monkeypatch.setattr(ba_mod.BrowserAgent, "crawl_for_endpoints", _raises)

    db = MagicMock()
    db.add_finding = AsyncMock()
    registry = MagicMock()
    registry.get_tool = lambda name: None

    agent = WebAgent(registry=registry, db=db, llm=None)
    urls = await agent._discover_param_urls_via_browser("https://test.local")
    assert urls == []

"""Tests for engine.cve_db.

Network calls to osv.dev are mocked. Real-network coverage runs in the
e2e CI job, not in the unit suite.
"""
from __future__ import annotations

import pytest

from engine import cve_db


def test_parse_package_json_dependencies_section():
    text = """{
        "name": "demo",
        "version": "1.0.0",
        "dependencies": {"express": "^4.16.0", "lodash": "~4.17.20"},
        "devDependencies": {"mocha": "10.0.0"}
    }"""
    deps = cve_db.parse_package_json(text)
    by_name = {d["name"]: d["version"] for d in deps}
    assert by_name["express"] == "4.16.0"
    assert by_name["lodash"] == "4.17.20"
    assert by_name["mocha"] == "10.0.0"


def test_parse_package_json_lockfile_v1():
    text = """{
        "name": "demo",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.16.0"},
            "lodash": {"version": "4.17.15"}
        }
    }"""
    deps = cve_db.parse_package_json(text)
    by_name = {d["name"]: d["version"] for d in deps}
    assert by_name["express"] == "4.16.0"
    assert by_name["lodash"] == "4.17.15"


def test_parse_package_json_lockfile_v2_packages():
    text = """{
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/express": {"version": "4.16.0"},
            "node_modules/lodash": {"version": "4.17.15"}
        }
    }"""
    deps = cve_db.parse_package_json(text)
    by_name = {d["name"]: d["version"] for d in deps}
    assert by_name["express"] == "4.16.0"
    assert by_name["lodash"] == "4.17.15"


def test_parse_package_json_invalid_input_returns_empty():
    assert cve_db.parse_package_json("") == []
    assert cve_db.parse_package_json("not json") == []
    assert cve_db.parse_package_json("123") == []


def test_strip_version_handles_semver_prefixes():
    assert cve_db._strip_version("^4.16.0") == "4.16.0"
    assert cve_db._strip_version("~1.0.0") == "1.0.0"
    assert cve_db._strip_version(">=2.0.0") == "2.0.0"
    assert cve_db._strip_version("=4.5") == "4.5"
    assert cve_db._strip_version("3.0.0 || 4.0.0") == "3.0.0"


def test_filter_vulnerable_drops_clean_packages():
    rows = [
        {"name": "a", "version": "1", "vulnerabilities": ["GHSA-1"]},
        {"name": "b", "version": "1", "vulnerabilities": []},
        {"name": "c", "version": "1", "vulnerabilities": ["GHSA-2", "GHSA-3"]},
    ]
    out = cve_db.filter_vulnerable(rows)
    assert [r["name"] for r in out] == ["a", "c"]


@pytest.mark.asyncio
async def test_query_batch_empty_returns_empty():
    out = await cve_db.query_batch([])
    assert out == []


@pytest.mark.asyncio
async def test_lookup_npm_packages_round_trip(monkeypatch):
    """Mock the batch transport and confirm the per-package shape lines up."""
    fake_results = [
        ["GHSA-aaaa-bbbb-cccc"],   # express -> one vuln
        [],                        # lodash -> clean
    ]

    async def fake_batch(queries, *, session=None):
        # The batch input must mirror the dep input order.
        assert len(queries) == 2
        assert queries[0]["package"]["name"] == "express"
        assert queries[1]["package"]["name"] == "lodash"
        return fake_results

    monkeypatch.setattr(cve_db, "query_batch", fake_batch)

    result = await cve_db.lookup_npm_packages([
        {"name": "express", "version": "4.16.0"},
        {"name": "lodash", "version": "4.17.15"},
    ])
    assert result == [
        {"name": "express", "version": "4.16.0", "vulnerabilities": ["GHSA-aaaa-bbbb-cccc"]},
        {"name": "lodash", "version": "4.17.15", "vulnerabilities": []},
    ]


@pytest.mark.asyncio
async def test_query_batch_handles_http_error(monkeypatch):
    """Non-200 from osv must produce empty results, not raise."""
    class FakeResp:
        def __init__(self):
            self.status = 503
        async def text(self):
            return "Service Unavailable"
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def __init__(self):
            self.closed = False
        def post(self, *a, **kw):
            return FakeResp()
        async def close(self):
            self.closed = True

    fake_sess = FakeSession()
    monkeypatch.setattr(cve_db.aiohttp, "ClientSession", lambda: fake_sess)
    out = await cve_db.query_batch([
        {"package": {"name": "x", "ecosystem": "npm"}, "version": "1.0.0"}
    ])
    assert out == [[]]
    assert fake_sess.closed is True

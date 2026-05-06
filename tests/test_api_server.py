"""Tests for the HTTP REST API surface.

Skipped automatically if FastAPI/httpx test dependencies aren't installed.
The full app loads via lifespan context which initializes the FindingsDB,
so we use FastAPI's TestClient and a temp DB path to keep tests hermetic.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# Skip the whole module gracefully if FastAPI isn't installed
fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture
def app_with_temp_db(monkeypatch: pytest.MonkeyPatch):
    """Build the FastAPI app pointing at a temp SQLite DB."""
    import contextlib

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("PENTEST_TOOLS_DB_PATH", db_path)

    from api.server import create_app

    app = create_app()
    yield app
    with contextlib.suppress(FileNotFoundError):
        os.unlink(db_path)


def test_health_endpoint(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


def test_version_endpoint(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/version")
        assert r.status_code == 200
        body = r.json()
        assert "version" in body
        # Either the real VERSION file content or "unknown"
        assert isinstance(body["version"], str)
        assert len(body["version"]) > 0


def test_agents_catalog(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/agents")
        assert r.status_code == 200
        agents = r.json()
        assert isinstance(agents, list)
        assert len(agents) >= 10
        names = {a["name"] for a in agents}
        for expected in ("recon", "web", "ad", "cloud", "mobile", "wireless"):
            assert expected in names


def test_tools_catalog_handles_missing_registry(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/tools")
        # Returns either a list of registered tools or an empty list if registry
        # isn't importable. Both are valid.
        assert r.status_code == 200
        assert isinstance(r.json(), list)


def test_engagements_list_empty(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/engagements")
        assert r.status_code == 200
        assert r.json() == []


def test_engagement_not_found_returns_404(app_with_temp_db) -> None:
    with TestClient(app_with_temp_db) as client:
        r = client.get("/engagements/does-not-exist")
        assert r.status_code == 404


def test_create_engagement_requires_token(app_with_temp_db, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without PENTEST_TOOLS_API_TOKEN set, write endpoints must 503."""
    monkeypatch.delenv("PENTEST_TOOLS_API_TOKEN", raising=False)

    with TestClient(app_with_temp_db) as client:
        r = client.post("/engagements", json={"target": "example.com"})
        assert r.status_code == 503


def test_create_engagement_rejects_bad_token(app_with_temp_db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTEST_TOOLS_API_TOKEN", "real-token")

    with TestClient(app_with_temp_db) as client:
        # Missing header
        r = client.post("/engagements", json={"target": "example.com"})
        assert r.status_code == 401

        # Wrong token
        r = client.post(
            "/engagements",
            json={"target": "example.com"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r.status_code == 403


def test_abort_engagement_requires_token(app_with_temp_db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PENTEST_TOOLS_API_TOKEN", raising=False)

    with TestClient(app_with_temp_db) as client:
        r = client.post("/engagements/some-id/abort")
        assert r.status_code == 503

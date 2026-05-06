"""Dashboard E2E coverage at the API + static-file level.

Full browser-driven Playwright tests run separately on a live server.
These hit the FastAPI TestClient directly and assert:
  - the dashboard HTML is served at /dashboard/
  - it references the expected CSS/JS files
  - security headers are present on responses
  - the SARIF download endpoint returns valid JSON for missing engagements
  - the static assets do not contain accidental secrets
"""

from __future__ import annotations

import os
import re
import tempfile

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    import contextlib

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("PENTEST_TOOLS_DB_PATH", db_path)

    from api.server import create_app

    app = create_app()
    with TestClient(app) as c:
        yield c
    with contextlib.suppress(FileNotFoundError):
        os.unlink(db_path)


# ─── Dashboard HTML serving ─────────────────────────────────────────────


def test_dashboard_index_served(client) -> None:
    """GET /dashboard/ returns the dashboard HTML."""
    r = client.get("/dashboard/")
    assert r.status_code == 200
    assert "<title>" in r.text
    assert "pentest-tools" in r.text.lower()


def test_dashboard_references_expected_assets(client) -> None:
    r = client.get("/dashboard/")
    assert "dashboard.css" in r.text
    assert "dashboard.js" in r.text


def test_dashboard_css_served(client) -> None:
    r = client.get("/dashboard/dashboard.css")
    assert r.status_code == 200
    # Sanity: design tokens match the live marketing site
    assert "--c-dirty-white" in r.text
    assert "--c-lime" in r.text
    assert "--c-dark-green" in r.text
    assert "Neue Montreal" in r.text
    assert "Geist Mono" in r.text


def test_dashboard_js_served(client) -> None:
    r = client.get("/dashboard/dashboard.js")
    assert r.status_code == 200
    # Critical pieces of behavior
    assert "WebSocket" in r.text
    assert "selectEngagement" in r.text
    assert "downloadSarif" in r.text


def test_root_redirects_to_dashboard(client) -> None:
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (301, 302, 307, 308)
    assert "/dashboard" in r.headers.get("location", "")


# ─── Security headers ───────────────────────────────────────────────────


def test_security_headers_on_dashboard(client) -> None:
    r = client.get("/dashboard/")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")


def test_security_headers_on_api(client) -> None:
    r = client.get("/health")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")


# ─── No accidental secrets in static assets ─────────────────────────────


def test_dashboard_assets_have_no_obvious_secrets() -> None:
    """Static assets shouldn't contain API keys, tokens, or .env values."""
    here = os.path.dirname(os.path.dirname(__file__))
    static_dir = os.path.join(here, "api", "static")
    if not os.path.isdir(static_dir):
        pytest.skip("static dir missing")
    suspicious = re.compile(
        r"(sk-[A-Za-z0-9]{20,}|"  # OpenAI-style
        r"sk-ant-[A-Za-z0-9_-]{20,}|"  # Anthropic
        r"AKIA[0-9A-Z]{16}|"  # AWS access key id
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"AIza[0-9A-Za-z_-]{35}|"  # Google
        r"ghp_[0-9A-Za-z]{36}|"  # GitHub PAT
        r"glpat-[0-9A-Za-z_-]{20})"  # GitLab PAT
    )
    for fname in os.listdir(static_dir):
        path = os.path.join(static_dir, fname)
        if os.path.isfile(path):
            with open(path) as fp:
                content = fp.read()
            assert not suspicious.search(content), f"suspicious token in {fname}"


# ─── SARIF endpoint for nonexistent engagement ──────────────────────────


def test_sarif_404_for_missing_engagement(client) -> None:
    r = client.get("/engagements/does-not-exist/sarif")
    assert r.status_code == 404

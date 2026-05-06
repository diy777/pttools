"""End-to-end smoke test for the APISecurityAgent.

Spins up a small aiohttp app that mimics the OWASP API Security Top 10
shape: a REST endpoint with IDOR-style behavior, a GraphQL endpoint with
introspection enabled, and a discoverable OpenAPI spec at /openapi.json.

The agent currently delegates the heavy lifting to external tools
(ffuf, kiterunner, hakrawler, jwt_tool, graphw00f, nuclei). Those won't
be installed in every environment, so this test focuses on what we can
verify universally: that the agent's wire path completes cleanly against
a real target, produces a structured result, and persists any findings
that surface.

If the right tools ARE installed locally, the test also picks up real
findings as a bonus. Either way it pins the agent's contract so a
refactor of run_assessment / _run_deterministic_api can't silently
break the wire path.
"""

from __future__ import annotations

import socket

import pytest
from aiohttp import web

# The agent's deterministic mode invokes external tools (ffuf, kiterunner,
# nuclei, etc.) which can each hit their per-tool timeout (~30s) when run
# against a real local target. The repo's pre-push hook caps tests at 30s,
# so this module needs an explicit per-test timeout to avoid being killed
# mid-run.
pytestmark = pytest.mark.timeout(900)

# ─── In-test API surface ──────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "User object"}},
            }
        },
        "/admin/users": {"get": {"operationId": "listUsers", "responses": {"200": {}}}},
    },
}


def _build_api_app() -> web.Application:
    """Mimics an API with discoverable spec + GraphQL introspection enabled."""

    async def openapi(_: web.Request) -> web.Response:
        return web.json_response(_OPENAPI_SPEC)

    async def get_user(request: web.Request) -> web.Response:
        # IDOR-flavored: returns any requested user without auth.
        uid = int(request.match_info["id"])
        return web.json_response({"id": uid, "name": f"user-{uid}", "role": "admin" if uid == 1 else "user"})

    async def admin_users(_: web.Request) -> web.Response:
        # BFLA-flavored: admin endpoint exposed without auth.
        return web.json_response([{"id": 1, "name": "admin"}, {"id": 2, "name": "alice"}])

    async def graphql_endpoint(request: web.Request) -> web.Response:
        # GraphQL with introspection enabled, returns the schema on __schema query.
        body = await request.json()
        query = body.get("query", "")
        if "__schema" in query:
            return web.json_response(
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {"name": "Query", "fields": [{"name": "user"}, {"name": "admin"}]},
                                {"name": "User", "fields": [{"name": "id"}, {"name": "email"}]},
                            ],
                        }
                    }
                }
            )
        return web.json_response({"data": None})

    app = web.Application()
    app.router.add_get("/openapi.json", openapi)
    app.router.add_get("/users/{id}", get_user)
    app.router.add_get("/admin/users", admin_users)
    app.router.add_post("/graphql", graphql_endpoint)
    return app


@pytest.fixture
async def api_app_url():
    app = _build_api_app()
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
async def test_api_security_agent_completes_against_real_target(api_app_url, tmp_path):
    """The agent's deterministic path must complete without raising."""
    from agents.api_security.api_security_agent import APISecurityAgent
    from engine.findings_db import FindingsDB
    from tools.registry import ToolRegistry

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target=api_app_url, scope="api", intensity="normal"
        )
        agent = APISecurityAgent(registry=ToolRegistry(), db=db, llm=None)
        result = await agent.run_assessment(
            target=api_app_url, engagement_id=engagement["id"]
        )
        assert isinstance(result, dict), f"expected dict, got {type(result)}"
        assert result["status"] == "complete", f"agent did not complete: {result}"
        assert result["target"] == api_app_url
        assert "findings_count" in result, f"missing findings_count: {result}"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_api_target_actually_exposes_introspection_for_test_realism(api_app_url):
    """Sanity: the in-test app must really expose introspection.

    If this test breaks, future API security findings against the in-test
    app are not meaningful (the target stopped being interesting).
    """
    import aiohttp

    async with aiohttp.ClientSession() as client, client.post(
        f"{api_app_url}/graphql",
        json={"query": "{ __schema { queryType { name } } }"},
    ) as resp:
        data = await resp.json()
    assert data["data"]["__schema"]["queryType"]["name"] == "Query", (
        f"introspection not enabled on the in-test target: {data}"
    )


@pytest.mark.asyncio
async def test_api_target_exposes_openapi_spec_for_test_realism(api_app_url):
    """Sanity: the in-test app must expose a discoverable OpenAPI spec."""
    import aiohttp

    async with aiohttp.ClientSession() as client, client.get(f"{api_app_url}/openapi.json") as resp:
        assert resp.status == 200
        spec = await resp.json()
    assert spec["openapi"].startswith("3."), f"unexpected spec: {spec}"
    assert "/users/{id}" in spec["paths"]


@pytest.mark.asyncio
async def test_api_security_findings_carry_expected_fields(api_app_url, tmp_path):
    """Any findings the agent produces must carry the standard finding fields.

    Catches regressions where a future agent-internal change drops required
    fields like severity or tool_source from the finding dict before it
    hits the DB.
    """
    from agents.api_security.api_security_agent import APISecurityAgent
    from engine.findings_db import FindingsDB
    from tools.registry import ToolRegistry

    db = FindingsDB(str(tmp_path / "findings.db"))
    try:
        engagement = await db.create_engagement(
            target=api_app_url, scope="api", intensity="normal"
        )
        agent = APISecurityAgent(registry=ToolRegistry(), db=db, llm=None)
        await agent.run_assessment(target=api_app_url, engagement_id=engagement["id"])

        findings = await db.get_findings(engagement_id=engagement["id"])
        for f in findings:
            assert "title" in f, f"finding missing title: {f}"
            assert "severity" in f, f"finding missing severity: {f}"
            assert f["severity"] in {"critical", "high", "medium", "low", "info"}, f
            assert f.get("engagement_id") == engagement["id"], (
                f"finding not tagged with engagement_id: {f}"
            )
    finally:
        await db.close()

"""FastAPI app exposing pentest-tools engagement and findings data over HTTP.

This is a read-mostly surface. The engagement-launch endpoint is protected by
an API token so the server cannot accidentally launch real scans if exposed to
untrusted clients. Read-only endpoints are meant for a local dashboard or a
trusted internal service.

The HTTP surface complements the MCP server. MCP is the integration path for
LLM-powered clients; this REST API is the integration path for everything else.

Endpoints:
    GET  /health                          liveness
    GET  /version                         build info
    GET  /agents                          list specialized agents
    GET  /tools                           list registered tool wrappers
    GET  /engagements                     list all engagements
    GET  /engagements/{id}                engagement detail + summary
    GET  /engagements/{id}/findings       findings list, supports filters
    GET  /engagements/{id}/chains         attack chains
    GET  /engagements/{id}/detections     generated detection rules
    GET  /engagements/{id}/sarif          SARIF v2.1 export for CI ingestion
    POST /engagements                     launch a new engagement (auth required)
    POST /engagements/{id}/abort          stop a running engagement (auth required)
    WS   /engagements/{id}/stream         live event stream (read-only)

The engagement launcher uses the same orchestrator path as the CLI.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger("pentest-tools.api")


def _import_fastapi() -> tuple[Any, Any, Any, Any, Any, Any, Any, Any]:
    """Lazy-import FastAPI so the core package install doesn't require it."""
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket
        from fastapi.responses import FileResponse
    except ImportError as e:
        raise RuntimeError(
            "API surface requires FastAPI. Install with: pip install pttools[api]"
        ) from e
    return Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, FileResponse


@asynccontextmanager
async def _lifespan(app: Any) -> AsyncIterator[None]:
    from engine.findings_db import FindingsDB

    db = FindingsDB(os.getenv("PENTEST_TOOLS_DB_PATH", "pentest_findings.db"))
    await db.init()
    app.state.db = db
    logger.info("pentest-tools API ready, db=%s", db.db_path if hasattr(db, "db_path") else "default")
    try:
        yield
    finally:
        await db.close()


def create_app() -> Any:
    """Construct and return the FastAPI app.

    Imports FastAPI lazily so that anyone importing `api.server` from a
    minimal install (without the [api] extra) gets a clear error pointing
    at the right install command.
    """
    Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, FileResponse = _import_fastapi()

    app = FastAPI(
        title="pentest-tools",
        description="Autonomous AI pentesting REST API",
        version=_read_version(),
        lifespan=_lifespan,
    )

    api_token_env = "PENTEST_TOOLS_API_TOKEN"

    # ─── Security headers middleware ────────────────────────────────────

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Strict CSP for the dashboard. self only, inline allowed (we ship a small JS file
        # but no third-party CDNs). connect-src includes ws/wss for WebSocket stream.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response

    def _require_token(authorization: str | None = Header(default=None)) -> None:
        expected = os.getenv(api_token_env, "")
        if not expected:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"State-mutating endpoints require {api_token_env} env var. "
                    "Set it on the server before calling write endpoints."
                ),
            )
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        if authorization.removeprefix("Bearer ").strip() != expected:
            raise HTTPException(status_code=403, detail="invalid token")

    # ─── liveness and metadata ──────────────────────────────────────────

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"version": _read_version()}

    # ─── catalog endpoints ──────────────────────────────────────────────

    @app.get("/agents")
    async def list_agents() -> list[dict[str, str]]:
        """Return the catalog of specialized agents shipped with pentest-tools."""
        return _agent_catalog()

    @app.get("/tools")
    async def list_tools() -> list[dict[str, Any]]:
        """Return the registered tool wrappers known to the engine."""
        try:
            from tools.registry import iter_tools  # type: ignore[attr-defined]
        except Exception:
            return []
        return [_tool_to_dict(t) for t in iter_tools()]

    # ─── engagements ────────────────────────────────────────────────────

    @app.get("/engagements")
    async def list_engagements(limit: int = Query(default=50, ge=1, le=500)) -> list[dict[str, Any]]:
        return await app.state.db.list_engagements(limit=limit)

    @app.get("/engagements/{engagement_id}")
    async def get_engagement(engagement_id: str) -> dict[str, Any]:
        eng = await app.state.db.get_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="engagement not found")
        summary = await app.state.db.get_engagement_summary(engagement_id)
        try:
            stages = await app.state.db.get_stage_records(engagement_id)
        except AttributeError:
            stages = []
        return {"engagement": eng, "summary": summary, "stages": stages}

    @app.get("/engagements/{engagement_id}/findings")
    async def get_findings(
        engagement_id: str,
        severity: str | None = Query(default=None, description="Filter: critical, high, medium, low, info"),
        confirmed: bool | None = Query(default=None, description="Filter: only PoC-confirmed findings"),
    ) -> list[dict[str, Any]]:
        return await app.state.db.get_findings(
            engagement_id=engagement_id,
            severity=severity,
            confirmed=confirmed,
        )

    @app.get("/engagements/{engagement_id}/chains")
    async def get_chains(engagement_id: str) -> list[dict[str, Any]]:
        return await app.state.db.get_attack_chains(engagement_id)

    @app.get("/engagements/{engagement_id}/detections")
    async def get_detections(engagement_id: str) -> list[dict[str, Any]]:
        return await app.state.db.get_detection_rules(engagement_id)

    @app.get("/engagements/{engagement_id}/stages")
    async def get_stage_records(engagement_id: str) -> list[dict[str, Any]]:
        try:
            return await app.state.db.get_stage_records(engagement_id)
        except AttributeError:
            return []

    @app.get("/engagements/{engagement_id}/sarif")
    async def get_sarif(engagement_id: str) -> dict[str, Any]:
        eng = await app.state.db.get_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="engagement not found")
        findings = await app.state.db.get_findings(engagement_id=engagement_id)
        try:
            from engine.sarif import findings_to_sarif

            return findings_to_sarif(findings, engagement=eng)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"sarif export failed: {e}") from e

    # ─── state-mutating endpoints (token required) ──────────────────────

    @app.post("/engagements", dependencies=[Depends(_require_token)])
    async def create_engagement(payload: dict[str, Any]) -> dict[str, Any]:
        target = payload.get("target")
        scope = payload.get("scope", target)
        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        # Mirror the data model the CLI uses; do not duplicate orchestrator
        # logic here — call into the same path via a thin adapter.
        try:
            from cli.main import _start_campaign_run  # type: ignore[attr-defined]
        except ImportError as e:
            raise HTTPException(status_code=500, detail=f"orchestrator import failed: {e}") from e

        # _start_campaign_run is blocking (Typer command body). Run it in a
        # threadpool so the FastAPI loop stays responsive.
        import anyio

        await anyio.to_thread.run_sync(
            _start_campaign_run,
            [target],
            scope,
            payload.get("intensity", "balanced"),
            False,  # ci flag off for API-launched runs
        )
        return {"status": "started", "target": target, "scope": scope}

    @app.post("/engagements/{engagement_id}/abort", dependencies=[Depends(_require_token)])
    async def abort_engagement(engagement_id: str) -> dict[str, str]:
        # Abort hook: write a marker the orchestrator polls. Real
        # implementation lives in engine/exec_context.py; this is the
        # external API for it.
        try:
            from engine.exec_context import set_abort_flag  # type: ignore[attr-defined]

            set_abort_flag(engagement_id)
        except Exception:
            # If the orchestrator doesn't yet expose set_abort_flag, fall
            # back to a no-op marker file so a future orchestrator can pick
            # it up. This keeps the API stable while the engine evolves.
            marker_dir = os.getenv("PENTEST_TOOLS_RUNTIME_DIR", "/tmp/pentest-tools")
            os.makedirs(marker_dir, exist_ok=True)
            with open(os.path.join(marker_dir, f"{engagement_id}.abort"), "w") as fp:
                fp.write("requested")
        return {"status": "abort_requested", "engagement_id": engagement_id}

    # ─── live event stream (websocket) ──────────────────────────────────

    @app.websocket("/engagements/{engagement_id}/stream")
    async def stream(websocket: WebSocket, engagement_id: str) -> None:  # noqa: ARG001
        await websocket.accept()
        try:
            # First implementation: poll the DB at 2s intervals and push deltas.
            # Future: hook into orchestrator's progress callback for push events.
            import asyncio

            last_finding_count = 0
            while True:
                findings = await app.state.db.get_findings(engagement_id=engagement_id)
                if len(findings) > last_finding_count:
                    new = findings[last_finding_count:]
                    for f in new:
                        await websocket.send_json({"type": "finding", "data": f})
                    last_finding_count = len(findings)
                summary = await app.state.db.get_engagement_summary(engagement_id)
                await websocket.send_json({"type": "summary", "data": summary})
                await asyncio.sleep(2.0)
        except Exception as e:  # noqa: BLE001
            logger.info("websocket closed: %s", e)
            import contextlib as _ctx

            with _ctx.suppress(Exception):
                await websocket.close()

    # ─── Static dashboard ───────────────────────────────────────────────

    static_dir = os.path.join(os.path.dirname(__file__), "static")

    if os.path.isdir(static_dir):
        try:
            from fastapi.staticfiles import StaticFiles

            app.mount("/dashboard", StaticFiles(directory=static_dir, html=True), name="dashboard")
        except Exception as e:  # noqa: BLE001
            logger.warning("static dashboard mount failed: %s", e)

        @app.get("/")
        async def _root_redirect() -> Any:
            from fastapi.responses import RedirectResponse

            return RedirectResponse(url="/dashboard/")

    return app


def _read_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "VERSION")) as fp:
            return fp.read().strip()
    except FileNotFoundError:
        return "unknown"


def _agent_catalog() -> list[dict[str, str]]:
    """Hardcoded snapshot of specialized agents shipped with pentest-tools-cli.

    This avoids a runtime dependency on importing every agent class just to
    list names. If the agent set changes, update this list.
    """
    return [
        {"name": "recon", "description": "Network and service reconnaissance"},
        {"name": "web", "description": "Web application security testing"},
        {"name": "ad", "description": "Active Directory enumeration and attacks"},
        {"name": "cloud", "description": "AWS/Azure/GCP misconfiguration and IAM"},
        {"name": "mobile", "description": "Mobile app static and dynamic analysis"},
        {"name": "wireless", "description": "WPA/WPA2/WPA3 testing"},
        {"name": "social_engineer", "description": "Phishing and pretexting design"},
        {"name": "exploit_chain", "description": "Multi-step attack path construction"},
        {"name": "poc_validator", "description": "Generate and run safe PoC scripts"},
        {"name": "detection", "description": "Sigma/SPL/KQL detection rule generation"},
        {"name": "report", "description": "Pentest report compilation"},
        {"name": "llm_redteam", "description": "LLM application red team"},
    ]


def _tool_to_dict(tool: Any) -> dict[str, Any]:
    """Best-effort serialization of a tool registry entry."""
    return {
        "name": getattr(tool, "name", str(tool)),
        "category": getattr(tool, "category", "uncategorized"),
        "description": getattr(tool, "description", ""),
    }


# Module-level app for `uvicorn api.server:app`
try:
    app = create_app()
except RuntimeError:
    # FastAPI not installed; module imports without crashing for users on
    # the minimal install. They'll see the install hint when they try to
    # call create_app() directly.
    app = None  # type: ignore[assignment]

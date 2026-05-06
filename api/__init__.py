"""HTTP REST API surface for pentest-tools.

Provides a FastAPI app that mirrors the engagement, findings, and engagement
control operations available through the CLI and MCP server. Designed for
non-MCP clients (web dashboards, custom integrations, CI pipelines that don't
already speak MCP).

Run via:
    pttools serve --port 8888
or directly:
    uvicorn api.server:app --port 8888

The API is read-mostly. State-mutating endpoints require an explicit
authorization header to prevent accidental remote engagements.
"""

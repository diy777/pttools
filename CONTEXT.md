# Core Tool Workspace (Layer 2)

## What this is
Open-source pentest-tools CLI and MCP server. MIT licensed. Published to PyPI as `pentestai`.

Note: this repo's `agents/` are Python `BaseAgent` orchestrator classes inside the engine. They are not Claude Code subagent markdown files. The standalone Claude Code subagent definitions live in the separate companion repo `pentest-tools-agents` (https://github.com/pentest-tools/pentest-tools-agents), which is optional and not required to run this CLI.

## Key directories
- `agents/` — Python `BaseAgent` orchestrator classes (recon, web, ad, cloud, mobile, browser, api_security, credential_tester, vuln_scanner, privesc, exploit_chain, poc_validator, detection, social_engineer, wireless, llm_redteam, report)
- `mcp_server/` — MCP server exposing tools to Claude Code
- `cli/` — `pttools` command and menus
- `engine/` — orchestration, findings DB, LLM client, scope/auth handling
- `tools/` — wrappers for ~191 underlying security tools

## Architecture
- MCP Server exposes 150+ security tools
- Python agents orchestrate tools via Claude Code
- CLI: `pip install pentestai`
- Auth: `pentest-tools auth <api-key>` validates against API

## Feature gating
- **Free**: Recon, web scanning, 3 orchestrator phases
- **Pro/Enterprise**: Exploit chaining, PoC validation, detection rules, AD/cloud agents (5 phases + 5 tools)

## Current version
Check `VERSION` file in repo root.

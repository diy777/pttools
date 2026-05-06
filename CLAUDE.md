# pentest-tools (the MCP product)

> **Heads up to Claude:** This IS `pentest-tools` (the Python CLI + MCP server, GitHub `pentest-tools/pentest-tools`). When Steph says "pentest-tools" they mean THIS codebase. The separate agents-only companion repo `pentest-tools-agents` (just .md files + bash) lives at `~/pentest-tools-agents/` (GitHub `pentest-tools/pentest-tools-agents`). Do NOT pull agent .md files from there into this repo. Reference the agents repo only via documented links (README, install hints, specs).

## Local-to-GitHub mapping (memorize this)

| Local dir | GitHub repo | Role |
|-----------|-------------|------|
| `~/pentest-tools-cli/` (this dir) | `pentest-tools/pentest-tools` | The product (Python CLI + MCP) |
| `~/pentest-tools-agents/` | `pentest-tools/pentest-tools-agents` | Agents-only companion repo |
| `~/pentest-tools-preview-v4/` | `pentestai-marketing` | Marketing site at pentest-tools.local |
| `~/pentestai-private/` | private | SaaS, auth worker, internal docs |

The word "pentest-tools" without a suffix always means this product. The agents repo is "pentest-tools-agents".

## What is in THIS repo

- `agents/` (Python BaseAgent classes: ad, browser, cloud, detection, exploit_chain, llm_redteam, mobile, poc_validator, recon, report, social_engineer, web, wireless)
- `cli/` (the `pttools` CLI entrypoint, menus, commands)
- `engine/` (orchestration, tracing, findings DB)
- `tools/` (tool wrappers, registry of 150+ security tools)
- `api/`, `functions/`, `dist/`, `docs/`, `specs/`, `benchmarks/`

## Auto-memory

Memory dir for THIS repo: `~/.claude/projects/-home-administrator-pentest-tools-cli/memory/`. It contains product, marketing, SaaS, pricing, and desktop app memory plus universal user/feedback rules. Created 2026-04-29 to stop cross-contamination with the agents-only repo memory.

# Phase 7: Continuous Pentest Platform

Phase 7 repositions `pttools` from a one-shot autonomous scanner into a continuous pentest platform that AppSec teams and pentesters both use. Shipped as six sub-phases that each stand on their own.

## What's new

### 7.0 — Coverage gap closed

`engine/target_expander.py` shipped at 0% coverage in Phase 5/6. Now ≥ 90% with tests for single targets, comma lists, CIDR blocks, file input, dedup, and the 4096-host cap.

### 7.1 — Authenticated & stateful web scanning

Pentest-ai now logs into the target, holds the session, and rotates credentials when sessions expire. Every web tool (ffuf, nuclei, sqlmap, gobuster, wapiti) gets the cookie or bearer token automatically.

Auth flows: `form_post`, `bearer_static`, `oauth_password`, `playwright_script`.

```bash
pttools start https://app.example.com \
  --auth-flow form_post \
  --auth-url /login \
  --auth-username admin \
  --auth-password-env APP_PASS \
  --auth-success-marker "Welcome"
```

Findings DB has a new `auth_sessions` table for audit trail.

### 7.2 — Diff mode / retest

```bash
pttools retest <engagement-id>
pttools diff <id-a> <id-b>
```

Re-runs an engagement with the same target, scope, and intensity, then prints a three-bucket diff: **new**, **resolved**, **unchanged**. Matching uses the same hash logic as `engine/dedup.py`.

### 7.3 — CI/CD native

New `--ci` and `--fail-on` flags. Non-interactive mode, machine-readable JSON status output, severity-gated exit codes, SARIF upload, optional PR comment via `GITHUB_TOKEN`.

```yaml
- name: pttools CI gate
  run: |
    pttools ci report \
      --engagement-id $ENGAGEMENT_ID \
      --fail-on high \
      --sarif pentest.sarif
```

Validated end-to-end against `pentest-tools/pentest-tools-action-test` — PR comment posts, SARIF uploads as artifact, build fails on gated findings.

### 7.4 — LLM red team phase

New `llm_redteam` agent ships a 14-probe corpus spanning 5 OWASP LLM Top 10 categories (LLM01 prompt injection, LLM02 insecure output handling, LLM06 sensitive info disclosure, LLM07 insecure plugin design, LLM10 model theft).

```bash
pttools llm-redteam run https://api.example.com/ask \
  --schema simple \
  --engagement-id <id>
```

Adapter supports openai, simple, and custom JSON schemas. Concurrent probe execution with configurable parallelism. Validated against a deliberately vulnerable local target: 14/14 probes fired.

### 7.5 — Result cache

SQLite-backed cache keyed on `sha256(tool + args + target + intensity)`. TTL is per tool (1h recon, 6h vuln scans, no cache for exploitation). Speeds up retests and playbook re-runs.

```bash
pttools cache stats
pttools cache clear
pttools start <target> --no-cache
```

### 7.6 — YAML playbooks (methodology-as-code)

Pentesters encode their methodology once, reuse forever, and share it. Mirrors the Nuclei template distribution pattern.

```bash
pttools playbook list
pttools playbook show web-app-quick
pttools playbook validate ./my-methodology.yaml
pttools playbook run llm-app-redteam -i target=https://api.example.com/ask
```

Builtin playbooks:
- `web-app-quick` — fast external sweep (recon + content discovery + vuln scan + optional LLM probe)
- `external-recon` — passive + active footprint mapping
- `llm-app-redteam` — OWASP LLM Top 10 against an AI endpoint

Schema supports: typed inputs with required/default/env fallback, phase dependencies, sandboxed conditions (`has_finding`, `count_findings`, `any_finding`, `phase_ran`, `phase_skipped`), manual phases with checklists.

```yaml
name: internal-ad-pentest
intensity: stealth
inputs:
  domain: { required: true, prompt: "AD domain" }
phases:
  - id: recon
    tools: [nmap, masscan]
  - id: kerberoast
    depends_on: [recon]
    condition: "has_finding(category='recon')"
    tools: [impacket-getuserspns]
```

Conditions run through an AST walker with a tight whitelist. No attribute access, no arbitrary calls, no bare names — only the five registered helpers.

## Numbers

- 500 tests pass
- 81% → 85%+ coverage on touched modules
- CI green

## What Phase 7 doesn't include

- Browser-based dashboard (deferred to Phase 8)
- Visual workflow editor (YAML covers this ground)
- Tool sandboxing (separate plan)
- Native Slack/Discord integrations (webhooks cover it)

## Upgrade

```bash
pip install --upgrade pttools
pttools playbook list
```

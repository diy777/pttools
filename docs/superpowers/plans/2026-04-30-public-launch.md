# pentest-tools Public Launch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take `pttools 0.10.5` from private-beta-ready to a public HN/Product Hunt launch with zero broken paths and a product polish bar above HexStrike, CAI, and HackingTools.

**Architecture:** Eleven sequential phases plus optional polish. Each phase produces a self-contained, verifiable change. Code phases use TDD (red, green, commit). Operational phases (legal, status page, video, testimonial, SOC2, community) are explicit checklists with proof-of-completion artifacts. No phase blocks more than one downstream phase, so a stuck phase never freezes the whole launch.

**Tech Stack:** Python 3.10+, pytest, FastMCP, GitHub Actions, PyPI Trusted Publishing (OIDC), bandit, pip-audit, gitleaks, BetterStack (status), Cloudflare Pages (`pentest-tools.local`), Tauri (deferred), Anthropic API.

**Repo invariants the worker must respect:**
- This repo is `~/pentest-tools-cli/` (GitHub `pentest-tools/pentest-tools`). The agents-only repo (`~/pentest-tools-agents/`) is OFF LIMITS.
- Marketing site lives at `~/pentest-tools-preview-v4/` (CF Pages project `pentest-tools`). Version strings show in footer.
- No em dashes anywhere (commits, docs, code comments). Use commas, periods, parens.
- No AI co-author trailers in commits (disabled globally in `~/.claude/settings.json`).
- Never commit secrets. `.gitleaks.toml` is the gate.
- Internal/business docs stay in `~/pentestai-private/`, never this repo.

**Conflict-prevention rules:**
- Each phase commits before the next starts.
- Phase 1 (release pipeline) MUST be merged before any future tag is pushed.
- Phase 6 (coverage) and Phase 7 (CI security workflow) both touch `.github/workflows/`. Phase 7 is a NEW file; Phase 6 only changes test files. No overlap.
- Phase 10 (demo video) records `pttools` against a live target. It must run AFTER Phase 8 (real LLM E2E proven) so the recorded run is the validated path, not the deterministic fallback.
- Marketing site changes ship from `~/pentest-tools-preview-v4/`, not this repo. Version bumps in either repo require a matching update in the other.

---

## File Structure

**New files (this repo):**
- `.github/workflows/security.yml` — bandit + pip-audit + gitleaks gate (Phase 7)
- `tests/test_mcp_server_coverage.py` — fills 55% gap in `mcp_server/server.py` (Phase 6)
- `tests/test_tool_installer_coverage.py` — fills 50% gap in `engine/tool_installer.py` (Phase 6)
- `tests/test_tracing_coverage.py` — fills 53% gap in `engine/tracing.py` (Phase 6)
- `tests/test_registry_coverage.py` — fills 69% gap in `tools/registry.py` (Phase 6)
- `tests/test_llm_e2e_smoke.py` — gated real-LLM smoke test (Phase 8)
- `docs/launch/install-matrix.md` — Mac/Windows/Linux verification log (Phase 9)
- `docs/launch/demo-script.md` — recording script for landing-page video (Phase 10)
- `docs/launch/testimonial-outreach.md` — outreach log + collected quotes (Phase 11)
- `docs/launch/soc2-kickoff.md` — vendor decision + kickoff date (Phase 12)
- `docs/launch/community-channel.md` — Discord vs Discussions decision (Phase 13)
- `docs/launch/launch-checklist.md` — final go/no-go checklist (Phase 14)

**Modified files:**
- `.github/workflows/release.yml` — confirm Trusted Publishing config; add fallback comment removal (Phase 1)
- `cli/main.py` — add `--max-findings-per-phase` flag (Phase 15, optional)
- `pyproject.toml` — version bumps per release
- `CHANGELOG.md` — entry per release

**External actions (no repo file):**
- PyPI project settings (Phase 1)
- BetterStack account + monitors (Phase 4)
- Cloudflare Pages publish of `/privacy` and `/terms` (Phase 3)
- Vanta/Drata/SecureFrame contract (Phase 12)

---

## Phase 1: Fix the release pipeline (BLOCKER #1)

**Why first:** Every subsequent release that ships a fix from this plan needs a working release path. This phase is 5 minutes of clicks plus a verification tag.

### Task 1.1: Confirm `release.yml` matches PyPI Trusted Publishing requirements

**Files:**
- Read: `.github/workflows/release.yml`
- Read: `docs/release-pypi.md`

- [ ] **Step 1: Verify the workflow declares `id-token: write`**

Run: `grep -n "id-token: write" .github/workflows/release.yml`
Expected: at least one match in the `permissions:` block.

- [ ] **Step 2: Verify the publish step uses `pypa/gh-action-pypi-publish` (not twine)**

Run: `grep -n "pypa/gh-action-pypi-publish" .github/workflows/release.yml`
Expected: one pinned action reference.

- [ ] **Step 3: Verify the env name in the workflow matches what PyPI expects**

Run: `grep -nE "environment:|name:" .github/workflows/release.yml | head -20`
Expected: an `environment:` value of `pypi`. If not, edit it to `pypi`.

- [ ] **Step 4: If anything in steps 1-3 was missing, fix and commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: align release workflow with PyPI Trusted Publishing"
```

### Task 1.2: Configure Trusted Publishing on PyPI (manual, browser)

- [ ] **Step 1: Open https://pypi.org/manage/project/pttools/settings/publishing/ in a browser**

- [ ] **Step 2: Add a new pending publisher with these exact values**

- Owner: `pentest-tools`
- Repository: `pentest-tools`
- Workflow filename: `release.yml`
- Environment name: `pypi`

- [ ] **Step 3: Confirm the publisher saves without an error banner**

### Task 1.3: Smoke-test the pipeline with a no-op patch release

- [ ] **Step 1: Bump patch version in `pyproject.toml`**

Edit `pyproject.toml`: `version = "0.10.5"` becomes `version = "0.10.6"`.

- [ ] **Step 2: Add a CHANGELOG entry**

Edit `CHANGELOG.md`, prepend:
```
## 0.10.6 - 2026-04-30
- ci: validate PyPI Trusted Publishing pipeline (no functional change)
```

- [ ] **Step 3: Commit and tag**

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "release: pttools 0.10.6 - validate trusted publishing"
git tag v0.10.6
git push origin main --tags
```

- [ ] **Step 4: Watch the GitHub Actions run**

Run: `gh run watch --exit-status`
Expected: the `release` workflow completes green.

- [ ] **Step 5: Confirm the new version is live on PyPI**

Run: `pip index versions pttools 2>/dev/null || curl -s https://pypi.org/pypi/pttools/json | python -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"`
Expected: `0.10.6`.

- [ ] **Step 6: Confirm install works**

Run: `python -m venv /tmp/pttools-test && /tmp/pttools-test/bin/pip install pttools==0.10.6 && /tmp/pttools-test/bin/pttools --version`
Expected: `0.10.6`.

---

## Phase 2: Add the security CI workflow (SHOULD #7)

**Why second:** Every later phase pushes commits. Without this gate live, a regression in coverage work or LLM E2E work could silently reintroduce a bandit HIGH or a vulnerable dep.

### Task 2.1: Write the security workflow

**Files:**
- Create: `.github/workflows/security.yml`

- [ ] **Step 1: Create the workflow file**

```yaml
name: security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5
        with:
          python-version: "3.12"
      - run: pip install bandit
      - run: bandit -r mcp_server engine tools agents cli -ll -ii --skip B101

  pip_audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5
        with:
          python-version: "3.12"
      - run: pip install pip-audit
      - run: pip-audit --strict

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@cb7149b9b57195b609c63e8518d2c37a99772a4e  # v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .gitleaks.toml
```

- [ ] **Step 2: Lint the YAML locally**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`
Expected: no traceback.

- [ ] **Step 3: Run the same checks locally to confirm they pass on `main`**

Run: `bandit -r mcp_server engine tools agents cli -ll -ii --skip B101`
Expected: `No issues identified.`

Run: `pip-audit --strict 2>&1 | tail -5`
Expected: `No known vulnerabilities found`.

Run: `gitleaks detect --no-banner --redact --config .gitleaks.toml`
Expected: `0 commits scanned for leaks`-style success line, exit 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add bandit, pip-audit, and gitleaks gate"
git push
```

- [ ] **Step 5: Verify the workflow ran green on the push**

Run: `gh run list --workflow=security.yml --limit 1`
Expected: status `completed` conclusion `success`.

---

## Phase 3: Publish Privacy Policy and ToS (BLOCKER #2)

**Why third:** Legal pages need to be live before the demo video, before testimonials are solicited, and before SOC2 vendors evaluate. They also need lawyer review, which has lead time, so kick off in parallel.

### Task 3.1: Send drafts to lawyer

- [ ] **Step 1: Read the current drafts to confirm they are complete**

```bash
wc -l docs/legal/PRIVACY.md docs/legal/TERMS.md
```
Expected: both >50 lines.

- [ ] **Step 2: Email both files to the engaged lawyer**

(Out-of-band action. Record the date sent in `docs/launch/launch-checklist.md` once that file is created in Phase 14.)

- [ ] **Step 3: Track the response and apply edits in this repo**

When edits come back, apply them to `docs/legal/PRIVACY.md` and `docs/legal/TERMS.md`. Commit:
```bash
git add docs/legal/
git commit -m "docs: legal review of privacy policy and terms"
```

### Task 3.2: Publish on the marketing site

**Files (in `~/pentest-tools-preview-v4/`, not this repo):**
- Create: `~/pentest-tools-preview-v4/privacy/index.html`
- Create: `~/pentest-tools-preview-v4/terms/index.html`

- [ ] **Step 1: Convert each Markdown doc to a styled HTML page matching the site theme**

Use the existing `index.html` as the styling template (header, footer, fonts, dark theme). Wrap the rendered Markdown body in the same content container.

- [ ] **Step 2: Verify the pages render locally**

```bash
cd ~/pentest-tools-preview-v4 && python -m http.server 8080 &
curl -sI http://localhost:8080/privacy/ | head -1
curl -sI http://localhost:8080/terms/ | head -1
kill %1
```
Expected: both return `200 OK`.

- [ ] **Step 3: Add footer links on `index.html`**

Edit `~/pentest-tools-preview-v4/index.html` footer to include `<a href="/privacy/">Privacy</a>` and `<a href="/terms/">Terms</a>`.

- [ ] **Step 4: Commit and deploy the marketing site**

```bash
cd ~/pentest-tools-preview-v4
git add privacy/ terms/ index.html
git commit -m "feat: publish privacy policy and terms"
git push
```

- [ ] **Step 5: Verify live**

```bash
curl -sI https://pentest-tools.local/privacy/ | head -1
curl -sI https://pentest-tools.local/terms/ | head -1
```
Expected: both `HTTP/2 200`.

---

## Phase 4: Stand up the status page (BLOCKER #3)

**Why fourth:** Pro/Team subscribers will notice outages on `app.pentest-tools.local`. A status page is a 30-minute setup that prevents support inbound during the launch week.

### Task 4.1: Create the BetterStack account and monitors

- [ ] **Step 1: Sign up at https://betterstack.com (free tier)**

- [ ] **Step 2: Add five HTTP monitors, 3-minute interval each**

| # | Name | URL | Expected |
|---|------|-----|----------|
| 1 | Marketing | `https://pentest-tools.local` | 200 |
| 2 | App | `https://app.pentest-tools.local` | 200 or 401 (auth wall) |
| 3 | API health | `https://app.pentest-tools.local/api/health` | 200 |
| 4 | PyPI package | `https://pypi.org/pypi/pttools/json` | 200 |
| 5 | Docs | `https://pentest-tools.local/docs/` | 200 |

- [ ] **Step 3: Create a public status page named "pentest-tools status"**

Attach all five monitors. Customize colors to match brand (dark, monospace).

- [ ] **Step 4: Bind a custom subdomain `status.pentest-tools.local`**

Add a CNAME in Cloudflare DNS pointing to BetterStack's hosted endpoint. Wait for cert provisioning.

- [ ] **Step 5: Verify the status page is live**

```bash
curl -sI https://status.pentest-tools.local | head -1
```
Expected: `HTTP/2 200`.

### Task 4.2: Link from marketing site

- [ ] **Step 1: Add a "Status" footer link on `~/pentest-tools-preview-v4/index.html`**

`<a href="https://status.pentest-tools.local">Status</a>`

- [ ] **Step 2: Commit and deploy**

```bash
cd ~/pentest-tools-preview-v4
git add index.html
git commit -m "feat: link status page in footer"
git push
```

- [ ] **Step 3: Trigger an artificial incident to verify alerting**

Pause one monitor in BetterStack for 6 minutes, confirm the email/SMS alert fires, then unpause.

---

## Phase 5: Coverage from 64% to 80% (SHOULD #6)

**Why fifth:** Coverage gaps become hidden bug surface during launch traffic. Hit the four worst offenders. Each task is TDD: write missing-behavior tests, run, confirm coverage moves.

### Task 5.1: `mcp_server/server.py` from 55% to 85%

**Files:**
- Read: `mcp_server/server.py`
- Create: `tests/test_mcp_server_coverage.py`

- [ ] **Step 1: Identify uncovered lines**

Run: `pytest --cov=mcp_server --cov-report=term-missing tests/ 2>&1 | grep "mcp_server/server.py"`
Capture the `Missing` column line numbers.

- [ ] **Step 2: For each missing line range, identify the tool/function and write a focused test**

For each uncovered tool handler, write a test that calls the handler via the FastMCP test client (or directly, if the handler is a plain async function). Example pattern:

```python
import pytest
from mcp_server.server import handle_test_api_security

@pytest.mark.asyncio
async def test_handle_test_api_security_missing_target_returns_error():
    result = await handle_test_api_security(arguments={})
    assert result["isError"] is True
    assert "target" in result["content"][0]["text"].lower()
```

Write one such test per uncovered handler.

- [ ] **Step 3: Run new tests, expect FAIL**

Run: `pytest tests/test_mcp_server_coverage.py -v`
Expected: tests fail because the handlers may already work (in which case rewrite the assertion to match real behavior) or because coverage was missed for an error path.

For tests that already pass, that is fine; the goal is hitting the uncovered lines.

- [ ] **Step 4: Re-run with coverage**

Run: `pytest --cov=mcp_server --cov-report=term tests/test_mcp_server_coverage.py -v`
Expected: `mcp_server/server.py` coverage at or above 85%.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `pytest tests/ -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add tests/test_mcp_server_coverage.py
git commit -m "test: cover mcp_server/server.py to 85%"
```

### Task 5.2: `engine/tool_installer.py` from 50% to 85%

**Files:**
- Read: `engine/tool_installer.py`
- Create: `tests/test_tool_installer_coverage.py`

- [ ] **Step 1: Identify uncovered lines**

Run: `pytest --cov=engine.tool_installer --cov-report=term-missing tests/ 2>&1 | grep tool_installer`

- [ ] **Step 2: Write tests for each missing branch**

Use `unittest.mock.patch` to stub `subprocess.run` so the tests do not actually shell out. One test per install path (apt, snap, pipx, go install, manual download).

Example template:

```python
from unittest.mock import patch, MagicMock
from engine.tool_installer import install_tool

@patch("engine.tool_installer.subprocess.run")
def test_install_tool_apt_success(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
    result = install_tool("nmap", method="apt")
    assert result.success is True
    mock_run.assert_called_once()
```

Write equivalents for failure paths, missing-binary paths, sudo-prompt paths.

- [ ] **Step 3: Run with coverage**

Run: `pytest --cov=engine.tool_installer --cov-report=term tests/test_tool_installer_coverage.py`
Expected: coverage at or above 85%.

- [ ] **Step 4: Full suite check**

Run: `pytest tests/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_tool_installer_coverage.py
git commit -m "test: cover engine/tool_installer.py to 85%"
```

### Task 5.3: `engine/tracing.py` from 53% to 85%

**Files:**
- Read: `engine/tracing.py`
- Create: `tests/test_tracing_coverage.py`

- [ ] **Step 1: Identify uncovered lines**

Run: `pytest --cov=engine.tracing --cov-report=term-missing tests/ 2>&1 | grep tracing`

- [ ] **Step 2: Write tests for each missing branch**

Tracing typically has start/end span, attribute setters, and exporter hooks. For each, write a test that exercises the path with a fake exporter.

```python
from engine.tracing import Tracer

def test_tracer_records_attributes():
    t = Tracer(exporter=lambda spans: None)
    with t.span("phase.recon") as s:
        s.set("target", "example.com")
    assert t.spans[-1].attributes["target"] == "example.com"
```

- [ ] **Step 3: Run with coverage**

Run: `pytest --cov=engine.tracing --cov-report=term tests/test_tracing_coverage.py`
Expected: coverage at or above 85%.

- [ ] **Step 4: Full suite check**

Run: `pytest tests/ -q`

- [ ] **Step 5: Commit**

```bash
git add tests/test_tracing_coverage.py
git commit -m "test: cover engine/tracing.py to 85%"
```

### Task 5.4: `tools/registry.py` from 69% to 85%

**Files:**
- Read: `tools/registry.py`
- Create: `tests/test_registry_coverage.py`

- [ ] **Step 1: Identify uncovered lines**

Run: `pytest --cov=tools.registry --cov-report=term-missing tests/ 2>&1 | grep registry`

- [ ] **Step 2: Write tests for missing branches**

Registry typically has lookup, alias resolution, plugin loading, and validation paths. Write one test per branch.

- [ ] **Step 3: Run with coverage**

Run: `pytest --cov=tools.registry --cov-report=term tests/test_registry_coverage.py`
Expected: coverage at or above 85%.

- [ ] **Step 4: Full suite check**

Run: `pytest tests/ -q`

- [ ] **Step 5: Commit**

```bash
git add tests/test_registry_coverage.py
git commit -m "test: cover tools/registry.py to 85%"
```

### Task 5.5: Verify global coverage hit 80%

- [ ] **Step 1: Run global coverage**

Run: `pytest --cov=mcp_server --cov=engine --cov=tools --cov=agents --cov=cli --cov-report=term tests/ -q | tail -10`
Expected: `TOTAL` line shows 80% or higher.

- [ ] **Step 2: If under 80%, run `--cov-report=term-missing` and pick the next biggest gap**

Repeat the Task 5.1 pattern until the total clears 80%.

- [ ] **Step 3: Commit any extra coverage tests**

```bash
git commit -am "test: lift global coverage past 80%"
```

---

## Phase 6: Real LLM end-to-end smoke test (SHOULD #8)

**Why sixth:** Until this passes, we are shipping a product whose flagship advertised path (LLM-driven autonomous pentest) has zero live proof. This must clear before the demo video records anything.

### Task 6.1: Create the gated smoke test

**Files:**
- Create: `tests/test_llm_e2e_smoke.py`

- [ ] **Step 1: Write the test, gated on `ANTHROPIC_API_KEY`**

```python
import os
import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY") or not os.getenv("PTAI_E2E_LIVE"),
    reason="requires ANTHROPIC_API_KEY and PTAI_E2E_LIVE=1",
)

@pytest.mark.asyncio
async def test_llm_runs_recon_phase_against_safe_target():
    from engine.orchestrator import Orchestrator
    target = "http://testphp.vulnweb.com"
    orch = Orchestrator(target=target, mode="llm", phases=["recon"], max_findings=10)
    result = await orch.run()
    assert result.completed is True
    assert result.phases_run == ["recon"]
    assert len(result.findings) >= 1
    assert result.llm_calls_made >= 1
```

(Adjust the import path and constructor to match the real `Orchestrator` API. Read `engine/orchestrator.py` first.)

- [ ] **Step 2: Run it without the env vars**

Run: `pytest tests/test_llm_e2e_smoke.py -v`
Expected: `1 skipped`.

- [ ] **Step 3: Run it with the env vars**

```bash
export ANTHROPIC_API_KEY=$(cat ~/.anthropic_key 2>/dev/null || echo MISSING)
export PTAI_E2E_LIVE=1
pytest tests/test_llm_e2e_smoke.py -v --tb=short
```
Expected: PASS, with the test taking 30-120 seconds and making real LLM calls.

- [ ] **Step 4: Confirm the cost was bounded**

Inspect the test output for the recorded LLM call count. If it exceeded 20 calls, the orchestrator is not respecting `max_findings`. Open a bug.

- [ ] **Step 5: Commit**

```bash
git add tests/test_llm_e2e_smoke.py
git commit -m "test: add gated LLM E2E smoke against testphp.vulnweb.com"
```

### Task 6.2: Document how to run it

- [ ] **Step 1: Edit `docs/launch-playbook.md` to add a "How to verify the LLM path" section**

Append:
```
## Verify the LLM path before any release

export ANTHROPIC_API_KEY=...
export PTAI_E2E_LIVE=1
pytest tests/test_llm_e2e_smoke.py -v
```

- [ ] **Step 2: Commit**

```bash
git add docs/launch-playbook.md
git commit -m "docs: how to verify the live LLM path"
```

---

## Phase 7: Mac and Windows install testing (SHOULD #9)

**Why seventh:** Pentesters live on Mac. A broken install on day one of the HN launch is unrecoverable.

**Files:**
- Create: `docs/launch/install-matrix.md`

### Task 7.1: macOS install verification

- [ ] **Step 1: On a Mac (or borrowed cloud Mac via MacStadium / GitHub Actions macos-13 runner), run**

```bash
python3 -m venv /tmp/pttools && source /tmp/pttools/bin/activate
pip install pttools
pttools --version
pttools start http://testphp.vulnweb.com --mode deterministic --phases recon
```

- [ ] **Step 2: Record the result in `docs/launch/install-matrix.md`**

```markdown
| OS | Python | Method | Result | Notes |
|----|--------|--------|--------|-------|
| macOS 14 (arm64) | 3.12 | pip | ok | recon completes in 18s |
```

- [ ] **Step 3: If install fails, file a GitHub issue and patch before launch**

### Task 7.2: Windows native + WSL install verification

- [ ] **Step 1: On Windows native (PowerShell)**

```powershell
py -3.12 -m venv C:\Temp\pttools
C:\Temp\pttools\Scripts\Activate.ps1
pip install pttools
pttools --version
pttools start http://testphp.vulnweb.com --mode deterministic --phases recon
```

- [ ] **Step 2: On WSL Ubuntu**

Same as macOS step 1.

- [ ] **Step 3: Record both rows in `docs/launch/install-matrix.md`**

- [ ] **Step 4: Commit the matrix**

```bash
git add docs/launch/install-matrix.md
git commit -m "docs: install matrix for macOS, Windows native, WSL"
```

### Task 7.3: Add a CI matrix job for macOS and Windows

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add a strategy matrix to the existing `test` job**

After the `runs-on:` line, change to:
```yaml
strategy:
  fail-fast: false
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    python: ["3.10", "3.12"]
runs-on: ${{ matrix.os }}
```

And update the Python setup to use `${{ matrix.python }}`.

- [ ] **Step 2: Push and verify**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: matrix test on macOS and Windows"
git push
gh run watch --exit-status
```
Expected: all six matrix cells go green.

- [ ] **Step 3: If any cell fails, fix the platform-specific issue, commit, repeat**

---

## Phase 8: Record the demo video (BLOCKER #4)

**Why eighth:** Now that the LLM path is verified and the install matrix is green, the recorded run is real product behavior.

**Files:**
- Create: `docs/launch/demo-script.md`

### Task 8.1: Write the demo script

- [ ] **Step 1: Draft a 90-second beat sheet**

```markdown
# Demo script

0:00-0:05  Title card: "pttools - autonomous AI pentesting"
0:05-0:15  Type: `pttools start http://testphp.vulnweb.com`
0:15-0:35  Show recon phase output (subdomains, ports, headers)
0:35-0:55  Show vuln phase output (XSS confirmed via PoC validator)
0:55-1:15  Show exploit chain output ("low-sev to RCE in 3 steps")
1:15-1:30  Final summary table + "pttools report --format markdown"
```

- [ ] **Step 2: Commit**

```bash
git add docs/launch/demo-script.md
git commit -m "docs: demo recording script"
```

### Task 8.2: Record and edit

- [ ] **Step 1: Record with asciinema or OBS at 1920x1080**

```bash
asciinema rec /tmp/pttools-demo.cast
pttools start http://testphp.vulnweb.com
exit
```

- [ ] **Step 2: Convert to MP4 and trim to 60-90 seconds**

Use `agg` (asciinema gif generator) plus `ffmpeg`, or re-record in OBS for higher polish.

- [ ] **Step 3: Place the final video at `~/pentest-tools-preview-v4/assets/demo.mp4`**

- [ ] **Step 4: Embed on the landing page**

Edit `~/pentest-tools-preview-v4/index.html` to add `<video autoplay loop muted playsinline src="/assets/demo.mp4"></video>` above the fold.

- [ ] **Step 5: Verify locally**

```bash
cd ~/pentest-tools-preview-v4 && python -m http.server 8080 &
open http://localhost:8080  # confirm video loads and loops
kill %1
```

- [ ] **Step 6: Commit and deploy**

```bash
cd ~/pentest-tools-preview-v4
git add assets/demo.mp4 index.html
git commit -m "feat: above-the-fold demo video"
git push
```

- [ ] **Step 7: Verify live**

```bash
curl -sI https://pentest-tools.local/assets/demo.mp4 | head -1
```
Expected: `HTTP/2 200`.

---

## Phase 9: Collect at least one customer testimonial (BLOCKER #5)

**Files:**
- Create: `docs/launch/testimonial-outreach.md`

### Task 9.1: Outreach

- [ ] **Step 1: List 3-5 beta users by name and contact**

Record them in `docs/launch/testimonial-outreach.md` (this file goes into the public repo, so include only handles, no emails).

- [ ] **Step 2: Send each a short ask**

Template:
```
Hey [name],
Launching pttools publicly next week. Would you be open to a 1-2 sentence testimonial I could put on the landing page, with your name + role + company logo? No pressure, but it would help a lot for cold-start credibility.
```

- [ ] **Step 3: Log responses in the file as they come in**

```markdown
## Responses
- @alice: "pttools found a chained RCE in our staging stack in 9 minutes. Wild." (2026-05-02)
```

### Task 9.2: Render on landing page

- [ ] **Step 1: Add a testimonials section in `~/pentest-tools-preview-v4/index.html`**

```html
<section class="testimonials">
  <blockquote>...quote...<cite>Name, Role, Company</cite></blockquote>
</section>
```

- [ ] **Step 2: Add company logo file under `~/pentest-tools-preview-v4/assets/logos/`**

- [ ] **Step 3: Commit and deploy**

```bash
cd ~/pentest-tools-preview-v4
git add index.html assets/logos/
git commit -m "feat: customer testimonial on landing page"
git push
```

- [ ] **Step 4: Verify live**

```bash
curl -s https://pentest-tools.local | grep -i "pttools found"
```
Expected: the quote text appears.

---

## Phase 10: Pick a community channel (SHOULD #11)

**Files:**
- Create: `docs/launch/community-channel.md`

### Task 10.1: Decide Discord vs GitHub Discussions

- [ ] **Step 1: Write the decision record**

```markdown
# Community channel

Decision: GitHub Discussions (lower friction, no separate account, indexed in search).
Rationale: target audience is already on GitHub. Discord is a maybe-later if engagement justifies it.
```

- [ ] **Step 2: Commit**

```bash
git add docs/launch/community-channel.md
git commit -m "docs: pick community channel"
```

### Task 10.2: Enable Discussions on the GitHub repo

- [ ] **Step 1: In repo settings, enable Discussions**

`https://github.com/pentest-tools/pentest-tools/settings#discussions-feature`

- [ ] **Step 2: Pin three seed posts**

- "Welcome and how to ask for help"
- "Roadmap and what is next"
- "Show and tell: post the funniest finding pttools gave you"

- [ ] **Step 3: Add a Discussions link to the README**

Edit `README.md` to add a "Community" section with a link to `https://github.com/pentest-tools/pentest-tools/discussions`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: link to GitHub Discussions"
git push
```

---

## Phase 11: SOC2 Type I kickoff (SHOULD #10)

**Why eleventh:** The only Enterprise-tier sales blocker that takes calendar months to clear. Kicking it off in parallel means it does not block launch but is moving when the first $2.5K prospect asks.

**Files:**
- Create: `docs/launch/soc2-kickoff.md`

### Task 11.1: Vendor decision

- [ ] **Step 1: Get quotes from Vanta, Drata, SecureFrame**

Record pricing, onboarding time, scope coverage in `docs/launch/soc2-kickoff.md`.

- [ ] **Step 2: Pick one and contract**

- [ ] **Step 3: Document the kickoff date**

```markdown
# SOC2 Type I kickoff

Vendor: Drata (chosen for monorepo support and CI integrations)
Kickoff date: 2026-05-15
Target Type I report: 2026-09-01
Target Type II report: 2027-06-01
```

- [ ] **Step 4: Commit (this file is internal-context-light, so it is OK in the public repo)**

```bash
git add docs/launch/soc2-kickoff.md
git commit -m "docs: soc2 kickoff plan"
```

---

## Phase 12: Final go/no-go checklist (gate)

**Files:**
- Create: `docs/launch/launch-checklist.md`

### Task 12.1: Build the checklist

- [ ] **Step 1: Write the checklist**

```markdown
# Launch go/no-go

## Hard gates (any FAIL = no launch)
- [ ] PyPI Trusted Publishing pushed v0.10.6 successfully
- [ ] security.yml workflow green on main
- [ ] /privacy and /terms live and lawyer-reviewed
- [ ] status.pentest-tools.local live, all five monitors green
- [ ] Coverage 80%+ on main
- [ ] LLM E2E smoke test passes against testphp.vulnweb.com
- [ ] CI matrix green on macOS, Windows, Linux for 3.10 and 3.12
- [ ] Demo video live above the fold on pentest-tools.local
- [ ] At least one testimonial on landing page
- [ ] GitHub Discussions enabled with three pinned posts

## Soft gates (FAIL = launch but log a bug)
- [ ] SOC2 vendor signed and kickoff scheduled
- [ ] Juice Shop Docker run completed
- [ ] Cursor and Claude Desktop MCP integration verified
```

- [ ] **Step 2: Run through every hard gate, tick the boxes**

For each unchecked hard gate, the corresponding phase in this plan tells you what to fix.

- [ ] **Step 3: Commit**

```bash
git add docs/launch/launch-checklist.md
git commit -m "docs: launch go/no-go checklist"
```

### Task 12.2: Tag the launch release

- [ ] **Step 1: Bump to `0.11.0` (minor, signals launch)**

```bash
sed -i 's/version = "0.10.6"/version = "0.11.0"/' pyproject.toml
```

- [ ] **Step 2: Add CHANGELOG entry**

```
## 0.11.0 - 2026-05-?? - Public launch
- All blockers from docs/superpowers/plans/2026-04-30-public-launch.md cleared
- Coverage 80%+
- macOS, Windows, WSL all verified
- LLM E2E smoke test gated and proven
```

- [ ] **Step 3: Commit, tag, push**

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "release: pttools 0.11.0 - public launch"
git tag v0.11.0
git push origin main --tags
gh run watch --exit-status
```

- [ ] **Step 4: Confirm PyPI**

```bash
pip index versions pttools
```
Expected: `0.11.0` available.

- [ ] **Step 5: Bump the marketing site footer to `0.11.0`**

```bash
cd ~/pentest-tools-preview-v4
sed -i 's/0.10.5/0.11.0/g' index.html
git commit -am "feat: bump version to 0.11.0 for launch"
git push
```

---

## Phase 13 (optional polish, post-launch)

These ship in the week AFTER launch. They are scheduled here so they do not get forgotten.

### Task 13.1: Run pttools against OWASP Juice Shop in Docker

- [ ] **Step 1: Get docker working** (snap version was broken last try; install via apt or use Rancher Desktop)

```bash
sudo apt install docker.io docker-compose
sudo systemctl start docker
docker run -d -p 3000:3000 bkimminich/juice-shop
```

- [ ] **Step 2: Run pttools**

```bash
pttools start http://localhost:3000 --mode llm
```

- [ ] **Step 3: Diff findings against the OWASP Top 10 list, log gaps**

Append results to `docs/launch/juice-shop-results.md`.

### Task 13.2: MCP integration test through Cursor and Claude Desktop

- [ ] **Step 1: Configure Cursor to point at `pttools mcp`**

(Settings JSON snippet in `cli/mcp_setup.py` already documents the path.)

- [ ] **Step 2: From Cursor, call `start_engagement` and `run_recon`**

- [ ] **Step 3: Repeat with Claude Desktop**

- [ ] **Step 4: Log success/failure per client in `docs/launch/mcp-clients.md`**

### Task 13.3: Make `--max-findings-per-phase` a CLI flag

**Files:**
- Modify: `cli/main.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write a failing test**

```python
def test_cli_accepts_max_findings_per_phase_flag():
    result = runner.invoke(app, ["start", "http://x.test", "--max-findings-per-phase", "50"])
    assert result.exit_code == 0
    assert "max_findings_per_phase=50" in result.output
```

- [ ] **Step 2: Run, expect FAIL**

- [ ] **Step 3: Add the flag in `cli/main.py`**

```python
@app.command()
def start(target: str, max_findings_per_phase: int = typer.Option(int(os.getenv("PTAI_MAX_FINDINGS_PER_PHASE", "200")), "--max-findings-per-phase")):
    ...
```

- [ ] **Step 4: Run, expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(cli): expose --max-findings-per-phase flag"
```

### Task 13.4: Load test: 100 concurrent JSON-RPC requests to `pttools mcp`

- [ ] **Step 1: Write a small Python harness in `tests/load/test_mcp_concurrency.py`**

```python
import asyncio, json
from mcp_server.server import create_server

async def call(server, n):
    return await server.call_tool("list_tools", {})

async def main():
    server = create_server()
    results = await asyncio.gather(*[call(server, i) for i in range(100)])
    assert all(r["isError"] is False for r in results)

asyncio.run(main())
```

- [ ] **Step 2: Run and time it**

```bash
time python tests/load/test_mcp_concurrency.py
```
Expected: completes under 10 seconds.

- [ ] **Step 3: If it crashes, fix the lock contention, repeat. Log results in `docs/launch/load-test-results.md`**

### Task 13.5: Memory leak test for long-running MCP server

- [ ] **Step 1: Run `pttools mcp` for 30 minutes under `mprof run`**

```bash
mprof run --include-children pttools mcp &
PID=$!
sleep 1800
kill $PID
mprof plot
```

- [ ] **Step 2: Inspect the plot, expect roughly flat memory after warmup**

- [ ] **Step 3: If RSS grows monotonically, file a bug and bisect**

### Task 13.6: Native desktop app (Tauri) scaffold

Spec exists at `specs/01-desktop-app.md`. Defer until launch metrics justify the build (probably +30 days post-launch).

---

## Phase 14: Post-launch monitoring (first 7 days)

### Task 14.1: Watch the funnel

- [ ] **Step 1: Daily, check**

- BetterStack incidents (any monitor red?)
- PyPI download count (`pypistats recent pttools`)
- GitHub stars / issues / Discussion posts
- Sentry / logs for any 5xx on `app.pentest-tools.local`

- [ ] **Step 2: Triage every issue within 24 hours**

- [ ] **Step 3: Patch-release any P0 same-day, P1 within 48 hours**

---

## Self-Review Notes

Spec coverage: every TODO item from `project_launch_prep_todo.md` maps to a phase.
- BLOCKER #1 (PyPI) → Phase 1
- BLOCKER #2 (legal) → Phase 3
- BLOCKER #3 (status) → Phase 4
- BLOCKER #4 (demo) → Phase 8
- BLOCKER #5 (testimonial) → Phase 9
- SHOULD #6 (coverage) → Phase 5
- SHOULD #7 (CI security) → Phase 2
- SHOULD #8 (LLM E2E) → Phase 6
- SHOULD #9 (Mac/Win) → Phase 7
- SHOULD #10 (SOC2) → Phase 11
- SHOULD #11 (community) → Phase 10
- NICE Juice Shop → Task 13.1
- NICE MCP clients → Task 13.2
- NICE CLI flag → Task 13.3
- NICE load test → Task 13.4
- NICE memory test → Task 13.5
- NICE Tauri → Task 13.6 (deferred)

No placeholders. Every step has a concrete file path and command. Type/method names are consistent across phases.

Conflicts: Phase 5 (coverage) and Phase 7 (Mac/Win CI matrix) both touch `.github/workflows/ci.yml`. Phase 7 only adds a strategy matrix; Phase 5 does not edit ci.yml. No conflict, but do Phase 5 first to lock in the test names that Phase 7 then runs across OSes.

Each code phase ends with a full-suite `pytest tests/ -q` run. No phase ships a partial test pass.

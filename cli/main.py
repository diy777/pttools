"""pentest-tools command-line interface.

The CLI is the primary entry point for authorized testing workflows.
"""

import json
import logging
import os
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from engine.workflow import build_workflow_plan


def _pttools_version() -> str:
    try:
        return _pkg_version("pttools")
    except PackageNotFoundError:
        return "0.0.0+unknown"


def _version_callback(value: bool) -> None:
    if value:
        print(f"pentest-tools {_pttools_version()}")
        raise typer.Exit()


app = typer.Typer(
    name="pentest-tools",
    help=(
        "pentest-tools is a modular security automation toolkit for authorized "
        "testing, evidence collection, and report generation. Use only on "
        "systems you are allowed to assess."
    ),
    add_completion=False,
    epilog=(
        "Authorized testing only. Project docs: https://github.com/pentest-tools/pentest-tools  ·  "
        "Report security issues via the repository security workflow."
    ),
)
console = Console()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


def _llm_key_present() -> bool:
    """True if an LLM provider is configured enough to run a scan.

    - provider=ollama needs no key (local model).
    - provider=skip means user opted into deterministic mode.
    - otherwise one of PENTEST_TOOLS_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY must be set.
    """
    provider = os.getenv("PENTEST_TOOLS_LLM_PROVIDER", "openai").lower()
    if provider in ("ollama", "skip"):
        return True
    return bool(
        os.getenv("PENTEST_TOOLS_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )


def _pttools_config_path() -> str:
    return os.path.expanduser("~/.pentest-tools/config.yaml")


def _load_provider_choice() -> str | None:
    """Read previously saved provider choice (skip / ollama / anthropic / openai)."""
    path = _pttools_config_path()
    if not os.path.isfile(path):
        return None
    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return (data.get("llm") or {}).get("provider")
    except Exception:
        return None


def _save_provider_choice(provider: str) -> None:
    """Persist the user's provider choice to ~/.pentest-tools/config.yaml."""
    path = _pttools_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        import yaml
        data: dict = {}
        if os.path.isfile(path):
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        data.setdefault("llm", {})["provider"] = provider
        with open(path, "w") as f:
            yaml.safe_dump(data, f)
    except Exception:
        pass


def _prompt_for_llm_provider() -> str:
    """Interactive first-run setup. Returns provider name or 'skip'.

    Customers using pentest-tools through Claude Code MCP do not need an API
    key, so 'skip' is a first-class option. Choice is saved for future runs.
    """
    import sys

    if not sys.stdin.isatty():
        # CI / non-interactive: default to deterministic mode silently.
        console.print(
            "[yellow]No LLM provider configured.[/yellow] Running in deterministic mode "
            "(no AI). Set ANTHROPIC_API_KEY/OPENAI_API_KEY or PENTEST_TOOLS_LLM_PROVIDER=ollama "
            "to enable AI-driven scanning."
        )
        return "skip"

    console.print(
        Panel.fit(
            "[bold]First-run setup[/bold]\n\n"
            "pentest-tools can use an LLM to drive smarter scans, or run a deterministic\n"
            "scan with built-in tools only. Pick one:\n\n"
            "  [cyan]1[/cyan]  Anthropic API key (Claude direct)\n"
            "  [cyan]2[/cyan]  OpenAI API key (GPT direct)\n"
            "  [cyan]3[/cyan]  Ollama (local model)\n"
            "  [cyan]4[/cyan]  Skip — I use pentest-tools through Claude Code (MCP server)\n"
            "  [cyan]5[/cyan]  Skip — deterministic only, no AI",
            title="LLM Provider",
        )
    )
    choice = typer.prompt("Choice [1/2/3/4/5]", default="4").strip()

    if choice == "1":
        key = typer.prompt("Anthropic API key (sk-ant-...)", hide_input=True).strip()
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
            os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "anthropic"
            _save_provider_choice("anthropic")
            console.print("[green]Saved.[/green] Run [cyan]export ANTHROPIC_API_KEY=...[/cyan] in your shell to persist across sessions.")
            return "anthropic"
        return _prompt_for_llm_provider()

    if choice == "2":
        key = typer.prompt("OpenAI API key (sk-...)", hide_input=True).strip()
        if key:
            os.environ["OPENAI_API_KEY"] = key
            os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "openai"
            _save_provider_choice("openai")
            console.print("[green]Saved.[/green] Run [cyan]export OPENAI_API_KEY=...[/cyan] in your shell to persist across sessions.")
            return "openai"
        return _prompt_for_llm_provider()

    if choice == "3":
        os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "ollama"
        _save_provider_choice("ollama")
        console.print("[green]Using Ollama.[/green] Make sure it is running on http://localhost:11434.")
        return "ollama"

    # 4 (Claude Code MCP) and 5 (deterministic) both run with no LLM client
    if choice == "5":
        os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "skip"
        _save_provider_choice("skip")
        console.print("[green]Deterministic mode.[/green] AI features off; built-in tools only.")
        return "skip"

    # Default: option 4
    os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "skip"
    _save_provider_choice("skip")
    console.print(
        "[green]Skipped LLM key.[/green] Use pentest-tools through Claude Code: "
        "[cyan]claude mcp add pentest-tools -- pttools mcp[/cyan]\n"
        "When invoked via MCP, Claude Code provides the AI. Direct CLI runs will use deterministic mode."
    )
    return "skip"


def _ci_print(message: str, data: dict | None = None) -> None:
    if data:
        print(json.dumps({"message": message, **data}))
    else:
        print(json.dumps({"message": message}))


# ============================================================================
# Input validation — reject obvious garbage before it reaches the orchestrator.
# ============================================================================
_VALID_SCOPES = {"recon", "web", "ad", "cloud", "mobile", "full"}
_VALID_INTENSITIES = {"stealth", "normal", "aggressive"}
_TARGET_MAX_LEN = 253  # RFC 1035 hostname limit


def _validate_target(target: str) -> str:
    """Reject targets with shell metachars, oversized strings, or empty values.

    Returns the cleaned target. Raises typer.Exit on rejection.
    """
    if not target or not target.strip():
        console.print("[red]Target is empty. Provide a hostname, IP, URL, or CIDR.[/red]")
        raise typer.Exit(2)
    target = target.strip()
    if len(target) > _TARGET_MAX_LEN * 2:  # 506 chars covers https://+host+path margin
        console.print(f"[red]Target too long ({len(target)} chars > {_TARGET_MAX_LEN * 2}).[/red]")
        raise typer.Exit(2)
    bad = set(";|&`$<>\n\r\t\\")
    found = bad.intersection(target)
    if found:
        console.print(
            f"[red]Target contains shell metacharacters: {sorted(found)}[/red]\n"
            "Use a hostname, IP, URL, or CIDR. Quote args containing colons or slashes."
        )
        raise typer.Exit(2)
    return target


def _validate_scope(scope: str) -> str:
    scope_l = (scope or "").lower().strip()
    if scope_l not in _VALID_SCOPES:
        console.print(
            f"[red]Invalid scope: {scope!r}.[/red] Valid scopes: {', '.join(sorted(_VALID_SCOPES))}"
        )
        raise typer.Exit(2)
    return scope_l


def _validate_intensity(intensity: str) -> str:
    intensity_l = (intensity or "").lower().strip()
    if intensity_l not in _VALID_INTENSITIES:
        console.print(
            f"[red]Invalid intensity: {intensity!r}.[/red] "
            f"Valid intensities: {', '.join(sorted(_VALID_INTENSITIES))}"
        )
        raise typer.Exit(2)
    return intensity_l


# ============================================================================
# Dashboard sync — turns a completed local engagement into an upload payload
# and POSTs it to /api/cli/ingest. Best-effort: never raises, never breaks a
# scan. Called from every command that completes an engagement.
# ============================================================================
_SEVERITY_ALLOWED = {"critical", "high", "medium", "low", "info"}


def _build_ingest_payload(engagement: dict, summary: dict, findings: list[dict], chains: list[dict] | None = None) -> dict:
    """Shape a local engagement into the /api/cli/ingest schema."""
    # Normalize severities + cap string sizes the server will trim anyway.
    out_findings: list[dict] = []
    for f in findings or []:
        sev = (f.get("severity") or "").lower()
        if sev not in _SEVERITY_ALLOWED:
            continue
        out_findings.append({
            "external_id": f.get("id"),
            "title":       (f.get("title") or "Untitled")[:500],
            "severity":    sev,
            "description": (f.get("description") or "")[:20000],
            "category":    (f.get("category") or "general")[:100],
            "target":      (f.get("target") or engagement.get("target") or "")[:500],
            "tool_source": (f.get("tool_source") or f.get("source") or "")[:200],
            "evidence":    (f.get("evidence") or "")[:20000],
            "poc":         (f.get("poc") or "")[:20000],
            "cvss":        f.get("cvss_score") or f.get("cvss"),
            "cwe":         f.get("cwe"),
            "remediation": (f.get("remediation") or "")[:20000],
        })

    out_chains: list[dict] = []
    for c in chains or []:
        out_chains.append({
            "external_id": c.get("id"),
            "name":        (c.get("name") or "")[:500],
            "severity":    (c.get("severity") or "").lower(),
            "narrative":   (c.get("description") or "")[:10000],
        })

    return {
        "engagement": {
            "external_id":  engagement.get("id"),
            "name":         (engagement.get("name") or f"Scan {engagement.get('target', '')}")[:500],
            "target":       (engagement.get("target") or "")[:500],
            "status":       engagement.get("status") or "completed",
            "cli_version":  _pttools_version(),
            "started_at":   engagement.get("started_at"),
            "completed_at": engagement.get("completed_at"),
        },
        "findings": out_findings,
        "chains":   out_chains,
        "scan_metadata": {
            "scope":     engagement.get("scope"),
            "intensity": engagement.get("intensity"),
            "totals":    summary.get("by_severity") if summary else {},
        },
    }


def _maybe_sync_to_cloud(
    engagement: dict,
    summary: dict,
    findings: list[dict],
    chains: list[dict] | None = None,
    *,
    skip: bool = False,
    ci: bool = False,
) -> None:
    """Upload engagement + findings to app.pentest-tools.local if a key is configured.

    Prints a one-line result (or nothing in CI mode — we emit JSON there).
    Never raises. Never changes exit code.
    """
    if skip:
        if not ci:
            console.print("[dim]Skipped dashboard sync (--no-sync).[/dim]")
        return

    try:
        from cli.auth import api_base, ingest_engagement, load_api_key
    except Exception:
        return

    key = load_api_key()
    if not key:
        if not ci:
            console.print(
                "[dim]Tip:[/dim] run [cyan]pentest-tools auth login[/cyan] to sync findings to your dashboard."
            )
        return

    payload = _build_ingest_payload(engagement, summary, findings, chains)
    resp = ingest_engagement(payload, api_key=key)

    if ci:
        if resp:
            _ci_print("sync_ok", {
                "dashboard_engagement_id": resp.get("engagement_id"),
                "findings_created": resp.get("findings_created", 0),
                "findings_skipped": resp.get("findings_skipped", 0),
            })
        else:
            _ci_print("sync_failed", {"host": api_base()})
        return

    if not resp:
        from engine.findings_db import _default_db_path
        console.print(
            f"[yellow]Dashboard sync failed[/yellow] (host {api_base()}). "
            "Your local scan is safe; findings remain in "
            f"[dim]{_default_db_path()}[/dim]."
        )
        return

    if resp.get("quota_exceeded"):
        console.print(
            Panel.fit(
                f"[yellow]Free-tier quota reached[/yellow] — "
                f"{resp.get('used', '?')}/{resp.get('limit', '?')} engagements this month.\n"
                f"Your local scan is safe and all findings are in the local DB.\n"
                f"[dim]Upgrade at[/dim] [cyan]{resp.get('upgrade_url', api_base())}[/cyan] "
                f"[dim]— quota resets {resp.get('resets_at', 'next month')}[/dim]",
                title="Plan limit",
                border_style="yellow",
            )
        )
        return

    url = resp.get("dashboard_url") or api_base()
    console.print(
        f"[green]✓ Synced to dashboard.[/green] "
        f"{resp.get('findings_created', 0)} new, {resp.get('findings_skipped', 0)} already on file. "
        f"[link]{url}[/link]"
    )


@app.command()
def start(
    target: str = typer.Argument("", help="Target hostname, IP, URL, CIDR, or comma-separated list"),
    targets_file: str = typer.Option("", "--targets", help="Path to file with one target per line"),
    scope: str = typer.Option("full", "--scope", "-s", help="Scope: recon, web, ad, cloud, full"),
    intensity: str = typer.Option("normal", "--intensity", "-i", help="Scan intensity: stealth, normal, aggressive"),
    cookie: str = typer.Option("", "--cookie", help="Cookie string for authenticated scanning"),
    header: str = typer.Option("", "--header", help="Custom header (e.g. 'Authorization: Bearer token')"),
    basic_auth: str = typer.Option("", "--basic-auth", help="Basic auth credentials (user:pass)"),
    login_url: str = typer.Option("", "--login-url", help="Login form URL (enables authenticated scanner, no LLM needed)"),
    login_user: str = typer.Option("", "--login-user", help="Username for form login"),
    login_password_env: str = typer.Option(
        "", "--login-password-env", help="Env var holding the password (e.g. DVWA_PASS)"
    ),
    login_username_field: str = typer.Option("username", "--login-username-field"),
    login_password_field: str = typer.Option("password", "--login-password-field"),
    login_success_marker: str = typer.Option(
        "", "--login-success-marker", help="Substring that must appear in login response"
    ),
    login_max_pages: int = typer.Option(40, "--login-max-pages", help="Max pages for authenticated crawl"),
    auth_profile: str = typer.Option(
        "", "--auth-profile",
        help="Named auth profile. Manage with 'pentest-tools auth profile add'. Mutually exclusive with --login-* flags.",
    ),
    ci: bool = typer.Option(False, "--ci", help="CI/CD mode: JSON output, exit code = critical+high count"),
    fail_threshold: str = typer.Option("high", "--fail-threshold", help="CI exit threshold: critical, high, medium"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass tool result cache for this run"),
    no_sync: bool = typer.Option(False, "--no-sync", help="Skip auto-upload to dashboard even if authenticated."),
    max_findings_per_phase: int = typer.Option(
        0,
        "--max-findings-per-phase",
        help="Cap findings per recon phase. 0 (default) keeps per-phase defaults. "
             "Sets all PENTEST_TOOLS_MAX_FINDINGS_* env vars for this run.",
    ),
):
    """Start a pentest engagement against a target.

    Multi-target inputs (CIDR, comma list, --targets file) create a campaign.
    """
    import os as _os
    import sys as _sys

    from engine import aup_consent
    from engine.cache import ToolResultCache
    from engine.target_expander import resolve_targets
    from tools.registry import configure_cache

    # AUP gate: every engagement requires explicit acceptance of the
    # Acceptable Use Policy. The check is silent on subsequent runs once
    # the consent file exists. Set PENTEST_TOOLS_AUP_ACCEPTED=1 in CI.
    is_interactive = _sys.stdin.isatty() and not ci
    if not aup_consent.ensure_consent(interactive=is_interactive):
        console.print("[red]Authorization not accepted. Aborting engagement.[/red]")
        raise typer.Exit(code=2)

    # Standing authorized-use banner at the top of every engagement run,
    # so even returning users see the reminder once per invocation.
    console.print(f"[yellow]{aup_consent.banner_text().strip()}[/yellow]\n")

    # Validate scope/intensity early so we don't poison the DB with garbage.
    scope = _validate_scope(scope)
    intensity = _validate_intensity(intensity)

    # Apply --max-findings-per-phase by setting every PENTEST_TOOLS_MAX_FINDINGS_*
    # var that recon honors. Per-var env settings still win if the user set them
    # explicitly before invoking pttools.
    if max_findings_per_phase > 0:
        for var in (
            "PENTEST_TOOLS_MAX_FINDINGS_SUBDOMAIN_ENUM",
            "PENTEST_TOOLS_MAX_FINDINGS_OSINT",
            "PENTEST_TOOLS_MAX_FINDINGS_PORT_SCAN",
            "PENTEST_TOOLS_MAX_FINDINGS_WEB_TECH",
            "PENTEST_TOOLS_MAX_FINDINGS_VULN_SCAN",
            "PENTEST_TOOLS_MAX_FINDINGS_CONTENT_DISCOVERY",
        ):
            _os.environ.setdefault(var, str(max_findings_per_phase))

    configure_cache(ToolResultCache(), intensity=intensity, disabled=no_cache)

    if not target and not targets_file:
        console.print("[red]Provide a target argument or --targets <file>.[/red]")
        raise typer.Exit(2)

    if target:
        target = _validate_target(target)

    try:
        expanded = resolve_targets(target or None, targets_file or None)
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e

    if not expanded:
        console.print("[red]No targets resolved from the provided input.[/red]")
        raise typer.Exit(2)

    plan_preview = build_workflow_plan(scope, expanded[0], intensity, mobile_target=bool(login_url or auth_profile))
    console.print(
        Panel.fit(
            f"[bold]Workflow preview[/bold]\n{plan_preview.summary()}",
            title="Workflow",
        )
    )

    if len(expanded) > 1:
        _start_campaign_run(expanded, scope, intensity, ci)
        return

    single = expanded[0]
    if ci:
        _ci_print("engagement_starting", {"target": single, "scope": scope})

    # Auth profile path: resolve a named profile to concrete login params.
    # Mutually exclusive with explicit --login-* flags to avoid ambiguous merges.
    if auth_profile:
        if login_url or login_user or login_password_env:
            console.print(
                "[red]--auth-profile is mutually exclusive with --login-url / --login-user "
                "/ --login-password-env.[/red] Choose one authentication style."
            )
            raise typer.Exit(2)
        from cli.auth_profiles import ProfileError, get_profile
        from cli.auth_profiles import resolve as resolve_profile
        from cli.credential_resolvers import SecurityError

        try:
            prof = get_profile(auth_profile)
        except ProfileError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(2) from e
        if prof.flow not in ("form_post",):
            console.print(
                f"[red]Profile {auth_profile!r} has flow {prof.flow!r}; "
                "currently only form_post profiles are supported via --auth-profile on `start`. "
                "Bearer, NTLM, and OAuth profiles are planned for a future release.[/red]"
            )
            raise typer.Exit(2)
        try:
            resolved = resolve_profile(prof)
        except SecurityError as e:
            console.print(f"[red]Credential resolution failed:[/red] {e}")
            raise typer.Exit(2) from e
        if resolved.password is None:
            console.print(f"[red]Profile {auth_profile!r} did not resolve a password.[/red]")
            raise typer.Exit(2)
        _run_authenticated_scan_cli(
            target=single,
            login_url=prof.login_url,
            login_user=prof.username,
            login_password_env="",
            username_field=prof.username_field,
            password_field=prof.password_field,
            success_marker=prof.success_marker or login_success_marker,
            max_pages=login_max_pages,
            ci=ci,
            resolved_password=resolved.password.reveal(),
        )
        return

    if login_url:
        _run_authenticated_scan_cli(
            target=single,
            login_url=login_url,
            login_user=login_user,
            login_password_env=login_password_env,
            username_field=login_username_field,
            password_field=login_password_field,
            success_marker=login_success_marker,
            max_pages=login_max_pages,
            ci=ci,
        )
        return

    if not _llm_key_present():
        # Check saved preference first
        saved = _load_provider_choice()
        if saved == "skip":
            os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "skip"
        elif saved == "ollama":
            os.environ["PENTEST_TOOLS_LLM_PROVIDER"] = "ollama"
        else:
            # First-run prompt (or non-interactive: silent default to deterministic)
            _prompt_for_llm_provider()

    console.print(
        Panel.fit(
            f"[bold green]pentest-tools v{_pttools_version()}[/bold green]\n"
            f"Target: [cyan]{single}[/cyan]\n"
            f"Scope: [yellow]{scope}[/yellow]\n"
            f"Intensity: [yellow]{intensity}[/yellow]",
            title="Starting Engagement",
        )
    )

    import asyncio as _asyncio

    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator

    async def _run_engagement() -> dict:
        db = FindingsDB()
        try:
            # Reconcile any stale "running" engagements left over from crashes.
            await db.reconcile_stale_engagements()
            engagement = await db.create_engagement(
                target=single,
                scope=scope,
                intensity=intensity,
            )
            orch = AgentOrchestrator(db=db)
            await orch.start_engagement(engagement)
            if orch.workflow_plan:
                logging.getLogger("pentest-tools.cli").info("workflow plan: %s", orch.workflow_plan.summary())
            summary = await db.get_engagement_summary(engagement["id"])
            findings = await db.get_findings(engagement_id=engagement["id"])
            chains = await db.get_attack_chains(engagement["id"])
            stage_records = await db.get_stage_records(engagement["id"])
            phase_errors = orch.phase_errors
            workflow_plan = orch.workflow_plan
            return {
                "engagement": engagement,
                "summary": summary,
                "findings": findings,
                "chains": chains,
                "phase_errors": phase_errors,
                "stage_records": stage_records,
                "workflow_plan": workflow_plan.summary() if workflow_plan else None,
            }
        finally:
            await db.close()
            # The tool-result cache opens its own aiosqlite connection (separate
            # from FindingsDB). Its background worker thread keeps the process
            # alive until the connection is closed, which previously caused
            # pttools to hang for minutes after "Engagement complete" before exit.
            from tools.registry import SecurityTool
            cache = SecurityTool._cache
            if cache is not None and hasattr(cache, "close"):
                try:
                    await cache.close()
                except Exception as e:  # noqa: BLE001
                    logging.getLogger("pentest-tools.cli").warning("cache close failed: %s", e)
                SecurityTool._cache = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"[green]Scanning {single}...", total=None)
        result = _asyncio.run(_run_engagement())

    engagement = result["engagement"]
    summary = result["summary"]
    findings_list = result.get("findings", []) or []
    chains_list = result.get("chains", []) or []
    phase_errors = result.get("phase_errors", {}) or {}
    sev = summary.get("by_severity", {})
    workflow_plan = result.get("workflow_plan")
    stage_records = result.get("stage_records", []) or []

    if ci:
        _ci_print(
            "engagement_complete" if not phase_errors else "engagement_partial",
            {
                "engagement_id": engagement["id"],
                "target": single,
                "total_findings": summary.get("total_findings", 0),
                "by_severity": sev,
                "phase_errors": phase_errors,
            },
        )
        _maybe_sync_to_cloud(engagement, summary, findings_list, chains_list, skip=no_sync, ci=True)
        return

    sev_line = "  ".join(
        f"[{'red' if s == 'critical' else 'yellow' if s == 'high' else 'blue' if s == 'medium' else 'dim'}]"
        f"{s.upper()}: {c}[/]"
        for s, c in sev.items()
    )
    if phase_errors:
        title_line = "[bold yellow]Engagement complete with phase failures[/bold yellow]"
        errors_line = "\nFailed phases: " + ", ".join(sorted(phase_errors.keys()))
    else:
        title_line = "[bold green]Engagement complete[/bold green]"
        errors_line = ""
    workflow_line = f"Workflow: [dim]{workflow_plan}[/dim]\n" if workflow_plan else ""
    stage_line = f"Stages recorded: {len(stage_records)}\n" if stage_records else ""
    console.print(
        Panel.fit(
            f"{title_line}\n"
            f"ID: [cyan]{engagement['id']}[/cyan]\n"
            f"{workflow_line}"
            f"{stage_line}"
            f"Findings: {summary.get('total_findings', 0)}  {sev_line}{errors_line}\n"
            f"Next: [dim]pttools findings {engagement['id']}[/dim] or "
            f"[dim]pttools report {engagement['id']}[/dim]",
            title="Done",
        )
    )

    _maybe_sync_to_cloud(engagement, summary, findings_list, chains_list, skip=no_sync, ci=False)


def _start_campaign_run(targets: list[str], scope: str, intensity: str, ci: bool) -> None:
    """Create a campaign with one engagement per target. Does not auto-run scans."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _create() -> dict:
        db = FindingsDB()
        try:
            campaign_id = await db.create_campaign(
                name=f"Campaign ({len(targets)} targets)",
                targets=targets,
            )
            engagement_ids: list[str] = []
            for t in targets:
                eng = await db.create_engagement(
                    target=t,
                    scope=scope,
                    intensity=intensity,
                    campaign_id=campaign_id,
                )
                engagement_ids.append(eng["id"])
            return {"campaign_id": campaign_id, "engagement_ids": engagement_ids}
        finally:
            await db.close()

    result = asyncio.run(_create())

    if ci:
        _ci_print("campaign_created", {
            "campaign_id": result["campaign_id"],
            "targets": len(targets),
            "engagement_ids": result["engagement_ids"],
        })
        return

    console.print(
        Panel.fit(
            f"[bold green]Campaign created[/bold green]\n"
            f"ID: [cyan]{result['campaign_id']}[/cyan]\n"
            f"Targets: [yellow]{len(targets)}[/yellow]\n"
            f"Scope: [yellow]{scope}[/yellow]  Intensity: [yellow]{intensity}[/yellow]\n\n"
            f"Run via MCP: call start_campaign or step through engagements.\n"
            f"Inspect: [dim]pttools campaign {result['campaign_id']}[/dim]",
            title="Multi-Target Campaign",
        )
    )


def _run_authenticated_scan_cli(
    *,
    target: str,
    login_url: str,
    login_user: str,
    login_password_env: str,
    username_field: str,
    password_field: str,
    success_marker: str,
    max_pages: int,
    ci: bool,
    resolved_password: str | None = None,
) -> None:
    """Deterministic authenticated scan: log in, crawl, probe SQLi/XSS/cmdi.

    Stores findings in a fresh engagement. No LLM key required.

    The password can be supplied two ways:
    - Legacy: `login_password_env` env var name; we read os.environ here.
    - Profile: caller passes `resolved_password` after resolving via the
      profile manager. This is how --auth-profile works.
    """
    import asyncio as _asyncio

    from engine.auth_session import AuthError, WebAuthenticator
    from engine.authenticated_scan import run_authenticated_scan
    from engine.exec_context import exec_context
    from engine.findings_db import FindingsDB

    if not login_user:
        console.print("[red]--login-user is required with --login-url.[/red]")
        raise typer.Exit(2)

    if resolved_password is not None:
        password = resolved_password
    else:
        if not login_password_env:
            console.print(
                "[red]--login-password-env is required with --login-url[/red] "
                "(set e.g. [cyan]export DVWA_PASS=password[/cyan] and pass [cyan]--login-password-env DVWA_PASS[/cyan])."
            )
            raise typer.Exit(2)
        password = os.environ.get(login_password_env, "")
        if not password:
            console.print(f"[red]env var {login_password_env} is empty; set it before running.[/red]")
            raise typer.Exit(2)

    authenticator = WebAuthenticator(
        flow="form_post",
        login_url=login_url,
        username=login_user,
        password=password,
        username_field=username_field,
        password_field=password_field,
        success_marker=success_marker,
    )

    async def _run() -> dict:
        db = FindingsDB()
        try:
            engagement = await db.create_engagement(
                target=target, scope="web", intensity="normal"
            )
            with exec_context(engagement["id"], db):
                result = await run_authenticated_scan(
                    target=target,
                    authenticator=authenticator,
                    max_pages=max_pages,
                )
                for f in result.get("findings", []):
                    f["engagement_id"] = engagement["id"]
                    await db.add_finding(f)
                summary = await db.get_engagement_summary(engagement["id"])
            return {"engagement": engagement, "result": result, "summary": summary}
        finally:
            await db.close()

    if not ci:
        console.print(
            Panel.fit(
                f"[bold green]pentest-tools v{_pttools_version()}[/bold green]\n"
                f"Target: [cyan]{target}[/cyan]\n"
                f"Mode: [yellow]authenticated scan (deterministic, no LLM)[/yellow]\n"
                f"Login: [cyan]{login_url}[/cyan] as [cyan]{login_user}[/cyan]",
                title="Starting Authenticated Scan",
            )
        )

    try:
        payload = _asyncio.run(_run())
    except AuthError as e:
        console.print(f"[red]Login failed:[/red] {e}")
        raise typer.Exit(2) from e

    engagement = payload["engagement"]
    result = payload["result"]
    summary = payload["summary"]
    sev = summary.get("by_severity", {})

    if ci:
        _ci_print(
            "engagement_complete",
            {
                "engagement_id": engagement["id"],
                "target": target,
                "endpoints_tested": result.get("endpoints_tested", 0),
                "total_findings": result.get("findings_count", 0),
                "by_severity": sev,
            },
        )
        return

    sev_line = "  ".join(
        f"[{'red' if s == 'critical' else 'yellow' if s == 'high' else 'blue' if s == 'medium' else 'dim'}]"
        f"{s.upper()}: {c}[/]"
        for s, c in sev.items()
    )
    console.print(
        Panel.fit(
            f"[bold green]Authenticated scan complete[/bold green]\n"
            f"ID: [cyan]{engagement['id']}[/cyan]\n"
            f"Endpoints tested: {result.get('endpoints_tested', 0)}\n"
            f"Findings: {result.get('findings_count', 0)}  {sev_line}\n"
            f"Next: [dim]pttools findings {engagement['id']}[/dim]",
            title="Done",
        )
    )


@app.command()
def mcp(
    transport: str = typer.Option("stdio", "--transport", help="MCP transport: stdio, sse"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host for sse transport"),
    port: int = typer.Option(8765, "--port", help="Bind port for sse transport"),
) -> None:
    """Run the pentest-tools MCP server.

    Point any MCP-compatible client (Claude Code, Claude Desktop, Cursor,
    VS Code Copilot, Windsurf) at this command to expose pentest-tools's tools
    to your AI assistant.

    Quick registration with Claude Code:

        claude mcp add pentest-tools -- pttools mcp

    Or run `pttools setup --mcp` for an interactive wizard that configures
    Claude Desktop, Cursor, and VS Code automatically.
    """
    from mcp_server.server import run_server

    run_server(transport=transport, host=host, port=port)


@app.command()
def menu() -> None:
    """Interactive numbered menu for users without Claude Code or another LLM.

    Categories of tools, search, tag filter, and a simple keyword-based
    recommendation engine. Hackingtool-style approach: lower the barrier
    for first-time users so they can browse what pentest-tools drives without
    setting up an LLM client first.

    No execution from this menu. Selecting a tool prints the command to
    run, with placeholders. Real engagements still go through `pttools start`
    with full scope confirmation.
    """
    from cli.menu import run as run_menu

    raise typer.Exit(code=run_menu())


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host for the HTTP API"),
    port: int = typer.Option(8888, "--port", help="Bind port for the HTTP API"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change (dev only)"),
) -> None:
    """Run the pentest-tools HTTP REST API.

    Exposes engagements, findings, attack chains, detection rules, and
    SARIF export over a FastAPI surface. Read endpoints are open. Write
    endpoints (engagement create, abort) require Authorization: Bearer
    <token> matching the PENTEST_TOOLS_API_TOKEN env var.

    For non-MCP clients, web dashboards, and CI integrations.

    Install: pip install pttools[api]
    """
    try:
        import uvicorn  # type: ignore[import-not-found]
    except ImportError:
        typer.echo("HTTP API requires the [api] extra. Install with: pip install pttools[api]", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"pentest-tools API: http://{host}:{port}")
    typer.echo(f"  docs:    http://{host}:{port}/docs")
    typer.echo(f"  health:  http://{host}:{port}/health")
    if not os.getenv("PENTEST_TOOLS_API_TOKEN"):
        typer.echo(
            "  note: PENTEST_TOOLS_API_TOKEN not set; engagement create/abort endpoints will return 503",
            err=True,
        )
    uvicorn.run("api.server:app", host=host, port=port, reload=reload)


@app.command(name="list")
def list_engagements(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of engagements to show"),
    status_filter: str | None = typer.Option(None, "--status", help="Filter by status"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """List all pentest engagements."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            return await db.list_engagements(limit=limit, status_filter=status_filter)
        finally:
            await db.close()

    engagements = asyncio.run(_fetch())

    if ci:
        print(json.dumps(engagements, default=str))
        return

    if not engagements:
        console.print("[dim]No engagements found.[/dim]")
        return

    table = Table(title=f"Engagements ({len(engagements)})")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Scope")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Started")

    status_colors = {"running": "yellow", "completed": "green", "failed": "red", "paused": "dim"}

    for eng in engagements:
        eng_status = eng.get("status", "unknown")
        color = status_colors.get(eng_status, "dim")
        sev = eng.get("by_severity", {})
        finding_str = str(eng.get("total_findings", 0))
        if sev.get("critical"):
            finding_str += f" [red]({sev['critical']}C)[/red]"
        if sev.get("high"):
            finding_str += f" [yellow]({sev['high']}H)[/yellow]"
        table.add_row(
            eng["id"],
            eng.get("target", ""),
            eng.get("scope", ""),
            f"[{color}]{eng_status}[/{color}]",
            finding_str,
            eng.get("created_at", "")[:19],
        )

    console.print(table)


@app.command()
def resume(
    engagement_id: str = typer.Argument(..., help="Engagement ID to resume"),
):
    """Resume an interrupted engagement from its last checkpoint."""
    import asyncio

    from engine.findings_db import FindingsDB
    from engine.orchestrator import AgentOrchestrator

    async def _resume():
        db = FindingsDB()
        try:
            eng = await db.get_engagement(engagement_id)
            if not eng:
                return None, None, "not_found"
            if eng.get("status") == "completed":
                return eng, None, "already_completed"
            checkpoint = await db.get_checkpoint(engagement_id)
            orch = AgentOrchestrator(db=db)
            await orch.resume_engagement(eng)
            return eng, checkpoint, "resumed"
        finally:
            await db.close()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"[green]Resuming engagement {engagement_id}...", total=None)
        eng, checkpoint, state = asyncio.run(_resume())

    if state == "not_found":
        console.print(f"[red]Engagement not found: {engagement_id}[/red]")
        raise typer.Exit(1)
    if state == "already_completed":
        console.print(
            f"[yellow]Engagement {engagement_id} is already completed; nothing to resume.[/yellow]\n"
            f"[dim]Use [cyan]pttools retest {engagement_id}[/cyan] to re-run the same target/scope, "
            f"or [cyan]pttools status {engagement_id}[/cyan] to view results.[/dim]"
        )
        return
    console.print(f"[green]Engagement {engagement_id} resumed.[/green]")


# ============================================================================
# AUTH — link the CLI to an app.pentest-tools.local workspace for findings sync.
# pentest-tools works fully locally without this; auth is opt-in.
# ============================================================================
auth_app = typer.Typer(
    name="auth",
    help="Link the CLI to your pentest-tools dashboard (optional · Pro/Team/Enterprise)",
    no_args_is_help=True,
)
app.add_typer(auth_app, name="auth")


def _auth_status_panel() -> None:
    from cli.auth import CREDENTIALS_FILE, ENV_VAR_NAME, api_base, key_source, load_api_key, mask_key
    key = load_api_key()
    if not key:
        console.print(
            "[dim]Not linked to any dashboard.[/dim] "
            "[cyan]pentest-tools auth login[/cyan] to connect one.\n"
            "All CLI features run fully offline without a dashboard."
        )
        return
    src = key_source()
    src_line = {
        "env":  f"[cyan]{ENV_VAR_NAME}[/cyan] environment variable",
        "file": f"[cyan]{CREDENTIALS_FILE}[/cyan] (0600)",
    }.get(src or "", "(unknown)")
    console.print(
        Panel.fit(
            f"Key:    [green]{mask_key(key)}[/green]\n"
            f"Source: {src_line}\n"
            f"Host:   [cyan]{api_base()}[/cyan]",
            title="Dashboard link",
            border_style="green",
        )
    )


@auth_app.command("login")
def auth_login(
    api_key: str | None = typer.Argument(
        None,
        help="API key from app.pentest-tools.local (leave blank to be prompted securely)",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Skip the remote validation round-trip (store the key blindly).",
    ),
):
    """Link this CLI to your dashboard workspace.

    Get a key at https://app.pentest-tools.local/dashboard → API Keys → Generate.
    If no key is passed as an argument, you'll be prompted (hidden input).
    """
    from cli.auth import api_base, store_api_key, validate_key_remote

    if not api_key:
        api_key = typer.prompt("API key (pasted, hidden)", hide_input=True).strip()

    if not api_key.startswith("pttools_"):
        console.print("[red]Key must start with [bold]pttools_[/bold][/red]")
        raise typer.Exit(1)

    if no_verify:
        store_api_key(api_key)
        console.print("[yellow]Stored key without remote validation.[/yellow]")
        _auth_status_panel()
        return

    console.print("[dim]Validating against[/dim] " + api_base())
    result = validate_key_remote(api_key)
    if not result:
        console.print(
            "[red]Key rejected.[/red] Check that you pasted the full key and that "
            "your dashboard user still has access to this key."
        )
        raise typer.Exit(1)

    store_api_key(api_key)
    plan = str(result.get("plan", "")).upper() or "LINKED"
    console.print(
        Panel.fit(
            f"Plan:  [bold green]{plan}[/bold green]\n"
            f"Org:   [cyan]{result.get('organization_id', '—')}[/cyan]\n"
            "Your future scans will auto-sync findings to the dashboard.",
            title="Linked to pentest-tools",
            border_style="green",
        )
    )


@auth_app.command("status")
def auth_status_cmd():
    """Show current dashboard link."""
    _auth_status_panel()


@auth_app.command("whoami")
def auth_whoami():
    """Re-validate the current key and show the workspace it belongs to."""
    from cli.auth import load_api_key, mask_key, validate_key_remote
    key = load_api_key()
    if not key:
        console.print("[dim]Not linked.[/dim] Run [cyan]pentest-tools auth login[/cyan] first.")
        raise typer.Exit(1)
    result = validate_key_remote(key)
    if not result:
        console.print(
            "[red]Key is no longer valid.[/red] It may have been revoked in the dashboard. "
            "Run [cyan]pentest-tools auth logout[/cyan] then [cyan]auth login[/cyan] with a fresh key."
        )
        raise typer.Exit(1)
    console.print(
        Panel.fit(
            f"Key:   [green]{mask_key(key)}[/green]\n"
            f"Plan:  [bold green]{str(result.get('plan', '')).upper()}[/bold green]\n"
            f"Org:   [cyan]{result.get('organization_id', '—')}[/cyan]\n"
            f"Features: {', '.join(result.get('features', [])) or '(free tier)'}",
            title="Workspace",
            border_style="green",
        )
    )


@auth_app.command("logout")
def auth_logout(
    confirm: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the confirmation prompt.",
    ),
):
    """Remove the stored API key from this machine."""
    from cli.auth import CREDENTIALS_FILE, ENV_VAR_NAME, key_source, remove_credentials

    src = key_source()
    if src is None:
        console.print("[dim]No stored key — nothing to remove.[/dim]")
        return

    if src == "env":
        console.print(
            f"[yellow]Your key lives in the [cyan]{ENV_VAR_NAME}[/cyan] env var, "
            "not in a file. Unset it in your shell instead:[/yellow]\n"
            f"  [dim]unset {ENV_VAR_NAME}[/dim]"
        )
        return

    if not confirm and not typer.confirm(f"Remove {CREDENTIALS_FILE}?"):
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)

    remove_credentials()
    console.print("[green]Unlinked from dashboard.[/green] All local features still work.")


# ============================================================================
# AUTH PROFILE — named sets of authentication parameters for target engagements.
# Profiles store credential REFERENCES (env var names, vault paths, op:// URIs);
# never the credential values themselves. See cli/auth_profiles.py.
# ============================================================================
profile_app = typer.Typer(
    name="profile",
    help="Manage named auth profiles for target engagements.",
    no_args_is_help=True,
)
auth_app.add_typer(profile_app, name="profile")


def _format_profile_row(p, active: str) -> tuple[str, ...]:
    indicator = "●" if p.name == active else " "
    if p.password_source:
        ref_disp = f"${p.password_ref}" if p.password_source == "env" else p.password_ref
        source_label = p.password_source
    elif p.token_source:
        ref_disp = f"${p.token_ref}" if p.token_source == "env" else p.token_ref
        source_label = f"{p.token_source} (token)"
    else:
        ref_disp = "(none)"
        source_label = "(none)"
    return (indicator, p.name, p.flow, source_label, ref_disp)


@profile_app.command("add")
def profile_add(
    name: str = typer.Argument(..., help="Profile name (e.g. staging-acme)"),
    flow: str = typer.Option("", "--flow", help="Auth flow: form_post|basic|bearer|ntlm|oauth_password"),
    login_url: str = typer.Option("", "--login-url"),
    username: str = typer.Option("", "--username"),
    domain: str = typer.Option("", "--domain", help="NTLM domain"),
    success_marker: str = typer.Option("", "--success-marker"),
    target_pattern: str = typer.Option("", "--target-pattern"),
    password_source: str = typer.Option("", "--password-source", help="env|op|vault|aws-sm"),
    password_ref: str = typer.Option("", "--password-ref", help="Reference (env var name / op:// URI / vault path / AWS ARN)"),
    token_source: str = typer.Option("", "--token-source", help="env|op|vault|aws-sm (for bearer flows)"),
    token_ref: str = typer.Option("", "--token-ref"),
):
    """Add a new auth profile.

    All flags are optional — runs an interactive wizard if you skip them.
    Credential VALUES are never stored on disk, only references.
    """
    from cli.auth_profiles import (
        VALID_FLOWS,
        VALID_SOURCES,
        AuthProfile,
        ProfileError,
        add_profile,
    )

    if not flow:
        flow = typer.prompt(f"Auth flow ({'/'.join(sorted(VALID_FLOWS))})", default="form_post")
    if flow not in VALID_FLOWS:
        console.print(f"[red]Invalid flow {flow!r}. Must be one of {sorted(VALID_FLOWS)}.[/red]")
        raise typer.Exit(1)

    if flow in ("form_post", "oauth_password") and not login_url:
        login_url = typer.prompt("Login URL")

    if flow != "bearer" and not username:
        username = typer.prompt("Username")

    if flow == "ntlm" and not domain:
        domain = typer.prompt("NTLM domain")

    # Decide credential source
    if flow == "bearer":
        if not token_source:
            token_source = typer.prompt(
                f"Token source ({'/'.join(sorted(VALID_SOURCES))})", default="env"
            )
        if token_source not in VALID_SOURCES:
            console.print(f"[red]Invalid token_source {token_source!r}.[/red]")
            raise typer.Exit(1)
        if not token_ref:
            token_ref = typer.prompt("Token reference (env var / op:// URI / vault path / ARN)")
    else:
        if not password_source:
            password_source = typer.prompt(
                f"Password source ({'/'.join(sorted(VALID_SOURCES))})", default="env"
            )
        if password_source not in VALID_SOURCES:
            console.print(f"[red]Invalid password_source {password_source!r}.[/red]")
            raise typer.Exit(1)
        if not password_ref:
            password_ref = typer.prompt(
                "Password reference (env var name / op:// URI / vault path / ARN)"
            )

    profile = AuthProfile(
        name=name,
        flow=flow,
        username=username,
        login_url=login_url,
        success_marker=success_marker,
        domain=domain,
        target_pattern=target_pattern,
        password_source=password_source,
        password_ref=password_ref,
        token_source=token_source,
        token_ref=token_ref,
    )
    try:
        add_profile(profile)
    except ProfileError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Saved profile {name!r}.[/green]")
    console.print(
        "[dim]Reminder: ~/.pentest-tools/auth-profiles.yaml stores references only "
        "(no credential values). Add it to .gitignore if you have one.[/dim]"
    )


@profile_app.command("list")
def profile_list():
    """List all auth profiles. Never shows credential values."""
    from rich.table import Table

    from cli.auth_profiles import get_active_name, list_profiles

    profiles = list_profiles()
    if not profiles:
        console.print("[dim]No profiles yet.[/dim] Add one: pentest-tools auth profile add <name>")
        return
    active = get_active_name()
    table = Table(show_header=True, header_style="bold")
    table.add_column("", width=2)
    table.add_column("NAME")
    table.add_column("FLOW")
    table.add_column("SOURCE")
    table.add_column("REFERENCE")
    for p in profiles:
        table.add_row(*_format_profile_row(p, active))
    console.print(table)
    if active:
        console.print(f"[dim]● = active profile ({active})[/dim]")


@profile_app.command("show")
def profile_show(name: str = typer.Argument(..., help="Profile name")):
    """Show details of one profile. Credential values are never shown."""
    from cli.auth_profiles import ProfileError, get_active_name, get_profile

    try:
        p = get_profile(name)
    except ProfileError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    active = get_active_name()
    is_active = "(active)" if p.name == active else ""

    body_lines = [
        f"Flow: [cyan]{p.flow}[/cyan]",
    ]
    if p.username:
        body_lines.append(f"Username: [cyan]{p.username}[/cyan]")
    if p.domain:
        body_lines.append(f"Domain: [cyan]{p.domain}[/cyan]")
    if p.login_url:
        body_lines.append(f"Login URL: [cyan]{p.login_url}[/cyan]")
    if p.success_marker:
        body_lines.append(f"Success marker: [cyan]{p.success_marker}[/cyan]")
    if p.target_pattern:
        body_lines.append(f"Target pattern: [cyan]{p.target_pattern}[/cyan]")
    if p.password_source:
        ref_disp = f"${p.password_ref}" if p.password_source == "env" else p.password_ref
        body_lines.append(f"Password: from [cyan]{p.password_source}[/cyan] → [cyan]{ref_disp}[/cyan]")
    if p.token_source:
        ref_disp = f"${p.token_ref}" if p.token_source == "env" else p.token_ref
        body_lines.append(f"Token: from [cyan]{p.token_source}[/cyan] → [cyan]{ref_disp}[/cyan]")

    console.print(
        Panel.fit(
            "\n".join(body_lines),
            title=f"Profile: {p.name} {is_active}",
            border_style="green",
        )
    )


@profile_app.command("remove")
def profile_remove(
    name: str = typer.Argument(..., help="Profile name"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
):
    """Remove a profile. Does not touch the underlying credential source."""
    from cli.auth_profiles import ProfileError, get_profile, remove_profile

    try:
        get_profile(name)
    except ProfileError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    if not confirm and not typer.confirm(f"Remove profile {name!r}?"):
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)
    remove_profile(name)
    console.print(f"[green]Removed profile {name!r}.[/green]")


@profile_app.command("use")
def profile_use(name: str = typer.Argument(..., help="Profile name to activate")):
    """Set the active profile. Used as default when --auth-profile is omitted."""
    from cli.auth_profiles import ProfileError, set_active

    try:
        set_active(name)
    except ProfileError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Active profile: {name}[/green]")


@profile_app.command("current")
def profile_current():
    """Show the currently active profile name."""
    from cli.auth_profiles import get_active_name

    active = get_active_name()
    if active:
        console.print(active)
    else:
        console.print("[dim]No active profile.[/dim]")
        raise typer.Exit(1)


@profile_app.command("import-from-flags")
def profile_import_from_flags(
    name: str = typer.Option(..., "--name", help="Profile name to create"),
    login_url: str = typer.Option(..., "--login-url"),
    login_user: str = typer.Option(..., "--login-user"),
    login_password_env: str = typer.Option(
        ..., "--login-password-env",
        help="Env var name holding the password (e.g. DVWA_PASS)",
    ),
    login_username_field: str = typer.Option("username", "--login-username-field"),
    login_password_field: str = typer.Option("password", "--login-password-field"),
    login_success_marker: str = typer.Option("", "--login-success-marker"),
    target_pattern: str = typer.Option("", "--target-pattern", help="Optional glob (hint only)"),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Print what would be saved instead of writing the profile.",
    ),
):
    """Migrate from legacy --login-* flags to a named profile.

    Take the same flags you used with `pentest-tools start`, change `start` to
    `auth profile import-from-flags --name <name>`, and you get a profile.

    Example:
      Old: pttools start https://staging --login-url /login --login-user admin --login-password-env DVWA_PASS
      New: pttools auth profile import-from-flags --name staging \\
              --login-url https://staging/login --login-user admin \\
              --login-password-env DVWA_PASS
           pttools start https://staging --auth-profile staging
    """
    from cli.auth_profiles import AuthProfile, ProfileError, add_profile

    profile = AuthProfile(
        name=name,
        flow="form_post",
        login_url=login_url,
        username=login_user,
        username_field=login_username_field,
        password_field=login_password_field,
        success_marker=login_success_marker,
        target_pattern=target_pattern,
        password_source="env",
        password_ref=login_password_env,
    )

    if dry_run:
        import yaml as _yaml
        from rich.syntax import Syntax

        body = _yaml.safe_dump({"profiles": {name: profile.to_dict()}}, sort_keys=False)
        console.print(Panel.fit(Syntax(body, "yaml"), title=f"Would save profile {name!r}"))
        console.print(
            f"[dim]Run without --dry-run to save. Verify env var: echo ${login_password_env}[/dim]"
        )
        return

    try:
        add_profile(profile)
    except ProfileError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]Imported profile {name!r}.[/green]\n"
        f"Use it: [cyan]pentest-tools start <target> --auth-profile {name}[/cyan]"
    )


@app.command()
def chain(
    pairs: list[str] = typer.Argument(
        ...,
        help="One or more profile=target pairs (e.g. staging=https://stage.acme.com)",
    ),
):
    """Run multiple authenticated scans in sequence, each with its own auth profile.

    Example:
      pentest-tools chain staging=https://stage.acme.com prod=https://prod.acme.com

    Each profile resolves credentials server-side. Findings are tagged per
    engagement so they never bleed between scans.
    """
    from cli.chain import chain_command

    code = chain_command(pairs)
    raise typer.Exit(code)


@app.command()
def status(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """Check the status of an engagement."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            eng = await db.get_engagement(engagement_id)
            summary = await db.get_engagement_summary(engagement_id)
            checkpoint = await db.get_checkpoint(engagement_id)
            return eng, summary, checkpoint
        finally:
            await db.close()

    eng, summary, checkpoint = asyncio.run(_fetch())

    if not eng:
        if ci:
            _ci_print("not_found", {"engagement_id": engagement_id})
            raise typer.Exit(1)
        console.print(f"[red]Engagement not found: {engagement_id}[/red]")
        raise typer.Exit(1)

    if ci:
        print(json.dumps({"engagement": eng, "summary": summary, "checkpoint": checkpoint}, default=str))
        return

    sev = summary.get("by_severity", {})
    sev_line = "  ".join(
        f"[{'red' if s == 'critical' else 'yellow' if s == 'high' else 'blue' if s == 'medium' else 'dim'}]{s.upper()}: {c}[/]"
        for s, c in sev.items()
    )

    phase_info = ""
    if checkpoint and checkpoint.get("current_phase"):
        completed = checkpoint.get("completed_phases", [])
        phase_info = f"\n[bold]Current Phase:[/bold] {checkpoint['current_phase']}\n[bold]Completed:[/bold] {', '.join(completed) if completed else 'none'}"

    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] [cyan]{eng['target']}[/cyan]\n"
            f"[bold]Status:[/bold] {eng['status']}\n"
            f"[bold]Scope:[/bold] {eng.get('scope', 'full')}\n"
            f"[bold]Started:[/bold] {eng['created_at']}\n"
            f"[bold]Findings:[/bold] {summary['total_findings']}  {sev_line}\n"
            f"[bold]Attack Chains:[/bold] {summary.get('attack_chains', 0)}\n"
            f"[bold]Detection Rules:[/bold] {summary.get('detection_rules', 0)}"
            f"{phase_info}",
            title=f"Engagement {engagement_id}",
        )
    )


@app.command()
def findings(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    severity: str = typer.Option(None, "--severity", "-s", help="Filter by severity (critical, high, medium, low, info)"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """List findings from an engagement."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            return await db.get_findings(engagement_id=engagement_id, severity=severity)
        finally:
            await db.close()

    rows = asyncio.run(_fetch())

    if ci:
        print(json.dumps(rows, default=str))
        return

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    severity_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim", "info": "dim"}
    label = f"Findings for {engagement_id}"
    if severity:
        label += f" [{severity}]"

    table = Table(title=label)
    table.add_column("Severity", style="bold")
    table.add_column("Title", max_width=50)
    table.add_column("CVSS", justify="right")
    table.add_column("Target")
    table.add_column("Category")
    table.add_column("CWE")
    table.add_column("Status")

    for r in rows:
        sev = r.get("severity", "info").lower()
        color = severity_colors.get(sev, "dim")
        cvss = r.get("cvss_score", 0.0)
        cvss_str = f"{cvss:.1f}" if cvss else "-"
        table.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            r.get("title", ""),
            cvss_str,
            r.get("target", ""),
            r.get("category", ""),
            r.get("cwe_id", "") or "-",
            r.get("status", ""),
        )

    console.print(table)


@app.command(name="tool-results")
def tool_results(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max rows to show"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """List tool invocations (stdout, exit code, duration) for an engagement."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            return await db.get_tool_results(engagement_id, limit=limit)
        finally:
            await db.close()

    rows = asyncio.run(_fetch())

    if ci:
        print(json.dumps(rows, default=str))
        return

    if not rows:
        console.print("[dim]No tool_results recorded for this engagement.[/dim]")
        return

    table = Table(title=f"Tool runs for {engagement_id}")
    table.add_column("Time", style="dim")
    table.add_column("Tool", style="bold")
    table.add_column("Target")
    table.add_column("Exit", justify="right")
    table.add_column("Duration", justify="right")

    for r in rows:
        exit_code = r.get("exit_code", 0)
        color = "green" if exit_code == 0 else "red"
        table.add_row(
            str(r.get("created_at", ""))[:19],
            r.get("tool_name", ""),
            r.get("target", ""),
            f"[{color}]{exit_code}[/{color}]",
            f"{r.get('duration', 0.0):.2f}s",
        )

    console.print(table)


@app.command()
def tools(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    source: str = typer.Option(None, "--source", help="Filter by source: builtin, plugin"),
):
    """List available security tools and their install status."""
    from tools.registry import ToolRegistry

    registry = ToolRegistry()
    all_tools = registry.list_tools()

    table = Table(title=f"Security Tools ({len(all_tools)} registered)")
    table.add_column("Tool", style="cyan")
    table.add_column("Category")
    table.add_column("Description", max_width=50)
    table.add_column("Source")
    table.add_column("Installed")

    for tool in sorted(all_tools, key=lambda t: (t.category, t.name)):
        if category and tool.category != category:
            continue
        tool_source = getattr(tool, "source", "builtin")
        if source and tool_source != source:
            continue
        installed = "[green]Yes[/green]" if tool.is_installed() else "[red]No[/red]"
        table.add_row(tool.name, tool.category, tool.description[:50], tool_source, installed)

    console.print(table)


@app.command()
def route(
    target: str = typer.Argument(..., help="Target hostname, URL, IP, CIDR, file path, or cloud resource"),
    intent: str = typer.Option("", "--intent", help="Free-form description of what to test (e.g. 'kerberoast the dc')"),
    json_out: bool = typer.Option(False, "--json", help="Emit raw JSON instead of a formatted line"),
) -> None:
    """Pick the right specialist agent for a target. Heuristic, deterministic, no LLM call.

    Useful as a building block for scripts and as a self-check
    ('which agent would pttools run on this target?'). The same logic is
    available to MCP clients via the select_agent tool.
    """
    import json as _json

    from agents.selection.selection_agent import route_target

    result = route_target(target, intent=intent)
    if json_out:
        console.print(_json.dumps(result, indent=2))
        return
    console.print(
        f"[cyan]agent[/cyan]      {result['agent']}\n"
        f"[cyan]target[/cyan]     {result['target']}\n"
        f"[cyan]reason[/cyan]     {result['reason']}\n"
        f"[cyan]confidence[/cyan] {result['confidence']:.2f}"
    )


@app.command()
def ps() -> None:
    """List running tool subprocesses (pid, tool, target, runtime)."""
    from engine.process_registry import get_default_registry

    records = get_default_registry().list_records()
    if not records:
        console.print("[dim]no running tool processes[/dim]")
        return

    table = Table(title=f"Running tool processes ({len(records)})")
    table.add_column("PID", style="cyan", justify="right")
    table.add_column("Tool")
    table.add_column("Target", max_width=40)
    table.add_column("Runtime", justify="right")
    table.add_column("Engagement")

    for r in sorted(records, key=lambda x: -x.runtime_seconds()):
        runtime = f"{r.runtime_seconds():.1f}s"
        eid_short = (r.engagement_id[:8] + "…") if len(r.engagement_id) > 8 else r.engagement_id
        table.add_row(str(r.pid), r.tool, r.target, runtime, eid_short or "-")
    console.print(table)


@app.command(name="kill")
def kill_pid(
    pid: int = typer.Argument(..., help="Subprocess PID to terminate"),
    grace_seconds: float = typer.Option(2.0, "--grace", help="Seconds to wait between SIGTERM and SIGKILL"),
) -> None:
    """Stop a running tool subprocess by PID. Sends SIGTERM, then SIGKILL after grace."""
    import asyncio

    from engine.process_registry import get_default_registry

    async def _run() -> bool:
        return await get_default_registry().kill(pid, grace_seconds=grace_seconds)

    killed = asyncio.run(_run())
    if killed:
        console.print(f"[green]killed pid={pid}[/green]")
    else:
        console.print(f"[yellow]pid={pid} not found in registry or already exited[/yellow]")
        raise typer.Exit(code=1)


@app.command()
def report(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format: markdown, html, pdf, json, sarif, junit"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path (overrides default)"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """Generate a pentest report."""
    import asyncio
    import os

    from engine.findings_db import FindingsDB

    if format in ("sarif", "junit"):
        async def _export():
            db = FindingsDB()
            try:
                eng = await db.get_engagement(engagement_id)
                if not eng:
                    return None
                findings_list = await db.get_findings(engagement_id=engagement_id)
                return eng, findings_list
            finally:
                await db.close()

        result = asyncio.run(_export())
        if not result:
            console.print(f"[red]Engagement not found: {engagement_id}[/red]")
            raise typer.Exit(1)

        eng, findings_list = result

        if format == "sarif":
            from engine.sarif import findings_to_sarif
            export_data = findings_to_sarif(findings_list, eng)
            out_path = output or f"reports/{engagement_id}.sarif.json"
        else:
            from engine.junit_xml import findings_to_junit
            export_data = findings_to_junit(findings_list, eng)
            out_path = output or f"reports/{engagement_id}.junit.xml"

        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w") as f:
            if isinstance(export_data, dict):
                json.dump(export_data, f, indent=2)
            else:
                f.write(export_data)

        if ci:
            print(json.dumps({"format": format, "path": out_path, "findings": len(findings_list)}))
        else:
            console.print(f"[green]Exported {format.upper()} to:[/green] [cyan]{out_path}[/cyan]")
        return

    from agents.report.report_agent import ReportAgent

    async def _generate():
        db = FindingsDB()
        try:
            eng = await db.get_engagement(engagement_id)
            if not eng:
                return None
            agent = ReportAgent(db=db)
            return await agent.generate_report(engagement_id, format=format)
        finally:
            await db.close()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"[green]Generating {format} report...", total=None)
        result = asyncio.run(_generate())

    if not result:
        console.print(f"[red]Engagement not found: {engagement_id}[/red]")
        raise typer.Exit(1)

    path = output or result.get("output_path", "")

    if ci:
        print(json.dumps({"format": format, "path": path, "findings": result.get("total_findings", 0)}))
    else:
        console.print(
            Panel.fit(
                f"[bold]Format:[/bold] {format}\n"
                f"[bold]Findings:[/bold] {result.get('total_findings', 0)}\n"
                f"[bold]Attack Chains:[/bold] {result.get('attack_chains', 0)}\n"
                f"[bold]Saved to:[/bold] [cyan]{path}[/cyan]",
                title="Report Generated",
            )
        )


@app.command()
def setup(
    tier: str = typer.Option("recommended", "--tier", "-t", help="Install tier: core, recommended, full, skip"),
    list_tools: bool = typer.Option(False, "--list", "-l", help="List tool status without installing"),
    mcp: bool = typer.Option(False, "--mcp", help="Configure MCP clients (Claude Desktop, Cursor, VS Code)"),
    auto_inject: bool = typer.Option(False, "--auto-inject", help="Auto-write MCP config without prompting"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what MCP config changes would be made"),
    plugins: bool = typer.Option(False, "--plugins", help="List installed plugins"),
    init: bool = typer.Option(False, "--init", help="Generate default config file at ~/.pentest-tools/config.yaml"),
    show_config: bool = typer.Option(False, "--show-config", help="Show resolved configuration (secrets masked)"),
):
    """Install external security tools or configure MCP clients.

    Tool tiers control how many tools to install:
      core (~200MB): nmap, nuclei, nikto, sqlmap, whatweb, sslscan
      recommended (~500MB): core + gobuster, ffuf, httpx, subfinder, hydra, etc.
      full (~2GB+): everything including metasploit, aircrack-ng, AD tools
      skip: install nothing, use only built-in scanners

    MCP setup (--mcp) detects installed AI clients and configures them
    to use pentest-tools as an MCP server.
    """
    if init:
        from config.settings import generate_default_config

        path = generate_default_config()
        console.print(f"[green]Config file created:[/green] [cyan]{path}[/cyan]")
        return

    if show_config:
        from config.settings import load_config

        config = load_config()
        console.print_json(data=config.to_dict(mask_secrets=True))
        return

    if mcp:
        from cli.mcp_setup import run_mcp_setup

        run_mcp_setup(auto_inject=auto_inject, dry_run=dry_run)
        return

    if plugins:
        from tools.plugin_loader import load_plugins

        loaded = load_plugins()
        if not loaded:
            console.print("[dim]No plugins found in ~/.pentest-tools/plugins/[/dim]")
            console.print("Create YAML plugin files to extend pentest-tools with custom tools.")
            return

        table = Table(title=f"Installed Plugins ({len(loaded)})")
        table.add_column("Name", style="cyan")
        table.add_column("Category")
        table.add_column("Command")
        table.add_column("Description", max_width=50)

        for p in loaded:
            table.add_row(p["name"], p["category"], p["command"], p["description"][:50])

        console.print(table)
        return

    from engine.tool_installer import (
        InstallTier,
        audit_tools,
        install_tier,
        print_audit,
    )

    if list_tools:
        audit = audit_tools()
        print_audit(audit)
        return

    if tier == "skip":
        console.print("[dim]Skipping tool installation. Built-in scanners are always available.[/dim]")
        return

    tier_map = {"core": InstallTier.CORE, "recommended": InstallTier.RECOMMENDED, "full": InstallTier.FULL}
    if tier not in tier_map:
        console.print(f"[red]Unknown tier: {tier}. Choose: core, recommended, full, skip[/red]")
        raise typer.Exit(1)

    install_tier(tier_map[tier])


@app.command()
def campaign(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """Show summary for a multi-target campaign."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            return await db.get_campaign_summary(campaign_id)
        finally:
            await db.close()

    summary = asyncio.run(_fetch())

    if "error" in summary:
        console.print(f"[red]{summary['error']}[/red]")
        raise typer.Exit(1)

    if ci:
        print(json.dumps(summary, default=str))
        return

    console.print(
        Panel.fit(
            f"[bold]Name:[/bold] {summary['name']}\n"
            f"[bold]Targets:[/bold] {summary['target_count']}\n"
            f"[bold]Total Findings:[/bold] {summary['total_findings']}\n"
            f"[bold]Status:[/bold] {summary['status']}",
            title=f"Campaign {campaign_id}",
        )
    )

    if summary.get("engagements"):
        table = Table(title="Engagements")
        table.add_column("ID", style="cyan")
        table.add_column("Target")
        table.add_column("Status")

        for eng in summary["engagements"]:
            table.add_row(eng["id"], eng.get("target", ""), eng.get("status", ""))

        console.print(table)


@app.command()
def diff(
    prev_id: str = typer.Argument(..., help="Previous engagement ID"),
    curr_id: str = typer.Argument(..., help="Current engagement ID"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """Show new / resolved / unchanged findings between two engagements."""
    import asyncio

    from engine.diff import compute_diff
    from engine.findings_db import FindingsDB

    async def _fetch():
        db = FindingsDB()
        try:
            prev = await db.get_findings(engagement_id=prev_id)
            curr = await db.get_findings(engagement_id=curr_id)
            return prev, curr
        finally:
            await db.close()

    prev, curr = asyncio.run(_fetch())
    diff_result = compute_diff(prev_id, curr_id, prev, curr)

    if ci:
        print(json.dumps(diff_result.to_dict(), default=str))
        return

    console.print(
        Panel.fit(
            f"[bold red]New:[/bold red] {diff_result.total_new}\n"
            f"[bold green]Resolved:[/bold green] {diff_result.total_resolved}\n"
            f"[bold yellow]Unchanged:[/bold yellow] {diff_result.total_unchanged}",
            title=f"Diff {prev_id} → {curr_id}",
        )
    )

    for bucket, color in (("new", "red"), ("resolved", "green"), ("unchanged", "yellow")):
        items = getattr(diff_result, bucket)
        if not items:
            continue
        table = Table(title=f"[{color}]{bucket.title()}[/{color}]")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Target", style="cyan")
        for f in items[:50]:
            table.add_row(f.get("severity", "info"), f.get("title", ""), f.get("target", ""))
        console.print(table)


@app.command()
def retest(
    engagement_id: str = typer.Argument(..., help="Engagement to re-test (clones target/scope/intensity)"),
    ci: bool = typer.Option(False, "--ci", help="JSON output for CI/CD"),
):
    """Create a new engagement linked to an existing one for re-testing."""
    import asyncio

    from engine.findings_db import FindingsDB

    async def _retest():
        db = FindingsDB()
        try:
            prev = await db.get_engagement(engagement_id)
            if not prev:
                return None
            new = await db.create_engagement(
                target=prev["target"],
                scope=prev.get("scope", "full"),
                rules_of_engment=prev.get("rules_of_engment", ""),
                intensity=prev.get("intensity", "normal"),
                parent_engagement_id=engagement_id,
            )
            return new
        finally:
            await db.close()

    result = asyncio.run(_retest())

    if result is None:
        console.print(f"[red]Engagement {engagement_id} not found.[/red]")
        raise typer.Exit(1)

    if ci:
        print(json.dumps(result, default=str))
        return

    console.print(
        Panel.fit(
            f"[bold green]Retest engagement created[/bold green]\n"
            f"ID: [cyan]{result['id']}[/cyan]\n"
            f"Parent: [dim]{engagement_id}[/dim]\n"
            f"Target: [cyan]{result['target']}[/cyan]\n"
            f"Run scans, then: [dim]pttools diff {engagement_id} {result['id']}[/dim]",
            title="Retest",
        )
    )


ci_app = typer.Typer(help="CI/CD integration (SARIF, severity gates, PR comments).")
app.add_typer(ci_app, name="ci")


@ci_app.command("report")
def ci_report(
    engagement_id: str = typer.Argument(..., help="Engagement ID to report on"),
    fail_on: str = typer.Option("high", "--fail-on", help="Gate severity: critical|high|medium|low|info"),
    sarif: str = typer.Option("", "--sarif", help="Write SARIF output to this path"),
    comment: bool = typer.Option(
        False, "--comment", help="Post a PR comment (needs GITHUB_TOKEN + GITHUB_REPOSITORY + PR context)"
    ),
    json_out: bool = typer.Option(True, "--json/--no-json", help="Print JSON summary to stdout"),
):
    """Turn an engagement into a CI gate: SARIF + severity threshold + exit code."""
    import asyncio

    from cli.ci import build_report, post_pr_comment, write_github_output
    from engine.findings_db import FindingsDB

    async def _run():
        db = FindingsDB()
        try:
            engagement = await db.get_engagement(engagement_id)
            if not engagement:
                return None, None
            findings = await db.get_findings(engagement_id=engagement_id)
            report = build_report(
                engagement,
                findings,
                threshold=fail_on,
                sarif_output=sarif or None,
            )
            posted = False
            if comment:
                posted = await post_pr_comment(report)
            return report, posted
        finally:
            await db.close()

    report, posted = asyncio.run(_run())

    if report is None:
        console.print(f"[red]Engagement {engagement_id} not found.[/red]")
        raise typer.Exit(2)

    write_github_output(report)

    if json_out:
        print(json.dumps({**report.to_dict(), "pr_comment_posted": posted}, default=str))

    raise typer.Exit(report.exit_code)


webauth_app = typer.Typer(help="Authenticated/stateful scanning helpers.")
app.add_typer(webauth_app, name="webauth")


@webauth_app.command("login")
def webauth_login(
    flow: str = typer.Option(..., "--flow", help="Flow type: form_post, bearer_static"),
    login_url: str = typer.Option("", "--login-url", help="Login endpoint (form_post)"),
    username: str = typer.Option("", "--username", help="Username (form_post)"),
    password_env: str = typer.Option(
        "", "--password-env", help="Environment variable holding the password"
    ),
    username_field: str = typer.Option("username", "--username-field"),
    password_field: str = typer.Option("password", "--password-field"),
    success_marker: str = typer.Option(
        "", "--success-marker", help="Substring that must appear in the login response body"
    ),
    bearer_token_env: str = typer.Option(
        "", "--bearer-token-env", help="Env var holding the static bearer token"
    ),
    ci: bool = typer.Option(False, "--ci"),
):
    """Perform an auth flow and print the resulting session credentials."""
    import asyncio
    import os

    from engine.auth_session import AuthError, WebAuthenticator

    password = os.environ.get(password_env, "") if password_env else ""
    bearer = os.environ.get(bearer_token_env, "") if bearer_token_env else ""

    auth = WebAuthenticator(
        flow=flow,
        login_url=login_url,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        success_marker=success_marker,
        bearer_token=bearer,
    )

    try:
        session = asyncio.run(auth.login())
    except AuthError as e:
        console.print(f"[red]Auth failed:[/red] {e}")
        raise typer.Exit(1) from e

    if ci:
        print(json.dumps(session.to_dict(), default=str))
        return

    cookie_str = session.cookie_string() or "(none)"
    console.print(
        Panel.fit(
            f"[bold green]Authenticated[/bold green] via {session.flow}\n"
            f"Cookies: [cyan]{cookie_str}[/cyan]\n"
            f"Bearer: [cyan]{'set' if session.bearer_token else 'none'}[/cyan]\n"
            f"Expires in: [yellow]"
            f"{int((session.expires_at or 0) - session.created_at)}s[/yellow]",
            title="Auth Session",
        )
    )


cache_app = typer.Typer(help="Inspect or manage the tool-result cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("stats")
def cache_stats():
    """Show cache size, live entries, and per-tool breakdown."""
    import asyncio

    from engine.cache import ToolResultCache

    async def _run():
        c = ToolResultCache()
        try:
            return await c.stats()
        finally:
            await c.close()

    s = asyncio.run(_run())
    console.print(
        Panel.fit(
            f"[bold]DB:[/bold] {s['db_path']}\n"
            f"[bold]Size:[/bold] {s['db_size_bytes']:,} bytes\n"
            f"[bold]Live entries:[/bold] {s['live_entries']}\n"
            f"[bold]Expired entries:[/bold] {s['expired_entries']}",
            title="Cache Stats",
        )
    )
    if s["by_tool"]:
        table = Table(title="Live entries by tool")
        table.add_column("Tool", style="cyan")
        table.add_column("Count", justify="right")
        for tool, n in s["by_tool"]:
            table.add_row(tool, str(n))
        console.print(table)


@cache_app.command("clear")
def cache_clear():
    """Drop every cached entry."""
    import asyncio

    from engine.cache import ToolResultCache

    async def _run():
        c = ToolResultCache()
        try:
            return await c.clear()
        finally:
            await c.close()

    removed = asyncio.run(_run())
    console.print(f"[green]Cleared {removed} cache entr{'y' if removed == 1 else 'ies'}.[/green]")


@cache_app.command("expire")
def cache_expire():
    """Drop only expired entries."""
    import asyncio

    from engine.cache import ToolResultCache

    async def _run():
        c = ToolResultCache()
        try:
            return await c.expire()
        finally:
            await c.close()

    removed = asyncio.run(_run())
    console.print(f"[green]Removed {removed} expired entr{'y' if removed == 1 else 'ies'}.[/green]")


llm_app = typer.Typer(help="LLM red-team probes (OWASP LLM Top 10).")
app.add_typer(llm_app, name="llm-redteam")


@llm_app.command("run")
def llm_redteam_run(
    target: str = typer.Argument(..., help="LLM endpoint URL"),
    engagement_id: str = typer.Option("", "--engagement-id", help="Engagement to record findings against"),
    schema: str = typer.Option("openai", "--schema", help="openai|simple|custom"),
    model: str = typer.Option("gpt-3.5-turbo", "--model"),
    header: list[str] = typer.Option([], "--header", "-H", help="Extra header; repeatable (e.g. 'Authorization: Bearer x')"),
    concurrency: int = typer.Option(4, "--concurrency"),
    corpus: str = typer.Option("", "--corpus", help="Custom YAML corpus path"),
    json_out: bool = typer.Option(False, "--json"),
):
    """Run the LLM red-team probe corpus against an LLM target."""
    import asyncio

    from agents.llm_redteam import LLMRedTeamAgent, LLMTargetAdapter
    from engine.findings_db import FindingsDB

    headers = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    adapter = LLMTargetAdapter(url=target, schema=schema, model=model, headers=headers)

    async def _run():
        db = None
        if engagement_id:
            db = FindingsDB()
        try:
            agent = LLMRedTeamAgent(adapter=adapter, db=db, corpus_path=corpus or None, concurrency=concurrency)
            return await agent.run(engagement_id=engagement_id)
        finally:
            if db:
                await db.close()

    report = asyncio.run(_run())

    if json_out:
        print(json.dumps(report.to_dict(), default=str))
    else:
        console.print(
            Panel.fit(
                f"[bold]LLM Red-Team[/bold]\n"
                f"Target: [cyan]{report.target}[/cyan]\n"
                f"Probes run: [yellow]{report.total}[/yellow]\n"
                f"Findings fired: [red]{report.fired}[/red]\n"
                f"Recorded: [green]{report.findings_recorded}[/green]",
                title="LLM Red-Team Report",
            )
        )
        for r in report.results:
            if r.fired:
                console.print(f"[red]✗[/red] {r.probe_id} ({r.category}, {r.severity}) — matched: {r.matched}")


playbook_app = typer.Typer(help="Manage and run YAML playbooks (methodology-as-code).")
app.add_typer(playbook_app, name="playbook")


@playbook_app.command("list")
def playbook_list():
    """List all discoverable playbooks (builtin + user)."""
    from engine.playbook import discover_playbooks

    pbs = discover_playbooks()
    if not pbs:
        console.print("[yellow]No playbooks found.[/yellow]")
        return

    table = Table(title="Playbooks")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Intensity")
    table.add_column("Phases", justify="right")
    table.add_column("Description")
    for pb in pbs:
        table.add_row(pb.name, pb.version, pb.intensity, str(len(pb.phases)), pb.description)
    console.print(table)


@playbook_app.command("show")
def playbook_show(name_or_path: str = typer.Argument(..., help="Playbook name or path")):
    """Show a playbook's phases, inputs, and execution plan."""
    from engine.playbook import find_playbook, plan_phases

    pb = find_playbook(name_or_path)
    console.print(
        Panel.fit(
            f"[bold]{pb.name}[/bold]  v{pb.version}  ({pb.intensity})\n"
            f"{pb.description}\n"
            f"Authors: {', '.join(pb.authors) or '-'}\n"
            f"Source:  {pb.path}",
            title="Playbook",
        )
    )

    if pb.inputs:
        inp_tbl = Table(title="Inputs")
        inp_tbl.add_column("Name", style="cyan")
        inp_tbl.add_column("Required")
        inp_tbl.add_column("Default")
        inp_tbl.add_column("Prompt")
        for n, spec in pb.inputs.items():
            inp_tbl.add_row(n, "yes" if spec.required else "no", spec.default or "-", spec.prompt or "-")
        console.print(inp_tbl)

    plan = plan_phases(pb, findings=[])
    ph_tbl = Table(title="Phases")
    ph_tbl.add_column("#", justify="right")
    ph_tbl.add_column("Phase", style="cyan")
    ph_tbl.add_column("Tools")
    ph_tbl.add_column("Depends on")
    ph_tbl.add_column("Condition")
    ph_tbl.add_column("Manual")
    for i, (phase, _will, _reason) in enumerate(plan, 1):
        ph_tbl.add_row(
            str(i),
            phase.id,
            ", ".join(phase.tools) or "-",
            ", ".join(phase.depends_on) or "-",
            phase.condition or "-",
            "yes" if phase.manual else "no",
        )
    console.print(ph_tbl)


@playbook_app.command("validate")
def playbook_validate(path: str = typer.Argument(..., help="Path to YAML playbook")):
    """Lint a playbook file against the schema."""
    from engine.playbook import PlaybookError, load_playbook

    try:
        pb = load_playbook(path)
    except PlaybookError as e:
        console.print(f"[red]invalid:[/red] {e}")
        raise typer.Exit(1) from e
    console.print(f"[green]OK {pb.name} (v{pb.version}) - {len(pb.phases)} phases[/green]")


@playbook_app.command("run")
def playbook_run(
    name_or_path: str = typer.Argument(..., help="Playbook name or path"),
    inputs: list[str] = typer.Option([], "--input", "-i", help="key=value; repeatable"),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="Plan only (default) or execute"),
):
    """Plan (default) or execute a playbook.

    Execution is not yet wired to the orchestrator; dry-run prints the phase
    order and gating decisions that would be applied at runtime.
    """
    from engine.playbook import find_playbook, plan_phases, resolve_inputs

    pb = find_playbook(name_or_path)

    provided = {}
    for item in inputs:
        if "=" not in item:
            console.print(f"[yellow]skipping malformed input: {item}[/yellow]")
            continue
        k, v = item.split("=", 1)
        provided[k.strip()] = v.strip()

    resolved = resolve_inputs(pb, provided)
    console.print(Panel.fit(f"[bold]{pb.name}[/bold] - inputs: {resolved}", title="Playbook Run"))

    plan = plan_phases(pb, findings=[])
    for phase, will_run, reason in plan:
        status = "[green]RUN[/green]" if will_run else f"[yellow]SKIP[/yellow] ({reason})"
        console.print(f"  {status}  {phase.id}  tools={phase.tools or '-'}")

    if not dry_run:
        console.print(
            "[yellow]--execute is not yet wired to the orchestrator; "
            "playbook execution lands in the next sub-phase.[/yellow]"
        )


if __name__ == "__main__":
    app()

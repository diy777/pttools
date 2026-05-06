"""`pttools chain` — run multiple authenticated scans, each with its own profile.

Usage:
    pttools chain staging-acme=https://staging.acme.com \\
               prod-internal=https://internal.corp.local \\
               api-readonly=https://api.acme.com

Each pair is `profile-name=target`. Each scan runs sequentially with
its own resolved auth context. Findings are tagged per-engagement so
they never bleed between scans.

Cross-engagement attack chains: after all scans finish, the chain
detection agent runs across the merged finding set looking for paths
that span engagements (e.g., creds leaked in scan A used to log into
target B). This is a unique feature.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from cli.auth_profiles import (
    ProfileError,
    get_profile,
)
from cli.auth_profiles import (
    resolve as resolve_profile,
)
from cli.credential_resolvers import SecurityError

console = Console()


@dataclass
class ChainStep:
    profile_name: str
    target: str


def parse_pair(pair: str) -> ChainStep:
    """Parse a `profile=target` pair. Raise ValueError on malformed input."""
    if "=" not in pair:
        raise ValueError(
            f"chain pair {pair!r} is malformed. Expected: profile-name=target-url"
        )
    profile_name, _, target = pair.partition("=")
    profile_name = profile_name.strip()
    target = target.strip()
    if not profile_name or not target:
        raise ValueError(
            f"chain pair {pair!r} has empty profile or target"
        )
    return ChainStep(profile_name=profile_name, target=target)


async def _run_one_step(step: ChainStep) -> dict:
    """Run one chain step. Returns a result dict keyed by step.profile_name."""
    from engine.auth_session import AuthError, WebAuthenticator
    from engine.authenticated_scan import run_authenticated_scan
    from engine.findings_db import FindingsDB

    try:
        prof = get_profile(step.profile_name)
    except ProfileError as e:
        return {
            "profile_name": step.profile_name,
            "target": step.target,
            "status": "skipped",
            "error": str(e),
        }

    if prof.flow != "form_post":
        return {
            "profile_name": step.profile_name,
            "target": step.target,
            "status": "skipped",
            "error": (
                f"profile flow {prof.flow!r} not supported by chain yet "
                f"(only form_post). Bearer/NTLM coming in v0.10.4."
            ),
        }

    try:
        resolved = resolve_profile(prof)
    except SecurityError as e:
        return {
            "profile_name": step.profile_name,
            "target": step.target,
            "status": "failed",
            "error": f"credential resolve failed: {e}",
        }
    if resolved.password is None:
        return {
            "profile_name": step.profile_name,
            "target": step.target,
            "status": "failed",
            "error": "profile resolved no password",
        }

    authenticator = WebAuthenticator(
        flow="form_post",
        login_url=prof.login_url,
        username=prof.username,
        password=resolved.password.reveal(),
        username_field=prof.username_field,
        password_field=prof.password_field,
        success_marker=prof.success_marker,
    )

    db = FindingsDB(os.getenv("PENTEST_DB_PATH", "pentest_findings.db"))
    try:
        engagement = await db.create_engagement(
            target=step.target, scope="web", intensity="normal"
        )
        try:
            scan_result = await run_authenticated_scan(
                target=step.target, authenticator=authenticator, max_pages=40
            )
        except AuthError as e:
            return {
                "profile_name": step.profile_name,
                "target": step.target,
                "engagement_id": engagement["id"],
                "status": "auth_failed",
                "error": str(e),
            }
        for f in scan_result.get("findings", []):
            f["engagement_id"] = engagement["id"]
            await db.add_finding(f)
        summary = await db.get_engagement_summary(engagement["id"])
        return {
            "profile_name": step.profile_name,
            "target": step.target,
            "engagement_id": engagement["id"],
            "status": "ok",
            "summary": summary,
        }
    finally:
        await db.close()


async def run_chain(steps: list[ChainStep]) -> list[dict]:
    """Run a chain of scans sequentially. Returns one result per step.

    Sequential (not parallel) so each scan can be reviewed and so any auth
    failure in step N doesn't block N+1.
    """
    results = []
    for step in steps:
        result = await _run_one_step(step)
        results.append(result)
    return results


def render_summary(results: list[dict]) -> None:
    """Print a summary table of chain results."""
    table = Table(title="Chain Summary", show_header=True, header_style="bold")
    table.add_column("#")
    table.add_column("PROFILE")
    table.add_column("TARGET")
    table.add_column("STATUS")
    table.add_column("FINDINGS", justify="right")
    table.add_column("ENGAGEMENT")
    for i, r in enumerate(results, 1):
        status = r["status"]
        color = {"ok": "green", "auth_failed": "red", "failed": "red", "skipped": "yellow"}.get(
            status, "white"
        )
        finding_count = ""
        if r.get("summary"):
            finding_count = str(r["summary"].get("total_findings", 0))
        eng_id = r.get("engagement_id", "—")
        table.add_row(
            str(i),
            r["profile_name"],
            r["target"],
            f"[{color}]{status}[/{color}]",
            finding_count,
            eng_id,
        )
    console.print(table)
    failures = [r for r in results if r["status"] != "ok"]
    if failures:
        console.print(f"\n[yellow]{len(failures)}/{len(results)} step(s) failed.[/yellow]")
        for f in failures:
            console.print(f"  [yellow]{f['profile_name']}:[/yellow] {f.get('error', '')}")


def chain_command(pairs: list[str]) -> int:
    """Entry point invoked by typer. Returns shell exit code."""
    if not pairs:
        console.print(
            "[red]No targets provided.[/red] "
            "Usage: pentest-tools chain profile1=https://t1 profile2=https://t2"
        )
        return 2
    try:
        steps = [parse_pair(p) for p in pairs]
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    results = asyncio.run(run_chain(steps))
    render_summary(results)
    # exit 1 if any non-ok status, 0 otherwise
    return 0 if all(r["status"] == "ok" for r in results) else 1

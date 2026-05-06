"""
pentest-tools MCP Server

Exposes 150+ security tools via the Model Context Protocol.
Connects to Claude, GPT, Copilot, or any MCP-compatible client.

AUTHORIZED TARGETS ONLY. Every tool exposed here performs real network
or host operations. Calling client (the LLM agent) and the operator
behind it are solely responsible for ensuring written authorization
exists for every target. See https://pentest-tools.local/aup.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastmcp import Context, FastMCP
from pydantic import BaseModel, Field

from engine.findings_db import FindingsDB
from engine.orchestrator import AgentOrchestrator
from tools.registry import ToolRegistry

logger = logging.getLogger("pentest-tools.mcp")

# Initialize MCP server
mcp = FastMCP("pentest-tools")

# Global state
findings_db: FindingsDB | None = None
orchestrator: AgentOrchestrator | None = None
tool_registry: ToolRegistry | None = None

def get_findings_db() -> FindingsDB:
    global findings_db
    if findings_db is None:
        findings_db = FindingsDB(os.getenv("PENTEST_DB_PATH", "pentest_findings.db"))
    return findings_db


def get_orchestrator() -> AgentOrchestrator:
    global orchestrator
    if orchestrator is None:
        orchestrator = AgentOrchestrator(get_findings_db())
    return orchestrator


def get_tool_registry() -> ToolRegistry:
    global tool_registry
    if tool_registry is None:
        tool_registry = ToolRegistry()
    return tool_registry


# ─── Engagement Management ───────────────────────────────────────────────


class EngagementParams(BaseModel):
    target: str = Field(description="Target hostname, IP, or URL")
    scope: str = Field(default="full", description="Scope: recon, web, ad, cloud, full")
    rules_of_engment: str = Field(default="", description="Rules of engagement / exclusions")
    intensity: str = Field(default="normal", description="Scan intensity: stealth, normal, aggressive")


@mcp.tool()
async def start_engagement(
    target: str,
    scope: str = "full",
    rules_of_engment: str = "",
    intensity: str = "normal",
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Start a new pentest engagement against a target. AUTHORIZED TARGETS ONLY.

    This initiates reconnaissance and begins the automated assessment.
    All findings are stored and correlated in the findings database.
    Streams phase progress to the MCP client as notifications.

    The caller (LLM agent and the human operator behind it) MUST have
    written authorization to test the target. See pentest-tools.local/aup.
    """
    db = get_findings_db()
    engagement = await db.create_engagement(
        target=target,
        scope=scope,
        rules_of_engment=rules_of_engment,
        intensity=intensity,
    )
    eng_id = engagement["id"]

    async def _notify(phase: str, message: str, pct: float) -> None:
        if ctx is None:
            return
        try:
            await ctx.report_progress(progress=pct, total=1.0, message=message)
            await ctx.info(f"[{eng_id}] {phase}: {message}")
        except Exception:
            pass

    def _on_progress(phase: str, message: str, pct: float) -> None:
        asyncio.create_task(_notify(phase, message, pct))

    orchestrator = get_orchestrator()
    await orchestrator.start_engagement(engagement, on_progress=_on_progress)

    return {
        "engagement_id": eng_id,
        "target": target,
        "scope": scope,
        "status": "running",
        "message": f"Engagement started against {target}. Recon phase initiated.",
    }


@mcp.tool()
async def get_engagement_status(engagement_id: str) -> dict[str, Any] | None:
    """Get the current status of a pentest engagement."""
    db = get_findings_db()
    return await db.get_engagement(engagement_id)


@mcp.tool()
async def get_findings(
    engagement_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Get findings from current or specific engagement.

    Filter by severity (critical, high, medium, low, info) or status (confirmed, pending, false_positive).
    """
    db = get_findings_db()
    return await db.get_findings(
        engagement_id=engagement_id,
        severity=severity,
        status=status,
    )


@mcp.tool()
async def get_attack_chains(engagement_id: str) -> list[dict[str, Any]]:
    """Get discovered attack chains for an engagement.

    Shows how individual findings chain together into full compromise paths.
    """
    db = get_findings_db()
    return await db.get_attack_chains(engagement_id)


# ─── Tool Execution ──────────────────────────────────────────────────────


@mcp.tool()
async def list_tools(category: str | None = None) -> list[dict[str, Any]]:
    """List all available security tools, optionally filtered by category.

    Categories: network, web, password, binary, cloud, osint
    """
    registry = get_tool_registry()
    tools = registry.list_tools(category=category)
    return [
        {
            "name": t.name,
            "category": t.category,
            "description": t.description,
            "required_deps": t.required_deps,
            "installed": t.is_installed(),
        }
        for t in tools
    ]


_TARGET_BAD_CHARS = set(";|&`$<>\n\r\t\\")


def _validate_target_arg(target: str) -> str | None:
    """Return None if target is acceptable, else an error string explaining why.

    Rejects shell metacharacters, empty strings, and excessively long inputs.
    Tools are launched without shell=True, but defense-in-depth + clearer errors
    are worth a few extra lines.
    """
    if not target or not target.strip():
        return "target is empty"
    if len(target) > 506:
        return f"target too long ({len(target)} chars; max 506)"
    found = _TARGET_BAD_CHARS.intersection(target)
    if found:
        return f"target contains shell metacharacters: {sorted(found)}"
    return None


@mcp.tool()
async def run_tool(
    tool_name: str,
    target: str,
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run a specific security tool against a target.

    Returns structured results that are automatically stored in the findings database.
    """
    bad = _validate_target_arg(target)
    if bad:
        return {"error": f"invalid target: {bad}", "tool": tool_name, "target": target}

    registry = get_tool_registry()
    tool = registry.get_tool(tool_name)

    if tool is None:
        return {"error": f"Tool '{tool_name}' not found. Use list_tools to see available tools."}

    if not tool.is_installed():
        return {"error": f"Tool '{tool_name}' is not installed on this system."}

    result = await tool.execute(target, args or {})

    # Auto-store findings
    if result.get("findings"):
        db = get_findings_db()
        for finding in result["findings"]:
            await db.add_finding(finding)

    return result


# ─── Reconnaissance ──────────────────────────────────────────────────────


@mcp.tool()
async def run_recon(target: str, depth: str = "standard") -> dict[str, Any]:
    """Run comprehensive reconnaissance against a target.

    Depth levels:
    - passive: OSINT only, no direct interaction
    - standard: Passive + light active scanning
    - deep: Full active scanning including port scans, vuln scans
    """
    from agents.recon.recon_agent import ReconAgent

    agent = ReconAgent(get_tool_registry(), get_findings_db())
    return await agent.run_recon(target, depth=depth)


# ─── Web Application Testing ─────────────────────────────────────────────


@mcp.tool()
async def test_web_app(
    target: str,
    auth_profile: str = "",
    auth_credentials: dict[str, str] | None = None,
    focus_areas: list[str] | None = None,
) -> dict[str, Any]:
    """Run automated web application security testing.

    Tests for: SQL injection, XSS, SSRF, IDOR, auth bypass, business logic flaws,
    API vulnerabilities, and more.

    Recommended (secure): pass ``auth_profile`` = name of a profile created
    via ``pentest-tools auth profile add``. Credentials never enter the MCP/LLM
    request payload.

    Deprecated (insecure, removed in 0.11): ``auth_credentials`` dict literal.

    focus_areas: Specific areas to focus on (sqli, xss, ssrf, idor, auth, api, all)
    """
    from agents.web.web_agent import WebAgent

    if auth_profile:
        if auth_credentials:
            return {"error": "auth_profile is mutually exclusive with auth_credentials"}
        try:
            from cli.auth_profiles import (
                ProfileError,
                get_profile,
            )
            from cli.auth_profiles import (
                resolve as resolve_profile,
            )
            from cli.credential_resolvers import SecurityError

            prof = get_profile(auth_profile)
            resolved = resolve_profile(prof)
        except (ProfileError, SecurityError) as e:
            return {"error": f"profile {auth_profile!r}: {e}"}
        if resolved.token is not None:
            auth_credentials = {
                "type": "bearer",
                "username": prof.username,
                "token": resolved.token.reveal(),
            }
        elif resolved.password is not None:
            auth_credentials = {
                "type": "form",
                "login_url": prof.login_url,
                "username": prof.username,
                "password": resolved.password.reveal(),
            }
        else:
            return {"error": f"profile {auth_profile!r} resolved no credential"}
    elif auth_credentials:
        logger.warning(
            "test_web_app: raw auth_credentials in MCP call. "
            "Migrate to auth_profile (will be removed in pttools 0.11)."
        )

    agent = WebAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, auth_credentials, focus_areas)


# ─── Authenticated Web Scanner ───────────────────────────────────────────


@mcp.tool()
async def authenticated_scan(
    target: str,
    auth_profile: str = "",
    login_url: str = "",
    username: str = "",
    password: str = "",
    username_field: str = "username",
    password_field: str = "password",
    success_marker: str = "",
    success_status: int | None = None,
    bearer_token: str = "",
    max_pages: int = 40,
    timeout_seconds: float = 10.0,
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run a deterministic authenticated web scan (no LLM required).

    Logs in, crawls same-host pages, probes each parameterized endpoint with
    SQLi/XSS/command-injection payloads. Returns structured findings suitable
    for the findings database.

    Recommended (secure): pass ``auth_profile`` = name of a profile created
    via ``pentest-tools auth profile add``. Credentials are resolved server-side
    and never enter the MCP request payload (so they never reach the LLM).

    Deprecated (insecure, removed in 0.11): ``login_url`` + ``username`` +
    ``password`` for form login, or ``bearer_token`` for a static API token.
    These pass the credential value through the MCP/LLM context.

    When ``engagement_id`` is set, findings are persisted to the DB.
    """
    from engine.auth_session import AuthError, WebAuthenticator
    from engine.authenticated_scan import run_authenticated_scan

    # If a profile name was supplied, resolve it server-side (credentials
    # never enter the MCP request payload).
    if auth_profile:
        if password or bearer_token:
            return {
                "error": (
                    "auth_profile is mutually exclusive with password/bearer_token. "
                    "Pick one: pass auth_profile (recommended) or the legacy raw "
                    "credential params (deprecated, removed in 0.11)."
                ),
                "target": target,
            }
        try:
            from cli.auth_profiles import (
                ProfileError,
                get_profile,
            )
            from cli.auth_profiles import (
                resolve as resolve_profile,
            )
            from cli.credential_resolvers import SecurityError

            prof = get_profile(auth_profile)
            resolved = resolve_profile(prof)
        except (ProfileError, SecurityError) as e:
            return {"error": f"profile {auth_profile!r}: {e}", "target": target}
        # Pull the resolved value into local vars; do not echo into logs.
        if prof.flow == "bearer":
            if resolved.token is None:
                return {
                    "error": f"profile {auth_profile!r}: bearer profile resolved no token",
                    "target": target,
                }
            flow = "bearer_static"
            bearer_token = resolved.token.reveal()
            login_url = ""
            username = ""
            password = ""
        else:
            if resolved.password is None:
                return {
                    "error": f"profile {auth_profile!r}: form profile resolved no password",
                    "target": target,
                }
            flow = "form_post"
            login_url = prof.login_url
            username = prof.username
            password = resolved.password.reveal()
            username_field = prof.username_field or username_field
            password_field = prof.password_field or password_field
            success_marker = prof.success_marker or success_marker
    else:
        # Legacy path: warn but accept.
        if password or bearer_token:
            logger.warning(
                "authenticated_scan: raw password/bearer_token in MCP call. "
                "Migrate to auth_profile (will be removed in pttools 0.11). "
                "See: pentest-tools auth profile add"
            )
        flow = "bearer_static" if bearer_token else "form_post"

    authenticator = WebAuthenticator(
        flow=flow,
        login_url=login_url,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        success_marker=success_marker,
        success_status=success_status,
        bearer_token=bearer_token,
    )

    try:
        result = await run_authenticated_scan(
            target=target,
            authenticator=authenticator,
            max_pages=max_pages,
            timeout_seconds=timeout_seconds,
        )
    except AuthError as e:
        return {"error": f"authentication failed: {e}", "target": target}

    if engagement_id and result.get("findings"):
        db = get_findings_db()
        for f in result["findings"]:
            f["engagement_id"] = engagement_id
            await db.add_finding(f)

    return result


# ─── Active Directory Testing ────────────────────────────────────────────


@mcp.tool()
async def test_active_directory(
    domain: str,
    target_ip: str,
    auth_profile: str = "",
    credentials: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run Active Directory security assessment.

    Includes: BloodHound enumeration, Kerberoasting, AS-REP roasting,
    privilege escalation paths, delegation attacks, and domain dominance.

    Recommended (secure): pass ``auth_profile`` = name of an ntlm profile
    created via ``pentest-tools auth profile add``. The password is resolved
    server-side and never enters the MCP/LLM context.

    Deprecated (insecure, removed in 0.11): ``credentials`` dict literal.
    """
    from agents.ad.ad_agent import ADAgent

    if auth_profile:
        if credentials:
            return {"error": "auth_profile is mutually exclusive with credentials"}
        try:
            from cli.auth_profiles import (
                ProfileError,
                get_profile,
            )
            from cli.auth_profiles import (
                resolve as resolve_profile,
            )
            from cli.credential_resolvers import SecurityError

            prof = get_profile(auth_profile)
            resolved = resolve_profile(prof)
        except (ProfileError, SecurityError) as e:
            return {"error": f"profile {auth_profile!r}: {e}"}
        if resolved.password is None:
            return {"error": f"profile {auth_profile!r} resolved no password"}
        credentials = {
            "username": prof.username,
            "domain": prof.domain or domain,
            "password": resolved.password.reveal(),
        }
    elif credentials:
        logger.warning(
            "test_active_directory: raw credentials in MCP call. "
            "Migrate to auth_profile (will be removed in pttools 0.11)."
        )

    agent = ADAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(domain, target_ip, credentials)


# ─── Cloud Security ──────────────────────────────────────────────────────


@mcp.tool()
async def test_cloud(
    provider: str,
    target: str,
    auth_profile: str = "",
    credentials: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run cloud security assessment.

    Providers: aws, azure, gcp

    Tests for: Misconfigurations, exposed secrets, overly permissive IAM,
    vulnerable services, and privilege escalation paths.

    Recommended (secure): pass ``auth_profile`` = name of a profile that
    references the cloud credential (env var, op://, vault path, AWS-SM ARN).

    Deprecated (insecure, removed in 0.11): ``credentials`` dict literal.
    """
    from agents.cloud.cloud_agent import CloudAgent

    if auth_profile:
        if credentials:
            return {"error": "auth_profile is mutually exclusive with credentials"}
        try:
            from cli.auth_profiles import (
                ProfileError,
                get_profile,
            )
            from cli.auth_profiles import (
                resolve as resolve_profile,
            )
            from cli.credential_resolvers import SecurityError

            prof = get_profile(auth_profile)
            resolved = resolve_profile(prof)
        except (ProfileError, SecurityError) as e:
            return {"error": f"profile {auth_profile!r}: {e}"}
        secret_value = ""
        if resolved.token is not None:
            secret_value = resolved.token.reveal()
        elif resolved.password is not None:
            secret_value = resolved.password.reveal()
        if not secret_value:
            return {"error": f"profile {auth_profile!r} resolved no credential"}
        credentials = {"profile_name": auth_profile, "secret": secret_value}
    elif credentials:
        logger.warning(
            "test_cloud: raw credentials in MCP call. "
            "Migrate to auth_profile (will be removed in pttools 0.11)."
        )

    agent = CloudAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(provider, target, credentials)


# ─── Exploit Chaining ────────────────────────────────────────────────────


@mcp.tool()
async def discover_attack_chains(engagement_id: str) -> dict[str, Any]:
    """Discover attack chains from existing findings.

    Analyzes all findings for an engagement and identifies how they can
    be chained together to achieve full system compromise.
    """
    from agents.exploit_chain.chain_agent import ExploitChainAgent

    agent = ExploitChainAgent(get_findings_db())
    chains = await agent.discover_chains(engagement_id)

    return {
        "engagement_id": engagement_id,
        "chains_found": len(chains),
        "chains": chains,
    }


# ─── Report Generation ───────────────────────────────────────────────────


@mcp.tool()
async def generate_report(
    engagement_id: str,
    format: str = "markdown",
    include_pocs: bool = True,
    include_detections: bool = True,
) -> dict[str, Any]:
    """Generate a professional pentest report.

    Formats: markdown, html, pdf, json

    Includes executive summary, technical findings, attack chains,
    proof of concepts, remediation guidance, and detection rules.
    """
    from agents.report.report_agent import ReportAgent

    agent = ReportAgent(get_findings_db())
    return await agent.generate_report(engagement_id, format, include_pocs, include_detections)


# ─── Detection Rule Generation ───────────────────────────────────────────


@mcp.tool()
async def generate_detection_rules(engagement_id: str) -> dict[str, Any]:
    """Generate detection rules (Sigma, SPL, KQL) for all discovered attacks.

    Every offensive technique gets a corresponding detection rule for blue teams.
    """
    from agents.detection.detection_agent import DetectionAgent

    agent = DetectionAgent(get_findings_db())
    rules = await agent.generate_rules(engagement_id)
    return {"engagement_id": engagement_id, "rules_count": len(rules), "rules": rules}


# ─── PoC Validation ──────────────────────────────────────────────────────


@mcp.tool()
async def validate_finding(finding_id: str) -> dict[str, Any]:
    """Validate a specific finding with a safe, non-destructive proof of concept.

    Confirms the vulnerability is real and exploitable without causing damage.
    """
    from agents.poc_validator.poc_agent import PoCAgent

    agent = PoCAgent(get_findings_db())
    return await agent.validate_finding(finding_id)


# ─── Specialist Agents Not Wired Above ───────────────────────────────────


@mcp.tool()
async def test_api_security(
    target: str,
    spec_url: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run API security testing (REST + GraphQL) following OWASP API Top 10.

    Tests for: BOLA/IDOR, JWT alg-confusion, OAuth callback validation,
    rate-limit bypass, mass assignment, GraphQL introspection.
    """
    from agents.api_security.api_security_agent import APISecurityAgent
    agent = APISecurityAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, spec_url=spec_url, engagement_id=engagement_id)


@mcp.tool()
async def test_credentials(
    target: str,
    userlist: str = "",
    wordlist: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run authentication testing (default creds, password spray, MFA bypass).

    Lockout-aware. Prefers spraying over brute force on production targets.
    """
    from agents.credential_tester.credential_tester_agent import CredentialTesterAgent
    agent = CredentialTesterAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, userlist=userlist, wordlist=wordlist, engagement_id=engagement_id)


@mcp.tool()
async def test_vulnerabilities(
    target: str,
    templates: str = "cves,vulnerabilities,misconfiguration,exposures",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run vulnerability scanning (Nuclei + RouterSploit + nikto + dirb).

    De-duplicates against findings already in the engagement, filters
    false positives, scores by CVSS + EPSS exploit probability.
    """
    from agents.vuln_scanner.vuln_scanner_agent import VulnScannerAgent
    agent = VulnScannerAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, templates=templates, engagement_id=engagement_id)


@mcp.tool()
async def test_privesc(
    target: str,
    platform: str = "linux",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run privilege escalation enumeration on a compromised host.

    Platforms: linux, windows, container. Uses linpeas/winpeas/deepce
    plus kernel-exploit-suggester. Enumeration only by default.
    """
    from agents.privesc.privesc_agent import PrivescAdvisorAgent
    agent = PrivescAdvisorAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, platform=platform, engagement_id=engagement_id)


@mcp.tool()
async def test_mobile(
    target: str,
    platform: str = "android",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run mobile app security testing (Android or iOS).

    Static + dynamic analysis. OWASP Mobile Top 10 coverage.
    """
    from agents.mobile.mobile_agent import MobileAgent
    agent = MobileAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, platform=platform, engagement_id=engagement_id)


@mcp.tool()
async def test_wireless(
    target: str,
    interface: str = "wlan0",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run wireless security assessment (WiFi + Bluetooth)."""
    from agents.wireless.wireless_agent import WirelessAgent
    agent = WirelessAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(target, interface=interface, engagement_id=engagement_id)


@mcp.tool()
async def test_social_engineering(
    target: str,
    campaign_type: str = "phishing",
    targets_list: list[str] | None = None,
    engagement_id: str = "",
) -> dict[str, Any]:
    """Run a social engineering assessment (phishing simulation, OSINT, DMARC audit)."""
    from agents.social_engineer.social_engineer_agent import SocialEngineerAgent
    agent = SocialEngineerAgent(get_tool_registry(), get_findings_db())
    return await agent.run_assessment(
        target, campaign_type=campaign_type, targets_list=targets_list, engagement_id=engagement_id
    )


@mcp.tool()
async def browser_inspect(
    url: str,
    action: str = "headers",
) -> dict[str, Any]:
    """Inspect a URL with the headless browser.

    Actions: headers (security headers), dom (forms+links+scripts),
    network (request log), forms, cookies, screenshot.
    """
    from agents.browser.browser_agent import BrowserAgent
    agent = BrowserAgent()
    if action == "headers":
        return {"url": url, "result": await agent.check_security_headers(url)}
    if action == "dom":
        return {"url": url, "result": await agent.inspect_dom(url)}
    if action == "network":
        return {"url": url, "result": await agent.capture_network(url)}
    if action == "forms":
        return {"url": url, "result": await agent.extract_forms(url)}
    if action == "cookies":
        return {"url": url, "result": await agent.get_cookies(url)}
    if action == "screenshot":
        return {"url": url, "result": "screenshot captured", "bytes": len(await agent.capture_screenshot(url))}
    return {"error": f"unknown action: {action}", "valid": ["headers", "dom", "network", "forms", "cookies", "screenshot"]}


# ─── Selection / Router ──────────────────────────────────────────────────


@mcp.tool()
async def select_agent(target: str, intent: str = "") -> dict[str, Any]:
    """Pick the right specialist agent for a target + optional intent hint.

    Heuristic, deterministic, no LLM call. Returns
    {"target", "agent", "reason", "confidence"}. Use this as a first
    step when an MCP client gets a free-form request and needs to know
    which test_* tool to invoke (e.g. test_web_app vs test_active_directory
    vs test_api_security).
    """
    from agents.selection.selection_agent import route_target
    return route_target(target, intent=intent)


# ─── Process Control ─────────────────────────────────────────────────────


@mcp.tool()
async def list_processes() -> list[dict[str, Any]]:
    """List running tool subprocesses tracked by the engine.

    Each entry includes pid, tool, target, runtime_seconds, engagement_id,
    and cmd. Useful for monitoring long-running scans (nuclei, masscan,
    full-portscan nmap) and deciding whether to kill them.
    """
    from engine.process_registry import get_default_registry
    return [r.to_dict() for r in get_default_registry().list_records()]


@mcp.tool()
async def kill_process(pid: int, grace_seconds: float = 2.0) -> dict[str, Any]:
    """Terminate a running tool subprocess by PID.

    Sends SIGTERM, waits up to grace_seconds, then escalates to SIGKILL.
    Returns {"killed": bool, "pid": int}. Use list_processes first to
    confirm the PID is one pttools owns.
    """
    from engine.process_registry import get_default_registry
    killed = await get_default_registry().kill(pid, grace_seconds=grace_seconds)
    return {"killed": killed, "pid": pid}


# ─── Built-in Scanners (No External Tools Required) ──────────────────────


@mcp.tool()
async def builtin_scan(
    target: str,
    scan_type: str = "all",
) -> dict[str, Any]:
    """Run built-in security scans without requiring any external tools.

    Works immediately after install. Scan types: all, ports, headers, ssl, paths, dns, secrets.
    Includes: port scanning, HTTP header analysis, SSL/TLS checks, sensitive path discovery,
    DNS enumeration, and secret/credential detection in responses.
    """
    from engine.scanners import run_builtin_scan

    result = await run_builtin_scan(target, scan_type)

    # Auto-store findings
    if result.get("findings"):
        db = get_findings_db()
        for f in result["findings"]:
            f["engagement_id"] = ""
            await db.add_finding(f)

    return result


@mcp.tool()
async def scan_ports_builtin(target: str) -> dict[str, Any]:
    """Scan common ports on a target (built-in, no nmap required)."""
    from engine.scanners import scan_ports

    findings = await scan_ports(target)
    return {"target": target, "findings_count": len(findings), "findings": findings}


@mcp.tool()
async def scan_headers_builtin(target: str) -> dict[str, Any]:
    """Analyze HTTP security headers (built-in)."""
    from engine.scanners import scan_http_headers

    findings = await scan_http_headers(target)
    return {"target": target, "findings_count": len(findings), "findings": findings}


@mcp.tool()
async def scan_ssl_builtin(target: str, port: int = 443) -> dict[str, Any]:
    """Check SSL/TLS configuration (built-in)."""
    from engine.scanners import check_ssl

    findings = await check_ssl(target, port)
    return {"target": target, "findings_count": len(findings), "findings": findings}


@mcp.tool()
async def scan_paths_builtin(target: str) -> dict[str, Any]:
    """Scan for common sensitive paths (built-in)."""
    from engine.scanners import scan_common_paths

    findings = await scan_common_paths(target)
    return {"target": target, "findings_count": len(findings), "findings": findings}


@mcp.tool()
async def scan_dns_builtin(target: str) -> dict[str, Any]:
    """Perform DNS enumeration (built-in)."""
    from engine.scanners import check_dns

    findings = await check_dns(target)
    return {"target": target, "findings_count": len(findings), "findings": findings}


@mcp.tool()
async def scan_secrets_builtin(target: str) -> dict[str, Any]:
    """Scan HTTP responses for leaked secrets and credentials (built-in)."""
    from engine.scanners import scan_secrets_in_response

    findings = await scan_secrets_in_response(target)
    return {"target": target, "findings_count": len(findings), "findings": findings}


# ─── Engagement Management Extras ────────────────────────────────────────


@mcp.tool()
async def get_engagement_summary(engagement_id: str) -> dict[str, Any]:
    """Get a summary of an engagement including finding counts, chains, and rules."""
    db = get_findings_db()
    return await db.get_engagement_summary(engagement_id)


@mcp.tool()
async def list_engagements(
    limit: int = 20,
    status_filter: str | None = None,
) -> list[dict[str, Any]]:
    """List all pentest engagements, optionally filtered by status."""
    db = get_findings_db()
    return await db.list_engagements(limit=limit, status_filter=status_filter)


@mcp.tool()
async def resume_engagement(engagement_id: str) -> dict[str, Any]:
    """Resume an interrupted engagement from its last checkpoint.

    Picks up from the last completed phase and continues the assessment.
    """
    db = get_findings_db()
    eng = await db.get_engagement(engagement_id)
    if not eng:
        return {"error": f"Engagement {engagement_id} not found"}

    checkpoint = await db.get_checkpoint(engagement_id)
    if not checkpoint:
        return {"error": f"No checkpoint found for {engagement_id}"}

    if checkpoint["status"] == "completed":
        return {"engagement_id": engagement_id, "status": "already_completed"}

    orch = get_orchestrator()
    await orch.resume_engagement(eng)
    return {
        "engagement_id": engagement_id,
        "status": "completed",
        "resumed_from": checkpoint.get("completed_phases", []),
    }


@mcp.tool()
async def close_engagement(engagement_id: str) -> dict[str, Any]:
    """Close an engagement and mark it as completed."""
    db = get_findings_db()
    await db._db.execute(
        "UPDATE engagements SET status = 'completed', updated_at = ?, completed_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), engagement_id),
    )
    await db._db.commit()
    return {"engagement_id": engagement_id, "status": "completed"}


# ─── Compliance & Evidence ───────────────────────────────────────────────


@mcp.tool()
async def query_compliance(
    engagement_id: str,
    framework: str = "all",
) -> dict[str, Any]:
    """Query compliance mapping for an engagement's findings.

    Frameworks: pci_dss, hipaa, soc2, owasp, all
    Returns findings grouped by compliance control.
    """
    db = get_findings_db()
    findings_list = await db.get_findings(engagement_id=engagement_id)
    from engine.compliance import map_finding_compliance

    results: dict[str, list[dict]] = {}
    for f in findings_list:
        mapping = map_finding_compliance(f)
        for fw, controls in mapping.items():
            if framework != "all" and fw != framework:
                continue
            for ctrl in controls:
                key = f"{fw}:{ctrl}"
                results.setdefault(key, []).append({"title": f.get("title"), "severity": f.get("severity")})
    return {"engagement_id": engagement_id, "framework": framework, "controls": results}


@mcp.tool()
async def get_evidence(
    engagement_id: str,
    finding_id: str | None = None,
) -> dict[str, Any]:
    """Retrieve evidence artifacts for an engagement or specific finding."""
    import os
    from pathlib import Path

    evidence_dir = Path(os.getenv("PENTEST_EVIDENCE_DIR", "evidence")) / engagement_id
    if not evidence_dir.exists():
        return {"engagement_id": engagement_id, "artifacts": [], "message": "No evidence directory found"}

    artifacts = []
    for f in sorted(evidence_dir.iterdir()):
        if finding_id and finding_id not in f.name:
            continue
        artifacts.append({
            "filename": f.name,
            "size_bytes": f.stat().st_size,
            "path": str(f),
        })
    return {"engagement_id": engagement_id, "artifacts": artifacts}


@mcp.tool()
async def list_plugins() -> list[dict[str, Any]]:
    """List installed YAML plugins from ~/.pentest-tools/plugins/."""
    from tools.plugin_loader import load_plugins
    return load_plugins()


@mcp.tool()
async def get_config() -> dict[str, Any]:
    """Get current pentest-tools configuration (secrets masked)."""
    from config.settings import load_config
    return load_config().to_dict(mask_secrets=True)


@mcp.tool()
async def set_intensity(engagement_id: str, intensity: str) -> dict[str, Any]:
    """Change scan intensity (stealth, normal, aggressive) mid-engagement.

    Persists to DB. If the engagement is currently running, also updates the
    live rate limiter so subsequent phases respect the new pace immediately.
    """
    db = get_findings_db()
    eng = await db.get_engagement(engagement_id)
    if not eng:
        return {"error": f"engagement not found: {engagement_id}", "engagement_id": engagement_id}

    orch = get_orchestrator()
    try:
        await orch.set_intensity(engagement_id, intensity)
    except ValueError as e:
        return {"error": str(e), "engagement_id": engagement_id}
    return {
        "engagement_id": engagement_id,
        "intensity": intensity,
        "applied_live": orch.is_running,
    }


# ─── Campaign Management ────────────────────────────────────────────────


@mcp.tool()
async def start_campaign(
    targets: list[str],
    scope: str = "full",
    intensity: str = "normal",
) -> dict[str, Any]:
    """Start a multi-target campaign. Creates one engagement per target.

    Accepts a list of IPs, hostnames, or URLs.
    """
    db = get_findings_db()
    campaign_id = await db.create_campaign(
        name=f"Campaign ({len(targets)} targets)",
        targets=targets,
    )

    engagements = []
    for target in targets:
        eng = await db.create_engagement(
            target=target,
            scope=scope,
            intensity=intensity,
            campaign_id=campaign_id,
        )
        engagements.append(eng["id"])

    return {
        "campaign_id": campaign_id,
        "targets": len(targets),
        "engagement_ids": engagements,
        "status": "created",
    }


@mcp.tool()
async def get_campaign_summary(campaign_id: str) -> dict[str, Any]:
    """Get aggregated summary across all engagements in a campaign."""
    db = get_findings_db()
    return await db.get_campaign_summary(campaign_id)


# ─── Server Entry Point ──────────────────────────────────────────────────


def run_server(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8765):
    """Start the MCP server."""
    logging.basicConfig(level=logging.INFO)
    logger.info(f"Starting pentest-tools MCP server v0.1.0 ({transport})")

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    run_server()

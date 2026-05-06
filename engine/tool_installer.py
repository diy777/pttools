"""Tool dependency manager for pentest-tools.

Handles detection, installation, and validation of external security tools.
Supports tiered installation profiles based on disk/network constraints.
"""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


class InstallTier(str, Enum):
    CORE = "core"
    RECOMMENDED = "recommended"
    FULL = "full"


class InstallMethod(str, Enum):
    APT = "apt"
    GO = "go"
    PIP = "pip"
    CARGO = "cargo"
    SNAP = "snap"
    MANUAL = "manual"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    command: str
    tier: InstallTier
    method: InstallMethod
    install_cmd: tuple[str, ...]
    category: str
    size_mb: int = 0
    description: str = ""


TOOL_CATALOG: tuple[ToolSpec, ...] = (
    # Core tier (~200 MB): essentials for any engagement
    ToolSpec("nmap", "nmap", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "nmap"), "network", 25,
             "Port scanner and service detection"),
    ToolSpec("nikto", "nikto", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "nikto"), "web", 15,
             "Web server vulnerability scanner"),
    ToolSpec("sqlmap", "sqlmap", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "sqlmap"), "web", 20,
             "SQL injection detection and exploitation"),
    ToolSpec("whatweb", "whatweb", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "whatweb"), "recon", 10,
             "Web technology fingerprinting"),
    ToolSpec("sslscan", "sslscan", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "sslscan"), "network", 5,
             "SSL/TLS configuration scanner"),
    ToolSpec("dnsutils", "dig", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "dnsutils"), "recon", 5,
             "DNS lookup utilities"),
    ToolSpec("whois", "whois", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "whois"), "recon", 2,
             "Domain registration lookups"),
    ToolSpec("curl", "curl", InstallTier.CORE, InstallMethod.APT,
             ("apt-get", "install", "-y", "curl"), "recon", 5,
             "HTTP client"),
    ToolSpec("nuclei", "nuclei", InstallTier.CORE, InstallMethod.GO,
             ("go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"), "web", 50,
             "Template-based vulnerability scanner"),

    # Recommended tier (~500 MB): solid coverage for most engagements
    ToolSpec("gobuster", "gobuster", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/OJ/gobuster/v3@latest"), "web", 15,
             "Directory and DNS brute-forcing"),
    ToolSpec("ffuf", "ffuf", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/ffuf/ffuf/v2@latest"), "web", 15,
             "Fast web fuzzer"),
    ToolSpec("httpx", "httpx", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"), "recon", 20,
             "HTTP probing and tech detection"),
    ToolSpec("subfinder", "subfinder", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"), "recon", 20,
             "Subdomain enumeration"),
    ToolSpec("naabu", "naabu", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"), "network", 15,
             "Fast port scanner"),
    ToolSpec("katana", "katana", InstallTier.RECOMMENDED, InstallMethod.GO,
             ("go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"), "web", 15,
             "Web crawler"),
    ToolSpec("wafw00f", "wafw00f", InstallTier.RECOMMENDED, InstallMethod.PIP,
             ("pip", "install", "wafw00f"), "web", 5,
             "WAF detection"),
    ToolSpec("dirsearch", "dirsearch", InstallTier.RECOMMENDED, InstallMethod.PIP,
             ("pip", "install", "dirsearch"), "web", 5,
             "Web path brute-forcer"),
    ToolSpec("wpscan", "wpscan", InstallTier.RECOMMENDED, InstallMethod.APT,
             ("apt-get", "install", "-y", "wpscan"), "web", 30,
             "WordPress vulnerability scanner"),
    ToolSpec("hydra", "hydra", InstallTier.RECOMMENDED, InstallMethod.APT,
             ("apt-get", "install", "-y", "hydra"), "network", 10,
             "Brute-force password testing"),
    ToolSpec("john", "john", InstallTier.RECOMMENDED, InstallMethod.APT,
             ("apt-get", "install", "-y", "john"), "network", 15,
             "Password hash cracker"),
    ToolSpec("hashcat", "hashcat", InstallTier.RECOMMENDED, InstallMethod.APT,
             ("apt-get", "install", "-y", "hashcat"), "network", 20,
             "GPU-accelerated hash cracker"),

    # Full tier (~2 GB+): everything for deep engagements
    ToolSpec("metasploit", "msfconsole", InstallTier.FULL, InstallMethod.APT,
             ("apt-get", "install", "-y", "metasploit-framework"), "exploit", 500,
             "Exploitation framework"),
    ToolSpec("responder", "responder", InstallTier.FULL, InstallMethod.APT,
             ("apt-get", "install", "-y", "responder"), "ad", 20,
             "LLMNR/NBT-NS/MDNS poisoner"),
    ToolSpec("crackmapexec", "crackmapexec", InstallTier.FULL, InstallMethod.PIP,
             ("pip", "install", "crackmapexec"), "ad", 40,
             "AD/SMB pentesting toolkit"),
    ToolSpec("bloodhound-python", "bloodhound-python", InstallTier.FULL, InstallMethod.PIP,
             ("pip", "install", "bloodhound"), "ad", 15,
             "AD relationship data collector"),
    ToolSpec("amass", "amass", InstallTier.FULL, InstallMethod.GO,
             ("go", "install", "github.com/owasp-amass/amass/v4/...@master"), "recon", 50,
             "Attack surface mapping"),
    ToolSpec("dalfox", "dalfox", InstallTier.FULL, InstallMethod.GO,
             ("go", "install", "github.com/hahwul/dalfox/v2@latest"), "web", 15,
             "XSS scanner"),
    ToolSpec("arjun", "arjun", InstallTier.FULL, InstallMethod.PIP,
             ("pip", "install", "arjun"), "web", 5,
             "HTTP parameter discovery"),
    ToolSpec("xsstrike", "xsstrike", InstallTier.FULL, InstallMethod.PIP,
             ("pip", "install", "xsstrike"), "web", 5,
             "XSS detection"),
    ToolSpec("testssl", "testssl.sh", InstallTier.FULL, InstallMethod.APT,
             ("apt-get", "install", "-y", "testssl.sh"), "network", 10,
             "TLS/SSL cipher testing"),
    ToolSpec("aircrack-ng", "aircrack-ng", InstallTier.FULL, InstallMethod.APT,
             ("apt-get", "install", "-y", "aircrack-ng"), "wireless", 20,
             "Wireless network auditing"),
)


def detect_os() -> str:
    if os.path.exists("/etc/debian_version"):
        return "debian"
    if os.path.exists("/etc/redhat-release"):
        return "redhat"
    if platform.system() == "Darwin":
        return "macos"
    return "unknown"


def has_go() -> bool:
    return shutil.which("go") is not None


def has_pip() -> bool:
    return shutil.which("pip") is not None or shutil.which("pip3") is not None


def audit_tools(tier: InstallTier | None = None) -> dict[str, Any]:
    """Check which tools are installed and which are missing."""
    installed: list[ToolSpec] = []
    missing: list[ToolSpec] = []

    for tool in TOOL_CATALOG:
        if tier and tool.tier.value > tier.value:
            continue
        if shutil.which(tool.command):
            installed.append(tool)
        else:
            missing.append(tool)

    total_missing_mb = sum(t.size_mb for t in missing)
    return {
        "installed": installed,
        "missing": missing,
        "total_missing_mb": total_missing_mb,
        "go_available": has_go(),
        "pip_available": has_pip(),
    }


def print_audit(audit: dict[str, Any]) -> None:
    """Print a rich table showing tool install status."""
    table = Table(title="Security Tool Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Tier")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Size")

    for tool in audit["installed"]:
        table.add_row(
            tool.name,
            tool.tier.value,
            tool.category,
            "[green]Installed[/green]",
            f"{tool.size_mb}MB",
        )
    for tool in audit["missing"]:
        table.add_row(
            tool.name,
            tool.tier.value,
            tool.category,
            "[red]Missing[/red]",
            f"{tool.size_mb}MB",
        )

    console.print(table)
    console.print(f"\n[bold]Missing tools need ~{audit['total_missing_mb']}MB[/bold]")
    if not audit["go_available"]:
        console.print("[yellow]Go toolchain not found. Go-based tools will be skipped.[/yellow]")


def install_tool(tool: ToolSpec, sudo_password: str | None = None) -> tuple[bool, str]:
    """Install a single tool. Returns (success, message)."""
    if shutil.which(tool.command):
        return True, f"{tool.name} already installed"

    if tool.method == InstallMethod.APT:
        if sudo_password:
            # Pipe the password to sudo's stdin instead of using shell=True with
            # an f-string (CWE-78 risk if the password contained shell metachars).
            result = subprocess.run(
                ["sudo", "-S"] + list(tool.install_cmd),
                input=sudo_password + "\n",
                capture_output=True, text=True, timeout=300,
            )
        else:
            result = subprocess.run(
                ["sudo"] + list(tool.install_cmd), capture_output=True, text=True, timeout=300
            )
    elif tool.method == InstallMethod.GO:
        if not has_go():
            return False, "Go toolchain not installed"
        env = os.environ.copy()
        env["GOPATH"] = os.path.expanduser("~/go")
        env["PATH"] = env["PATH"] + ":" + os.path.expanduser("~/go/bin")
        result = subprocess.run(
            list(tool.install_cmd), capture_output=True, text=True, timeout=600, env=env
        )
    elif tool.method == InstallMethod.PIP:
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
        pip_argv: list[str] = list(tool.install_cmd)
        pip_argv[0] = pip_cmd
        result = subprocess.run(pip_argv, capture_output=True, text=True, timeout=300)
    else:
        return False, f"Unsupported install method: {tool.method}"

    if result.returncode == 0:
        return True, f"{tool.name} installed"
    return False, f"Failed: {result.stderr[:200]}"


def install_tier(
    tier: InstallTier,
    sudo_password: str | None = None,
    skip_tools: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Install all tools up to a given tier."""
    tier_order = {InstallTier.CORE: 0, InstallTier.RECOMMENDED: 1, InstallTier.FULL: 2}
    target_level = tier_order[tier]

    to_install = [
        t for t in TOOL_CATALOG
        if tier_order[t.tier] <= target_level
        and t.name not in skip_tools
        and not shutil.which(t.command)
    ]

    if not to_install:
        console.print("[green]All tools for this tier are already installed.[/green]")
        return {"installed": 0, "failed": 0, "skipped": 0}

    # Run apt-get update once if any APT tools are needed
    apt_tools = [t for t in to_install if t.method == InstallMethod.APT]
    if apt_tools:
        console.print("[dim]Updating package index...[/dim]")
        if sudo_password:
            # See note in install_tool: pipe the password via stdin, never f-string into a shell.
            subprocess.run(
                ["sudo", "-S", "apt-get", "update", "-qq"],
                input=sudo_password + "\n",
                text=True, capture_output=True, timeout=120,
            )
        else:
            subprocess.run(
                ["sudo", "apt-get", "update", "-qq"],
                capture_output=True, timeout=120,
            )

    installed_count = 0
    failed_count = 0
    results: list[dict[str, str]] = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"Installing {len(to_install)} tools...", total=len(to_install))

        for tool in to_install:
            progress.update(task, description=f"Installing {tool.name}...")
            ok, msg = install_tool(tool, sudo_password)
            if ok:
                installed_count += 1
                results.append({"tool": tool.name, "status": "ok", "message": msg})
            else:
                failed_count += 1
                results.append({"tool": tool.name, "status": "failed", "message": msg})
            progress.advance(task)

    console.print(f"\n[bold green]{installed_count} installed[/bold green], [bold red]{failed_count} failed[/bold red]")
    for r in results:
        if r["status"] == "failed":
            console.print(f"  [red]{r['tool']}: {r['message']}[/red]")

    return {"installed": installed_count, "failed": failed_count, "skipped": len(skip_tools), "details": results}


def interactive_setup(sudo_password: str | None = None) -> dict[str, Any]:
    """Run the interactive setup flow. Returns install results."""
    console.print(Panel.fit(
        "[bold cyan]pentest-tools Tool Setup[/bold cyan]\n\n"
        "This will install external security tools needed for pentesting.\n"
        "All tools are open source. You can skip any tier.",
        title="Setup",
    ))

    audit = audit_tools()
    print_audit(audit)

    console.print("\n[bold]Installation Tiers:[/bold]")
    console.print("  [cyan]core[/cyan]         ~200MB  Essential scanners (nmap, nuclei, nikto, sqlmap)")
    console.print("  [cyan]recommended[/cyan]   ~500MB  Core + fuzzers, crawlers, password tools")
    console.print("  [cyan]full[/cyan]          ~2GB+   Everything including Metasploit, wireless, AD tools")
    console.print("  [cyan]skip[/cyan]          0MB     Install nothing, use only built-in scanners\n")

    return audit

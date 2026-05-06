"""
Tool Registry — Manages 150+ security tool wrappers with intelligent output parsing.

Each tool is defined with metadata, command templates, and output parsers
that convert raw tool output into structured findings.
"""

import asyncio
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

BLOCKED_ARG_KEYS = frozenset({
    "script", "script-args", "output", "oN", "oX", "oG", "oA",
    "exec", "eval", "command", "cmd", "shell", "system",
    "upload", "download", "write", "config",
})

# Bundled fallback wordlist ships with the package. Keeps gobuster/ffuf usable
# on systems that don't have /usr/share/wordlists (i.e., everything that isn't Kali).
_BUNDLED_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")

_WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    _BUNDLED_WORDLIST,
)


def _find_wordlist() -> str:
    """Return the first wordlist that exists, falling back to the bundled one."""
    for path in _WORDLIST_CANDIDATES:
        if os.path.exists(path):
            return path
    return _BUNDLED_WORDLIST


@dataclass
class SecurityTool:
    name: str
    category: str
    description: str
    command: str
    required_deps: list[str] = field(default_factory=list)
    build_args: Callable | None = None
    parse_output: Callable | None = None
    allowed_args: set[str] | None = None

    # Class-level cache + intensity injection. Set via configure_cache().
    _cache: ClassVar[Any] = None
    _cache_intensity: ClassVar[str] = "normal"
    _cache_disabled: ClassVar[bool] = False

    def is_installed(self) -> bool:
        return shutil.which(self.command) is not None

    def _build_command(self, target: str, args: dict[str, Any] | None = None) -> list[str]:
        if self.build_args:
            return self.build_args(target, args)
        cmd_parts = [self.command]
        if args:
            for key, value in args.items():
                if key in BLOCKED_ARG_KEYS:
                    continue
                if self.allowed_args and key not in self.allowed_args:
                    continue
                if not re.match(r"^[a-zA-Z0-9_-]+$", key):
                    continue
                if isinstance(value, bool) and value:
                    cmd_parts.append(f"--{key}")
                elif isinstance(value, (str, int)):
                    str_val = str(value)
                    if any(c in str_val for c in (";", "|", "&", "`", "$", "\n")):
                        continue
                    cmd_parts.extend([f"--{key}", str_val])
        cmd_parts.append(target)
        return cmd_parts

    async def execute(self, target: str, args: dict[str, Any] | None = None, timeout: float = 600.0) -> dict[str, Any]:
        cache = type(self)._cache
        intensity = type(self)._cache_intensity
        cache_disabled = type(self)._cache_disabled
        cache_key = None

        if cache is not None and not cache_disabled:
            from engine.cache import make_key
            cache_key = make_key(self.name, target, intensity, args)
            cached = await cache.get(cache_key)
            if cached is not None:
                cached["cache_hit"] = True
                # Even on a cache hit the engagement still "ran" this tool
                # (from the auditor's point of view). Persist a tool_results
                # row so the engagement audit reflects every tool that produced
                # findings, regardless of whether the data came from cache.
                await _persist_tool_result(cached, args)
                return cached

        start = time.time()
        cmd_parts = self._build_command(target, args)

        result: dict[str, Any] = {
            "tool": self.name,
            "target": target,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration": 0.0,
            "findings": [],
            "cache_hit": False,
        }

        should_persist = True
        registered_pid: int | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Register the live PID so `pttools ps` / list_processes can see it
            # and `pttools kill <pid>` can stop a runaway tool without aborting
            # the whole engagement.
            try:
                from engine.exec_context import current_engagement_id
                from engine.process_registry import ProcessRecord, get_default_registry

                eid = current_engagement_id.get()
                get_default_registry().register(
                    ProcessRecord(
                        pid=proc.pid,
                        tool=self.name,
                        target=target,
                        started_at=start,
                        engagement_id=eid,
                        cmd=self.command,
                    )
                )
                registered_pid = proc.pid
            except Exception as e:  # noqa: BLE001
                # Registry failures must never break tool execution.
                import logging
                logging.getLogger("pentest-tools.tools").debug(
                    f"process registry register failed for {self.name}: {e}"
                )
            # Wrap communicate() in wait_for so we can kill the subprocess on
            # timeout instead of orphaning it. Orphaned subprocesses keep their
            # pipe fds attached to the asyncio loop, which prevents clean shutdown
            # and was the root cause of pttools hanging for minutes after
            # "Engagement complete" was printed.
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                exit_code = proc.returncode
            except asyncio.TimeoutError:
                proc.kill()
                # Drain pipes and reap zombie. Bound the wait so a stuck kill
                # doesn't replace one hang with another.
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
                except (asyncio.TimeoutError, Exception):
                    stdout, stderr = b"", b""
                exit_code = -1
            duration = time.time() - start

            result.update({
                "exit_code": exit_code,
                "stdout": stdout.decode(errors="replace") if stdout else "",
                "stderr": stderr.decode(errors="replace") if stderr else "",
                "duration": round(duration, 2),
            })

            if self.parse_output:
                try:
                    result["findings"] = self.parse_output(result)
                except Exception as e:
                    # Parser bug must not lose the audit row. Log and continue.
                    import logging
                    logging.getLogger("pentest-tools.tools").warning(
                        f"parse_output failed for {self.name}: {e}"
                    )

            if cache is not None and not cache_disabled and cache_key and exit_code == 0:
                from engine.cache import ttl_for
                ttl = ttl_for(self.category)
                if ttl > 0:
                    try:
                        await cache.put(
                            cache_key,
                            result,
                            tool=self.name,
                            target=target,
                            intensity=intensity,
                            ttl=ttl,
                        )
                    except Exception as e:
                        # Cache write failure must not lose the audit row.
                        import logging
                        logging.getLogger("pentest-tools.tools").warning(
                            f"cache.put failed for {self.name}: {e}"
                        )

            return result
        except FileNotFoundError:
            # Binary isn't installed. Skip the audit row: it would just be
            # noise about a missing tool, not a record of work done.
            should_persist = False
            return {"error": f"Tool '{self.command}' not found", "tool": self.name, "findings": []}
        except Exception as e:
            # Subprocess spawn or communicate failed for some other reason.
            # The engagement tried to run this tool, so persist the audit row
            # with the error captured.
            result["error"] = str(e)
            result["exit_code"] = -2
            return result
        finally:
            # Unregister the PID once the subprocess has exited (or failed
            # to spawn). Safe to call with None or unknown PID.
            if registered_pid is not None:
                try:
                    from engine.process_registry import get_default_registry
                    get_default_registry().unregister(registered_pid)
                except Exception as e:  # noqa: BLE001
                    import logging
                    logging.getLogger("pentest-tools.tools").debug(
                        f"process registry unregister failed for pid={registered_pid}: {e}"
                    )
            # Always persist the audit row when we attempted execution,
            # including timeouts, parser errors, and cache write failures.
            # Only the "binary missing" case skips this.
            if should_persist:
                await _persist_tool_result(result, args)


def configure_cache(cache: Any | None, intensity: str = "normal", disabled: bool = False) -> None:
    """Wire a ToolResultCache (or None) into all SecurityTool instances."""
    SecurityTool._cache = cache
    SecurityTool._cache_intensity = intensity
    SecurityTool._cache_disabled = disabled


async def _persist_tool_result(result: dict[str, Any], args: dict[str, Any] | None) -> None:
    """Write tool execution to findings_db.tool_results if an engagement context is active.

    No-op when exec_context hasn't been set (bare tool calls, unit tests, etc.).
    Swallows DB errors so a persistence hiccup can never break tool execution.
    """
    try:
        from engine.exec_context import get_exec_context
    except Exception:
        return
    engagement_id, db = get_exec_context()
    if not engagement_id or db is None:
        return
    try:
        output = (result.get("stdout", "") or "") + (result.get("stderr", "") or "")
        await db.add_tool_result({
            "engagement_id": engagement_id,
            "tool_name": result.get("tool", ""),
            "target": result.get("target", ""),
            "args": args or {},
            "output": output,
            "exit_code": result.get("exit_code", 0),
            "duration": result.get("duration", 0.0),
        })
    except Exception as e:
        import logging
        logging.getLogger("pentest-tools.tools").warning(f"tool_result persistence failed: {e}")


# ─── Output Parsers ──────────────────────────────────────────────────────


def parse_nmap(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        port_match = re.match(r"(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?", line.strip())
        if port_match:
            port, state, service, version = port_match.groups()
            if state == "open":
                severity = "info"
                if service in ("ssh", "ftp", "telnet", "rsh", "rlogin") or service in (
                    "smb",
                    "microsoft-ds",
                    "netbios-ssn",
                ):
                    severity = "medium"
                elif service in ("mysql", "postgres", "mssql", "oracle", "redis", "mongodb"):
                    severity = "high"
                elif service in ("http", "https", "http-alt"):
                    severity = "low"
                findings.append(
                    {
                        "title": f"Open port {port}/tcp — {service}",
                        "description": f"Port {port}/tcp is open running {service}"
                        + (f" ({version})" if version else ""),
                        "severity": severity,
                        "category": "network",
                        "tool_source": "nmap",
                        "target": target,
                        "evidence": line.strip(),
                        "raw_output": line.strip(),
                    }
                )
    vuln_match = re.findall(r"VULNERABLE:.*?\n.*?\n(?:.*?\n)*?\s*State: VULNERABLE", stdout, re.MULTILINE)
    for v in vuln_match:
        findings.append(
            {
                "title": f"Nmap NSE vulnerability: {v.splitlines()[0].replace('VULNERABLE: ', '')}",
                "description": v.strip(),
                "severity": "high",
                "category": "vulnerability",
                "tool_source": "nmap",
                "target": target,
                "evidence": v.strip(),
            }
        )
    return findings


# Nuclei info-level templates that are pure tech-fingerprint noise — already
# covered by the dedicated tech_fingerprint phase (whatweb/httpx). Dropping
# them keeps the findings table focused on actionable signal.
_NUCLEI_NOISE_TEMPLATES = (
    "tech-detect",
    "fingerprint",
    "favicon-detect",
    "wappalyzer",
    "robots-txt",
    "options-method",
    "http-trace",
    "server-header",
    "powered-by",
    "x-powered-by",
)

# Nuclei info templates that are real security observations — bump from
# "info" to "low" so they actually surface in user reports (default reports
# filter info-level out).
_NUCLEI_BUMP_TO_LOW = (
    "missing-csp",
    "missing-hsts",
    "missing-x-frame-options",
    "missing-x-content-type",
    "missing-referrer-policy",
    "missing-permissions-policy",
    "cookies-without-secure",
    "cookies-without-httponly",
    "cookies-without-samesite",
    "directory-listing",
    "exposed-",
    "open-redirect",
)


def _calibrate_nuclei_severity(line: str, raw_severity: str) -> str | None:
    """Return the calibrated severity, or None to drop the finding entirely.

    Nuclei templates ship with their own severity but the info tier is
    swamped with tech-detect noise. This filter drops fingerprint-style
    noise (already covered elsewhere in the pipeline) and bumps real
    security misconfigs from info to low.
    """
    lower = line.lower()
    if raw_severity == "info":
        if any(noise in lower for noise in _NUCLEI_NOISE_TEMPLATES):
            return None
        if any(bump in lower for bump in _NUCLEI_BUMP_TO_LOW):
            return "low"
    return raw_severity


def parse_nuclei(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
    for line in stdout.splitlines():
        if "[" in line and "]" in line and any(s in line for s in ["critical", "high", "medium", "low", "info"]):
            sev_match = re.search(r"\[(critical|high|medium|low|info)\]", line)
            if sev_match:
                raw_severity = sev_match.group(1)
                calibrated = _calibrate_nuclei_severity(line, raw_severity)
                if calibrated is None:
                    continue
                findings.append(
                    {
                        "title": f"Nuclei: {line.strip()}",
                        "description": line.strip(),
                        "severity": severity_map.get(calibrated, "info"),
                        "category": "vulnerability",
                        "tool_source": "nuclei",
                        "target": target,
                        "evidence": line.strip(),
                    }
                )
    return findings


def parse_sqlmap(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    if "is vulnerable" in stdout.lower() or "injection found" in stdout.lower():
        inj_type = "SQL injection"
        if "union" in stdout.lower():
            inj_type = "UNION-based SQL injection"
        elif "boolean" in stdout.lower():
            inj_type = "Boolean-based blind SQL injection"
        elif "time" in stdout.lower():
            inj_type = "Time-based blind SQL injection"
        elif "error" in stdout.lower():
            inj_type = "Error-based SQL injection"
        findings.append(
            {
                "title": f"SQL injection detected — {inj_type}",
                "description": f"sqlmap confirmed {inj_type} on {target}",
                "severity": "critical",
                "category": "injection",
                "tool_source": "sqlmap",
                "target": target,
                "evidence": stdout[:2000],
            }
        )
    return findings


def parse_gobuster(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        if "Status: " in line or "(Status: " in line:
            status_match = re.search(r"Status:\s*(\d+)", line)
            if status_match:
                status_code = int(status_match.group(1))
                path = line.split()[0] if line.split() else "/"
                severity = "info"
                if status_code == 200:
                    severity = "low"
                elif status_code in (301, 302):
                    severity = "info"
                elif status_code == 403:
                    severity = "medium"
                elif status_code == 500:
                    severity = "high"
                findings.append(
                    {
                        "title": f"Discovered path: {path} (HTTP {status_code})",
                        "description": f"Gobuster found {path} returning HTTP {status_code}",
                        "severity": severity,
                        "category": "discovery",
                        "tool_source": "gobuster",
                        "target": target,
                        "evidence": line.strip(),
                    }
                )
    return findings


# Nikto observations that look like security misconfigs — bumped to "low"
# so they surface in user-facing reports rather than getting dropped as
# info noise. Each pattern is matched case-insensitively against the line.
_NIKTO_BUMP_TO_LOW = (
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "strict-transport-security",
    "content-security-policy",
    "referrer-policy",
    "httponly",
    "secure flag",
    "samesite",
    "directory indexing",
    "directory listing",
)

# Nikto observations that duplicate other phases or are trivia. Drop them
# rather than spamming the findings table with low-signal info entries.
_NIKTO_NOISE = (
    "robots.txt",
    "favicon",
    "the anti-clickjacking",  # explained elsewhere via header check
    "retrieved x-powered-by",
    "server may leak inodes",
    "uncommon header",
)


def parse_nikto(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        if line.strip().startswith("+ ") and not line.startswith("+ "):
            continue
        if "+ " in line:
            content = line.split("+ ", 1)[-1].strip() if "+ " in line else ""
            if not content:
                continue
            lower = content.lower()
            if any(noise in lower for noise in _NIKTO_NOISE):
                continue
            is_high_signal = any(
                kw in lower
                for kw in ["vuln", "exploit", "backdoor", "injection", "xss", "sqli", "overflow", "disclosure"]
            )
            is_misconfig = any(pat in lower for pat in _NIKTO_BUMP_TO_LOW)
            if is_high_signal:
                severity = "high"
                category = "vulnerability"
            elif is_misconfig:
                severity = "low"
                category = "misconfiguration"
            else:
                severity = "info"
                category = "discovery"
            findings.append(
                {
                    "title": f"Nikto: {content[:120]}",
                    "description": content,
                    "severity": severity,
                    "category": category,
                    "tool_source": "nikto",
                    "target": target,
                    "evidence": line.strip(),
                }
            )
    return findings


def parse_wafw00f(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    waf_match = re.search(r"Detected WAF:\s*(\S+)", stdout)
    if waf_match:
        waf_name = waf_match.group(1)
        findings.append(
            {
                "title": f"WAF detected: {waf_name}",
                "description": f"A Web Application Firewall ({waf_name}) was detected on {target}",
                "severity": "info",
                "category": "discovery",
                "tool_source": "wafw00f",
                "target": target,
                "evidence": stdout.strip(),
            }
        )
    return findings


def parse_subfinder(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        subdomain = line.strip()
        if subdomain and "." in subdomain and subdomain != target:
            findings.append(
                {
                    "title": f"Subdomain discovered: {subdomain}",
                    "description": f"Passive enumeration found subdomain {subdomain}",
                    "severity": "info",
                    "category": "recon",
                    "tool_source": "subfinder",
                    "target": subdomain,
                    "evidence": subdomain,
                }
            )
    return findings


def parse_amass(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    result.get("target", "")
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            subdomain = parts[0]
            source = parts[-1] if len(parts) > 1 else "unknown"
            if "." in subdomain:
                findings.append(
                    {
                        "title": f"Subdomain discovered: {subdomain}",
                        "description": f"Amass found {subdomain} via {source}",
                        "severity": "info",
                        "category": "recon",
                        "tool_source": "amass",
                        "target": subdomain,
                        "evidence": line.strip(),
                    }
                )
    return findings


def parse_whatweb(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    tech_match = re.findall(r"\[(\d+[A-Z]*)\]\s+(\S+)\s+\[(.*?)\]", stdout)
    for _code, url, techs in tech_match:
        for tech in techs.split(","):
            tech = tech.strip()
            if tech:
                findings.append(
                    {
                        "title": f"Technology detected: {tech}",
                        "description": f"WhatWeb identified {tech} on {url}",
                        "severity": "info",
                        "category": "discovery",
                        "tool_source": "whatweb",
                        "target": target,
                        "evidence": tech,
                    }
                )
    return findings


def parse_hydra(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    if "host:" in stdout and "login:" in stdout and "password:" in stdout:
        for line in stdout.splitlines():
            if "login:" in line and "password:" in line:
                login_match = re.search(r"login:\s*(\S+)", line)
                pass_match = re.search(r"password:\s*(\S+)", line)
                if login_match and pass_match:
                    findings.append(
                        {
                            "title": f"Valid credentials found: {login_match.group(1)}:{pass_match.group(1)}",
                            "description": f"Hydra found valid credentials for {target}",
                            "severity": "critical",
                            "category": "authentication",
                            "tool_source": "hydra",
                            "target": target,
                            "evidence": line.strip(),
                        }
                    )
    return findings


def parse_trufflehog(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        if "Detector Type:" in line or "Secret:" in line or "decoder_type" in line:
            findings.append(
                {
                    "title": "Secret/credential exposed in repository",
                    "description": f"TruffleHog found a secret in {target}",
                    "severity": "critical",
                    "category": "secret",
                    "tool_source": "trufflehog",
                    "target": target,
                    "evidence": line.strip()[:500],
                }
            )
    return findings


def parse_gitleaks(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        if "rule:" in line.lower() or "secret:" in line.lower() or "author:" in line.lower():
            findings.append(
                {
                    "title": "Git secret detected",
                    "description": f"Gitleaks found a secret in {target}",
                    "severity": "critical",
                    "category": "secret",
                    "tool_source": "gitleaks",
                    "target": target,
                    "evidence": line.strip()[:500],
                }
            )
    return findings


def parse_checksec(result: dict) -> list[dict]:
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    if "No RELRO" in stdout:
        findings.append(
            {
                "title": "No RELRO protection",
                "description": "Binary compiled without RELRO",
                "severity": "medium",
                "category": "binary",
                "tool_source": "checksec",
                "target": target,
                "evidence": stdout[:500],
            }
        )
    if "No canary found" in stdout:
        findings.append(
            {
                "title": "No stack canary",
                "description": "Binary compiled without stack canaries",
                "severity": "medium",
                "category": "binary",
                "tool_source": "checksec",
                "target": target,
                "evidence": stdout[:500],
            }
        )
    if "NX disabled" in stdout:
        findings.append(
            {
                "title": "NX bit disabled",
                "description": "Binary compiled without NX (DEP)",
                "severity": "high",
                "category": "binary",
                "tool_source": "checksec",
                "target": target,
                "evidence": stdout[:500],
            }
        )
    if "PIE disabled" in stdout:
        findings.append(
            {
                "title": "No PIE",
                "description": "Binary compiled without Position Independent Executable",
                "severity": "medium",
                "category": "binary",
                "tool_source": "checksec",
                "target": target,
                "evidence": stdout[:500],
            }
        )
    return findings


_FFUF_HIGH_SIGNAL_PATHS = frozenset({
    ".git", ".env", ".htaccess", ".htpasswd", ".svn",
    "admin", "administrator", "backup", "backup.zip", "backups",
    "config", "config.json", "config.php", "config.yml", "config.yaml",
    "phpinfo", "phpinfo.php", "phpmyadmin",
    "api", "api/v1", "api/v2", "graphql",
    "swagger", "swagger-ui", "swagger.json",
    "secrets", "secret", "passwords", "password",
    "private", "internal", "intranet",
    "console", "debug", "metrics", "server-status",
    ".well-known",
})


def parse_ffuf(result: dict) -> list[dict]:
    """ffuf in silent mode emits one matched path per line. Each line is a
    discovered endpoint (status already filtered server-side via -mc).
    Promotes high-signal paths (admin, .git, .env, backup, config, api) to
    medium severity so they surface in chains; everything else stays info."""
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    for line in stdout.splitlines():
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        # ffuf -s prints just the matched word/path. Skip status banners or
        # non-path artefacts.
        if any(c in path for c in (" ", "\t")):
            continue
        is_high_signal = path.lower() in _FFUF_HIGH_SIGNAL_PATHS or any(
            path.lower().startswith(p) for p in (".git", ".env", "backup", "admin", "config")
        )
        severity = "medium" if is_high_signal else "info"
        category = "exposure" if is_high_signal else "discovery"
        findings.append({
            "title": f"Discovered path: /{path}",
            "description": f"ffuf surfaced /{path} as a reachable endpoint on {target}",
            "severity": severity,
            "category": category,
            "tool_source": "ffuf",
            "target": target,
            "evidence": f"GET {target.rstrip('/')}/{path}",
        })
    return findings


_ARJUN_PARAM_LINE = re.compile(
    r"(?:parameters?\s+found|discovered\s+parameters?|reflections?|heuristic\s+(?:scanner\s+)?found(?:\s+these\s+parameters)?)\s*:?\s*(.+)$",
    re.IGNORECASE,
)
_ARJUN_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")


def _extract_arjun_params(stdout: str) -> list[str]:
    """Extract parameter names from arjun's stdout.

    arjun's output format varies by version; instead of locking in to one
    layout, scan every line for any of the known param-list intros and pull
    valid identifier names from the rest of the line. Dedupes preserving order.
    """
    seen: set[str] = set()
    params: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _ARJUN_PARAM_LINE.search(line)
        if not m:
            continue
        for name in _ARJUN_NAME_RE.findall(m.group(1)):
            if name in seen:
                continue
            # Filter out arjun's own status words that match identifier regex.
            if name.lower() in {
                "with", "the", "and", "found", "parameters",
                "discovered", "reflections", "heuristic", "scanner",
                "stable", "response", "anomaly", "this", "url",
            }:
                continue
            seen.add(name)
            params.append(name)
    return params


def parse_arjun(result: dict) -> list[dict]:
    """Parse arjun output into a single discovery finding listing the params.

    The actual injection happens later via sqlmap/dalfox using the param list;
    this finding records what was discovered so the audit + chaining stages
    have something to reason about.
    """
    stdout = result.get("stdout", "") or ""
    target = result.get("target", "")
    params = _extract_arjun_params(stdout)
    if not params:
        return []
    return [
        {
            "title": f"Discovered hidden parameters on {target}",
            "description": (
                f"arjun identified {len(params)} hidden GET parameter(s): "
                f"{', '.join(params[:20])}"
            ),
            "severity": "info",
            "category": "discovery",
            "tool_source": "arjun",
            "target": target,
            "evidence": f"params={','.join(params)}",
        }
    ]


def parse_default(result: dict) -> list[dict]:
    """Generic parser for tools without specialized parsers."""
    findings = []
    stdout = result.get("stdout", "")
    target = result.get("target", "")
    tool = result.get("tool", "unknown")
    if stdout.strip() and len(stdout.strip()) > 10:
        findings.append(
            {
                "title": f"{tool} output for {target}",
                "description": stdout.strip()[:500],
                "severity": "info",
                "category": "recon",
                "tool_source": tool,
                "target": target,
                "evidence": stdout.strip()[:1000],
            }
        )
    return findings


# ─── Tool Definitions ────────────────────────────────────────────────────

NETWORK_TOOLS = [
    SecurityTool(
        "nmap",
        "network",
        "Advanced port scanner with NSE scripts",
        "nmap",
        ["nmap"],
        # -O (OS detection) requires root; dropped so the default invocation works
        # under unprivileged users. Users who want OS detection can run nmap-os
        # explicitly with sudo.
        build_args=lambda t, a: ["nmap", "-sV", "-sC", "--script", "vuln", t],
        parse_output=parse_nmap,
    ),
    SecurityTool(
        "masscan",
        "network",
        "High-speed Internet-scale port scanner",
        "masscan",
        ["masscan"],
        build_args=lambda t, a: ["masscan", "-p1-65535", "--rate", "10000", t],
        parse_output=parse_default,
    ),
    SecurityTool(
        "rustscan",
        "network",
        "Ultra-fast port scanner",
        "rustscan",
        ["rustscan"],
        build_args=lambda t, a: ["rustscan", "-a", t, "--", "-sV", "-sC"],
        parse_output=parse_default,
    ),
    SecurityTool("autorecon", "network", "Comprehensive automated reconnaissance", "autorecon", ["autorecon"]),
    SecurityTool(
        "amass",
        "network",
        "Subdomain enumeration and OSINT",
        "amass",
        ["amass"],
        build_args=lambda t, a: ["amass", "enum", "-d", t],
        parse_output=parse_amass,
    ),
    SecurityTool(
        "subfinder",
        "network",
        "Fast passive subdomain discovery",
        "subfinder",
        ["subfinder"],
        build_args=lambda t, a: ["subfinder", "-d", t],
        parse_output=parse_subfinder,
    ),
    SecurityTool("fierce", "network", "DNS reconnaissance and zone transfer", "fierce", ["fierce"]),
    SecurityTool("dnsenum", "network", "DNS information gathering", "dnsenum", ["dnsenum"]),
    SecurityTool(
        "theharvester",
        "network",
        "Email and subdomain harvesting",
        "theHarvester",
        ["theHarvester"],
        build_args=lambda t, a: ["theHarvester", "-d", t, "-b", "all"],
    ),
    SecurityTool("responder", "network", "LLMNR/NBT-NS/MDNS poisoner", "Responder", ["Responder"]),
    SecurityTool("netexec", "network", "Network service exploitation framework", "netexec", ["netexec"]),
    SecurityTool("enum4linux", "network", "SMB enumeration", "enum4linux", ["enum4linux"]),
    SecurityTool("enum4linux-ng", "network", "Advanced SMB enumeration", "enum4linux-ng", ["enum4linux-ng"]),
    SecurityTool("smbmap", "network", "SMB share enumeration", "smbmap", ["smbmap"]),
    SecurityTool("arp-scan", "network", "Network discovery using ARP", "arp-scan", ["arp-scan"]),
    SecurityTool("nbtscan", "network", "NetBIOS name scanning", "nbtscan", ["nbtscan"]),
    SecurityTool("rpcclient", "network", "RPC enumeration", "rpcclient", ["rpcclient"]),
    SecurityTool(
        "whatweb", "network", "Web technology identification", "whatweb", ["whatweb"], parse_output=parse_whatweb
    ),
    SecurityTool("httprobe", "network", "HTTP probing", "httprobe", ["httprobe"]),
    SecurityTool("naabu", "network", "Fast port scanner by ProjectDiscovery", "naabu", ["naabu"]),
    SecurityTool("dnsx", "network", "DNS query toolkit", "dnsx", ["dnsx"]),
    SecurityTool("httpx", "network", "HTTP probing toolkit", "httpx", ["httpx"]),
    SecurityTool(
        "katana",
        "network",
        "Next-gen crawling and spidering",
        "katana",
        ["katana"],
        # -u target, -d depth, -silent suppresses banner, -jc enables JS crawl,
        # -nc disables ANSI codes so stdout is pure URLs (one per line).
        build_args=lambda t, a: ["katana", "-u", t, "-d", "2", "-silent", "-nc", "-jc"],
    ),
    SecurityTool("gau", "network", "Get All URLs from archives", "gau", ["gau"]),
    SecurityTool("waybackurls", "network", "Historical URL discovery", "waybackurls", ["waybackurls"]),
    SecurityTool("dnsrecon", "network", "DNS reconnaissance", "dnsrecon", ["dnsrecon"]),
    SecurityTool("knockpy", "network", "Subdomain enumeration", "knockpy", ["knockpy"]),
    SecurityTool("assetfinder", "network", "Domain asset finder", "assetfinder", ["assetfinder"]),
    SecurityTool(
        "nmap-vulners",
        "network",
        "Nmap vulners NSE script",
        "nmap",
        ["nmap"],
        build_args=lambda t, a: ["nmap", "--script", "vulners", "-sV", t],
    ),
    SecurityTool(
        "nmap-enum",
        "network",
        "Nmap enumeration scripts",
        "nmap",
        ["nmap"],
        build_args=lambda t, a: ["nmap", "--script", "enum", "-sV", t],
    ),
]

WEB_TOOLS = [
    SecurityTool(
        "gobuster",
        "web",
        "Directory/file/DNS enumeration",
        "gobuster",
        ["gobuster"],
        # --no-error suppresses per-request connection errors. -s lists explicit
        # status codes to count as "found" — needed for SPAs (Juice Shop, Next.js)
        # that return 200 for every path. Without an explicit allowlist, gobuster
        # aborts with a wildcard error and finds nothing.
        build_args=lambda t, a: ["gobuster", "dir", "-u", t, "-w", _find_wordlist(), "--no-error", "-s", "204,301,302,307,401,403", "-b", ""],
        parse_output=parse_gobuster,
    ),
    SecurityTool(
        "dirsearch",
        "web",
        "Advanced directory discovery",
        "dirsearch",
        ["dirsearch"],
        build_args=lambda t, a: ["dirsearch", "-u", t],
    ),
    SecurityTool("feroxbuster", "web", "Recursive content discovery", "feroxbuster", ["feroxbuster"]),
    SecurityTool(
        "ffuf",
        "web",
        "Fast web fuzzer",
        "ffuf",
        ["ffuf"],
        # -ac (auto-calibration) sends a random non-existent path first, learns
        # the wildcard response (size + lines + words), and filters every match
        # that fits that fingerprint. Without this, SPAs like Juice Shop return
        # 200 for everything and ffuf reports the entire wordlist as findings.
        build_args=lambda t, a: ["ffuf", "-u", f"{t}/FUZZ", "-w", _find_wordlist(), "-mc", "200,204,301,302,307,401,403", "-ac", "-s"],
        parse_output=parse_ffuf,
    ),
    SecurityTool("dirb", "web", "Web content scanner", "dirb", ["dirb"]),
    SecurityTool(
        "nuclei",
        "web",
        "Vulnerability scanner with templates",
        "nuclei",
        ["nuclei"],
        # Default nuclei runs all 8000+ templates which is unusable in
        # deterministic mode (>5 minutes). Restrict to high-signal categories
        # that surface real vulnerabilities (exposure, misconfig, CVEs, takeover,
        # tech detection) and bump concurrency. Users who want full coverage can
        # call nuclei explicitly with their own template set.
        build_args=lambda t, a: [
            "nuclei", "-u", t,
            "-tags", "exposure,misconfig,cve,takeover,tech,default-logins,exposed-panels",
            "-c", "50",  # concurrency
            "-rl", "200",  # rate limit per second
            "-timeout", "10",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ],
        parse_output=parse_nuclei,
    ),
    SecurityTool(
        "nikto",
        "web",
        "Web server vulnerability scanner",
        "nikto",
        ["nikto"],
        build_args=lambda t, a: ["nikto", "-h", t],
        parse_output=parse_nikto,
    ),
    SecurityTool(
        "sqlmap",
        "web",
        "SQL injection testing",
        "sqlmap",
        ["sqlmap"],
        build_args=lambda t, a: ["sqlmap", "-u", t, "--batch", "--level=3", "--risk=2"],
        parse_output=parse_sqlmap,
    ),
    SecurityTool(
        "wpscan",
        "web",
        "WordPress security scanner",
        "wpscan",
        ["wpscan"],
        build_args=lambda t, a: ["wpscan", "--url", t, "--enumerate", "vp,vt,tt,cb,dbe"],
    ),
    SecurityTool(
        "arjun",
        "web",
        "HTTP parameter discovery",
        "arjun",
        ["arjun"],
        # arjun requires -u to take a URL. --stable reduces false positives
        # by re-checking parameters that look reflected; -t 10 keeps the
        # request rate sane on small targets.
        build_args=lambda t, a: ["arjun", "-u", t, "--stable", "-t", "10"],
        parse_output=parse_arjun,
    ),
    SecurityTool("paramspider", "web", "Parameter mining from archives", "paramspider", ["paramspider"]),
    SecurityTool(
        "dalfox",
        "web",
        "XSS vulnerability scanning",
        "dalfox",
        ["dalfox"],
        # dalfox requires the `url` subcommand for single-URL scans.
        build_args=lambda t, a: ["dalfox", "url", t],
    ),
    SecurityTool("wafw00f", "web", "WAF fingerprinting", "wafw00f", ["wafw00f"], parse_output=parse_wafw00f),
    SecurityTool(
        "testssl",
        "web",
        "SSL/TLS configuration testing",
        "testssl.sh",
        ["testssl.sh"],
        build_args=lambda t, a: ["testssl.sh", t],
    ),
    SecurityTool("sslscan", "web", "SSL/TLS cipher enumeration", "sslscan", ["sslscan"]),
    SecurityTool("sslyze", "web", "SSL/TLS configuration analyzer", "sslyze", ["sslyze"]),
    SecurityTool("jwt_tool", "web", "JWT testing", "jwt_tool", ["jwt_tool"]),
    SecurityTool("commix", "web", "Command injection exploitation", "commix", ["commix"]),
    SecurityTool("nosqlmap", "web", "NoSQL injection testing", "nosqlmap", ["nosqlmap"]),
    SecurityTool("tplmap", "web", "Template injection exploitation", "tplmap", ["tplmap"]),
    SecurityTool("wfuzz", "web", "Web application fuzzer", "wfuzz", ["wfuzz"]),
    SecurityTool("xsstrike", "web", "Advanced XSS detection", "xsstrike", ["xsstrike"]),
    SecurityTool("x8", "web", "Hidden parameter discovery", "x8", ["x8"]),
    SecurityTool("jaeles", "web", "Advanced vulnerability scanning", "jaeles", ["jaeles"]),
    SecurityTool("hakrawler", "web", "Fast web endpoint discovery", "hakrawler", ["hakrawler"]),
    SecurityTool("uro", "web", "URL filtering and deduplication", "uro", ["uro"]),
    SecurityTool("qsreplace", "web", "Query string replacement", "qsreplace", ["qsreplace"]),
    SecurityTool("anew", "web", "Append new lines efficiently", "anew", ["anew"]),
    SecurityTool("subjack", "web", "Subdomain takeover checker", "subjack", ["subjack"]),
    SecurityTool("kiterunner", "web", "API endpoint discovery", "kr", ["kr"]),
    SecurityTool("dirhunt", "web", "Web crawler without brute force", "dirhunt", ["dirhunt"]),
    SecurityTool("joomscan", "web", "Joomla vulnerability scanner", "joomscan", ["joomscan"]),
    SecurityTool("droopescan", "web", "CMS scanner", "droopescan", ["droopescan"]),
    SecurityTool("cmsmap", "web", "Multi-CMS scanner", "cmsmap", ["cmsmap"]),
    SecurityTool("skipfish", "web", "Web application security scanner", "skipfish", ["skipfish"]),
    SecurityTool("graphql-voyager", "web", "GraphQL schema exploration", "graphql-voyager", ["graphql-voyager"]),
    SecurityTool("zaproxy", "web", "OWASP ZAP scanning", "zaproxy", ["zaproxy"]),
    SecurityTool("burp", "web", "Burp Suite integration", "burpsuite", ["burpsuite"]),
    SecurityTool("postman", "web", "API testing", "postman", ["postman"]),
    SecurityTool(
        "nmap-http",
        "web",
        "HTTP NSE script scanning",
        "nmap",
        ["nmap"],
        build_args=lambda t, a: ["nmap", "-p", "80,443,8080,8443", "--script", "http-enum,http-vuln-*", t],
    ),
    SecurityTool(
        "eyewitness-web",
        "web",
        "Web screenshot and analysis",
        "EyeWitness",
        ["EyeWitness"],
        build_args=lambda t, a: ["EyeWitness", "--web", "-d", t, "--no-prompt"],
    ),
]

PASSWORD_TOOLS = [
    SecurityTool(
        "hydra",
        "password",
        "Network login cracker",
        "hydra",
        ["hydra"],
        build_args=lambda t, a: ["hydra", "-L", "users.txt", "-P", "passwords.txt", t, "ssh"],
        parse_output=parse_hydra,
    ),
    SecurityTool("john", "password", "Password hash cracking", "john", ["john"]),
    SecurityTool("hashcat", "password", "GPU-accelerated password recovery", "hashcat", ["hashcat"]),
    SecurityTool("medusa", "password", "Parallel login brute-forcer", "medusa", ["medusa"]),
    SecurityTool("patator", "password", "Multi-purpose brute-forcer", "patator", ["patator"]),
    SecurityTool("crackmapexec", "password", "Network pentesting swiss army knife", "crackmapexec", ["crackmapexec"]),
    SecurityTool("evil-winrm", "password", "Windows Remote Management shell", "evil-winrm", ["evil-winrm"]),
    SecurityTool("hash-identifier", "password", "Hash type identification", "hash-identifier", ["hash-identifier"]),
    SecurityTool("hashid", "password", "Advanced hash identifier", "hashid", ["hashid"]),
    SecurityTool("cewl", "password", "Custom wordlist generator", "cewl", ["cewl"]),
    SecurityTool("crunch", "password", "Wordlist generator", "crunch", ["crunch"]),
    SecurityTool("cupp", "password", "Common User Password Profiler", "cupp", ["cupp"]),
    SecurityTool("kerbrute", "password", "Kerberos brute-forcing", "kerbrute", ["kerbrute"]),
    SecurityTool("rsmangler", "password", "Rule-based wordlist mangler", "rsmangler", ["rsmangler"]),
]

BINARY_TOOLS = [
    SecurityTool("gdb", "binary", "GNU Debugger", "gdb", ["gdb"]),
    SecurityTool("radare2", "binary", "Reverse engineering framework", "r2", ["r2"]),
    SecurityTool("ghidra", "binary", "NSA reverse engineering suite", "analyzeHeadless", ["analyzeHeadless"]),
    SecurityTool("binwalk", "binary", "Firmware analysis", "binwalk", ["binwalk"]),
    SecurityTool(
        "checksec", "binary", "Binary security property checker", "checksec", ["checksec"], parse_output=parse_checksec
    ),
    SecurityTool("strings", "binary", "Extract printable strings", "strings", ["strings"]),
    SecurityTool("objdump", "binary", "Object file information", "objdump", ["objdump"]),
    SecurityTool("volatility3", "binary", "Memory forensics", "vol", ["vol"]),
    SecurityTool("foremost", "binary", "File carving", "foremost", ["foremost"]),
    SecurityTool("steghide", "binary", "Steganography detection", "steghide", ["steghide"]),
    SecurityTool("exiftool", "binary", "Metadata reader/writer", "exiftool", ["exiftool"]),
    SecurityTool("ropgadget", "binary", "ROP/JOP gadget finder", "ROPgadget", ["ROPgadget"]),
    SecurityTool("ropper", "binary", "ROP gadget finder", "ropper", ["ropper"]),
    SecurityTool("one-gadget", "binary", "One-shot RCE gadget finder", "one_gadget", ["one_gadget"]),
    SecurityTool("pwntools", "binary", "CTF framework", "python3", ["python3"]),
    SecurityTool("angr", "binary", "Binary analysis platform", "python3", ["python3"]),
    SecurityTool("libc-database", "binary", "Libc identification", "python3", ["python3"]),
    SecurityTool("pwninit", "binary", "Binary exploitation setup", "pwninit", ["pwninit"]),
    SecurityTool("msfvenom", "binary", "Payload generator", "msfvenom", ["msfvenom"]),
    SecurityTool("upx", "binary", "Executable packer/unpacker", "upx", ["upx"]),
    SecurityTool("xxd", "binary", "Hex dump utility", "xxd", ["xxd"]),
    SecurityTool("hexdump", "binary", "Hex viewer", "hexdump", ["hexdump"]),
    SecurityTool("readelf", "binary", "ELF file analyzer", "readelf", ["readelf"]),
    SecurityTool("ltrace", "binary", "Library call tracer", "ltrace", ["ltrace"]),
    SecurityTool("strace", "binary", "System call tracer", "strace", ["strace"]),
    SecurityTool("file", "binary", "File type identification", "file", ["file"]),
    SecurityTool("nm", "binary", "List symbols from object files", "nm", ["nm"]),
]

CLOUD_TOOLS = [
    SecurityTool("prowler", "cloud", "AWS/Azure/GCP security assessment", "prowler", ["prowler"]),
    SecurityTool("scout-suite", "cloud", "Multi-cloud security auditing", "scout", ["scout"]),
    SecurityTool("trivy", "cloud", "Container vulnerability scanner", "trivy", ["trivy"]),
    SecurityTool("kube-hunter", "cloud", "Kubernetes pentesting", "kube-hunter", ["kube-hunter"]),
    SecurityTool("kube-bench", "cloud", "CIS Kubernetes benchmark", "kube-bench", ["kube-bench"]),
    SecurityTool(
        "docker-bench-security",
        "cloud",
        "Docker security assessment",
        "docker-bench-security",
        ["docker-bench-security"],
    ),
    SecurityTool("checkov", "cloud", "IaC security scanning", "checkov", ["checkov"]),
    SecurityTool("terrascan", "cloud", "Infrastructure security scanner", "terrascan", ["terrascan"]),
    SecurityTool("cloudsploit", "cloud", "Cloud security scanning", "cloudsploit", ["cloudsploit"]),
    SecurityTool("pacu", "cloud", "AWS exploitation framework", "pacu", ["pacu"]),
    SecurityTool("cloudmapper", "cloud", "AWS network visualization", "cloudmapper", ["cloudmapper"]),
    SecurityTool("aws-cli", "cloud", "AWS command line", "aws", ["aws"]),
    SecurityTool("azure-cli", "cloud", "Azure command line", "az", ["az"]),
    SecurityTool("gcloud", "cloud", "GCP command line", "gcloud", ["gcloud"]),
    SecurityTool("kubectl", "cloud", "Kubernetes CLI", "kubectl", ["kubectl"]),
    SecurityTool("helm", "cloud", "Kubernetes package manager", "helm", ["helm"]),
    SecurityTool("falco", "cloud", "Runtime security monitoring", "falco", ["falco"]),
    SecurityTool("clair", "cloud", "Container vulnerability analysis", "clair", ["clair"]),
    SecurityTool("istioctl", "cloud", "Istio service mesh", "istioctl", ["istioctl"]),
    SecurityTool("opa", "cloud", "Policy engine", "opa", ["opa"]),
    SecurityTool("steampipe", "cloud", "Cloud resource querying", "steampipe", ["steampipe"]),
    SecurityTool("cloudsplaining", "cloud", "AWS IAM policy analysis", "cloudsplaining", ["cloudsplaining"]),
]

OSINT_TOOLS = [
    SecurityTool("sherlock", "osint", "Username investigation", "sherlock", ["sherlock"]),
    SecurityTool("social-analyzer", "osint", "Social media analysis", "social-analyzer", ["social-analyzer"]),
    SecurityTool("recon-ng", "osint", "Web reconnaissance framework", "recon-ng", ["recon-ng"]),
    SecurityTool("spiderfoot", "osint", "OSINT automation", "spiderfoot", ["spiderfoot"]),
    SecurityTool("maltego", "osint", "Link analysis", "maltego", ["maltego"]),
    SecurityTool("shodan", "osint", "Internet device search", "shodan", ["shodan"]),
    SecurityTool("censys", "osint", "Internet asset discovery", "censys", ["censys"]),
    SecurityTool("haveibeenpwned", "osint", "Breach data analysis", "haveibeenpwned", ["haveibeenpwned"]),
    SecurityTool(
        "trufflehog", "osint", "Git secret scanning", "trufflehog", ["trufflehog"], parse_output=parse_trufflehog
    ),
    SecurityTool("gitrob", "osint", "GitHub reconnaissance", "gitrob", ["gitrob"]),
    SecurityTool("gitleaks", "osint", "Git secret detection", "gitleaks", ["gitleaks"], parse_output=parse_gitleaks),
    SecurityTool("aquatone", "osint", "Visual website inspection", "aquatone", ["aquatone"]),
    SecurityTool("eyeWitness", "osint", "Screenshot and credential capture", "EyeWitness", ["EyeWitness"]),
    SecurityTool("theHarvester", "osint", "Email/subdomain harvesting", "theHarvester", ["theHarvester"]),
    SecurityTool("google-dorks", "osint", "Google dorking", "google", ["google"]),
    SecurityTool("wayback-machine", "osint", "Historical web content", "waybackurls", ["waybackurls"]),
    SecurityTool("github-search", "osint", "GitHub code search", "gh", ["gh"]),
    SecurityTool("dnsrecon", "osint", "DNS reconnaissance", "dnsrecon", ["dnsrecon"]),
    SecurityTool("knockpy", "osint", "Subdomain enumeration", "knockpy", ["knockpy"]),
    SecurityTool("assetfinder", "osint", "Domain asset finder", "assetfinder", ["assetfinder"]),
    SecurityTool("urlcrazy", "osint", "Typosquatting detection", "urlcrazy", ["urlcrazy"]),
    SecurityTool("datasploit", "osint", "OSINT framework", "datasploit", ["datasploit"]),
    SecurityTool(
        "theHarvester-email",
        "osint",
        "Email harvesting",
        "theHarvester",
        ["theHarvester"],
        build_args=lambda t, a: ["theHarvester", "-d", t, "-b", "all", "-e"],
    ),
    SecurityTool("metagoofil", "osint", "Metadata extraction from documents", "metagoofil", ["metagoofil"]),
    SecurityTool(
        "whois", "osint", "Domain WHOIS lookup (registrar, registrant, nameservers, expiry)",
        "whois", ["whois"],
        build_args=lambda t, a: ["whois", t],
    ),
    SecurityTool(
        "ipgeolocation", "osint", "IP geolocation, ASN, ISP, and city lookup",
        "ipgeolocation", ["ipgeolocation"],
        build_args=lambda t, a: ["ipgeolocation", "-t", t],
    ),
    SecurityTool(
        "evilurl", "osint", "Homograph (IDN/Punycode) lookalike domain generator for phishing-defense",
        "evilurl", ["evilurl"],
        build_args=lambda t, a: ["evilurl", t],
    ),
]

MOBILE_TOOLS = [
    SecurityTool("jadx", "mobile", "Android APK decompiler", "jadx", ["jadx"]),
    SecurityTool(
        "apktool", "mobile", "Android APK reverse engineering", "apktool", ["apktool"],
        build_args=lambda t, a: ["apktool", "d", t, "-o", f"{t}.decoded"],
    ),
    SecurityTool("drozer", "mobile", "Android security testing framework", "drozer", ["drozer"]),
    SecurityTool("frida", "mobile", "Dynamic instrumentation toolkit", "frida", ["frida-tools"]),
    SecurityTool("objection", "mobile", "Runtime mobile exploration", "objection", ["objection"]),
    SecurityTool("class-dump", "mobile", "iOS Objective-C header dump", "class-dump", ["class-dump"]),
    SecurityTool("otool", "mobile", "iOS Mach-O binary analysis", "otool", []),
    SecurityTool("binwalk", "mobile", "Firmware and binary analysis", "binwalk", ["binwalk"]),
    SecurityTool("mob-sf", "mobile", "Mobile Security Framework", "mobsf", ["mobsf"]),
    SecurityTool("qark", "mobile", "Android static analysis", "qark", ["qark"]),
]

WIRELESS_TOOLS = [
    SecurityTool(
        "airodump-ng", "wireless", "WiFi network scanner", "airodump-ng", ["aircrack-ng"],
        build_args=lambda t, a: ["airodump-ng", t],
    ),
    SecurityTool(
        "aireplay-ng", "wireless", "WiFi deauthentication and injection", "aireplay-ng", ["aircrack-ng"],
    ),
    SecurityTool("kismet", "wireless", "Wireless network detector and sniffer", "kismet", ["kismet"]),
    SecurityTool("wash", "wireless", "WPS-enabled AP scanner", "wash", ["reaver"]),
    SecurityTool("hashcat", "wireless", "Advanced password recovery", "hashcat", ["hashcat"]),
    SecurityTool("john", "wireless", "John the Ripper password cracker", "john", ["john"]),
    SecurityTool("bluelog", "wireless", "Bluetooth device scanner", "bluelog", ["bluelog"]),
    SecurityTool("btscanner", "wireless", "Bluetooth device discovery", "btscanner", ["btscanner"]),
]

SOCIAL_TOOLS = [
    SecurityTool("gophish", "social", "Phishing campaign framework", "gophish", ["gophish"]),
    SecurityTool("setoolkit", "social", "Social Engineering Toolkit", "setoolkit", ["setoolkit"]),
    SecurityTool("evilginx2", "social", "MitM attack framework for credentials", "evilginx2", ["evilginx2"]),
    SecurityTool("spoofcheck", "social", "Email spoofing verification", "spoofcheck", ["spoofcheck"]),
    SecurityTool(
        "dmarc-report", "social", "DMARC/SPF/DKIM analysis", "checkdmarc", ["checkdmarc"],
        build_args=lambda t, a: ["checkdmarc", t],
    ),
]

AD_TOOLS = [
    SecurityTool("enum4linux", "ad", "SMB/NetBIOS enumeration", "enum4linux", ["enum4linux"]),
    SecurityTool("ldapsearch", "ad", "LDAP directory queries", "ldapsearch", []),
    SecurityTool("rpcclient", "ad", "Windows RPC enumeration", "rpcclient", []),
    SecurityTool("smbclient", "ad", "SMB share enumeration", "smbclient", []),
    SecurityTool("nbtscan", "ad", "NetBIOS name scanner", "nbtscan", ["nbtscan"]),
    SecurityTool("netexec", "ad", "Network execution and Kerberos attacks", "netexec", ["netexec"]),
    SecurityTool("kerbrute", "ad", "Kerberos brute force and enumeration", "kerbrute", ["kerbrute"]),
    SecurityTool("bloodhound-python", "ad", "BloodHound data collector", "bloodhound-python", ["bloodhound"]),
    SecurityTool(
        "impacket-secretsdump", "ad", "Credential dumping", "secretsdump.py", ["impacket"],
        build_args=lambda t, a: ["secretsdump.py", t],
    ),
    SecurityTool(
        "impacket-getTGT", "ad", "Kerberos TGT request", "getTGT.py", ["impacket"],
        build_args=lambda t, a: ["getTGT.py", t],
    ),
    # ─── Added 2026-04-28: AD attack-surface tools ──────────────────────
    SecurityTool(
        "coercer", "ad", "Coerce SMB/HTTP authentication via MS-RPRN, MS-EFSR, MS-DFSNM", "coercer",
        ["coercer"],
        build_args=lambda t, a: ["coercer", "coerce", "-l", t] + ([str(a.get("listener"))] if a and a.get("listener") else []),
    ),
    SecurityTool(
        "krbrelayx", "ad", "Kerberos relay and abuse (S4U2Self, RBCD)", "krbrelayx.py",
        ["krbrelayx"],
        build_args=lambda t, a: ["krbrelayx.py", "-t", t],
    ),
    SecurityTool(
        "certipy", "ad", "AD CS enumeration and abuse (ESC1-ESC15)", "certipy",
        ["certipy"],
        build_args=lambda t, a: ["certipy", "find", "-target", t],
    ),
    SecurityTool(
        "responder-multirelay", "ad", "MultiRelay forced authentication", "MultiRelay.py",
        ["Responder"],
        build_args=lambda t, a: ["MultiRelay.py", "-t", t, "-u", "ALL"],
    ),
]


# ─── Added 2026-04-28: extra coverage from the deferred wishlist ────────
# Forensics and DFIR adjacent tools, web parameter discovery, cloud asset
# mapping. Each is a thin SecurityTool entry; the engine handles execution
# and dedup automatically.

FORENSICS_EXTRA_TOOLS = [
    SecurityTool(
        "bulk-extractor", "binary", "Recover artifacts from disk images at scale",
        "bulk_extractor", ["bulk_extractor"],
        build_args=lambda t, a: ["bulk_extractor", "-o", (a or {}).get("out", "/tmp/be-out"), t],
    ),
    SecurityTool(
        "stegseek", "binary", "Brute-force steghide passphrases against image carriers",
        "stegseek", ["stegseek"],
        build_args=lambda t, a: ["stegseek", t, (a or {}).get("wordlist", "/usr/share/wordlists/rockyou.txt")],
    ),
    SecurityTool(
        "zsteg", "binary", "PNG/BMP LSB steganography analysis", "zsteg", ["zsteg"],
        build_args=lambda t, a: ["zsteg", "-a", t],
    ),
    SecurityTool(
        "pngcheck", "binary", "PNG chunk validation, often surfaces hidden data after IEND",
        "pngcheck", ["pngcheck"],
        build_args=lambda t, a: ["pngcheck", "-v", t],
    ),
]

WEB_EXTRA_TOOLS = [
    SecurityTool(
        "paramminer", "web", "Discover hidden HTTP parameters via differential analysis",
        "param-miner", ["param-miner"],
        build_args=lambda t, a: ["param-miner", "-u", t],
    ),
    SecurityTool(
        "jwt-tool", "web", "JWT inspection, manipulation, and signature attacks",
        "jwt_tool", ["jwt_tool"],
        build_args=lambda t, a: ["jwt_tool", t],
    ),
    SecurityTool(
        "semgrep", "web", "Static analysis for source code (SAST) including security rules",
        "semgrep", ["semgrep"],
        build_args=lambda t, a: ["semgrep", "--config", (a or {}).get("config", "auto"), t],
    ),
]

CLOUD_EXTRA_TOOLS = [
    SecurityTool(
        "cartography", "cloud", "Asset and identity graph across AWS, GCP, Azure, K8s",
        "cartography", ["cartography"],
        build_args=lambda t, a: ["cartography", "--neo4j-uri", (a or {}).get("neo4j", "bolt://localhost:7687")],
    ),
    SecurityTool(
        "principalmapper", "cloud", "AWS IAM privilege escalation graph",
        "pmapper", ["pmapper"],
        build_args=lambda t, a: ["pmapper", "graph", "create", "--profile", t],
    ),
    SecurityTool(
        "cloudfox", "cloud", "AWS multi-account post-foothold inventory and attack surface",
        "cloudfox", ["cloudfox"],
        build_args=lambda t, a: ["cloudfox", "aws", "all-checks", "--profile", t],
    ),
]


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, SecurityTool] = {}
        self._register_all_tools()
        # PTAI_SKIP_TOOLS=nikto,skipfish lets ops opt out of tools that flood
        # a target with requests (nikto's 6544 probes can OOM SPA backends like
        # Juice Shop even at 8GB heap). Skipped tools simply look "not
        # installed" to the rest of the engine, so phases gracefully no-op.
        import os
        skip_env = os.getenv("PTAI_SKIP_TOOLS", "").strip()
        self._skip: set[str] = {
            n.strip().lower() for n in skip_env.split(",") if n.strip()
        }

    def _register(self, tool: SecurityTool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> SecurityTool | None:
        if name.lower() in self._skip:
            return None
        return self._tools.get(name)

    def list_tools(self, category: str | None = None) -> list[SecurityTool]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def _register_all_tools(self):
        for tool in NETWORK_TOOLS:
            self._register(tool)
        for tool in WEB_TOOLS:
            self._register(tool)
        for tool in PASSWORD_TOOLS:
            self._register(tool)
        for tool in BINARY_TOOLS:
            self._register(tool)
        for tool in CLOUD_TOOLS:
            self._register(tool)
        for tool in OSINT_TOOLS:
            self._register(tool)
        for tool in MOBILE_TOOLS:
            self._register(tool)
        for tool in WIRELESS_TOOLS:
            self._register(tool)
        for tool in SOCIAL_TOOLS:
            self._register(tool)
        for tool in AD_TOOLS:
            self._register(tool)
        for tool in FORENSICS_EXTRA_TOOLS:
            self._register(tool)
        for tool in WEB_EXTRA_TOOLS:
            self._register(tool)
        for tool in CLOUD_EXTRA_TOOLS:
            self._register(tool)

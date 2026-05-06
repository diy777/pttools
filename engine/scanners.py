"""
Built-in Security Scanners — No external tool dependencies.

These scanners work out of the box without installing any security tools.
They provide immediate value when pentest-tools is first installed.
"""

import asyncio
import contextlib
import re
import socket
import ssl
from typing import Any

import httpx


async def _resolve_http_url(target: str, client: httpx.AsyncClient) -> str | None:
    """Pick the right URL scheme for a bare host.

    If target already has a scheme, return as-is. Otherwise probe https first,
    fall back to http on connection failure. Returns None if both fail so the
    caller can short-circuit cleanly instead of silently scanning the wrong scheme.
    """
    if target.startswith(("http://", "https://")):
        return target
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            await client.head(url, timeout=5.0)
            return url
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout, OSError):
            continue
    return None


async def scan_ports(target: str, ports: list[int] | None = None, timeout: float = 2.0) -> list[dict[str, Any]]:
    """Scan common ports on a target host."""
    if ports is None:
        ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            1521,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            9200,
            27017,
        ]

    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        5900: "vnc",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }

    severity_map = {
        "ftp": "medium",
        "telnet": "high",
        "ssh": "medium",
        "smb": "medium",
        "mysql": "high",
        "postgres": "high",
        "mssql": "high",
        "redis": "high",
        "mongodb": "high",
        "rdp": "medium",
        "vnc": "medium",
        "elasticsearch": "high",
    }

    findings = []
    tasks = []
    for port in ports:
        tasks.append(_check_port(target, port, timeout, service_map.get(port, "unknown"), severity_map))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict) and r.get("open"):
            findings.append(r)

    return findings


async def _check_port(target: str, port: int, timeout: float, service: str, severity_map: dict) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        severity = severity_map.get(service, "info")
        return {
            "title": f"Open port {port}/tcp — {service}",
            "description": f"Port {port}/tcp ({service}) is open on {target}",
            "severity": severity,
            "category": "network",
            "tool_source": "pentest-tools-port-scan",
            "target": f"{target}:{port}",
            "evidence": f"TCP connect to {target}:{port} succeeded",
            "open": True,
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"open": False}


async def scan_http_headers(target: str) -> list[dict[str, Any]]:
    """Analyze HTTP security headers."""
    findings = []

    # Built-in scanners scan targets which may have invalid/self-signed certs.
    # Cert problems are part of what we report on, not something to abort on.
    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:  # nosec B501
        url = await _resolve_http_url(target, client)
        if url is None:
            return [{
                "title": f"HTTP scan: target unreachable on http and https ({target})",
                "description": f"Tried https://{target} and http://{target}; both failed to connect.",
                "severity": "info",
                "category": "discovery",
                "tool_source": "builtin_http_headers",
                "target": target,
                "evidence": "",
                "remediation": "Verify the target is online and reachable.",
            }]
        try:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Missing security headers
            security_headers = {
                "strict-transport-security": (
                    "Missing HSTS header",
                    "medium",
                    "Add Strict-Transport-Security header to enforce HTTPS",
                ),
                "content-security-policy": (
                    "Missing Content-Security-Policy header",
                    "medium",
                    "Add CSP header to prevent XSS and data injection",
                ),
                "x-content-type-options": (
                    "Missing X-Content-Type-Options header",
                    "low",
                    "Add X-Content-Type-Options: nosniff",
                ),
                "x-frame-options": ("Missing X-Frame-Options header", "low", "Add X-Frame-Options: DENY or SAMEORIGIN"),
                "x-xss-protection": ("Missing X-XSS-Protection header", "info", "Add X-XSS-Protection: 1; mode=block"),
                "referrer-policy": ("Missing Referrer-Policy header", "info", "Add Referrer-Policy header"),
                "permissions-policy": (
                    "Missing Permissions-Policy header",
                    "info",
                    "Add Permissions-Policy to restrict browser features",
                ),
            }

            for header, (title, severity, remediation) in security_headers.items():
                if header not in headers:
                    findings.append(
                        {
                            "title": title,
                            "description": f"The {header} header is not set on {url}",
                            "severity": severity,
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-header-scan",
                            "target": url,
                            "evidence": f"Response headers do not include {header}",
                            "remediation": remediation,
                        }
                    )

            # Server header disclosure
            if "server" in headers:
                findings.append(
                    {
                        "title": f"Server header reveals technology: {headers['server']}",
                        "description": f"The Server header exposes technology information: {headers['server']}",
                        "severity": "info",
                        "category": "information_disclosure",
                        "tool_source": "pentest-tools-header-scan",
                        "target": url,
                        "evidence": f"Server: {headers['server']}",
                        "remediation": "Remove or obfuscate the Server header",
                    }
                )

            # CORS misconfiguration
            if "access-control-allow-origin" in headers:
                acao = headers["access-control-allow-origin"]
                if acao == "*":
                    findings.append(
                        {
                            "title": "Overly permissive CORS policy",
                            "description": f"Access-Control-Allow-Origin is set to * on {url}",
                            "severity": "medium",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-header-scan",
                            "target": url,
                            "evidence": "Access-Control-Allow-Origin: *",
                            "remediation": "Restrict CORS to specific trusted origins",
                        }
                    )

            # Cookie security
            if "set-cookie" in headers:
                cookie = headers["set-cookie"].lower()
                if "secure" not in cookie:
                    findings.append(
                        {
                            "title": "Cookie missing Secure flag",
                            "description": "Session cookie does not have the Secure flag set",
                            "severity": "medium",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-header-scan",
                            "target": url,
                            "evidence": "Set-Cookie header missing Secure attribute",
                            "remediation": "Add Secure flag to all cookies",
                        }
                    )
                if "httponly" not in cookie:
                    findings.append(
                        {
                            "title": "Cookie missing HttpOnly flag",
                            "description": "Session cookie does not have the HttpOnly flag set",
                            "severity": "medium",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-header-scan",
                            "target": url,
                            "evidence": "Set-Cookie header missing HttpOnly attribute",
                            "remediation": "Add HttpOnly flag to session cookies",
                        }
                    )

        except Exception as e:
            findings.append(
                {
                    "title": f"HTTP scan failed for {url}",
                    "description": str(e),
                    "severity": "info",
                    "category": "error",
                    "tool_source": "pentest-tools-header-scan",
                    "target": url,
                    "evidence": str(e),
                }
            )

    return findings


async def check_ssl(target: str, port: int = 443) -> list[dict[str, Any]]:
    """Check SSL/TLS configuration."""
    findings = []
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

            # Check certificate expiration
            not_after = cert.get("notAfter", "")
            if not_after:
                from datetime import datetime

                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                if days_left < 0:
                    findings.append(
                        {
                            "title": "SSL certificate has expired",
                            "description": f"The SSL certificate for {hostname} expired {abs(days_left)} days ago",
                            "severity": "high",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-ssl-check",
                            "target": hostname,
                            "evidence": f"Certificate expired on {not_after}",
                        }
                    )
                elif days_left < 30:
                    findings.append(
                        {
                            "title": f"SSL certificate expires in {days_left} days",
                            "description": f"The SSL certificate for {hostname} expires soon",
                            "severity": "medium",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-ssl-check",
                            "target": hostname,
                            "evidence": f"Certificate expires on {not_after}",
                        }
                    )

            # Check TLS version
            if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(
                    {
                        "title": f"Weak TLS version: {version}",
                        "description": f"Server supports deprecated {version}",
                        "severity": "high",
                        "category": "misconfiguration",
                        "tool_source": "pentest-tools-ssl-check",
                        "target": hostname,
                        "evidence": f"Negotiated version: {version}",
                        "remediation": "Disable TLS 1.0/1.1 and SSL, use TLS 1.2+ only",
                    }
                )

            # Check cipher strength
            if cipher:
                cipher_name = cipher[0]
                if "RC4" in cipher_name or "DES" in cipher_name or "3DES" in cipher_name:
                    findings.append(
                        {
                            "title": f"Weak cipher suite: {cipher_name}",
                            "description": f"Server supports weak cipher {cipher_name}",
                            "severity": "high",
                            "category": "misconfiguration",
                            "tool_source": "pentest-tools-ssl-check",
                            "target": hostname,
                            "evidence": f"Cipher: {cipher_name}",
                        }
                    )

    except ssl.SSLCertVerificationError as e:
        findings.append(
            {
                "title": f"SSL certificate verification failed: {hostname}",
                "description": str(e),
                "severity": "high",
                "category": "misconfiguration",
                "tool_source": "pentest-tools-ssl-check",
                "target": hostname,
                "evidence": str(e),
            }
        )
    except Exception as e:
        findings.append(
            {
                "title": f"SSL check failed for {hostname}:{port}",
                "description": str(e),
                "severity": "info",
                "category": "error",
                "tool_source": "pentest-tools-ssl-check",
                "target": hostname,
                "evidence": str(e),
            }
        )

    return findings


async def scan_common_paths(target: str) -> list[dict[str, Any]]:
    """Scan for common sensitive paths."""
    findings = []
    # Built-in scanners scan targets that may have invalid certs (see scan_http_headers note).
    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as probe:  # nosec B501
        resolved = await _resolve_http_url(target, probe)
    if resolved is None:
        return [{
            "title": f"Path scan: target unreachable on http and https ({target})",
            "description": f"Tried https://{target} and http://{target}; both failed to connect.",
            "severity": "info",
            "category": "discovery",
            "tool_source": "builtin_path_scan",
            "target": target,
            "evidence": "",
            "remediation": "Verify the target is online and reachable.",
        }]
    base = resolved.rstrip("/")

    common_paths = [
        "/admin",
        "/login",
        "/dashboard",
        "/api",
        "/api/v1",
        "/api/v2",
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/server-status",
        "/server-info",
        "/debug",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/swagger.json",
        "/swagger-ui.html",
        "/api-docs",
        "/graphql",
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml",
        "/config.json",
        "/config.yml",
        "/backup",
        "/backup.sql",
        "/dump.sql",
        "/database.sql",
        "/test",
        "/staging",
        "/dev",
        "/devops",
        "/console",
        "/manager",
        "/jenkins",
        "/solr",
        "/elasticsearch",
    ]

    # Built-in scanners scan targets that may have invalid certs (see scan_http_headers note).
    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:  # nosec B501
        tasks = []
        for path in common_paths:
            tasks.append(_check_path(client, base + path, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r.get("found"):
                findings.append(r)

    return findings


async def _check_path(client: httpx.AsyncClient, url: str, path: str) -> dict[str, Any]:
    try:
        resp = await client.get(url)
        if resp.status_code == 200 and len(resp.text) > 0:
            severity = "info"
            if path in ("/.env", "/.git/config", "/.git/HEAD"):
                severity = "critical"
            elif path in ("/phpmyadmin", "/server-status", "/actuator/env", "/debug"):
                severity = "high"
            elif path in ("/admin", "/dashboard", "/manager", "/console", "/jenkins"):
                severity = "medium"
            elif path in ("/backup", "/backup.sql", "/dump.sql", "/database.sql"):
                severity = "critical"

            return {
                "title": f"Accessible path: {path} (HTTP {resp.status_code})",
                "description": f"The path {path} is accessible and returns HTTP {resp.status_code}",
                "severity": severity,
                "category": "discovery",
                "tool_source": "pentest-tools-path-scan",
                "target": url,
                "evidence": f"GET {path} returned {resp.status_code} ({len(resp.text)} bytes)",
            }
    except Exception:
        pass
    return {"found": False}


async def check_dns(target: str) -> list[dict[str, Any]]:
    """Perform DNS enumeration and checks."""
    findings = []
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        # A record
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(info[4][0] for info in infos))
        for ip in ips:
            findings.append(
                {
                    "title": f"DNS A record: {hostname} → {ip}",
                    "description": f"DNS resolves {hostname} to {ip}",
                    "severity": "info",
                    "category": "recon",
                    "tool_source": "pentest-tools-dns-check",
                    "target": hostname,
                    "evidence": f"A record: {ip}",
                }
            )

        # Check for common subdomains
        subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "db", "git"]
        for sub in subdomains:
            subdomain = f"{sub}.{hostname}"
            try:
                infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
                ips = list(set(info[4][0] for info in infos))
                findings.append(
                    {
                        "title": f"Subdomain discovered: {subdomain}",
                        "description": f"DNS resolves {subdomain} to {', '.join(ips)}",
                        "severity": "info",
                        "category": "recon",
                        "tool_source": "pentest-tools-dns-check",
                        "target": subdomain,
                        "evidence": f"A record: {', '.join(ips)}",
                    }
                )
            except socket.gaierror:
                pass

    except socket.gaierror:
        findings.append(
            {
                "title": f"DNS resolution failed for {hostname}",
                "description": f"Could not resolve {hostname}",
                "severity": "info",
                "category": "error",
                "tool_source": "pentest-tools-dns-check",
                "target": hostname,
                "evidence": "DNS resolution failed",
            }
        )

    return findings


async def scan_secrets_in_response(target: str) -> list[dict[str, Any]]:
    """Scan HTTP responses for leaked secrets and credentials."""
    findings = []
    # Built-in scanners scan targets that may have invalid certs (see scan_http_headers note).
    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as probe:  # nosec B501
        url = await _resolve_http_url(target, probe)
    if url is None:
        return [{
            "title": f"Secrets scan: target unreachable on http and https ({target})",
            "description": f"Tried https://{target} and http://{target}; both failed to connect.",
            "severity": "info",
            "category": "discovery",
            "tool_source": "builtin_secret_scan",
            "target": target,
            "evidence": "",
            "remediation": "Verify the target is online and reachable.",
        }]

    secret_patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
        "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}",
        "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"<>]{8,}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "Slack Token": r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "Connection String": r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]+",
    }

    # Built-in scanners scan targets which may have invalid/self-signed certs.
    # Cert problems are part of what we report on, not something to abort on.
    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:  # nosec B501
        try:
            resp = await client.get(url)
            body = resp.text

            for secret_type, pattern in secret_patterns.items():
                matches = re.findall(pattern, body)
                for match in matches[:3]:  # Limit to first 3 matches per type
                    findings.append(
                        {
                            "title": f"Potential {secret_type} exposed",
                            "description": f"A potential {secret_type} was found in the response from {url}",
                            "severity": "critical",
                            "category": "secret",
                            "tool_source": "pentest-tools-secret-scan",
                            "target": url,
                            "evidence": f"Pattern matched: {match[:50]}...",
                            "remediation": "Remove the secret immediately and rotate credentials",
                        }
                    )
        except Exception:
            pass

    return findings


async def run_builtin_scan(target: str, scan_type: str = "all") -> dict[str, Any]:
    """Run all built-in scans against a target. No external tools required."""
    findings = []
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    is_http = target.startswith("http") or scan_type in ("http", "all")

    scans = {
        "ports": lambda: scan_ports(hostname),
        "headers": lambda: scan_http_headers(target) if is_http else [],
        "ssl": lambda: check_ssl(hostname) if is_http else [],
        "paths": lambda: scan_common_paths(target) if is_http else [],
        "dns": lambda: check_dns(hostname),
        "secrets": lambda: scan_secrets_in_response(target) if is_http else [],
    }

    if scan_type == "all":
        tasks = [fn() for fn in scans.values()]
    elif scan_type in scans:
        tasks = [scans[scan_type]()]
    else:
        tasks = [scans.get(scan_type, lambda: [])()]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplicate by title
    seen = set()
    unique_findings = []
    for f in findings:
        key = f.get("title", "")
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    severity_counts = {}
    for f in unique_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "target": target,
        "scan_type": scan_type,
        "findings_count": len(unique_findings),
        "findings": unique_findings,
        "by_severity": severity_counts,
        "status": "complete",
        "builtin": True,
    }

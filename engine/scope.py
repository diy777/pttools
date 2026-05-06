"""Scope enforcement engine. Prevents any tool from hitting out-of-scope targets.

Enforcement happens at the SecurityTool.execute() chokepoint, not at the agent level.
Even a hallucinating LLM cannot bypass this layer.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("pentest-tools.scope")


@dataclass(frozen=True)
class ScopeViolation:
    target: str
    tool: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScopeEnforcer:
    def __init__(
        self,
        allowed_targets: list[str] | None = None,
        excluded_targets: list[str] | None = None,
        allowed_ports: list[int] | None = None,
        mode: str = "strict",
    ):
        self.mode = mode
        self._allowed_domains: list[str] = []
        self._allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_domains: list[str] = []
        self._excluded_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allowed_ports = set(allowed_ports) if allowed_ports else None
        self._violations: list[ScopeViolation] = []

        for t in (allowed_targets or []):
            self._parse_target(t, allow=True)
        for t in (excluded_targets or []):
            self._parse_target(t, allow=False)

    def _parse_target(self, target: str, allow: bool) -> None:
        target = target.strip()
        try:
            network = ipaddress.ip_network(target, strict=False)
            if allow:
                self._allowed_cidrs.append(network)
            else:
                self._excluded_cidrs.append(network)
            return
        except ValueError:
            pass

        _domain = target.lstrip("*.")
        if allow:
            self._allowed_domains.append(target)
        else:
            self._excluded_domains.append(target)

    def check(self, target: str, tool_name: str = "") -> tuple[bool, str]:
        if not self._allowed_domains and not self._allowed_cidrs:
            if self.mode == "permissive":
                return True, "No scope defined, permissive mode"
            return False, "No scope defined. Add targets to scope before scanning."

        hostname = _extract_hostname(target)
        if not hostname:
            reason = f"Cannot extract hostname from target: {target}"
            self._record_violation(target, tool_name, reason)
            return False, reason

        if self._is_excluded(hostname):
            reason = f"Target {hostname} is explicitly excluded from scope"
            self._record_violation(target, tool_name, reason)
            return False, reason

        if self._is_allowed(hostname):
            return True, "Target is in scope"

        ip = _resolve_to_ip(hostname)
        if ip and self._is_ip_allowed(ip):
            return True, f"Target {hostname} resolves to {ip} which is in scope"

        if ip and self._is_ip_excluded(ip):
            reason = f"Target {hostname} resolves to {ip} which is excluded"
            self._record_violation(target, tool_name, reason)
            return False, reason

        reason = f"Target {hostname} is not in scope"
        self._record_violation(target, tool_name, reason)
        return False, reason

    def check_port(self, port: int) -> tuple[bool, str]:
        if self._allowed_ports is None:
            return True, "No port restrictions"
        if port in self._allowed_ports:
            return True, "Port is in scope"
        return False, f"Port {port} is not in allowed ports"

    def _is_allowed(self, hostname: str) -> bool:
        for pattern in self._allowed_domains:
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if hostname.endswith(suffix) or hostname == pattern[2:]:
                    return True
            elif hostname == pattern:
                return True
        try:
            ip = ipaddress.ip_address(hostname)
            return self._is_ip_allowed(ip)
        except ValueError:
            return False

    def _is_excluded(self, hostname: str) -> bool:
        for pattern in self._excluded_domains:
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if hostname.endswith(suffix) or hostname == pattern[2:]:
                    return True
            elif hostname == pattern:
                return True
        try:
            ip = ipaddress.ip_address(hostname)
            return self._is_ip_excluded(ip)
        except ValueError:
            return False

    def _is_ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in cidr for cidr in self._allowed_cidrs)

    def _is_ip_excluded(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in cidr for cidr in self._excluded_cidrs)

    def _record_violation(self, target: str, tool: str, reason: str) -> None:
        violation = ScopeViolation(target=target, tool=tool, reason=reason)
        self._violations.append(violation)
        logger.warning(f"SCOPE VIOLATION: {tool} tried to access {target}: {reason}")

    @property
    def violations(self) -> list[ScopeViolation]:
        return list(self._violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_domains": self._allowed_domains,
            "allowed_cidrs": [str(c) for c in self._allowed_cidrs],
            "excluded_domains": self._excluded_domains,
            "excluded_cidrs": [str(c) for c in self._excluded_cidrs],
            "allowed_ports": sorted(self._allowed_ports) if self._allowed_ports else None,
            "mode": self.mode,
            "violation_count": len(self._violations),
        }


def _extract_hostname(target: str) -> str:
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        return hostname.lower()
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target.lower()


def _resolve_to_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if result:
            return ipaddress.ip_address(result[0][4][0])
    except (socket.gaierror, OSError, ValueError, TimeoutError):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None

"""Expand target arguments into concrete target lists.

Supports:
- Single target: "example.com" or "10.0.0.1"
- Comma-separated: "10.0.0.1,10.0.0.2,example.com"
- CIDR notation: "10.0.0.0/24" → 254 hosts (excludes network + broadcast)
- File input: one target per line, "#" comments allowed
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

MAX_EXPANDED_TARGETS = 4096


def expand_target(raw: str) -> list[str]:
    """Expand a single target string. Returns list (always non-empty on success)."""
    raw = raw.strip()
    if not raw:
        return []

    if "," in raw:
        out: list[str] = []
        for part in raw.split(","):
            out.extend(expand_target(part))
        return out

    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            hosts = [str(h) for h in net.hosts()]
            if not hosts and net.num_addresses == 1:
                hosts = [str(net.network_address)]
            return hosts
        except ValueError:
            return [raw]

    return [raw]


def load_targets_file(path: str | Path) -> list[str]:
    """Read targets from a file. One per line. '#' starts a comment."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"targets file not found: {p}")

    targets: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        targets.extend(expand_target(line))
    return targets


def resolve_targets(
    target_arg: str | None,
    targets_file: str | None,
) -> list[str]:
    """Resolve user input into a deduplicated, bounded target list."""
    raw: list[str] = []
    if targets_file:
        raw.extend(load_targets_file(targets_file))
    if target_arg:
        raw.extend(expand_target(target_arg))

    seen: set[str] = set()
    result: list[str] = []
    for t in raw:
        if t and t not in seen:
            seen.add(t)
            result.append(t)

    if len(result) > MAX_EXPANDED_TARGETS:
        raise ValueError(
            f"target expansion exceeds cap ({len(result)} > {MAX_EXPANDED_TARGETS}); "
            "narrow the CIDR or split the targets file"
        )
    return result

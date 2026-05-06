"""CVE intelligence wrapper around osv.dev's batch query API.

osv.dev (Google's open-source vulnerability database) ingests advisories
from NPM, PyPI, RubyGems, Maven, NVD, GHSA, etc. The batched query API at
POST /v1/querybatch takes up to 1000 (ecosystem, package, version) tuples
and returns matching vulnerability IDs in a single round trip.

This module wraps that API so probes can ask "given the dependency manifest
I just leaked, which packages are known-vulnerable" and turn the answer
into structured findings without baking a snapshot of the CVE database
into the repo.

Usage:
    from engine.cve_db import lookup_npm_packages

    deps = [{"name": "express", "version": "4.16.0"}, ...]
    vulns = await lookup_npm_packages(deps)
    # vulns = [{"name": "express", "version": "4.16.0",
    #           "vulnerabilities": ["GHSA-xxx-xxx-xxx", ...]}, ...]
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

logger = logging.getLogger("pentest-tools.cve_db")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{vid}"

# osv.dev expects ecosystem strings to match these canonical forms exactly.
ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "Gemfile.lock": "RubyGems",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "Cargo.lock": "crates.io",
    "Cargo.toml": "crates.io",
}

_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=15)


async def query_batch(
    queries: list[dict[str, Any]],
    *,
    session: aiohttp.ClientSession | None = None,
) -> list[list[str]]:
    """Send a batch query to osv.dev. Returns one list of vuln IDs per query.

    Each input query is shaped like:
      {"package": {"name": "express", "ecosystem": "npm"}, "version": "4.16.0"}
    """
    if not queries:
        return []
    payload = {"queries": queries}
    own_session = False
    if session is None:
        session = aiohttp.ClientSession()
        own_session = True
    try:
        async with session.post(
            OSV_BATCH_URL, json=payload, timeout=_DEFAULT_TIMEOUT
        ) as resp:
            if resp.status != 200:
                logger.warning("osv.dev returned %s: %s", resp.status, await resp.text())
                return [[] for _ in queries]
            data = await resp.json()
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
        logger.warning("osv.dev query failed: %s", e)
        return [[] for _ in queries]
    finally:
        if own_session:
            await session.close()

    results: list[list[str]] = []
    for entry in data.get("results", []):
        vulns = entry.get("vulns") or []
        results.append([v.get("id") for v in vulns if v.get("id")])
    while len(results) < len(queries):
        results.append([])
    return results


async def lookup_npm_packages(
    deps: list[dict[str, str]],
    *,
    session: aiohttp.ClientSession | None = None,
) -> list[dict[str, Any]]:
    """Given [{name, version}, ...] for npm deps, return vulnerability hits.

    Returns one dict per input dep:
        {"name": "...", "version": "...", "vulnerabilities": ["GHSA-..."]}
    Empty 'vulnerabilities' means the package is clean (or osv has no record).
    """
    queries = [
        {"package": {"name": d["name"], "ecosystem": "npm"}, "version": d.get("version", "")}
        for d in deps if d.get("name")
    ]
    if not queries:
        return []
    batch = await query_batch(queries, session=session)
    out: list[dict[str, Any]] = []
    for d, vulns in zip(deps, batch, strict=False):
        out.append({
            "name": d.get("name"),
            "version": d.get("version", ""),
            "vulnerabilities": vulns,
        })
    return out


def parse_package_json(text: str) -> list[dict[str, str]]:
    """Extract (name, version) pairs from a package.json or package-lock.json
    string. Returns flat list, deduped on (name, version).

    Accepts either npm v1 lockfiles (top-level "dependencies" map of name to
    version-string), npm v2/v3 lockfiles (top-level "packages" map of path
    to {version}), or a regular package.json (dependencies + devDependencies
    as version-string maps).
    """
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, dict):
        return []
    deps: dict[tuple[str, str], None] = {}

    # package.json shape
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = parsed.get(key)
        if isinstance(section, dict):
            for name, ver in section.items():
                if isinstance(ver, str):
                    deps[(name, _strip_version(ver))] = None

    # package-lock.json v1 shape
    section = parsed.get("dependencies")
    if isinstance(section, dict):
        for name, info in section.items():
            if isinstance(info, dict) and "version" in info:
                deps[(name, str(info["version"]))] = None

    # package-lock.json v2/v3 shape: top-level "packages" maps install paths
    # to {name?, version}. The root package has path "" and we skip it; nested
    # entries are keyed by node_modules/<name>.
    section = parsed.get("packages")
    if isinstance(section, dict):
        for path, info in section.items():
            if path == "" or not isinstance(info, dict):
                continue
            ver = info.get("version")
            if not isinstance(ver, str):
                continue
            name = info.get("name")
            if isinstance(name, str):
                deps[(name, ver)] = None
            elif path.startswith("node_modules/"):
                name = path.split("node_modules/", 1)[-1]
                deps[(name, ver)] = None

    return [{"name": n, "version": v} for (n, v) in deps if n]


def _strip_version(ver: str) -> str:
    """Drop common semver prefixes so versions match osv.dev's format."""
    ver = ver.strip()
    while ver and ver[0] in "^~>=<":
        ver = ver[1:]
    if ver.startswith("="):
        ver = ver[1:]
    return ver.split(" ", 1)[0].strip()


def filter_vulnerable(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop entries that have no vulnerabilities."""
    return [r for r in results if r.get("vulnerabilities")]

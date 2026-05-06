#!/usr/bin/env python3
"""Pre-launch dry-run check.

Hits every public URL the launch depends on and reports green/red. Run
once before posting "Show HN" so you don't ship broken links.

    python3 scripts/preflight-check.py

Exit code is 0 if every required URL responds, non-zero otherwise.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

TIMEOUT = 10


@dataclass
class Check:
    name: str
    url: str
    expected_status: int = 200
    expected_substring: str | None = None
    required: bool = True
    notes: str = ""


CHECKS: list[Check] = [
    # Marketing site
    Check("Marketing root", "https://pentest-tools.local/"),
    Check("Privacy policy", "https://pentest-tools.local/privacy/"),
    Check("Terms of service", "https://pentest-tools.local/terms/"),
    Check("Acceptable use", "https://pentest-tools.local/aup/"),
    Check("Cookie policy", "https://pentest-tools.local/cookies/"),
    Check("Subprocessors", "https://pentest-tools.local/subprocessors/"),
    Check("Security disclosure", "https://pentest-tools.local/security/"),
    Check("Legal landing", "https://pentest-tools.local/legal/"),
    Check("Getting started", "https://pentest-tools.local/docs/getting-started/"),
    Check(".well-known/security.txt", "https://pentest-tools.local/.well-known/security.txt",
          expected_substring="Contact: mailto:security@pentest-tools.local"),
    Check(".well-known/pgp-key.txt", "https://pentest-tools.local/.well-known/pgp-key.txt",
          expected_substring="BEGIN PGP PUBLIC KEY BLOCK"),
    Check("sitemap.xml", "https://pentest-tools.local/sitemap.xml"),
    Check("robots.txt", "https://pentest-tools.local/robots.txt"),

    # SaaS dashboard
    Check("App root", "https://app.pentest-tools.local/", required=False,
          notes="May be 401 / 302 if sign-in gated; that's fine"),
    Check("API health", "https://app.pentest-tools.local/api/health",
          expected_substring="status"),

    # Status page
    Check("Status page", "https://status.pentest-tools.local/", required=False,
          notes="Only after BetterStack DNS propagates"),

    # PyPI
    Check("PyPI pttools metadata", "https://pypi.org/pypi/pttools/json",
          expected_substring='"author":"pentest-tools"',
          notes="Confirms latest version is published"),

    # GitHub
    Check("OSS repo", "https://github.com/pentest-tools/pentest-tools"),
    Check("Issues", "https://github.com/pentest-tools/pentest-tools/issues"),
    Check("Discussions", "https://github.com/pentest-tools/pentest-tools/discussions"),
    Check("Security advisories", "https://github.com/pentest-tools/pentest-tools/security/advisories"),
]


@dataclass
class Result:
    check: Check
    status_code: int
    body_excerpt: str
    error: str | None
    ok: bool


def _hit(check: Check) -> Result:
    req = urllib.request.Request(
        check.url,
        headers={"User-Agent": "pttools-preflight/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            ok = resp.status == check.expected_status
            if check.expected_substring and check.expected_substring not in body:
                ok = False
            return Result(check, resp.status, body[:200], None, ok)
    except urllib.error.HTTPError as e:
        return Result(check, e.code, "", f"HTTP {e.code}", False)
    except urllib.error.URLError as e:
        return Result(check, 0, "", f"URL error: {e.reason}", False)
    except Exception as e:
        return Result(check, 0, "", f"error: {e}", False)


def main() -> int:
    print(f"Running {len(CHECKS)} preflight checks...\n")

    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_hit, c) for c in CHECKS]
        for f in as_completed(futures):
            results.append(f.result())

    # Stable order for printing
    by_name = {r.check.name: r for r in results}
    fail_count = 0
    optional_fail_count = 0

    for c in CHECKS:
        r = by_name[c.name]
        if r.ok:
            print(f"  OK   {c.name:<35} {c.url}")
        else:
            tag = "FAIL" if c.required else "skip"
            label = c.name + (" (optional)" if not c.required else "")
            err = r.error or f"status={r.status_code}"
            extra = f"  ({c.notes})" if c.notes else ""
            print(f"  {tag} {label:<35} {c.url}  -> {err}{extra}")
            if c.required:
                fail_count += 1
            else:
                optional_fail_count += 1

    print()
    if fail_count == 0 and optional_fail_count == 0:
        print(f"All {len(CHECKS)} checks passed. Launch surface is live.")
        return 0
    if fail_count == 0:
        print(f"All required checks passed. {optional_fail_count} optional checks not yet live (acceptable).")
        return 0
    print(f"{fail_count} REQUIRED checks failed. Fix before launch.")
    if optional_fail_count:
        print(f"{optional_fail_count} optional checks also not yet live.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

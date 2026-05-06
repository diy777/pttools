"""First-run AUP / authorization consent gate.

pentest-tools performs real network operations against targets. This module
gates `pttools start` and equivalent entry points behind an explicit consent
prompt that the user has read the Acceptable Use Policy at
https://pentest-tools.local/aup and confirms they have written authorization
to test every target they specify.

The acceptance is persisted to ~/.pentest-tools/aup-consent.txt so the
prompt only fires once per machine. Subsequent runs are silent.

Configuration / overrides:
    PENTEST_TOOLS_AUP_ACCEPTED=1     skip the prompt (CI / scripts);
                                   does NOT persist the consent file
    PENTEST_TOOLS_CONFIG_DIR=...     override default ~/.pentest-tools/

Why this matters legally: explicit per-machine consent makes the AUP a
clickwrap-equivalent contract. Combined with the AUP § 1 (authorization
is your responsibility) and § 8 (user indemnifies us), this closes the
"I didn't know I needed authorization" defense if a user misuses the
tool against an unauthorized target.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("pentest-tools.aup")

CONFIG_DIR = Path(os.environ.get("PENTEST_TOOLS_CONFIG_DIR", str(Path.home() / ".pentest-tools")))
CONSENT_PATH = CONFIG_DIR / "aup-consent.txt"
AUP_URL = "https://pentest-tools.local/aup"
TERMS_URL = "https://pentest-tools.local/terms"
AUP_VERSION = "1.0"

PROMPT_TEXT = f"""
pentest-tools is offensive security tooling. By using it you confirm:

  1. You have explicit, written authorization to test every target you
     specify (a Statement of Work, bug-bounty scope, or written consent
     from the system owner).
  2. You will comply with applicable law (CFAA, Computer Misuse Act,
     equivalents) when running scans.
  3. You accept the Acceptable Use Policy at:
         {AUP_URL}
  4. You accept the Terms of Service at:
         {TERMS_URL}

Misuse of pentest-tools (testing without authorization, attacking
infrastructure you don't own, etc.) is your sole responsibility.

Type 'yes' to accept and proceed. Anything else exits without scanning.

Accept the AUP and Terms? [yes/N]: """


def has_consent() -> bool:
    """True iff a valid consent file exists."""
    try:
        return CONSENT_PATH.is_file() and CONSENT_PATH.read_text(encoding="utf-8").strip() != ""
    except OSError:
        return False


def grant_consent() -> None:
    """Persist consent. Writes ISO timestamp + AUP version + AUP URL."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    body = (
        f"accepted_at: {datetime.now(timezone.utc).isoformat()}\n"
        f"version: {AUP_VERSION}\n"
        f"aup_url: {AUP_URL}\n"
        f"terms_url: {TERMS_URL}\n"
    )
    CONSENT_PATH.write_text(body, encoding="utf-8")
    # Restrict to user-only read on POSIX. No-op on Windows; Cygwin path
    # mapping makes chmod() irrelevant under WSL/Windows.
    if os.name != "nt":
        try:
            os.chmod(CONSENT_PATH, 0o600)
        except OSError as e:
            logger.debug("chmod 0o600 on %s failed: %s", CONSENT_PATH, e)


def revoke_consent() -> None:
    """Delete the consent file. Run before starting an engagement to re-prompt."""
    try:
        CONSENT_PATH.unlink()
    except FileNotFoundError:
        return
    except OSError as e:
        logger.debug("revoke unlink failed: %s", e)


def ensure_consent(interactive: bool = True) -> bool:
    """Return True if the user has accepted the AUP, False otherwise.

    - PENTEST_TOOLS_AUP_ACCEPTED=1 in env → return True without prompt or persist.
    - File already exists → return True silently.
    - File missing + interactive → print prompt, accept on 'yes', else False.
    - File missing + non-interactive → return False.
    """
    if os.environ.get("PENTEST_TOOLS_AUP_ACCEPTED", "").strip() in ("1", "true", "yes", "on"):
        return True

    if has_consent():
        return True

    if not interactive:
        return False

    sys.stdout.write(PROMPT_TEXT)
    sys.stdout.flush()
    try:
        answer = input("").strip().lower()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write("\n")
        return False

    if answer in ("yes", "y"):
        grant_consent()
        sys.stdout.write("\n[aup] consent recorded. This prompt will not appear again on this machine.\n")
        sys.stdout.write(f"[aup] revoke any time with: rm {CONSENT_PATH}\n\n")
        return True

    sys.stdout.write("\n[aup] not accepted; exiting without scanning.\n")
    return False


def banner_text() -> str:
    """One-line authorized-use banner shown at the top of every engagement."""
    return (
        "pentest-tools performs real network operations. Authorized targets only.\n"
        f"AUP: {AUP_URL}  ·  Terms: {TERMS_URL}\n"
    )

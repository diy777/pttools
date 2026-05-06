# Spec 05: Scope-gated phishing payload tools

**Status:** deferred
**Effort:** 3 days
**Revenue impact:** low (catalog completeness for authorized red team work)

## Goal

Integrate phishing payload + endpoint testing tools (Lockphish,
BlackEye, ShellPhish, Spycam, Keydroid, Chrome Keylogger) behind a
strong authorization gate. Real red team engagements legitimately use
these for awareness testing and EDR validation; pentest-tools currently
gives them generic agent guidance but no execution path.

## The gate (mirrors stress-tools gate, with tighter requirements)

1. **Engagement-level ROE flag** `roe_phishing_payload` set via:
   ```
   pttools start --roe-phishing-payload \
     --roe-text "Authorized red team engagement <id>; ROE permits  
                 phishing payload deployment to authorized recipients" \
     --target-recipients <list-of-emails-or-domain-patterns> \
     --recipients-source <"opt-in-list" | "ad-export" | "hr-roster">
   ```

2. **Recipient allowlist mandatory.** Phishing tools cannot send to
   any recipient not on the explicit list. Glob domain matches require
   `--recipients-domain <domain.com>` AND a confirmation prompt.

3. **Sandbox-only by default.** First run of any phishing tool is
   constrained to send only to a `--sandbox-recipient <email>`
   address, and the operator must confirm in HITL before live mode is
   unlocked for the engagement.

4. **Detection engineering pairing.** Every phishing run automatically
   produces detection content (Sigma rule for the phishing email
   pattern, Sigma rule for the lure domain, MITRE ATT&CK technique
   tags) which gets handed to the engagement's blue team contact.

5. **Decommission policy.** Lure domains must be flagged for
   decommission within 30 days of the engagement closing. The
   `engine/findings_db.py` records the lure domains and a cron-
   compatible decommission_at timestamp.

## Tools to integrate

| Tool | Use | Wrapper |
|------|-----|---------|
| GoPhish | Email campaign + tracking | wrapper around the GoPhish API |
| Evilginx2 | Phishlets + reverse-proxy auth | wrapper around the binary |
| Lockphish | Lockscreen lookalike payload | upstream `lockphish.py` |
| BlackEye | Service login phishlet collection | upstream `blackeye.sh` |
| ShellPhish | Multi-target phishing pages | upstream `shellphish.sh` |

Endpoint payload tools (separate gate, even tighter):

| Tool | Use | Special requirement |
|------|-----|---------------------|
| Spycam | Webcam capture payload | Target device list AND notification banner enforced in payload |
| Keydroid | Android keylogger | Test devices only, MDM enrollment proof required |
| Chrome Keylogger | Browser extension keylogger | Test workstations, EDR-detection-validation purpose only |

## Inputs

- `agents/social_engineer/` already has agent guidance for phishing
- `agents/phishing_operator.md` (in pentest-tools-agents repo) covers
  Evilginx, GoPhish methodology
- `engine/scope.py` validates targets-against-scope
- `engine/findings_db.py` schema can extend with phishing-specific
  tables (`lure_domains`, `phishing_recipients`, `phishing_runs`)
- `engine/hitl.py` for the sandbox-vs-live confirmation gate

## Steps

### Day 1: Gate + DB primitives

1. Migration: add `roe_phishing_payload` column to engagements,
   create `lure_domains`, `phishing_recipients`, `phishing_runs` tables
2. Add `engine/phishing_gate.py`:
   - `validate_engagement_for_phishing(engagement)`
   - `validate_recipient(email, engagement)` — blocks any non-allowlisted
   - `record_lure_domain(domain, engagement, decommission_at)`
   - `validate_decommission_due(engagement_id) -> list[domain]`
3. Tests

### Day 2: GoPhish + Evilginx wrappers

1. Add `tools/web/phishing.py` with:
   - GoPhish wrapper that talks to the GoPhish REST API (campaign
     creation, recipient list upload, send)
   - Evilginx wrapper that drives the binary via subprocess and
     captures session tokens to the findings DB

2. Each wrapper:
   - Calls `validate_engagement_for_phishing` first
   - Iterates recipients and validates each
   - Records run in `phishing_runs` table
   - Auto-generates detection content via the `detection` agent

3. Tests

### Day 3: CLI + endpoint payload tools + docs

1. Add `pttools phishing init` interactive command for setting up the
   ROE + recipient list + sandbox recipient
2. Add `pttools phishing send <campaign>` command
3. Endpoint payload wrappers (Spycam, Keydroid, Chrome Keylogger):
   each has its own narrower gate requiring per-device opt-in evidence
4. README + SECURITY.md updates listing what is and isn't allowed
5. Decommission cron: `pttools phishing decommission` that lists overdue
   lure domains and their cleanup commands

## Validation

- Without `--roe-phishing-payload`, all wrappers fail at the registry
- Without recipient allowlist, send fails before any email
- First run is sandbox-only; live mode requires HITL confirmation
- Detection content is auto-produced and saved
- `pttools phishing decommission` shows overdue domains 30+ days post-
  engagement close

## Out of scope (refused even with all flags set)

- Targeting recipients outside the customer's organization (vendors,
  customers of the customer, partners) without their separate
  authorization
- Persistent malware deployment (the payload tools are for
  awareness/EDR testing, not persistent foothold)
- Anything against political figures, journalists, or activists
  regardless of ROE claims
- Mass-target social media bruteforce (separately scoped, separately
  refused — see Engagement principles)

## Refusal criteria

The orchestrator hard-refuses any run that matches:
- Recipients in domain `*.gov` without an explicit Federal contracting
  number on the ROE
- Lure domains registered in the last 24 hours (immature; signals
  rushed engagement, often a mistake)
- Recipients who appear in a `excluded_recipients` table (added by
  customer admins to opt out specific people from awareness testing)

## How to resume

Paste this spec as the next-session prompt. Start with Day 1 (gate +
DB primitives). The wrappers cannot safely land without the gate
existing first.

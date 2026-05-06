# Spec 04: Scope-gated stress / DoS testing tools

**Status:** deferred
**Effort:** 3 days
**Revenue impact:** low (catalog completeness, niche use cases)

## Goal

Integrate authorized stress and resilience testing tools (SlowLoris,
GoldenEye, hping3, KawaiiDeauther, WifiJammer-NG) behind a gate that
prevents accidental or unauthorized use. Real pentest scope occasionally
includes resilience testing; ignoring this category leaves a gap.

## The gate (mandatory before any of these tools execute)

Each tool is registered as a `SecurityTool` in `tools/registry.py` with
a special category `"stress-test"`. The orchestrator and CLI both check
the following before execution:

1. **Engagement-level ROE flag.** A new column `engagements.roe_stress`
   in the findings DB, set only via:
   ```
   pttools start <target> --roe-stress \
     --roe-text "Customer authorizes stress testing per signed ROE doc <ref>"
   ```
   The `--roe-text` is required (free-form, recorded as evidence).

2. **Target-explicit allowlist.** The target host must be explicitly
   added with `--stress-target <host>` to the engagement. No glob
   patterns, no IP ranges. One host per flag.

3. **Rate ramp.** All stress tools wrap a rate-limit ramp:
   - Start at 1 request / second
   - Double every 30 seconds
   - Cap at the engagement-declared `max_rps` (default 100)
   - Operator must press Enter at each ramp step in the first run
     (can be `--auto-ramp` after a successful first run)

4. **Abort triggers.** The wrapper installs three abort conditions:
   - Target returns >50% non-2xx for 10 consecutive seconds
   - Operator presses Ctrl+C twice (HITL pause, then 'abort')
   - Pre-set wall-clock cap (default: 5 minutes)

5. **Evidence packaging.** Each stress run produces:
   - The exact command and argv
   - A JSON timeline of rates and observed response codes
   - A pre-state and post-state HTTP probe (target reachable / not)

## Tools to integrate

| Tool | Layer | Purpose | Wrapper plan |
|------|-------|---------|--------------|
| SlowLoris | Layer-7 | Slow HTTP keep-alive flood | Existing slowloris.py from upstream |
| GoldenEye | Layer-7 | HTTP DoS with random URLs | upstream `goldeneye.py` |
| hping3 | Layer-3/4 | TCP/IP packet crafting | system `hping3` binary |
| KawaiiDeauther | Wireless | 802.11 deauth packets | upstream go binary |
| WifiJammer-NG | Wireless | 802.11 deauth + disassoc | upstream Python script |

KawaiiDeauther and WifiJammer-NG additionally require an interface in
monitor mode AND a `--wireless-channel <n>` flag (no scanning all
channels).

## Inputs

- `tools/registry.py` already has the `SecurityTool` dataclass and a
  pattern for category-grouped lists
- `engine/scope.py` already validates target-against-scope; we extend
  with `--stress-target` allowlist
- `engine/rate_limiter.py` provides token-bucket primitives we can use
  for the ramp
- `engine/findings_db.py` already has the `engagements` table; we add
  the `roe_stress` column via migration
- `engine/hitl.py` for the operator-press-Enter ramp gates

## Steps

### Day 1: Gate primitives

1. Add migration: `ALTER TABLE engagements ADD COLUMN roe_stress INT DEFAULT 0`
2. Add `engine/stress_gate.py` that exposes:
   - `validate_engagement(engagement) -> bool` — returns True only if
     ROE flag set and ROE text recorded
   - `validate_target(target, engagement) -> bool` — must be in
     stress-target allowlist
   - `RampController` class implementing the rate ramp + abort triggers
3. Tests for each (mock targets and engagements)

### Day 2: Tool wrappers

1. Add `STRESS_TOOLS = [...]` in `tools/registry.py` with the 5 tools
2. Each wrapper's `build_args` calls `validate_engagement` and
   `validate_target` and raises if either fails
3. Wrap execution in `RampController.run(...)` so the rate ramp is
   enforced regardless of how the tool is invoked
4. Tests that confirm: (a) tool refuses without ROE flag, (b) tool
   refuses if target not in allowlist, (c) ramp triggers abort on
   hostile response

### Day 3: CLI + docs

1. Add `--roe-stress` and `--roe-text` flags to `pttools start`
2. Add `--stress-target` (multi-value) flag
3. Add `--auto-ramp` flag (default off; first run is interactive)
4. Update README with a "Stress testing" section that emphasizes
   the gate semantics
5. Add a SECURITY.md section explicitly listing what cannot be done
   even with --roe-stress (e.g., DDoS without a hosting provider's
   blessing in shared infra)

## Validation

- Without `--roe-stress`, attempting to invoke a stress tool fails
  at the registry layer (before any packets sent)
- With `--roe-stress` but a target outside the allowlist, fails before
  packets sent
- First run with valid scope shows the rate ramp prompts each step
- Ctrl+C during ramp aborts cleanly
- Evidence package includes the ROE text on every stress run

## Out of scope

- IP-spoofed amplification attacks (NTP, DNS, memcached) — refused
  outright. The infrastructure they target isn't the user's, even
  with authorization claims about their own server.
- Layer-2 ARP storms beyond /24 broadcast domains
- Wireless tools that target third-party (non-engagement) APs nearby

## Refusal criteria (hard-coded, no flag bypass)

- Targets not under the engagement's authorization
- Floods originating from infrastructure the user doesn't control
- Deauth attacks against APs where the user cannot prove ownership
  (engagement notes are evidence, not proof; if challenged, refuse)
- Any pattern matching "ddos as a service" / "rent flood capacity" —
  this tooling is for authorized resilience testing, not as-a-service

## How to resume

Paste this spec as the next-session prompt. Start with Day 1 (gate
primitives) — the gate must exist before any of the tool wrappers can
safely land.

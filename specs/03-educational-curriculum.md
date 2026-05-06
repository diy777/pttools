# Spec 03: Educational curriculum (CAI Fluency-style)

**Status:** deferred
**Effort:** 4-6 weeks of content
**Revenue impact:** medium (onboarding asset, SEO, conference workshop)

## Goal

8-episode hands-on series teaching pentest-tools from zero to running real
engagements. Content lives at pentest-tools.local/learn and on YouTube. Target
audience: security students, junior pentesters, bug bounty hunters new
to AI tooling.

Inspired by CAI Fluency (Mayoral-Vilches et al. 2025, arXiv 2508.13588)
which is the educational asset CAI uses to onboard users.

## Episode plan

### Episode 1: First scan (15 min)
- Install pttools
- `pttools start http://testphp.vulnweb.com` against an OWASP-blessed
  vulnerable site
- Read the report
- Question: what's a finding? What's a chain? What's an evidence?

### Episode 2: Authentication (15 min)
- DVWA local Docker setup
- `pttools auth profile add dvwa-low`
- Authenticated scan
- Compare findings with vs without auth

### Episode 3: Scope and ROE (10 min)
- Why scope.py matters
- Walking through a 4-line ROE doc
- What pentest-tools refuses to do without authorization
- The Tier 1 vs Tier 2 model

### Episode 4: The agent specialization (20 min)
- recon → web → exploit_chain → poc_validator → report flow
- When you'd use each individually
- Multi-agent coordination via the orchestrator
- Visual: dashboard timeline as agents hand off

### Episode 5: Reading findings (15 min)
- CVSS scoring philosophy (v3.1 base score, environmental, temporal)
- ATT&CK mapping
- Confidence levels: confirmed vs inferred vs speculative
- The PoC validator's role

### Episode 6: Reporting (15 min)
- 6 output formats: Markdown, HTML, PDF, SARIF, JUnit, compliance
- When to use which
- Customizing the report template
- Client-ready vs internal triage

### Episode 7: Detection engineering (15 min)
- Pairing offense with defense
- The detection agent's output
- Sigma → SPL → KQL conversion
- Handing rules to the blue team

### Episode 8: HITL and the dashboard (20 min)
- Ctrl+C twice to take over
- Real-time dashboard view
- Injecting instructions mid-run
- When the agent gets it wrong (and how to recognize it early)

## Format

- Each episode: 10-20 min video + accompanying markdown writeup
- Hands-on labs: every episode produces a Docker-compose snippet the
  viewer can spin up themselves
- Final exam: 5-question quiz per episode (knowledge of the concept,
  not pass/fail gating)
- Optional: completion badge issued at pentest-tools.local/learn/badge

## Inputs

- README + INSTALL.md cover Episode 1's content already
- `benchmarks/challenges/dvwa-sqli/` is Episode 2's lab setup
- `engine/scope.py` is Episode 3's reference
- `agents/*` directory structure is Episode 4's outline
- `engine/cvss.py` and `engine/sarif.py` are Episodes 5-6
- `engine/hitl.py` is Episode 8

## Steps

### Phase 1: Outlines and scripts (1 week)

1. Draft a 1-page script per episode
2. Identify each lab setup (Docker compose, target host, expected
   commands)
3. Review for accuracy and tone

### Phase 2: Recording (2-3 weeks)

1. Screen recording with terminal + dashboard view
2. Cut and dub voiceover
3. Add text overlays for commands (so viewers can pause and copy)
4. Render at 1080p, English subtitles

### Phase 3: Companion writeups (1 week)

1. Markdown writeup per episode at `learn/episode-NN-<topic>.md`
2. Each includes: what we cover, hands-on lab steps, quiz, next steps
3. Cross-link episodes

### Phase 4: Publishing (3 days)

1. YouTube playlist: "pentest-tools from zero"
2. Marketing site `/learn` page indexing the playlist + writeups
3. Cross-post episode 1 to LinkedIn, X, Reddit r/cybersecurity
4. Announce in Discord (when that exists)

## Validation

- All 8 episodes published
- Total runtime: 2-2.5 hours
- /learn page indexed by Google
- Episode 1 has >5,000 views in 30 days (conservative target)
- 1+ enterprise customer cites the curriculum in a sales conversation

## Out of scope

- Paid premium content (curriculum stays free for SEO and adoption)
- Certification exam (later, if user demand justifies it)
- Translations (English first; community-translated later)
- Mobile-app filming (desktop screen recording only for v1)

## How to resume

Paste this spec as the next-session prompt. Start with Phase 1
(outlining episode 1 in detail) — that's the smallest unit that
produces the first deliverable.

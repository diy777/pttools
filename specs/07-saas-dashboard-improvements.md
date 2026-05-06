# Spec 07: SaaS dashboard improvements (app.pentest-tools.local)

**Status:** deferred
**Effort:** multi-week (3-4 weeks for v1)
**Revenue impact:** high — direct ARR growth on existing $39/$59 tiers

## Goal

Improve the existing SaaS dashboard at `app.pentest-tools.local` (which lives
in `pentestai-private/saas-platform/`) with the features that justify
upgrading from OSS to Pro / Team / Enterprise.

The OSS local dashboard (shipped 2026-04-28) is the entry point. The
SaaS dashboard is what users pay $39 to upgrade to. It must feel like
a meaningful step up.

## Inputs (existing in pentestai-private/saas-platform/)

- 25 D1 migrations
- Multi-tenant Cloudflare Pages deployment at `pentest-tools-prod`
- Existing pages: `dashboard.html`, `signup.html`, `billing.html`,
  `dpa.html`, `privacy.html`, `refunds.html`, `status.html`, `demo.html`
- Functions: `_lib/`, `api/`, `scim/` (SCIM 2.0 already implemented)
- Stripe integration (in `scripts/stripe-setup.sh`)
- Scan worker for queued scans

## Features to add

### Tier 1: Pro-tier upgrades (highest leverage)

1. **Scheduled scans** — UI to schedule recurring scans (cron-style),
   stored in D1, executed by the scan worker. The single biggest
   "convenience" value Pro adds over OSS.

2. **Mobile-friendly responsive design** — current dashboard isn't
   mobile-optimized; "check your scan from your phone" is a Pro
   selling point but doesn't currently work.

3. **Email + Slack + Discord notifications** — scan completion, new
   critical finding, weekly summary digest. Webhooks already exist
   in `engine/webhooks.py`; SaaS exposes them via UI.

4. **Trend dashboards** — engagement count over time, severity
   distribution, mean-time-to-finding by agent. Uses existing D1
   data; needs a charts UI.

5. **PDF report customization** — logo upload, color theme, footer
   text. Report agent already produces PDFs; UI lets Pro users brand
   them per-engagement or per-customer.

6. **API key management** — generate, rotate, scope-limit API keys
   for the REST API. Already partially in saas-platform; needs UI
   polish.

### Tier 2: Team-tier additions

1. **Multi-user workspace** — invite teammates via email, role-based
   access (admin, analyst, reviewer). SCIM is already implemented;
   the UI needs to expose it.

2. **Findings triage workflow** — assign findings to teammates,
   comment thread per finding, status workflow (new → triage →
   confirmed → reported → resolved → dismissed).

3. **Per-client engagement segregation** — group engagements by
   customer, separate report templates per customer, separate
   billing line items.

4. **Audit log UI** — who did what when. Backend exists; UI doesn't.

5. **Shared playbooks** — team library of reusable engagement
   templates, copy-on-fork to a new engagement.

### Tier 3: Enterprise additions

1. **SAML SSO UI** — IDP config wizard, certificate upload, mapping
   rules. SCIM endpoint is at `saas-platform/scim/`; SAML hookup is
   the next step.

2. **Audit log export** — SARIF-style JSON export for SOC 2 auditors,
   plus a webhook for live SIEM forwarding (Splunk, Elastic, Sentinel).

3. **IP allowlist** — restrict which source IPs can authenticate to
   an Enterprise tenant. Cloudflare Worker can enforce this trivially
   via a list maintained in D1.

4. **Custom integrations** — Jira / Linear / GitHub project field
   mappings, configurable per-customer.

5. **Dedicated subdomain** — `{customer-slug}.pentest-tools-prod.pages.dev`
   for white-label deployments.

## Steps

### Sprint 1 (week 1): Pro-tier scheduled scans + mobile

1. D1 migration: `scheduled_scans` table (engagement_id, cron, next_run,
   last_run, last_status)
2. Scheduler worker: polls every minute, kicks off scans on due rows
3. UI: "Schedule" button on engagement detail, cron picker, list of
   scheduled scans, pause / resume / delete actions
4. Mobile: rebuild current dashboard with a responsive grid; current
   layout fights at <600px
5. Tests: scheduler doesn't fire-and-forget (idempotent on retry),
   missed runs are caught up

### Sprint 2 (week 2): Notifications + trend dashboard

1. Notification settings UI: per-user, per-channel (email, Slack,
   Discord), per-event (scan-complete, critical-finding, weekly-digest)
2. Use existing `engine/webhooks.py` patterns; add email via Resend
3. Trend dashboard: 4 charts (engagement count, severity histogram,
   findings-per-day, agent-mix). Uses Chart.js loaded via CDN.

### Sprint 3 (week 3): Team workspace + triage

1. Workspace admin UI: invite teammates (already SCIM-capable backend),
   roles, role-based visibility
2. Findings triage: assignee dropdown, comment thread, status workflow
3. Audit log UI: filterable list of who-did-what-when
4. Per-client engagement grouping

### Sprint 4 (week 4): Enterprise SAML + audit export

1. SAML SSO config wizard
2. Audit log export endpoint with cursor-based pagination
3. SIEM webhook forwarder (configurable per Enterprise tenant)
4. IP allowlist enforced at Cloudflare Worker layer

## Validation

- Pro signups in the 30 days post Sprint 1 land >2x baseline
- Scheduled scans deliver on time within 60 seconds of cron tick
- Mobile dashboard score >85 on Lighthouse mobile audit
- Team workspace: 2-user test setup completes signup → invite →
  accept → finding assignment in <5 minutes
- Enterprise SAML wizard works against Okta + Azure AD as test IDPs

## Out of scope

- Self-service Enterprise signup (sales-led for the foreseeable
  future)
- Crypto / on-chain payment options
- Localization (English first; community-translated later)
- Native mobile app (PWA on app.pentest-tools.local suffices for v1)

## How to resume

Paste this spec as the next-session prompt. Start with Sprint 1
(scheduled scans + mobile) — the highest-leverage Pro feature. Each
sprint is mostly independent so they can run in parallel if you have
the bandwidth.

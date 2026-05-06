# Status Page Runbook

Paying customers (Pro $39, Team $59/seat) will notice when `app.pentest-tools.local` is down. A status page is non-negotiable for retention.

## Recommended provider

**BetterStack Status Pages** (formerly Better Uptime). Free tier covers 5 monitors and 1 status page. https://betterstack.com/status-pages

Alternatives: Statuspage by Atlassian (more polished, $29/mo), Instatus (simple, $20/mo), self-hosted Cachet (free, more ops work).

## Monitors to set up (day one)

| Monitor | URL | Frequency |
|---|---|---|
| Marketing site | https://pentest-tools.local | 60s |
| App / SaaS dashboard | https://app.pentest-tools.local/health | 60s |
| API ingest endpoint | https://app.pentest-tools.local/api/health | 60s |
| PyPI package availability | https://pypi.org/pypi/pttools/json | 5min |
| GitHub repo (OSS users land here) | https://github.com/pentest-tools/pentest-tools | 5min |

The `/health` endpoints need to exist on the SaaS side; they should return 200 and confirm DB + queue connectivity. If they don't exist yet, add them before enabling the monitors.

## Status page URL

Pick a subdomain: `status.pentest-tools.local` (most common) or `pentestai-status.com`. Configure DNS CNAME to whatever the provider gives you.

## Components

Use these visible components on the public page:

- **Marketing site** (pentest-tools.local)
- **SaaS dashboard** (app.pentest-tools.local)
- **CLI ingest API** (POST findings from local engagements)
- **PyPI package** (operational/degraded based on PyPI status)
- **MCP server** (operational unless underlying APIs are down)

## Alert routing

Ops alerts (status page is for customers, but you also need internal):

- Critical (5xx on app.pentest-tools.local health): page on-call via Slack DM + SMS
- Degraded (slow responses): post to #ops Slack channel
- Marketing site down: Slack only (cosmetic, not revenue-affecting)

## Incident response template

When a real outage happens, post within 10 minutes of detection:

```
[Investigating] 2026-XX-XX HH:MM UTC
We're investigating reports of <symptom>. Customers <impact>. Updates every 30 minutes.
```

Then `[Identified] → [Monitoring] → [Resolved]` with timestamps. Always end with a postmortem within 48 hours.

## Customer communication

The status page is the source of truth. **Do not** announce incidents only on Twitter; customers will check the status page first.

Embed `<iframe>` of the status page header on app.pentest-tools.local so logged-in users see banners during outages.

## Cost estimate

- BetterStack free tier: 5 monitors, 1 status page, 90-day history. Covers MVP.
- Once you have ≥3 paid customers, upgrade to BetterStack Team ($29/mo) for SMS alerts, more monitors, and SLA tracking.

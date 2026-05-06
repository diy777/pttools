# Subprocessor List

> **Effective date:** 2026-05-15
> **Last updated:** 2026-05-15

This page lists the third-party service providers (subprocessors) that may process personal data on behalf of pentest-tools under the [Privacy Policy](PRIVACY.md). We update this list whenever we add or remove a subprocessor; material changes are notified to active customers via email at least 30 days before they take effect, so you have time to object.

## Active subprocessors

| Vendor | Purpose | Personal data accessed | Region of processing | DPA / SCCs |
|--------|---------|------------------------|----------------------|------------|
| Cloudflare, Inc. | Marketing site CDN, DNS, DDoS, Workers (auth), Pages (hosting) | IP address, request headers, cookies | Global edge; primary US | Cloudflare DPA + 2021 SCCs |
| Stripe, Inc. | Payment processing, subscription billing | Name, email, billing address, last 4 of card (Stripe holds full PAN), payment history | US, with EU sub-processors | Stripe DPA |
| Anthropic, PBC | LLM inference for the dashboard's optional managed-model tier (only if you opt in to managed keys; default is BYOK) | Engagement context sent to the model | US | Anthropic DPA |
| OpenAI OpCo, LLC | LLM inference for managed-model tier (opt-in only) | Engagement context | US | OpenAI DPA |
| Cloudflare Workers + D1 | Application hosting, database, object storage for evidence | All dashboard data | global edge; primary US, EU region (eu-west) available on request for Enterprise | DPA + 2021 SCCs |
| Resend | Transactional email (account, billing, security alerts) | Email address, email content | US | DPA available |
| Sentry | Application error monitoring with PII scrubbing | Stack traces, scrubbed of secrets and PII | EU or US | DPA |
| BetterStack | Status page hosting and uptime monitoring | Aggregated metrics, no customer personal data | EU | BetterStack DPA |
| GitHub, Inc. | Source code hosting (public OSS repo + closed dashboard repo); release automation | None directly; we never push customer data to GitHub | US | GitHub DPA |
| PyPI (Python Software Foundation) | Distribution of the open-source CLI package | None | US | PSF privacy policy |

**No "selling" or "sharing" for advertising.** None of the above receives data for advertising or third-party tracking. Each subprocessor is contractually limited to the listed purposes.

## Onboarding a new subprocessor

Before we add a subprocessor, we:

1. Conduct a due-diligence review (security posture, certifications, breach history, ownership)
2. Sign a Data Processing Agreement and (for transfers outside the EEA/UK) Standard Contractual Clauses
3. Conduct a transfer impact assessment if the subprocessor is in a third country
4. Update this page and email active customers at least 30 days in advance

Customers may object by emailing `privacy@pentest-tools.local`. If we cannot reach an alternative arrangement, we will work with you to wind down the affected portion of the Service.

## Removing a subprocessor

When we remove a subprocessor we delete or return the data they hold within the timeline required by the underlying DPA (typically 30 to 90 days), confirm deletion in writing, and update this page.

## Audit rights

Enterprise customers have the right to request audit reports (SOC2, ISO 27001) from our subprocessors via us, or to conduct on-site audits per the terms of the Enterprise MSA. Pro and Team tier customers may request the most recent audit attestation summary via `privacy@pentest-tools.local`.

## Contact

- Subprocessor questions: `privacy@pentest-tools.local`
- Notification mechanism: in-app banner on the dashboard plus an email to the workspace owner

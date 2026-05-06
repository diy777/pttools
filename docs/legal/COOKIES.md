# Cookie Policy

> **Effective date:** 2026-05-15
> **Last updated:** 2026-05-15

This Cookie Policy explains how we use cookies and similar technologies on `pentest-tools.local`, `app.pentest-tools.local`, `status.pentest-tools.local`, and any other domain we operate. It supplements the [Privacy Policy](PRIVACY.md).

## What is a cookie?

A cookie is a small text file that a website saves on your device (browser, phone, desktop) when you visit. Cookies let the site remember actions and preferences over time. We also use related technologies like local storage and session storage; for simplicity we call them all "cookies" here.

## Cookies we use

### Strictly necessary (always on, no consent needed)

These cookies are required for the Service to function. You cannot disable them via our consent banner; you can disable them in your browser, but the Service will not work.

| Name | Purpose | Domain | Lifetime |
|------|---------|--------|----------|
| `pa_session` | Login session for the dashboard | `app.pentest-tools.local` | 30 days, refreshed on activity |
| `pa_csrf` | CSRF token for forms | `app.pentest-tools.local` | session |
| `cf_*` | Cloudflare security and bot detection | `*.pentest-tools.local` | per Cloudflare |
| `__stripe_*` | Stripe checkout and SCA | `app.pentest-tools.local` (set by Stripe iframe) | per Stripe |

### Functional (off by default; on if you opt in)

These cookies improve the user experience but are not strictly necessary.

| Name | Purpose | Domain | Lifetime |
|------|---------|--------|----------|
| `pa_theme` | Remember your light/dark theme preference | `app.pentest-tools.local` | 1 year |
| `pa_workspace` | Remember the last workspace you viewed | `app.pentest-tools.local` | 90 days |

### Analytics (off by default; on if you opt in)

We use **Plausible Analytics** (privacy-by-design, no cookies, no personal data, no cross-site tracking) for aggregate page views and referrer counts. Plausible does not set cookies, so no consent banner is required in the EU/UK/CA for analytics. If we ever add an analytics vendor that does set cookies we will update this section at least 30 days before the change takes effect.

**Option A. Privacy-respecting analytics (Plausible or Simple Analytics):**

| Name | Purpose | Lifetime | Cookies set |
|------|---------|----------|-------------|
| Plausible (or Simple Analytics) | Aggregate page views and referrers; no personal data, no cross-site tracking, no cookies | — | none |

If you go this route you don't need analytics consent under most regimes because no personal data is processed and no cookies are set. State that clearly here.

**Option B. Google Analytics 4 (cookies + consent banner required):**

| Name | Purpose | Domain | Lifetime |
|------|---------|--------|----------|
| `_ga` | GA4 client ID | `pentest-tools.local` | 2 years |
| `_ga_*` | GA4 session state | `pentest-tools.local` | 2 years |

GA4 receives IP-truncated, anonymized data. Consent is required in the EEA, UK, Switzerland, and California (do-not-sell). You can opt out via our cookie banner at any time.

### Marketing (off by default; on if you opt in)

We do not run paid retargeting at this time. This section is a placeholder so when we add marketing pixels (LinkedIn, Twitter/X, Reddit, etc.) we update it 30 days before the change takes effect.

## How to control cookies

- **Cookie banner.** On first visit you see a banner with three options: Accept all, Reject non-essential, Customize. Your choice is remembered for 12 months and you can change it any time at `pentest-tools.local/cookies`.
- **Browser settings.** All major browsers let you block, allow, or delete cookies. If you block strictly necessary cookies, the dashboard will not work.
- **Do Not Track / Global Privacy Control.** We honor the GPC signal as an opt-out from non-essential cookies, consistent with CPRA.

## Changes

We update this policy when we add or remove cookies. Material changes are notified at least 30 days in advance via the cookie banner and email. The "Last updated" date at the top reflects the most recent version.

## Contact

- Privacy: `privacy@pentest-tools.local`

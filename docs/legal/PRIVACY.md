# Privacy Policy

> **Effective date:** 2026-05-15
> **Last updated:** 2026-05-15
>
> **DRAFT — pending legal review.** Have a lawyer review before publishing at `pentest-tools.local/privacy`. Particularly important: GDPR (EU customers), UK GDPR, CCPA / CPRA (California), VCDPA (Virginia), CTDPA (Connecticut), other state privacy laws (Colorado, Utah, Oregon, Texas, etc.), HIPAA (any healthcare client whose data you scan, only relevant if you sign a BAA), SOC2 (enterprise tier audit), and any local data protection law in jurisdictions where you sell.

## Who we are

The Service is operated by pentest-tools, (legal entity formation in progress — write to legal@pentest-tools.local for verified entity name and registered office address), registered office: Postal correspondence: write to legal@pentest-tools.local to request the, current registered address. We will publish a permanent postal address, here when the legal entity is finalized. ("we", "us", "our"). Contact: `privacy@pentest-tools.local`. EU/UK data subjects: see Section 9 for our Article 27 representative if applicable.

## What this policy covers

This Privacy Policy describes how we collect, use, and protect personal data when you interact with:

- the **pentest-tools CLI** installed on your machine (open source, MIT licensed)
- the **pentest-tools SaaS dashboard** at `app.pentest-tools.local` (paid tiers)
- the **MCP server** when configured to sync to our cloud
- the **pentest-tools.local** marketing site, status page, and supporting domains

It does **not** cover data handled by third-party LLM providers (Anthropic, OpenAI, etc.) when you bring your own key; those vendors have their own policies you must accept directly. It also does not cover data on systems you scan with the Service; you are responsible for your testing scope (see [AUP](AUP.md)).

## Legal bases for processing (GDPR / UK GDPR)

We process personal data under one or more of these legal bases:

| Activity | Legal basis |
|----------|-------------|
| Account login, billing, supplying the Service | Contract (Article 6(1)(b)) |
| Security, fraud prevention, abuse handling, audit logs | Legitimate interests (Article 6(1)(f)) |
| Compliance with legal obligations (tax, KYC where applicable) | Legal obligation (Article 6(1)(c)) |
| Marketing email | Consent (Article 6(1)(a)) — opt-in only, withdrawable any time |
| Anonymized telemetry from the CLI | Consent (Article 6(1)(a)) — off by default |

We do not rely on legitimate interests for marketing.

## Data the CLI collects

**By default: none.** The CLI runs locally. Findings are written to a SQLite file in your working directory. No telemetry, no analytics, no phone-home unless you explicitly opt in.

**Opt-in telemetry** (run `pttools telemetry enable` or set `PENTEST_TOOLS_TELEMETRY=1` *and* the consent file): we collect anonymous usage counters (engagements started, scopes used, error types, agent durations). We do **not** collect target identifiers, IP addresses you scan, finding contents, credentials, source code, or PII. The exact payload schema is in our public source at [`engine/telemetry.py`](https://github.com/pentest-tools/pentest-tools/blob/main/engine/telemetry.py) so you can audit it. You may revoke consent at any time with `pttools telemetry disable`.

## Data the dashboard collects

When you sign in to `app.pentest-tools.local` with a Pro, Team, or Enterprise account:

| Data | Purpose | Retention |
|------|---------|-----------|
| Email address, name | Login, transactional email, billing receipts | Until account deletion |
| Hashed password (bcrypt/argon2id) | Authentication | Until account deletion or password change |
| Workspace and team membership | Multi-user access control | Until removed by you |
| Engagement metadata (target identifier, scope, status, timestamps) | Display history, generate reports, sync from CLI | 12 months default; configurable per workspace; deletable on request |
| Findings (title, severity, evidence excerpt, remediation text) | The product itself | Same as engagements |
| Audit log (who did what, when, from which IP) | SOC2 controls, customer accountability, abuse handling | 7 years (legal/compliance retention) |
| Stripe customer ID, last 4 digits of card, billing address | Billing (Stripe holds full PAN) | While account is active + 7 years for tax records |
| Support ticket history | Customer support | 3 years from last contact |
| Cookies and similar technologies | Session, security, optional analytics | See [Cookie Policy](COOKIES.md) |

We do **not** store:

- Your LLM API keys (they live in your shell env or your dashboard secrets vault, encrypted at rest with a per-workspace key you control)
- Plaintext credentials for scanned targets (auth profiles store references to env vars or external vaults, not the secret values)
- Source code from your scanned targets (we store findings, not the targets themselves)
- Full network captures from scans

## How we use data

We use personal data to:

- Operate, maintain, and improve the Service
- Authenticate you, bill you, send you transactional email
- Detect and prevent abuse, fraud, and security incidents
- Comply with legal obligations (tax, lawful demands, audit)
- Conduct aggregated, anonymized analytics for product decisions (e.g., "70% of engagements use the web scope")
- With your opt-in consent, send you marketing email about the product

We do **not**:

- Use your engagement data, findings, or scanned target content to train AI models — yours or ours
- Sell personal data to third parties
- Share data with third parties other than the subprocessors in Section 7
- Send marketing email without consent

## Sharing and subprocessors

The current list of subprocessors (vendors who process personal data on our behalf) is maintained at `pentest-tools.local/subprocessors` and in the [SUBPROCESSORS.md](SUBPROCESSORS.md) file. Material changes (adding a new subprocessor) get 30 days' notice via email so you can object.

We may also disclose data:

- To comply with valid legal process (subpoena, court order). We notify you unless legally prohibited.
- To enforce our rights (these Terms, the AUP), prevent fraud, or protect users.
- In a merger, acquisition, or asset sale, subject to standard data-protection covenants.

## International transfers

Personal data may be processed in the United States and other jurisdictions where our subprocessors operate. For transfers from the EEA, UK, and Switzerland, we rely on:

- **Standard Contractual Clauses (SCCs)** (Module 2 — controller to processor) approved by the European Commission, Decision (EU) 2021/914
- **UK International Data Transfer Addendum** to the EU SCCs
- **Swiss FDPIC SCC supplements**

We perform transfer impact assessments (TIAs) for high-risk recipients and apply supplementary measures (encryption in transit and at rest, access controls, ability to challenge requests) to meet the Schrems II standard.

## Your rights

Subject to your local law (GDPR / UK GDPR Articles 15-22, CCPA / CPRA Sections 1798.100-1798.150, Virginia VCDPA, Connecticut CTDPA, Colorado CPA, etc.):

- **Access:** request a copy of the personal data we hold about you. We respond within 30 days (45 with notice for complex cases) and in JSON or PDF.
- **Rectification:** correct inaccurate data via dashboard settings or by emailing us.
- **Deletion / erasure:** delete your account (which purges your data within 30 days) via dashboard settings or by emailing us. Audit logs are retained per legal obligation; we redact unnecessary personal data on deletion.
- **Portability:** export all your engagements and findings as JSON or CSV via dashboard settings.
- **Restriction / object:** ask us to stop processing your data for marketing or analytics. Some processing is necessary to operate the Service and cannot be stopped without account deletion.
- **Withdraw consent:** for telemetry or marketing, toggle in dashboard settings or run `pttools telemetry disable`.
- **Non-discrimination:** we do not deny service, change pricing, or degrade experience because you exercised a right.
- **Lodge a complaint:** with your local data protection authority. EU residents: see https://edpb.europa.eu/about-edpb/about-edpb/members_en. UK: ICO. California: CA DOJ.

To exercise any right, email `privacy@pentest-tools.local` with proof of identity (we may ask for verification before responding).

## Children

The Service is not directed at children under 16. We do not knowingly collect personal data from anyone under 16. If you believe we have collected such data, email `privacy@pentest-tools.local` and we will delete it.

## EU / UK Article 27 representative

We do not currently offer the Service to residents of the EU, the EEA, the United Kingdom, or Switzerland. Sign-up from those jurisdictions is geofenced at the application layer (HTTP 451) and we will appoint an Article 27 / UK GDPR representative before we open availability there. Customers in those regions: write to `privacy@pentest-tools.local` to be notified when sign-up opens.

## Security measures

- TLS 1.3 for all traffic (HSTS preload submitted)
- Encryption at rest with AES-256 for the dashboard database
- Hashed passwords (argon2id) — we cannot recover the plaintext
- Per-customer data isolation in the multi-tenant DB (workspace_id row-level filter on every query)
- Principle of least privilege for employee access; access is logged and reviewed
- SOC2 Type I attestation: in progress; target completion Q4 2026
- SOC2 Type II audit: planned for 2027
- Bug bounty / responsible disclosure: see [SECURITY.md](../../SECURITY.md)
- Quarterly third-party penetration test by an independent firm (you, ironically)

## Breach notification

In the event of a personal data breach as defined under GDPR Article 33, we will:

- Notify the relevant supervisory authority within 72 hours of becoming aware (GDPR Article 33)
- Notify affected data subjects without undue delay if the breach is high risk (Article 34)
- Provide affected customers with the nature of the breach, categories and approximate number of records, contact for more information, and mitigation steps
- Document the incident and remediation in our internal incident register (Article 33(5))

## California-specific disclosures

Under the CCPA / CPRA:

- We do not "sell" personal information.
- We do not "share" personal information for cross-context behavioral advertising.
- "Categories collected" maps to the table in "Data the dashboard collects" above.
- "Categories disclosed for a business purpose" is the same as the subprocessors list.
- You may submit consumer requests at `privacy@pentest-tools.local`. We do not require an account to submit a request.
- You may authorize an agent (with proof) to submit requests for you.
- Notice at collection: we collect identifiers (email, IP), commercial information (subscription tier), internet activity (logs), and inferences (none for advertising). Sources: directly from you and from your CLI/dashboard usage.

## Changes to this policy

We may update this Privacy Policy from time to time. Material changes are posted at `pentest-tools.local/privacy` with at least 30 days' notice via email. The "Last updated" date at the top reflects the most recent version. Continued use after the effective date constitutes acceptance.

## Contact

- Privacy: `privacy@pentest-tools.local`
- Postal: Postal correspondence: write to legal@pentest-tools.local to request the, current registered address. We will publish a permanent postal address, here when the legal entity is finalized.
- Data Protection Officer: not appointed (we are not subject to the narrow Article 37 mandatory cases).

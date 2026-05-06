# Acceptable Use Policy

> **Effective date:** 2026-05-15
>
> **DRAFT — pending legal review.** Have a lawyer review the indemnification, takedown, and abuse-handling sections before publishing at `pentest-tools.local/aup`. This policy is more important than the Terms of Service for a tool of this kind: it is what limits our liability when a user misuses pttools to attack a target they were not authorized to test.

This Acceptable Use Policy ("AUP") governs your use of the pentest-tools CLI, the pentest-tools SaaS dashboard, the MCP server, and any related services (collectively, the "Service"). By using the Service you agree to this AUP and to the [Terms of Service](TERMS.md) and [Privacy Policy](PRIVACY.md). The AUP is incorporated into the Terms by reference; a violation of this AUP is a violation of the Terms.

## 1. Authorization is your responsibility

The Service is offensive security tooling. It performs real network and host operations (port scans, vulnerability probes, credential testing, browser automation, exploitation proof-of-concept generation) against the targets you specify.

**You are solely responsible for ensuring you have explicit, written, in-scope authorization to test every target before you run the Service against it.** Acceptable forms of authorization include:

- A signed Statement of Work (SOW) or Master Services Agreement (MSA) with rules-of-engagement
- A Bug Bounty program scope page that explicitly permits the techniques the Service uses (and you stay within that scope)
- Written authorization from the target system's legal owner that names you and the time window of the test
- A documented authorization for a system you personally own and operate

You must keep this authorization on file and produce it on request from us, the target's owner, or law enforcement.

We do not authorize you to test anything. We provide a tool. We have no relationship with the targets you scan and no ability to verify you have permission. Misuse is your liability, not ours.

## 2. Prohibited targets

You may not use the Service against:

- Any system, network, application, account, or data you do not own or have explicit written authorization to test
- Infrastructure operated by us, our subprocessors (Cloudflare, Stripe, Anthropic, OpenAI, AWS, GCP, etc.), or any third-party service whose terms prohibit security testing
- Critical infrastructure as defined by CISA's 16 critical infrastructure sectors (United States) without explicit, current, written authorization from the operator
- Government systems, election systems, healthcare systems, or financial systems you do not own
- Systems located in jurisdictions where the technique is illegal regardless of authorization (some EU member states still criminalize "hacking tools" possession; you are responsible for knowing your local law)

## 3. Prohibited conduct

Even on authorized targets, you may not:

- Run denial-of-service attacks (the Service's safety defaults prevent volumetric DoS; do not disable them)
- Exfiltrate data beyond what is strictly necessary to demonstrate a finding (no full-database dumps, no credential harvest beyond a single proof, no PII extraction)
- Persist or escalate beyond the scope agreed with the target's owner
- Use the Service to commit fraud, money laundering, sextortion, doxxing, harassment, or any other criminal act
- Use the Service to develop or deliver malware against unauthorized targets
- Re-sell access to the Service or the dashboard without a written agreement with us
- Attempt to access another customer's workspace, findings, or audit logs
- Reverse-engineer, decompile, or extract source from the closed-source dashboard server
- Circumvent rate limits, license gates, or scope enforcement in the Service

## 4. Compliance with law

You must comply with all applicable laws when using the Service, including but not limited to:

- The **Computer Fraud and Abuse Act (CFAA)** and the **Wiretap Act** in the United States
- The **Computer Misuse Act 1990** in the United Kingdom
- The **NIS2 Directive** and **GDPR Article 32** in the European Union
- **PIPEDA** in Canada, **Privacy Act 1988** in Australia, **PIPL** in China, equivalents elsewhere
- Local laws on the possession, use, and export of penetration testing tools

If your country considers offensive-security tooling to require a license, certification, or government registration, you are responsible for holding that authorization before using the Service.

## 5. Reporting findings to target owners

If you find a critical vulnerability in a target you are authorized to test, you should disclose it to the target's owner under the terms of your engagement. We do not disclose findings to anyone other than you or your team.

If you find a vulnerability in a target you are NOT authorized to test (the Service should not be in this state, but mistakes happen), you must:

1. Stop immediately
2. Delete any findings, evidence, or screenshots that captured the unauthorized target
3. Notify the target's owner via their published security disclosure channel if practical
4. Not publicly disclose the vulnerability without the target's consent

## 6. Reporting abuse of the Service

If you believe someone is using pttools to attack a target without authorization (your target, or any other), report it to us:

- Email: `abuse@pentest-tools.local` with subject `[ABUSE] short description`
- Include: the target identifier, the date/time you observed activity, what you observed, and any evidence (logs, packet captures, finding IDs if you saw them in our system)
- We acknowledge receipt within 1 business day
- We do not promise to identify the actor; we cooperate with valid legal process from law enforcement

## 7. Our enforcement options

When we receive a credible abuse report, we may, in our sole discretion:

- Suspend the offending account immediately
- Delete the offending workspace, including findings and evidence (subject to our 7-year audit log retention obligation)
- Refuse refunds for the suspended period
- Cooperate with law enforcement, including handing over account information, IP addresses, billing data, and audit logs in response to valid legal process
- Terminate the account permanently and refuse future signups from the same actor
- Publicly disclose abuse patterns without naming the actor (e.g., "we suspended N accounts in 2026 for unauthorized testing of healthcare systems") in our annual transparency report

We do not pre-screen scans; we have no way to know whether you have authorization to test a target. We act on reports.

## 8. Indemnification

You will defend, indemnify, and hold us harmless from any claim, loss, damage, or expense (including reasonable legal fees) arising from:

- Your use of the Service against a target you were not authorized to test
- Your violation of any law in connection with the Service
- Your violation of this AUP, the Terms, or the Privacy Policy
- Any dispute between you and a target system owner about your testing

This obligation survives termination of your account.

## 9. Changes to this AUP

We may update this AUP to address new threats, new laws, or new product capabilities. Material changes will be posted at `pentest-tools.local/aup` with at least 30 days' notice via email to account holders. Continued use after the effective date constitutes acceptance.

## 10. Contact

- General abuse reports: `abuse@pentest-tools.local`
- Legal process / law-enforcement requests: `legal@pentest-tools.local`
- Security vulnerabilities in the Service itself: see [SECURITY.md](../../SECURITY.md)

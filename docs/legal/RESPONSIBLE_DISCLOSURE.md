# Responsible Disclosure Policy

> Public-facing version of [SECURITY.md](../../SECURITY.md). Lives at `pentest-tools.local/security`.

We take security seriously. If you discover a vulnerability in the pentest-tools CLI, the dashboard, the MCP server, the marketing site, or any other system we operate, we want to hear about it. This policy describes how to report and what you can expect from us in return.

## Scope

**In scope:**

- The pentest-tools CLI (`pip install pttools`) — Python source in `agents/`, `engine/`, `cli/`, `mcp_server/`, `tools/`, `playbooks/`
- The dashboard at `app.pentest-tools.local` and any subdomain
- The marketing site at `pentest-tools.local`
- The MCP server's HTTP and stdio surfaces
- The cloud sync API endpoints (the part of the dashboard the CLI connects to)
- Authentication, authorization, scope-enforcement, and evidence-handling code

**Out of scope:**

- Third-party tools the engine invokes (nmap, nuclei, sqlmap, etc.). Report those upstream.
- Issues in our subprocessors (Cloudflare, Stripe, Anthropic, OpenAI, AWS/GCP). Report to them.
- Theoretical issues without a working proof of concept.
- Self-XSS, missing best-practice headers without a concrete impact, or cosmetic issues that don't affect security.
- Volumetric denial-of-service, brute-force on login (we rate-limit), or any test that requires more than a single user's worth of traffic.
- Social engineering of our staff or customers.
- Physical attacks against our offices or staff.

## Reporting channel

**Preferred:** open a private GitHub Security Advisory at https://github.com/pentest-tools/pentest-tools/security/advisories/new. This gives us a private channel to coordinate without the issue being visible to the public.

**Alternative:** email `security@pentest-tools.local` with subject `[SECURITY] short description`. PGP key is published at `pentest-tools.local/.well-known/security.txt` and at the bottom of this page.

## What to include

To help us triage quickly:

- The component affected (CLI version + commit, dashboard URL, MCP path)
- A clear description of the issue and its impact
- A minimal proof of concept (commands, requests, or a minimal repro repo)
- Your name or handle if you'd like credit; otherwise we'll keep you anonymous

If your finding involves data of other users or our own infrastructure, **stop testing immediately**, do not download more than the minimum needed to demonstrate the issue, and contact us before doing anything else.

## Our commitments to you

- We acknowledge receipt within **3 business days**.
- We perform initial triage within **7 business days**.
- We keep you informed of remediation progress at least every 14 days until resolution.
- We coordinate disclosure timing with you. Default window: up to **90 days** from initial report; we may ask for extensions for complex fixes and we will explain why.
- We credit you in the release notes and at `pentest-tools.local/security/hall-of-fame` if you want it. Anonymous reports are also welcome.
- We do not pursue legal action against good-faith researchers who follow this policy and the [Acceptable Use Policy](AUP.md).

## Safe harbor

If you make a good-faith effort to comply with this policy, we consider your testing authorized and we will not initiate or support any legal action against you. We waive any claim against you under the Computer Fraud and Abuse Act, similar laws in other jurisdictions, and DMCA anti-circumvention provisions, to the extent those laws would otherwise apply to your testing of our systems within this scope.

The safe harbor does not authorize:

- Testing of systems out of scope (Section 1)
- Public disclosure before we have a chance to fix
- Exfiltration of customer data beyond a single demonstration
- Persisting access after the initial finding
- Any action that violates the AUP

## Bug bounty

We currently do not run a paid bug bounty program. We may offer swag, recognition, or invitations to private programs at our discretion. We may launch a paid program in the future; this policy will be updated when we do.

## Public disclosure

After we publish a fix, you may publicly disclose the issue. We will publish:

- A CVE (if applicable) via our CNA path or GitHub
- Release notes describing the issue at a high level
- Credit to the reporter (if requested)

## Contact

- `security@pentest-tools.local`
- GitHub Security Advisory: https://github.com/pentest-tools/pentest-tools/security/advisories/new
- PGP key fingerprint: `742F E41A 69B6 5995 7390  BA89 2041 C71E 654B 47A4`
- PGP public key: https://pentest-tools.local/.well-known/pgp-key.txt
- Key expires: 2028-05-01

The full ASCII-armored public key is also reproduced below for offline verification:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=WzIZ
-----END PGP PUBLIC KEY BLOCK-----
```

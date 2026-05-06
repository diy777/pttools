# Legal documents

Source-of-truth for the legal documents published at `pentest-tools.local`. The HTML pages on the marketing site mirror these markdown files 1:1.

| File | Public URL |
|------|------------|
| [PRIVACY.md](PRIVACY.md) | https://pentest-tools.local/privacy |
| [TERMS.md](TERMS.md) | https://pentest-tools.local/terms |
| [AUP.md](AUP.md) | https://pentest-tools.local/aup |
| [COOKIES.md](COOKIES.md) | https://pentest-tools.local/cookies |
| [SUBPROCESSORS.md](SUBPROCESSORS.md) | https://pentest-tools.local/subprocessors |
| [RESPONSIBLE_DISCLOSURE.md](RESPONSIBLE_DISCLOSURE.md) | https://pentest-tools.local/security |
| [DPA.md](DPA.md) | not published; signed on request via `legal@pentest-tools.local` |

## Why a pentest tool needs these

A pentest SaaS needs more than the standard SaaS legal pack because the tool itself executes offensive operations against external networks:

- **Acceptable Use Policy** is the most load-bearing document. It shifts authorization-to-test responsibility to the user and limits our exposure when pttools is misused.
- **Data Processing Agreement** is required by GDPR Article 28 for any EU customer.
- **Subprocessor list** is required to be public and notified before changes by GDPR Article 28(2).
- **Responsible Disclosure** is required to safely accept inbound vulnerability reports from researchers.

## Reporting issues

- Privacy or data subject requests: `privacy@pentest-tools.local`
- Acceptable use violations / abuse reports: `abuse@pentest-tools.local`
- Vulnerabilities in pentest-tools itself: `security@pentest-tools.local` (see also [SECURITY.md](../../SECURITY.md))
- Legal: `legal@pentest-tools.local`

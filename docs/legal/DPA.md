# Data Processing Agreement (Template)

> **Status:** template, not finalized. Have a lawyer review before sending to a customer for signature.
>
> When a customer asks for a signed DPA (typical for any EU customer or any enterprise procurement), use this as the starting point. Most customers will accept it as-is; large enterprises may redline. The terms here are aligned with GDPR Articles 28 and 32 and the 2021 EU Standard Contractual Clauses (Module 2: controller-to-processor).

This Data Processing Agreement ("**DPA**") is incorporated into and forms part of the Terms of Service or Master Services Agreement (the "**Agreement**") between [Customer] ("**Customer**" or "**Controller**") and pentest-tools, (legal entity formation in progress — write to legal@pentest-tools.local for verified entity name and registered office address) ("**Processor**", "we", "us"). In the event of a conflict between this DPA and the Agreement, this DPA controls for matters relating to the processing of personal data.

## 1. Definitions

Capitalized terms have the meanings given in GDPR (EU 2016/679), UK GDPR, or, where applicable, CCPA / CPRA. "**Personal Data**", "**Data Subject**", "**Processing**", "**Controller**", and "**Processor**" have their GDPR meanings. "**Customer Personal Data**" means personal data that we process on Customer's behalf in the course of providing the Service.

## 2. Roles and scope

Customer is the Controller; we are the Processor. The subject matter, duration, nature, purpose, types of personal data, and categories of data subjects are described in **Annex I** below. We do not process Customer Personal Data for any purpose other than performing the Service for Customer or as required by law.

## 3. Customer instructions

We process Customer Personal Data only on documented instructions from Customer, including with regard to transfers, unless required to do otherwise by EU, UK, or Member State law to which we are subject. The Agreement, this DPA, and the configuration choices Customer makes in the dashboard constitute documented instructions.

We will inform Customer if, in our opinion, an instruction infringes GDPR or other applicable data protection law.

## 4. Confidentiality

Personnel authorized to process Customer Personal Data are bound by appropriate confidentiality obligations.

## 5. Security (GDPR Article 32)

We implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including, as appropriate:

- Pseudonymization and encryption of Personal Data in transit (TLS 1.3) and at rest (AES-256)
- Ability to ensure ongoing confidentiality, integrity, availability, and resilience
- Ability to restore availability after a physical or technical incident
- Regular testing, assessing, and evaluating effectiveness (third-party penetration tests, internal vulnerability scans)
- Per-customer data isolation (workspace_id row-level filter on every query)
- Principle of least privilege for employee access; access reviewed quarterly
- Logging and monitoring of access to production systems

A current description of the measures is in **Annex II**.

## 6. Sub-processors

Customer authorizes us to engage the sub-processors listed at `pentest-tools.local/subprocessors`. We will give Customer at least **30 days' notice** before adding or replacing a sub-processor. Customer may object on reasonable grounds related to data protection by emailing `privacy@pentest-tools.local`. If we cannot reach an alternative arrangement, Customer may terminate the affected portion of the Service.

We remain liable to Customer for the acts and omissions of our sub-processors as if performed by us.

## 7. Data Subject rights

We assist Customer, by appropriate technical and organizational measures and insofar as possible, to fulfill its obligation to respond to Data Subject requests under Articles 15 to 22 GDPR. We provide:

- Self-service access, export, and deletion in the dashboard
- An API endpoint for programmatic export
- A response within 7 business days to manual support tickets at `privacy@pentest-tools.local`

## 8. Personal Data breach notification

We notify Customer **without undue delay and in any event within 72 hours** of becoming aware of a Personal Data Breach affecting Customer Personal Data, in accordance with Article 33 GDPR. The notification will include, to the extent known:

- Nature of the breach (categories and approximate number of data subjects and records concerned)
- Likely consequences
- Measures taken or proposed to address the breach and mitigate adverse effects
- Contact for more information

## 9. Data Protection Impact Assessments

On Customer's reasonable request, and taking into account the nature of the processing and the information available to us, we provide reasonable assistance with Customer's Data Protection Impact Assessments (Article 35) and prior consultations with supervisory authorities (Article 36).

## 10. Audit rights

We make available to Customer all information necessary to demonstrate compliance with this DPA. We allow for and contribute to audits, including inspections, conducted by Customer or another auditor mandated by Customer, no more than once per year (unless required by a supervisory authority), with at least 30 days' written notice, during business hours, and subject to confidentiality. We may satisfy this obligation by providing the most recent SOC 2 Type II report or equivalent third-party attestation; on-site audits are reserved for material reasons.

## 11. International transfers

Where the processing of Customer Personal Data involves a transfer outside the EEA, UK, or Switzerland to a country without an adequacy decision, the parties incorporate the **2021 EU Standard Contractual Clauses (Module 2: controller-to-processor)** as if executed in full and signed by the parties on the effective date of this DPA. The optional Clause 7 docking clause is included. Clause 17 governing law: the law of the EU member state where the Customer (data exporter) is established. Clause 18 jurisdiction: the courts of that EU member state.

For UK transfers, the parties incorporate the **UK International Data Transfer Addendum** to the EU SCCs, version B1.0.

For Swiss transfers, the parties apply the SCCs with the FDPIC supplements (replacing references to GDPR with the Swiss FADP, identifying the FDPIC as the supervisory authority, and adjusting governing law to Switzerland for clauses involving Swiss data subjects).

A signed copy of the SCCs is in **Annex III**.

## 12. Return or deletion

On termination of the Agreement, at Customer's choice, we delete or return all Customer Personal Data, and delete existing copies, unless EU or Member State law requires storage. We provide written confirmation of deletion within 30 days of completion.

Audit logs may be retained for the duration required by law (typically 7 years) in a redacted form.

## 13. Liability

The Processor's aggregate liability under this DPA is subject to the limits of liability in the Agreement. Nothing in this DPA limits any rights a Data Subject has under GDPR.

## 14. Amendments

We may amend this DPA from time to time to address regulatory changes (e.g., updated SCCs). Material amendments require Customer's signature; non-material amendments take effect on 30 days' notice.

## 15. Governing law

This DPA is governed by the law specified in the Agreement, except as overridden by mandatory provisions of GDPR and the SCCs.

---

## Annex I — Description of processing

| Item | Description |
|------|-------------|
| Subject matter | Provision of pentest-tools SaaS dashboard and CLI cloud sync |
| Duration | For the term of the Agreement, plus retention periods specified in the Privacy Policy |
| Nature and purpose | Hosting, organizing, and presenting Customer's penetration test engagement data |
| Types of Personal Data | Account: name, email, IP. Engagement: target identifiers, tester identity, timestamps. Findings: descriptions, evidence excerpts. Audit logs: actor, action, time, IP. |
| Categories of Data Subjects | Customer's authorized users (typically employees or contractors) and incidental data subjects whose personal data appears in scan findings |
| Frequency of processing | Continuous |
| Retention | Per Privacy Policy: engagements 12 months default (configurable), audit logs 7 years |

## Annex II — Technical and organizational measures

Current technical and organizational measures, reviewed annually:

- TLS 1.3 in transit; AES-256 at rest
- Argon2id password hashing
- MFA required for all administrative access
- Per-tenant logical isolation via workspace_id
- Quarterly access reviews
- Quarterly third-party penetration tests
- Annual SOC 2 Type II audit (target 2027)
- Backups encrypted, 30-day retention, tested quarterly
- Incident response plan documented and exercised annually
- Staff security awareness training annually
- Vendor risk management review for every new sub-processor

## Annex III — Standard Contractual Clauses

Attached as Schedule 1 at signing time. The base text is the European Commission's 2021 SCCs Module 2 (Decision (EU) 2021/914), available at https://eur-lex.europa.eu/eli/dec_impl/2021/914.

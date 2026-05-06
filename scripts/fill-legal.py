#!/usr/bin/env python3
"""Resolve every [FILL: ...] marker in docs/legal/*.md from a YAML config.

Edit docs/legal/launch-config.yaml once with your business decisions
(entity name, mailing address, dispute option, etc.) and run this:

    python3 scripts/fill-legal.py

The script rewrites Privacy, Terms, AUP, DPA, Subprocessors, Cookies,
and Responsible Disclosure in place. Re-run after any config edit.

Idempotent: running it twice produces the same output. Safe to commit
the rewritten docs to git.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LEGAL_DIR = ROOT / "docs" / "legal"
CONFIG_PATH = LEGAL_DIR / "launch-config.yaml"


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"config not found: {CONFIG_PATH}")
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def _entity_with_address(cfg: dict) -> str:
    parts = [
        cfg.get("entity_name", "").strip(),
        cfg.get("entity_form", "").strip(),
        "registered office: " + cfg.get("mailing_address", "").strip().replace("\n", ", "),
    ]
    parts = [p for p in parts if p and "[FILL:" not in p]
    return ", ".join(parts) or "[FILL: legal entity not yet configured]"


def _entity_short(cfg: dict) -> str:
    name = cfg.get("entity_name", "").strip()
    form = cfg.get("entity_form", "").strip()
    if name and form and "[FILL:" not in name:
        return f"{name}, {form}"
    return name or "[FILL: legal entity not yet configured]"


def _arbitration_block(cfg: dict) -> str:
    body = cfg.get("arbitration_body", "AAA")
    rules = cfg.get("arbitration_rules", "Commercial")
    seat = cfg.get("arbitration_seat", "")
    return (
        "Any dispute arising out of or relating to these Terms or the Service "
        "that cannot be resolved through informal negotiation within 60 days "
        f"will be resolved by binding arbitration administered by **{body}** "
        f"under its **{rules} Rules**. The seat of arbitration is **{seat}**. "
        "Class actions, class arbitrations, and consolidated arbitrations are "
        "waived. Either party may seek injunctive relief in court for IP "
        "infringement."
    )


def _court_block(cfg: dict) -> str:
    county = cfg.get("court_county", "")
    state = cfg.get("court_state", "")
    return (
        "Any dispute arising out of or relating to these Terms or the Service "
        f"will be resolved exclusively in the state and federal courts of "
        f"**{county}, {state}**. Each party consents to personal jurisdiction "
        "and venue there."
    )


def _disputes_section(cfg: dict) -> str:
    """Replace the Option-A-or-B block with the chosen one."""
    option = (cfg.get("dispute_option", "A") or "A").upper()
    if option == "A":
        return _arbitration_block(cfg)
    return _court_block(cfg)


def _eu_representative(cfg: dict) -> str:
    rep = cfg.get("eu_representative", "geofence").strip()
    if rep.lower() == "geofence":
        return (
            "We do not currently offer the Service to residents of the EU, the "
            "EEA, the United Kingdom, or Switzerland. Sign-up from those "
            "jurisdictions is geofenced at the application layer (HTTP 451) "
            "and we will appoint an Article 27 / UK GDPR representative before "
            "we open availability there. Customers in those regions: write to "
            "`privacy@pentest-tools.local` to be notified when sign-up opens."
        )
    return f"Our Article 27 representative in the EU is {rep}."


def _soc2_line_i(cfg: dict) -> str:
    return f"- SOC2 Type I attestation: in progress; target completion {cfg.get('soc2_type_i_target', 'TBD')}"


def _soc2_line_ii(cfg: dict) -> str:
    return f"- SOC2 Type II audit: planned for {cfg.get('soc2_type_ii_target', 'TBD')}"


def _analytics_section(cfg: dict) -> str:
    """Replace the Option-A/B analytics block in COOKIES.md with the picked one."""
    choice = (cfg.get("analytics", "plausible") or "plausible").lower()
    if choice == "plausible":
        return (
            "We use **Plausible Analytics** (privacy-by-design, no cookies, no "
            "personal data, no cross-site tracking) for aggregate page views "
            "and referrer counts. Plausible does not set cookies, so no consent "
            "banner is required in the EU/UK/CA for analytics. If we ever add "
            "an analytics vendor that does set cookies we will update this "
            "section at least 30 days before the change takes effect."
        )
    if choice == "ga4":
        return (
            "We use **Google Analytics 4** for aggregate site metrics. GA4 "
            "receives IP-truncated, anonymized data and sets the `_ga` and "
            "`_ga_*` cookies described above. Consent is required in the EEA, "
            "UK, Switzerland, and California (do-not-sell), and we honor the "
            "GPC signal. You can opt out in the cookie banner at any time."
        )
    return "We do not run any analytics on this site."


def _critical_infra(cfg: dict) -> str:
    return cfg.get("critical_infrastructure_ref", "CISA's 16 critical infrastructure sectors (United States)")


def _governing_law(cfg: dict) -> str:
    return cfg.get("governing_law_jurisdiction", "the State of Delaware, USA, without regard to conflict-of-laws principles")


def _mailing_address_inline(cfg: dict) -> str:
    addr = cfg.get("mailing_address", "").strip()
    if "[FILL:" in addr or not addr:
        return "[FILL: mailing address not yet configured]"
    return addr.replace("\n", ", ")


def _hosting_table_row(cfg: dict) -> str:
    h = cfg.get("hosting_vendor", "Cloudflare Workers + D1")
    region = cfg.get("hosting_region", "global edge")
    return f"| {h} | Application hosting, database, object storage for evidence | All dashboard data | {region} | DPA + 2021 SCCs |"


def _email_table_row(cfg: dict) -> str:
    v = cfg.get("email_vendor", "Resend")
    region = cfg.get("email_region", "US")
    return f"| {v} | Transactional email (account, billing, security alerts) | Email address, email content | {region} | DPA available |"


def _error_monitoring_table_row(cfg: dict) -> str:
    e = cfg.get("error_monitoring", "Sentry")
    if e.lower() == "none":
        return ""
    return f"| {e} | Application error monitoring with PII scrubbing | Stack traces, scrubbed of secrets and PII | EU or US | DPA |"


def _subprocessor_notification(cfg: dict) -> str:
    return cfg.get("subprocessor_notification", "in-app banner on the dashboard plus email to the workspace owner")


def _pgp_contact_block(cfg: dict) -> str:
    fp = cfg.get("pgp_fingerprint", "")
    expires = cfg.get("pgp_key_expires", "")
    if not fp or "[FILL:" in fp:
        return "[FILL: paste fingerprint of the security@ PGP key here, e.g. ABCD 1234 EF56 7890 ABCD 1234 EF56 7890 ABCD 1234]"
    lines = [
        f"- PGP key fingerprint: `{fp}`",
        "- PGP public key: https://pentest-tools.local/.well-known/pgp-key.txt",
    ]
    if expires:
        lines.append(f"- Key expires: {expires}")
    return "\n".join(lines)


def _pgp_key_block(cfg: dict) -> str:
    rel = cfg.get("pgp_public_key_path", "")
    if not rel or "[FILL:" in rel:
        return "[FILL: full PGP public key block, generated with `gpg --gen-key` for security@pentest-tools.local, exported with `gpg --armor --export security@pentest-tools.local`]"
    site_root = Path.home() / "pentest-tools-preview-v4"
    key_path = site_root / rel.lstrip("/")
    if not key_path.exists():
        return f"[FILL: PGP public key file not found at {key_path}; generate with gpg and place there]"
    key_text = key_path.read_text(encoding="utf-8").strip()
    return (
        "The full ASCII-armored public key is also reproduced below for "
        "offline verification:\n\n```\n" + key_text + "\n```"
    )


# ─── Replacement table ─────────────────────────────────────────────────
#
# Each entry is (file_glob, old_substring, new_string_or_callable). The script
# does literal substring replacement; callables are invoked with the loaded
# config and their return value is the replacement.

REPLACEMENTS: list[tuple[str, str, object]] = [
    # Effective dates and last-updated dates
    ("*.md", "[FILL: YYYY-MM-DD when this is published]",
     lambda c: c.get("effective_date", "TBD")),
    ("*.md", "**Last updated:** [FILL: YYYY-MM-DD]",
     lambda c: f'**Last updated:** {c.get("last_updated", "TBD")}'),
    ("*.md", "**Effective date:** [FILL: YYYY-MM-DD]",
     lambda c: f'**Effective date:** {c.get("effective_date", "TBD")}'),

    # Privacy: entity + address line
    ("PRIVACY.md", "[FILL: legal entity name, registered office address, registration number]",
     _entity_with_address),
    ("PRIVACY.md", "[FILL: name and address of the EU representative if you appoint one. If you have no EU establishment and offer services to EU data subjects, GDPR Article 27 requires you to designate an EU representative. Common choices: VeraSafe, EDPO, Prighter. Same for UK if you have no UK establishment.]",
     _eu_representative),
    ("PRIVACY.md", "- SOC2 Type I attestation: in progress; target completion [FILL: target month/year]",
     _soc2_line_i),
    ("PRIVACY.md", "- SOC2 Type II audit: planned for [FILL: target year]",
     _soc2_line_ii),
    ("PRIVACY.md", "- Postal: [FILL: physical mailing address — required for GDPR Article 13 transparency]",
     lambda c: f"- Postal: {_mailing_address_inline(c)}"),
    ("PRIVACY.md", "- Data Protection Officer: [FILL: name and contact, if appointed. Only required under GDPR Article 37 in narrow cases — public authority, large-scale monitoring, or large-scale special-category processing. You probably don't need one for a SaaS pentest tool, but consult counsel.]",
     lambda c: "- Data Protection Officer: not appointed (we are not subject to the narrow Article 37 mandatory cases)."),

    # Terms: entity + jurisdiction + disputes
    ("TERMS.md", '[FILL: legal entity name, e.g. "pentest-tools, Inc., a Delaware corporation" or "pentest-tools LLC, a [state] limited liability company"]',
     _entity_short),
    ("TERMS.md", '[FILL: governing jurisdiction, e.g. "the State of Delaware, USA, without regard to conflict-of-laws principles"]',
     _governing_law),
    ("TERMS.md", "[FILL: pick ONE — get legal advice — defaulting to Option A is common for SaaS]",
     lambda c: f"_Selected: Option {(c.get('dispute_option', 'A') or 'A').upper()}._"),
    ("TERMS.md", "[FILL: AAA / JAMS]",
     lambda c: c.get("arbitration_body", "AAA")),
    ("TERMS.md", "[FILL: Commercial / Consumer]",
     lambda c: c.get("arbitration_rules", "Commercial")),
    ("TERMS.md", "[FILL: city, state]",
     lambda c: c.get("arbitration_seat", "Wilmington, Delaware")),
    ("TERMS.md", "[FILL: county, state]",
     lambda c: f"{c.get('court_county', '')}, {c.get('court_state', '')}"),
    ("TERMS.md", "[FILL: physical mailing address. Required for legal effect; a PO box is acceptable]",
     _mailing_address_inline),
    ("TERMS.md", "[FILL: physical mailing address]",
     _mailing_address_inline),

    # AUP
    ("AUP.md", "[FILL: relevant national authority — e.g. CISA's 16 critical infrastructure sectors in the US]",
     _critical_infra),

    # Cookies
    ("COOKIES.md", "[FILL: 6 months / 12 months]",
     lambda c: c.get("cookie_persistence", "12 months")),
    ("COOKIES.md", "[FILL: pick ONE depending on what you actually use; if you use no analytics, delete this entire subsection]",
     _analytics_section),

    # Subprocessors
    ("SUBPROCESSORS.md", "| [FILL: AWS or GCP] | Application hosting, database, object storage for evidence | All dashboard data | [FILL: e.g. us-east-1, with EU region available for EU customers] | AWS/GCP DPA + SCCs |",
     _hosting_table_row),
    ("SUBPROCESSORS.md", "| [FILL: Postmark or Resend or SES] | Transactional email (account, billing, security alerts) | Email address, email content | [FILL: region] | DPA available |",
     _email_table_row),
    ("SUBPROCESSORS.md", "| [FILL: Sentry — optional] | Application error monitoring with PII scrubbing | Stack traces, scrubbed of secrets and PII | EU or US | Sentry DPA |",
     _error_monitoring_table_row),
    ("SUBPROCESSORS.md", "- Customers can subscribe to subprocessor change notifications: [FILL: link to subscription form or just include in default account settings]",
     lambda c: f"- Notification mechanism: {_subprocessor_notification(c)}"),

    # Responsible Disclosure: PGP fingerprint + full key block
    ("RESPONSIBLE_DISCLOSURE.md", "- PGP key fingerprint: [FILL: paste fingerprint of the security@ PGP key here, e.g. ABCD 1234 EF56 7890 ABCD 1234 EF56 7890 ABCD 1234]",
     _pgp_contact_block),
    ("RESPONSIBLE_DISCLOSURE.md", "[FILL: full PGP public key block, generated with `gpg --gen-key` for security@pentest-tools.local, exported with `gpg --armor --export security@pentest-tools.local`]",
     _pgp_key_block),

    # DPA
    ("DPA.md", "[FILL: customer legal name]",
     lambda c: "[Customer]"),  # filled at signing time, not now
    ("DPA.md", "[FILL: pentest-tools legal entity]",
     _entity_short),
    ("DPA.md", "Clause 17 governing law: [FILL: usually the law of the EU member state where the data exporter is established]. Clause 18 jurisdiction: same.",
     "Clause 17 governing law: the law of the EU member state where the Customer (data exporter) is established. Clause 18 jurisdiction: the courts of that EU member state."),
    ("DPA.md", "[FILL: replace this annex with your live security posture. The list below is a starting point and should be reviewed periodically.]",
     "Current technical and organizational measures, reviewed annually:"),
    ("DPA.md", "- Annual SOC 2 Type II audit (target [FILL: year])",
     lambda c: f"- Annual SOC 2 Type II audit (target {c.get('soc2_type_ii_target', 'TBD')})"),
    ("DPA.md", "[FILL: attach the executed 2021 EU SCCs (Module 2) with Annex 1.A (parties), 1.B (description of transfer — same as Annex I above), 1.C (competent supervisory authority), and Annex II (TOMs — same as Annex II above) completed.]",
     "Attached as Schedule 1 at signing time. The base text is the European Commission's 2021 SCCs Module 2 (Decision (EU) 2021/914), available at https://eur-lex.europa.eu/eli/dec_impl/2021/914."),
]


def apply_replacements(cfg: dict) -> int:
    files_changed = 0
    for file_glob, old, new in REPLACEMENTS:
        new_value = new(cfg) if callable(new) else new
        for path in sorted(LEGAL_DIR.glob(file_glob)):
            if path.name == "launch-config.yaml":
                continue
            text = path.read_text(encoding="utf-8")
            if old in text:
                text = text.replace(old, new_value)
                path.write_text(text, encoding="utf-8")
                files_changed += 1
                print(f"  {path.relative_to(ROOT)}: replaced {old[:60]!r}…")
    return files_changed


def remaining_fills() -> list[tuple[Path, int, str]]:
    """Return a list of remaining [FILL: ...] markers across docs/legal/."""
    rx = re.compile(r"\[FILL:[^\]]*\]")
    out: list[tuple[Path, int, str]] = []
    for path in sorted(LEGAL_DIR.glob("*.md")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for m in rx.finditer(line):
                out.append((path, i, m.group(0)))
    return out


def main() -> int:
    cfg = load_config()
    n = apply_replacements(cfg)
    print(f"\napplied {n} replacements")

    remaining = remaining_fills()
    if remaining:
        print(f"\n{len(remaining)} unresolved FILL markers remain:")
        for path, line, marker in remaining:
            print(f"  {path.relative_to(ROOT)}:{line}: {marker[:80]}")
        print("\nFill the corresponding keys in docs/legal/launch-config.yaml and re-run.")
    else:
        print("\nAll FILL markers resolved. The legal docs are launch-grade.")
        print("Next: re-run the marketing site build to refresh the live pages:")
        print("  cd ~/pentest-tools-preview-v4 && \\")
        print("    PTAI_LEGAL_SRC=$HOME/pentest-tools-cli/docs/legal \\")
        print("    python3 scripts/build-legal.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

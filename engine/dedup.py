"""Finding deduplication and CWE/OWASP correlation engine.

Deduplicates findings across multiple tools using composite fingerprints
and fuzzy title matching. Maps findings to CWE IDs and OWASP categories.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


class FindingDeduplicator:
    def __init__(self) -> None:
        self._seen_fingerprints: dict[str, str] = {}

    def fingerprint(self, finding: dict[str, Any]) -> str:
        target = _normalize(finding.get("target", ""))
        category = _normalize(finding.get("category", ""))
        title_tokens = _normalize_title(finding.get("title", ""))
        raw = f"{target}|{category}|{title_tokens}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_duplicate(self, finding: dict[str, Any]) -> tuple[bool, str]:
        fp = self.fingerprint(finding)
        if fp in self._seen_fingerprints:
            return True, self._seen_fingerprints[fp]
        self._seen_fingerprints[fp] = finding.get("id", "")
        return False, ""

    def check_fuzzy_duplicate(self, finding: dict[str, Any], existing_findings: list[dict[str, Any]]) -> str | None:
        target = _normalize(finding.get("target", ""))
        title = finding.get("title", "").lower()

        for existing in existing_findings:
            if _normalize(existing.get("target", "")) != target:
                continue
            existing_title = existing.get("title", "").lower()
            if _levenshtein_ratio(title, existing_title) > 0.85:
                return existing.get("id", "")
        return None

    def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        title = finding.get("title", "").lower()
        category = finding.get("category", "").lower()
        combined = f"{title} {category}"

        cwe = _map_to_cwe(combined)
        owasp = _map_to_owasp(combined)

        result = dict(finding)
        if cwe:
            result["cwe_id"] = cwe
        if owasp:
            result["owasp_category"] = owasp
        result["fingerprint"] = self.fingerprint(finding)
        return result


CWE_PATTERNS: list[tuple[str, str, str]] = [
    (r"sql.?inject", "CWE-89", "SQL Injection"),
    (r"cross.?site.?script|xss", "CWE-79", "Cross-site Scripting"),
    (r"command.?inject|os.?command", "CWE-78", "OS Command Injection"),
    (r"path.?travers|directory.?travers|lfi|rfi", "CWE-22", "Path Traversal"),
    (r"ssrf|server.?side.?request", "CWE-918", "Server-Side Request Forgery"),
    (r"xxe|xml.?external", "CWE-611", "XML External Entity"),
    (r"deserialization|deserialize", "CWE-502", "Deserialization of Untrusted Data"),
    (r"csrf|cross.?site.?request.?forg", "CWE-352", "Cross-Site Request Forgery"),
    (r"open.?redirect", "CWE-601", "Open Redirect"),
    (r"idor|insecure.?direct.?object", "CWE-639", "Insecure Direct Object Reference"),
    (r"broken.?auth|auth.?bypass|authentication", "CWE-287", "Improper Authentication"),
    (r"broken.?access|authorization|privilege.?escalat", "CWE-862", "Missing Authorization"),
    (r"sensitive.?data|information.?disclos|data.?expos", "CWE-200", "Information Disclosure"),
    (r"weak.?crypto|weak.?cipher|deprecated.?protocol", "CWE-327", "Broken Cryptographic Algorithm"),
    (r"hardcoded.?secret|hardcoded.?password|exposed.?key", "CWE-798", "Hardcoded Credentials"),
    (r"missing.?header|security.?header|hsts|csp|x-frame", "CWE-693", "Protection Mechanism Failure"),
    (r"ssl|tls|certificate", "CWE-295", "Improper Certificate Validation"),
    (r"cors|cross.?origin", "CWE-942", "Permissive Cross-domain Policy"),
    (r"buffer.?overflow|stack.?overflow", "CWE-120", "Buffer Overflow"),
    (r"race.?condition|toctou", "CWE-362", "Race Condition"),
    (r"session.?fixation", "CWE-384", "Session Fixation"),
    (r"file.?upload|unrestricted.?upload", "CWE-434", "Unrestricted File Upload"),
    (r"subdomain.?takeover", "CWE-284", "Improper Access Control"),
    (r"dns.?zone.?transfer", "CWE-200", "Information Disclosure"),
    (r"default.?cred|default.?password", "CWE-1392", "Use of Default Credentials"),
    (r"brute.?force|password.?spray", "CWE-307", "Improper Restriction of Authentication Attempts"),
    (r"kerberoast|as.?rep.?roast", "CWE-916", "Use of Password Hash With Insufficient Effort"),
    (r"dcsync|golden.?ticket|silver.?ticket", "CWE-522", "Insufficiently Protected Credentials"),
    (r"public.?bucket|storage.?exposed", "CWE-732", "Incorrect Permission Assignment"),
    (r"metadata.?service|imds", "CWE-918", "Server-Side Request Forgery"),
]

OWASP_PATTERNS: list[tuple[str, str]] = [
    (r"sql.?inject|command.?inject|xxe|deserialization|ldap.?inject", "A03:2021 Injection"),
    (r"broken.?auth|auth.?bypass|credential|session|brute.?force|kerberoast", "A07:2021 Identification and Authentication Failures"),
    (r"sensitive.?data|information.?disclos|data.?expos|cleartext|weak.?crypto", "A02:2021 Cryptographic Failures"),
    (r"xss|cross.?site.?script", "A03:2021 Injection"),
    (r"broken.?access|idor|privilege.?escalat|authorization|missing.?auth", "A01:2021 Broken Access Control"),
    (r"misconfig|default.?cred|security.?header|cors|ssl|tls|certificate", "A05:2021 Security Misconfiguration"),
    (r"outdated|vulnerable.?component|cve-|known.?vuln", "A06:2021 Vulnerable and Outdated Components"),
    (r"log|monitor|audit|detect", "A09:2021 Security Logging and Monitoring Failures"),
    (r"ssrf|server.?side.?request", "A10:2021 Server-Side Request Forgery"),
    (r"design|business.?logic|workflow|race.?condition", "A04:2021 Insecure Design"),
]


def _map_to_cwe(text: str) -> str:
    for pattern, cwe_id, _ in CWE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return cwe_id
    return ""


def _map_to_owasp(text: str) -> str:
    for pattern, owasp_cat in OWASP_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return owasp_cat
    return ""


def _normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"https?://", "", s)
    s = re.sub(r"[/:].*$", "", s)
    return s


def _normalize_title(title: str) -> str:
    title = title.lower()
    title = re.sub(r"[^a-z0-9\s]", "", title)
    tokens = sorted(set(title.split()))
    return " ".join(tokens)


def _levenshtein_ratio(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)
    if len1 < len2:
        s1, s2 = s2, s1
        len1, len2 = len2, len1

    prev_row = list(range(len2 + 1))
    for i in range(1, len1 + 1):
        curr_row = [i]
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr_row.append(min(curr_row[j - 1] + 1, prev_row[j] + 1, prev_row[j - 1] + cost))
        prev_row = curr_row

    distance = prev_row[len2]
    return 1.0 - (distance / max(len1, len2))

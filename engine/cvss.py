"""CVSS v3.1 base score calculator.

Maps CWE IDs and finding categories to default CVSS vectors,
then computes the base score. Scanner-provided vectors take precedence.
"""

from __future__ import annotations

import math
from typing import Any

CWE_VECTORS: dict[str, str] = {
    "CWE-89": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "CWE-79": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-78": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-22": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-918": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "CWE-611": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-502": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-352": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "CWE-601": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-639": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "CWE-287": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-862": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-200": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-327": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-798": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-693": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "CWE-295": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-942": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "CWE-120": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-362": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-384": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "CWE-434": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CWE-284": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "CWE-1392": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-307": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-916": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CWE-522": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "CWE-732": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

SEVERITY_FALLBACK: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse_vector(vector: str) -> dict[str, str]:
    parts = {}
    for component in vector.split("/"):
        if ":" in component:
            key, val = component.split(":", 1)
            parts[key] = val
    return parts


def compute_base_score(vector: str) -> float:
    p = _parse_vector(vector)
    try:
        av = _AV[p["AV"]]
        ac = _AC[p["AC"]]
        scope_changed = p["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        pr = pr_table[p["PR"]]
        ui = _UI[p["UI"]]
        c = _CIA[p["C"]]
        i = _CIA[p["I"]]
        a = _CIA[p["A"]]
    except KeyError:
        return 0.0

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    raw = min(1.08 * (impact + exploitability), 10.0) if scope_changed else min(impact + exploitability, 10.0)

    return math.ceil(raw * 10) / 10


def calculate_cvss(finding: dict[str, Any]) -> float:
    if finding.get("cvss_vector"):
        return compute_base_score(finding["cvss_vector"])

    cwe = finding.get("cwe_id", "")
    if cwe and cwe in CWE_VECTORS:
        vector = CWE_VECTORS[cwe]
        finding["cvss_vector"] = vector
        return compute_base_score(vector)

    return SEVERITY_FALLBACK.get(finding.get("severity", "info"), 0.0)

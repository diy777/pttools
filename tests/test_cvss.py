"""Tests for CVSS v3.1 calculator."""


from engine.cvss import CWE_VECTORS, calculate_cvss, compute_base_score


class TestComputeBaseScore:
    def test_critical_rce_vector(self):
        score = compute_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_xss_reflected_vector(self):
        score = compute_base_score("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert score == 6.1

    def test_low_impact_vector(self):
        score = compute_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N")
        assert score > 0
        assert score < 6.0

    def test_zero_impact_returns_zero(self):
        score = compute_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0

    def test_invalid_vector_returns_zero(self):
        assert compute_base_score("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 0.0
        assert compute_base_score("garbage") == 0.0

    def test_scope_changed_increases_score(self):
        unchanged = compute_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        changed = compute_base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N")
        assert changed > unchanged

    def test_all_cwe_vectors_produce_valid_scores(self):
        for cwe, vector in CWE_VECTORS.items():
            score = compute_base_score(vector)
            assert 0.0 <= score <= 10.0, f"{cwe} vector {vector} produced invalid score {score}"


class TestCalculateCvss:
    def test_uses_provided_cvss_vector(self):
        finding = {"cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "critical"}
        assert calculate_cvss(finding) == 9.8

    def test_uses_cwe_default_vector(self):
        finding = {"cwe_id": "CWE-89", "severity": "critical"}
        score = calculate_cvss(finding)
        assert score > 8.0

    def test_falls_back_to_severity(self):
        finding = {"severity": "high"}
        assert calculate_cvss(finding) == 7.5

    def test_info_severity_is_zero(self):
        finding = {"severity": "info"}
        assert calculate_cvss(finding) == 0.0

    def test_unknown_cwe_falls_back(self):
        finding = {"cwe_id": "CWE-99999", "severity": "medium"}
        assert calculate_cvss(finding) == 5.0

    def test_vector_populated_after_cwe_lookup(self):
        finding = {"cwe_id": "CWE-79", "severity": "medium"}
        calculate_cvss(finding)
        assert finding.get("cvss_vector") == CWE_VECTORS["CWE-79"]

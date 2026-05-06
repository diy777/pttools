"""Tests for compliance framework mapping."""


from engine.compliance import map_finding_compliance


class TestComplianceMapping:
    def test_sql_injection_maps_to_all_frameworks(self):
        finding = {"cwe_id": "CWE-89", "owasp_category": "A03:2021 Injection", "category": "web"}
        result = map_finding_compliance(finding)
        assert "pci_dss" in result
        assert "6.5.1" in result["pci_dss"]
        assert "hipaa" in result
        assert "soc2" in result
        assert "owasp" in result

    def test_auth_finding_maps_correctly(self):
        finding = {"cwe_id": "CWE-287", "category": "authentication"}
        result = map_finding_compliance(finding)
        assert "8.1" in result["pci_dss"] or "8.2" in result["pci_dss"]
        assert "164.312(d)" in result["hipaa"]

    def test_empty_finding_returns_empty(self):
        finding = {}
        result = map_finding_compliance(finding)
        assert result == {}

    def test_category_only_mapping(self):
        finding = {"category": "network"}
        result = map_finding_compliance(finding)
        assert "pci_dss" in result
        assert "11.2" in result["pci_dss"]

    def test_owasp_included(self):
        finding = {"owasp_category": "A01:2021 Broken Access Control"}
        result = map_finding_compliance(finding)
        assert result["owasp"] == ["A01:2021 Broken Access Control"]

    def test_no_duplicate_controls(self):
        finding = {"cwe_id": "CWE-287", "category": "authentication"}
        result = map_finding_compliance(finding)
        for controls in result.values():
            assert len(controls) == len(set(controls))

    def test_encryption_category(self):
        finding = {"category": "encryption"}
        result = map_finding_compliance(finding)
        assert "4.1" in result["pci_dss"]
        assert "164.312(e)(1)" in result["hipaa"]

    def test_unknown_cwe_skips_frameworks(self):
        finding = {"cwe_id": "CWE-99999"}
        result = map_finding_compliance(finding)
        assert "pci_dss" not in result

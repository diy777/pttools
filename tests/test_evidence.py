"""Tests for evidence collection (engine/evidence.py)."""


import pytest

from engine.evidence import EvidenceCollector


@pytest.fixture
def collector(tmp_path):
    return EvidenceCollector(base_dir=str(tmp_path))


class TestToolOutput:
    async def test_store_tool_output(self, collector):
        artifact = await collector.store_tool_output(
            engagement_id="eng-1",
            finding_id="f-1",
            tool_name="nmap",
            command="nmap -sV target.com",
            stdout="22/tcp open ssh",
            stderr="",
            exit_code=0,
            duration_ms=1500,
        )
        assert artifact.artifact_type == "tool_output"
        assert artifact.finding_id == "f-1"
        assert artifact.sha256
        assert artifact.size_bytes > 0

    async def test_tool_output_file_created(self, collector, tmp_path):
        await collector.store_tool_output(
            engagement_id="eng-1",
            finding_id="f-1",
            tool_name="nmap",
            command="nmap target.com",
            stdout="output here",
            stderr="",
            exit_code=0,
            duration_ms=100,
        )
        expected_dir = tmp_path / "eng-1"
        assert expected_dir.exists()


class TestHTTPExchange:
    async def test_store_http_exchange(self, collector):
        artifact = await collector.store_http_exchange(
            engagement_id="eng-1",
            finding_id="f-2",
            method="GET",
            url="https://target.com/admin",
            request_headers={"Host": "target.com"},
            request_body="",
            status_code=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html>admin panel</html>",
        )
        assert artifact.artifact_type == "http_request"
        assert artifact.sha256


class TestRawEvidence:
    async def test_store_raw(self, collector):
        artifact = await collector.store_raw(
            engagement_id="eng-1",
            finding_id="f-3",
            artifact_type="screenshot",
            filename="screenshot.png",
            content=b"fake png data",
        )
        assert artifact.artifact_type == "screenshot"
        assert artifact.filename == "screenshot.png"


class TestIntegrity:
    async def test_verify_integrity_clean(self, collector):
        await collector.store_tool_output(
            engagement_id="eng-2",
            finding_id="f-1",
            tool_name="nuclei",
            command="nuclei -u target.com",
            stdout="found stuff",
            stderr="",
            exit_code=0,
            duration_ms=500,
        )
        violations = collector.verify_integrity("eng-2")
        assert len(violations) == 0

    async def test_verify_integrity_tampered(self, collector, tmp_path):
        await collector.store_tool_output(
            engagement_id="eng-3",
            finding_id="f-1",
            tool_name="nmap",
            command="nmap target.com",
            stdout="original content",
            stderr="",
            exit_code=0,
            duration_ms=100,
        )
        evidence_dir = tmp_path / "eng-3"
        files = list(evidence_dir.iterdir())
        if files:
            with open(files[0], "a") as f:
                f.write("TAMPERED")
            violations = collector.verify_integrity("eng-3")
            assert len(violations) >= 1

"""Tests for pentest-tools"""

import asyncio

import pytest

from engine.findings_db import FindingsDB
from tools.registry import ToolRegistry


class TestToolRegistry:
    def test_tool_count(self):
        registry = ToolRegistry()
        tools = registry.list_tools()
        assert len(tools) >= 150, f"Expected 150+ tools, got {len(tools)}"

    def test_categories(self):
        registry = ToolRegistry()
        cats = set(t.category for t in registry.list_tools())
        assert "network" in cats
        assert "web" in cats
        assert "password" in cats
        assert "binary" in cats
        assert "cloud" in cats
        assert "osint" in cats

    def test_tool_lookup(self):
        registry = ToolRegistry()
        assert registry.get_tool("nmap") is not None
        assert registry.get_tool("sqlmap") is not None
        assert registry.get_tool("nuclei") is not None
        assert registry.get_tool("gobuster") is not None
        assert registry.get_tool("hydra") is not None
        assert registry.get_tool("trufflehog") is not None
        assert registry.get_tool("checksec") is not None
        assert registry.get_tool("prowler") is not None
        assert registry.get_tool("sherlock") is not None

    def test_nonexistent_tool(self):
        registry = ToolRegistry()
        assert registry.get_tool("nonexistent") is None

    def test_category_filter(self):
        registry = ToolRegistry()
        web_tools = registry.list_tools(category="web")
        assert len(web_tools) >= 40
        assert all(t.category == "web" for t in web_tools)

    def test_nmap_parser(self):
        registry = ToolRegistry()
        nmap = registry.get_tool("nmap")
        result = {
            "stdout": "22/tcp open  ssh     OpenSSH 8.9\n80/tcp open  http    Apache httpd 2.4.52\n443/tcp open  https\n3306/tcp open  mysql   MySQL 8.0",
            "target": "test.example.com",
            "tool": "nmap",
        }
        findings = nmap.parse_output(result)
        assert len(findings) == 4
        assert findings[0]["severity"] == "medium"  # ssh
        assert findings[1]["severity"] == "low"  # http
        assert findings[2]["severity"] == "low"  # https (http/https group)
        assert findings[3]["severity"] == "high"  # mysql

    def test_nuclei_parser(self):
        registry = ToolRegistry()
        nuclei = registry.get_tool("nuclei")
        result = {
            "stdout": (
                "[critical] http://test.example.com/vuln [cve-2024-1234]\n"
                "[high] http://test.example.com/xss [reflected-xss]\n"
                # info-level tech-detect is intentionally dropped by the
                # severity calibration logic (duplicates tech_fingerprint phase).
                "[info] http://test.example.com/tech [tech-detect]"
            ),
            "target": "test.example.com",
            "tool": "nuclei",
        }
        findings = nuclei.parse_output(result)
        assert len(findings) == 2  # tech-detect info is filtered out
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "high"

    def test_sqlmap_parser(self):
        registry = ToolRegistry()
        sqlmap = registry.get_tool("sqlmap")
        result = {
            "stdout": "Parameter 'id' is vulnerable. sqlmap identified the following injection points: Type: boolean-based blind",
            "target": "http://test.example.com/page?id=1",
            "tool": "sqlmap",
        }
        findings = sqlmap.parse_output(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert "SQL injection" in findings[0]["title"]

    def test_gobuster_parser(self):
        registry = ToolRegistry()
        gobuster = registry.get_tool("gobuster")
        result = {
            "stdout": "/admin (Status: 200)\n/login (Status: 302)\n/backup (Status: 403)\n/error (Status: 500)",
            "target": "http://test.example.com",
            "tool": "gobuster",
        }
        findings = gobuster.parse_output(result)
        assert len(findings) == 4
        assert findings[0]["severity"] == "low"  # 200
        assert findings[2]["severity"] == "medium"  # 403
        assert findings[3]["severity"] == "high"  # 500

    def test_hydra_parser(self):
        registry = ToolRegistry()
        hydra = registry.get_tool("hydra")
        result = {
            "stdout": "[22][ssh] host: test.example.com   login: admin   password: password123",
            "target": "test.example.com",
            "tool": "hydra",
        }
        findings = hydra.parse_output(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_checksec_parser(self):
        registry = ToolRegistry()
        checksec = registry.get_tool("checksec")
        result = {
            "stdout": "RELRO:    No RELRO\nStack:    No canary found\nNX:       NX disabled\nPIE:      PIE disabled",
            "target": "./vuln_binary",
            "tool": "checksec",
        }
        findings = checksec.parse_output(result)
        assert len(findings) == 4
        assert findings[0]["severity"] == "medium"  # No RELRO
        assert findings[2]["severity"] == "high"  # NX disabled


class TestFindingsDB:
    @pytest.fixture
    def db(self):
        return FindingsDB(":memory:")

    @pytest.fixture
    def engagement(self, db):
        async def _create():
            return await db.create_engagement("test.example.com", "full", "", "normal")

        return asyncio.run(_create())

    def test_create_engagement(self, engagement):
        assert engagement["id"] is not None
        assert engagement["target"] == "test.example.com"
        assert engagement["status"] == "running"

    def test_add_and_get_finding(self, db, engagement):
        async def _test():
            fid = await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Test finding",
                    "description": "Test description",
                    "severity": "high",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            findings = await db.get_findings(engagement_id=engagement["id"])
            assert len(findings) == 1
            assert findings[0]["title"] == "Test finding"
            return fid

        asyncio.run(_test())

    def test_severity_sorting(self, db, engagement):
        async def _test():
            await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Low finding",
                    "description": "",
                    "severity": "low",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Critical finding",
                    "description": "",
                    "severity": "critical",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Medium finding",
                    "description": "",
                    "severity": "medium",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            findings = await db.get_findings(engagement_id=engagement["id"])
            assert findings[0]["severity"] == "critical"
            assert findings[1]["severity"] == "medium"
            assert findings[2]["severity"] == "low"

        asyncio.run(_test())

    def test_attack_chains(self, db, engagement):
        async def _test():
            fid = await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Finding",
                    "description": "",
                    "severity": "high",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            await db.add_attack_chain(
                {
                    "engagement_id": engagement["id"],
                    "name": "Test chain",
                    "description": "Test",
                    "severity": "critical",
                    "steps": [{"step": 1, "action": "test"}],
                    "finding_ids": [fid],
                    "impact": "Test",
                }
            )
            chains = await db.get_attack_chains(engagement["id"])
            assert len(chains) == 1
            assert chains[0]["steps"][0]["action"] == "test"

        asyncio.run(_test())

    def test_engagement_summary(self, db, engagement):
        async def _test():
            await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "Critical",
                    "description": "",
                    "severity": "critical",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            await db.add_finding(
                {
                    "engagement_id": engagement["id"],
                    "title": "High",
                    "description": "",
                    "severity": "high",
                    "category": "test",
                    "target": "test.example.com",
                }
            )
            summary = await db.get_engagement_summary(engagement["id"])
            assert summary["total_findings"] == 2
            assert summary["by_severity"]["critical"] == 1
            assert summary["by_severity"]["high"] == 1

        asyncio.run(_test())

    def test_nonexistent_engagement(self, db):
        async def _test():
            result = await db.get_engagement("nonexistent")
            assert result is None

        asyncio.run(_test())


class TestAgents:
    def test_recon_agent_init(self):
        from agents.recon.recon_agent import ReconAgent

        registry = ToolRegistry()
        db = FindingsDB(":memory:")
        agent = ReconAgent(registry, db)
        assert agent is not None

    def test_web_agent_init(self):
        from agents.web.web_agent import WebAgent

        registry = ToolRegistry()
        db = FindingsDB(":memory:")
        agent = WebAgent(registry, db)
        assert agent is not None

    def test_ad_agent_init(self):
        from agents.ad.ad_agent import ADAgent

        registry = ToolRegistry()
        db = FindingsDB(":memory:")
        agent = ADAgent(registry, db)
        assert agent is not None

    def test_cloud_agent_init(self):
        from agents.cloud.cloud_agent import CloudAgent

        registry = ToolRegistry()
        db = FindingsDB(":memory:")
        agent = CloudAgent(registry, db)
        assert agent is not None

    def test_exploit_chain_agent_init(self):
        from agents.exploit_chain.chain_agent import ExploitChainAgent

        db = FindingsDB(":memory:")
        agent = ExploitChainAgent(db)
        assert agent is not None

    def test_poc_agent_init(self):
        from agents.poc_validator.poc_agent import PoCAgent

        db = FindingsDB(":memory:")
        agent = PoCAgent(db)
        assert agent is not None

    def test_detection_agent_init(self):
        from agents.detection.detection_agent import DetectionAgent

        db = FindingsDB(":memory:")
        agent = DetectionAgent(db)
        assert agent is not None

    def test_report_agent_init(self):
        from agents.report.report_agent import ReportAgent

        db = FindingsDB(":memory:")
        agent = ReportAgent(db)
        assert agent is not None

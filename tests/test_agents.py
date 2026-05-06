"""Tests for all agent types with BaseAgent integration."""

from unittest.mock import patch

import pytest

from agents.base import BaseAgent
from engine.findings_db import FindingsDB
from tools.registry import ToolRegistry


@pytest.fixture
def db():
    return FindingsDB(":memory:")


@pytest.fixture
def registry():
    return ToolRegistry()


class TestBaseAgent:
    def test_init_without_llm(self, registry, db):
        agent = BaseAgent(registry, db)
        assert agent.llm is None
        assert agent.agent_type == "base"

    def test_system_prompt_fallback(self, registry, db):
        agent = BaseAgent(registry, db)
        prompt = agent._get_system_prompt()
        assert len(prompt) > 0

    def test_available_tools_include_builtins(self, registry, db):
        agent = BaseAgent(registry, db)
        tools = agent._get_available_tools()
        names = {t.name for t in tools}
        assert "analyze_findings" in names
        assert "store_finding" in names
        assert "builtin_port_scan" in names

    def test_available_tools_include_registry_tools(self, registry, db):
        agent = BaseAgent(registry, db)
        tools = agent._get_available_tools()
        names = {t.name for t in tools}
        assert len(names) > 6

    async def test_deterministic_fallback(self, registry, db):
        agent = BaseAgent(registry, db)
        result = await agent.run_tool_loop("test prompt", "eng-1")
        assert result["status"] == "complete"
        assert "No LLM" in result["summary"]


class TestReconAgent:
    def test_init(self, registry, db):
        from agents.recon.recon_agent import ReconAgent
        agent = ReconAgent(registry, db)
        assert agent.agent_type == "recon"

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_deterministic_run(self, _mock_installed, registry, db):
        from agents.recon.recon_agent import ReconAgent
        agent = ReconAgent(registry, db)
        result = await agent.run_recon("example.com", engagement_id="eng-1")
        assert "findings_count" in result or "status" in result


class TestWebAgent:
    def test_init(self, registry, db):
        from agents.web.web_agent import WebAgent
        agent = WebAgent(registry, db)
        assert agent.agent_type == "web"

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_deterministic_run(self, _mock_installed, registry, db):
        from agents.web.web_agent import WebAgent
        agent = WebAgent(registry, db)
        result = await agent.run_assessment("http://example.com", engagement_id="eng-1")
        assert "findings_count" in result or "status" in result


class TestADAgent:
    def test_init(self, registry, db):
        from agents.ad.ad_agent import ADAgent
        agent = ADAgent(registry, db)
        assert agent.agent_type == "ad"

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_deterministic_run(self, _mock_installed, registry, db):
        from agents.ad.ad_agent import ADAgent
        agent = ADAgent(registry, db)
        result = await agent.run_assessment("dc.example.com", "example.com", engagement_id="eng-1")
        assert "findings_count" in result or "status" in result


class TestCloudAgent:
    def test_init(self, registry, db):
        from agents.cloud.cloud_agent import CloudAgent
        agent = CloudAgent(registry, db)
        assert agent.agent_type == "cloud"

    @patch("tools.registry.SecurityTool.is_installed", return_value=False)
    async def test_deterministic_run(self, _mock_installed, registry, db):
        from agents.cloud.cloud_agent import CloudAgent
        agent = CloudAgent(registry, db)
        result = await agent.run_assessment("aws", "target-account", engagement_id="eng-1")
        assert "findings_count" in result or "status" in result


class TestMobileAgent:
    def test_init(self, registry, db):
        from agents.mobile.mobile_agent import MobileAgent
        agent = MobileAgent(registry, db)
        assert agent.agent_type == "mobile"

    async def test_deterministic_run(self, registry, db):
        from agents.mobile.mobile_agent import MobileAgent
        agent = MobileAgent(registry, db)
        result = await agent._run_deterministic_mobile("app.apk", "android", "eng-1")
        assert result["status"] == "complete"
        assert result["platform"] == "android"


class TestWirelessAgent:
    def test_init(self, registry, db):
        from agents.wireless.wireless_agent import WirelessAgent
        agent = WirelessAgent(registry, db)
        assert agent.agent_type == "wireless"

    async def test_deterministic_run(self, registry, db):
        from agents.wireless.wireless_agent import WirelessAgent
        agent = WirelessAgent(registry, db)
        result = await agent._run_deterministic_wireless("target-ap", "wlan0", "eng-1")
        assert result["status"] == "complete"


class TestSocialEngineerAgent:
    def test_init(self, registry, db):
        from agents.social_engineer.social_engineer_agent import SocialEngineerAgent
        agent = SocialEngineerAgent(registry, db)
        assert agent.agent_type == "social_engineer"

    async def test_deterministic_run(self, registry, db):
        from agents.social_engineer.social_engineer_agent import SocialEngineerAgent
        agent = SocialEngineerAgent(registry, db)
        result = await agent._run_deterministic_social("target.com", "phishing", None, "eng-1")
        assert result["status"] == "complete"


class TestExploitChainAgent:
    def test_init(self, db):
        from agents.exploit_chain.chain_agent import ExploitChainAgent
        agent = ExploitChainAgent(db)
        assert agent.agent_type == "exploit_chain"

    async def test_empty_findings_no_chains(self, db):
        from agents.exploit_chain.chain_agent import ExploitChainAgent

        eng = await db.create_engagement("example.com", "full", "", "normal")
        agent = ExploitChainAgent(db)
        chains = await agent.discover_chains(eng["id"])
        assert chains == []

    async def test_template_chain_discovery(self, db):
        from agents.exploit_chain.chain_agent import ExploitChainAgent

        eng = await db.create_engagement("example.com", "full", "", "normal")
        await db.add_finding({
            "engagement_id": eng["id"], "title": "SQL Injection", "description": "SQLi",
            "severity": "critical", "category": "injection", "target": "example.com",
        })
        await db.add_finding({
            "engagement_id": eng["id"], "title": "Open Admin Port", "description": "Port 8080",
            "severity": "medium", "category": "discovery", "target": "example.com",
        })
        agent = ExploitChainAgent(db)
        chains = await agent.discover_chains(eng["id"])
        assert len(chains) >= 1


class TestPoCAgent:
    def test_init(self, db):
        from agents.poc_validator.poc_agent import PoCAgent
        agent = PoCAgent(db)
        assert agent.agent_type == "poc_validator"

    async def test_static_poc_injection(self, db):
        from agents.poc_validator.poc_agent import PoCAgent
        agent = PoCAgent(db)
        finding = {"id": "f-1", "category": "injection", "target": "http://example.com/vuln", "port": "80"}
        result = agent._generate_static_poc(finding)
        assert "SLEEP" in result["poc"] or "curl" in result["poc"]
        assert result["validated"] is False

    async def test_static_poc_xss(self, db):
        from agents.poc_validator.poc_agent import PoCAgent
        agent = PoCAgent(db)
        finding = {"id": "f-2", "category": "xss", "target": "http://example.com/search", "port": "80"}
        result = agent._generate_static_poc(finding)
        assert "script" in result["poc"]


class TestDetectionAgent:
    def test_init(self, db):
        from agents.detection.detection_agent import DetectionAgent
        agent = DetectionAgent(db)
        assert agent.agent_type == "detection"

    async def test_template_rules_generation(self, db):
        from agents.detection.detection_agent import DetectionAgent

        eng = await db.create_engagement("example.com", "full", "", "normal")
        await db.add_finding({
            "engagement_id": eng["id"], "title": "SQL Injection", "description": "SQLi on login",
            "severity": "critical", "category": "injection", "target": "example.com",
        })
        agent = DetectionAgent(db)
        rules = await agent.generate_rules(eng["id"])
        assert len(rules) == 3
        formats = {r["format"] for r in rules}
        assert formats == {"sigma", "spl", "kql"}

    async def test_sigma_rule_content(self, db):
        from agents.detection.detection_agent import _build_sigma_rule

        rule = _build_sigma_rule("SQL Injection", "example.com", "T1190", "Exploit Public-Facing Application", "injection")
        assert "title:" in rule
        assert "logsource:" in rule
        assert "detection:" in rule
        assert "web" in rule

    async def test_spl_query_injection(self, db):
        from agents.detection.detection_agent import _build_spl_query

        query = _build_spl_query("SQLi", "example.com", "injection")
        assert "index=web" in query
        assert "example.com" in query

    async def test_kql_query_ad(self, db):
        from agents.detection.detection_agent import _build_kql_query

        query = _build_kql_query("Kerberoasting", "dc.example.com", "ad")
        assert "SecurityEvent" in query
        assert "4625" in query or "4768" in query


class TestReportAgent:
    async def test_markdown_report_generation(self, db, tmp_path):
        import os

        from agents.report.report_agent import ReportAgent

        os.chdir(tmp_path)
        eng = await db.create_engagement("example.com", "full", "", "normal")
        await db.add_finding({
            "engagement_id": eng["id"], "title": "Critical SQLi", "description": "Found SQL injection",
            "severity": "critical", "category": "injection", "target": "example.com",
        })
        agent = ReportAgent(db)
        result = await agent.generate_report(eng["id"])
        assert result["total_findings"] == 1
        assert os.path.exists(result["output_path"])

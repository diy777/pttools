"""Tests for LLM integration layer (engine/llm/)."""

import pytest

from engine.llm.client import LLMMessage, LLMResponse, TokenUsage, ToolCall, ToolDefinition
from engine.llm.factory import create_llm_client
from engine.llm.prompts import AGENT_PROMPTS, BASE_SYSTEM
from engine.llm.tool_schemas import agent_decision_tools, builtin_scanner_tools, security_tool_to_llm_tool


class TestLLMTypes:
    def test_llm_message_creation(self):
        msg = LLMMessage(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"
        assert msg.tool_calls == ()

    def test_llm_message_frozen(self):
        msg = LLMMessage(role="user", content="hello")
        with pytest.raises(AttributeError):
            msg.content = "changed"

    def test_tool_call_creation(self):
        tc = ToolCall(id="tc-1", name="run_nmap", arguments={"target": "example.com"})
        assert tc.name == "run_nmap"
        assert tc.arguments["target"] == "example.com"

    def test_tool_definition_creation(self):
        td = ToolDefinition(
            name="test_tool",
            description="A test tool",
            parameters={"type": "object", "properties": {"target": {"type": "string"}}},
        )
        assert td.name == "test_tool"

    def test_llm_response_creation(self):
        resp = LLMResponse(
            content="response text",
            tool_calls=(),
            usage=TokenUsage(prompt_tokens=10, completion_tokens=5),
            model="test-model",
        )
        assert resp.content == "response text"
        assert resp.usage.prompt_tokens == 10

    def test_token_usage_fields(self):
        usage = TokenUsage(prompt_tokens=100, completion_tokens=50)
        assert usage.prompt_tokens == 100
        assert usage.completion_tokens == 50


class TestToolSchemas:
    def test_agent_decision_tools(self):
        tools = agent_decision_tools()
        names = {t.name for t in tools}
        assert "analyze_findings" in names
        assert "store_finding" in names

    def test_builtin_scanner_tools(self):
        tools = builtin_scanner_tools()
        names = {t.name for t in tools}
        assert "builtin_port_scan" in names
        assert "builtin_http_headers" in names
        assert "builtin_ssl_check" in names

    def test_security_tool_to_llm_tool(self):
        tool = security_tool_to_llm_tool(
            name="nmap",
            category="network",
            description="Network scanner",
            installed=True,
        )
        assert tool.name == "run_nmap"
        assert "network" in tool.description.lower() or "Network" in tool.description


class TestPrompts:
    def test_base_system_prompt_exists(self):
        assert len(BASE_SYSTEM) > 100

    def test_all_agent_types_have_prompts(self):
        expected = ["recon", "web", "ad", "cloud", "exploit_chain", "poc_validator", "detection", "report", "mobile", "social_engineer", "wireless"]
        for agent_type in expected:
            assert agent_type in AGENT_PROMPTS, f"Missing prompt for {agent_type}"

    def test_prompts_contain_methodology(self):
        assert "PTES" in AGENT_PROMPTS["recon"] or "recon" in AGENT_PROMPTS["recon"].lower()
        assert "OWASP" in AGENT_PROMPTS["web"] or "web" in AGENT_PROMPTS["web"].lower()


class TestFactory:
    def test_no_key_still_creates_client(self, monkeypatch):
        monkeypatch.delenv("PENTEST_TOOLS_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("PENTEST_TOOLS_LLM_PROVIDER", raising=False)
        client = create_llm_client()
        assert client is not None

    def test_anthropic_provider(self):
        client = create_llm_client(provider="anthropic", api_key="test-key")
        from engine.llm.providers.anthropic import AnthropicProvider
        # Factory wraps with CostTrackingLLMClient; unwrap for type check.
        inner = getattr(client, "inner", client)
        assert isinstance(inner, AnthropicProvider)

    def test_ollama_provider(self):
        client = create_llm_client(provider="ollama")
        from engine.llm.providers.ollama import OllamaProvider
        inner = getattr(client, "inner", client)
        assert isinstance(inner, OllamaProvider)

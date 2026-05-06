"""Tests for LLM provider implementations."""


from engine.llm.client import LLMMessage, ToolDefinition


class TestOpenAIProvider:
    def test_init(self):
        from engine.llm.providers.openai import OpenAIProvider
        provider = OpenAIProvider(api_key="test-key", model="gpt-4o")
        assert provider is not None

    def test_format_message(self):
        from engine.llm.providers.openai import _format_message
        msg = LLMMessage(role="user", content="Hello")
        formatted = _format_message(msg)
        assert formatted["role"] == "user"
        assert formatted["content"] == "Hello"

    def test_format_system_message(self):
        from engine.llm.providers.openai import _format_message
        msg = LLMMessage(role="system", content="You are helpful")
        formatted = _format_message(msg)
        assert formatted["role"] == "system"

    def test_format_tool(self):
        from engine.llm.providers.openai import _format_tool
        tool = ToolDefinition(
            name="test_tool",
            description="A test",
            parameters={"type": "object", "properties": {}},
        )
        formatted = _format_tool(tool)
        assert formatted["type"] == "function"
        assert formatted["function"]["name"] == "test_tool"

    def test_parse_response(self):
        from engine.llm.providers.openai import _parse_response
        data = {
            "choices": [{"message": {"content": "Hello back", "tool_calls": []}, "finish_reason": "stop"}],
            "model": "gpt-4o",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        resp = _parse_response(data)
        assert resp.content == "Hello back"
        assert resp.model == "gpt-4o"
        assert resp.finish_reason == "stop"


class TestAnthropicProvider:
    def test_init(self):
        from engine.llm.providers.anthropic import AnthropicProvider
        provider = AnthropicProvider(api_key="test-key", model="claude-sonnet-4-20250514")
        assert provider is not None

    def test_format_tool(self):
        from engine.llm.providers.anthropic import _format_tool
        tool = ToolDefinition(
            name="test_tool",
            description="A test",
            parameters={"type": "object", "properties": {}},
        )
        formatted = _format_tool(tool)
        assert formatted["name"] == "test_tool"
        assert "input_schema" in formatted

    def test_parse_response(self):
        from engine.llm.providers.anthropic import _parse_response
        data = {
            "content": [{"type": "text", "text": "Hello"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        resp = _parse_response(data)
        assert resp.content == "Hello"
        assert resp.model == "claude-sonnet-4-20250514"


class TestOllamaProvider:
    def test_init(self):
        from engine.llm.providers.ollama import OllamaProvider
        provider = OllamaProvider(model="llama3.1")
        assert provider is not None

    def test_parse_response(self):
        from engine.llm.providers.ollama import _parse_response
        data = {
            "message": {"content": "Hello from ollama", "tool_calls": []},
            "model": "llama3.1",
            "done_reason": "stop",
            "prompt_eval_count": 10,
            "eval_count": 5,
        }
        resp = _parse_response(data)
        assert resp.content == "Hello from ollama"
        assert resp.model == "llama3.1"

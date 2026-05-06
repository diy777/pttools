"""HTTP adapters for speaking to LLM targets under different schemas."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class LLMAdapterError(Exception):
    pass


@dataclass
class LLMTargetAdapter:
    """Sends a prompt to an LLM endpoint and returns the model's reply string.

    ``schema`` selects the request/response shape:
    - ``openai``: POST ``{url}`` with ``{"model": ..., "messages": [...]}``,
      extract ``choices[0].message.content``.
    - ``simple``: POST ``{url}`` with ``{"prompt": ...}``, extract
      ``response`` or ``output`` or ``text`` (first present).
    - ``custom``: caller supplies a request body template containing the
      literal ``{{PROMPT}}`` placeholder and a ``response_key`` for the
      field to read from the JSON response.
    """

    url: str
    schema: str = "openai"
    model: str = "gpt-3.5-turbo"
    headers: dict[str, str] | None = None
    timeout: float = 30.0
    custom_body: dict[str, Any] | None = None
    custom_response_key: str = "response"

    async def send(self, prompt: str, client: httpx.AsyncClient | None = None) -> str:
        body = self._build_body(prompt)
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout)
        try:
            resp = await client.post(self.url, json=body, headers=self.headers or {})
        finally:
            if owns_client:
                await client.aclose()

        if resp.status_code >= 500:
            raise LLMAdapterError(f"LLM target returned {resp.status_code}: {resp.text[:200]}")

        try:
            data = resp.json()
        except ValueError:
            return resp.text

        return self._extract(data)

    def _build_body(self, prompt: str) -> dict[str, Any]:
        if self.schema == "openai":
            return {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            }
        if self.schema == "simple":
            return {"prompt": prompt}
        if self.schema == "custom":
            body = _deep_replace(self.custom_body or {}, "{{PROMPT}}", prompt)
            return body
        raise LLMAdapterError(f"Unknown schema: {self.schema}")

    def _extract(self, data: Any) -> str:
        if self.schema == "openai":
            try:
                return str(data["choices"][0]["message"]["content"])
            except (KeyError, IndexError, TypeError):
                return str(data)
        if self.schema == "simple":
            for key in ("response", "output", "text", "message"):
                if isinstance(data, dict) and key in data:
                    return str(data[key])
            return str(data)
        if self.schema == "custom":
            if isinstance(data, dict) and self.custom_response_key in data:
                return str(data[self.custom_response_key])
            return str(data)
        return str(data)


def _deep_replace(obj: Any, needle: str, replacement: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(needle, replacement)
    if isinstance(obj, list):
        return [_deep_replace(item, needle, replacement) for item in obj]
    if isinstance(obj, dict):
        return {k: _deep_replace(v, needle, replacement) for k, v in obj.items()}
    return obj

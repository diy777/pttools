"""Tests for engine.tracing and engine.telemetry.

Both modules degrade gracefully when their optional deps / network are
absent. Tests verify the no-op paths are safe and the consent gating is
strict (telemetry off by default).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from engine import telemetry, tracing

# ─── tracing ───────────────────────────────────────────────────────────


def test_tracer_no_op_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PENTEST_TOOLS_TRACING", raising=False)
    t = tracing.Tracer()
    assert t.enabled is False
    with t.span("test.op", agent="recon") as s:
        s.set_attr("foo", "bar")
        s.set_attr("count", 42)
        s.set_status(True)
        s.add_event("milestone")
    # No exception, that's the contract


def test_tracer_no_op_does_not_crash_on_complex_attrs() -> None:
    t = tracing.Tracer()
    with t.span("test.op") as s:
        s.set_attr("dict", {"a": 1})
        s.set_attr("list", [1, 2, 3])
        s.set_attr("none", None)
        s.set_attr("very_long", "x" * 1000)


def test_safe_attr_value_truncates_long_strings() -> None:
    long_string = "y" * 800
    out = tracing._safe_attr_value(long_string)
    assert isinstance(out, str)
    assert len(out) <= 500
    assert out.endswith("...")


def test_safe_attr_value_handles_primitives() -> None:
    assert tracing._safe_attr_value("hello") == "hello"
    assert tracing._safe_attr_value(42) == 42
    assert tracing._safe_attr_value(3.14) == 3.14
    assert tracing._safe_attr_value(True) is True
    assert tracing._safe_attr_value([1, 2, 3]) == [1, 2, 3]


def test_safe_attr_value_stringifies_complex() -> None:
    out = tracing._safe_attr_value({"a": 1})
    assert isinstance(out, str)


def test_module_level_tracer_singleton() -> None:
    assert tracing.tracer is tracing.tracer  # same instance


def test_tracer_when_otel_unavailable_logs_warning(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")
    # Force the import to fail
    import builtins

    real_import = builtins.__import__

    def block(name: str, *a, **kw):
        if name.startswith("opentelemetry"):
            raise ImportError("simulated missing opentelemetry")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", block)

    t = tracing.Tracer()
    # First use triggers init, which logs the warning, then no-op for the actual span
    with t.span("foo"):
        pass
    assert t.enabled is False


# ─── telemetry ─────────────────────────────────────────────────────────


@pytest.fixture
def fresh_config_dir(monkeypatch: pytest.MonkeyPatch):
    """Use a temp dir for the consent file and client_id file."""
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setenv("PENTEST_TOOLS_CONFIG_DIR", str(tmp))
    # Re-resolve module-level paths
    import importlib

    importlib.reload(telemetry)
    yield tmp


def test_telemetry_off_by_default(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PENTEST_TOOLS_TELEMETRY", raising=False)
    assert telemetry.is_enabled() is False
    assert "disabled" in telemetry.consent_status()


def test_telemetry_requires_explicit_consent(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTEST_TOOLS_TELEMETRY", "1")
    # Even with env var, consent file is required
    assert telemetry.is_enabled() is False
    telemetry.grant_consent()
    assert telemetry.is_enabled() is True


def test_telemetry_env_zero_overrides_consent(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    telemetry.grant_consent()
    assert telemetry.is_enabled() is True
    monkeypatch.setenv("PENTEST_TOOLS_TELEMETRY", "0")
    assert telemetry.is_enabled() is False


def test_revoke_consent_removes_files(fresh_config_dir) -> None:
    telemetry.grant_consent()
    assert telemetry.CONSENT_PATH.is_file()
    telemetry.revoke_consent()
    assert not telemetry.CONSENT_PATH.is_file()
    assert not telemetry.CLIENT_ID_PATH.is_file()


def test_telemetry_emit_does_not_send_when_disabled(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    """When disabled, emit must be a complete no-op."""
    monkeypatch.delenv("PENTEST_TOOLS_TELEMETRY", raising=False)
    called = {"v": False}

    def fake_urlopen(*args, **kwargs):
        called["v"] = True
        raise AssertionError("should not be called")

    monkeypatch.setattr("engine.telemetry.urlopen", fake_urlopen)
    telemetry.emit("engagement.start", agent="recon")
    assert called["v"] is False


def test_telemetry_emit_when_enabled_fires_post(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    telemetry.grant_consent()
    captured = {}

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["method"] = req.get_method()
        return _FakeResp()

    monkeypatch.setattr("engine.telemetry.urlopen", fake_urlopen)
    telemetry.emit("engagement.start", agent="recon", duration_seconds=42, success=True)

    assert captured["method"] == "POST"
    import json as _json

    payload = _json.loads(captured["body"])
    assert payload["event"] == "engagement.start"
    assert payload["agent"] == "recon"
    assert payload["duration_seconds"] == 42
    assert payload["success"] is True
    # Required fields
    assert "ts" in payload
    assert "client_id" in payload
    assert "version" in payload
    assert "platform" in payload


def test_telemetry_emit_filters_sensitive_keys(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    telemetry.grant_consent()
    captured = {}

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data
        return _FakeResp()

    monkeypatch.setattr("engine.telemetry.urlopen", fake_urlopen)
    telemetry.emit(
        "tool.exec",
        agent="recon",
        target="https://victim.example",  # blocked
        api_key="sk-secret",  # blocked
        password="hunter2",  # blocked
        url="http://anything",  # blocked
        username="bob",  # blocked
        success=True,
    )
    import json as _json

    payload = _json.loads(captured["body"])
    assert "target" not in payload
    assert "api_key" not in payload
    assert "password" not in payload
    assert "url" not in payload
    assert "username" not in payload
    # Allowed keys still present
    assert payload["agent"] == "recon"
    assert payload["success"] is True


def test_telemetry_emit_swallows_network_errors(fresh_config_dir, monkeypatch: pytest.MonkeyPatch) -> None:
    """Telemetry must NEVER raise back to the caller."""
    telemetry.grant_consent()

    def boom(*args, **kwargs):
        raise OSError("network down")

    monkeypatch.setattr("engine.telemetry.urlopen", boom)
    # Must not raise
    telemetry.emit("engagement.end", success=False)

"""Coverage fill for engine/tracing.py.

Targets: _NoopSpan/_OTelSpanWrapper methods (incl. swallowed exceptions),
the lazy init paths (env-disabled, ImportError, console exporter, OTLP
exporter init failure, OTLP success), the span context manager (no-op
path, real-span happy path, real-span exception path, init-failure
fallback), and _safe_attr_value coercion edge cases.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from engine.tracing import (
    Tracer,
    _NoopSpan,
    _OTelSpanWrapper,
    _safe_attr_value,
)


def _otlp_or_skip():
    """Skip tests that require the optional OTLP gRPC exporter package."""
    pytest.importorskip("opentelemetry.exporter.otlp.proto.grpc.trace_exporter")

# ─── _NoopSpan no-ops ───────────────────────────────────────────────────


def test_noopspan_methods_return_none():
    s = _NoopSpan()
    assert s.set_attr("k", "v") is None
    assert s.set_status(True, "ok") is None
    assert s.add_event("ev", {"a": 1}) is None


# ─── _OTelSpanWrapper ───────────────────────────────────────────────────


def test_otel_wrapper_set_attr_calls_underlying():
    raw = MagicMock()
    w = _OTelSpanWrapper(raw)
    w.set_attr("phase", "recon")
    raw.set_attribute.assert_called_once_with("phase", "recon")


def test_otel_wrapper_set_attr_swallows_exception():
    raw = MagicMock()
    raw.set_attribute.side_effect = RuntimeError("boom")
    w = _OTelSpanWrapper(raw)
    # Must not raise
    w.set_attr("phase", "recon")


def test_otel_wrapper_set_status_ok():
    raw = MagicMock()
    w = _OTelSpanWrapper(raw)
    w.set_status(True, "fine")
    raw.set_status.assert_called_once()


def test_otel_wrapper_set_status_error():
    raw = MagicMock()
    w = _OTelSpanWrapper(raw)
    w.set_status(False, "broken")
    raw.set_status.assert_called_once()


def test_otel_wrapper_set_status_swallows():
    raw = MagicMock()
    raw.set_status.side_effect = RuntimeError("boom")
    w = _OTelSpanWrapper(raw)
    w.set_status(True)


def test_otel_wrapper_add_event_calls_underlying():
    raw = MagicMock()
    w = _OTelSpanWrapper(raw)
    w.add_event("got_finding", {"sev": "high"})
    raw.add_event.assert_called_once()


def test_otel_wrapper_add_event_no_attrs():
    raw = MagicMock()
    w = _OTelSpanWrapper(raw)
    w.add_event("started")
    raw.add_event.assert_called_once()


def test_otel_wrapper_add_event_swallows():
    raw = MagicMock()
    raw.add_event.side_effect = RuntimeError("boom")
    w = _OTelSpanWrapper(raw)
    w.add_event("ev")


# ─── Tracer lazy init ───────────────────────────────────────────────────


def test_tracer_disabled_when_env_unset(monkeypatch):
    monkeypatch.delenv("PENTEST_TOOLS_TRACING", raising=False)
    t = Tracer()
    assert t.enabled is False


def test_tracer_disabled_for_falsy_env(monkeypatch):
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "off")
    t = Tracer()
    assert t.enabled is False


def test_tracer_init_only_runs_once(monkeypatch):
    monkeypatch.delenv("PENTEST_TOOLS_TRACING", raising=False)
    t = Tracer()
    t._init_if_needed()
    t._init_if_needed()  # second call is a no-op via `_initialized` guard
    assert t._initialized is True


def test_tracer_handles_otel_import_error(monkeypatch):
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("opentelemetry"):
            raise ImportError(f"no {name}")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        t = Tracer()
        t._init_if_needed()
        assert t._enabled is False


def test_tracer_console_exporter(monkeypatch):
    # The lazy init path imports OTLP unconditionally, so the test needs that
    # package even though the chosen exporter is console-only.
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "true")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "console")
    t = Tracer()
    t._init_if_needed()
    assert t._enabled is True


def test_tracer_otlp_exporter_init_failure(monkeypatch):
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "yes")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    with patch(
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter",
        side_effect=RuntimeError("cannot connect"),
    ):
        t = Tracer()
        t._init_if_needed()
        assert t._enabled is False


def test_tracer_otlp_exporter_success(monkeypatch):
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "on")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    fake_exporter = MagicMock()
    with patch(
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter",
        return_value=fake_exporter,
    ):
        t = Tracer()
        t._init_if_needed()
        assert t._enabled is True


def test_tracer_otlp_default_endpoint(monkeypatch):
    """Cover the no-endpoint branch of OTLP setup."""
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")

    fake_exporter = MagicMock()
    with patch(
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter",
        return_value=fake_exporter,
    ):
        t = Tracer()
        t._init_if_needed()
        assert t._enabled is True


# ─── Tracer.span context manager ────────────────────────────────────────


def test_span_yields_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("PENTEST_TOOLS_TRACING", raising=False)
    t = Tracer()
    with t.span("phase.recon") as s:
        assert isinstance(s, _NoopSpan)
        s.set_attr("anything", "ok")


def test_span_real_path_happy(monkeypatch):
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "console")

    t = Tracer()
    with t.span("phase.recon", target="x") as s:
        assert hasattr(s, "set_attr")
        s.set_attr("count", 5)
        s.set_status(True)


def test_span_user_exception_propagates_cleanly(monkeypatch):
    """User exception inside an active span re-raises and is not masked."""
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "console")
    t = Tracer()
    with pytest.raises(ValueError, match="user error"), t.span("phase.web") as s:
        s.set_attr("x", "y")
        raise ValueError("user error")


def test_span_outer_failure_falls_back_to_noop(monkeypatch):
    """If start_as_current_span itself raises, span() yields a NoopSpan."""
    _otlp_or_skip()
    monkeypatch.setenv("PENTEST_TOOLS_TRACING", "1")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "console")
    t = Tracer()
    t._init_if_needed()
    # Force the otel tracer's start_as_current_span to blow up
    fake_otel = MagicMock()
    fake_otel.start_as_current_span.side_effect = RuntimeError("backend dead")
    t._otel_tracer = fake_otel
    with t.span("phase.x") as s:
        assert isinstance(s, _NoopSpan)


# ─── _safe_attr_value edge cases ────────────────────────────────────────


def test_safe_attr_value_short_str_passthrough():
    assert _safe_attr_value("ok") == "ok"


def test_safe_attr_value_truncates_long_str():
    long = "x" * 1000
    out = _safe_attr_value(long)
    assert len(out) == 500
    assert out.endswith("...")


def test_safe_attr_value_int_float_bool():
    assert _safe_attr_value(42) == 42
    assert _safe_attr_value(3.14) == 3.14
    assert _safe_attr_value(True) is True


def test_safe_attr_value_homogeneous_list():
    assert _safe_attr_value([1, 2, 3]) == [1, 2, 3]
    assert _safe_attr_value(("a", "b")) == ["a", "b"]


def test_safe_attr_value_mixed_list_stringified():
    out = _safe_attr_value([1, "x", {"k": "v"}])
    assert isinstance(out, str)


def test_safe_attr_value_arbitrary_object_stringified_and_truncated():
    class Big:
        def __str__(self) -> str:
            return "y" * 1000

    out = _safe_attr_value(Big())
    assert len(out) == 500
    assert out.endswith("...")

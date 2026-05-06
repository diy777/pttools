"""OpenTelemetry tracing primitive for pentest-tools engagements.

Provides span context managers that the orchestrator, agents, and LLM
client can wrap around their work. Spans flow to any OTLP-compatible
backend (Phoenix, Jaeger, Tempo, Datadog, Honeycomb).

When the OTel SDK is not installed (the default), this module degrades
to a no-op so the rest of the engine works unchanged.

Configuration via env vars:
    PENTEST_TOOLS_TRACING        on | off (default: off)
    OTEL_EXPORTER_OTLP_ENDPOINT  e.g. http://localhost:4317
    OTEL_SERVICE_NAME            default: pentest-tools
    OTEL_TRACES_EXPORTER         otlp | console (default: otlp)

Usage:

    from engine.tracing import tracer

    with tracer.span("agent.decide", agent="recon", engagement_id=eid):
        decision = await agent.next_step()

    with tracer.span("llm.complete", model=self.model) as s:
        resp = await self.client.complete(messages=msgs, tools=tools)
        s.set_attr("tokens.input", resp.usage.prompt_tokens)
        s.set_attr("tokens.output", resp.usage.completion_tokens)

    with tracer.span("tool.exec", tool=tool.name, target=target) as s:
        result = await tool.execute(target, args)
        s.set_attr("exit_code", result.get("returncode", -1))

The `span` context manager always returns a Span-like object that has
.set_attr() and .set_status() methods, regardless of whether the real
OTel SDK is loaded. Code is safe to write the OTel-style calls and not
think about whether tracing is on.

Optional dependency: pip install pttools[tracing]
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("pentest-tools.tracing")


# ─── Public API: a single shared tracer instance ────────────────────────


class _NoopSpan:
    """No-op span returned when tracing is disabled."""

    def set_attr(self, key: str, value: Any) -> None:  # noqa: ARG002
        return None

    def set_status(self, ok: bool, description: str = "") -> None:  # noqa: ARG002
        return None

    def add_event(self, name: str, attrs: dict[str, Any] | None = None) -> None:  # noqa: ARG002
        return None


class _OTelSpanWrapper:
    """Thin adapter so user code doesn't import OTel directly."""

    def __init__(self, span: Any) -> None:
        self._span = span

    def set_attr(self, key: str, value: Any) -> None:
        try:
            self._span.set_attribute(key, _safe_attr_value(value))
        except Exception as e:  # noqa: BLE001
            logger.debug("set_attr failed: %s", e)

    def set_status(self, ok: bool, description: str = "") -> None:
        try:
            from opentelemetry.trace import Status, StatusCode

            self._span.set_status(
                Status(StatusCode.OK if ok else StatusCode.ERROR, description)
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("set_status failed: %s", e)

    def add_event(self, name: str, attrs: dict[str, Any] | None = None) -> None:
        try:
            self._span.add_event(name, {k: _safe_attr_value(v) for k, v in (attrs or {}).items()})
        except Exception as e:  # noqa: BLE001
            logger.debug("add_event failed: %s", e)


class Tracer:
    """Lazy-initialized tracer. Resolves the OTel SDK on first use."""

    def __init__(self) -> None:
        self._initialized = False
        self._enabled = False
        self._otel_tracer: Any = None

    def _init_if_needed(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        if (os.getenv("PENTEST_TOOLS_TRACING", "").lower() not in ("1", "true", "on", "yes")):
            return

        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError as e:
            logger.warning(
                "PENTEST_TOOLS_TRACING enabled but opentelemetry not installed (%s). "
                "Install with: pip install pttools[tracing]",
                e,
            )
            return

        service_name = os.getenv("OTEL_SERVICE_NAME", "pentest-tools")
        resource = Resource.create({"service.name": service_name})

        exporter_kind = os.getenv("OTEL_TRACES_EXPORTER", "otlp").lower()
        provider = TracerProvider(resource=resource)

        if exporter_kind == "console":
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter

            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        else:
            endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
            try:
                exporter = OTLPSpanExporter(endpoint=endpoint) if endpoint else OTLPSpanExporter()
                provider.add_span_processor(BatchSpanProcessor(exporter))
            except Exception as e:  # noqa: BLE001
                logger.warning("OTLP exporter init failed: %s", e)
                return

        trace.set_tracer_provider(provider)
        self._otel_tracer = trace.get_tracer("pentest-tools")
        self._enabled = True
        logger.info("OpenTelemetry tracing enabled, exporter=%s", exporter_kind)

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Any:
        """Context manager yielding a span-like object.

        When tracing is enabled, this opens a real OTel span and exports
        it on context exit. When disabled, returns a no-op span so the
        calling code is identical in either case.
        """
        self._init_if_needed()

        if not self._enabled or self._otel_tracer is None:
            yield _NoopSpan()
            return

        # Try to enter the OTel span context. If start fails (backend dead,
        # exporter broken, etc.) yield a NoopSpan so the caller isn't
        # punished for tracing failures. Once we *have* yielded, we no longer
        # catch exceptions at this outer scope: a contextmanager generator
        # may yield only once, and re-yielding after the inner block raises
        # is what produced the latent "generator didn't stop after throw()"
        # bug surfaced by tests/test_tracing_coverage.py.
        try:
            span_cm = self._otel_tracer.start_as_current_span(name)
            raw = span_cm.__enter__()
        except Exception as e:  # noqa: BLE001
            logger.debug("span(%s) start failed: %s", name, e)
            yield _NoopSpan()
            return

        wrapper = _OTelSpanWrapper(raw)
        for k, v in attributes.items():
            wrapper.set_attr(k, v)
        try:
            try:
                yield wrapper
            except Exception as e:
                wrapper.set_status(False, repr(e))
                span_cm.__exit__(type(e), e, e.__traceback__)
                raise
            else:
                wrapper.set_status(True)
                span_cm.__exit__(None, None, None)
        except Exception:
            # User exception already propagated through __exit__; do not
            # swallow it. (We still re-raise to honor the with semantics.)
            raise

    @property
    def enabled(self) -> bool:
        self._init_if_needed()
        return self._enabled


# Module-level singleton
tracer = Tracer()


# ─── helpers ───────────────────────────────────────────────────────────


_MAX_ATTR_STR_LEN = 500


def _safe_attr_value(v: Any) -> Any:
    """OTel only accepts str/int/float/bool/list-of-those for attrs.

    Strings are truncated at 500 chars so a single noisy attribute can't
    bloat the span payload. Non-primitives are stringified then truncated.
    """
    if isinstance(v, str):
        if len(v) > _MAX_ATTR_STR_LEN:
            return v[: _MAX_ATTR_STR_LEN - 3] + "..."
        return v
    if isinstance(v, (int, float, bool)):
        return v
    if isinstance(v, (list, tuple)) and all(isinstance(x, (str, int, float, bool)) for x in v):
        return list(v)
    s = str(v)
    if len(s) > _MAX_ATTR_STR_LEN:
        s = s[: _MAX_ATTR_STR_LEN - 3] + "..."
    return s
